//! Shared worker input, observed guest lifecycle, and platform entrypoint.

use std::path::PathBuf;
use std::time::Duration;

#[cfg(target_arch = "aarch64")]
pub use crate::aarch64::arm::MAX_VCPUS;
#[cfg(target_arch = "x86_64")]
pub use crate::amd64::machine::MAX_VCPUS;

/// Resources supplied to one platform VM worker.
pub struct WorkerInput {
    pub kernel: Vec<u8>,
    pub boot_disk: Vec<u8>,
    pub root_disk: PathBuf,
    pub volume_disks: Vec<PathBuf>,
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub shares: Vec<terra_runtime::component::fs::host::ShareGrant>,
    pub plan: Vec<u8>,
    pub artifacts: terra_runtime::TrustedArtifacts,
    pub network_policy: terra_network::PolicyHandle,
    pub port_mappings: Vec<terra_network::PortMapping>,
    pub ram_bytes: u64,
    pub component_memory_limits: terra_runtime::box_runtime::store::ComponentMemoryLimits,
    pub vcpus: usize,
    pub deadline: Option<Duration>,
    pub hard_stop: Option<fn() -> !>,
    pub listener: Option<terra_io::local::LocalListener>,
    pub control: Option<terra_io::local::LocalStream>,
    pub diagnostics: Option<std::fs::File>,
}

pub(crate) fn create_runtime(
    input: &WorkerInput,
) -> wasmtime::Result<terra_runtime::box_runtime::BoxRuntime> {
    terra_runtime::box_runtime::BoxRuntime::new(
        &terra_runtime::engine::device_engine()?,
        terra_runtime::box_runtime::store::BoxHost::with_memory_limits(
            input.component_memory_limits,
        ),
    )
}

pub(crate) async fn boot_prepared<
    M: terra_runtime::component::vmm::virtualization::VirtualMachine,
>(
    mut runtime: terra_runtime::box_runtime::BoxRuntime,
    mut prepared: terra_runtime::component::vmm::virtualization::PreparedMachine<M>,
    input: &mut WorkerInput,
) -> wasmtime::Result<(
    terra_runtime::box_runtime::BoxRuntime,
    terra_runtime::component::vmm::virtualization::MachineHandle<M>,
)> {
    let boot = input.artifacts.boot().deserialize(runtime.store.engine())?;
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    let kernel_cmdline = crate::windows::amd64::build_kernel_cmdline(
        crate::windows::whp::query_tsc_frequency().map_err(|error| {
            wasmtime::Error::msg(format!("querying the WHP guest clock: {error}"))
        })?,
    )?;
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    let kernel_cmdline = terra_protocol::KERNEL_CMDLINE.to_owned();
    let entry = runtime
        .boot_prepared_machine(
            &boot,
            prepared.config(),
            prepared.ram()?,
            std::mem::take(&mut input.kernel),
            &kernel_cmdline,
        )
        .await?;
    prepared.accept_boot(entry)?;
    runtime.initialize_mmio_artifact(&input.artifacts).await?;
    runtime.attach_machine(prepared).await
}

pub(crate) fn assemble_devices(
    runtime: &mut terra_runtime::box_runtime::BoxRuntime,
    input: &mut WorkerInput,
    ram: terra_runtime::component::vmm::virtualization::RamGrant,
    disks: &[(PathBuf, bool)],
    bind_interrupt: impl Fn(
        terra_runtime::component::vmm::machine::DeviceKind,
        usize,
    ) -> Result<terra_runtime::component::network::Interrupt, String>,
) -> Result<(), String> {
    use terra_runtime::component::vmm::machine::DeviceKind;
    blocks(runtime, ram.clone(), input, disks, |index| {
        bind_interrupt(DeviceKind::Block, index)
    })?;
    filesystems(runtime, ram.clone(), input, |index| {
        bind_interrupt(DeviceKind::Fs, index)
    })?;
    memory(
        runtime,
        ram.clone(),
        input,
        bind_interrupt(DeviceKind::Memory, 0)?,
    )?;
    network(
        runtime,
        ram.clone(),
        input,
        bind_interrupt(DeviceKind::Net, 0)?,
    )?;
    vsock(runtime, ram, input, bind_interrupt(DeviceKind::Vsock, 0)?)?;
    Ok(())
}

pub(crate) fn disk_paths(input: &WorkerInput) -> Vec<(PathBuf, bool)> {
    let mut disks = Vec::with_capacity(1 + input.volume_disks.len());
    disks.push((input.root_disk.clone(), false));
    disks.extend(input.volume_disks.iter().cloned().map(|path| (path, false)));
    disks
}

/// Platform-neutral vCPU stop result retained for lifecycle diagnostics.
pub type VcpuResult = Result<(), String>;

#[derive(Debug)]
pub struct WorkerOutcome {
    pub exit_code: Option<i32>,
    pub vcpu_outcomes: Vec<VcpuResult>,
}

pub struct PreparedVmm {
    pub runtime: terra_runtime::box_runtime::PreparedBoxRuntime,
    pub observation: VmmObservation,
}

pub struct VmmObservation {
    pub(crate) reaper: terra_runtime::component::vmm::virtualization::VcpuReaper,
    pub(crate) lifecycle: terra_runtime::component::vmm::lifecycle::LifecycleNotifier,
    pub(crate) deadline: Option<Duration>,
    pub(crate) failure: terra_runtime::component::vmm::mmio::FailureObservation,
    pub(crate) teardown: terra_runtime::component::vmm::teardown::NativeTeardown,
}

impl VmmObservation {
    pub async fn observe(
        self,
        runtime: terra_runtime::box_runtime::BoxRuntimeHandle,
    ) -> Result<WorkerOutcome, String> {
        use terra_runtime::component::vmm::lifecycle::{Outcome, wait_for_outcome};

        let outcome = wait_for_outcome(
            &mut self.lifecycle.subscribe(),
            self.deadline,
            &self.lifecycle,
        )
        .await;
        let shutdown_deadline = self.lifecycle.begin_shutdown();
        let cleanup = self.teardown.wait_until(shutdown_deadline).await;
        let runtime = finish_component_runtime(runtime, cleanup, shutdown_deadline).await;
        let outcome = outcome.map_err(|error| format!("VMM lifecycle: {error:?}"))?;
        let exit_code = match outcome {
            Outcome::GuestExit(code) => Some(code),
            Outcome::VcpuFinished | Outcome::Deadline => None,
            Outcome::ComponentFailed => {
                return Err(self
                    .failure
                    .failure()
                    .unwrap_or_else(|| "VMM component failed".to_owned()));
            }
        };
        let vcpu_outcomes = self.reaper.wait_until(shutdown_deadline).await?;
        runtime?;
        Ok(WorkerOutcome {
            exit_code,
            vcpu_outcomes,
        })
    }
}

#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ),
    all(target_os = "macos", target_arch = "aarch64"),
    target_os = "windows",
))]
pub async fn prepare(input: WorkerInput) -> Result<PreparedVmm, String> {
    prepare_native(input)
        .await
        .map_err(|error| format!("{error:?}"))
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub async fn prepare(_input: WorkerInput) -> Result<PreparedVmm, String> {
    Err("macOS on Intel is unsupported".to_owned())
}

#[cfg(test)]
pub async fn run(input: WorkerInput) -> Result<WorkerOutcome, String> {
    let PreparedVmm {
        runtime,
        observation,
    } = prepare(input).await?;
    observation.observe(runtime.start()).await
}

pub(crate) async fn finish_component_runtime(
    runtime: terra_runtime::box_runtime::BoxRuntimeHandle,
    cleanup: Result<(), String>,
    deadline: std::time::Instant,
) -> Result<(), String> {
    match cleanup {
        Ok(()) => runtime
            .join_until(deadline.into())
            .await
            .map_err(|error| error.to_string()),
        Err(error) => {
            runtime.abort_and_join_until(deadline.into()).await;
            Err(error)
        }
    }
}

pub(crate) fn blocks(
    runtime: &mut terra_runtime::box_runtime::BoxRuntime,
    ram: impl Into<terra_runtime::component::vmm::virtualization::RamGrant> + Send,
    input: &mut WorkerInput,
    disks: &[(PathBuf, bool)],
    interrupt: impl Fn(usize) -> Result<terra_runtime::component::block::Interrupt, String>,
) -> Result<Vec<terra_runtime::component::DeviceChannel>, String> {
    use terra_runtime::component::block::backing::{DiskGrant, FileDisk};
    use terra_runtime::component::block::host::BlockHost;

    let component = input
        .artifacts
        .block()
        .deserialize(runtime.store.engine())
        .map_err(|error| error.to_string())?;
    let disks = disks
        .iter()
        .map(|(path, readonly)| {
            FileDisk::open(path, *readonly)
                .map(|disk| (DiskGrant::File(disk), *readonly))
                .map_err(|error| format!("opening block backing {}: {error}", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let boot_disk = DiskGrant::Mem(
        terra_runtime::component::block::backing::BoundedDisk::from_readonly_bytes(std::mem::take(
            &mut input.boot_disk,
        )),
    );
    let disks = std::iter::once((boot_disk, true)).chain(disks);
    let ram = ram.into();
    let mut channels = Vec::with_capacity(2 + input.volume_disks.len());
    for (index, (disk, readonly)) in disks.enumerate() {
        let ram = ram.clone();
        let host = move || Ok(BlockHost::new(ram.resolve()?, disk));
        let channel = terra_runtime::component::block::grant_shared(
            runtime,
            host,
            &component,
            readonly,
            interrupt(index)?,
        )
        .map_err(|error| error.to_string())?;
        channels.push(channel);
    }
    Ok(channels)
}

pub(crate) fn network(
    runtime: &mut terra_runtime::box_runtime::BoxRuntime,
    ram: impl Into<terra_runtime::component::vmm::virtualization::RamGrant> + Send,
    input: &WorkerInput,
    interrupt: terra_runtime::component::network::Interrupt,
) -> Result<terra_runtime::component::DeviceChannel, String> {
    use terra_runtime::component::context::DeviceContext;

    let component = input
        .artifacts
        .network()
        .deserialize(runtime.store.engine())
        .map_err(|error| error.to_string())?;
    let ram = ram.into();
    terra_runtime::component::network::grant_shared(
        runtime,
        move || Ok(DeviceContext::with_ram(ram.resolve()?)),
        &component,
        input.network_policy.clone(),
        input.port_mappings.clone(),
        terra_network::GuestNetworkConfig::default(),
        interrupt,
    )
    .map_err(|error| error.to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn filesystems(
    runtime: &mut terra_runtime::box_runtime::BoxRuntime,
    ram: impl Into<terra_runtime::component::vmm::virtualization::RamGrant> + Send,
    input: &WorkerInput,
    interrupt: impl Fn(usize) -> Result<terra_runtime::component::network::Interrupt, String>,
) -> Result<Vec<terra_runtime::component::DeviceChannel>, String> {
    use terra_runtime::component::context::DeviceContext;

    if input.shares.is_empty() {
        return Ok(Vec::new());
    }
    let component = input
        .artifacts
        .fs()
        .deserialize(runtime.store.engine())
        .map_err(|error| error.to_string())?;
    let ram = ram.into();
    let mut channels = Vec::with_capacity(input.shares.len());
    let resource_capacity = filesystem_resource_capacity(input.shares.len());
    let max_nodes = u32::try_from(resource_capacity.saturating_sub(16) / 2).unwrap_or(u32::MAX);
    if max_nodes == 0 {
        return Err(
            "file descriptor limit is too low for configured shares; raise the host open-file limit or reduce shares"
                .into(),
        );
    }
    let mut grants = input.shares.clone();
    terra_runtime::component::fs::host::share_notification_budgets(&mut grants);
    for (index, grant) in grants.into_iter().enumerate() {
        let ram = ram.clone();
        let host = move || {
            Ok(
                terra_runtime::component::fs::host::FsHost::with_resource_capacity(
                    DeviceContext::with_ram(ram.resolve()?),
                    grant,
                    resource_capacity,
                ),
            )
        };
        let channel = terra_runtime::component::fs::grant_shared(
            runtime,
            host,
            &component,
            &terra_runtime::component::fs::host::share_tag(index),
            max_nodes,
            interrupt(index)?,
        )
        .map_err(|error| error.to_string())?;
        channels.push(channel);
    }
    Ok(channels)
}

fn filesystem_resource_capacity(shares: usize) -> usize {
    #[cfg(unix)]
    let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile)
        .current
        .unwrap_or(terra_limits::MAX_VM_OPEN_FILES as u64)
        .min(terra_limits::MAX_VM_OPEN_FILES as u64);
    #[cfg(not(unix))]
    let limit = terra_limits::MAX_VM_OPEN_FILES as u64;
    filesystem_resource_capacity_for(usize::try_from(limit).unwrap_or(usize::MAX), shares)
}

fn filesystem_resource_capacity_for(limit: usize, shares: usize) -> usize {
    const FIXED_HEADROOM: usize = 128;

    limit.saturating_sub(FIXED_HEADROOM) / 4 * 3 / shares
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn memory(
    runtime: &mut terra_runtime::box_runtime::BoxRuntime,
    ram: impl Into<terra_runtime::component::vmm::virtualization::RamGrant> + Send,
    input: &WorkerInput,
    interrupt: terra_runtime::component::network::Interrupt,
) -> Result<terra_runtime::component::DeviceChannel, String> {
    use terra_runtime::component::context::DeviceContext;

    let component = input
        .artifacts
        .mem()
        .deserialize(runtime.store.engine())
        .map_err(|error| error.to_string())?;
    let ram = ram.into();
    let host = move || Ok(DeviceContext::with_ram(ram.resolve()?));
    terra_runtime::component::mem::grant_shared(runtime, host, &component, interrupt)
        .map_err(|error| error.to_string())
}

pub(crate) fn vsock(
    runtime: &mut terra_runtime::box_runtime::BoxRuntime,
    ram: impl Into<terra_runtime::component::vmm::virtualization::RamGrant> + Send,
    input: &mut WorkerInput,
    interrupt: terra_runtime::component::network::Interrupt,
) -> Result<terra_runtime::component::vsock::VsockChannel, String> {
    let listener = input.listener.take();
    let control = input.control.take();
    let diagnostics = input.diagnostics.take();
    terra_runtime::component::vsock::VsockChannel::from_trusted_artifact(
        runtime,
        ram,
        input.artifacts.vsock(),
        std::mem::take(&mut input.plan),
        listener,
        control,
        diagnostics,
        interrupt,
    )
    .map_err(|error| error.to_string())
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use crate::linux::kvm::aarch64::worker::prepare as prepare_native;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::linux::kvm::amd64::worker::prepare as prepare_native;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use crate::macos::aarch64::worker::prepare as prepare_native;
#[cfg(target_os = "windows")]
use crate::windows::worker::prepare as prepare_native;

#[cfg(test)]
mod tests {
    #[test]
    fn filesystem_resources_stay_within_the_vm_file_limit() {
        assert_eq!(super::filesystem_resource_capacity_for(4096, 1), 2976);
        assert_eq!(super::filesystem_resource_capacity_for(4096, 32), 93);
        assert_eq!(super::filesystem_resource_capacity_for(128, 32), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)]
    async fn prepared_vmm_observes_wasi_startup_and_shutdown() {
        use std::sync::Arc;
        use terra_runtime::component::vmm::machine::{Device, DeviceKind};
        use terra_runtime::component::vmm::virtualization::{Architecture, MachineConfig};

        use terra_runtime::component::context::DeviceContext;
        use terra_runtime::component::vmm::virtualization::{
            PreparedMachine, StartedVcpus, VirtualMachine,
        };

        struct TestVm(terra_runtime::memory::GuestRam);
        impl VirtualMachine for TestVm {
            fn memory(&self) -> wasmtime::Result<terra_runtime::memory::GuestRam> {
                Ok(self.0.clone())
            }
        }
        let engine = terra_runtime::engine::device_engine().unwrap();
        let mut runtime = terra_runtime::box_runtime::BoxRuntime::new(
            &engine,
            terra_runtime::box_runtime::store::BoxHost::new(),
        )
        .unwrap();
        let component = wasmtime::component::Component::new(
            &engine,
            include_bytes!(
                "../../../components/target/wasm32-wasip3/release/terra_vmm_component.wasm"
            ),
        )
        .unwrap();
        let devices = [
            (DeviceKind::Block, 11),
            (DeviceKind::Block, 12),
            (DeviceKind::Net, 13),
            (DeviceKind::Vsock, 14),
            (DeviceKind::Memory, 15),
        ]
        .into_iter()
        .zip(0..)
        .map(|((kind, irq), slot)| Device {
            kind,
            irq,
            mmio_base: 0xd000_0000 + slot * 0x1000,
        })
        .collect();
        let config = MachineConfig::new(Architecture::X86, 8 << 20, 1, devices).unwrap();
        let mut prepared = PreparedMachine::new(
            config,
            TestVm(terra_runtime::memory::GuestRam::new(8 << 20).unwrap()),
        );
        let mut kernel = vec![0; 512];
        kernel[..4].copy_from_slice(b"\x7fELF");
        kernel[4] = 2;
        kernel[5] = 1;
        kernel[18..20].copy_from_slice(&62_u16.to_le_bytes());
        kernel[24..32].copy_from_slice(&0x10_0000_u64.to_le_bytes());
        kernel[32..40].copy_from_slice(&64_u64.to_le_bytes());
        kernel[56..58].copy_from_slice(&1_u16.to_le_bytes());
        kernel[64..68].copy_from_slice(&1_u32.to_le_bytes());
        kernel[72..80].copy_from_slice(&0x100_u64.to_le_bytes());
        kernel[88..96].copy_from_slice(&0x10_0000_u64.to_le_bytes());
        kernel[96..104].copy_from_slice(&16_u64.to_le_bytes());
        kernel[104..112].copy_from_slice(&32_u64.to_le_bytes());
        let boot = wasmtime::component::Component::new(
            &engine,
            include_bytes!(
                "../../../components/target/wasm32-wasip3/release/terra_boot_component.wasm"
            ),
        )
        .unwrap();
        let entry = runtime
            .boot_prepared_machine(
                &boot,
                prepared.config(),
                prepared.ram().unwrap(),
                kernel,
                "",
            )
            .await
            .unwrap();
        prepared.accept_boot(entry).unwrap();
        runtime.initialize_mmio(&component).await.unwrap();
        let (mut runtime, machine) = runtime.attach_machine(prepared).await.unwrap();
        let component = wasmtime::component::Component::new(
            &engine,
            include_bytes!(
                "../../../components/target/wasm32-wasip3/release/terra_mem_component.wasm"
            ),
        )
        .unwrap();
        let ram = machine.ram();
        let channel = terra_runtime::component::mem::grant_shared(
            &mut runtime,
            move || Ok(DeviceContext::with_ram(ram.resolve()?)),
            &component,
            Arc::new(|_| Ok(())),
        )
        .unwrap();
        let injections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let delivered = Arc::clone(&injections);
        let interrupt = machine
            .bind_interrupt(
                terra_runtime::component::vmm::machine::DeviceKind::Memory,
                0,
                move |_, irq, level| {
                    assert_eq!(irq, 15);
                    assert!(level);
                    delivered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                },
            )
            .unwrap();
        let _ = machine.machine();
        let denied = machine.bind_interrupt(
            terra_runtime::component::vmm::machine::DeviceKind::Memory,
            1,
            |_, _, _| panic!("ungranted interrupt"),
        );
        assert!(denied.is_err());
        let failure = runtime.mmio_failure_observation().unwrap();
        let startup_interrupt = Arc::clone(&interrupt);
        let (runtime, startup) = runtime
            .prepare_vcpus(move |controls, _| {
                startup_interrupt(true)?;
                Ok(StartedVcpus::new(
                    controls,
                    || Ok(()),
                    |controls| {
                        drop(controls);
                        Ok(vec![Ok(())])
                    },
                ))
            })
            .await
            .unwrap();
        let lifecycle = runtime.lifecycle_notifier();
        let teardown = runtime.native_teardown();
        let prepared = super::PreparedVmm {
            runtime,
            observation: super::VmmObservation {
                reaper: startup,
                lifecycle: lifecycle.clone(),
                deadline: None,
                failure,
                teardown,
            },
        };
        let _ = machine.machine();
        let running = prepared.runtime.start();
        lifecycle.guest_exit(7);
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            prepared.observation.observe(running),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(outcome.exit_code, Some(7));
        assert_eq!(outcome.vcpu_outcomes, vec![Ok(())]);
        let _ = machine.machine();
        assert!(machine.ram().resolve().is_ok());

        assert_eq!(injections.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(channel.read(0, 4).is_err());
    }

    #[tokio::test]
    async fn timed_out_device_close_does_not_start_later_devices() {
        use terra_runtime::component::vmm::{machine::DeviceKind, teardown::DeviceShutdown};

        let (release, released) = std::sync::mpsc::channel();
        let (second_started, second_started_receiver) = std::sync::mpsc::channel();
        let first = DeviceShutdown::new(DeviceKind::Memory, async move {
            released.recv().expect("release first device");
            Ok(())
        });
        let second = DeviceShutdown::new(DeviceKind::Block, async move {
            second_started.send(()).expect("record second device");
            Ok(())
        });

        let engine = terra_runtime::engine::device_engine().unwrap();
        let mut runtime = terra_runtime::box_runtime::BoxRuntime::new(
            &engine,
            terra_runtime::box_runtime::store::BoxHost::new(),
        )
        .unwrap();
        runtime.add_device_shutdown(first).unwrap();
        runtime.add_device_shutdown(second).unwrap();
        let teardown = runtime.native_teardown();
        assert_eq!(
            teardown
                .wait_until(std::time::Instant::now() + std::time::Duration::from_millis(20))
                .await,
            Err("native task timed out".to_owned())
        );
        assert!(matches!(
            second_started_receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        release.send(()).expect("release first device");
        assert_eq!(
            teardown
                .wait_until(std::time::Instant::now() + std::time::Duration::from_secs(2))
                .await,
            Ok(())
        );
        second_started_receiver
            .recv()
            .expect("second device closes after the first");
    }

    struct DenyAll;

    impl terra_network::Policy for DenyAll {
        fn allows(&self, _: std::net::IpAddr, _: Option<u16>) -> bool {
            false
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn empty_shares_do_not_load_the_filesystem_artifact() {
        // SAFETY: every field is trusted AOT output for this Wasmtime build.
        // A block artifact in the filesystem field proves that it is not used.
        #[allow(unsafe_code)]
        let artifacts = unsafe {
            terra_runtime::TrustedArtifacts::new(
                include_bytes!("../../../build/terra-block-component.cwasm"),
                include_bytes!("../../../build/terra-vsock-component.cwasm"),
                include_bytes!("../../../build/terra-network-component.cwasm"),
                include_bytes!("../../../build/terra-block-component.cwasm"),
                include_bytes!("../../../build/terra-mem-component.cwasm"),
                include_bytes!("../../../build/terra-boot-component.cwasm"),
                include_bytes!("../../../build/terra-vmm-component.cwasm"),
            )
        };
        let input = super::WorkerInput {
            component_memory_limits:
                terra_runtime::box_runtime::store::ComponentMemoryLimits::default(),
            kernel: Vec::new(),
            boot_disk: Vec::new(),
            root_disk: std::path::PathBuf::new(),
            volume_disks: Vec::new(),
            shares: Vec::new(),
            plan: Vec::new(),
            artifacts,
            network_policy: std::sync::Arc::new(DenyAll),
            port_mappings: Vec::new(),
            ram_bytes: 4096,
            vcpus: 1,
            deadline: None,
            hard_stop: None,
            listener: None,
            control: None,
            diagnostics: None,
        };
        let engine = terra_runtime::engine::device_engine().unwrap();
        let mut runtime = terra_runtime::box_runtime::BoxRuntime::new(
            &engine,
            terra_runtime::box_runtime::store::BoxHost::new(),
        )
        .unwrap();
        let shares = super::filesystems(
            &mut runtime,
            terra_runtime::memory::GuestRam::new(4096).unwrap(),
            &input,
            |_| Ok(std::sync::Arc::new(|_| Ok(()))),
        )
        .unwrap();
        assert!(shares.is_empty());
    }
}
