//! Shared worker input, observed guest lifecycle, and platform entrypoint.

use std::path::PathBuf;
use std::time::Duration;

pub use crate::TrustedArtifacts;
#[cfg(target_arch = "aarch64")]
pub use crate::aarch64::arm::MAX_VCPUS;
#[cfg(target_arch = "x86_64")]
pub use crate::amd64::machine::MAX_VCPUS;

/// Resources supplied to one platform VM worker.
pub struct WorkerInput {
    pub kernel: Vec<u8>,
    pub boot_disk: PathBuf,
    pub root_disk: PathBuf,
    pub volume_disks: Vec<PathBuf>,
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub shares: Vec<crate::component::fs::host::ShareGrant>,
    pub plan: Vec<u8>,
    pub artifacts: crate::TrustedArtifacts,
    pub network_policy: terra_network::PolicyHandle,
    pub port_mappings: Vec<terra_network::PortMapping>,
    pub ram_bytes: u64,
    pub component_memory_limits: terra_runtime::box_runtime::ComponentMemoryLimits,
    pub vcpus: usize,
    pub deadline: Option<Duration>,
    pub hard_stop: Option<fn() -> !>,
    pub listener: Option<terra_io::local::LocalListener>,
    pub control: Option<terra_io::local::LocalStream>,
    pub diagnostics: Option<std::fs::File>,
}

pub(crate) fn create_runtime(
    input: &WorkerInput,
) -> wasmtime::Result<crate::box_runtime::BoxRuntime> {
    crate::box_runtime::BoxRuntime::new(
        &crate::engine::device_engine()?,
        crate::box_runtime::BoxHost::with_memory_limits(input.component_memory_limits),
    )
}

#[allow(unsafe_code)]
pub(crate) async fn boot_prepared<
    M: terra_runtime::component::vmm::virtualization::VirtualMachine,
>(
    runtime: &mut crate::box_runtime::BoxRuntime,
    mut prepared: terra_runtime::component::vmm::virtualization::PreparedMachine<M>,
    input: &mut WorkerInput,
) -> wasmtime::Result<terra_runtime::component::vmm::virtualization::MachineHandle<M>> {
    // SAFETY: TrustedArtifacts admits only build-embedded AOT output for this runtime.
    let boot = unsafe {
        wasmtime::component::Component::deserialize(runtime.store.engine(), input.artifacts.boot)
    }?;
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

pub(crate) async fn assemble_devices(
    runtime: &mut crate::box_runtime::BoxRuntime,
    input: &mut WorkerInput,
    ram: terra_runtime::component::vmm::virtualization::RamGrant,
    disks: &[(PathBuf, bool)],
    bind_interrupt: impl Fn(
        terra_runtime::component::vmm::machine::DeviceKind,
        usize,
    ) -> crate::component::network::Interrupt,
) -> Result<Vec<MmioDevice>, String> {
    use terra_runtime::component::vmm::machine::DeviceKind;
    let blocks = blocks(runtime, ram.clone(), input, disks, |index| {
        bind_interrupt(DeviceKind::Block, index)
    })
    .await?;
    let filesystems = filesystems(runtime, ram.clone(), input, |index| {
        bind_interrupt(DeviceKind::Fs, index)
    })
    .await?;
    let memory = memory(
        runtime,
        ram.clone(),
        input,
        bind_interrupt(DeviceKind::Memory, 0),
    )
    .await?;
    let network = network(
        runtime,
        ram.clone(),
        input,
        bind_interrupt(DeviceKind::Net, 0),
    )
    .await?;
    let vsock = vsock(runtime, ram, input, bind_interrupt(DeviceKind::Vsock, 0)).await?;
    let mut devices = blocks
        .into_iter()
        .map(MmioDevice::Block)
        .collect::<Vec<_>>();
    devices.extend(filesystems.into_iter().map(MmioDevice::Filesystem));
    devices.push(MmioDevice::Memory(memory));
    devices.push(MmioDevice::Network(network));
    devices.push(MmioDevice::Vsock(vsock));
    Ok(devices)
}

pub(crate) fn disk_paths(input: &WorkerInput) -> Vec<(PathBuf, bool)> {
    let mut disks = Vec::with_capacity(2 + input.volume_disks.len());
    disks.push((input.boot_disk.clone(), true));
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
    pub runtime: crate::box_runtime::BoxRuntime,
    pub observation: VmmObservation,
}

pub struct VmmObservation {
    pub(crate) reaper: terra_runtime::component::vmm::virtualization::VcpuReaper,
    pub(crate) lifecycle: terra_runtime::component::vmm::lifecycle::LifecycleNotifier,
    pub(crate) deadline: Option<Duration>,
    pub(crate) devices: Vec<MmioDevice>,
    pub(crate) shutdowns: Vec<terra_runtime::component::vmm::teardown::DeviceShutdown>,
    pub(crate) interrupts: Option<terra_runtime::component::vmm::teardown::NativeCleanup>,
}

impl VmmObservation {
    pub async fn observe(
        self,
        runtime: crate::box_runtime::BoxRuntimeHandle,
    ) -> Result<WorkerOutcome, String> {
        use terra_runtime::component::vmm::lifecycle::{Outcome, wait_for_outcome};

        let outcome = wait_for_outcome(
            &mut self.lifecycle.subscribe(),
            self.deadline,
            &self.lifecycle,
        )
        .await;
        let vcpu_outcomes = self.reaper.wait().await;
        let device_cleanup = finish_device_shutdown(&self.shutdowns).await;
        let interrupt_cleanup = match self.interrupts {
            Some(interrupts) => interrupts.wait().await,
            None => Ok(()),
        };
        let cleanup =
            finish_component_runtime(runtime, device_cleanup.and(interrupt_cleanup)).await;
        let vcpu_outcomes = vcpu_outcomes?;
        let exit_code = match outcome.map_err(|error| format!("VMM lifecycle: {error:?}"))? {
            Outcome::GuestExit(code) => Some(code),
            Outcome::VcpuFinished | Outcome::Deadline => None,
            Outcome::ComponentFailed => {
                return Err(self
                    .devices
                    .iter()
                    .find_map(MmioDevice::failure)
                    .unwrap_or_else(|| "VMM component failed".to_owned()));
            }
        };
        cleanup?;
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
    runtime: crate::box_runtime::BoxRuntimeHandle,
    cleanup: Result<(), String>,
) -> Result<(), String> {
    match cleanup {
        Ok(()) => runtime.join().await.map_err(|error| error.to_string()),
        Err(error) => {
            runtime.abort_and_join().await;
            Err(error)
        }
    }
}

pub(crate) fn grant_device_shutdown(
    runtime: &mut crate::box_runtime::BoxRuntime,
    devices: &[MmioDevice],
) -> Result<Vec<terra_runtime::component::vmm::teardown::DeviceShutdown>, String> {
    use terra_runtime::component::vmm::{machine::DeviceKind, teardown::DeviceShutdown};

    let shutdowns = devices
        .iter()
        .cloned()
        .map(|device| {
            let kind = match &device {
                MmioDevice::Block(_) => DeviceKind::Block,
                MmioDevice::Filesystem(_) => DeviceKind::Fs,
                MmioDevice::Memory(_) => DeviceKind::Memory,
                MmioDevice::Vsock(_) => DeviceKind::Vsock,
                MmioDevice::Network(_) => DeviceKind::Net,
            };
            DeviceShutdown::new(kind, move || device.close())
        })
        .collect::<Vec<_>>();
    runtime
        .grant_device_shutdown(shutdowns.clone())
        .map_err(|error| error.to_string())?;
    Ok(shutdowns)
}

pub(crate) async fn finish_device_shutdown(
    devices: &[terra_runtime::component::vmm::teardown::DeviceShutdown],
) -> Result<(), String> {
    let mut first_error = None;
    for device in devices {
        if let Err(error) = device.wait().await {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

#[allow(unsafe_code)]
pub(crate) async fn blocks(
    runtime: &mut crate::box_runtime::BoxRuntime,
    ram: impl Into<terra_runtime::component::vmm::virtualization::RamGrant> + Send,
    input: &WorkerInput,
    disks: &[(PathBuf, bool)],
    interrupt: impl Fn(usize) -> crate::component::block::Interrupt,
) -> Result<Vec<crate::component::DeviceChannel>, String> {
    use crate::component::block::backing::FileDisk;
    use crate::engine::{DeviceHost, DiskGrant, trusted_component};

    // SAFETY: TrustedArtifacts admits only build-embedded AOT output for this runtime.
    let component = unsafe { trusted_component(runtime.store.engine(), input.artifacts.block) }
        .map_err(|error| error.to_string())?;
    let disks = disks
        .iter()
        .map(|(path, readonly)| {
            FileDisk::open(path, *readonly)
                .map(|disk| (disk, *readonly))
                .map_err(|error| format!("opening block backing {}: {error}", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let ram = ram.into();
    let mut channels = Vec::with_capacity(disks.len());
    for (index, (disk, readonly)) in disks.into_iter().enumerate() {
        let ram = ram.clone();
        let host = move || {
            let mut host = DeviceHost::with_ram(ram.resolve()?);
            host.set_disk(DiskGrant::File(disk));
            Ok(host)
        };
        channels.push(
            crate::component::block::grant_shared(
                runtime,
                host,
                &component,
                readonly,
                interrupt(index),
            )
            .await
            .map_err(|error| error.to_string())?,
        );
    }
    Ok(channels)
}

#[allow(unsafe_code)]
pub(crate) async fn network(
    runtime: &mut crate::box_runtime::BoxRuntime,
    ram: impl Into<terra_runtime::component::vmm::virtualization::RamGrant> + Send,
    input: &WorkerInput,
    interrupt: crate::component::network::Interrupt,
) -> Result<crate::component::DeviceChannel, String> {
    use crate::engine::{DeviceHost, trusted_component};

    // SAFETY: TrustedArtifacts admits only build-embedded AOT output for this runtime.
    let component = unsafe { trusted_component(runtime.store.engine(), input.artifacts.network) }
        .map_err(|error| error.to_string())?;
    let ram = ram.into();
    crate::component::network::grant_shared(
        runtime,
        move || Ok(DeviceHost::with_ram(ram.resolve()?)),
        &component,
        input.network_policy.clone(),
        input.port_mappings.clone(),
        terra_network::GuestNetworkConfig::default(),
        interrupt,
    )
    .await
    .map_err(|error| error.to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[allow(unsafe_code)]
pub(crate) async fn filesystems(
    runtime: &mut crate::box_runtime::BoxRuntime,
    ram: impl Into<terra_runtime::component::vmm::virtualization::RamGrant> + Send,
    input: &WorkerInput,
    interrupt: impl Fn(usize) -> crate::component::network::Interrupt,
) -> Result<Vec<crate::component::DeviceChannel>, String> {
    use crate::engine::{DeviceHost, trusted_component};

    if input.shares.is_empty() {
        return Ok(Vec::new());
    }
    // SAFETY: TrustedArtifacts admits only build-embedded AOT output for this runtime.
    let component = unsafe { trusted_component(runtime.store.engine(), input.artifacts.fs) }
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
    for (index, grant) in input.shares.iter().cloned().enumerate() {
        let ram = ram.clone();
        let host = move || {
            Ok(crate::component::fs::host::FsHost::with_resource_capacity(
                DeviceHost::with_ram(ram.resolve()?),
                grant,
                resource_capacity,
            ))
        };
        channels.push(
            crate::component::fs::grant_shared(
                runtime,
                host,
                &component,
                &crate::component::fs::host::share_tag(index),
                max_nodes,
                interrupt(index),
            )
            .await
            .map_err(|error| error.to_string())?,
        );
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
#[allow(unsafe_code)]
pub(crate) async fn memory(
    runtime: &mut crate::box_runtime::BoxRuntime,
    ram: impl Into<terra_runtime::component::vmm::virtualization::RamGrant> + Send,
    input: &WorkerInput,
    interrupt: crate::component::network::Interrupt,
) -> Result<crate::component::DeviceChannel, String> {
    use crate::engine::{DeviceHost, trusted_component};

    // SAFETY: TrustedArtifacts admits only build-embedded AOT output for this runtime.
    let component = unsafe { trusted_component(runtime.store.engine(), input.artifacts.mem) }
        .map_err(|error| error.to_string())?;
    let ram = ram.into();
    let host = move || {
        Ok(crate::component::mem::host::MemHost::new(
            DeviceHost::with_ram(ram.resolve()?),
        ))
    };
    crate::component::mem::grant_shared(runtime, host, &component, interrupt)
        .await
        .map_err(|error| error.to_string())
}

#[allow(unsafe_code)]
pub(crate) async fn vsock(
    runtime: &mut crate::box_runtime::BoxRuntime,
    ram: impl Into<terra_runtime::component::vmm::virtualization::RamGrant> + Send,
    input: &mut WorkerInput,
    interrupt: crate::component::network::Interrupt,
) -> Result<crate::component::vsock::VsockChannel, String> {
    let artifact = input.artifacts.vsock;
    let listener = input.listener.take();
    let control = input.control.take();
    let diagnostics = input.diagnostics.take();
    // SAFETY: TrustedArtifacts admits only build-embedded AOT output.
    unsafe {
        crate::component::vsock::VsockChannel::from_trusted_shared(
            runtime,
            ram,
            artifact,
            std::mem::take(&mut input.plan),
            true,
            listener,
            control,
            diagnostics,
            interrupt,
        )
        .await
    }
    .map_err(|error| error.to_string())
}

/// Component-backed device selected by a platform MMIO slot.
#[derive(Clone)]
pub enum MmioDevice {
    Block(crate::component::DeviceChannel),
    Filesystem(crate::component::DeviceChannel),
    Memory(crate::component::DeviceChannel),
    Vsock(crate::component::vsock::VsockChannel),
    Network(crate::component::DeviceChannel),
}

impl MmioDevice {
    pub fn close(&self) -> Result<(), String> {
        match self {
            Self::Block(channel)
            | Self::Filesystem(channel)
            | Self::Memory(channel)
            | Self::Network(channel) => channel.close(),
            Self::Vsock(channel) => channel.close(),
        }
        .map_err(|error| error.to_string())
    }

    #[must_use]
    pub fn failure(&self) -> Option<String> {
        match self {
            Self::Block(channel) if channel.request_counts().1 != 0 => {
                Some("block component failed".to_owned())
            }
            Self::Filesystem(channel) if channel.request_counts().1 != 0 => {
                Some("filesystem component failed".to_owned())
            }
            Self::Memory(channel) | Self::Network(channel) => channel.failure(),
            Self::Vsock(vsock) => vsock.failure(),
            Self::Block(_) | Self::Filesystem(_) => None,
        }
    }
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

        use terra_runtime::component::mem::host::MemHost;
        use terra_runtime::component::vmm::virtualization::{
            PreparedMachine, StartedVcpus, VirtualMachine,
        };
        use terra_runtime::engine::DeviceHost;

        struct TestVm(terra_runtime::SyntheticRam);
        impl VirtualMachine for TestVm {
            fn memory(&self) -> wasmtime::Result<terra_runtime::SyntheticRam> {
                Ok(self.0.clone())
            }
        }
        let engine = terra_runtime::engine::device_engine().unwrap();
        let mut runtime = terra_runtime::box_runtime::BoxRuntime::new(
            &engine,
            terra_runtime::box_runtime::BoxHost::new(),
        )
        .unwrap();
        let component = wasmtime::component::Component::new(
            &engine,
            include_bytes!(
                "../../../components/vmm/target/wasm32-wasip3/release/terra_vmm_component.wasm"
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
            TestVm(terra_runtime::SyntheticRam::new(8 << 20).unwrap()),
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
                "../../../components/boot/target/wasm32-wasip3/release/terra_boot_component.wasm"
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
        let machine = runtime.attach_machine(prepared).await.unwrap();
        let component = wasmtime::component::Component::new(
            &engine,
            include_bytes!(
                "../../../components/mem/target/wasm32-wasip3/release/terra_mem_component.wasm"
            ),
        )
        .unwrap();
        let ram = machine.ram();
        let channel = crate::component::mem::grant_shared(
            &mut runtime,
            move || Ok(MemHost::new(DeviceHost::with_ram(ram.resolve()?))),
            &component,
            Arc::new(|_| Ok(())),
        )
        .await
        .unwrap();
        let devices = vec![super::MmioDevice::Memory(channel.clone())];
        let shutdowns = super::grant_device_shutdown(&mut runtime, &devices).unwrap();
        let injections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let delivered = Arc::clone(&injections);
        let interrupt = machine.bind_interrupt(
            terra_runtime::component::vmm::machine::DeviceKind::Memory,
            0,
            move |_, irq, level| {
                assert_eq!(irq, 15);
                assert!(level);
                delivered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        );
        let _ = machine.machine();
        let denied = machine.bind_interrupt(
            terra_runtime::component::vmm::machine::DeviceKind::Memory,
            1,
            |_, _, _| panic!("ungranted interrupt"),
        );
        let startup_interrupt = Arc::clone(&interrupt);
        let startup = runtime
            .grant_vcpus(move |controls, _| {
                assert!(denied(true).is_err());
                startup_interrupt(true)?;
                Ok(
                    StartedVcpus::new(controls, || Ok(())).with_reaper(|controls| {
                        drop(controls);
                        Ok(vec![Ok(())])
                    }),
                )
            })
            .await
            .unwrap();
        let lifecycle = runtime.lifecycle_notifier();
        let prepared = super::PreparedVmm {
            runtime,
            observation: super::VmmObservation {
                reaper: startup,
                lifecycle: lifecycle.clone(),
                deadline: None,
                devices,
                shutdowns,
                interrupts: None,
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
            component_memory_limits: terra_runtime::box_runtime::ComponentMemoryLimits::default(),
            kernel: Vec::new(),
            boot_disk: std::path::PathBuf::new(),
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
            terra_runtime::box_runtime::BoxHost::new(),
        )
        .unwrap();
        let shares = super::filesystems(
            &mut runtime,
            terra_runtime::SyntheticRam::new(4096).unwrap(),
            &input,
            |_| std::sync::Arc::new(|_| Ok(())),
        )
        .await
        .unwrap();
        assert!(shares.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn vsock_actor_alone_publishes_interrupt_levels() {
        let plan = terra_protocol::encode_frame(&terra_protocol::Plan {
            mode: terra_protocol::PlanMode::Run,
            workdir: None,
            shares: Vec::new(),
            volumes: Vec::new(),
            net: terra_protocol::Net {
                guest_ip: "100.96.0.2".parse().unwrap(),
                prefix: 30,
                gateway: "100.96.0.1".parse().unwrap(),
                dns: "100.96.0.1".parse().unwrap(),
            },
            env: std::collections::BTreeMap::new(),
            root: false,
            sudo: Vec::new(),
            on_create: Vec::new(),
            on_start: Vec::new(),
            pre_stop: Vec::new(),
            daemons: Vec::new(),
            workload: vec!["/bin/sh".into()],
            sandbox_info: String::new(),
            workload_on_console: false,
            await_initial_session: false,
            lifecycle_protocol: terra_protocol::LifecycleProtocol::EventsV1,
            host_tz: None,
            host_time: None,
            host_seed: None,
        })
        .unwrap();
        let engine = terra_runtime::engine::device_engine().unwrap();
        let mut runtime = terra_runtime::box_runtime::BoxRuntime::new(
            &engine,
            terra_runtime::box_runtime::BoxHost::new(),
        )
        .unwrap();
        // SAFETY: the artifact is embedded from the trusted build.
        #[allow(unsafe_code)]
        let channel = unsafe {
            terra_runtime::component::vsock::VsockChannel::from_trusted_shared(
                &mut runtime,
                terra_runtime::SyntheticRam::new(4096).unwrap(),
                include_bytes!("../../../build/terra-vsock-component.cwasm"),
                plan,
                false,
                None,
                None,
                None,
                std::sync::Arc::new(|_| Ok(())),
            )
            .await
        }
        .unwrap();
        let runtime_task = runtime.start();
        let device = channel;
        assert_eq!(
            device.read_mmio(0, 4).unwrap(),
            0x7472_6976_u32.to_le_bytes()
        );
        device.write_mmio(0x70, &0_u32.to_le_bytes()).unwrap();
        device.close_async().await.unwrap();
        runtime_task.join().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn filesystem_actor_alone_publishes_interrupt_levels() {
        use terra_runtime::component::fs::host::{FsHost, ShareGrant};
        use terra_runtime::engine::{DeviceHost, device_engine};

        let directory = tempfile::tempdir().unwrap();
        let mount = std::fs::canonicalize(directory.path()).unwrap();
        let engine = device_engine().unwrap();
        let component = wasmtime::component::Component::new(
            &engine,
            include_bytes!(
                "../../../components/fs/target/wasm32-wasip3/release/terra_fs_component.wasm"
            ),
        )
        .unwrap();
        let host = FsHost::new(
            DeviceHost::new(64 * 1024).unwrap(),
            ShareGrant::new(&mount, false).unwrap(),
        );
        let channel = crate::component::fs::instantiate(
            wasmtime::Store::new(&engine, host),
            &component,
            "test",
            8192,
            std::sync::Arc::new(|_| Ok(())),
        )
        .await
        .unwrap();
        let device = channel;
        assert_eq!(device.read(0, 4).unwrap(), 0x7472_6976_u32.to_le_bytes());
        device.write(0x70, &0_u32.to_le_bytes()).unwrap();
        device.close().unwrap();
    }
}
