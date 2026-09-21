//! Shared worker input, observed guest lifecycle, and platform entrypoint.

use std::path::PathBuf;
use std::time::Duration;

pub(crate) mod devices;

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
        crate::windows::whp::amd64::query_tsc_frequency().map_err(|error| {
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
    reaper: terra_runtime::component::vmm::virtualization::VcpuReaper,
    lifecycle: terra_runtime::component::vmm::lifecycle::LifecycleNotifier,
    deadline: Option<Duration>,
    failure: terra_runtime::component::vmm::mmio::FailureObservation,
    teardown: terra_runtime::component::vmm::teardown::NativeTeardown,
}

pub(crate) async fn finish_preparation(
    runtime: terra_runtime::box_runtime::BoxRuntime,
    deadline: Option<Duration>,
    start: impl FnOnce(
        Vec<terra_runtime::component::vmm::NativeVcpu>,
        terra_runtime::component::vmm::boot::BootEntry,
    )
        -> wasmtime::Result<terra_runtime::component::vmm::virtualization::StartedVcpus>
    + Send
    + 'static,
) -> wasmtime::Result<PreparedVmm> {
    let failure = runtime.mmio_failure_observation()?;
    let lifecycle = runtime.lifecycle_notifier();
    let (runtime, reaper) = runtime.prepare_vcpus(start).await?;
    let teardown = runtime.native_teardown();
    Ok(PreparedVmm {
        runtime,
        observation: VmmObservation {
            reaper,
            lifecycle,
            deadline,
            failure,
            teardown,
        },
    })
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

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use crate::linux::kvm::aarch64::worker::prepare as prepare_native;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::linux::kvm::amd64::worker::prepare as prepare_native;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use crate::macos::aarch64::worker::prepare as prepare_native;
#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
use crate::windows::aarch64::worker::prepare as prepare_native;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use crate::windows::amd64::worker::prepare as prepare_native;

#[cfg(test)]
mod tests {
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)]
    async fn prepared_vmm_observes_wasi_startup_and_shutdown() {
        use std::sync::Arc;
        use terra_runtime::component::vmm::bindings::machine::{Device, DeviceKind};
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
        let component =
            wasmtime::component::Component::new(&engine, crate::test_support::artifacts::wasm::VMM)
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
            crate::test_support::artifacts::wasm::BOOT,
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
        let component =
            wasmtime::component::Component::new(&engine, crate::test_support::artifacts::wasm::MEM)
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
                terra_runtime::component::vmm::bindings::machine::DeviceKind::Memory,
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
            terra_runtime::component::vmm::bindings::machine::DeviceKind::Memory,
            1,
            |_, _, _| panic!("ungranted interrupt"),
        );
        assert!(denied.is_err());
        let lifecycle = runtime.lifecycle_notifier();
        let startup_interrupt = Arc::clone(&interrupt);
        let deadline = Some(std::time::Duration::from_secs(5));
        let prepared = super::finish_preparation(runtime, deadline, move |controls, _| {
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
        let _ = machine.machine();
        assert_eq!(prepared.observation.deadline, deadline);
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
        use terra_runtime::component::vmm::bindings::machine::DeviceKind;
        use terra_runtime::component::vmm::teardown::DeviceShutdown;

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
}
