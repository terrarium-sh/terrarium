//! VM component orchestration and guest device assembly.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use terra_platform::io::local::{LocalListener, LocalStream};
use terra_platform::vm::{self, GicConfig, InterruptControllerConfig, InterruptMode, VmConfig};

pub(crate) mod devices;

pub const MAX_VCPUS: usize = if cfg!(target_arch = "aarch64") {
    terra_limits::ARM_MAX_VCPUS as usize
} else {
    terra_limits::X86_MAX_VCPUS as usize
};

pub struct WorkerInput {
    pub kernel: Vec<u8>,
    pub boot_disk: Vec<u8>,
    pub root_disk: PathBuf,
    pub volume_disks: Vec<PathBuf>,
    pub shares: Vec<crate::component::fs::ShareGrant>,
    pub plan: Vec<u8>,
    pub artifacts: crate::TrustedArtifacts,
    pub network_policy: terra_network::PolicyHandle,
    pub port_mappings: Vec<terra_network::PortMapping>,
    pub ram_bytes: u64,
    pub component_memory_limits: crate::box_runtime::ComponentMemoryLimits,
    pub vcpus: usize,
    pub deadline: Option<Duration>,
    pub hard_stop: Option<fn() -> !>,
    pub listener: Option<LocalListener>,
    pub control: Option<LocalStream>,
    pub diagnostics: Option<std::fs::File>,
}

pub type VcpuResult = Result<(), String>;

#[derive(Debug)]
pub struct WorkerOutcome {
    pub exit_code: Option<i32>,
    pub vcpu_outcomes: Vec<VcpuResult>,
}

pub struct PreparedVmm {
    pub runtime: crate::box_runtime::PreparedBoxRuntime,
    pub observation: VmmObservation,
}

pub struct VmmObservation {
    reaper: crate::component::vmm::VcpuReaper,
    lifecycle: crate::component::vmm::lifecycle::LifecycleNotifier,
    deadline: Option<Duration>,
    failure: crate::component::vmm::mmio::FailureObservation,
    teardown: crate::component::vmm::teardown::NativeTeardown,
}

#[allow(clippy::needless_return, clippy::too_many_lines)]
pub async fn prepare(mut input: WorkerInput) -> Result<PreparedVmm, String> {
    let disks = devices::disk_paths(&input);
    let layout =
        crate::machine::build_machine_layout(input.ram_bytes, 1 + disks.len(), input.shares.len())
            .map_err(|error| format!("invalid guest layout: {error:?}"))?;
    let config = layout
        .machine_config(input.vcpus)
        .map_err(|error| error.to_string())?;
    let native_config = VmConfig {
        ram_base: match layout.architecture() {
            crate::component::vmm::Architecture::X86 => 0,
            crate::component::vmm::Architecture::Arm => terra_limits::ARM_RAM_BASE,
        },
        ram_bytes: input.ram_bytes,
        vcpus: u8::try_from(input.vcpus).map_err(|_| "vCPU count exceeds platform limit")?,
        interrupt_controller: match layout.architecture() {
            crate::component::vmm::Architecture::X86 => InterruptControllerConfig::X86,
            crate::component::vmm::Architecture::Arm => InterruptControllerConfig::Arm(GicConfig {
                distributor_base: terra_limits::ARM_GIC_DIST_BASE,
                distributor_size: terra_limits::ARM_GIC_DIST_SIZE,
                redistributor_base: terra_limits::ARM_GIC_REDIST_BASE,
                redistributor_size: terra_limits::ARM_GIC_REDIST_SIZE,
            }),
        },
        irq_routes: layout.devices().iter().map(|device| device.irq).collect(),
    };
    let capabilities = vm::PreparedVm::capabilities()
        .map_err(|error| format!("reading native VM capabilities: {error}"))?;
    let native = vm::PreparedVm::create(&native_config, input.hard_stop)?;
    let handle = native.handle();
    let runtime = create_runtime(&input).map_err(|error| error.to_string())?;
    let prepared = crate::component::vmm::PreparedMachine::new(config, handle);
    let (mut runtime, machine) = boot_prepared(
        runtime,
        prepared,
        &mut input,
        kernel_cmdline_for(capabilities.tsc_frequency)?,
    )
    .await
    .map_err(|error| error.to_string())?;

    let native_handle = machine.machine();
    match capabilities.interrupt_mode {
        InterruptMode::SoftwareIoapic => {
            let inject = Arc::clone(&native_handle);
            let interrupts = runtime
                .grant_ioapic(Arc::new(move |interrupt| {
                    inject
                        .request_x86_interrupt(interrupt.vector, interrupt.destination)
                        .map_err(wasmtime::Error::msg)
                }))
                .await
                .map_err(|error| error.to_string())?;
            devices::assemble_devices(
                &mut runtime,
                &mut input,
                machine.ram(),
                &disks,
                |kind, index| {
                    interrupts
                        .bind_interrupt(kind, index)
                        .map_err(|error| error.to_string())
                },
            )?;
            let ioapic = interrupts.clone();
            runtime
                .grant_interrupt_shutdown(async move {
                    interrupts.close().await.map_err(|error| error.to_string())
                })
                .map_err(|error| error.to_string())?;
            return finish_preparation(runtime, input.deadline, move |controls, boot| {
                let handlers = controls
                    .into_iter()
                    .map(|vcpu| {
                        Box::new(RuntimeVcpu::with_ioapic(vcpu, ioapic.clone()))
                            as Box<dyn vm::VcpuHandler>
                    })
                    .collect();
                start_native_vcpus(native, boot, handlers)
            })
            .await
            .map_err(|error| error.to_string());
        }
        InterruptMode::X86IrqLines => {
            let inject = Arc::clone(&native_handle);
            let interrupts = runtime
                .grant_irq_lines(move |irq, level| {
                    inject
                        .inject_interrupt(irq, level)
                        .map_err(wasmtime::Error::msg)
                })
                .await
                .map_err(|error| error.to_string())?;
            devices::assemble_devices(
                &mut runtime,
                &mut input,
                machine.ram(),
                &disks,
                |kind, index| {
                    interrupts
                        .bind_interrupt(kind, index)
                        .map_err(|error| error.to_string())
                },
            )?;
            runtime
                .grant_interrupt_shutdown(async move {
                    interrupts.close().await.map_err(|error| error.to_string())
                })
                .map_err(|error| error.to_string())?;
        }
        InterruptMode::ArmIrqLines => {
            devices::assemble_devices(
                &mut runtime,
                &mut input,
                machine.ram(),
                &disks,
                |kind, index| {
                    machine
                        .bind_interrupt(kind, index, |vm, irq, level| {
                            vm.inject_interrupt(irq, level)
                                .map_err(wasmtime::Error::msg)
                        })
                        .map_err(|error| error.to_string())
                },
            )?;
            let native_handle = Arc::clone(&native_handle);
            runtime
                .grant_interrupt_shutdown(async move { native_handle.clear_interrupts() })
                .map_err(|error| error.to_string())?;
        }
    }

    finish_preparation(runtime, input.deadline, move |controls, boot| {
        let handlers = controls
            .into_iter()
            .map(|vcpu| Box::new(RuntimeVcpu::plain(vcpu)) as Box<dyn vm::VcpuHandler>)
            .collect();
        start_native_vcpus(native, boot, handlers)
    })
    .await
    .map_err(|error| error.to_string())
}

fn start_native_vcpus(
    native: vm::PreparedVm,
    boot: crate::component::vmm::BootEntry,
    handlers: Vec<Box<dyn vm::VcpuHandler>>,
) -> wasmtime::Result<crate::component::vmm::StartedVcpus> {
    let running = native
        .start(
            vm::BootState {
                entry: boot.entry,
                boot_argument: boot.boot_argument,
            },
            handlers,
        )
        .map_err(wasmtime::Error::msg)?;
    let running = Arc::new(Mutex::new(running));
    let stopping = Arc::clone(&running);
    Ok(crate::component::vmm::StartedVcpus::new(
        running,
        move || {
            stopping
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .request_stop();
            Ok(())
        },
        |running| {
            running
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .join()
        },
    ))
}

struct RuntimeVcpu {
    native: crate::component::vmm::NativeVcpu,
    ioapic: Option<crate::component::vmm::interrupts::IoApicHandle>,
}

impl RuntimeVcpu {
    fn plain(native: crate::component::vmm::NativeVcpu) -> Self {
        Self {
            native,
            ioapic: None,
        }
    }

    fn with_ioapic(
        native: crate::component::vmm::NativeVcpu,
        ioapic: crate::component::vmm::interrupts::IoApicHandle,
    ) -> Self {
        Self {
            native,
            ioapic: Some(ioapic),
        }
    }
}

impl vm::VcpuHandler for RuntimeVcpu {
    fn exchange(&mut self, exit: vm::VcpuExit) -> Result<vm::VcpuAction, String> {
        match exit {
            vm::VcpuExit::IoApicAccess(access) => self
                .ioapic
                .as_ref()
                .ok_or("IOAPIC access on a non-x86 VM")?
                .access(access.offset, access.width, access.write, access.value)
                .map(vm::VcpuAction::IoApicValue)
                .map_err(|error| error.to_string()),
            vm::VcpuExit::IoApicEoi(vector) => {
                self.ioapic
                    .as_ref()
                    .ok_or("IOAPIC EOI on a non-x86 VM")?
                    .eoi(vector)
                    .map_err(|error| error.to_string())?;
                Ok(vm::VcpuAction::Reenter)
            }
            exit => vm::VcpuHandler::exchange(&mut self.native, exit),
        }
    }

    fn finished(&mut self, outcome: vm::VcpuOutcome) {
        vm::VcpuHandler::finished(&mut self.native, outcome);
    }
}

fn create_runtime(input: &WorkerInput) -> wasmtime::Result<crate::box_runtime::BoxRuntime> {
    crate::box_runtime::BoxRuntime::new(
        &crate::engine::device_engine()?,
        crate::box_runtime::BoxHost::with_memory_limits(input.component_memory_limits),
    )
}

async fn boot_prepared<M: crate::component::vmm::VirtualMachine>(
    mut runtime: crate::box_runtime::BoxRuntime,
    mut prepared: crate::component::vmm::PreparedMachine<M>,
    input: &mut WorkerInput,
    kernel_cmdline: String,
) -> wasmtime::Result<(
    crate::box_runtime::BoxRuntime,
    crate::component::vmm::MachineHandle<M>,
)> {
    let boot = input.artifacts.boot().deserialize(runtime.store.engine())?;
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

fn kernel_cmdline_for(frequency: Option<u64>) -> Result<String, String> {
    let Some(frequency) = frequency else {
        return Ok(terra_protocol::KERNEL_CMDLINE.to_owned());
    };
    let khz = u32::try_from(frequency / 1000)
        .map_err(|_| "native guest clock frequency exceeds kernel command-line range")?;
    if khz == 0 {
        return Err("native guest clock frequency is below one kilohertz".to_owned());
    }
    Ok(format!(
        "{} tsc_early_khz={khz}",
        terra_protocol::KERNEL_CMDLINE
    ))
}

#[cfg(test)]
pub(crate) async fn run(input: WorkerInput) -> Result<WorkerOutcome, String> {
    let PreparedVmm {
        runtime,
        observation,
    } = prepare(input).await?;
    observation.observe(runtime.start()).await
}

async fn finish_preparation(
    runtime: crate::box_runtime::BoxRuntime,
    deadline: Option<Duration>,
    start: impl FnOnce(
        Vec<crate::component::vmm::NativeVcpu>,
        crate::component::vmm::BootEntry,
    ) -> wasmtime::Result<crate::component::vmm::StartedVcpus>
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
        runtime: crate::box_runtime::BoxRuntimeHandle,
    ) -> Result<WorkerOutcome, String> {
        use crate::component::vmm::lifecycle::{Outcome, wait_for_outcome};
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

async fn finish_component_runtime(
    runtime: crate::box_runtime::BoxRuntimeHandle,
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

#[cfg(test)]
mod tests {
    #[test]
    fn kernel_cmdline_uses_the_native_clock_when_present() {
        assert_eq!(
            super::kernel_cmdline_for(Some(2_400_000)).unwrap(),
            format!("{} tsc_early_khz=2400", terra_protocol::KERNEL_CMDLINE)
        );
        assert_eq!(
            super::kernel_cmdline_for(None).unwrap(),
            terra_protocol::KERNEL_CMDLINE
        );
        assert!(super::kernel_cmdline_for(Some(0)).is_err());
        assert!(super::kernel_cmdline_for(Some(999)).is_err());
        assert!(super::kernel_cmdline_for(Some(u64::from(u32::MAX) * 1000 + 1000)).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)]
    async fn prepared_vmm_observes_wasi_startup_and_shutdown() {
        use crate::component::context::DeviceContext;
        use crate::component::vmm::{
            Architecture, Device, DeviceKind, MachineConfig, PreparedMachine, StartedVcpus,
            VirtualMachine,
        };
        use std::sync::Arc;

        struct TestVm(crate::memory::GuestRam);
        impl VirtualMachine for TestVm {
            fn memory(&self) -> wasmtime::Result<crate::memory::GuestRam> {
                Ok(self.0.clone())
            }
        }
        let engine = crate::engine::device_engine().unwrap();
        let mut runtime =
            crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new())
                .unwrap();
        let component =
            wasmtime::component::Component::new(&engine, crate::test_fixtures::wasm::VMM).unwrap();
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
        let mut machine = PreparedMachine::new(
            config,
            TestVm(crate::memory::GuestRam::new(8 << 20).unwrap()),
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
        let boot =
            wasmtime::component::Component::new(&engine, crate::test_fixtures::wasm::BOOT).unwrap();
        let entry = runtime
            .boot_prepared_machine(&boot, machine.config(), machine.ram().unwrap(), kernel, "")
            .await
            .unwrap();
        machine.accept_boot(entry).unwrap();
        runtime.initialize_mmio(&component).await.unwrap();
        let (mut runtime, machine) = runtime.attach_machine(machine).await.unwrap();
        let component =
            wasmtime::component::Component::new(&engine, crate::test_fixtures::wasm::MEM).unwrap();
        let ram = machine.ram();
        let channel = crate::component::mem::register_device_with_host_factory(
            &mut runtime,
            move || Ok(DeviceContext::with_ram(ram.resolve()?)),
            &component,
            Arc::new(|_| Ok(())),
        )
        .unwrap();
        let injections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let delivered = Arc::clone(&injections);
        let interrupt = machine
            .bind_interrupt(DeviceKind::Memory, 0, move |_, irq, level| {
                assert_eq!(irq, 15);
                assert!(level);
                delivered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .unwrap();
        assert!(
            machine
                .bind_interrupt(DeviceKind::Memory, 1, |_, _, _| panic!(
                    "ungranted interrupt"
                ))
                .is_err()
        );
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
        assert!(machine.ram().resolve().is_ok());
        assert_eq!(injections.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(channel.read(0, 4).is_err());
    }

    #[tokio::test]
    async fn timed_out_device_close_does_not_start_later_devices() {
        use crate::component::vmm::DeviceKind;
        use crate::component::vmm::teardown::DeviceShutdown;

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
        let engine = crate::engine::device_engine().unwrap();
        let mut runtime =
            crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new())
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
