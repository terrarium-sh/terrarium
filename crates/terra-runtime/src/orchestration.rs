//! VM component orchestration and guest device assembly.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use terra_platform::io::local::{LocalListener, LocalStream};
use terra_platform::vm::{self, InterruptMode};

mod devices;
mod observation;

use observation::finish_preparation;

pub struct VmInput {
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
pub struct VmOutcome {
    pub exit_code: Option<i32>,
    pub vcpu_outcomes: Vec<VcpuResult>,
}

pub struct PreparedVm {
    runtime: crate::box_runtime::PreparedBoxRuntime,
    observation: observation::VmObservation,
}

impl PreparedVm {
    pub async fn run(self) -> Result<VmOutcome, String> {
        self.observation.observe(self.runtime.start()).await
    }
}

#[allow(clippy::needless_return, clippy::too_many_lines)]
pub async fn prepare(mut input: VmInput) -> Result<PreparedVm, String> {
    let disks = devices::disk_paths(&input);
    let layout =
        crate::machine::build_machine_layout(input.ram_bytes, 1 + disks.len(), input.shares.len())
            .map_err(|error| format!("invalid guest layout: {error:?}"))?;
    let config = layout
        .to_machine_config(input.vcpus)
        .map_err(|error| error.to_string())?;
    let native_config = config.to_native_config();
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
            let controller = input
                .artifacts
                .interrupt_controller()
                .deserialize(runtime.store.engine())
                .map_err(|error| error.to_string())?;
            let inject = Arc::clone(&native_handle);
            let interrupts = runtime
                .grant_ioapic(
                    &controller,
                    Arc::new(move |interrupt| {
                        inject
                            .request_x86_interrupt(interrupt.vector, interrupt.destination)
                            .map_err(wasmtime::Error::msg)
                    }),
                )
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
            let controller = input
                .artifacts
                .interrupt_controller()
                .deserialize(runtime.store.engine())
                .map_err(|error| error.to_string())?;
            let inject = Arc::clone(&native_handle);
            let interrupts = runtime
                .grant_irq_lines(&controller, move |irq, level| {
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
    ioapic: Option<crate::component::interrupt_controller::IoApicHandle>,
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
        ioapic: crate::component::interrupt_controller::IoApicHandle,
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

fn create_runtime(input: &VmInput) -> wasmtime::Result<crate::box_runtime::BoxRuntime> {
    crate::box_runtime::BoxRuntime::new(
        &crate::engine::device_engine()?,
        crate::box_runtime::BoxHost::with_memory_limits(input.component_memory_limits),
    )
}

async fn boot_prepared<M: crate::component::vmm::VirtualMachine>(
    mut runtime: crate::box_runtime::BoxRuntime,
    mut prepared: crate::component::vmm::PreparedMachine<M>,
    input: &mut VmInput,
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
    runtime.initialize_vmm_artifact(&input.artifacts).await?;
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
}
