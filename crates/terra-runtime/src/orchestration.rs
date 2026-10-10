//! VM component orchestration and guest device assembly.

use crate::component::network::{NetworkBackend, PortMapping};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use terra_platform::io::local::{LocalListener, LocalStream};
use terra_platform::vm::{self, InterruptMode};

mod devices;
mod observation;

use observation::finish_preparation;

pub const GUEST_BOOT_TIMEOUT: Duration = Duration::from_secs(60);

pub struct VmInput {
    pub kernel: Vec<u8>,
    pub boot_disk: Vec<u8>,
    pub root_disk: PathBuf,
    pub volume_disks: Vec<PathBuf>,
    pub shares: Vec<crate::component::fs::ShareGrant>,
    pub plan: Vec<u8>,
    pub artifacts: crate::TrustedArtifacts,
    pub network_backend: Option<NetworkBackend>,
    pub port_mappings: Vec<PortMapping>,
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
    pub async fn run(self, agent_ready: impl FnOnce() + Send) -> Result<VmOutcome, String> {
        self.observation
            .observe(self.runtime.start(), agent_ready)
            .await
    }
}

#[allow(clippy::needless_return, clippy::too_many_lines)]
pub async fn prepare(mut input: VmInput) -> Result<PreparedVm, String> {
    let disks = devices::disk_paths(&input);
    let layout =
        crate::machine::build_machine_layout(input.ram_bytes, 1 + disks.len(), input.shares.len())
            .map_err(|error| format!("invalid guest layout: {error:?}"))?;
    if input.network_backend.is_none() && !input.port_mappings.is_empty() {
        return Err("local-only VM cannot publish ports".into());
    }
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
    let lifecycle = runtime.lifecycle_notifier();
    let mmio = runtime
        .mmio
        .as_ref()
        .map(crate::component::mmio::MmioInstance::client)
        .ok_or("MMIO service missing")?;
    match capabilities.interrupt_mode {
        InterruptMode::SoftwareIoapic => {
            let controller = input
                .artifacts
                .interrupt_controller()
                .deserialize(runtime.store.engine())
                .map_err(|error| error.to_string())?;
            let inject = Arc::clone(&native_handle);
            let interrupts = runtime
                .grant_ioapic(&controller, move |interrupt| {
                    inject
                        .request_x86_interrupt(interrupt.vector, interrupt.destination)
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
                        Box::new(RuntimeVcpu::with_ioapic(
                            vcpu,
                            mmio.clone(),
                            ioapic.clone(),
                            lifecycle.clone(),
                        )) as Box<dyn vm::VcpuHandler>
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
            .map(|vcpu| {
                Box::new(RuntimeVcpu::plain(vcpu, mmio.clone(), lifecycle.clone()))
                    as Box<dyn vm::VcpuHandler>
            })
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
    log::info!(
        "terra boot_stage=vm_entry unix_time_ns={}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
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

/// Device register exits go straight to the MMIO bridge, which owns address routing; the VMM
/// component only forwarded them.
struct RuntimeVcpu {
    native: crate::component::vmm::NativeVcpu,
    mmio: crate::component::mmio::Client,
    /// At most one kick in flight per vCPU, settled before the vCPU's next device access.
    posted_write: Option<crate::component::mmio::PostedWrite>,
    ioapic: Option<crate::component::interrupt_controller::IoApicHandle>,
    lifecycle: crate::component::vmm::lifecycle::LifecycleNotifier,
}

impl RuntimeVcpu {
    fn plain(
        native: crate::component::vmm::NativeVcpu,
        mmio: crate::component::mmio::Client,
        lifecycle: crate::component::vmm::lifecycle::LifecycleNotifier,
    ) -> Self {
        Self {
            native,
            mmio,
            posted_write: None,
            ioapic: None,
            lifecycle,
        }
    }

    fn with_ioapic(
        native: crate::component::vmm::NativeVcpu,
        mmio: crate::component::mmio::Client,
        ioapic: crate::component::interrupt_controller::IoApicHandle,
        lifecycle: crate::component::vmm::lifecycle::LifecycleNotifier,
    ) -> Self {
        Self {
            native,
            mmio,
            posted_write: None,
            ioapic: Some(ioapic),
            lifecycle,
        }
    }

    fn settle_posted_write(&mut self) -> Result<(), String> {
        match self.posted_write.take() {
            Some(posted) => self.mmio.settle(&posted).map_err(|error| error.to_string()),
            None => Ok(()),
        }
    }

    fn write_device(&mut self, address: u64, width: u8, value: u64) -> Result<(), String> {
        self.settle_posted_write()?;
        match self.mmio.post_queue_notify(address, width, value) {
            Ok(Some(posted)) => {
                self.posted_write = Some(posted);
                Ok(())
            }
            Ok(None) => self
                .mmio
                .access_from_vcpu(address, width, value, true)
                .map(|_| ())
                .map_err(|error| error.to_string()),
            Err(error) => Err(error.to_string()),
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
            vm::VcpuExit::MmioRead(vm::MmioRead { address, width }) => {
                self.settle_posted_write()?;
                self.mmio
                    .access_from_vcpu(address, width, 0, false)
                    .map(vm::VcpuAction::MmioRead)
                    .map_err(|error| error.to_string())
            }
            vm::VcpuExit::MmioWrite(vm::MmioWrite {
                address,
                width,
                value,
            }) => self
                .write_device(address, width, value)
                .map(|()| vm::VcpuAction::Reenter),
            exit => vm::VcpuHandler::exchange(&mut self.native, exit),
        }
    }

    fn failed(&mut self, error: &str) {
        self.lifecycle.native_failed(error);
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
    runtime.initialize_mmio()?;
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
    use super::*;
    use crate::component::mmio::{DeviceError, Operation, Reply, Request};
    use crate::component::relay;
    use terra_platform::vm::VcpuHandler;

    fn create_device_handler() -> (
        RuntimeVcpu,
        relay::Stream<Request>,
        relay::Sink<Reply>,
        tokio::task::JoinHandle<wasmtime::Result<()>>,
    ) {
        let engine = crate::engine::device_engine().unwrap();
        let mut runtime =
            crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new())
                .unwrap();
        runtime.initialize_mmio().unwrap();
        crate::component::mmio::MmioDevice::grant_worker(
            &mut runtime,
            crate::machine::DeviceKind::Block,
            Box::new(|_| Box::pin(async { unreachable!() })),
        )
        .unwrap();
        let (native, _) = runtime.store.data_mut().platform.add_test_vcpu();
        let instance = runtime.mmio.take().unwrap();
        let handler = RuntimeVcpu::plain(native, instance.client(), runtime.lifecycle_notifier());
        assert!(
            instance
                .devices
                .set(
                    instance
                        .device_plan
                        .into_iter()
                        .map(|plan| plan.device)
                        .collect()
                )
                .is_ok()
        );
        let (request_sink, requests) = relay::channel(relay::MMIO_CAPACITY);
        let (replies, reply_stream) = relay::channel(relay::MMIO_CAPACITY);
        let bridge = crate::component::mmio::bridge::create_component_loop(
            crate::component::mmio::bridge::BridgeContext {
                devices: instance.devices,
                admission: instance.admission,
            },
            instance.sender,
            instance.receiver,
            vec![Some(crate::component::mmio::DeviceChannel {
                requests: request_sink,
                replies: reply_stream,
                sequence: 0,
            })],
        );
        let bridge = tokio::spawn(async move {
            runtime
                .store
                .run_concurrent(async |accessor| bridge(accessor).await)
                .await
                .unwrap()
        });
        (handler, requests, replies, bridge)
    }

    fn device_accesses() -> [(vm::VcpuExit, Operation, u64, u64, vm::VcpuAction); 3] {
        [
            (
                vm::VcpuExit::MmioRead(vm::MmioRead {
                    address: 0x18,
                    width: 4,
                }),
                Operation::Read,
                0x18,
                0,
                vm::VcpuAction::MmioRead(0x42),
            ),
            (
                vm::VcpuExit::MmioWrite(vm::MmioWrite {
                    address: 0x18,
                    width: 4,
                    value: 7,
                }),
                Operation::Write,
                0x18,
                7,
                vm::VcpuAction::Reenter,
            ),
            (
                vm::VcpuExit::MmioWrite(vm::MmioWrite {
                    address: 0x50,
                    width: 4,
                    value: 2,
                }),
                Operation::Write,
                0x50,
                2,
                vm::VcpuAction::Reenter,
            ),
        ]
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn next_device_access_settles_the_posted_queue_kick() {
        for (exit, operation, offset, value, expected) in device_accesses() {
            let (mut handler, mut requests, mut replies, bridge) = create_device_handler();
            assert_eq!(
                handler.exchange(vm::VcpuExit::MmioWrite(vm::MmioWrite {
                    address: 0x50,
                    width: 4,
                    value: 1,
                })),
                Ok(vm::VcpuAction::Reenter)
            );
            assert!(handler.posted_write.is_some());
            let kick = requests.next().await.unwrap();
            assert_eq!(
                (kick.operation, kick.offset, kick.width, kick.value),
                (Operation::Write, 0x50, 4, 1)
            );
            replies
                .send(Reply {
                    sequence: kick.sequence,
                    value: 0,
                    error: None,
                })
                .await
                .unwrap();
            let next_access = tokio::task::spawn_blocking(move || {
                let action = handler.exchange(exit);
                (handler, action)
            });
            let request = requests.next().await.unwrap();
            assert_eq!(
                (
                    request.operation,
                    request.offset,
                    request.width,
                    request.value
                ),
                (operation, offset, 4, value)
            );
            replies
                .send(Reply {
                    sequence: request.sequence,
                    value: 0x42,
                    error: None,
                })
                .await
                .unwrap();
            let (mut handler, action) = next_access.await.unwrap();
            assert_eq!(action, Ok(expected));
            assert_eq!(handler.posted_write.is_some(), offset == 0x50);
            handler.settle_posted_write().unwrap();
            bridge.abort();
            assert!(bridge.await.unwrap_err().is_cancelled());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn next_device_access_reports_the_posted_queue_kick_failure() {
        for (exit, ..) in device_accesses() {
            let (mut handler, mut requests, mut replies, bridge) = create_device_handler();
            assert_eq!(
                handler.exchange(vm::VcpuExit::MmioWrite(vm::MmioWrite {
                    address: 0x50,
                    width: 4,
                    value: 1,
                })),
                Ok(vm::VcpuAction::Reenter)
            );
            let kick = requests.next().await.unwrap();
            replies
                .send(Reply {
                    sequence: kick.sequence,
                    value: 0,
                    error: Some(DeviceError::Io),
                })
                .await
                .unwrap();
            let (handler, action) = tokio::task::spawn_blocking(move || {
                let action = handler.exchange(exit);
                (handler, action)
            })
            .await
            .unwrap();
            assert_eq!(
                action.unwrap_err(),
                "MMIO block device error DeviceError::Io"
            );
            assert!(handler.posted_write.is_none());
            assert!(
                bridge
                    .await
                    .unwrap()
                    .unwrap_err()
                    .to_string()
                    .contains("MMIO block device error DeviceError::Io")
            );
            assert!(requests.next().await.is_none());
        }
    }

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
