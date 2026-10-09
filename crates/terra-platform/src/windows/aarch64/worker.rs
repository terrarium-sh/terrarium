use crate::memory::GuestMemory;
use crate::vm::{
    ArmException, ArmRead, BootState, InterruptControllerConfig, InterruptMode, VcpuAction,
    VcpuExit, VcpuHandler, VcpuOutcome, VmCapabilities, VmConfig, VmHandle, report_vcpu_failure,
};
use crate::windows::worker::VcpuGroup;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use terra_limits::ARM_MAX_VCPUS;

pub struct WindowsVm {
    partition: Arc<crate::windows::whp::Partition>,
    hard_stop: Option<fn() -> !>,
}

impl WindowsVm {
    pub fn create(config: &VmConfig, hard_stop: Option<fn() -> !>) -> Result<Self, String> {
        let InterruptControllerConfig::Arm(gic) = config.interrupt_controller else {
            return Err("Windows ARM64 requires an ARM interrupt controller".to_owned());
        };
        if config.vcpus == 0 || usize::from(config.vcpus) > ARM_MAX_VCPUS as usize {
            return Err("invalid Windows ARM64 VM dimensions".to_owned());
        }
        if config.ram_base != terra_limits::ARM_RAM_BASE {
            return Err("invalid Windows ARM64 RAM base".to_owned());
        }
        let memory =
            GuestMemory::allocate_arm_ram(config.ram_bytes).ok_or("allocating ARM WHP RAM")?;
        let partition = Arc::new(
            crate::windows::whp::Partition::new(memory, u32::from(config.vcpus), Some(gic))
                .map_err(|error| error.to_string())?,
        );
        for id in 0..u32::from(config.vcpus) {
            partition
                .create_vcpu(id)
                .map_err(|error| error.to_string())?;
        }
        Ok(Self {
            partition,
            hard_stop,
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    pub const fn capabilities() -> Result<VmCapabilities, String> {
        Ok(VmCapabilities {
            interrupt_mode: InterruptMode::ArmIrqLines,
            tsc_frequency: None,
        })
    }

    #[must_use]
    pub fn handle(&self) -> VmHandle {
        VmHandle::new(Arc::clone(&self.partition))
    }

    pub fn start(
        self,
        boot: BootState,
        handlers: Vec<Box<dyn VcpuHandler>>,
    ) -> Result<VcpuGroup, String> {
        if handlers.len() != usize::try_from(self.partition.vcpu_count()).unwrap_or(usize::MAX) {
            return Err("vCPU handler count changed during startup".to_owned());
        }
        let partition = self.partition;
        crate::windows::aarch64::setup_bsp(&partition, boot.entry, boot.boot_argument)
            .map_err(|error| error.to_string())?;
        let mut group = VcpuGroup::new(partition, self.hard_stop);
        for (id, mut handler) in (0_u32..).zip(handlers) {
            let partition = Arc::clone(&group.partition);
            let stop = Arc::clone(&group.stop);
            group.spawn(move || {
                let outcome = arm_run_vcpu(&partition, id, handler.as_mut(), &stop);
                report_vcpu_failure(id, handler.as_mut(), outcome)
            })?;
        }
        Ok(group)
    }
}

fn arm_run_vcpu(
    partition: &crate::windows::whp::Partition,
    vcpu: u32,
    handler: &mut dyn VcpuHandler,
    stop: &AtomicBool,
) -> Result<(), String> {
    while !stop.load(Ordering::Relaxed) {
        match partition
            .run_vcpu(vcpu)
            .map_err(|error| error.to_string())?
        {
            crate::windows::whp::RunExit::MemoryAccess {
                gpa, pc, syndrome, ..
            } => arm_mmio(partition, vcpu, handler, gpa, pc, syndrome)?,
            crate::windows::whp::RunExit::Canceled => break,
            crate::windows::whp::RunExit::Reset { reboot } => {
                stop.store(true, Ordering::Relaxed);
                for index in 0..partition.vcpu_count() {
                    let _ = partition.cancel_vcpu(index);
                }
                handler.finished(if reboot {
                    VcpuOutcome::Stopped
                } else {
                    VcpuOutcome::Shutdown
                });
                return Ok(());
            }
            crate::windows::whp::RunExit::Other(reason) => {
                return Err(format!("unexpected ARM WHP exit {reason:#x} on CPU {vcpu}"));
            }
        }
    }
    handler.finished(VcpuOutcome::Stopped);
    Ok(())
}

fn arm_mmio(
    partition: &crate::windows::whp::Partition,
    vcpu: u32,
    handler: &mut dyn VcpuHandler,
    gpa: u64,
    pc: u64,
    syndrome: u64,
) -> Result<(), String> {
    let exception = ArmException::capture(gpa, syndrome, |register| {
        partition
            .register_u64(vcpu, arm_general_register(register)?)
            .map_err(|error| error.to_string())
    })?;
    let action = handler.exchange(VcpuExit::ArmException(exception))?;
    let pc = pc.checked_add(4).ok_or("ARM PC overflow")?;
    match action {
        VcpuAction::ArmRead(ArmRead { register, value }) => {
            let mut registers = vec![(crate::windows::aarch64::WHV_ARM64_REGISTER_PC, pc)];
            if let Some(register) = register {
                registers.push((arm_general_register(register)?, value));
            }
            arm_set_registers(partition, vcpu, &registers)?;
            Ok(())
        }
        VcpuAction::Start
        | VcpuAction::Reenter
        | VcpuAction::MmioRead(_)
        | VcpuAction::PioZero
        | VcpuAction::Rdmsr(_)
        | VcpuAction::MsrFault
        | VcpuAction::Wrmsr
        | VcpuAction::IoApicValue(_)
        | VcpuAction::HvcReturn(_)
        | VcpuAction::CpuStart(_)
        | VcpuAction::CpuOff
        | VcpuAction::SystemStop => Err("unexpected ARM VMM completion".to_owned()),
    }
}

fn arm_general_register(
    index: u8,
) -> Result<windows_sys::Win32::System::Hypervisor::WHV_REGISTER_NAME, String> {
    if index > 30 {
        return Err("ARM MMIO used SP/ZR as a destination register".to_owned());
    }
    Ok(crate::windows::aarch64::WHV_ARM64_REGISTER_X0 + i32::from(index))
}

fn arm_set_registers(
    partition: &crate::windows::whp::Partition,
    vcpu: u32,
    values: &[(
        windows_sys::Win32::System::Hypervisor::WHV_REGISTER_NAME,
        u64,
    )],
) -> Result<(), String> {
    let names = values.iter().map(|(name, _)| *name).collect::<Vec<_>>();
    let values = values
        .iter()
        .map(
            |(_, value)| windows_sys::Win32::System::Hypervisor::WHV_REGISTER_VALUE {
                Reg64: *value,
            },
        )
        .collect::<Vec<_>>();
    partition
        .set_registers(vcpu, &names, &values)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::GicConfig;
    use std::sync::mpsc;
    use std::time::Duration;

    struct MmioSentinel {
        vcpu: u32,
        writes: mpsc::Sender<(u32, u64)>,
        outcomes: mpsc::Sender<(u32, VcpuOutcome)>,
    }

    impl VcpuHandler for MmioSentinel {
        fn exchange(&mut self, exit: VcpuExit) -> Result<VcpuAction, String> {
            let VcpuExit::ArmException(exception) = exit else {
                return Err(format!("unexpected sentinel exit {exit:?}"));
            };
            assert_eq!(exception.address, 0x1000_0000);
            assert_eq!(exception.syndrome >> 26, 0x24);
            assert_ne!(exception.syndrome & (1 << 6), 0);
            let value = exception.write_value.expect("MMIO source register");
            self.writes.send((self.vcpu, value)).unwrap();
            Ok(VcpuAction::ArmRead(ArmRead {
                register: None,
                value: 0,
            }))
        }

        fn finished(&mut self, outcome: VcpuOutcome) {
            self.outcomes.send((self.vcpu, outcome)).unwrap();
        }
    }

    fn write_native_psci_guest(memory: &GuestMemory) {
        // CPU_ON(1, 0x40001000, 0x1234); write the result; WFI forever.
        let bsp = [
            0x5280_0060_u32,
            0x72b8_8000,
            0xd280_0021,
            0x5800_00e2,
            0xd282_4683,
            0xd400_0002,
            0xd2a2_0005,
            0xf900_00a0,
            0xd503_207f,
            0x17ff_ffff,
            0x4000_1000,
            0,
        ];
        // Write the PSCI context from X0; WFI forever.
        let secondary = [0xd2a2_0005_u32, 0xf900_00a0, 0xd503_207f, 0x17ff_ffff];
        for (address, instructions) in [
            (terra_limits::ARM_RAM_BASE, bsp.as_slice()),
            (terra_limits::ARM_RAM_BASE + 4096, secondary.as_slice()),
        ] {
            let bytes = instructions
                .iter()
                .flat_map(|instruction| instruction.to_le_bytes())
                .collect::<Vec<_>>();
            memory.write(address, &bytes).unwrap();
        }
    }

    /// Native PSCI `CPU_ON` must release a secondary through WHP rather than a
    /// userspace channel. Both CPUs write a sentinel and then idle in WFI;
    /// cancellation must wake and join both native runs.
    #[test]
    #[ignore = "requires Windows Arm64 Hypervisor Platform"]
    fn native_psci_starts_secondary_and_idle_cpus_cancel() {
        let gic = GicConfig {
            distributor_base: terra_limits::ARM_GIC_DIST_BASE,
            distributor_size: terra_limits::ARM_GIC_DIST_SIZE,
            redistributor_base: terra_limits::ARM_GIC_REDIST_BASE,
            redistributor_size: terra_limits::ARM_GIC_REDIST_SIZE,
        };
        let vm = WindowsVm::create(
            &VmConfig {
                ram_base: terra_limits::ARM_RAM_BASE,
                ram_bytes: 2 << 20,
                vcpus: 2,
                interrupt_controller: InterruptControllerConfig::Arm(gic),
                irq_routes: vec![],
            },
            None,
        )
        .unwrap();
        for index in 0..2 {
            assert_eq!(
                vm.partition
                    .register_u64(
                        index,
                        crate::windows::aarch64::WHV_ARM64_REGISTER_GICR_BASE_GPA
                    )
                    .unwrap(),
                gic.redistributor_base + u64::from(index) * 0x2_0000
            );
        }
        let memory = vm.handle().memory();
        write_native_psci_guest(&memory);
        let (writes, written) = mpsc::channel();
        let (outcomes, finished) = mpsc::channel();
        let handlers = (0..2)
            .map(|vcpu| {
                Box::new(MmioSentinel {
                    vcpu,
                    writes: writes.clone(),
                    outcomes: outcomes.clone(),
                }) as Box<dyn VcpuHandler>
            })
            .collect();
        let mut group = vm
            .start(
                BootState {
                    entry: terra_limits::ARM_RAM_BASE,
                    boot_argument: 0,
                },
                handlers,
            )
            .unwrap();
        let mut observed = (0..2)
            .map(|_| written.recv_timeout(Duration::from_secs(5)).unwrap())
            .collect::<Vec<_>>();
        observed.sort_unstable();
        assert_eq!(observed, [(0, 0), (1, 0x1234)]);
        let results = group.join().unwrap();
        assert_eq!(results, [Ok(()), Ok(())]);
        let mut observed = (0..2)
            .map(|_| finished.recv_timeout(Duration::from_secs(1)).unwrap())
            .collect::<Vec<_>>();
        observed.sort_unstable_by_key(|(vcpu, _)| *vcpu);
        assert_eq!(
            observed,
            [(0, VcpuOutcome::Stopped), (1, VcpuOutcome::Stopped)]
        );
    }
}
