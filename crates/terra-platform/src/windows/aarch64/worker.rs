use crate::memory::GuestMemory;
use crate::vm::{
    ArmException, ArmRead, BootState, CpuStart, InterruptControllerConfig, InterruptMode,
    VcpuAction, VcpuExit, VcpuHandler, VcpuOutcome, VmCapabilities, VmConfig, VmHandle,
};
use crate::windows::worker::VcpuGroup;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
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
        let memory = GuestMemory::allocate_at(config.ram_base, config.ram_bytes)
            .ok_or("allocating ARM WHP RAM")?;
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
        let (starts, receivers) = ArmCpuStarts::new(Arc::clone(&group.partition));
        group.secondary = Some(Arc::clone(&starts));
        for ((id, handler), receiver) in (0_u32..).zip(handlers).zip(receivers) {
            let partition = Arc::clone(&group.partition);
            let stop = Arc::clone(&group.stop);
            let starts = Arc::clone(&starts);
            group
                .spawn(move || arm_run_vcpu(&partition, id, handler, &receiver, &starts, &stop))?;
        }
        Ok(group)
    }
}

fn arm_run_vcpu(
    partition: &Arc<crate::windows::whp::Partition>,
    vcpu: u32,
    mut handler: Box<dyn VcpuHandler>,
    receiver: &mpsc::Receiver<ArmCpuCommand>,
    starts: &ArmCpuStarts,
    stop: &Arc<AtomicBool>,
) -> Result<(), String> {
    let mut active = vcpu == 0;
    loop {
        if !active {
            match receiver.recv() {
                Ok(ArmCpuCommand::Start) => active = true,
                Ok(ArmCpuCommand::Stop) | Err(_) => {
                    handler.finished(VcpuOutcome::Stopped);
                    return Ok(());
                }
            }
        }
        while !stop.load(Ordering::Relaxed) {
            match partition
                .run_vcpu(vcpu)
                .map_err(|error| error.to_string())?
            {
                crate::windows::whp::RunExit::MemoryAccess {
                    gpa, pc, syndrome, ..
                } => {
                    match arm_mmio(partition, vcpu, handler.as_mut(), starts, gpa, pc, syndrome)? {
                        ArmRun::Continue => {}
                        ArmRun::Off => {
                            starts.powered_off(vcpu);
                            active = false;
                            break;
                        }
                        ArmRun::Stop => {
                            stop.store(true, Ordering::Relaxed);
                            starts.stop();
                            handler.finished(VcpuOutcome::Shutdown);
                            return Ok(());
                        }
                    }
                }
                crate::windows::whp::RunExit::Canceled => {
                    handler.finished(VcpuOutcome::Stopped);
                    return Ok(());
                }
                crate::windows::whp::RunExit::Reset { .. } => {
                    stop.store(true, Ordering::Relaxed);
                    starts.stop();
                    handler.finished(VcpuOutcome::Stopped);
                    return Ok(());
                }
                crate::windows::whp::RunExit::Other(reason) => {
                    stop.store(true, Ordering::Relaxed);
                    starts.stop();
                    return Err(format!("unexpected ARM WHP exit {reason:#x} on CPU {vcpu}"));
                }
            }
        }
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
    }
}

pub(crate) struct ArmCpuStarts {
    partition: Arc<crate::windows::whp::Partition>,
    started: std::sync::Mutex<Vec<bool>>,
    senders: Vec<mpsc::Sender<ArmCpuCommand>>,
    stopped: AtomicBool,
}

enum ArmCpuCommand {
    Start,
    Stop,
}

impl ArmCpuStarts {
    fn new(
        partition: Arc<crate::windows::whp::Partition>,
    ) -> (Arc<Self>, Vec<mpsc::Receiver<ArmCpuCommand>>) {
        let vcpu_count = (0..partition.vcpu_count()).count();
        let (senders, receivers): (Vec<_>, Vec<_>) =
            (0..vcpu_count).map(|_| mpsc::channel()).unzip();
        (
            Arc::new(Self {
                partition,
                started: std::sync::Mutex::new((0..vcpu_count).map(|vcpu| vcpu == 0).collect()),
                senders,
                stopped: AtomicBool::new(false),
            }),
            receivers,
        )
    }

    fn start(&self, start: &CpuStart) -> i64 {
        if self.stopped.load(Ordering::Relaxed) {
            return -3;
        }
        let target = usize::from(start.target);
        let Ok(mut started) = self.started.lock() else {
            return -3;
        };
        if target >= started.len() {
            return -2;
        }
        if started[target] {
            return -4;
        }
        let Ok(target_vcpu) = u32::try_from(target) else {
            return -2;
        };
        if crate::windows::aarch64::setup_secondary(
            &self.partition,
            target_vcpu,
            start.entry,
            start.context,
        )
        .is_err()
        {
            return -3;
        }
        if self.senders[target].send(ArmCpuCommand::Start).is_err() {
            return -3;
        }
        started[target] = true;
        0
    }

    fn powered_off(&self, vcpu: u32) {
        if let Ok(mut started) = self.started.lock()
            && let Ok(vcpu) = usize::try_from(vcpu)
            && let Some(started) = started.get_mut(vcpu)
        {
            *started = false;
        }
    }

    pub(crate) fn stop(&self) {
        if !self.stopped.swap(true, Ordering::Relaxed) {
            for sender in &self.senders {
                let _ = sender.send(ArmCpuCommand::Stop);
            }
            for vcpu in 0..self.partition.vcpu_count() {
                let _ = self.partition.cancel_vcpu(vcpu);
            }
        }
    }
}

enum ArmRun {
    Continue,
    Off,
    Stop,
}

fn arm_mmio(
    partition: &crate::windows::whp::Partition,
    vcpu: u32,
    handler: &mut dyn VcpuHandler,
    starts: &ArmCpuStarts,
    gpa: u64,
    pc: u64,
    syndrome: u64,
) -> Result<ArmRun, String> {
    let mut action = handler.exchange(VcpuExit::ArmException(ArmException {
        address: gpa,
        syndrome,
    }))?;
    while let VcpuAction::ArmRegister(register) = action {
        if register > 31 {
            return Err("ARM register outside vCPU grant".to_owned());
        }
        let value = if register == 31 {
            0
        } else {
            partition
                .register_u64(vcpu, arm_general_register(register)?)
                .map_err(|error| error.to_string())?
        };
        action = handler.exchange(VcpuExit::ArmRegisterValue(value))?;
    }
    let pc = pc.checked_add(4).ok_or("ARM PC overflow")?;
    match action {
        VcpuAction::ArmRead(ArmRead { register, value }) => {
            let mut registers = vec![(crate::windows::aarch64::WHV_ARM64_REGISTER_PC, pc)];
            if let Some(register) = register {
                registers.push((arm_general_register(register)?, value));
            }
            arm_set_registers(partition, vcpu, &registers)?;
            Ok(ArmRun::Continue)
        }
        VcpuAction::HvcReturn(status) => {
            arm_set_registers(
                partition,
                vcpu,
                &[
                    (
                        crate::windows::aarch64::WHV_ARM64_REGISTER_X0,
                        status.cast_unsigned(),
                    ),
                    (crate::windows::aarch64::WHV_ARM64_REGISTER_PC, pc),
                ],
            )?;
            Ok(ArmRun::Continue)
        }
        VcpuAction::CpuStart(start) => {
            let status = starts.start(&start);
            let action = handler.exchange(VcpuExit::HvcResult(crate::vm::HvcResult {
                target: start.target,
                status,
            }))?;
            let VcpuAction::HvcReturn(status) = action else {
                return Err("unexpected PSCI start completion".to_owned());
            };
            arm_set_registers(
                partition,
                vcpu,
                &[
                    (
                        crate::windows::aarch64::WHV_ARM64_REGISTER_X0,
                        status.cast_unsigned(),
                    ),
                    (crate::windows::aarch64::WHV_ARM64_REGISTER_PC, pc),
                ],
            )?;
            Ok(ArmRun::Continue)
        }
        VcpuAction::CpuOff => {
            arm_set_registers(
                partition,
                vcpu,
                &[(crate::windows::aarch64::WHV_ARM64_REGISTER_PC, pc)],
            )?;
            Ok(ArmRun::Off)
        }
        VcpuAction::SystemStop => {
            arm_set_registers(
                partition,
                vcpu,
                &[(crate::windows::aarch64::WHV_ARM64_REGISTER_PC, pc)],
            )?;
            Ok(ArmRun::Stop)
        }
        VcpuAction::Start
        | VcpuAction::Reenter
        | VcpuAction::MmioRead(_)
        | VcpuAction::PioZero
        | VcpuAction::Rdmsr(_)
        | VcpuAction::MsrFault
        | VcpuAction::Wrmsr
        | VcpuAction::ArmRegister(_)
        | VcpuAction::IoApicValue(_) => Err("unexpected ARM VMM completion".to_owned()),
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
