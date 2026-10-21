//! KVM `aarch64` VM preparation and vCPU threads.

mod machine;

pub(crate) use machine::Machine;

use std::sync::Arc;

use super::KvmError;
use super::kick::PthreadKicks;
use crate::vcpus::{Startup, Stop, Vcpus};
use crate::vm::{
    BootState, InterruptControllerConfig, InterruptMode, VcpuAction, VcpuExit as NativeExit,
    VcpuHandler, VcpuOutcome, VmCapabilities, VmConfig, VmHandle, report_vcpu_failure,
};
use kvm_bindings::{
    KVM_REG_ARM_CORE, KVM_REG_ARM64, KVM_REG_SIZE_U64, KVM_SYSTEM_EVENT_RESET,
    KVM_SYSTEM_EVENT_SHUTDOWN, kvm_regs, user_pt_regs,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd};
use terra_limits::ARM_MAX_VCPUS;

fn configure_boot_vcpu(vcpu: &VcpuFd, entry: u64, boot_argument: u64) -> Result<(), KvmError> {
    set_core_register(
        vcpu,
        std::mem::offset_of!(user_pt_regs, pstate),
        terra_limits::ARM_PSTATE_EL1H_DAIF,
    )?;
    set_core_register(vcpu, std::mem::offset_of!(user_pt_regs, pc), entry)?;
    set_core_register(
        vcpu,
        std::mem::offset_of!(user_pt_regs, regs),
        boot_argument,
    )?;
    for register in 1..4 {
        set_core_register(
            vcpu,
            std::mem::offset_of!(user_pt_regs, regs) + register * std::mem::size_of::<u64>(),
            0,
        )?;
    }
    Ok(())
}

pub struct Vm {
    machine: Arc<Machine>,
    vcpus: Vcpus,
}

impl Vm {
    pub fn create(config: &VmConfig, hard_stop: Option<fn() -> !>) -> Result<Self, String> {
        let count = usize::from(config.vcpus);
        match config.interrupt_controller {
            InterruptControllerConfig::Arm(_) => {}
            InterruptControllerConfig::X86 => {
                return Err(KvmError::InvalidInterruptController.to_string());
            }
        }
        if count == 0 || count > ARM_MAX_VCPUS as usize {
            return Err(KvmError::BadVcpuCount(count).to_string());
        }
        let kvm = Kvm::new().map_err(|error| {
            KvmError::Operation("opening /dev/kvm; check KVM access permissions", error).to_string()
        })?;
        let machine = Arc::new(Machine::new(&kvm, config).map_err(|error| error.to_string())?);
        let kicks =
            PthreadKicks::new(count).map_err(|error| KvmError::KickHandler(error).to_string())?;
        let mut vcpus = Vcpus::new(count, kicks.clone(), hard_stop);
        let prepared = machine
            .prepare_vcpus(count)
            .map_err(|error| error.to_string())?;
        for (id, vcpu) in prepared.into_iter().enumerate() {
            let machine = Arc::clone(&machine);
            let kicks = Arc::clone(&kicks);
            let stop = vcpus.stop();
            vcpus
                .spawn(move |startup| {
                    // The running vCPU's guest RAM lives in `machine`.
                    let _machine = machine;
                    run_vcpu_thread(id, vcpu, &kicks, &stop, startup)
                        .map_err(|error| error.to_string())
                })
                .map_err(|error| format!("preparing KVM vCPU {id}: {error}"))?;
        }
        Ok(Self { machine, vcpus })
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
        VmHandle::new(Arc::clone(&self.machine))
    }

    pub(crate) fn start(
        mut self,
        boot: BootState,
        handlers: Vec<Box<dyn VcpuHandler>>,
    ) -> Result<Vcpus, String> {
        self.vcpus.start(boot, handlers)?;
        Ok(self.vcpus)
    }
}

fn run_vcpu_thread(
    id: usize,
    mut vcpu: VcpuFd,
    kicks: &PthreadKicks,
    stop: &Stop,
    startup: Startup,
) -> Result<(), KvmError> {
    let _published = kicks.publish(id).map_err(KvmError::KickHandler)?;
    let Some((mut handler, boot)) = startup.wait() else {
        return Ok(());
    };
    let outcome = if id == 0 {
        configure_boot_vcpu(&vcpu, boot.entry, boot.boot_argument)
    } else {
        Ok(())
    }
    .and_then(|()| run_vcpu(&mut vcpu, stop, handler.as_mut()));
    let outcome = report_vcpu_failure(id, handler.as_mut(), outcome)?;
    handler.finished(outcome);
    Ok(())
}

fn run_vcpu(
    vcpu: &mut VcpuFd,
    stop: &Stop,
    handler: &mut dyn VcpuHandler,
) -> Result<VcpuOutcome, KvmError> {
    loop {
        if stop.is_requested() {
            return Ok(VcpuOutcome::Stopped);
        }
        match vcpu.run() {
            Ok(VcpuExit::MmioRead(address, data)) => {
                let width = width(data.len())?;
                let VcpuAction::MmioRead(value) = handler
                    .exchange(NativeExit::MmioRead(crate::vm::MmioRead { address, width }))
                    .map_err(KvmError::Handler)?
                else {
                    return Err(KvmError::UnexpectedExit("mmio-read-completion"));
                };
                data.copy_from_slice(&value.to_le_bytes()[..usize::from(width)]);
            }
            Ok(VcpuExit::MmioWrite(address, data)) => {
                reenter(
                    handler
                        .exchange(NativeExit::MmioWrite(crate::vm::MmioWrite {
                            address,
                            width: width(data.len())?,
                            value: value(data)?,
                        }))
                        .map_err(KvmError::Handler)?,
                )?;
            }
            Ok(VcpuExit::Hlt) => reenter(
                handler
                    .exchange(NativeExit::Halt)
                    .map_err(KvmError::Handler)?,
            )?,
            Ok(VcpuExit::Intr) => {
                if stop.is_requested() {
                    return Ok(VcpuOutcome::Stopped);
                }
                reenter(
                    handler
                        .exchange(NativeExit::Interrupted)
                        .map_err(KvmError::Handler)?,
                )?;
            }
            Ok(
                VcpuExit::Shutdown
                | VcpuExit::SystemEvent(KVM_SYSTEM_EVENT_SHUTDOWN | KVM_SYSTEM_EVENT_RESET, _),
            ) => {
                stop.request();
                let _ = handler.exchange(NativeExit::Shutdown);
                return Ok(VcpuOutcome::Shutdown);
            }
            Ok(_) => return Err(KvmError::UnexpectedExit("KVM exit")),
            Err(error) if matches!(error.errno(), libc::EINTR | libc::EAGAIN) => {}
            Err(error) => return Err(KvmError::Operation("KVM_RUN", error)),
        }
    }
}

fn width(length: usize) -> Result<u8, KvmError> {
    match length {
        1 | 2 | 4 | 8 => u8::try_from(length).map_err(|_| KvmError::UnexpectedExit("mmio-width")),
        _ => Err(KvmError::UnexpectedExit("mmio-width")),
    }
}

fn value(data: &[u8]) -> Result<u64, KvmError> {
    if data.len() > 8 {
        return Err(KvmError::UnexpectedExit("mmio-width"));
    }
    let mut bytes = [0; 8];
    bytes[..data.len()].copy_from_slice(data);
    Ok(u64::from_le_bytes(bytes))
}

fn reenter(action: VcpuAction) -> Result<(), KvmError> {
    if matches!(action, VcpuAction::Reenter) {
        Ok(())
    } else {
        Err(KvmError::UnexpectedExit("completion"))
    }
}

fn set_core_register(vcpu: &VcpuFd, offset: usize, value: u64) -> Result<(), KvmError> {
    let register = core_register_id(offset)?;
    vcpu.set_one_reg(register, &value.to_ne_bytes())?;
    Ok(())
}

fn core_register_id(offset: usize) -> Result<u64, KvmError> {
    let index = (std::mem::offset_of!(kvm_regs, regs) + offset) / std::mem::size_of::<u32>();
    Ok(KVM_REG_ARM64
        | KVM_REG_SIZE_U64
        | u64::from(KVM_REG_ARM_CORE)
        | u64::try_from(index).map_err(|_| KvmError::Memory("ARM guest memory"))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_register_ids_use_u32_word_indexes() {
        let base = KVM_REG_ARM64 | KVM_REG_SIZE_U64 | u64::from(KVM_REG_ARM_CORE);
        let first = core_register_id(0).expect("first register id");
        let next = core_register_id(std::mem::size_of::<u64>()).expect("next register id");
        assert_eq!(
            first,
            base | u64::try_from(std::mem::offset_of!(kvm_regs, regs) / 4).expect("index")
        );
        assert_eq!(next - first, 2);
    }
}
