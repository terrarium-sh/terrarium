//! Linux/KVM `AArch64` vCPU runners.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Instant;

use super::super::KvmError;
use super::super::{STOP_DEADLINE, VcpuCommand, VcpuHandle, spawn_configured_vcpu_ready};
use super::machine::Machine;
use crate::vm::{
    BootState, InterruptControllerConfig, InterruptMode, VcpuAction, VcpuExit as NativeExit,
    VcpuHandler, VcpuOutcome, VmCapabilities, VmConfig, VmHandle,
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

pub struct KvmArmVm {
    machine: Arc<Machine>,
    group: PreparedVcpuGroup,
}

impl KvmArmVm {
    pub fn create(config: &VmConfig, hard_stop: Option<fn() -> !>) -> Result<Self, String> {
        Self::prepare_native(config, hard_stop).map_err(|error| error.to_string())
    }

    fn prepare_native(config: &VmConfig, hard_stop: Option<fn() -> !>) -> Result<Self, KvmError> {
        let vcpus = usize::from(config.vcpus);
        match config.interrupt_controller {
            InterruptControllerConfig::Arm(_) => {}
            InterruptControllerConfig::X86 => {
                return Err(KvmError::InvalidInterruptController);
            }
        }
        if vcpus == 0 || vcpus > ARM_MAX_VCPUS as usize {
            return Err(KvmError::BadVcpuCount(vcpus));
        }
        let kvm = Kvm::new().map_err(|error| {
            KvmError::Operation("opening /dev/kvm; check KVM access permissions", error)
        })?;
        let machine = Arc::new(Machine::new(&kvm, config)?);
        let group = PreparedVcpuGroup {
            group: VcpuGroup::prepare(&machine, vcpus, hard_stop)?,
        };
        Ok(Self { machine, group })
    }

    #[allow(clippy::unnecessary_wraps)]
    pub const fn capabilities() -> Result<VmCapabilities, String> {
        Ok(VmCapabilities {
            interrupt_mode: InterruptMode::ArmIrqLines,
            tsc_frequency: None,
        })
    }
}

impl KvmArmVm {
    #[must_use]
    pub fn handle(&self) -> VmHandle {
        VmHandle::new(Arc::clone(&self.machine))
    }

    pub(crate) fn start(
        self,
        boot: BootState,
        handlers: Vec<Box<dyn VcpuHandler>>,
    ) -> Result<VcpuGroup, String> {
        self.group
            .start(handlers, boot)
            .map_err(|error| format!("{error:?}"))
    }
}

struct PreparedVcpuGroup {
    group: VcpuGroup,
}

pub(crate) struct VcpuGroup {
    runners: Vec<VcpuHandle>,
    senders: Vec<mpsc::Sender<VcpuCommand>>,
    hard_stop: Option<fn() -> !>,
}

impl VcpuGroup {
    fn prepare(
        machine: &Arc<Machine>,
        count: usize,
        hard_stop: Option<fn() -> !>,
    ) -> Result<Self, KvmError> {
        let vcpus = machine.prepare_vcpus(count)?;
        let mut group = Self {
            runners: Vec::with_capacity(count),
            senders: Vec::with_capacity(count),
            hard_stop,
        };
        for (id, mut vcpu) in vcpus.into_iter().enumerate() {
            let (sender, receiver) = mpsc::channel();
            let machine = Arc::clone(machine);
            group.runners.push(spawn_configured_vcpu_ready(
                u64::try_from(id).map_err(|_| KvmError::BadVcpuCount(count))?,
                move |stop, ready| {
                    let _machine = machine;
                    ready.send(()).map_err(|_| KvmError::ThreadGone)?;
                    let VcpuCommand::Start(mut handler, boot) =
                        receiver.recv().map_err(|_| KvmError::ThreadGone)?
                    else {
                        return Ok(VcpuOutcome::Stopped);
                    };
                    if stop.load(Ordering::Acquire) {
                        return Ok(VcpuOutcome::Stopped);
                    }
                    if id == 0 {
                        configure_boot_vcpu(&vcpu, boot.entry, boot.boot_argument)?;
                    }
                    let outcome = run_vcpu(&mut vcpu, stop, handler.as_mut())?;
                    handler.finished(outcome);
                    Ok(outcome)
                },
            )?);
            group.senders.push(sender);
        }
        Ok(group)
    }
}

impl PreparedVcpuGroup {
    fn start(
        self,
        handlers: Vec<Box<dyn VcpuHandler>>,
        boot: BootState,
    ) -> Result<VcpuGroup, KvmError> {
        if self.group.runners.len() != handlers.len() {
            return Err(KvmError::BadVcpuCount(handlers.len()));
        }
        for (sender, handler) in self.group.senders.iter().zip(handlers) {
            sender
                .send(VcpuCommand::Start(handler, boot))
                .map_err(|_| KvmError::ThreadGone)?;
        }
        Ok(self.group)
    }
}

impl VcpuGroup {
    pub(crate) fn request_stop(&mut self) {
        for runner in &self.runners {
            runner.request_stop();
        }
        for sender in &self.senders {
            let _ = sender.send(VcpuCommand::Stop);
        }
    }

    pub(crate) fn join(&mut self) -> Result<Vec<Result<(), String>>, String> {
        self.stop()
            .map(|outcomes| {
                outcomes
                    .into_iter()
                    .map(|outcome| outcome.map(|_| ()).map_err(|error| format!("{error:?}")))
                    .collect()
            })
            .map_err(|error| format!("{error:?}"))
    }

    fn stop(&mut self) -> Result<Vec<Result<VcpuOutcome, KvmError>>, KvmError> {
        self.request_stop();
        stop_runners(std::mem::take(&mut self.runners), self.hard_stop)
    }
}

impl Drop for VcpuGroup {
    fn drop(&mut self) {
        if !self.runners.is_empty() {
            let _ = self.stop();
        }
    }
}

fn stop_runners(
    mut runners: Vec<VcpuHandle>,
    hard_stop: Option<fn() -> !>,
) -> Result<Vec<Result<VcpuOutcome, KvmError>>, KvmError> {
    let deadline = Instant::now() + STOP_DEADLINE;
    let outcomes = runners
        .iter_mut()
        .map(|runner| runner.stop(deadline.saturating_duration_since(Instant::now())))
        .collect::<Vec<_>>();
    if outcomes
        .iter()
        .any(|outcome| matches!(outcome, Err(KvmError::Timeout)))
    {
        if let Some(hard_stop) = hard_stop {
            hard_stop();
        }
        std::mem::forget(runners);
        return Err(KvmError::Timeout);
    }
    Ok(outcomes)
}

fn run_vcpu(
    vcpu: &mut VcpuFd,
    stop: &AtomicBool,
    handler: &mut dyn VcpuHandler,
) -> Result<VcpuOutcome, KvmError> {
    loop {
        if stop.load(Ordering::Acquire) {
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
                if stop.load(Ordering::Acquire) {
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
    fn dropping_a_partially_started_group_stops_and_reaps_its_threads() {
        let stopped = Arc::new(AtomicBool::new(false));
        let thread_stopped = Arc::clone(&stopped);
        let running = spawn_configured_vcpu_ready(0, move |stop, ready| {
            ready.send(()).unwrap();
            while !stop.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            thread_stopped.store(true, Ordering::Release);
            Ok(VcpuOutcome::Stopped)
        })
        .unwrap();
        let waiting_stopped = Arc::new(AtomicBool::new(false));
        let thread_waiting_stopped = Arc::clone(&waiting_stopped);
        let (command, commands) = mpsc::channel();
        let waiting = spawn_configured_vcpu_ready(1, move |_, ready| {
            ready.send(()).unwrap();
            assert!(matches!(commands.recv().unwrap(), VcpuCommand::Stop));
            thread_waiting_stopped.store(true, Ordering::Release);
            Ok(VcpuOutcome::Stopped)
        })
        .unwrap();
        drop(VcpuGroup {
            runners: vec![running, waiting],
            senders: vec![command],
            hard_stop: None,
        });
        assert!(stopped.load(Ordering::Acquire));
        assert!(waiting_stopped.load(Ordering::Acquire));
    }

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
