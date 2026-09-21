//! Linux/KVM `AArch64` vCPU runners.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use super::ArmWorkerError;
use super::machine::Machine;
use crate::aarch64::arm::MAX_VCPUS;
use crate::memory::GuestMemory;
use crate::runner::{PthreadPublication, install_kick_handler, unblock_kick_signal};
use crate::vm::{
    BootState, InterruptControllerConfig, InterruptMode, VcpuAction, VcpuExit as NativeExit,
    VcpuHandler, VcpuOutcome, VmCapabilities, VmConfig, VmHandle,
};
use kvm_bindings::{
    KVM_REG_ARM_CORE, KVM_REG_ARM64, KVM_REG_SIZE_U64, KVM_SYSTEM_EVENT_RESET,
    KVM_SYSTEM_EVENT_SHUTDOWN, kvm_regs, user_pt_regs,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd};

const STOP_DEADLINE: Duration = Duration::from_secs(5);

fn configure_boot_vcpu(
    vcpu: &VcpuFd,
    entry: u64,
    boot_argument: u64,
) -> Result<(), ArmWorkerError> {
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

struct VcpuRunner {
    stop: Arc<AtomicBool>,
    publication: PthreadPublication,
    command: mpsc::Sender<VcpuCommand>,
    thread: Option<std::thread::JoinHandle<()>>,
    done: mpsc::Receiver<Result<ArmVcpuOutcome, ArmWorkerError>>,
}

enum VcpuCommand {
    Start {
        handler: Box<dyn VcpuHandler>,
        boot: Option<BootState>,
    },
    Stop,
}

#[derive(Debug)]
enum ArmVcpuOutcome {
    Shutdown,
    Stopped,
}

impl VcpuRunner {
    fn spawn(id: usize, mut vcpu: VcpuFd, ram: GuestMemory) -> Result<Self, ArmWorkerError> {
        install_kick_handler().map_err(ArmWorkerError::KickHandler)?;
        let stop = Arc::new(AtomicBool::new(false));
        let publication = PthreadPublication::new();
        let (done, receiver) = mpsc::channel();
        let (command, commands) = mpsc::channel();
        let thread_stop = Arc::clone(&stop);
        let thread_publication = publication.clone();
        let thread = std::thread::Builder::new()
            .name(format!("aarch64-vcpu-{id}"))
            .spawn(move || {
                let _ram = ram;
                let result = match unblock_kick_signal().map_err(ArmWorkerError::KickHandler) {
                    Err(error) => Err(error),
                    Ok(()) => match commands.recv() {
                        Ok(VcpuCommand::Start { mut handler, boot }) => {
                            if thread_stop.load(Ordering::Acquire) {
                                Ok(ArmVcpuOutcome::Stopped)
                            } else if let Some(boot) = boot {
                                if let Err(error) =
                                    configure_boot_vcpu(&vcpu, boot.entry, boot.boot_argument)
                                {
                                    Err(error)
                                } else {
                                    let _published = thread_publication.publish();
                                    let result =
                                        run_vcpu(&mut vcpu, &thread_stop, handler.as_mut());
                                    thread_publication.clear();
                                    if let Ok(outcome) = &result {
                                        handler.finished(match outcome {
                                            ArmVcpuOutcome::Shutdown => VcpuOutcome::Shutdown,
                                            ArmVcpuOutcome::Stopped => VcpuOutcome::Stopped,
                                        });
                                    }
                                    result
                                }
                            } else {
                                let _published = thread_publication.publish();
                                let result = run_vcpu(&mut vcpu, &thread_stop, handler.as_mut());
                                thread_publication.clear();
                                if let Ok(outcome) = &result {
                                    handler.finished(match outcome {
                                        ArmVcpuOutcome::Shutdown => VcpuOutcome::Shutdown,
                                        ArmVcpuOutcome::Stopped => VcpuOutcome::Stopped,
                                    });
                                }
                                result
                            }
                        }
                        Ok(VcpuCommand::Stop) => Ok(ArmVcpuOutcome::Stopped),
                        Err(_) => Err(ArmWorkerError::ThreadGone),
                    },
                };
                let _ = done.send(result);
            })
            .map_err(|_| ArmWorkerError::ThreadGone)?;
        Ok(Self {
            stop,
            publication,
            command,
            thread: Some(thread),
            done: receiver,
        })
    }

    fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.command.send(VcpuCommand::Stop);
        self.publication.kick();
    }

    fn start(
        &self,
        handler: Box<dyn VcpuHandler>,
        boot: Option<BootState>,
    ) -> Result<(), ArmWorkerError> {
        self.command
            .send(VcpuCommand::Start { handler, boot })
            .map_err(|_| ArmWorkerError::ThreadGone)
    }

    fn stop(&mut self, timeout: Duration) -> Result<ArmVcpuOutcome, ArmWorkerError> {
        self.request_stop();
        let outcome = self
            .done
            .recv_timeout(timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => ArmWorkerError::Timeout,
                mpsc::RecvTimeoutError::Disconnected => ArmWorkerError::ThreadGone,
            })?;
        self.thread
            .take()
            .ok_or(ArmWorkerError::ThreadGone)?
            .join()
            .map_err(|_| ArmWorkerError::ThreadGone)?;
        outcome
    }
}

pub struct KvmArmVm {
    machine: Arc<Machine>,
    group: PreparedVcpuGroup,
}

impl KvmArmVm {
    pub fn create(config: &VmConfig, hard_stop: Option<fn() -> !>) -> Result<Self, String> {
        Self::prepare_native(config, hard_stop).map_err(|error| error.to_string())
    }

    fn prepare_native(
        config: &VmConfig,
        hard_stop: Option<fn() -> !>,
    ) -> Result<Self, ArmWorkerError> {
        let vcpus = usize::from(config.vcpus);
        match config.interrupt_controller {
            InterruptControllerConfig::Arm(_) => {}
            InterruptControllerConfig::X86 => {
                return Err(ArmWorkerError::InvalidInterruptController);
            }
        }
        if vcpus == 0 || vcpus > MAX_VCPUS {
            return Err(ArmWorkerError::BadVcpuCount(vcpus));
        }
        let kvm = Kvm::new().map_err(|error| {
            ArmWorkerError::Native(format!(
                "opening /dev/kvm: {error}; check KVM access permissions"
            ))
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
    _machine: Option<Arc<Machine>>,
    runners: Vec<VcpuRunner>,
    hard_stop: Option<fn() -> !>,
}

impl VcpuGroup {
    fn prepare(
        machine: &Arc<Machine>,
        count: usize,
        hard_stop: Option<fn() -> !>,
    ) -> Result<Self, ArmWorkerError> {
        let vcpus = machine.prepare_vcpus(count)?;
        let mut group = Self {
            _machine: Some(Arc::clone(machine)),
            runners: Vec::with_capacity(count),
            hard_stop,
        };
        for (id, vcpu) in vcpus.into_iter().enumerate() {
            group
                .runners
                .push(VcpuRunner::spawn(id, vcpu, machine.memory())?);
        }
        Ok(group)
    }
}

impl PreparedVcpuGroup {
    fn start(
        self,
        handlers: Vec<Box<dyn VcpuHandler>>,
        boot: BootState,
    ) -> Result<VcpuGroup, ArmWorkerError> {
        if self.group.runners.len() != handlers.len() {
            return Err(ArmWorkerError::BadVcpuCount(handlers.len()));
        }
        for (id, (runner, handler)) in self.group.runners.iter().zip(handlers).enumerate() {
            runner.start(handler, (id == 0).then_some(boot))?;
        }
        Ok(self.group)
    }
}

impl VcpuGroup {
    pub(crate) fn request_stop(&mut self) {
        for runner in &self.runners {
            runner.request_stop();
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

    fn stop(&mut self) -> Result<Vec<Result<ArmVcpuOutcome, ArmWorkerError>>, ArmWorkerError> {
        stop_runners(&mut std::mem::take(&mut self.runners), self.hard_stop)
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
    runners: &mut [VcpuRunner],
    hard_stop: Option<fn() -> !>,
) -> Result<Vec<Result<ArmVcpuOutcome, ArmWorkerError>>, ArmWorkerError> {
    for runner in &*runners {
        runner.request_stop();
    }
    let deadline = Instant::now() + STOP_DEADLINE;
    let outcomes = runners
        .iter_mut()
        .map(|runner| runner.stop(deadline.saturating_duration_since(Instant::now())))
        .collect::<Vec<_>>();
    if outcomes
        .iter()
        .any(|outcome| matches!(outcome, Err(ArmWorkerError::Timeout)))
    {
        if let Some(hard_stop) = hard_stop {
            hard_stop();
        }
        return Err(ArmWorkerError::Timeout);
    }
    Ok(outcomes)
}

fn run_vcpu(
    vcpu: &mut VcpuFd,
    stop: &AtomicBool,
    handler: &mut dyn VcpuHandler,
) -> Result<ArmVcpuOutcome, ArmWorkerError> {
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(ArmVcpuOutcome::Stopped);
        }
        match vcpu.run() {
            Ok(VcpuExit::MmioRead(address, data)) => {
                let width = width(data.len())?;
                let VcpuAction::MmioRead(value) = handler
                    .exchange(NativeExit::MmioRead(crate::vm::MmioRead { address, width }))
                    .map_err(ArmWorkerError::Native)?
                else {
                    return Err(ArmWorkerError::UnexpectedExit("mmio-read-completion"));
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
                        .map_err(ArmWorkerError::Native)?,
                )?;
            }
            Ok(VcpuExit::Hlt) => reenter(
                handler
                    .exchange(NativeExit::Halt)
                    .map_err(ArmWorkerError::Native)?,
            )?,
            Ok(VcpuExit::Intr) => {
                if stop.load(Ordering::Acquire) {
                    return Ok(ArmVcpuOutcome::Stopped);
                }
                reenter(
                    handler
                        .exchange(NativeExit::Interrupted)
                        .map_err(ArmWorkerError::Native)?,
                )?;
            }
            Ok(
                VcpuExit::Shutdown
                | VcpuExit::SystemEvent(KVM_SYSTEM_EVENT_SHUTDOWN | KVM_SYSTEM_EVENT_RESET, _),
            ) => {
                let _ = handler.exchange(NativeExit::Shutdown);
                return Ok(ArmVcpuOutcome::Shutdown);
            }
            Ok(_) => return Err(ArmWorkerError::UnexpectedExit("KVM exit")),
            Err(error) if matches!(error.errno(), libc::EINTR | libc::EAGAIN) => {}
            Err(error) => return Err(ArmWorkerError::Kvm(error)),
        }
    }
}

fn width(length: usize) -> Result<u8, ArmWorkerError> {
    match length {
        1 | 2 | 4 | 8 => {
            u8::try_from(length).map_err(|_| ArmWorkerError::UnexpectedExit("mmio-width"))
        }
        _ => Err(ArmWorkerError::UnexpectedExit("mmio-width")),
    }
}

fn value(data: &[u8]) -> Result<u64, ArmWorkerError> {
    if data.len() > 8 {
        return Err(ArmWorkerError::UnexpectedExit("mmio-width"));
    }
    let mut bytes = [0; 8];
    bytes[..data.len()].copy_from_slice(data);
    Ok(u64::from_le_bytes(bytes))
}

fn reenter(action: VcpuAction) -> Result<(), ArmWorkerError> {
    if matches!(action, VcpuAction::Reenter) {
        Ok(())
    } else {
        Err(ArmWorkerError::UnexpectedExit("completion"))
    }
}

fn set_core_register(vcpu: &VcpuFd, offset: usize, value: u64) -> Result<(), ArmWorkerError> {
    let register = core_register_id(offset)?;
    vcpu.set_one_reg(register, &value.to_ne_bytes())?;
    Ok(())
}

fn core_register_id(offset: usize) -> Result<u64, ArmWorkerError> {
    let index = (std::mem::offset_of!(kvm_regs, regs) + offset) / std::mem::size_of::<u32>();
    Ok(KVM_REG_ARM64
        | KVM_REG_SIZE_U64
        | u64::from(KVM_REG_ARM_CORE)
        | u64::try_from(index).map_err(|_| ArmWorkerError::Memory)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropping_a_partially_started_group_stops_and_reaps_its_threads() {
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_stopped = Arc::clone(&stopped);
        let (done, receiver) = mpsc::channel();
        let (command, _) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            thread_stopped.store(true, Ordering::Release);
            let _ = done.send(Ok(ArmVcpuOutcome::Stopped));
        });
        drop(VcpuGroup {
            _machine: None,
            runners: vec![VcpuRunner {
                stop,
                publication: PthreadPublication::new(),
                command,
                thread: Some(thread),
                done: receiver,
            }],
            hard_stop: None,
        });
        assert!(stopped.load(Ordering::Acquire));
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
