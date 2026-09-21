use crate::macos::aarch64::machine::{Cpu, Machine, RunExit};
use crate::vm::{
    ArmException, ArmRead, BootState, CpuStart, HvcResult, InterruptControllerConfig,
    InterruptMode, VcpuAction, VcpuExit, VcpuHandler, VcpuOutcome, VmCapabilities, VmConfig,
    VmHandle,
};
use applevisor::prelude::VcpuHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Instant;
use terra_limits::ARM_MAX_VCPUS;

const STOP_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

enum CpuCommand {
    Start {
        handler: Box<dyn VcpuHandler>,
        boot: Option<BootState>,
    },
    CpuStart(u64, u64),
    Stop,
}

struct CpuStarts {
    machine: Arc<Machine>,
    handles: Mutex<Vec<VcpuHandle>>,
    started: Mutex<Vec<bool>>,
    senders: Vec<mpsc::Sender<CpuCommand>>,
    stopped: AtomicBool,
}

impl CpuStarts {
    fn add_handle(&self, handle: VcpuHandle) -> Result<(), String> {
        self.handles
            .lock()
            .map_err(|_| "secondary CPU handles poisoned")?
            .push(handle.clone());
        if self.stopped.load(Ordering::SeqCst) {
            self.machine
                .exit(&[handle])
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn replace_handle(&self, old: u64, handle: VcpuHandle) -> Result<(), String> {
        let mut handles = self
            .handles
            .lock()
            .map_err(|_| "secondary CPU handles poisoned")?;
        handles.retain(|current| current.id() != old);
        handles.push(handle.clone());
        drop(handles);
        if self.stopped.load(Ordering::SeqCst) {
            self.machine
                .exit(&[handle])
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn start(&self, mpidr: u64, entry: u64, context: u64) -> i64 {
        let Ok(cpu) = usize::try_from(mpidr) else {
            return -2;
        };
        if cpu == 0 {
            return -4;
        }
        let Some(sender) = self.senders.get(cpu) else {
            return -2;
        };
        let Ok(mut started) = self.started.lock() else {
            return -3;
        };
        if started[cpu] {
            return -4;
        }
        if sender.send(CpuCommand::CpuStart(entry, context)).is_err() {
            return -3;
        }
        started[cpu] = true;
        0
    }

    fn powered_off(&self, cpu: usize) {
        if let Ok(mut started) = self.started.lock() {
            started[cpu] = false;
        }
    }

    fn stop(&self) {
        if !self.stopped.swap(true, Ordering::SeqCst) {
            for sender in &self.senders {
                let _ = sender.send(CpuCommand::Stop);
            }
            if let Ok(handles) = self.handles.lock() {
                let _ = self.machine.exit(&handles);
            }
        }
    }

    fn cancel(&self) {
        for sender in &self.senders {
            let _ = sender.send(CpuCommand::Stop);
        }
        if let Ok(handles) = self.handles.lock() {
            let _ = self.machine.exit(&handles);
        }
    }
}

fn stop_threads(
    starts: &CpuStarts,
    threads: &[thread::JoinHandle<Result<(), String>>],
    hard_stop: Option<fn() -> !>,
) -> Result<(), String> {
    starts.stop();
    let deadline = Instant::now() + STOP_WAIT;
    while threads.iter().any(|thread| !thread.is_finished()) && Instant::now() < deadline {
        starts.cancel();
        thread::sleep(std::time::Duration::from_millis(10));
    }
    if threads.iter().any(|thread| !thread.is_finished()) {
        if let Some(hard_stop) = hard_stop {
            hard_stop();
        }
        return Err("HVF vCPU did not stop".to_owned());
    }
    Ok(())
}

enum CpuRun {
    Continue,
    Off,
    Stop,
}

pub struct MacArmVm {
    machine: Arc<Machine>,
    group: PreparedVcpuGroup,
}

impl MacArmVm {
    pub fn create(config: &VmConfig, hard_stop: Option<fn() -> !>) -> Result<Self, String> {
        let vcpus = usize::from(config.vcpus);
        match config.interrupt_controller {
            InterruptControllerConfig::Arm(_) => {}
            InterruptControllerConfig::X86 => {
                return Err("ARM interrupt controller required".to_owned());
            }
        }
        if vcpus == 0 || vcpus > ARM_MAX_VCPUS as usize {
            return Err(format!("invalid vCPU count: {vcpus}"));
        }
        let machine = Arc::new(Machine::new(config).map_err(|error| error.to_string())?);
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

impl MacArmVm {
    #[must_use]
    pub fn handle(&self) -> VmHandle {
        VmHandle::new(Arc::clone(&self.machine))
    }

    pub(crate) fn start(
        self,
        boot: BootState,
        handlers: Vec<Box<dyn VcpuHandler>>,
    ) -> Result<VcpuGroup, String> {
        self.group.start(handlers, boot)
    }
}

struct PreparedVcpuGroup {
    group: VcpuGroup,
}

pub(crate) struct VcpuGroup {
    starts: Arc<CpuStarts>,
    threads: Vec<thread::JoinHandle<Result<(), String>>>,
    hard_stop: Option<fn() -> !>,
}

impl VcpuGroup {
    fn prepare(
        machine: &Arc<Machine>,
        vcpu_count: usize,
        hard_stop: Option<fn() -> !>,
    ) -> Result<Self, String> {
        let (ready_sender, ready_receiver) = mpsc::channel::<Result<(), String>>();
        let mut senders = Vec::with_capacity(vcpu_count);
        let mut receivers = Vec::with_capacity(vcpu_count);
        for _ in 0..vcpu_count {
            let (sender, receiver) = mpsc::channel();
            senders.push(sender);
            receivers.push(receiver);
        }
        let starts = Arc::new(CpuStarts {
            machine: Arc::clone(machine),
            handles: Mutex::new(Vec::with_capacity(vcpu_count)),
            started: Mutex::new(vec![false; vcpu_count]),
            senders,
            stopped: AtomicBool::new(false),
        });
        let mut group = Self {
            starts: Arc::clone(&starts),
            threads: Vec::with_capacity(vcpu_count),
            hard_stop,
        };
        for (cpu_id, receiver) in receivers.into_iter().enumerate() {
            group.threads.push(spawn_cpu(
                Arc::clone(machine),
                cpu_id,
                Arc::clone(&starts),
                receiver,
                ready_sender.clone(),
            )?);
        }
        drop(ready_sender);
        for _ in 0..vcpu_count {
            ready_receiver
                .recv_timeout(STOP_WAIT)
                .map_err(|_| "vCPU setup timed out")??;
        }
        Ok(group)
    }
}

impl PreparedVcpuGroup {
    fn start(
        self,
        handlers: Vec<Box<dyn VcpuHandler>>,
        boot: BootState,
    ) -> Result<VcpuGroup, String> {
        if self.group.starts.senders.len() != handlers.len() {
            return Err("vCPU worker count changed during startup".to_owned());
        }
        for (cpu_id, (sender, handler)) in
            self.group.starts.senders.iter().zip(handlers).enumerate()
        {
            sender
                .send(CpuCommand::Start {
                    handler,
                    boot: (cpu_id == 0).then_some(boot),
                })
                .map_err(|_| "vCPU startup thread disappeared")?;
        }
        Ok(self.group)
    }
}

impl VcpuGroup {
    pub(crate) fn request_stop(&mut self) {
        self.starts.stop();
    }

    pub(crate) fn join(&mut self) -> Result<Vec<Result<(), String>>, String> {
        self.stop()
    }

    fn stop(&mut self) -> Result<Vec<Result<(), String>>, String> {
        let threads = std::mem::take(&mut self.threads);
        stop_threads(&self.starts, &threads, self.hard_stop)?;
        Ok(threads
            .into_iter()
            .map(|thread| {
                thread
                    .join()
                    .map_err(|_| "secondary CPU thread panicked".to_owned())
                    .and_then(|outcome| outcome)
            })
            .collect())
    }
}

fn spawn_cpu(
    machine: Arc<Machine>,
    cpu_id: usize,
    starts: Arc<CpuStarts>,
    receiver: mpsc::Receiver<CpuCommand>,
    ready_sender: mpsc::Sender<Result<(), String>>,
) -> Result<thread::JoinHandle<Result<(), String>>, String> {
    thread::Builder::new()
        .spawn(move || {
            let result = (|| -> Result<(), String> {
                let mut cpu = machine
                    .create_secondary(u64::try_from(cpu_id).map_err(|_| "CPU ID overflow")?, 0, 0)
                    .map_err(|error| error.to_string())?;
                starts.add_handle(cpu.handle())?;
                ready_sender
                    .send(Ok(()))
                    .map_err(|_| "vCPU setup receiver disappeared")?;
                let (mut handler, boot) = match receiver
                    .recv()
                    .map_err(|_| "vCPU startup sender disappeared")?
                {
                    CpuCommand::Start { handler, boot } => (handler, boot),
                    CpuCommand::Stop => return Ok(()),
                    CpuCommand::CpuStart(_, _) => {
                        return Err("vCPU started before native startup".to_owned());
                    }
                };
                if cpu_id == 0 {
                    let boot = boot.ok_or("bootstrap vCPU missing boot entry")?;
                    cpu.set_reg(applevisor::prelude::Reg::PC, boot.entry)
                        .map_err(|error| error.to_string())?;
                    cpu.set_reg(applevisor::prelude::Reg::X0, boot.boot_argument)
                        .map_err(|error| error.to_string())?;
                    loop {
                        match run_one(&cpu, cpu_id, handler.as_mut(), &starts)? {
                            CpuRun::Continue => {}
                            CpuRun::Off | CpuRun::Stop => {
                                handler.finished(VcpuOutcome::Stopped);
                                return Ok(());
                            }
                        }
                    }
                }
                if boot.is_some() {
                    return Err("secondary vCPU received boot entry".to_owned());
                }
                while let Ok(command) = receiver.recv() {
                    let (entry, context) = match command {
                        CpuCommand::CpuStart(entry, context) => (entry, context),
                        CpuCommand::Stop => return Ok(()),
                        CpuCommand::Start { .. } => {
                            return Err("secondary vCPU started twice".to_owned());
                        }
                    };
                    cpu.set_reg(applevisor::prelude::Reg::PC, entry)
                        .map_err(|error| error.to_string())?;
                    cpu.set_reg(applevisor::prelude::Reg::X0, context)
                        .map_err(|error| error.to_string())?;
                    loop {
                        match run_one(&cpu, cpu_id, handler.as_mut(), &starts)? {
                            CpuRun::Continue => {}
                            CpuRun::Off => {
                                starts.powered_off(cpu_id);
                                let old = cpu.handle().id();
                                drop(cpu);
                                cpu = machine
                                    .create_secondary(
                                        u64::try_from(cpu_id).map_err(|_| "CPU ID overflow")?,
                                        0,
                                        0,
                                    )
                                    .map_err(|error| error.to_string())?;
                                starts.replace_handle(old, cpu.handle())?;
                                break;
                            }
                            CpuRun::Stop => {
                                handler.finished(VcpuOutcome::Stopped);
                                return Ok(());
                            }
                        }
                    }
                }
                Ok(())
            })();
            if result.is_err() {
                starts.stop();
            }
            result
        })
        .map_err(|error| error.to_string())
}

impl Drop for VcpuGroup {
    fn drop(&mut self) {
        if !self.threads.is_empty() {
            let _ = self.stop();
        }
    }
}

fn run_one(
    cpu: &Cpu,
    cpu_id: usize,
    handler: &mut dyn VcpuHandler,
    starts: &CpuStarts,
) -> Result<CpuRun, String> {
    match cpu.run().map_err(|error| error.to_string())? {
        RunExit::Canceled => Ok(CpuRun::Stop),
        RunExit::Timer => Err(format!(
            "HVF virtual timer exited on CPU {cpu_id}; the hardware GIC should deliver its PPI"
        )),
        RunExit::Exception {
            syndrome,
            physical_address,
            ..
        } => {
            let mut action = handler.exchange(VcpuExit::ArmException(ArmException {
                address: physical_address,
                syndrome,
            }))?;
            while let VcpuAction::ArmRegister(register) = action {
                let value = cpu
                    .arm_register_value(register)
                    .map_err(|error| error.to_string())?;
                action = handler.exchange(VcpuExit::ArmRegisterValue(value))?;
            }
            match action {
                VcpuAction::ArmRead(ArmRead { register, value }) => {
                    cpu.set_arm_mmio_read(register, value)
                        .map_err(|error| error.to_string())?;
                    cpu.advance_pc().map_err(|error| error.to_string())?;
                    Ok(CpuRun::Continue)
                }

                VcpuAction::HvcReturn(status) => {
                    cpu.set_reg(applevisor::prelude::Reg::X0, status.cast_unsigned())
                        .map_err(|error| error.to_string())?;
                    Ok(CpuRun::Continue)
                }
                VcpuAction::CpuStart(CpuStart {
                    target,
                    entry,
                    context,
                }) => {
                    let status = starts.start(u64::from(target), entry, context);
                    let VcpuAction::HvcReturn(status) =
                        handler.exchange(VcpuExit::HvcResult(HvcResult { target, status }))?
                    else {
                        return Err("unexpected PSCI start completion".to_owned());
                    };
                    cpu.set_reg(applevisor::prelude::Reg::X0, status.cast_unsigned())
                        .map_err(|error| error.to_string())?;
                    Ok(CpuRun::Continue)
                }
                VcpuAction::CpuOff => Ok(CpuRun::Off),
                VcpuAction::SystemStop => {
                    starts.stop();
                    Ok(CpuRun::Stop)
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
        RunExit::Unknown => Err(format!("unexpected HVF exit on CPU {cpu_id}")),
    }
}
