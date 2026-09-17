use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Instant;
use terra_runtime::component::vmm::virtualization::{PreparedMachine, StartedVcpus, VcpuReaper};
use terra_runtime::component::vmm::{NativeVcpu, boot::BootEntry};

use crate::macos::aarch64::machine::{Cpu, Machine, RunExit};
use crate::worker::{self, PreparedVmm, VmmObservation, WorkerInput};
use applevisor::prelude::VcpuHandle;

const STOP_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

enum CpuCommand {
    Start {
        worker: NativeVcpu,
        boot: Option<BootEntry>,
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

fn inject_irq(machine: &Machine, irq: u32, level: bool) -> wasmtime::Result<()> {
    machine
        .set_irq(irq, level)
        .map_err(|error| wasmtime::Error::msg(error.to_string()))
}

#[allow(clippy::too_many_lines)]
pub async fn prepare(mut input: WorkerInput) -> Result<PreparedVmm, String> {
    let disks = crate::worker::disk_paths(&input);
    let blocks = 1 + disks.len();
    let shares = input.shares.len();
    let layout = crate::aarch64::arm::build_machine_layout(input.ram_bytes, blocks, shares)
        .map_err(|error| format!("invalid HVF layout: {error:?}"))?;
    let config = layout
        .machine_config(input.vcpus)
        .map_err(|error| error.to_string())?;
    let native_machine =
        Arc::new(Machine::new(layout.ram_size()).map_err(|error| error.to_string())?);
    let group = VcpuGroup::prepare(&native_machine, input.vcpus, input.hard_stop)?;
    let prepared = PreparedMachine::new(config, Arc::clone(&native_machine));
    let mut component_runtime =
        crate::worker::create_runtime(&input).map_err(|error| error.to_string())?;
    let machine = crate::worker::boot_prepared(&mut component_runtime, prepared, &mut input)
        .await
        .map_err(|error| error.to_string())?;
    let devices = worker::assemble_devices(
        &mut component_runtime,
        &mut input,
        machine.ram(),
        &disks,
        |kind, index| {
            machine.bind_interrupt(kind, index, |machine, irq, level| {
                inject_irq(machine, irq, level)
            })
        },
    )
    .await?;
    let shutdowns = worker::grant_device_shutdown(&mut component_runtime, &devices)?;
    let lifecycle = component_runtime.lifecycle_notifier();
    let group = component_runtime
        .grant_vcpus(move |controls, boot| {
            group.start(controls, boot).map_err(wasmtime::Error::msg)
        })
        .await
        .map_err(|error| error.to_string())?;
    Ok(PreparedVmm {
        runtime: component_runtime,
        observation: VmmObservation {
            reaper: group,
            lifecycle,
            deadline: input.deadline,
            devices,
            shutdowns,
            interrupts: None,
        },
    })
}

struct VcpuGroup {
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

    fn start(
        self,
        workers: Vec<NativeVcpu>,
        boot: BootEntry,
    ) -> Result<StartedVcpus<VcpuReaper>, String> {
        if self.starts.senders.len() != workers.len() {
            return Err("vCPU worker count changed during startup".to_owned());
        }
        for (cpu_id, (sender, worker)) in self.starts.senders.iter().zip(workers).enumerate() {
            sender
                .send(CpuCommand::Start {
                    worker,
                    boot: (cpu_id == 0).then_some(boot),
                })
                .map_err(|_| "vCPU startup thread disappeared")?;
        }
        let starts = Arc::clone(&self.starts);
        Ok(StartedVcpus::new(self, move || {
            starts.stop();
            Ok(())
        })
        .with_reaper(|mut group| group.stop()))
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
                let (worker, boot) = match receiver
                    .recv()
                    .map_err(|_| "vCPU startup sender disappeared")?
                {
                    CpuCommand::Start { worker, boot } => (worker, boot),
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
                        match run_one(&cpu, cpu_id, &worker, &starts)? {
                            CpuRun::Continue => {}
                            CpuRun::Off | CpuRun::Stop => return Ok(()),
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
                        match run_one(&cpu, cpu_id, &worker, &starts)? {
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
                            CpuRun::Stop => return Ok(()),
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
    worker: &NativeVcpu,
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
            let completion = worker
                .exchange_arm_exception(physical_address, syndrome, |register| {
                    cpu.arm_register_value(register)
                        .map_err(|error| wasmtime::Error::msg(error.to_string()))
                })
                .map_err(|error| error.to_string())?;
            match completion {
                terra_runtime::component::vmm::Completion::ArmRead(completion) => {
                    cpu.set_arm_mmio_read(completion.register, completion.value)
                        .map_err(|error| error.to_string())?;
                    cpu.advance_pc().map_err(|error| error.to_string())?;
                    Ok(CpuRun::Continue)
                }

                terra_runtime::component::vmm::Completion::HvcReturn(status) => {
                    cpu.set_reg(applevisor::prelude::Reg::X0, status.cast_unsigned())
                        .map_err(|error| error.to_string())?;
                    Ok(CpuRun::Continue)
                }
                terra_runtime::component::vmm::Completion::CpuStart(start) => {
                    let status = starts.start(u64::from(start.target), start.entry, start.context);
                    let completion = worker
                        .exchange(terra_runtime::component::vmm::Exit::HvcResult(
                            terra_runtime::component::vmm::platform::HvcResult {
                                target: start.target,
                                status,
                            },
                        ))
                        .map_err(|error| error.to_string())?;
                    let terra_runtime::component::vmm::Completion::HvcReturn(status) = completion
                    else {
                        return Err("unexpected PSCI start completion".to_owned());
                    };
                    cpu.set_reg(applevisor::prelude::Reg::X0, status.cast_unsigned())
                        .map_err(|error| error.to_string())?;
                    Ok(CpuRun::Continue)
                }
                terra_runtime::component::vmm::Completion::CpuOff => Ok(CpuRun::Off),
                terra_runtime::component::vmm::Completion::SystemStop => {
                    starts.stop();
                    Ok(CpuRun::Stop)
                }
                terra_runtime::component::vmm::Completion::Start
                | terra_runtime::component::vmm::Completion::Reenter
                | terra_runtime::component::vmm::Completion::MmioRead(_)
                | terra_runtime::component::vmm::Completion::PioZero
                | terra_runtime::component::vmm::Completion::Rdmsr(_)
                | terra_runtime::component::vmm::Completion::MsrFault
                | terra_runtime::component::vmm::Completion::Wrmsr
                | terra_runtime::component::vmm::Completion::ArmRegister(_) => {
                    Err("unexpected ARM VMM completion".to_owned())
                }
            }
        }
        RunExit::Unknown => Err(format!("unexpected HVF exit on CPU {cpu_id}")),
    }
}
