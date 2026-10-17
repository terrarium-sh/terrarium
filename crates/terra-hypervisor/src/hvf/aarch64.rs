//! HVF `aarch64` VM preparation, PSCI, and vCPU threads.

mod machine;

pub(crate) use machine::{Machine, map_guest_ram, unmap_guest_ram};

use crate::arm::psci::{self, PsciAction, PsciCall};
use crate::arm::{ArmDebugOsAccess, ArmMmioAccess, ArmRegisterWrite};
use crate::vcpus::{Kick, Startup, Stop, Vcpus};
use crate::vm::{
    BootState, InterruptControllerConfig, InterruptMode, VcpuHandler, VcpuOutcome, VmCapabilities,
    VmConfig, VmHandle, report_vcpu_failure,
};
use applevisor::prelude::VcpuHandle;
use machine::{Cpu, RunExit};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use terra_limits::ARM_MAX_VCPUS;

/// A request for a vCPU thread that is not running its vCPU.
enum CpuCommand {
    PowerOn { entry: u64, context: u64 },
    Stop,
}

/// The vCPUs' PSCI power state and the handles HVF exits them through.
struct Cpus {
    machine: Arc<Machine>,
    handles: Mutex<Vec<Option<VcpuHandle>>>,
    powered: Mutex<Vec<bool>>,
    commands: Vec<mpsc::Sender<CpuCommand>>,
}

impl Cpus {
    /// A stop requested before registration found no handle, so this exits the new vCPU itself.
    fn register(&self, cpu: usize, handle: VcpuHandle, stop: &Stop) -> Result<(), String> {
        let mut handles = self.handles.lock().map_err(|_| "vCPU handles poisoned")?;
        *handles.get_mut(cpu).ok_or("vCPU ID outside the VM")? = Some(handle.clone());
        if stop.is_requested() {
            self.machine
                .exit(&[handle])
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn unregister(&self, cpu: usize) {
        let mut handles = self.handles.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(handle) = handles.get_mut(cpu) {
            *handle = None;
        }
    }

    /// Returns the PSCI `CPU_ON` status for the caller.
    fn power_on(&self, cpu: usize, entry: u64, context: u64, stop: &Stop) -> i64 {
        if stop.is_requested() {
            return -3;
        }
        let Some(command) = self.commands.get(cpu) else {
            return -2;
        };
        let Ok(mut powered) = self.powered.lock() else {
            return -3;
        };
        if powered[cpu] {
            return -4;
        }
        if command
            .send(CpuCommand::PowerOn { entry, context })
            .is_err()
        {
            return -3;
        }
        powered[cpu] = true;
        0
    }

    fn power_off(&self, cpu: usize) {
        if let Ok(mut powered) = self.powered.lock() {
            powered[cpu] = false;
        }
    }
}

impl Kick for Cpus {
    /// Holding the handle lock keeps a vCPU from being destroyed while HVF exits it.
    fn kick(&self, cpu: usize) {
        if let Some(command) = self.commands.get(cpu) {
            let _ = command.send(CpuCommand::Stop);
        }
        let handles = self.handles.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(Some(handle)) = handles.get(cpu) {
            let _ = self.machine.exit(std::slice::from_ref(handle));
        }
    }
}

/// A vCPU created on its own thread, as HVF requires, and registered for kicks.
struct RegisteredCpu<'a> {
    cpu: Cpu,
    id: usize,
    cpus: &'a Cpus,
    stop: &'a Stop,
}

impl<'a> RegisteredCpu<'a> {
    fn create(cpus: &'a Cpus, stop: &'a Stop, id: usize) -> Result<Self, String> {
        let cpu = cpus
            .machine
            .create_secondary(u64::try_from(id).map_err(|_| "CPU ID overflow")?, 0, 0)
            .map_err(|error| error.to_string())?;
        let registered = Self {
            cpu,
            id,
            cpus,
            stop,
        };
        cpus.register(id, registered.cpu.handle(), stop)?;
        Ok(registered)
    }
}

impl Drop for RegisteredCpu<'_> {
    fn drop(&mut self) {
        self.stop.request();
        // `cpu` drops after this body, so no kick can exit a destroyed vCPU.
        self.cpus.unregister(self.id);
    }
}

enum CpuRun {
    Continue,
    Off,
    Stop,
}

pub struct Vm {
    cpus: Arc<Cpus>,
    vcpus: Vcpus,
}

impl Vm {
    pub fn create(config: &VmConfig, hard_stop: Option<fn() -> !>) -> Result<Self, String> {
        let count = usize::from(config.vcpus);
        match config.interrupt_controller {
            InterruptControllerConfig::Arm(_) => {}
            InterruptControllerConfig::X86 => {
                return Err("ARM interrupt controller required".to_owned());
            }
        }
        if count == 0 || count > ARM_MAX_VCPUS as usize {
            return Err(format!("invalid vCPU count: {count}"));
        }
        let machine = Arc::new(Machine::new(config).map_err(|error| error.to_string())?);
        let (commands, receivers): (Vec<_>, Vec<_>) = (0..count).map(|_| mpsc::channel()).unzip();
        let cpus = Arc::new(Cpus {
            machine,
            handles: Mutex::new((0..count).map(|_| None).collect()),
            powered: Mutex::new((0..count).map(|cpu| cpu == 0).collect()),
            commands,
        });
        let mut vcpus = Vcpus::new(count, cpus.clone(), hard_stop);
        for (id, commands) in receivers.into_iter().enumerate() {
            let cpus = Arc::clone(&cpus);
            let stop = vcpus.stop();
            vcpus.spawn(move |startup| run_cpu_thread(id, &cpus, &stop, &commands, startup))?;
        }
        Ok(Self { cpus, vcpus })
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
        VmHandle::new(Arc::clone(&self.cpus.machine))
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

fn run_cpu_thread(
    id: usize,
    cpus: &Cpus,
    stop: &Stop,
    commands: &mpsc::Receiver<CpuCommand>,
    startup: Startup,
) -> Result<(), String> {
    let registered = RegisteredCpu::create(cpus, stop, id)?;
    let Some((mut handler, boot)) = startup.wait() else {
        return Ok(());
    };
    let outcome = run_cpu(&registered, commands, boot, handler.as_mut());
    let outcome = report_vcpu_failure(id, handler.as_mut(), outcome);
    if outcome.is_err() {
        stop.request();
    }
    outcome
}

/// Runs the boot vCPU from `boot`, and every vCPU after each PSCI `CPU_ON`, until the VM stops.
fn run_cpu(
    registered: &RegisteredCpu<'_>,
    commands: &mpsc::Receiver<CpuCommand>,
    boot: BootState,
    handler: &mut dyn VcpuHandler,
) -> Result<(), String> {
    let RegisteredCpu {
        cpu,
        id,
        cpus,
        stop,
    } = registered;
    let id = *id;
    if id == 0 {
        cpu.set_reg(applevisor::prelude::Reg::PC, boot.entry)
            .map_err(|error| error.to_string())?;
        cpu.set_reg(applevisor::prelude::Reg::X0, boot.boot_argument)
            .map_err(|error| error.to_string())?;
        if let CpuRun::Stop = run_until_off(cpu, id, handler, cpus, stop)? {
            handler.finished(VcpuOutcome::Stopped);
            return Ok(());
        }
    }
    while let Ok(command) = commands.recv() {
        let CpuCommand::PowerOn { entry, context } = command else {
            handler.finished(VcpuOutcome::Stopped);
            return Ok(());
        };
        cpu.reset_for_start(entry, context)
            .map_err(|error| error.to_string())?;
        if let CpuRun::Stop = run_until_off(cpu, id, handler, cpus, stop)? {
            handler.finished(VcpuOutcome::Stopped);
            return Ok(());
        }
    }
    Ok(())
}

/// Returns [`CpuRun::Off`] after PSCI `CPU_OFF`, or [`CpuRun::Stop`].
fn run_until_off(
    cpu: &Cpu,
    id: usize,
    handler: &mut dyn VcpuHandler,
    cpus: &Cpus,
    stop: &Stop,
) -> Result<CpuRun, String> {
    loop {
        match run_one(cpu, id, handler, cpus, stop)? {
            CpuRun::Continue => {}
            CpuRun::Off => {
                cpus.power_off(id);
                return Ok(CpuRun::Off);
            }
            CpuRun::Stop => return Ok(CpuRun::Stop),
        }
    }
}

fn run_psci(cpu: &Cpu, cpus: &Cpus, stop: &Stop) -> Result<CpuRun, String> {
    let mut registers = [0; 4];
    for (index, value) in (0..).zip(&mut registers) {
        *value = cpu
            .arm_register_value(index)
            .map_err(|error| error.to_string())?;
    }
    let powered_cpus = cpus
        .powered
        .lock()
        .map_err(|_| "powered CPU state poisoned")?
        .clone();
    let is_entry_valid =
        |entry: u64| entry.is_multiple_of(4) && cpus.machine.memory().read(entry, 4).is_ok();
    let status = match psci::decide(
        PsciCall::from_registers(registers),
        &powered_cpus,
        is_entry_valid,
    ) {
        PsciAction::Return(status) => status,
        PsciAction::StartCpu {
            target,
            entry,
            context,
        } => cpus.power_on(target, entry, context, stop),
        PsciAction::PowerOffCaller => return Ok(CpuRun::Off),
        PsciAction::StopMachine => {
            stop.request();
            return Ok(CpuRun::Stop);
        }
    };
    cpu.set_reg(applevisor::prelude::Reg::X0, status.cast_unsigned())
        .map_err(|error| error.to_string())?;
    Ok(CpuRun::Continue)
}

fn run_one(
    cpu: &Cpu,
    cpu_id: usize,
    handler: &mut dyn VcpuHandler,
    cpus: &Cpus,
    stop: &Stop,
) -> Result<CpuRun, String> {
    if stop.is_requested() {
        return Ok(CpuRun::Stop);
    }
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
            if let Some(access) = ArmDebugOsAccess::decode(syndrome) {
                let ArmRegisterWrite { register, value } = access.complete();
                cpu.set_arm_general_register(register, value)
                    .map_err(|error| error.to_string())?;
            } else if let Some(access) = ArmMmioAccess::decode(syndrome)? {
                let exit = access.exit(physical_address, |register| {
                    cpu.arm_register_value(register)
                        .map_err(|error| error.to_string())
                })?;
                let ArmRegisterWrite { register, value } =
                    access.complete(handler.exchange(exit)?)?;
                cpu.set_arm_general_register(register, value)
                    .map_err(|error| error.to_string())?;
            } else {
                return run_psci(cpu, cpus, stop);
            }
            cpu.advance_pc().map_err(|error| error.to_string())?;
            Ok(CpuRun::Continue)
        }
        RunExit::Unknown => Err(format!("unexpected HVF exit on CPU {cpu_id}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::GicConfig;
    use crate::vm::{VcpuAction, VcpuExit};
    use std::time::{Duration, Instant};

    const CPU_OFF: u64 = 0x8400_0002;
    const HVC_0: u32 = 0xd400_0002;

    struct NoExitsHandler;

    impl VcpuHandler for NoExitsHandler {
        fn exchange(&mut self, exit: VcpuExit) -> Result<VcpuAction, String> {
            Err(format!("PSCI is answered by the platform: {exit:?}"))
        }

        fn finished(&mut self, _outcome: VcpuOutcome) {}
    }

    /// Apple's running GIC topology requires `CPU_OFF`/`CPU_ON` to retain the vCPU.
    /// Teardown must hold the handle alive until the native exit call returns.
    #[test]
    #[ignore = "requires Apple Silicon Hypervisor.framework and hypervisor entitlement"]
    fn cpu_power_cycles_preserve_the_handle_until_teardown() {
        for cpu_id in [0, 1] {
            power_cycle_cpu(cpu_id);
        }
    }

    fn power_cycle_cpu(cpu_id: usize) {
        let vm = Vm::create(
            &VmConfig {
                ram_base: terra_limits::ARM_RAM_BASE,
                ram_bytes: 16 * 1024 * 1024,
                vcpus: 2,
                interrupt_controller: InterruptControllerConfig::Arm(GicConfig {
                    distributor_base: terra_limits::ARM_GIC_DIST_BASE,
                    distributor_size: terra_limits::ARM_GIC_DIST_SIZE,
                    redistributor_base: terra_limits::ARM_GIC_REDIST_BASE,
                    redistributor_size: terra_limits::ARM_GIC_REDIST_SIZE,
                }),
                irq_routes: Vec::new(),
            },
            None,
        )
        .unwrap();
        let entry = terra_limits::ARM_RAM_BASE;
        vm.cpus
            .machine
            .memory()
            .write(entry, &HVC_0.to_le_bytes())
            .unwrap();
        let cpus = Arc::clone(&vm.cpus);
        let stop = vm.vcpus.stop();
        let mut vcpus = vm
            .start(
                BootState {
                    entry,
                    boot_argument: CPU_OFF,
                },
                vec![Box::new(NoExitsHandler), Box::new(NoExitsHandler)],
            )
            .unwrap();
        let handle = cpus.handles.lock().unwrap()[cpu_id].clone().unwrap();
        for round in 0..3 {
            if cpu_id != 0 || round != 0 {
                assert_eq!(cpus.power_on(cpu_id, entry, CPU_OFF, &stop), 0);
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while cpus.powered.lock().unwrap()[cpu_id] && Instant::now() < deadline {
                std::thread::yield_now();
            }
            assert!(!cpus.powered.lock().unwrap()[cpu_id]);
            assert!(handle.is_valid());
        }
        assert_eq!(vcpus.join().unwrap(), [Ok(()), Ok(())]);
        assert_eq!(cpus.power_on(cpu_id, entry, CPU_OFF, &stop), -3);
        assert!(!handle.is_valid());
        assert!(cpus.handles.lock().unwrap().iter().all(Option::is_none));
    }
}
