use crate::windows::worker::VcpuGroup;
use crate::worker::{self, PreparedVmm, WorkerInput};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use terra_runtime::component::vmm::virtualization::{PreparedMachine, StartedVcpus};
use terra_runtime::component::vmm::{Exit, platform};
use terra_runtime::memory::WindowsRam;

fn launch_vcpus(
    partition: Arc<crate::windows::whp::Partition>,
    controls: Vec<terra_runtime::component::vmm::NativeVcpu>,
    boot: terra_runtime::component::vmm::boot::BootEntry,
    hard_stop: Option<fn() -> !>,
) -> Result<StartedVcpus, String> {
    crate::windows::aarch64::setup_bsp(&partition, boot.entry, boot.boot_argument)
        .map_err(|error| error.to_string())?;
    let mut group = VcpuGroup::new(partition, hard_stop);
    let (starts, receivers) = ArmCpuStarts::new(Arc::clone(&group.partition));
    group.on_stop = Some({
        let starts = Arc::clone(&starts);
        Arc::new(move || starts.stop())
    });
    for ((id, control), receiver) in (0_u32..).zip(controls).zip(receivers) {
        let partition = Arc::clone(&group.partition);
        let stop = Arc::clone(&group.stop);
        let starts = Arc::clone(&starts);
        group.spawn(move || arm_run_vcpu(&partition, id, &control, &receiver, &starts, &stop))?;
    }
    Ok(group.into_started())
}

#[allow(clippy::too_many_lines)]
pub async fn prepare(mut input: WorkerInput) -> Result<PreparedVmm, String> {
    use crate::aarch64::arm::{MAX_VCPUS, RAM_BASE};

    if input.vcpus == 0 || input.vcpus > MAX_VCPUS {
        return Err("invalid Windows ARM64 vCPU count".to_owned());
    }
    let component_runtime =
        crate::worker::create_runtime(&input).map_err(|error| error.to_string())?;
    let disks = crate::worker::devices::disk_paths(&input);
    let block_count = 1 + disks.len();
    let shares = input.shares.len();
    let layout = crate::aarch64::arm::build_machine_layout(input.ram_bytes, block_count, shares)
        .map_err(|error| format!("invalid ARM WHP layout: {error:?}"))?;
    let config = layout
        .machine_config(input.vcpus)
        .map_err(|error| error.to_string())?;
    let ram =
        WindowsRam::allocate_at(config.ram_bytes(), RAM_BASE).ok_or("allocating ARM WHP RAM")?;
    let partition = crate::windows::whp::Partition::new(ram, u32::from(config.vcpus()))
        .map_err(|error| error.to_string())?;
    for id in 0..u32::from(config.vcpus()) {
        partition
            .create_vcpu(id)
            .map_err(|error| error.to_string())?;
    }
    let prepared = PreparedMachine::new(config, partition);
    let (mut component_runtime, partition) =
        crate::worker::boot_prepared(component_runtime, prepared, &mut input)
            .await
            .map_err(|error| error.to_string())?;
    let ram_alias = partition.ram();
    worker::devices::assemble_devices(
        &mut component_runtime,
        &mut input,
        ram_alias,
        &disks,
        |kind, index| {
            partition
                .bind_interrupt(kind, index, inject_arm_irq)
                .map_err(|error| error.to_string())
        },
    )?;
    let hard_stop = input.hard_stop;
    crate::worker::finish_preparation(component_runtime, input.deadline, move |controls, boot| {
        launch_vcpus(partition.machine(), controls, boot, hard_stop).map_err(wasmtime::Error::msg)
    })
    .await
    .map_err(|error| error.to_string())
}

fn arm_run_vcpu(
    partition: &Arc<crate::windows::whp::Partition>,
    vcpu: u32,
    worker: &terra_runtime::component::vmm::NativeVcpu,
    receiver: &mpsc::Receiver<ArmCpuCommand>,
    starts: &ArmCpuStarts,
    stop: &Arc<AtomicBool>,
) -> Result<(), String> {
    let mut active = vcpu == 0;
    loop {
        if !active {
            match receiver.recv() {
                Ok(ArmCpuCommand::Start) => active = true,
                Ok(ArmCpuCommand::Stop) | Err(_) => return Ok(()),
            }
        }
        while !stop.load(Ordering::Relaxed) {
            match partition
                .run_vcpu(vcpu)
                .map_err(|error| error.to_string())?
            {
                crate::windows::whp::RunExit::MemoryAccess {
                    gpa, pc, syndrome, ..
                } => match arm_mmio(partition, vcpu, worker, starts, gpa, pc, syndrome)? {
                    ArmRun::Continue => {}
                    ArmRun::Off => {
                        starts.powered_off(vcpu);
                        active = false;
                        break;
                    }
                    ArmRun::Stop => {
                        stop.store(true, Ordering::Relaxed);
                        starts.stop();
                        return Ok(());
                    }
                },
                crate::windows::whp::RunExit::Halt | crate::windows::whp::RunExit::Canceled => {
                    return Ok(());
                }
                crate::windows::whp::RunExit::Reset { .. } => {
                    stop.store(true, Ordering::Relaxed);
                    starts.stop();
                    return Ok(());
                }
                crate::windows::whp::RunExit::Other(reason) => {
                    stop.store(true, Ordering::Relaxed);
                    starts.stop();
                    return Err(format!("unexpected ARM WHP exit {reason:#x} on CPU {vcpu}"));
                }
                crate::windows::whp::RunExit::ApicEoi(_) => {
                    return Err("x64 APIC exit on ARM CPU".to_owned());
                }
                crate::windows::whp::RunExit::IoPortAccess => {
                    return Err("x64 I/O-port exit on ARM CPU".to_owned());
                }
            }
        }
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
    }
}

struct ArmCpuStarts {
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

    fn start(&self, start: &terra_runtime::component::vmm::platform::CpuStart) -> i64 {
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

    fn stop(&self) {
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
    worker: &terra_runtime::component::vmm::NativeVcpu,
    starts: &ArmCpuStarts,
    gpa: u64,
    pc: u64,
    syndrome: u64,
) -> Result<ArmRun, String> {
    let completion = worker
        .exchange_arm_exception(gpa, syndrome, |register| {
            if register == 31 {
                return Ok(0);
            }
            let register = arm_general_register(register).map_err(wasmtime::Error::msg)?;
            partition
                .register_u64(vcpu, register)
                .map_err(|error| wasmtime::Error::msg(error.to_string()))
        })
        .map_err(|error| error.to_string())?;
    let pc = pc.checked_add(4).ok_or("ARM PC overflow")?;
    match completion {
        terra_runtime::component::vmm::Completion::ArmRead(completion) => {
            let mut registers = vec![(crate::windows::aarch64::WHV_ARM64_REGISTER_PC, pc)];
            if let Some(register) = completion.register {
                registers.push((arm_general_register(register)?, completion.value));
            }
            arm_set_registers(partition, vcpu, &registers)?;
            Ok(ArmRun::Continue)
        }
        terra_runtime::component::vmm::Completion::HvcReturn(status) => {
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
        terra_runtime::component::vmm::Completion::CpuStart(start) => {
            let status = starts.start(&start);
            let completion = worker
                .exchange(Exit::HvcResult(platform::HvcResult {
                    target: start.target,
                    status,
                }))
                .map_err(|error| error.to_string())?;
            let terra_runtime::component::vmm::Completion::HvcReturn(status) = completion else {
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
        terra_runtime::component::vmm::Completion::CpuOff => {
            arm_set_registers(
                partition,
                vcpu,
                &[(crate::windows::aarch64::WHV_ARM64_REGISTER_PC, pc)],
            )?;
            Ok(ArmRun::Off)
        }
        terra_runtime::component::vmm::Completion::SystemStop => {
            arm_set_registers(
                partition,
                vcpu,
                &[(crate::windows::aarch64::WHV_ARM64_REGISTER_PC, pc)],
            )?;
            Ok(ArmRun::Stop)
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

fn inject_arm_irq(
    partition: &crate::windows::whp::Partition,
    irq: u32,
    level: bool,
) -> wasmtime::Result<()> {
    partition
        .request_arm64_spi(irq, level)
        .map_err(|error| wasmtime::Error::msg(error.to_string()))
}
