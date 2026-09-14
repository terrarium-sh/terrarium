use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_arch = "aarch64")]
use std::sync::mpsc;
use std::time::{Duration, Instant};
use terra_runtime::component::vmm::virtualization::{StartedVcpus, VcpuReaper};

use crate::WindowsRam;
#[cfg(target_arch = "x86_64")]
use crate::machine::MAX_VCPUS;
use crate::worker::{self, PreparedVmm, VmmObservation, WorkerInput};
#[cfg(target_arch = "x86_64")]
use terra_runtime::component::vmm::interrupts::{IoApicHandle, X86Interrupt};
use terra_runtime::component::vmm::virtualization::PreparedMachine;
#[cfg(target_arch = "x86_64")]
use terra_runtime::component::vmm::{Completion, NativeVcpu};
use terra_runtime::component::vmm::{Exit, platform};

const STOP_DEADLINE: Duration = Duration::from_secs(5);

struct VcpuGroup {
    partition: Arc<crate::windows::whp::Partition>,
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<Result<(), String>>>,
    hard_stop: Option<fn() -> !>,
    on_stop: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl VcpuGroup {
    fn new(partition: Arc<crate::windows::whp::Partition>, hard_stop: Option<fn() -> !>) -> Self {
        Self {
            partition,
            stop: Arc::new(AtomicBool::new(false)),
            threads: Vec::new(),
            hard_stop,
            on_stop: None,
        }
    }

    fn into_started(self) -> StartedVcpus<VcpuReaper> {
        let partition = Arc::clone(&self.partition);
        let stop = Arc::clone(&self.stop);
        let on_stop = self.on_stop.clone();
        let count = self.threads.len();
        StartedVcpus::new(self, move || {
            stop.store(true, Ordering::Relaxed);
            if let Some(on_stop) = on_stop {
                on_stop();
            }
            for id in (0_u32..).take(count) {
                let _ = partition.cancel_vcpu(id);
            }
            Ok(())
        })
        .with_reaper(|mut group| group.stop())
    }

    fn spawn(
        &mut self,
        run: impl FnOnce() -> Result<(), String> + Send + 'static,
    ) -> Result<(), String> {
        self.threads.push(
            std::thread::Builder::new()
                .spawn(run)
                .map_err(|error| error.to_string())?,
        );
        Ok(())
    }

    fn stop(&mut self) -> Result<Vec<Result<(), String>>, String> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(on_stop) = &self.on_stop {
            on_stop();
        }
        let threads = std::mem::take(&mut self.threads);
        let deadline = Instant::now() + STOP_DEADLINE;
        loop {
            for (id, thread) in (0_u32..).zip(&threads) {
                if !thread.is_finished() {
                    let _ = self.partition.cancel_vcpu(id);
                }
            }
            if threads.iter().all(std::thread::JoinHandle::is_finished) {
                break;
            }
            if Instant::now() >= deadline {
                if let Some(hard_stop) = self.hard_stop {
                    hard_stop();
                }
                return Err("Windows vCPU stop timed out".to_owned());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(threads
            .into_iter()
            .map(|thread| {
                thread
                    .join()
                    .map_err(|_| "vCPU thread panicked".to_owned())
                    .and_then(|outcome| outcome)
            })
            .collect())
    }
}

impl Drop for VcpuGroup {
    fn drop(&mut self) {
        if !self.threads.is_empty() {
            let _ = self.stop();
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn launch_vcpus(
    partition: Arc<crate::windows::whp::Partition>,
    controls: Vec<NativeVcpu>,
    boot: terra_runtime::component::vmm::boot::BootEntry,
    ioapic: &IoApicHandle,
    hard_stop: Option<fn() -> !>,
) -> Result<StartedVcpus<VcpuReaper>, String> {
    crate::windows::amd64::configure_planned_boot(&partition, boot.entry, boot.boot_argument)
        .map_err(|error| format!("configuring boot: {error:?}"))?;
    let mut group = VcpuGroup::new(partition, hard_stop);
    for (id, control) in (0_u32..).zip(controls) {
        let partition = Arc::clone(&group.partition);
        let stop = Arc::clone(&group.stop);
        let ioapic = ioapic.clone();
        group.spawn(move || run_x64_vcpu(&partition, id, &ioapic, &control, &stop))?;
    }
    Ok(group.into_started())
}

#[cfg(target_arch = "aarch64")]
fn launch_vcpus(
    partition: Arc<crate::windows::whp::Partition>,
    controls: Vec<terra_runtime::component::vmm::NativeVcpu>,
    boot: terra_runtime::component::vmm::boot::BootEntry,
    hard_stop: Option<fn() -> !>,
) -> Result<StartedVcpus<VcpuReaper>, String> {
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

pub async fn prepare(input: WorkerInput) -> Result<PreparedVmm, String> {
    #[cfg(target_arch = "x86_64")]
    {
        prepare_x64(input).await
    }
    #[cfg(target_arch = "aarch64")]
    {
        prepare_arm64(input).await
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(clippy::too_many_lines)]
async fn prepare_x64(mut input: WorkerInput) -> Result<PreparedVmm, String> {
    if input.vcpus == 0 || input.vcpus > MAX_VCPUS {
        return Err("invalid Windows x64 VM dimensions".to_owned());
    }
    let mut component_runtime =
        crate::worker::create_runtime(&input).map_err(|error| error.to_string())?;
    let disks = crate::worker::disk_paths(&input);
    let block_count = disks.len();
    let share_count = input.shares.len();
    let layout = crate::machine::build_machine_layout(input.ram_bytes, block_count, share_count)
        .map_err(|error| format!("invalid WHP layout: {error:?}"))?;
    let config = layout
        .machine_config(input.vcpus)
        .map_err(|error| error.to_string())?;
    let vcpus = u32::from(config.vcpus());
    let ram = WindowsRam::allocate(config.ram_bytes()).ok_or("allocating WHP guest RAM")?;
    let partition = crate::windows::whp::Partition::new(ram, u32::from(config.vcpus()))
        .map_err(|error| format!("creating WHP VM: {error}"))?;
    for id in 0..u32::from(config.vcpus()) {
        partition
            .create_vcpu(id)
            .map_err(|error| error.to_string())?;
    }
    let prepared = PreparedMachine::new(config, partition);
    let partition = crate::worker::boot_prepared(&mut component_runtime, prepared, &mut input)
        .await
        .map_err(|error| error.to_string())?;
    let ram_alias = partition.ram();
    let ioapic = component_runtime
        .grant_ioapic(Arc::new({
            let interrupt_partition = partition.clone();
            move |interrupt: X86Interrupt| {
                if interrupt.vector < 32
                    || (u32::from(interrupt.destination) >= vcpus
                        && interrupt.destination != u8::MAX)
                {
                    return Err(wasmtime::Error::msg("invalid IOAPIC interrupt"));
                }
                let partition = interrupt_partition.machine();
                partition
                    .request_x64_interrupt(
                        interrupt.vector,
                        interrupt.destination,
                        interrupt.level_triggered,
                    )
                    .map_err(|error| wasmtime::Error::msg(error.to_string()))
            }
        }))
        .await
        .map_err(|error| error.to_string())?;
    let devices = worker::assemble_devices(
        &mut component_runtime,
        &mut input,
        ram_alias.clone(),
        &disks,
        |kind, index| ioapic.bind_interrupt(kind, index),
    )
    .await?;
    let shutdowns = worker::grant_device_shutdown(&mut component_runtime, &devices)?;
    let interrupt_handle = ioapic.clone();
    let interrupt_shutdown = component_runtime
        .grant_interrupt_shutdown(move || {
            interrupt_handle.close().map_err(|error| error.to_string())
        })
        .map_err(|error| error.to_string())?;
    let lifecycle = component_runtime.lifecycle_notifier();
    let launch_ioapic = ioapic.clone();
    let hard_stop = input.hard_stop;
    let runners = component_runtime
        .grant_vcpus(move |controls, boot| {
            launch_vcpus(
                partition.machine(),
                controls,
                boot,
                &launch_ioapic,
                hard_stop,
            )
            .map_err(wasmtime::Error::msg)
        })
        .await
        .map_err(|error| error.to_string())?;
    Ok(PreparedVmm {
        runtime: component_runtime,
        observation: VmmObservation {
            reaper: runners,
            lifecycle,
            deadline: input.deadline,
            devices,
            shutdowns,
            interrupts: Some(interrupt_shutdown),
        },
    })
}

#[cfg(target_arch = "x86_64")]
fn run_x64_vcpu(
    partition: &Arc<crate::windows::whp::Partition>,
    vcpu: u32,
    ioapic: &IoApicHandle,
    worker: &NativeVcpu,
    stop: &Arc<AtomicBool>,
) -> Result<(), String> {
    let emulator = crate::windows::whp::Emulator::new().map_err(|error| error.to_string())?;
    while !stop.load(Ordering::Relaxed) {
        let raw = partition
            .run_vcpu_context(vcpu)
            .map_err(|error| error.to_string())?;
        match crate::windows::whp::RunExit::from(raw) {
            crate::windows::whp::RunExit::MemoryAccess { .. } => {
                let mut access =
                    |address: u64,
                     write: bool,
                     data: &mut [u8]|
                     -> Result<(), crate::windows::whp::PartitionError> {
                        if partition.contains_guest_memory(address, data.len()) {
                            return partition.access_guest_memory(address, write, data);
                        }
                        if (crate::windows::amd64::IOAPIC_BASE
                            ..crate::windows::amd64::IOAPIC_BASE
                                + crate::windows::amd64::IOAPIC_SIZE)
                            .contains(&address)
                        {
                            return ioapic_access(ioapic, address, write, data);
                        }
                        mmio_access(worker, address, write, data)
                    };
                let mut io = |port,
                              write,
                              length,
                              value: &mut u32|
                 -> Result<_, crate::windows::whp::PartitionError> {
                    pio_access(worker, port, write, length, value)
                };
                let mut context = crate::windows::whp::EmulationContext::new(
                    partition,
                    vcpu,
                    &mut access,
                    &mut io,
                );
                emulator
                    .emulate_mmio(&mut context, &raw)
                    .map_err(|error| error.to_string())?;
            }
            crate::windows::whp::RunExit::IoPortAccess => {
                let mut memory = |address, write, data: &mut [u8]| {
                    if partition.contains_guest_memory(address, data.len()) {
                        partition.access_guest_memory(address, write, data)
                    } else {
                        if !write {
                            data.fill(0);
                        }
                        Ok(())
                    }
                };
                let mut io = |port,
                              write,
                              length,
                              value: &mut u32|
                 -> Result<_, crate::windows::whp::PartitionError> {
                    pio_access(worker, port, write, length, value)
                };
                let mut context = crate::windows::whp::EmulationContext::new(
                    partition,
                    vcpu,
                    &mut memory,
                    &mut io,
                );
                emulator
                    .emulate_io(&mut context, &raw)
                    .map_err(|error| error.to_string())?;
            }
            crate::windows::whp::RunExit::ApicEoi(vector) => {
                ioapic.eoi(vector).map_err(|error| error.to_string())?;
            }
            crate::windows::whp::RunExit::Halt => require_reentry(worker, Exit::Halt)?,
            crate::windows::whp::RunExit::Canceled => return Ok(()),
            crate::windows::whp::RunExit::Reset { reboot } => {
                return Err(format!("unexpected x64 reset exit (reboot: {reboot})"));
            }
            crate::windows::whp::RunExit::Other(reason) => {
                return Err(format!("unexpected WHP exit {reason}"));
            }
        }
    }
    partition
        .cancel_vcpu(vcpu)
        .map_err(|error| error.to_string())
}

#[cfg(target_arch = "x86_64")]
fn require_reentry(worker: &NativeVcpu, exit: Exit) -> Result<(), String> {
    matches!(
        worker.exchange(exit).map_err(|error| error.to_string())?,
        Completion::Reenter
    )
    .then_some(())
    .ok_or("unexpected Windows x64 VMM completion".to_owned())
}

#[cfg(target_arch = "x86_64")]
fn mmio_access(
    worker: &NativeVcpu,
    address: u64,
    write: bool,
    data: &mut [u8],
) -> Result<(), crate::windows::whp::PartitionError> {
    let Some(width) = valid_mmio_width(data.len()) else {
        if !write {
            data.fill(0);
        }
        return Ok(());
    };
    if write {
        let mut value = [0; 8];
        let Some(destination) = value.get_mut(..data.len()) else {
            return Ok(());
        };
        destination.copy_from_slice(data);
        return require_reentry(
            worker,
            Exit::MmioWrite(platform::MmioWrite {
                address,
                width,
                value: u64::from_le_bytes(value),
            }),
        )
        .map_err(|_| crate::windows::whp::PartitionError::Transport);
    }
    let completion = worker
        .exchange(Exit::MmioRead(platform::MmioRead { address, width }))
        .map_err(|_| crate::windows::whp::PartitionError::Transport)?;
    let Completion::MmioRead(value) = completion else {
        return Err(crate::windows::whp::PartitionError::Transport);
    };
    data.copy_from_slice(&value.to_le_bytes()[..usize::from(width)]);
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn pio_access(
    worker: &NativeVcpu,
    port: u16,
    write: bool,
    length: u8,
    value: &mut u32,
) -> Result<(), crate::windows::whp::PartitionError> {
    if write {
        return require_reentry(
            worker,
            Exit::PioWrite(platform::PioWrite {
                port,
                length: u32::from(length),
            }),
        )
        .map_err(|_| crate::windows::whp::PartitionError::Transport);
    }
    let completion = worker
        .exchange(Exit::PioRead(platform::PioRead {
            port,
            length: u32::from(length),
        }))
        .map_err(|_| crate::windows::whp::PartitionError::Transport)?;
    if !matches!(completion, Completion::PioZero) {
        return Err(crate::windows::whp::PartitionError::Transport);
    }
    *value = 0;
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn ioapic_access(
    ioapic: &IoApicHandle,
    address: u64,
    write: bool,
    data: &mut [u8],
) -> Result<(), crate::windows::whp::PartitionError> {
    let Some(offset) = address
        .checked_sub(crate::windows::amd64::IOAPIC_BASE)
        .and_then(|offset| u8::try_from(offset).ok())
    else {
        if !write {
            data.fill(0);
        }
        return Ok(());
    };
    let Some(width) = valid_mmio_width(data.len()).filter(|_| data.len() <= 4) else {
        if !write {
            data.fill(0);
        }
        return Ok(());
    };
    let value = if write {
        let mut bytes = [0; 4];
        let Some(destination) = bytes.get_mut(..data.len()) else {
            return Ok(());
        };
        destination.copy_from_slice(data);
        u32::from_le_bytes(bytes)
    } else {
        0
    };
    let value = ioapic
        .access(offset, width, write, value)
        .map_err(|_| crate::windows::whp::PartitionError::Transport)?;
    if !write {
        let Some(destination) = data.get_mut(..4) else {
            data.fill(0);
            return Ok(());
        };
        destination.copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn valid_mmio_width(length: usize) -> Option<u8> {
    match length {
        1 | 2 | 4 | 8 => u8::try_from(length).ok(),
        _ => None,
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod width_tests {
    #[test]
    fn whp_mmio_widths_match_the_native_dispatcher() {
        for width in [1, 2, 4, 8] {
            assert_eq!(super::valid_mmio_width(width), u8::try_from(width).ok());
        }
        for width in [0, 3, 5, 6, 7, 9, 16] {
            assert_eq!(super::valid_mmio_width(width), None);
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[allow(clippy::too_many_lines)]
async fn prepare_arm64(mut input: WorkerInput) -> Result<PreparedVmm, String> {
    use crate::aarch64::arm::{MAX_VCPUS, RAM_BASE};

    if input.vcpus == 0 || input.vcpus > MAX_VCPUS {
        return Err("invalid Windows ARM64 vCPU count".to_owned());
    }
    let mut component_runtime =
        crate::worker::create_runtime(&input).map_err(|error| error.to_string())?;
    let disks = crate::worker::disk_paths(&input);
    let block_count = disks.len();
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
    let partition = crate::worker::boot_prepared(&mut component_runtime, prepared, &mut input)
        .await
        .map_err(|error| error.to_string())?;
    let ram_alias = partition.ram();
    let devices = worker::assemble_devices(
        &mut component_runtime,
        &mut input,
        ram_alias,
        &disks,
        |kind, index| partition.bind_interrupt(kind, index, inject_arm_irq),
    )
    .await?;
    let shutdowns = worker::grant_device_shutdown(&mut component_runtime, &devices)?;
    let lifecycle = component_runtime.lifecycle_notifier();
    let hard_stop = input.hard_stop;
    let runners = component_runtime
        .grant_vcpus(move |controls, boot| {
            launch_vcpus(partition.machine(), controls, boot, hard_stop)
                .map_err(wasmtime::Error::msg)
        })
        .await
        .map_err(|error| error.to_string())?;
    Ok(PreparedVmm {
        runtime: component_runtime,
        observation: VmmObservation {
            reaper: runners,
            lifecycle,
            deadline: input.deadline,
            devices,
            shutdowns,
            interrupts: None,
        },
    })
}

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "aarch64")]
struct ArmCpuStarts {
    partition: Arc<crate::windows::whp::Partition>,
    started: std::sync::Mutex<Vec<bool>>,
    senders: Vec<mpsc::Sender<ArmCpuCommand>>,
    stopped: AtomicBool,
}

#[cfg(target_arch = "aarch64")]
enum ArmCpuCommand {
    Start,
    Stop,
}

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "aarch64")]
enum ArmRun {
    Continue,
    Off,
    Stop,
}

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "aarch64")]
fn arm_general_register(
    index: u8,
) -> Result<windows_sys::Win32::System::Hypervisor::WHV_REGISTER_NAME, String> {
    if index > 30 {
        return Err("ARM MMIO used SP/ZR as a destination register".to_owned());
    }
    Ok(crate::windows::aarch64::WHV_ARM64_REGISTER_X0 + i32::from(index))
}

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "aarch64")]
fn inject_arm_irq(
    partition: &crate::windows::whp::Partition,
    irq: u32,
    level: bool,
) -> wasmtime::Result<()> {
    partition
        .request_arm64_spi(irq, level)
        .map_err(|error| wasmtime::Error::msg(error.to_string()))
}
