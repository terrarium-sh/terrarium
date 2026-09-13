//! Linux/KVM `AArch64` worker backed by scoped WASI VMM components.

#![allow(unsafe_code)]

use terra_runtime::component::vmm::virtualization::{PreparedMachine, StartedVcpus, VcpuReaper};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use kvm_bindings::{
    KVM_ARM_VCPU_POWER_OFF, KVM_ARM_VCPU_PSCI_0_2, KVM_DEV_ARM_VGIC_CTRL_INIT,
    KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_DEV_ARM_VGIC_GRP_CTRL, KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
    KVM_REG_ARM_CORE, KVM_REG_ARM64, KVM_REG_SIZE_U64, KVM_SYSTEM_EVENT_RESET,
    KVM_SYSTEM_EVENT_SHUTDOWN, KVM_VGIC_V3_ADDR_TYPE_DIST, KVM_VGIC_V3_ADDR_TYPE_REDIST,
    kvm_create_device, kvm_device_attr, kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3, kvm_regs,
    kvm_userspace_memory_region, kvm_vcpu_init, user_pt_regs,
};
use kvm_ioctls::{DeviceFd, Kvm, VcpuExit, VcpuFd, VmFd};
use terra_runtime::SyntheticRam;
use terra_runtime::component::vmm::{Completion, Exit, NativeVcpu, platform};
use vm_memory::{GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

use crate::aarch64::arm::{GIC_DIST_BASE, GIC_REDIST_BASE, MAX_VCPUS, RAM_BASE};
use crate::runner::{PthreadPublication, install_kick_handler, unblock_kick_signal};
use crate::worker::{self, PreparedVmm, VmmObservation, WorkerInput};

const GIC_SPI_OFFSET: u32 = 32;
const VGIC_IRQS: u32 = 128;
const STOP_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum ArmWorkerError {
    BadVcpuCount(usize),
    TooManyDevices,
    Memory,
    Kvm(kvm_ioctls::Error),
    Component(String),
    ThreadGone,
    KickHandler(std::io::Error),
    Timeout,
    UnexpectedExit(&'static str),
}

impl From<kvm_ioctls::Error> for ArmWorkerError {
    fn from(error: kvm_ioctls::Error) -> Self {
        Self::Kvm(error)
    }
}

struct Machine {
    vgic: DeviceFd,
    vm: Arc<VmFd>,
    ram: Arc<GuestMemoryMmap<()>>,
    irqs: Vec<u32>,
}

impl terra_runtime::component::vmm::virtualization::VirtualMachine for Machine {
    fn memory(&self) -> wasmtime::Result<SyntheticRam> {
        SyntheticRam::from_shared(self.ram())
            .ok_or_else(|| wasmtime::Error::msg("aliasing ARM KVM RAM"))
    }
}

impl Machine {
    fn new(
        kvm: &Kvm,
        config: &terra_runtime::component::vmm::virtualization::MachineConfig,
    ) -> Result<Self, ArmWorkerError> {
        let ram_bytes = config.ram_bytes();
        let ram_size = usize::try_from(ram_bytes).map_err(|_| ArmWorkerError::Memory)?;
        if ram_size == 0 || !ram_bytes.is_multiple_of(4096) {
            return Err(ArmWorkerError::Memory);
        }
        let vm = Arc::new(kvm.create_vm()?);
        let ram = Arc::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(RAM_BASE), ram_size)])
                .map_err(|_| ArmWorkerError::Memory)?,
        );
        let host_address = ram
            .get_host_address(GuestAddress(RAM_BASE))
            .map_err(|_| ArmWorkerError::Memory)?;
        let region = kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            guest_phys_addr: RAM_BASE,
            memory_size: ram_bytes,
            userspace_addr: host_address as u64,
        };
        // SAFETY: this machine owns the mapped RAM for the VM lifetime.
        unsafe { vm.set_user_memory_region(region)? };
        let mut device = kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
            fd: 0,
            flags: 0,
        };
        let vgic = vm.create_device(&mut device)?;
        set_vgic_address(&vgic, KVM_VGIC_V3_ADDR_TYPE_DIST, GIC_DIST_BASE)?;
        set_vgic_address(&vgic, KVM_VGIC_V3_ADDR_TYPE_REDIST, GIC_REDIST_BASE)?;
        vgic.set_device_attr(&kvm_device_attr {
            group: KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            attr: 0,
            addr: std::ptr::from_ref(&VGIC_IRQS) as u64,
            flags: 0,
        })?;
        Ok(Self {
            vgic,
            vm,
            ram,
            irqs: config.devices().iter().map(|device| device.irq).collect(),
        })
    }

    fn prepare_vcpus(&self, count: usize) -> Result<Vec<VcpuFd>, ArmWorkerError> {
        if count == 0 || count > MAX_VCPUS {
            return Err(ArmWorkerError::BadVcpuCount(count));
        }
        let mut vcpus = Vec::with_capacity(count);
        for id in 0..count {
            let vcpu = self
                .vm
                .create_vcpu(u64::try_from(id).map_err(|_| ArmWorkerError::Memory)?)?;
            let mut init = kvm_vcpu_init::default();
            self.vm.get_preferred_target(&mut init)?;
            init.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
            if id != 0 {
                init.features[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
            }
            vcpu.vcpu_init(&init)?;
            vcpus.push(vcpu);
        }
        self.vgic.set_device_attr(&kvm_device_attr {
            group: KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT),
            addr: 0,
            flags: 0,
        })?;
        Ok(vcpus)
    }

    fn ram(&self) -> Arc<GuestMemoryMmap<()>> {
        Arc::clone(&self.ram)
    }

    fn interrupt(&self, irq: u32, level: bool) -> Result<(), ArmWorkerError> {
        let irq = GIC_SPI_OFFSET
            .checked_add(irq)
            .ok_or(ArmWorkerError::TooManyDevices)?;
        self.vm.set_irq_line(irq, level)?;
        Ok(())
    }
}

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
        component: NativeVcpu,
        boot: Option<terra_runtime::component::vmm::boot::BootEntry>,
    },
    Stop,
}

#[derive(Debug)]
enum ArmVcpuOutcome {
    Shutdown,
    Stopped,
}

impl VcpuRunner {
    fn spawn(
        id: usize,
        mut vcpu: VcpuFd,
        ram: Arc<GuestMemoryMmap<()>>,
        lifecycle: terra_runtime::component::vmm::lifecycle::LifecycleNotifier,
    ) -> Result<Self, ArmWorkerError> {
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
                        Ok(VcpuCommand::Start { component, boot }) => {
                            if thread_stop.load(Ordering::Acquire) {
                                Ok(ArmVcpuOutcome::Stopped)
                            } else if let Some(boot) = boot {
                                if let Err(error) =
                                    configure_boot_vcpu(&vcpu, boot.entry, boot.boot_argument)
                                {
                                    Err(error)
                                } else {
                                    let _published = thread_publication.publish();
                                    let result = run_vcpu(&mut vcpu, &thread_stop, &component);
                                    thread_publication.clear();
                                    result
                                }
                            } else {
                                let _published = thread_publication.publish();
                                let result = run_vcpu(&mut vcpu, &thread_stop, &component);
                                thread_publication.clear();
                                result
                            }
                        }
                        Ok(VcpuCommand::Stop) => Ok(ArmVcpuOutcome::Stopped),
                        Err(_) => Err(ArmWorkerError::ThreadGone),
                    },
                };
                if result.is_err() {
                    lifecycle.component_failed();
                }
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
        component: NativeVcpu,
        boot: Option<terra_runtime::component::vmm::boot::BootEntry>,
    ) -> Result<(), ArmWorkerError> {
        self.command
            .send(VcpuCommand::Start { component, boot })
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

#[allow(clippy::too_many_lines)]
pub async fn prepare(mut input: WorkerInput) -> Result<PreparedVmm, ArmWorkerError> {
    if input.vcpus == 0 || input.vcpus > MAX_VCPUS {
        return Err(ArmWorkerError::BadVcpuCount(input.vcpus));
    }
    let disks = crate::worker::disk_paths(&input);
    let blocks = disks.len();
    let shares = input.shares.len();
    let layout = crate::aarch64::arm::build_machine_layout(input.ram_bytes, blocks, shares)
        .map_err(|error| ArmWorkerError::Component(format!("invalid ARM layout: {error:?}")))?;
    let config = layout
        .machine_config(input.vcpus)
        .map_err(|error| ArmWorkerError::Component(error.to_string()))?;
    let kvm = Kvm::new().map_err(|error| component_error(&wasmtime::Error::from(error)))?;
    let machine = Machine::new(&kvm, &config)?;
    let mut runtime =
        crate::worker::create_runtime(&input).map_err(|error| component_error(&error))?;
    let lifecycle = runtime.lifecycle_notifier();
    let hard_stop = input.hard_stop;
    let group = VcpuGroup::prepare(&machine, input.vcpus, &lifecycle, hard_stop)?;
    let prepared = PreparedMachine::new(config, machine);
    let machine = crate::worker::boot_prepared(&mut runtime, prepared, &mut input)
        .await
        .map_err(|error| component_error(&error))?;
    let devices = worker::assemble_devices(
        &mut runtime,
        &mut input,
        machine.ram(),
        &disks,
        |kind, index| machine.bind_interrupt(kind, index, inject_irq),
    )
    .await
    .map_err(ArmWorkerError::Component)?;
    let shutdowns =
        worker::grant_device_shutdown(&mut runtime, &devices).map_err(ArmWorkerError::Component)?;
    let interrupt_machine = machine.clone();
    let interrupt_shutdown = runtime
        .grant_interrupt_shutdown(move || {
            let interrupt_machine = interrupt_machine.machine();
            interrupt_machine
                .irqs
                .iter()
                .try_for_each(|irq| interrupt_machine.interrupt(*irq, false))
                .map_err(|error| format!("{error:?}"))
        })
        .map_err(|error| component_error(&error))?;
    let runners = runtime
        .grant_vcpus(move |controls, boot| {
            group
                .start(controls, boot)
                .map_err(|error| wasmtime::Error::msg(format!("ARM vCPU startup: {error:?}")))
        })
        .await
        .map_err(|error| component_error(&error))?;
    Ok(PreparedVmm {
        runtime,
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

struct VcpuGroup {
    runners: Vec<VcpuRunner>,
    hard_stop: Option<fn() -> !>,
}

impl VcpuGroup {
    fn prepare(
        machine: &Machine,
        count: usize,
        lifecycle: &terra_runtime::component::vmm::lifecycle::LifecycleNotifier,
        hard_stop: Option<fn() -> !>,
    ) -> Result<Self, ArmWorkerError> {
        let vcpus = machine.prepare_vcpus(count)?;
        let mut group = Self {
            runners: Vec::with_capacity(count),
            hard_stop,
        };
        for (id, vcpu) in vcpus.into_iter().enumerate() {
            group.runners.push(VcpuRunner::spawn(
                id,
                vcpu,
                machine.ram(),
                lifecycle.clone(),
            )?);
        }
        Ok(group)
    }

    fn start(
        self,
        controls: Vec<NativeVcpu>,
        boot: terra_runtime::component::vmm::boot::BootEntry,
    ) -> Result<StartedVcpus<VcpuReaper>, ArmWorkerError> {
        if self.runners.len() != controls.len() {
            return Err(ArmWorkerError::BadVcpuCount(controls.len()));
        }
        for (id, (runner, component)) in self.runners.iter().zip(controls).enumerate() {
            runner.start(component, (id == 0).then_some(boot))?;
        }
        let stops = self
            .runners
            .iter()
            .map(|runner| (Arc::clone(&runner.stop), runner.publication.clone()))
            .collect::<Vec<_>>();
        Ok(StartedVcpus::new(self, move || {
            for (stop, publication) in stops {
                stop.store(true, Ordering::Release);
                publication.kick();
            }
            Ok(())
        })
        .with_reaper(|mut group| {
            group
                .stop()
                .map(|outcomes| {
                    outcomes
                        .into_iter()
                        .map(|outcome| outcome.map(|_| ()).map_err(|error| format!("{error:?}")))
                        .collect()
                })
                .map_err(|error| format!("{error:?}"))
        }))
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

fn component_error(error: &wasmtime::Error) -> ArmWorkerError {
    ArmWorkerError::Component(error.to_string())
}

fn inject_irq(machine: &Machine, irq: u32, level: bool) -> wasmtime::Result<()> {
    machine
        .interrupt(irq, level)
        .map_err(|error| wasmtime::Error::msg(format!("ARM interrupt: {error:?}")))
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
    component: &NativeVcpu,
) -> Result<ArmVcpuOutcome, ArmWorkerError> {
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(ArmVcpuOutcome::Stopped);
        }
        match vcpu.run() {
            Ok(VcpuExit::MmioRead(address, data)) => {
                let width = width(data.len())?;
                let Completion::MmioRead(value) = component
                    .exchange(Exit::MmioRead(platform::MmioRead { address, width }))
                    .map_err(|error| component_error(&error))?
                else {
                    return Err(ArmWorkerError::UnexpectedExit("mmio-read-completion"));
                };
                data.copy_from_slice(&value.to_le_bytes()[..usize::from(width)]);
            }
            Ok(VcpuExit::MmioWrite(address, data)) => {
                reenter(
                    component
                        .exchange(Exit::MmioWrite(platform::MmioWrite {
                            address,
                            width: width(data.len())?,
                            value: value(data)?,
                        }))
                        .map_err(|error| component_error(&error))?,
                )?;
            }
            Ok(VcpuExit::Hlt) => reenter(
                component
                    .exchange(Exit::Halt)
                    .map_err(|error| component_error(&error))?,
            )?,
            Ok(VcpuExit::Intr) => {
                if stop.load(Ordering::Acquire) {
                    return Ok(ArmVcpuOutcome::Stopped);
                }
                reenter(
                    component
                        .exchange(Exit::Interrupted)
                        .map_err(|error| component_error(&error))?,
                )?;
            }
            Ok(
                VcpuExit::Shutdown
                | VcpuExit::SystemEvent(KVM_SYSTEM_EVENT_SHUTDOWN | KVM_SYSTEM_EVENT_RESET, _),
            ) => {
                let _ = component.exchange(Exit::Shutdown);
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

fn reenter(completion: Completion) -> Result<(), ArmWorkerError> {
    if matches!(completion, Completion::Reenter) {
        Ok(())
    } else {
        Err(ArmWorkerError::UnexpectedExit("completion"))
    }
}

fn set_vgic_address(vgic: &DeviceFd, kind: u32, address: u64) -> Result<(), ArmWorkerError> {
    vgic.set_device_attr(&kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_ADDR,
        attr: u64::from(kind),
        addr: std::ptr::from_ref(&address) as u64,
        flags: 0,
    })?;
    Ok(())
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
