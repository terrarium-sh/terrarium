//! Reusable `x86_64` KVM worker for component-backed Linux boots.

#![allow(unsafe_code)]

use terra_runtime::component::vmm::virtualization::{PreparedMachine, StartedVcpus};

use std::sync::Arc;
use std::time::Instant;

use crate::arch::{KVM_MAX_CPUID_ENTRIES, setup_bsp_planned, setup_irqchip};
use crate::kvm::{
    KvmError, Machine, STOP_DEADLINE, VcpuOutcome, open, park_ap, run_kernel_vcpu,
    spawn_configured_vcpu_ready,
};
use crate::machine::MAX_VCPUS;

pub use crate::worker::{PreparedVmm, VmmObservation, WorkerInput};

fn stop_timed_out(outcomes: &[Result<VcpuOutcome, KvmError>]) -> bool {
    outcomes
        .iter()
        .any(|outcome| matches!(outcome, Err(KvmError::Timeout)))
}

#[allow(clippy::too_many_lines)]
pub async fn prepare(mut input: WorkerInput) -> Result<PreparedVmm, KvmError> {
    if input.vcpus == 0 || input.vcpus > MAX_VCPUS {
        return Err(KvmError::BadVcpuCount(input.vcpus));
    }
    let kvm = open()?;
    let kvm = Arc::new(kvm);
    let disks = crate::worker::disk_paths(&input);
    let block_count = 1 + disks.len();
    let cpuid = build_cpuid(&kvm, input.vcpus)?;
    let share_count = input.shares.len();
    let layout = crate::machine::build_machine_layout(input.ram_bytes, block_count, share_count)
        .map_err(|error| KvmError::Component(format!("invalid KVM layout: {error:?}")))?;
    let config = layout
        .machine_config(input.vcpus)
        .map_err(|error| KvmError::Component(error.to_string()))?;
    let machine = Arc::new(Machine::new(&kvm, &layout, input.vcpus)?);
    let gsis = layout
        .devices()
        .iter()
        .map(|device| device.irq)
        .collect::<Vec<_>>();
    setup_irqchip(machine.vm_fd(), &gsis)
        .map_err(|error| KvmError::Component(format!("creating KVM irqchip: {error:?}")))?;
    let vcpus = PreparedVcpuGroup::prepare(&machine, &cpuid, input.vcpus, input.hard_stop)?;
    let prepared = PreparedMachine::new(config, machine);
    let component_runtime = crate::worker::create_runtime(&input)
        .map_err(|error| KvmError::Component(error.to_string()))?;
    let (mut component_runtime, machine) =
        crate::worker::boot_prepared(component_runtime, prepared, &mut input)
            .await
            .map_err(|error| KvmError::Component(error.to_string()))?;
    let irq_machine = machine.clone();
    let interrupts = component_runtime
        .grant_irq_lines(move |gsi, level| {
            irq_machine.inject_irq(gsi, level, |machine, gsi, level| {
                machine
                    .vm_fd()
                    .set_irq_line(gsi, level)
                    .map_err(|error| wasmtime::Error::msg(format!("KVM interrupt: {error}")))
            })
        })
        .await
        .map_err(|error| KvmError::Component(error.to_string()))?;
    let devices = crate::worker::assemble_devices(
        &mut component_runtime,
        &mut input,
        machine.ram(),
        &disks,
        |kind, index| Ok(interrupts.bind_interrupt(kind, index)),
    )
    .map_err(KvmError::Component)?;
    crate::worker::grant_device_shutdown(&mut component_runtime, &devices)
        .map_err(KvmError::Component)?;
    component_runtime
        .grant_interrupt_shutdown(async move {
            interrupts.close().await.map_err(|error| error.to_string())
        })
        .map_err(|error| KvmError::Component(error.to_string()))?;
    let lifecycle = component_runtime.lifecycle_notifier();
    let (component_runtime, runners) = component_runtime
        .prepare_vcpus(move |controls, boot| {
            vcpus
                .start(controls, boot)
                .map_err(|error| wasmtime::Error::msg(format!("vCPU startup: {error:?}")))
        })
        .await
        .map_err(|error| KvmError::Component(error.to_string()))?;
    let teardown = component_runtime.native_teardown();
    Ok(PreparedVmm {
        runtime: component_runtime,
        observation: VmmObservation {
            reaper: runners,
            lifecycle,
            deadline: input.deadline,
            devices,
            teardown,
        },
    })
}

pub(super) fn build_cpuid(
    kvm: &kvm_ioctls::Kvm,
    vcpu_count: usize,
) -> Result<kvm_bindings::CpuId, KvmError> {
    let vcpus = u8::try_from(vcpu_count).map_err(|_| KvmError::BadVcpuCount(vcpu_count))?;
    if vcpu_count == 0 || vcpu_count > MAX_VCPUS {
        return Err(KvmError::BadVcpuCount(vcpu_count));
    }
    let mut cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
    for entry in cpuid.as_mut_slice() {
        if entry.function == 1 {
            entry.ecx |= 1 << 31;
            entry.ebx = (entry.ebx & 0xff00_ffff) | (u32::from(vcpus) << 16);
            if vcpus > 1 {
                entry.edx |= 1 << 28;
            } else {
                entry.edx &= !(1 << 28);
            }
        }
    }
    Ok(cpuid)
}

enum VcpuCommand {
    Start(
        terra_runtime::component::vmm::NativeVcpu,
        terra_runtime::component::vmm::boot::BootEntry,
    ),
    Stop,
}

struct PreparedVcpuGroup {
    group: VcpuGroup,
    senders: Vec<std::sync::mpsc::SyncSender<VcpuCommand>>,
}

impl PreparedVcpuGroup {
    fn prepare(
        machine: &Arc<Machine>,
        cpuid: &kvm_bindings::CpuId,
        vcpu_count: usize,
        hard_stop: Option<fn() -> !>,
    ) -> Result<Self, KvmError> {
        let mut group = VcpuGroup {
            runners: Vec::with_capacity(vcpu_count),
            hard_stop,
        };
        let mut senders = Vec::with_capacity(vcpu_count);
        for id in 0..vcpu_count {
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            let cpu_cpuid = cpuid.clone();
            group.runners.push(spawn_configured_vcpu_ready(
                Arc::clone(machine),
                u64::try_from(id).map_err(|_| KvmError::BadVcpuCount(vcpu_count))?,
                move |vcpu, stop, ready| {
                    if id == 0 {
                        ready.send(()).map_err(|_| KvmError::ThreadGone)?;
                        let VcpuCommand::Start(worker, boot) =
                            receiver.recv().map_err(|_| KvmError::ThreadGone)?
                        else {
                            return Ok(VcpuOutcome::Stopped);
                        };
                        setup_bsp_planned(&cpu_cpuid, vcpu, boot.entry, boot.boot_argument)
                            .map_err(|_| KvmError::Memory("bsp"))?;
                        run_kernel_vcpu(vcpu, stop, &worker)
                    } else {
                        vcpu.set_cpuid2(&cpu_cpuid)?;
                        park_ap(vcpu)?;
                        ready.send(()).map_err(|_| KvmError::ThreadGone)?;
                        let VcpuCommand::Start(worker, _) =
                            receiver.recv().map_err(|_| KvmError::ThreadGone)?
                        else {
                            return Ok(VcpuOutcome::Stopped);
                        };
                        run_kernel_vcpu(vcpu, stop, &worker)
                    }
                },
            )?);
            senders.push(sender);
        }
        Ok(Self { group, senders })
    }

    fn start(
        mut self,
        workers: Vec<terra_runtime::component::vmm::NativeVcpu>,
        boot: terra_runtime::component::vmm::boot::BootEntry,
    ) -> Result<StartedVcpus, KvmError> {
        if workers.len() != self.senders.len() {
            return Err(KvmError::ThreadGone);
        }
        for (sender, worker) in self.senders.drain(..).zip(workers) {
            sender
                .send(VcpuCommand::Start(worker, boot))
                .map_err(|_| KvmError::ThreadGone)?;
        }
        let hard_stop = self.group.hard_stop;
        let group = std::mem::replace(
            &mut self.group,
            VcpuGroup {
                runners: Vec::new(),
                hard_stop,
            },
        );
        Ok(started_vcpus(group))
    }
}

impl Drop for PreparedVcpuGroup {
    fn drop(&mut self) {
        for sender in &self.senders {
            let _ = sender.send(VcpuCommand::Stop);
        }
        let _ = self.group.stop();
    }
}

fn started_vcpus(group: VcpuGroup) -> StartedVcpus {
    let stops = group
        .runners
        .iter()
        .map(crate::kvm::VcpuHandle::stop_callback)
        .collect::<Vec<_>>();
    StartedVcpus::new(
        group,
        move || {
            for stop in stops {
                stop();
            }
            Ok(())
        },
        |mut group| group.stop(),
    )
}

struct VcpuGroup {
    runners: Vec<crate::kvm::VcpuHandle>,
    hard_stop: Option<fn() -> !>,
}

impl VcpuGroup {
    fn stop(&mut self) -> Result<Vec<Result<(), String>>, String> {
        let mut runners = std::mem::take(&mut self.runners);
        for runner in &runners {
            runner.request_stop();
        }
        let deadline = Instant::now() + STOP_DEADLINE;
        let outcomes = runners
            .iter_mut()
            .map(|runner| runner.stop(deadline.saturating_duration_since(Instant::now())))
            .collect::<Vec<_>>();
        if stop_timed_out(&outcomes) {
            if let Some(hard_stop) = self.hard_stop {
                hard_stop();
            }
            std::mem::forget(runners);
            return Err("KVM vCPU stop timed out".to_owned());
        }
        Ok(outcomes
            .into_iter()
            .map(|outcome| outcome.map(|_| ()).map_err(|error| format!("{error:?}")))
            .collect())
    }
}

impl Drop for VcpuGroup {
    fn drop(&mut self) {
        if !self.runners.is_empty() {
            let _ = self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::machine::{DeviceKind, build_machine_layout};

    #[test]
    fn volume_blocks_precede_network_and_vsock() {
        let layout = build_machine_layout(512 << 20, 10, 0).expect("layout");
        let kinds = layout
            .devices()
            .iter()
            .map(|device| device.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            [
                vec![DeviceKind::Block; 10],
                vec![DeviceKind::Net, DeviceKind::Vsock, DeviceKind::Memory]
            ]
            .concat()
        );
    }

    #[test]
    #[ignore = "needs /dev/kvm"]
    fn cpuid_matches_the_fixed_vcpu_count() {
        let kvm = crate::kvm::open().expect("open KVM");
        for count in [1, 2, 8, 32] {
            let cpuid = super::build_cpuid(&kvm, count).expect("native CPUID");
            let leaf = cpuid
                .as_slice()
                .iter()
                .find(|entry| entry.function == 1)
                .expect("leaf 1");
            assert_ne!(leaf.ecx & (1 << 31), 0);
            assert_eq!((leaf.ebx >> 16) & 0xff, u32::try_from(count).unwrap());
            assert_eq!(leaf.edx & (1 << 28) != 0, count > 1);
        }
        assert!(super::build_cpuid(&kvm, 0).is_err());
        assert!(super::build_cpuid(&kvm, 256).is_err());
    }

    #[test]
    fn a_stop_timeout_requires_the_process_supervisor() {
        assert!(super::stop_timed_out(&[Err(crate::kvm::KvmError::Timeout)]));
        assert!(!super::stop_timed_out(&[Ok(
            crate::kvm::VcpuOutcome::Stopped
        )]));
    }
}
