//! Native `x86_64` KVM vCPU preparation and execution.

#![allow(unsafe_code)]

use super::super::{KvmError, STOP_DEADLINE, VcpuCommand, VcpuHandle, spawn_configured_vcpu_ready};
use std::time::Instant;

use super::arch::{setup_bsp_planned, setup_irqchip};
use super::kvm::{Machine, park_ap, run_kernel_vcpu};
use crate::vm::{
    BootState, InterruptControllerConfig, InterruptMode, VcpuHandler, VcpuOutcome, VmCapabilities,
    VmConfig, VmHandle, report_vcpu_failure,
};
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use terra_limits::X86_MAX_VCPUS;

fn stop_timed_out(outcomes: &[Result<VcpuOutcome, KvmError>]) -> bool {
    outcomes
        .iter()
        .any(|outcome| matches!(outcome, Err(KvmError::Timeout)))
}

pub(super) fn build_cpuid(
    kvm: &kvm_ioctls::Kvm,
    vcpu_count: usize,
) -> Result<kvm_bindings::CpuId, KvmError> {
    let vcpus = u8::try_from(vcpu_count).map_err(|_| KvmError::BadVcpuCount(vcpu_count))?;
    if vcpu_count == 0 || vcpu_count > X86_MAX_VCPUS as usize {
        return Err(KvmError::BadVcpuCount(vcpu_count));
    }
    let mut cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
    configure_cpuid(cpuid.as_mut_slice(), vcpus, 0);
    Ok(cpuid)
}

fn configure_cpuid(entries: &mut [kvm_bindings::kvm_cpuid_entry2], vcpus: u8, id: u8) {
    let core_bits = u32::from(vcpus).next_power_of_two().trailing_zeros();
    for entry in entries {
        match entry.function {
            1 => {
                entry.ecx |= 1 << 31;
                entry.ebx = (entry.ebx & 0xffff) | (u32::from(vcpus) << 16) | (u32::from(id) << 24);
                if vcpus > 1 {
                    entry.edx |= 1 << 28;
                } else {
                    entry.edx &= !(1 << 28);
                }
            }
            4 | 0x8000_001d if entry.eax & 0x1f != 0 => {
                let shared_cpus = if (entry.eax >> 5) & 7 >= 3 { vcpus } else { 1 };
                entry.eax = (entry.eax & 0x3fff) | (u32::from(shared_cpus - 1) << 14);
                if entry.function == 4 {
                    entry.eax |= u32::from(vcpus - 1) << 26;
                }
            }
            0xb | 0x1f => {
                entry.eax = 0;
                entry.ebx = 0;
                entry.ecx = entry.index;
                entry.edx = u32::from(id);
            }
            0x8000_0008 => {
                entry.ecx = (entry.ecx & !0xf0ff) | u32::from(vcpus - 1) | (core_bits << 12);
            }
            0x8000_001e => {
                entry.eax = u32::from(id);
                entry.ebx = u32::from(id);
                entry.ecx = 0;
                entry.edx = 0;
            }
            _ => {}
        }
    }
}

pub struct KvmX86Vm {
    machine: std::sync::Arc<Machine>,
    vcpus: NativePreparedVcpus,
}

impl KvmX86Vm {
    pub fn create(config: &VmConfig, hard_stop: Option<fn() -> !>) -> Result<Self, String> {
        let vcpu_count = usize::from(config.vcpus);
        if config.interrupt_controller != InterruptControllerConfig::X86
            || vcpu_count == 0
            || vcpu_count > X86_MAX_VCPUS as usize
        {
            return Err(format!("invalid x86 KVM VM dimensions: {vcpu_count} vCPUs"));
        }
        let kvm = super::kvm::open().map_err(|error| format!("opening KVM: {error}"))?;
        let cpuid = build_cpuid(&kvm, vcpu_count).map_err(|error| format!("KVM CPUID: {error}"))?;
        let machine = std::sync::Arc::new(
            Machine::new(&kvm, config.ram_base, config.ram_bytes, vcpu_count)
                .map_err(|error| format!("creating KVM VM: {error}"))?,
        );
        setup_irqchip(machine.vm_fd(), &config.irq_routes)
            .map_err(|error| format!("creating KVM irqchip: {error}"))?;
        let vcpus = NativePreparedVcpus::new(&machine, &cpuid, vcpu_count, hard_stop)
            .map_err(|error| format!("preparing KVM vCPUs: {error}"))?;
        Ok(Self { machine, vcpus })
    }

    #[allow(clippy::unnecessary_wraps)]
    pub const fn capabilities() -> Result<VmCapabilities, String> {
        Ok(VmCapabilities {
            interrupt_mode: InterruptMode::X86IrqLines,
            tsc_frequency: None,
        })
    }

    #[must_use]
    pub fn handle(&self) -> VmHandle {
        VmHandle::new(std::sync::Arc::clone(&self.machine))
    }

    pub fn start(
        self,
        boot: BootState,
        handlers: Vec<Box<dyn VcpuHandler>>,
    ) -> Result<VcpuGroup, String> {
        self.vcpus
            .start(handlers, boot)
            .map_err(|error| format!("starting KVM vCPUs: {error}"))
    }
}

pub(crate) struct NativePreparedVcpus {
    group: VcpuGroup,
    senders: Vec<std::sync::mpsc::SyncSender<VcpuCommand>>,
}

impl NativePreparedVcpus {
    pub(crate) fn new(
        machine: &std::sync::Arc<Machine>,
        cpuid: &kvm_bindings::CpuId,
        vcpu_count: usize,
        hard_stop: Option<fn() -> !>,
    ) -> Result<Self, KvmError> {
        if vcpu_count == 0 || vcpu_count > X86_MAX_VCPUS as usize {
            return Err(KvmError::BadVcpuCount(vcpu_count));
        }
        let mut group = VcpuGroup {
            runners: Vec::with_capacity(vcpu_count),
            hard_stop,
        };
        let mut senders = Vec::with_capacity(vcpu_count);
        for id in 0..vcpu_count {
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            let mut cpu_cpuid = cpuid.clone();
            configure_cpuid(
                cpu_cpuid.as_mut_slice(),
                u8::try_from(vcpu_count).map_err(|_| KvmError::BadVcpuCount(vcpu_count))?,
                u8::try_from(id).map_err(|_| KvmError::BadVcpuCount(vcpu_count))?,
            );
            let machine = std::sync::Arc::clone(machine);
            let vcpu_id = u64::try_from(id).map_err(|_| KvmError::BadVcpuCount(vcpu_count))?;
            group
                .runners
                .push(spawn_configured_vcpu_ready(vcpu_id, move |stop, ready| {
                    let mut vcpu = machine.create_vcpu(vcpu_id)?;
                    if id == 0 {
                        ready.send(()).map_err(|_| KvmError::ThreadGone)?;
                        let VcpuCommand::Start(mut handler, boot) =
                            receiver.recv().map_err(|_| KvmError::ThreadGone)?
                        else {
                            return Ok(VcpuOutcome::Stopped);
                        };
                        let outcome =
                            setup_bsp_planned(&cpu_cpuid, &vcpu, boot.entry, boot.boot_argument)
                                .map_err(KvmError::Bsp)
                                .and_then(|()| run_kernel_vcpu(&mut vcpu, stop, handler.as_mut()));
                        report_vcpu_failure(id, handler.as_mut(), outcome)
                    } else {
                        vcpu.set_cpuid2(&cpu_cpuid)
                            .map_err(|e| KvmError::Operation("KVM_SET_CPUID2", e))?;
                        park_ap(&vcpu)?;
                        ready.send(()).map_err(|_| KvmError::ThreadGone)?;
                        let VcpuCommand::Start(mut handler, _) =
                            receiver.recv().map_err(|_| KvmError::ThreadGone)?
                        else {
                            return Ok(VcpuOutcome::Stopped);
                        };
                        let outcome = run_kernel_vcpu(&mut vcpu, stop, handler.as_mut());
                        report_vcpu_failure(id, handler.as_mut(), outcome)
                    }
                })?);
            senders.push(sender);
        }
        Ok(Self { group, senders })
    }

    pub(crate) fn start(
        mut self,
        handlers: Vec<Box<dyn VcpuHandler>>,
        boot: BootState,
    ) -> Result<VcpuGroup, KvmError> {
        if handlers.len() != self.senders.len() {
            return Err(KvmError::ThreadGone);
        }
        for (sender, handler) in self.senders.drain(..).zip(handlers) {
            sender
                .send(VcpuCommand::Start(handler, boot))
                .map_err(|_| KvmError::ThreadGone)?;
        }
        let hard_stop = self.group.hard_stop;
        Ok(std::mem::replace(
            &mut self.group,
            VcpuGroup {
                runners: Vec::new(),
                hard_stop,
            },
        ))
    }
}

impl Drop for NativePreparedVcpus {
    fn drop(&mut self) {
        for sender in &self.senders {
            let _ = sender.send(VcpuCommand::Stop);
        }
        let hard_stop = self.group.hard_stop;
        let mut group = std::mem::replace(
            &mut self.group,
            VcpuGroup {
                runners: Vec::new(),
                hard_stop,
            },
        );
        let _ = group.join();
    }
}

pub struct VcpuGroup {
    runners: Vec<VcpuHandle>,
    hard_stop: Option<fn() -> !>,
}

impl VcpuGroup {
    pub fn request_stop(&self) {
        for runner in &self.runners {
            runner.request_stop();
        }
    }

    pub fn join(&mut self) -> Result<Vec<Result<(), String>>, String> {
        self.request_stop();
        let mut runners = std::mem::take(&mut self.runners);
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
            .map(|outcome| outcome.map(|_| ()).map_err(|error| error.to_string()))
            .collect())
    }
}

impl Drop for VcpuGroup {
    fn drop(&mut self) {
        if !self.runners.is_empty() {
            let runners = std::mem::take(&mut self.runners);
            let mut group = Self {
                runners,
                hard_stop: self.hard_stop,
            };
            let _ = group.join();
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cpuid_identities_and_topology_match_one_thread_per_guest_core() {
        use kvm_bindings::kvm_cpuid_entry2;

        let host_entries = [
            (1, 0, u32::MAX),
            (4, 0, 1 | (1 << 5) | 0xffff_c000),
            (4, 1, 3 | (3 << 5) | 0xffff_c000),
            (4, 2, 0),
            (0xb, 0, u32::MAX),
            (0xb, 1, u32::MAX),
            (0x1f, 0, u32::MAX),
            (0x8000_0008, 0, u32::MAX),
            (0x8000_001d, 0, 3 | (3 << 5) | 0xffff_c000),
            (0x8000_001e, 0, u32::MAX),
            (7, 0, u32::MAX),
        ]
        .map(|(function, index, eax)| kvm_cpuid_entry2 {
            function,
            index,
            eax,
            ebx: u32::MAX,
            ecx: u32::MAX,
            edx: u32::MAX,
            ..kvm_cpuid_entry2::default()
        });
        for count in [1_u8, 2, 3, terra_limits::X86_MAX_VCPUS] {
            for id in 0..count {
                let mut entries = host_entries;
                super::configure_cpuid(&mut entries, count, id);
                assert_eq!(entries[0].ebx >> 24, u32::from(id));
                assert_eq!((entries[0].ebx >> 16) & 0xff, u32::from(count));
                assert_eq!(entries[0].ebx & 0xffff, 0xffff);
                assert_ne!(entries[0].ecx & (1 << 31), 0);
                assert_eq!(entries[0].edx & (1 << 28) != 0, count > 1);
                for index in [1, 2] {
                    assert_eq!(entries[index].eax >> 26, u32::from(count - 1));
                }
                assert_eq!(entries[8].eax >> 26, 0);
                assert_eq!((entries[1].eax >> 14) & 0xfff, 0);
                assert_eq!((entries[2].eax >> 14) & 0xfff, u32::from(count - 1));
                assert_eq!(entries[3], host_entries[3]);
                for entry in &entries[4..7] {
                    assert_eq!((entry.eax, entry.ebx, entry.ecx), (0, 0, entry.index));
                    assert_eq!(entry.edx, u32::from(id));
                }
                assert_eq!(entries[7].ecx & 0xff, u32::from(count - 1));
                assert_eq!(
                    (entries[7].ecx >> 12) & 0xf,
                    u32::from(count).next_power_of_two().trailing_zeros()
                );
                assert_eq!(entries[7].eax, host_entries[7].eax);
                assert_eq!(entries[9].eax, u32::from(id));
                assert_eq!(entries[9].ebx, u32::from(id));
                assert_eq!((entries[9].ecx, entries[9].edx), (0, 0));
                assert_eq!(entries[10], host_entries[10]);
            }
        }
    }

    #[test]
    fn native_failure_notifies_the_host_with_cpu_and_hardware_reason() {
        struct Handler(Option<String>);
        impl crate::vm::VcpuHandler for Handler {
            fn exchange(
                &mut self,
                _: crate::vm::VcpuExit,
            ) -> Result<crate::vm::VcpuAction, String> {
                panic!("failure reporting must not re-enter the guest")
            }
            fn finished(&mut self, _: crate::vm::VcpuOutcome) {
                panic!("failure must not become a successful stop")
            }
            fn failed(&mut self, error: &str) {
                self.0 = Some(error.to_owned());
            }
        }
        let mut handler = Handler(None);
        let error = super::KvmError::Dispatch(super::super::kvm::DispatchError::Fatal(
            "fail-entry",
            0x8000_0021,
        ));
        let result: Result<crate::vm::VcpuOutcome, _> =
            super::report_vcpu_failure(2, &mut handler, Err(error));
        assert!(result.is_err());
        let error = handler.0.unwrap();
        assert!(error.contains("vCPU 2"));
        assert!(error.contains("fail-entry (0x80000021)"));
    }

    #[test]
    #[ignore = "needs /dev/kvm"]
    fn cpuid_matches_the_fixed_vcpu_count() {
        let kvm = super::super::kvm::open().expect("open KVM");
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
        assert!(super::stop_timed_out(&[Err(super::KvmError::Timeout)]));
        assert!(!super::stop_timed_out(&[Ok(
            crate::vm::VcpuOutcome::Stopped
        )]));
    }
}
