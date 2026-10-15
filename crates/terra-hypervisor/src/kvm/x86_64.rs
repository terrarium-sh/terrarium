//! KVM `x86_64` VM preparation, CPUID topology, and vCPU threads.

#![allow(unsafe_code)]

mod boot;
mod machine;

pub(crate) use machine::Machine;

use super::KvmError;
use super::kick::PthreadKicks;
use crate::vcpus::{Startup, Stop, Vcpus};
use crate::vm::{
    BootState, InterruptControllerConfig, InterruptMode, VcpuHandler, VmCapabilities, VmConfig,
    VmHandle, report_vcpu_failure,
};
use boot::{setup_bsp_planned, setup_irqchip};
use kvm_bindings::{CpuId, KVM_MAX_CPUID_ENTRIES};
use machine::{open_kvm, park_ap, run_kernel_vcpu};
use std::sync::Arc;
use terra_limits::X86_MAX_VCPUS;

pub(super) fn build_cpuid(
    kvm: &kvm_ioctls::Kvm,
    vcpu_count: usize,
) -> Result<kvm_bindings::CpuId, KvmError> {
    let vcpus = u8::try_from(vcpu_count).map_err(|_| KvmError::BadVcpuCount(vcpu_count))?;
    if vcpu_count == 0 || vcpu_count > X86_MAX_VCPUS as usize {
        return Err(KvmError::BadVcpuCount(vcpu_count));
    }
    let mut cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
    hide_virtualization_extensions(cpuid.as_mut_slice());
    configure_cpuid(cpuid.as_mut_slice(), vcpus, 0);
    Ok(cpuid)
}

const CPUID_VMX: (u32, u32) = (1, 1 << 5);
const CPUID_SVM: (u32, u32) = (0x8000_0001, 1 << 2);

/// KVM offers VMX/SVM whenever the host enables nested KVM, exposing its nested code to the
/// guest; without the CPUID bit KVM rejects CR4.VMXE and EFER.SVME, whatever the guest kernel.
fn hide_virtualization_extensions(entries: &mut [kvm_bindings::kvm_cpuid_entry2]) {
    for entry in entries {
        for (function, ecx) in [CPUID_VMX, CPUID_SVM] {
            if entry.function == function {
                entry.ecx &= !ecx;
            }
        }
    }
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

pub struct Vm {
    machine: Arc<Machine>,
    vcpus: Vcpus,
}

impl Vm {
    pub fn create(config: &VmConfig, hard_stop: Option<fn() -> !>) -> Result<Self, String> {
        let vcpu_count = usize::from(config.vcpus);
        if config.interrupt_controller != InterruptControllerConfig::X86
            || vcpu_count == 0
            || vcpu_count > X86_MAX_VCPUS as usize
        {
            return Err(format!("invalid x86 KVM VM dimensions: {vcpu_count} vCPUs"));
        }
        let kvm = open_kvm().map_err(|error| format!("opening KVM: {error}"))?;
        let cpuid = build_cpuid(&kvm, vcpu_count).map_err(|error| format!("KVM CPUID: {error}"))?;
        let machine = Arc::new(
            Machine::new(&kvm, config.ram_base, config.ram_bytes, vcpu_count)
                .map_err(|error| format!("creating KVM VM: {error}"))?,
        );
        setup_irqchip(machine.vm_fd(), &config.irq_routes)
            .map_err(|error| format!("creating KVM irqchip: {error}"))?;
        let kicks = PthreadKicks::new(vcpu_count)
            .map_err(|error| KvmError::KickHandler(error).to_string())?;
        let mut vcpus = Vcpus::new(vcpu_count, kicks.clone(), hard_stop);
        for id in 0..vcpu_count {
            let mut vcpu_cpuid = cpuid.clone();
            configure_cpuid(
                vcpu_cpuid.as_mut_slice(),
                config.vcpus,
                u8::try_from(id).map_err(|_| KvmError::BadVcpuCount(vcpu_count).to_string())?,
            );
            let machine = Arc::clone(&machine);
            let kicks = Arc::clone(&kicks);
            let stop = vcpus.stop();
            vcpus
                .spawn(move |startup| {
                    run_vcpu_thread(id, &machine, &vcpu_cpuid, &kicks, &stop, startup)
                        .map_err(|error| error.to_string())
                })
                .map_err(|error| format!("preparing KVM vCPU {id}: {error}"))?;
        }
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
        VmHandle::new(Arc::clone(&self.machine))
    }

    pub fn start(
        mut self,
        boot: BootState,
        handlers: Vec<Box<dyn VcpuHandler>>,
    ) -> Result<Vcpus, String> {
        self.vcpus
            .start(boot, handlers)
            .map_err(|error| format!("starting KVM vCPUs: {error}"))?;
        Ok(self.vcpus)
    }
}

/// Parks each AP before startup completes, since the BSP's SIPIs need parked APs.
fn run_vcpu_thread(
    id: usize,
    machine: &Machine,
    cpuid: &CpuId,
    kicks: &PthreadKicks,
    stop: &Stop,
    startup: Startup,
) -> Result<(), KvmError> {
    let _published = kicks.publish(id).map_err(KvmError::KickHandler)?;
    let mut vcpu =
        machine.create_vcpu(u64::try_from(id).map_err(|_| KvmError::BadVcpuCount(id))?)?;
    if id != 0 {
        vcpu.set_cpuid2(cpuid)
            .map_err(|e| KvmError::Operation("KVM_SET_CPUID2", e))?;
        park_ap(&vcpu)?;
    }
    let Some((mut handler, boot)) = startup.wait() else {
        return Ok(());
    };
    let outcome = if id == 0 {
        setup_bsp_planned(cpuid, &vcpu, boot.entry, boot.boot_argument)
            .and_then(|()| run_kernel_vcpu(&mut vcpu, stop, handler.as_mut()))
    } else {
        run_kernel_vcpu(&mut vcpu, stop, handler.as_mut())
    };
    report_vcpu_failure(id, handler.as_mut(), outcome).map(drop)
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

    /// A host with nested KVM must not hand the guest VMX or SVM.
    #[test]
    fn virtualization_extensions_are_hidden() {
        use kvm_bindings::kvm_cpuid_entry2;

        let mut entries =
            [(1, 1 << 5), (0x8000_0001, 1 << 2), (7, u32::MAX)].map(|(function, ecx)| {
                kvm_cpuid_entry2 {
                    function,
                    ecx: ecx | 1,
                    ..kvm_cpuid_entry2::default()
                }
            });
        super::hide_virtualization_extensions(&mut entries);
        assert_eq!(entries.map(|entry| entry.ecx), [1, 1, u32::MAX]);
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
        let error = super::KvmError::FatalExit("fail-entry", 0x8000_0021);
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
        let kvm = super::open_kvm().expect("open KVM");
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
            for (function, ecx) in [super::CPUID_VMX, super::CPUID_SVM] {
                assert!(
                    cpuid
                        .as_slice()
                        .iter()
                        .all(|entry| entry.function != function || entry.ecx & ecx == 0)
                );
            }
        }
        assert!(super::build_cpuid(&kvm, 0).is_err());
        assert!(super::build_cpuid(&kvm, 256).is_err());
    }
}
