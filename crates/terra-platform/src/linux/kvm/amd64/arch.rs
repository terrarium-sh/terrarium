//! KVM x86 CPU state and interrupt routing for boot tables staged by Wasm.

use kvm_bindings::{CpuId, KvmIrqRouting, kvm_regs, kvm_segment, kvm_sregs};
use kvm_ioctls::{VcpuFd, VmFd};

pub const GDT_ADDR: u64 = terra_limits::X86_GDT_ADDR;
pub const PML4_ADDR: u64 = terra_limits::X86_PML4_ADDR;
pub const STACK_TOP: u64 = terra_limits::X86_STACK_TOP;
pub(crate) const KVM_MAX_CPUID_ENTRIES: usize = 80;
const CR0_PROTECTED_PAGING: u64 = 0x8005_0033;
const CR4_PAE: u64 = 0x20;
const EFER_LME_LMA: u64 = 0x500;
const IOAPIC_GSI_BASE: u32 = crate::machine::IRQ_BASE;
const IOAPIC_PINS: u32 = terra_limits::X86_IOAPIC_PINS;

#[derive(Debug)]
pub enum ArchError {
    Kvm(kvm_ioctls::Error),
    IrqOutOfRange(u32),
    Routing,
}

impl From<kvm_ioctls::Error> for ArchError {
    fn from(error: kvm_ioctls::Error) -> Self {
        Self::Kvm(error)
    }
}

fn code_segment() -> kvm_segment {
    kvm_segment {
        base: 0,
        limit: 0xFFFFF,
        selector: 0x08,
        type_: 0xB,
        present: 1,
        dpl: 0,
        db: 0,
        s: 1,
        l: 1,
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

fn data_segment() -> kvm_segment {
    kvm_segment {
        base: 0,
        limit: 0xFFFFF,
        selector: 0x10,
        type_: 0x3,
        present: 1,
        dpl: 0,
        db: 1,
        s: 1,
        l: 0,
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

fn configure_sregs(vcpu: &VcpuFd) -> Result<(), ArchError> {
    let mut sregs: kvm_sregs = vcpu.get_sregs()?;
    sregs.cs = code_segment();
    sregs.ds = data_segment();
    sregs.es = data_segment();
    sregs.fs = data_segment();
    sregs.gs = data_segment();
    sregs.ss = data_segment();
    sregs.gdt.base = GDT_ADDR;
    sregs.gdt.limit = 0x17;
    sregs.cr0 = CR0_PROTECTED_PAGING;
    sregs.cr3 = PML4_ADDR;
    sregs.cr4 = CR4_PAE;
    sregs.efer = EFER_LME_LMA;
    vcpu.set_sregs(&sregs)?;
    Ok(())
}

fn setup_regs(vcpu: &VcpuFd, entry: u64, boot_argument: u64) -> Result<(), ArchError> {
    vcpu.set_regs(&kvm_regs {
        rip: entry,
        rsi: boot_argument,
        rflags: 2,
        rsp: STACK_TOP,
        ..Default::default()
    })?;
    Ok(())
}

pub fn setup_bsp_planned(
    cpuid: &CpuId,
    vcpu: &VcpuFd,
    entry: u64,
    boot_argument: u64,
) -> Result<(), ArchError> {
    vcpu.set_cpuid2(cpuid)?;
    configure_sregs(vcpu)?;
    setup_regs(vcpu, entry, boot_argument)
}

fn unique_gsis(gsis: &[u32]) -> Result<Vec<u32>, ArchError> {
    let mut unique = Vec::new();
    for gsi in gsis {
        if *gsi < IOAPIC_GSI_BASE || *gsi >= IOAPIC_PINS {
            return Err(ArchError::IrqOutOfRange(*gsi));
        }
        if !unique.contains(gsi) {
            unique.push(*gsi);
        }
    }
    Ok(unique)
}

pub fn setup_irqchip(vm: &VmFd, gsis: &[u32]) -> Result<(), ArchError> {
    let gsis = unique_gsis(gsis)?;
    let mut routing = KvmIrqRouting::new(gsis.len()).map_err(|_| ArchError::Routing)?;
    for (entry, gsi) in routing.as_mut_slice().iter_mut().zip(gsis) {
        entry.gsi = gsi;
        entry.type_ = kvm_bindings::KVM_IRQ_ROUTING_IRQCHIP;
        entry.u.irqchip.irqchip = kvm_bindings::KVM_IRQCHIP_IOAPIC;
        entry.u.irqchip.pin = gsi;
    }
    vm.create_irq_chip()?;
    vm.set_gsi_routing(&routing)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn irq_routes_are_deduplicated_before_installation() {
        assert_eq!(unique_gsis(&[11, 12, 11, 20, 12]).unwrap(), [11, 12, 20]);
        assert!(matches!(
            unique_gsis(&[10]),
            Err(ArchError::IrqOutOfRange(10))
        ));
    }
}
