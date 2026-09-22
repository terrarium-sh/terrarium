//! KVM x86 CPU state and interrupt routing for boot tables staged by Wasm.

use kvm_bindings::{CpuId, KvmIrqRouting, kvm_regs, kvm_segment, kvm_sregs};
use kvm_ioctls::{VcpuFd, VmFd};
use std::{error, fmt};

pub const GDT_ADDR: u64 = terra_limits::X86_GDT_ADDR;
pub const PML4_ADDR: u64 = terra_limits::X86_PML4_ADDR;
pub const STACK_TOP: u64 = terra_limits::X86_STACK_TOP;
const CR0_PROTECTED_PAGING: u64 = 0x8005_0033;
const CR4_PAE: u64 = 0x20;
const EFER_LME_LMA: u64 = 0x500;
const IOAPIC_GSI_BASE: u32 = 11;
const IOAPIC_PINS: u32 = terra_limits::X86_IOAPIC_PINS;
const PIC_PINS: u32 = 8;
const PIC_IRQS: u32 = PIC_PINS * 2;

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

impl fmt::Display for ArchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kvm(error) => write!(formatter, "KVM error: {error}"),
            Self::IrqOutOfRange(irq) => write!(formatter, "IRQ {irq} is outside the IOAPIC range"),
            Self::Routing => formatter.write_str("allocating KVM IRQ routing"),
        }
    }
}

impl error::Error for ArchError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Kvm(error) => Some(error),
            Self::IrqOutOfRange(_) | Self::Routing => None,
        }
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

fn validate_device_gsis(gsis: &[u32]) -> Result<(), ArchError> {
    for gsi in gsis {
        if *gsi < IOAPIC_GSI_BASE || *gsi >= IOAPIC_PINS {
            return Err(ArchError::IrqOutOfRange(*gsi));
        }
    }
    Ok(())
}

pub fn setup_irqchip(vm: &VmFd, gsis: &[u32]) -> Result<(), ArchError> {
    validate_device_gsis(gsis)?;
    let route_count = usize::try_from(IOAPIC_PINS + PIC_IRQS).map_err(|_| ArchError::Routing)?;
    let mut routing = KvmIrqRouting::new(route_count).map_err(|_| ArchError::Routing)?;
    for (entry, gsi) in routing
        .as_mut_slice()
        .iter_mut()
        .take(usize::try_from(IOAPIC_PINS).map_err(|_| ArchError::Routing)?)
        .zip(0..IOAPIC_PINS)
    {
        entry.gsi = gsi;
        entry.type_ = kvm_bindings::KVM_IRQ_ROUTING_IRQCHIP;
        entry.u.irqchip.irqchip = kvm_bindings::KVM_IRQCHIP_IOAPIC;
        entry.u.irqchip.pin = gsi;
    }
    for (entry, gsi) in routing
        .as_mut_slice()
        .iter_mut()
        .skip(usize::try_from(IOAPIC_PINS).map_err(|_| ArchError::Routing)?)
        .zip(0..PIC_IRQS)
    {
        entry.gsi = gsi;
        entry.type_ = kvm_bindings::KVM_IRQ_ROUTING_IRQCHIP;
        if gsi < PIC_PINS {
            entry.u.irqchip.irqchip = kvm_bindings::KVM_IRQCHIP_PIC_MASTER;
            entry.u.irqchip.pin = gsi;
        } else {
            entry.u.irqchip.irqchip = kvm_bindings::KVM_IRQCHIP_PIC_SLAVE;
            entry.u.irqchip.pin = gsi - PIC_PINS;
        }
    }
    vm.create_irq_chip()?;
    vm.create_pit2(kvm_bindings::kvm_pit_config::default())?;
    vm.set_gsi_routing(&routing)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_routes_stay_within_the_virtio_irq_range() {
        assert!(validate_device_gsis(&[11, 12, 11, 20, 12]).is_ok());
        assert!(matches!(
            validate_device_gsis(&[10]),
            Err(ArchError::IrqOutOfRange(10))
        ));
    }
}
