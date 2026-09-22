//! KVM x86 CPU state and interrupt routing for boot tables staged by Wasm.

use kvm_bindings::{CpuId, kvm_regs, kvm_segment, kvm_sregs};
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

#[derive(Debug)]
pub enum ArchError {
    Kvm(&'static str, kvm_ioctls::Error),
    IrqOutOfRange(u32),
}

impl From<kvm_ioctls::Error> for ArchError {
    fn from(error: kvm_ioctls::Error) -> Self {
        Self::Kvm("KVM", error)
    }
}

impl fmt::Display for ArchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kvm(operation, error) => write!(formatter, "{operation}: {error}"),
            Self::IrqOutOfRange(irq) => write!(formatter, "IRQ {irq} is outside the IOAPIC range"),
        }
    }
}

impl error::Error for ArchError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Kvm(_, error) => Some(error),
            Self::IrqOutOfRange(_) => None,
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
    let mut sregs: kvm_sregs = vcpu
        .get_sregs()
        .map_err(|e| ArchError::Kvm("KVM_GET_SREGS", e))?;
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
    vcpu.set_sregs(&sregs)
        .map_err(|e| ArchError::Kvm("KVM_SET_SREGS", e))?;
    Ok(())
}

fn setup_regs(vcpu: &VcpuFd, entry: u64, boot_argument: u64) -> Result<(), ArchError> {
    vcpu.set_regs(&kvm_regs {
        rip: entry,
        rsi: boot_argument,
        rflags: 2,
        rsp: STACK_TOP,
        ..Default::default()
    })
    .map_err(|e| ArchError::Kvm("KVM_SET_REGS", e))?;
    Ok(())
}

pub fn setup_bsp_planned(
    cpuid: &CpuId,
    vcpu: &VcpuFd,
    entry: u64,
    boot_argument: u64,
) -> Result<(), ArchError> {
    vcpu.set_cpuid2(cpuid)
        .map_err(|e| ArchError::Kvm("KVM_SET_CPUID2", e))?;
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
    // KVM installs the legacy PIC and IOAPIC routes; replacing them with device grants drops IRQ 0.
    vm.create_irq_chip()
        .map_err(|e| ArchError::Kvm("KVM_CREATE_IRQCHIP", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_gsis_stay_in_the_virtio_range() {
        assert!(validate_device_gsis(&[11, 12, 11, 20, 23]).is_ok());
        for gsi in [0, 10, 24, u32::MAX] {
            assert!(matches!(
                validate_device_gsis(&[gsi]),
                Err(ArchError::IrqOutOfRange(irq)) if irq == gsi
            ));
        }
    }

    #[test]
    #[ignore = "requires /dev/kvm"]
    #[allow(unsafe_code)]
    fn device_grants_preserve_legacy_pic_routing() {
        let kvm = kvm_ioctls::Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        setup_irqchip(&vm, &[11, 12, 23]).unwrap();
        let _vcpu = vm.create_vcpu(0).unwrap();
        for (gsi, chip_id) in [
            (0, kvm_bindings::KVM_IRQCHIP_PIC_MASTER),
            (8, kvm_bindings::KVM_IRQCHIP_PIC_SLAVE),
        ] {
            vm.set_irq_line(gsi, true).unwrap();
            let mut chip = kvm_bindings::kvm_irqchip {
                chip_id,
                ..Default::default()
            };
            vm.get_irqchip(&mut chip).unwrap();
            // SAFETY: chip_id selects the PIC member populated by KVM_GET_IRQCHIP.
            assert_ne!(unsafe { chip.chip.pic.irr } & 1, 0, "GSI {gsi}");
            vm.set_irq_line(gsi, false).unwrap();
        }
    }
}
