//! KVM `x86_64` boot vCPU registers and the in-kernel interrupt controller.

use crate::kvm::KvmError;
use crate::x86::{self, Segment};
use kvm_bindings::{CpuId, kvm_regs, kvm_segment, kvm_sregs};
use kvm_ioctls::{VcpuFd, VmFd};

const IOAPIC_GSI_BASE: u32 = 11;
const IOAPIC_PINS: u32 = terra_limits::X86_IOAPIC_PINS;

fn kvm_segment(segment: Segment) -> kvm_segment {
    kvm_segment {
        base: Segment::BASE,
        limit: Segment::LIMIT,
        selector: segment.selector,
        type_: segment.descriptor_type,
        present: 1,
        dpl: 0,
        db: segment.is_32_bit_default.into(),
        s: 1,
        l: segment.is_long_mode.into(),
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

fn configure_sregs(vcpu: &VcpuFd) -> Result<(), KvmError> {
    let mut sregs: kvm_sregs = vcpu
        .get_sregs()
        .map_err(|e| KvmError::Operation("KVM_GET_SREGS", e))?;
    let data = kvm_segment(x86::DATA_SEGMENT);
    sregs.cs = kvm_segment(x86::CODE_SEGMENT);
    sregs.ds = data;
    sregs.es = data;
    sregs.fs = data;
    sregs.gs = data;
    sregs.ss = data;
    sregs.gdt.base = x86::GDT_BASE;
    sregs.gdt.limit = x86::GDT_LIMIT;
    sregs.cr0 = x86::CR0_PROTECTED_PAGING;
    sregs.cr3 = x86::CR3_PML4;
    sregs.cr4 = x86::CR4_PAE;
    sregs.efer = x86::EFER_LME_LMA;
    vcpu.set_sregs(&sregs)
        .map_err(|e| KvmError::Operation("KVM_SET_SREGS", e))?;
    Ok(())
}

fn setup_regs(vcpu: &VcpuFd, entry: u64, boot_argument: u64) -> Result<(), KvmError> {
    vcpu.set_regs(&kvm_regs {
        rip: entry,
        rsi: boot_argument,
        rflags: x86::RFLAGS,
        rsp: x86::RSP,
        ..Default::default()
    })
    .map_err(|e| KvmError::Operation("KVM_SET_REGS", e))?;
    Ok(())
}

pub(super) fn setup_bsp_planned(
    cpuid: &CpuId,
    vcpu: &VcpuFd,
    entry: u64,
    boot_argument: u64,
) -> Result<(), KvmError> {
    vcpu.set_cpuid2(cpuid)
        .map_err(|e| KvmError::Operation("KVM_SET_CPUID2", e))?;
    configure_sregs(vcpu)?;
    setup_regs(vcpu, entry, boot_argument)
}

fn validate_device_gsis(gsis: &[u32]) -> Result<(), KvmError> {
    for gsi in gsis {
        if *gsi < IOAPIC_GSI_BASE || *gsi >= IOAPIC_PINS {
            return Err(KvmError::IrqOutOfRange(*gsi));
        }
    }
    Ok(())
}

pub(super) fn setup_irqchip(vm: &VmFd, gsis: &[u32]) -> Result<(), KvmError> {
    validate_device_gsis(gsis)?;
    // KVM installs the legacy PIC and IOAPIC routes; replacing them with device grants drops IRQ 0.
    vm.create_irq_chip()
        .map_err(|e| KvmError::Operation("KVM_CREATE_IRQCHIP", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn device_gsis_stay_in_the_virtio_range() {
        assert!(validate_device_gsis(&[11, 12, 11, 20, 23]).is_ok());
        for gsi in [0, 10, 24, u32::MAX] {
            assert_matches!(
                validate_device_gsis(&[gsi]),
                Err(KvmError::IrqOutOfRange(irq)) if irq == gsi
            );
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
