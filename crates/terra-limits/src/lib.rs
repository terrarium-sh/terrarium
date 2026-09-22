#![no_std]

pub const X86_MAX_DEVICES: usize = 37;
pub const X86_MAX_VCPUS: u8 = 32;
pub const ARM_MAX_DEVICES: usize = 16;
pub const ARM_MAX_VCPUS: u8 = 8;
pub const MAX_DEVICES: usize = if X86_MAX_DEVICES > ARM_MAX_DEVICES {
    X86_MAX_DEVICES
} else {
    ARM_MAX_DEVICES
};
pub const MAX_VCPUS: u8 = if X86_MAX_VCPUS > ARM_MAX_VCPUS {
    X86_MAX_VCPUS
} else {
    ARM_MAX_VCPUS
};
pub const ARM_PSTATE_EL1H_DAIF: u64 = 0x3c5;
pub const X86_GDT_ADDR: u64 = X86_RAM_BASE + 0x500;
pub const X86_PML4_ADDR: u64 = X86_RAM_BASE + 0x9000;
pub const X86_STACK_TOP: u64 = X86_RAM_BASE + 0x8ff0;
pub const X86_IOAPIC_PINS: u32 = 24;
pub const X86_RAM_BASE: u64 = 0;
pub const X86_MMIO_BASE: u64 = 0xd000_0000;
pub const X86_MMIO_STRIDE: u64 = 0x1000;
pub const X86_RAM_LOW_END: u64 = X86_MMIO_BASE;
pub const X86_KVM_IDENTITY_MAP_ADDR: u64 = 0xfffb_c000;
pub const X86_KVM_TSS_ADDR: u64 = 0xfffb_d000;
const _: () = {
    assert!(X86_RAM_LOW_END <= X86_KVM_IDENTITY_MAP_ADDR);
    assert!(X86_MMIO_BASE + X86_MAX_DEVICES as u64 * X86_MMIO_STRIDE <= X86_KVM_IDENTITY_MAP_ADDR);
    assert!(0xfee0_1000 <= X86_KVM_IDENTITY_MAP_ADDR);
    assert!(X86_KVM_IDENTITY_MAP_ADDR + RAM_PAGE_SIZE == X86_KVM_TSS_ADDR);
    assert!(X86_KVM_TSS_ADDR + 3 * RAM_PAGE_SIZE <= X86_HIGH_RAM_BASE);
};
pub const X86_HIGH_RAM_BASE: u64 = 0x1_0000_0000;
pub const X86_ZERO_PAGE: u64 = X86_RAM_BASE + 0x7000;
pub const RAM_PAGE_SIZE: u64 = 4096;
const _: () = assert!(X86_RAM_LOW_END <= X86_MMIO_BASE);
pub const MAX_VM_OPEN_FILES: usize = 4096;
pub const MAX_SINGLE_GUEST_COPY_BYTES: u64 = 16 * 1024;
pub const MAX_BATCH_GUEST_COPY_BYTES: u64 = 64 * 1024;
pub const MAX_GUEST_DISCARD_BYTES: u64 = 1024 * 1024;

pub const ARM_RAM_BASE: u64 = 0x4000_0000;
pub const ARM_GIC_DIST_BASE: u64 = 0x0800_0000;
pub const ARM_GIC_DIST_SIZE: u64 = 0x0001_0000;
pub const ARM_GIC_REDIST_BASE: u64 = 0x080a_0000;
pub const ARM_GIC_REDIST_SIZE: u64 = 0x0020_0000;
pub const ARM_VIRTIO_MMIO_BASE: u64 = 0x0a00_0000;
pub const ARM_VIRTIO_MMIO_STRIDE: u64 = 0x200;
pub const ARM_VIRTIO_IRQ_BASE: u32 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RamRegion {
    pub base: u64,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RamLayout {
    One(RamRegion),
    Two(RamRegion, RamRegion),
}

impl RamLayout {
    pub fn regions(self) -> impl Iterator<Item = RamRegion> {
        match self {
            Self::One(region) => [Some(region), None],
            Self::Two(first, second) => [Some(first), Some(second)],
        }
        .into_iter()
        .flatten()
    }
}

#[must_use]
pub const fn x86_ram_layout(size: u64) -> Option<RamLayout> {
    if size == 0 || !size.is_multiple_of(RAM_PAGE_SIZE) {
        return None;
    }
    let low_capacity = X86_RAM_LOW_END - X86_RAM_BASE;
    let low_size = if size < low_capacity {
        size
    } else {
        low_capacity
    };
    let high_size = size - low_size;
    if high_size == 0 {
        return Some(RamLayout::One(RamRegion {
            base: X86_RAM_BASE,
            size: low_size,
        }));
    }
    if X86_HIGH_RAM_BASE.checked_add(high_size).is_none() {
        return None;
    }
    Some(RamLayout::Two(
        RamRegion {
            base: X86_RAM_BASE,
            size: low_size,
        },
        RamRegion {
            base: X86_HIGH_RAM_BASE,
            size: high_size,
        },
    ))
}

#[must_use]
pub const fn arm_ram_layout(size: u64) -> Option<RamLayout> {
    if size == 0 || !size.is_multiple_of(RAM_PAGE_SIZE) {
        return None;
    }
    if ARM_RAM_BASE.checked_add(size).is_none() {
        return None;
    }
    Some(RamLayout::One(RamRegion {
        base: ARM_RAM_BASE,
        size,
    }))
}

pub const MAX_LOG_FILE_BYTES: u64 = 8 << 20;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_ram_uses_the_low_region_before_the_device_hole() {
        let low_size = X86_RAM_LOW_END - X86_RAM_BASE;
        assert_eq!(
            x86_ram_layout(low_size),
            Some(RamLayout::One(RamRegion {
                base: X86_RAM_BASE,
                size: low_size,
            }))
        );
        assert_eq!(
            x86_ram_layout(low_size + RAM_PAGE_SIZE),
            Some(RamLayout::Two(
                RamRegion {
                    base: X86_RAM_BASE,
                    size: low_size,
                },
                RamRegion {
                    base: X86_HIGH_RAM_BASE,
                    size: RAM_PAGE_SIZE,
                },
            ))
        );
    }

    #[test]
    fn ram_layouts_reject_invalid_sizes_and_overflow() {
        assert_eq!(x86_ram_layout(0), None);
        assert_eq!(x86_ram_layout(1), None);
        assert_eq!(x86_ram_layout(u64::MAX - (RAM_PAGE_SIZE - 1)), None);
        assert_eq!(arm_ram_layout(0), None);
        assert_eq!(arm_ram_layout(1), None);
        assert_eq!(arm_ram_layout(u64::MAX - (RAM_PAGE_SIZE - 1)), None);
    }
}
