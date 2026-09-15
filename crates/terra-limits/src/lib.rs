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
pub const X86_GDT_ADDR: u64 = 0x500;
pub const X86_PML4_ADDR: u64 = 0x9000;
pub const X86_STACK_TOP: u64 = 0x8ff0;
pub const X86_IOAPIC_PINS: u32 = 24;
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
