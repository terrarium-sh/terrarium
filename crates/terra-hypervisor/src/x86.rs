//! The 64-bit long-mode CPU state an x86 guest boots in, before each backend's register encoding.

pub(crate) const CR0_PROTECTED_PAGING: u64 = 0x8005_0033;
pub(crate) const CR3_PML4: u64 = terra_limits::X86_PML4_ADDR;
pub(crate) const CR4_PAE: u64 = 0x20;
pub(crate) const EFER_LME_LMA: u64 = 0x500;
pub(crate) const GDT_BASE: u64 = terra_limits::X86_GDT_ADDR;
pub(crate) const GDT_LIMIT: u16 = 0x17;
pub(crate) const RSP: u64 = terra_limits::X86_STACK_TOP;
pub(crate) const RFLAGS: u64 = 2;

/// A flat 4 GiB segment descriptor in the guest GDT.
#[derive(Clone, Copy)]
pub(crate) struct Segment {
    pub(crate) selector: u16,
    pub(crate) descriptor_type: u8,
    pub(crate) is_long_mode: bool,
    pub(crate) is_32_bit_default: bool,
}

pub(crate) const CODE_SEGMENT: Segment = Segment {
    selector: 0x08,
    descriptor_type: 0xB,
    is_long_mode: true,
    is_32_bit_default: false,
};

pub(crate) const DATA_SEGMENT: Segment = Segment {
    selector: 0x10,
    descriptor_type: 0x3,
    is_long_mode: false,
    is_32_bit_default: true,
};

impl Segment {
    pub(crate) const BASE: u64 = 0;
    pub(crate) const LIMIT: u32 = 0xF_FFFF;

    /// The present, ring-0, page-granular code or data descriptor attribute word.
    #[cfg(any(windows, test))]
    pub(crate) fn attributes(self) -> u16 {
        const DESCRIPTOR: u16 = 1 << 4;
        const PRESENT: u16 = 1 << 7;
        const LONG_MODE: u16 = 1 << 13;
        const DEFAULT_32_BIT: u16 = 1 << 14;
        const PAGE_GRANULAR: u16 = 1 << 15;
        u16::from(self.descriptor_type)
            | DESCRIPTOR
            | PRESENT
            | if self.is_long_mode { LONG_MODE } else { 0 }
            | if self.is_32_bit_default {
                DEFAULT_32_BIT
            } else {
                0
            }
            | PAGE_GRANULAR
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The attribute words match the GDT entries the guest's boot tables describe.
    #[test]
    fn segments_set_the_long_mode_descriptor_bits() {
        assert_eq!(CODE_SEGMENT.attributes(), 0xA09B);
        assert_eq!(DATA_SEGMENT.attributes(), 0xC093);
    }
}
