//! AMD64 WHP planned-boot register state.

use windows_sys::Win32::System::Hypervisor::{
    WHV_REGISTER_VALUE, WHV_X64_SEGMENT_REGISTER, WHV_X64_SEGMENT_REGISTER_0,
    WHV_X64_TABLE_REGISTER,
};

pub use windows_sys::Win32::System::Hypervisor::{
    WHvX64RegisterCr0 as WHV_X64_REGISTER_CR0, WHvX64RegisterCr3 as WHV_X64_REGISTER_CR3,
    WHvX64RegisterCr4 as WHV_X64_REGISTER_CR4, WHvX64RegisterCs as WHV_X64_REGISTER_CS,
    WHvX64RegisterDs as WHV_X64_REGISTER_DS, WHvX64RegisterEfer as WHV_X64_REGISTER_EFER,
    WHvX64RegisterEs as WHV_X64_REGISTER_ES, WHvX64RegisterFs as WHV_X64_REGISTER_FS,
    WHvX64RegisterGdtr as WHV_X64_REGISTER_GDTR, WHvX64RegisterGs as WHV_X64_REGISTER_GS,
    WHvX64RegisterIdtr as WHV_X64_REGISTER_IDTR, WHvX64RegisterRflags as WHV_X64_REGISTER_RFLAGS,
    WHvX64RegisterRip as WHV_X64_REGISTER_RIP, WHvX64RegisterRsi as WHV_X64_REGISTER_RSI,
    WHvX64RegisterRsp as WHV_X64_REGISTER_RSP, WHvX64RegisterSs as WHV_X64_REGISTER_SS,
};

use super::whp::{Partition, PartitionError};

pub const IOAPIC_BASE: u64 = 0xFEC0_0000;
pub const IOAPIC_SIZE: u64 = 0x20;

const GDT_ADDR: u64 = terra_limits::X86_GDT_ADDR;
const PML4_ADDR: u64 = terra_limits::X86_PML4_ADDR;
const STACK_TOP: u64 = terra_limits::X86_STACK_TOP;
const CR0_PROTECTED_PAGING: u64 = 0x8005_0033;
const CR4_PAE: u64 = 0x20;
const EFER_LME_LMA: u64 = 0x500;
const CODE_SEGMENT_ATTRIBUTES: u16 = 0xA09B;
const DATA_SEGMENT_ATTRIBUTES: u16 = 0xC093;

fn segment(selector: u16, attributes: u16) -> WHV_X64_SEGMENT_REGISTER {
    WHV_X64_SEGMENT_REGISTER {
        Base: 0,
        Limit: 0xF_FFFF,
        Selector: selector,
        Anonymous: WHV_X64_SEGMENT_REGISTER_0 {
            Attributes: attributes,
        },
    }
}

fn table(base: u64, limit: u16) -> WHV_X64_TABLE_REGISTER {
    WHV_X64_TABLE_REGISTER {
        Pad: [0; 3],
        Limit: limit,
        Base: base,
    }
}

/// Initialize the WHP BSP from Wasm-planned boot tables already in guest RAM.
pub fn configure_planned_boot(
    partition: &Partition,
    kernel_entry: u64,
    boot_params_address: u64,
) -> Result<(), PartitionError> {
    let code = segment(0x08, CODE_SEGMENT_ATTRIBUTES);
    let data = segment(0x10, DATA_SEGMENT_ATTRIBUTES);
    let names = [
        WHV_X64_REGISTER_CR0,
        WHV_X64_REGISTER_CR3,
        WHV_X64_REGISTER_CR4,
        WHV_X64_REGISTER_EFER,
        WHV_X64_REGISTER_CS,
        WHV_X64_REGISTER_DS,
        WHV_X64_REGISTER_ES,
        WHV_X64_REGISTER_FS,
        WHV_X64_REGISTER_GS,
        WHV_X64_REGISTER_SS,
        WHV_X64_REGISTER_GDTR,
        WHV_X64_REGISTER_IDTR,
        WHV_X64_REGISTER_RIP,
        WHV_X64_REGISTER_RSI,
        WHV_X64_REGISTER_RSP,
        WHV_X64_REGISTER_RFLAGS,
    ];
    let values = [
        WHV_REGISTER_VALUE {
            Reg64: CR0_PROTECTED_PAGING,
        },
        WHV_REGISTER_VALUE { Reg64: PML4_ADDR },
        WHV_REGISTER_VALUE { Reg64: CR4_PAE },
        WHV_REGISTER_VALUE {
            Reg64: EFER_LME_LMA,
        },
        WHV_REGISTER_VALUE { Segment: code },
        WHV_REGISTER_VALUE { Segment: data },
        WHV_REGISTER_VALUE { Segment: data },
        WHV_REGISTER_VALUE { Segment: data },
        WHV_REGISTER_VALUE { Segment: data },
        WHV_REGISTER_VALUE { Segment: data },
        WHV_REGISTER_VALUE {
            Table: table(GDT_ADDR, 0x17),
        },
        WHV_REGISTER_VALUE { Table: table(0, 0) },
        WHV_REGISTER_VALUE {
            Reg64: kernel_entry,
        },
        WHV_REGISTER_VALUE {
            Reg64: boot_params_address,
        },
        WHV_REGISTER_VALUE { Reg64: STACK_TOP },
        WHV_REGISTER_VALUE { Reg64: 2 },
    ];
    partition.set_registers(0, &names, &values)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planned_segments_set_the_long_mode_descriptor_bits() {
        assert_eq!(CODE_SEGMENT_ATTRIBUTES & 0x0F00, 0);
        assert_eq!(CODE_SEGMENT_ATTRIBUTES & (1 << 13), 1 << 13);
        assert_eq!(CODE_SEGMENT_ATTRIBUTES & (1 << 14), 0);
        assert_eq!(CODE_SEGMENT_ATTRIBUTES & (1 << 15), 1 << 15);
        assert_eq!(DATA_SEGMENT_ATTRIBUTES & 0x0F00, 0);
        assert_eq!(DATA_SEGMENT_ATTRIBUTES & (1 << 13), 0);
        assert_eq!(DATA_SEGMENT_ATTRIBUTES & (1 << 14), 1 << 14);
        assert_eq!(DATA_SEGMENT_ATTRIBUTES & (1 << 15), 1 << 15);
    }
}
