//! WHP `x86_64` boot vCPU registers.

use crate::whp::{Machine, MachineError};
use crate::x86::{self, Segment};
use windows_sys::Win32::System::Hypervisor::{
    WHV_REGISTER_VALUE, WHV_X64_SEGMENT_REGISTER, WHV_X64_SEGMENT_REGISTER_0,
    WHV_X64_TABLE_REGISTER, WHvX64RegisterCr0, WHvX64RegisterCr3, WHvX64RegisterCr4,
    WHvX64RegisterCs, WHvX64RegisterDs, WHvX64RegisterEfer, WHvX64RegisterEs, WHvX64RegisterFs,
    WHvX64RegisterGdtr, WHvX64RegisterGs, WHvX64RegisterIdtr, WHvX64RegisterRflags,
    WHvX64RegisterRip, WHvX64RegisterRsi, WHvX64RegisterRsp, WHvX64RegisterSs,
};

fn segment(segment: Segment) -> WHV_REGISTER_VALUE {
    WHV_REGISTER_VALUE {
        Segment: WHV_X64_SEGMENT_REGISTER {
            Base: Segment::BASE,
            Limit: Segment::LIMIT,
            Selector: segment.selector,
            Anonymous: WHV_X64_SEGMENT_REGISTER_0 {
                Attributes: segment.attributes(),
            },
        },
    }
}

fn table(base: u64, limit: u16) -> WHV_REGISTER_VALUE {
    WHV_REGISTER_VALUE {
        Table: WHV_X64_TABLE_REGISTER {
            Pad: [0; 3],
            Limit: limit,
            Base: base,
        },
    }
}

/// Initialize the WHP BSP from Wasm-planned boot tables already in guest RAM.
pub(super) fn configure_planned_boot(
    machine: &Machine,
    kernel_entry: u64,
    boot_params_address: u64,
) -> Result<(), MachineError> {
    let data = segment(x86::DATA_SEGMENT);
    let registers = [
        (
            WHvX64RegisterCr0,
            WHV_REGISTER_VALUE {
                Reg64: x86::CR0_PROTECTED_PAGING,
            },
        ),
        (
            WHvX64RegisterCr3,
            WHV_REGISTER_VALUE {
                Reg64: x86::CR3_PML4,
            },
        ),
        (
            WHvX64RegisterCr4,
            WHV_REGISTER_VALUE {
                Reg64: x86::CR4_PAE,
            },
        ),
        (
            WHvX64RegisterEfer,
            WHV_REGISTER_VALUE {
                Reg64: x86::EFER_LME_LMA,
            },
        ),
        (WHvX64RegisterCs, segment(x86::CODE_SEGMENT)),
        (WHvX64RegisterDs, data),
        (WHvX64RegisterEs, data),
        (WHvX64RegisterFs, data),
        (WHvX64RegisterGs, data),
        (WHvX64RegisterSs, data),
        (WHvX64RegisterGdtr, table(x86::GDT_BASE, x86::GDT_LIMIT)),
        (WHvX64RegisterIdtr, table(0, 0)),
        (
            WHvX64RegisterRip,
            WHV_REGISTER_VALUE {
                Reg64: kernel_entry,
            },
        ),
        (
            WHvX64RegisterRsi,
            WHV_REGISTER_VALUE {
                Reg64: boot_params_address,
            },
        ),
        (WHvX64RegisterRsp, WHV_REGISTER_VALUE { Reg64: x86::RSP }),
        (
            WHvX64RegisterRflags,
            WHV_REGISTER_VALUE { Reg64: x86::RFLAGS },
        ),
    ];
    let (names, values): (Vec<_>, Vec<_>) = registers.into_iter().unzip();
    machine.set_registers(0, &names, &values)
}
