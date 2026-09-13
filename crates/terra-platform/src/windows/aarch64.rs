//! `AArch64` WHP register names absent from the current `windows-rs` metadata.

use windows_sys::Win32::System::Hypervisor::WHV_REGISTER_NAME;

use super::whp::{Partition, PartitionError};

pub const WHV_ARM64_REGISTER_X0: WHV_REGISTER_NAME = 0x0002_0000;
pub const WHV_ARM64_REGISTER_X1: WHV_REGISTER_NAME = 0x0002_0001;
pub const WHV_ARM64_REGISTER_X2: WHV_REGISTER_NAME = 0x0002_0002;
pub const WHV_ARM64_REGISTER_X3: WHV_REGISTER_NAME = 0x0002_0003;
pub const WHV_ARM64_REGISTER_PC: WHV_REGISTER_NAME = 0x0002_0022;
pub const WHV_ARM64_REGISTER_PSTATE: WHV_REGISTER_NAME = 0x0002_0023;
pub const WHV_ARM64_REGISTER_GICR_BASE_GPA: WHV_REGISTER_NAME = 0x0006_3000;

fn setup_cpu(
    partition: &Partition,
    vcpu: u32,
    kernel_entry: u64,
    fdt_address: u64,
) -> Result<(), PartitionError> {
    let names = [
        WHV_ARM64_REGISTER_X0,
        WHV_ARM64_REGISTER_X1,
        WHV_ARM64_REGISTER_X2,
        WHV_ARM64_REGISTER_X3,
        WHV_ARM64_REGISTER_PSTATE,
        WHV_ARM64_REGISTER_PC,
    ];
    let values = [
        windows_sys::Win32::System::Hypervisor::WHV_REGISTER_VALUE { Reg64: fdt_address },
        windows_sys::Win32::System::Hypervisor::WHV_REGISTER_VALUE { Reg64: 0 },
        windows_sys::Win32::System::Hypervisor::WHV_REGISTER_VALUE { Reg64: 0 },
        windows_sys::Win32::System::Hypervisor::WHV_REGISTER_VALUE { Reg64: 0 },
        windows_sys::Win32::System::Hypervisor::WHV_REGISTER_VALUE {
            Reg64: terra_limits::ARM_PSTATE_EL1H_DAIF,
        },
        windows_sys::Win32::System::Hypervisor::WHV_REGISTER_VALUE {
            Reg64: kernel_entry,
        },
    ];
    partition.set_registers(vcpu, &names, &values)
}

/// Start the planned-boot BSP with the Linux arm64 entry contract.
pub fn setup_bsp(
    partition: &Partition,
    kernel_entry: u64,
    fdt_address: u64,
) -> Result<(), PartitionError> {
    setup_cpu(partition, 0, kernel_entry, fdt_address)
}

/// Start an `AArch64` secondary with the PSCI CPU_ON entry contract.
pub fn setup_secondary(
    partition: &Partition,
    vcpu: u32,
    entry: u64,
    context: u64,
) -> Result<(), PartitionError> {
    setup_cpu(partition, vcpu, entry, context)
}
