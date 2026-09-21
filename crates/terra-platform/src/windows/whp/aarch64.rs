use super::{AvailabilityError, Partition, PartitionError, RunExit, WhpError, result};
use windows_sys::Win32::System::Hypervisor::{
    WHV_CAPABILITY, WHV_REGISTER_VALUE, WHvGetCapability, WHvRequestInterrupt,
    WHvRunVirtualProcessor, WHvSetPartitionProperty, WHvSetVirtualProcessorRegisters,
};
const ARM64_SUPPORT: u64 = 1 << 11;

#[repr(C)]
#[derive(Default)]
struct Arm64RunVpExitContext {
    exit_reason: i32,
    reserved: u32,
    reserved1: u64,
    payload: [u64; 32],
}

const _: () = assert!(size_of::<Arm64RunVpExitContext>() == 272);

#[repr(C)]
struct Arm64MemoryAccessContext {
    vp_index: u32,
    instruction_length: u8,
    access_type: u8,
    execution_state: u16,
    pc: u64,
    cpsr: u64,
    reserved0: u32,
    instruction_byte_count: u8,
    access_info: u8,
    reserved1: u16,
    instruction_bytes: [u8; 4],
    reserved2: u32,
    gva: u64,
    gpa: u64,
    syndrome: u64,
}

const _: () = assert!(size_of::<Arm64MemoryAccessContext>() == 64);

#[repr(C)]
struct Arm64ResetContext {
    vp_index: u32,
    instruction_length: u8,
    intercept_access_type: u8,
    execution_state: u16,
    pc: u64,
    cpsr: u64,
    reset_type: u32,
    reserved: u32,
}

const _: () = assert!(size_of::<Arm64ResetContext>() == 32);

const WHV_PARTITION_PROPERTY_CODE_ARM64_IC_PARAMETERS: i32 = 0x0000_1012;

const WHV_CAPABILITY_CODE_GIC_LPI_INT_ID_BITS: i32 = 0x0000_2011;

const ARM64_IC_EMULATION_MODE_GIC_V3: u32 = 1;

const ARM64_GIC_REDISTRIBUTOR_STRIDE: u64 = 0x20_000;

#[repr(C)]
struct Arm64IcGicV3Parameters {
    gicd_base_address: u64,
    gits_translater_base_address: u64,
    reserved: u32,
    gic_lpi_int_id_bits: u32,
    gic_ppi_overflow_interrupt_from_cntv: u32,
    gic_ppi_performance_monitors_interrupt: u32,
    reserved1: [u32; 6],
}

#[repr(C)]
struct Arm64IcParameters {
    emulation_mode: u32,
    reserved: u32,
    gic_v3: Arm64IcGicV3Parameters,
}

#[repr(C)]
struct Arm64InterruptControl {
    target_partition: u64,
    interrupt_control: u64,
    destination_address: u64,
    requested_vector: u32,
    target_vtl: u8,
    reserved_z0: u8,
    reserved_z1: u16,
}

const ARM64_INTERRUPT_ASSERTED: u64 = 1 << 34;

const _: () = {
    assert!(size_of::<Arm64InterruptControl>() == 32);
    assert!(std::mem::offset_of!(Arm64InterruptControl, interrupt_control) == 8);
    assert!(ARM64_INTERRUPT_ASSERTED == 0x0000_0004_0000_0000);
};

fn arm64_lpi_id_bits() -> Result<u32, WhpError> {
    let mut lpi_id_bits = 0;
    let mut written = 0;
    // SAFETY: lpi_id_bits is the documented u32 output for this capability.
    result(unsafe {
        WHvGetCapability(
            WHV_CAPABILITY_CODE_GIC_LPI_INT_ID_BITS,
            (&raw mut lpi_id_bits).cast(),
            size_of::<u32>() as u32,
            &raw mut written,
        )
    })?;
    if written == size_of::<u32>() as u32 {
        Ok(lpi_id_bits)
    } else {
        Err(WhpError(-1))
    }
}

impl Partition {
    pub fn run_vcpu(&self, index: u32) -> Result<RunExit, PartitionError> {
        self.require_vcpu(index)?;
        let mut context = Arm64RunVpExitContext::default();
        // SAFETY: Arm64RunVpExitContext has the documented 272-byte ARM64 ABI size.
        result(unsafe {
            WHvRunVirtualProcessor(
                self.handle,
                index,
                (&raw mut context).cast(),
                size_of::<Arm64RunVpExitContext>() as u32,
            )
        })
        .map_err(PartitionError::Api)?;
        Ok(RunExit::from_arm64(&context))
    }

    pub fn vcpu_count(&self) -> u32 {
        self.vcpu_count
    }

    pub fn request_arm64_spi(&self, irq: u32, asserted: bool) -> Result<(), PartitionError> {
        let intid = irq.checked_add(32).ok_or(PartitionError::InvalidVcpu)?;
        let interrupt = Arm64InterruptControl {
            target_partition: 0,
            interrupt_control: u64::from(asserted) * ARM64_INTERRUPT_ASSERTED,
            destination_address: 0,
            requested_vector: intid,
            target_vtl: 0,
            reserved_z0: 0,
            reserved_z1: 0,
        };
        // SAFETY: Arm64InterruptControl is the Arm64 WHV_INTERRUPT_CONTROL ABI.
        result(unsafe {
            WHvRequestInterrupt(
                self.handle,
                (&raw const interrupt).cast(),
                size_of::<Arm64InterruptControl>() as u32,
            )
        })
        .map_err(PartitionError::Api)
    }

    pub(super) fn configure_interrupt_controller(&self) -> Result<(), PartitionError> {
        let lpi_id_bits = arm64_lpi_id_bits().map_err(PartitionError::Api)?;
        let parameters = Arm64IcParameters {
            emulation_mode: ARM64_IC_EMULATION_MODE_GIC_V3,
            reserved: 0,
            gic_v3: Arm64IcGicV3Parameters {
                gicd_base_address: crate::aarch64::arm::GIC_DIST_BASE,
                gits_translater_base_address: 0,
                reserved: 0,
                gic_lpi_int_id_bits: lpi_id_bits,
                gic_ppi_overflow_interrupt_from_cntv: 27,
                gic_ppi_performance_monitors_interrupt: 23,
                reserved1: [0; 6],
            },
        };
        // SAFETY: parameters has the documented ARM64 IC property layout.
        result(unsafe {
            WHvSetPartitionProperty(
                self.handle,
                WHV_PARTITION_PROPERTY_CODE_ARM64_IC_PARAMETERS,
                (&raw const parameters).cast(),
                size_of::<Arm64IcParameters>() as u32,
            )
        })
        .map_err(PartitionError::Api)
    }

    pub(super) fn configure_arm64_vcpu(&self, index: u32) -> Result<(), PartitionError> {
        let gicr_base = crate::aarch64::arm::GIC_REDIST_BASE
            + u64::from(index) * ARM64_GIC_REDISTRIBUTOR_STRIDE;
        let names = [crate::windows::aarch64::WHV_ARM64_REGISTER_GICR_BASE_GPA];
        let values = [WHV_REGISTER_VALUE { Reg64: gicr_base }];
        // SAFETY: the just-created vCPU accepts the documented GICR base register.
        result(unsafe {
            WHvSetVirtualProcessorRegisters(
                self.handle,
                index,
                names.as_ptr(),
                names.len() as u32,
                values.as_ptr(),
            )
        })
        .map_err(PartitionError::Api)
    }
}

impl RunExit {
    fn from_reason(reason: i32) -> Self {
        const WHV_RUN_VP_EXIT_REASON_CANCELED: i32 = -1;
        match reason {
            WHV_RUN_VP_EXIT_REASON_CANCELED => Self::Canceled,
            reason => Self::Other(reason),
        }
    }

    fn from_arm64(context: &Arm64RunVpExitContext) -> Self {
        const UNMAPPED_GPA: i32 = 0x8000_0000u32 as i32;
        const GPA_INTERCEPT: i32 = 0x8000_0001u32 as i32;
        const RESET: i32 = 0x8001_000c_u32 as i32;
        match context.exit_reason {
            UNMAPPED_GPA | GPA_INTERCEPT => {
                // SAFETY: these exit reasons select WHV_MEMORY_ACCESS_CONTEXT.
                let access = unsafe {
                    (&raw const context.payload)
                        .cast::<Arm64MemoryAccessContext>()
                        .read()
                };
                Self::MemoryAccess {
                    gpa: access.gpa,
                    access_info: u32::from(access.access_type),
                    pc: access.pc,
                    cpsr: access.cpsr,
                    syndrome: access.syndrome,
                }
            }
            RESET => {
                // SAFETY: the exit reason selects WHV_ARM64_RESET_CONTEXT.
                let reset = unsafe {
                    (&raw const context.payload)
                        .cast::<Arm64ResetContext>()
                        .read()
                };
                Self::Reset {
                    reboot: reset.reset_type == 1,
                }
            }
            reason => Self::from_reason(reason),
        }
    }
}

pub(super) fn check_available() -> Result<(), AvailabilityError> {
    let mut written = 0;
    let mut features = WHV_CAPABILITY::default();
    // SAFETY: WHV_CAPABILITY is the output type required by WHvGetCapability.
    result(unsafe {
        WHvGetCapability(
            windows_sys::Win32::System::Hypervisor::WHvCapabilityCodeFeatures,
            (&raw mut features).cast(),
            size_of::<WHV_CAPABILITY>() as u32,
            &raw mut written,
        )
    })
    .map_err(AvailabilityError::Api)?;
    // SAFETY: WHvGetCapability initialized the Features union member.
    let supported = unsafe { features.Features.AsUINT64 } & ARM64_SUPPORT != 0;
    if !supported {
        return Err(AvailabilityError::Arm64Unsupported);
    }
    Ok(())
}
