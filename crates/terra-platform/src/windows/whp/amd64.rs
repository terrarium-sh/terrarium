pub mod emulator;

use super::{Partition, PartitionError, RunExit, WhpError, result};
use std::sync::Arc;
use windows_sys::Win32::System::Hypervisor::{
    WHV_INTERRUPT_CONTROL, WHV_REGISTER_VALUE, WHV_RUN_VP_EXIT_CONTEXT,
    WHV_X64_PENDING_INTERRUPTION_REGISTER, WHvGetCapability, WHvRegisterPendingInterruption,
    WHvRequestInterrupt, WHvRunVirtualProcessor, WHvSetPartitionProperty,
};

pub fn query_tsc_frequency() -> Result<u64, WhpError> {
    let mut frequency = 0_u64;
    // SAFETY: ProcessorClockFrequency writes one u64 frequency in Hz.
    result(unsafe {
        WHvGetCapability(
            windows_sys::Win32::System::Hypervisor::WHvCapabilityCodeProcessorClockFrequency,
            (&raw mut frequency).cast(),
            size_of::<u64>() as u32,
            std::ptr::null_mut(),
        )
    })?;
    Ok(frequency)
}

impl From<WHV_RUN_VP_EXIT_CONTEXT> for RunExit {
    fn from(context: WHV_RUN_VP_EXIT_CONTEXT) -> Self {
        const WHV_RUN_VP_EXIT_REASON_MEMORY_ACCESS: i32 = 1;
        const WHV_RUN_VP_EXIT_REASON_X64_IO_PORT_ACCESS: i32 = 2;
        const WHV_RUN_VP_EXIT_REASON_X64_APIC_EOI: i32 = 9;
        const WHV_RUN_VP_EXIT_REASON_X64_HALT: i32 = 8;
        const WHV_RUN_VP_EXIT_REASON_CANCELED: i32 = 8193;
        match context.ExitReason {
            WHV_RUN_VP_EXIT_REASON_MEMORY_ACCESS => {
                // SAFETY: the exit reason selects the MemoryAccess union member.
                let access = unsafe { context.Anonymous.MemoryAccess };
                // SAFETY: the MemoryAccess context initializes AccessInfo.
                let access_info = unsafe { access.AccessInfo.AsUINT32 };
                Self::MemoryAccess {
                    gpa: access.Gpa,
                    access_info,
                    pc: 0,
                    cpsr: 0,
                    syndrome: 0,
                }
            }
            WHV_RUN_VP_EXIT_REASON_X64_IO_PORT_ACCESS => Self::IoPortAccess,
            WHV_RUN_VP_EXIT_REASON_X64_APIC_EOI => {
                // SAFETY: the exit reason selects the ApicEoi union member.
                let eoi = unsafe { context.Anonymous.ApicEoi };
                Self::ApicEoi(eoi.InterruptVector.to_le_bytes()[0])
            }
            WHV_RUN_VP_EXIT_REASON_X64_HALT => Self::Halt,
            WHV_RUN_VP_EXIT_REASON_CANCELED => Self::Canceled,
            reason => Self::Other(reason),
        }
    }
}

fn encode_pending_invalid_opcode() -> u64 {
    1 | (3 << 1) | (6 << 16)
}

impl Partition {
    pub fn run_vcpu(&self, index: u32) -> Result<RunExit, PartitionError> {
        Ok(RunExit::from(self.run_vcpu_context(index)?))
    }

    pub fn contains_guest_memory(&self, address: u64, len: usize) -> bool {
        let Some(len) = u64::try_from(len).ok() else {
            return false;
        };
        let Some(memory_end) = u64::try_from(self.memory.size())
            .ok()
            .and_then(|size| self.mapped_gpa.checked_add(size))
        else {
            return false;
        };
        address >= self.mapped_gpa
            && address
                .checked_add(len)
                .is_some_and(|end| end <= memory_end)
    }

    pub fn access_guest_memory(
        &self,
        address: u64,
        write: bool,
        data: &mut [u8],
    ) -> Result<(), PartitionError> {
        let ram = terra_runtime::memory::GuestRam::from_windows_ram(Arc::clone(&self.memory))
            .ok_or(PartitionError::InvalidMemorySize)?;
        let memory = terra_runtime::memory::BoundedMemory::new(&ram);
        if write {
            memory
                .write(address, data)
                .map_err(|_| PartitionError::InvalidVcpu)
        } else {
            let bytes = memory
                .read(
                    address,
                    u64::try_from(data.len()).map_err(|_| PartitionError::InvalidVcpu)?,
                )
                .map_err(|_| PartitionError::InvalidVcpu)?;
            data.copy_from_slice(&bytes);
            Ok(())
        }
    }

    pub(crate) fn run_vcpu_context(
        &self,
        index: u32,
    ) -> Result<WHV_RUN_VP_EXIT_CONTEXT, PartitionError> {
        self.require_vcpu(index)?;
        let mut context = WHV_RUN_VP_EXIT_CONTEXT::default();
        // SAFETY: context has the exact size and remains valid for the synchronous call.
        result(unsafe {
            WHvRunVirtualProcessor(
                self.handle,
                index,
                (&raw mut context).cast(),
                size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
            )
        })
        .map_err(PartitionError::Api)?;
        Ok(context)
    }

    fn inject_invalid_opcode(&self, index: u32) -> Result<(), PartitionError> {
        self.set_registers(
            index,
            &[WHvRegisterPendingInterruption],
            &[WHV_REGISTER_VALUE {
                PendingInterruption: WHV_X64_PENDING_INTERRUPTION_REGISTER {
                    AsUINT64: encode_pending_invalid_opcode(),
                },
            }],
        )
    }

    fn request_interrupt(&self, interrupt: &WHV_INTERRUPT_CONTROL) -> Result<(), PartitionError> {
        // SAFETY: interrupt points to the documented WHP interrupt-control layout.
        result(unsafe {
            WHvRequestInterrupt(
                self.handle,
                interrupt,
                size_of::<WHV_INTERRUPT_CONTROL>() as u32,
            )
        })
        .map_err(PartitionError::Api)
    }

    pub fn request_x64_interrupt(
        &self,
        vector: u8,
        destination: u8,
        level: bool,
    ) -> Result<(), PartitionError> {
        let interrupt = WHV_INTERRUPT_CONTROL {
            _bitfield: (u64::from(level)) << 12,
            Destination: u32::from(destination),
            Vector: u32::from(vector),
        };
        self.request_interrupt(&interrupt)
    }

    pub(super) fn configure_interrupt_controller(&self) -> Result<(), PartitionError> {
        let mode = windows_sys::Win32::System::Hypervisor::WHvX64LocalApicEmulationModeXApic;
        // SAFETY: the pre-setup partition accepts the xAPIC emulation mode.
        result(unsafe {
            WHvSetPartitionProperty(
                self.handle,
                windows_sys::Win32::System::Hypervisor::WHvPartitionPropertyCodeLocalApicEmulationMode,
                (&raw const mode).cast(),
                size_of::<i32>() as u32,
            )
        })
        .map_err(PartitionError::Api)
    }
}

#[cfg(test)]
mod tests {
    use super::{Partition, WHV_REGISTER_VALUE};

    #[test]
    #[ignore = "requires Windows Hypervisor Platform"]
    fn register_access_accepts_unaligned_binding_values() {
        use windows_sys::Win32::System::Hypervisor::{WHvX64RegisterRax, WHvX64RegisterRbx};

        #[repr(C, align(16))]
        struct RegisterInput {
            padding: u64,
            values: [WHV_REGISTER_VALUE; 2],
        }

        let input = RegisterInput {
            padding: 0,
            values: [
                WHV_REGISTER_VALUE { Reg64: 0x1234 },
                WHV_REGISTER_VALUE { Reg64: 0x5678 },
            ],
        };
        assert_eq!(input.values.as_ptr().addr() % 16, 8);
        let ram = terra_runtime::memory::WindowsRam::allocate(2 << 20).unwrap();
        let partition = Partition::new(ram, 1).unwrap();
        partition.create_vcpu(0).unwrap();
        let names = [WHvX64RegisterRax, WHvX64RegisterRbx];
        partition.set_registers(0, &names, &input.values).unwrap();
        assert_eq!(partition.register_u64(0, names[0]).unwrap(), 0x1234);
        assert_eq!(partition.register_u64(0, names[1]).unwrap(), 0x5678);
    }

    #[test]
    fn invalid_opcode_is_a_pending_exception() {
        assert_eq!(
            super::encode_pending_invalid_opcode(),
            1 | (3 << 1) | (6 << 16)
        );
    }
}
