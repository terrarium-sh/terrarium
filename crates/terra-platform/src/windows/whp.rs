//! Minimal ownership wrapper for Windows Hypervisor Platform partitions.

#![allow(unsafe_code)]
#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]

use std::error::Error;
#[cfg(target_arch = "x86_64")]
use std::ffi::c_void;
use std::fmt;
use std::mem::size_of;
use std::sync::{Arc, Mutex};
use windows_sys::Win32::System::Hypervisor::{
    WHV_CAPABILITY, WHV_PARTITION_HANDLE, WHV_REGISTER_NAME, WHV_REGISTER_VALUE,
    WHV_RUN_VP_EXIT_CONTEXT, WHvCancelRunVirtualProcessor,
    WHvCapabilityCodeHypervisorPresent as WHV_CAPABILITY_CODE_HYPERVISOR_PRESENT,
    WHvCreatePartition, WHvCreateVirtualProcessor, WHvDeletePartition, WHvDeleteVirtualProcessor,
    WHvGetCapability, WHvGetVirtualProcessorRegisters, WHvMapGpaRange,
    WHvMapGpaRangeFlagExecute as WHV_MAP_GPA_RANGE_FLAG_EXECUTE,
    WHvMapGpaRangeFlagRead as WHV_MAP_GPA_RANGE_FLAG_READ,
    WHvMapGpaRangeFlagWrite as WHV_MAP_GPA_RANGE_FLAG_WRITE,
    WHvPartitionPropertyCodeProcessorCount as WHV_PARTITION_PROPERTY_CODE_PROCESSOR_COUNT,
    WHvRequestInterrupt, WHvRunVirtualProcessor, WHvSetPartitionProperty,
    WHvSetVirtualProcessorRegisters, WHvSetupPartition, WHvUnmapGpaRange,
};
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Hypervisor::{
    WHV_EMULATOR_CALLBACKS, WHV_EMULATOR_IO_ACCESS_INFO, WHV_EMULATOR_MEMORY_ACCESS_INFO,
    WHV_EMULATOR_STATUS, WHV_INTERRUPT_CONTROL, WHV_TRANSLATE_GVA_FLAGS, WHV_TRANSLATE_GVA_RESULT,
    WHV_TRANSLATE_GVA_RESULT_CODE, WHV_X64_PENDING_INTERRUPTION_REGISTER,
    WHvEmulatorCreateEmulator, WHvEmulatorDestroyEmulator, WHvEmulatorTryIoEmulation,
    WHvEmulatorTryMmioEmulation, WHvRegisterPendingInterruption, WHvTranslateGva,
};
#[cfg(target_arch = "aarch64")]
const ARM64_SUPPORT: u64 = 1 << 11;

// windows-sys omits the WHP register union's required 16-byte alignment.
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct AlignedRegisterValue(WHV_REGISTER_VALUE);

const _: () = assert!(size_of::<AlignedRegisterValue>() == size_of::<WHV_REGISTER_VALUE>());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WhpError(i32);

impl fmt::Display for WhpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Windows Hypervisor Platform failed with HRESULT {:#010x}",
            self.0
        )
    }
}

impl Error for WhpError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvailabilityError {
    Api(WhpError),
    HypervisorDisabled,
    Arm64Unsupported,
}

impl fmt::Display for AvailabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api(error) => error.fmt(formatter),
            Self::HypervisorDisabled => formatter.write_str(
                "Windows Hypervisor Platform is unavailable; enable the Windows Hypervisor Platform feature",
            ),
            Self::Arm64Unsupported => formatter.write_str(
                "this Windows Arm64 host needs Windows 11 24H2 or later with Windows Hypervisor Platform enabled",
            ),
        }
    }
}

impl Error for AvailabilityError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionError {
    Availability(AvailabilityError),
    InvalidMemorySize,
    InvalidVcpu,
    Transport,
    Api(WhpError),
}

impl fmt::Display for PartitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Availability(error) => error.fmt(formatter),
            Self::InvalidMemorySize => {
                formatter.write_str("guest memory must be a nonzero multiple of 4096 bytes")
            }
            Self::InvalidVcpu => {
                formatter.write_str("virtual processor index is outside the configured partition")
            }
            Self::Transport => formatter.write_str("VMM transport failed"),
            Self::Api(error) => error.fmt(formatter),
        }
    }
}

impl Error for PartitionError {}

fn result(status: i32) -> Result<(), WhpError> {
    (status >= 0).then_some(()).ok_or(WhpError(status))
}

#[cfg(target_arch = "x86_64")]
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

/// Check that the installed host can create WHP partitions on this architecture.
pub fn check_available() -> Result<(), AvailabilityError> {
    let mut present = WHV_CAPABILITY::default();
    let mut written = 0;
    // SAFETY: WHV_CAPABILITY is the output type required by WHvGetCapability.
    result(unsafe {
        WHvGetCapability(
            WHV_CAPABILITY_CODE_HYPERVISOR_PRESENT,
            (&raw mut present).cast(),
            size_of::<WHV_CAPABILITY>() as u32,
            &raw mut written,
        )
    })
    .map_err(AvailabilityError::Api)?;
    // SAFETY: WHvGetCapability initialized the HypervisorPresent union member.
    if unsafe { present.HypervisorPresent } == 0 {
        return Err(AvailabilityError::HypervisorDisabled);
    }

    #[cfg(target_arch = "aarch64")]
    {
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
    }
    Ok(())
}

/// A configured WHP partition with one contiguous guest-physical RAM range.
pub struct Partition {
    handle: WHV_PARTITION_HANDLE,
    memory: Arc<terra_runtime::memory::WindowsRam>,
    vcpu_count: u32,
    mapped: bool,
    mapped_gpa: u64,
    vcpus: Mutex<Vec<u32>>,
}

impl terra_runtime::component::vmm::virtualization::VirtualMachine for Partition {
    fn memory(&self) -> wasmtime::Result<terra_runtime::memory::GuestRam> {
        terra_runtime::memory::GuestRam::from_windows_ram(Arc::clone(&self.memory))
            .ok_or_else(|| wasmtime::Error::msg("aliasing WHP guest RAM"))
    }
}

impl Partition {
    pub fn new(
        memory: Arc<terra_runtime::memory::WindowsRam>,
        vcpu_count: u32,
    ) -> Result<Self, PartitionError> {
        check_available().map_err(PartitionError::Availability)?;
        if memory.size() == 0 || !memory.size().is_multiple_of(4096) {
            return Err(PartitionError::InvalidMemorySize);
        }
        if vcpu_count == 0 {
            return Err(PartitionError::InvalidVcpu);
        }
        let mut handle = 0;
        // SAFETY: handle points to storage for the output partition handle.
        result(unsafe { WHvCreatePartition(&raw mut handle) }).map_err(PartitionError::Api)?;
        let mapped_gpa = memory.guest_base();
        let mut partition = Self {
            handle,
            memory,
            vcpu_count,
            mapped: false,
            mapped_gpa,
            vcpus: Mutex::new(Vec::new()),
        };
        result(
            // SAFETY: the pre-setup partition accepts ProcessorCount as a u32 property.
            unsafe {
                WHvSetPartitionProperty(
                    partition.handle,
                    WHV_PARTITION_PROPERTY_CODE_PROCESSOR_COUNT,
                    (&raw const partition.vcpu_count).cast(),
                    size_of::<u32>() as u32,
                )
            },
        )
        .map_err(PartitionError::Api)?;
        #[cfg(target_arch = "x86_64")]
        partition.configure_x64_local_apic()?;
        #[cfg(target_arch = "aarch64")]
        partition.configure_arm64_gic()?;
        // SAFETY: the configured partition handle is valid until Partition drops it.
        result(unsafe { WHvSetupPartition(partition.handle) }).map_err(PartitionError::Api)?;
        // SAFETY: WindowsRam owns the page-aligned source range until the partition unmaps it.
        result(unsafe {
            WHvMapGpaRange(
                partition.handle,
                partition.memory.address().cast(),
                partition.mapped_gpa,
                partition.memory.size() as u64,
                WHV_MAP_GPA_RANGE_FLAG_READ
                    | WHV_MAP_GPA_RANGE_FLAG_WRITE
                    | WHV_MAP_GPA_RANGE_FLAG_EXECUTE,
            )
        })
        .map_err(PartitionError::Api)?;
        partition.mapped = true;
        Ok(partition)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn vcpu_count(&self) -> u32 {
        self.vcpu_count
    }

    #[cfg(target_arch = "x86_64")]
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

    #[cfg(target_arch = "x86_64")]
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

    pub fn create_vcpu(&self, index: u32) -> Result<(), PartitionError> {
        let mut vcpus = self
            .vcpus
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if index >= self.vcpu_count || vcpus.contains(&index) {
            return Err(PartitionError::InvalidVcpu);
        }
        // SAFETY: index was validated against the configured processor count.
        result(unsafe { WHvCreateVirtualProcessor(self.handle, index, 0) })
            .map_err(PartitionError::Api)?;
        #[cfg(target_arch = "aarch64")]
        if let Err(error) = self.configure_arm64_vcpu(index) {
            // SAFETY: this vCPU was just created in this partition.
            unsafe { WHvDeleteVirtualProcessor(self.handle, index) };
            return Err(error);
        }
        vcpus.push(index);
        Ok(())
    }

    pub fn run_vcpu(&self, index: u32) -> Result<RunExit, PartitionError> {
        #[cfg(target_arch = "aarch64")]
        {
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
        #[cfg(target_arch = "x86_64")]
        Ok(RunExit::from(self.run_vcpu_context(index)?))
    }

    #[cfg(target_arch = "x86_64")]
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

    pub fn cancel_vcpu(&self, index: u32) -> Result<(), PartitionError> {
        self.require_vcpu(index)?;
        // SAFETY: index identifies a vCPU owned by this partition.
        result(unsafe { WHvCancelRunVirtualProcessor(self.handle, index, 0) })
            .map_err(PartitionError::Api)
    }

    pub fn registers(
        &self,
        index: u32,
        names: &[WHV_REGISTER_NAME],
    ) -> Result<Vec<WHV_REGISTER_VALUE>, PartitionError> {
        self.require_vcpu(index)?;
        let mut values = vec![AlignedRegisterValue::default(); names.len()];
        // SAFETY: names and values have equal, valid lengths for this synchronous call.
        result(unsafe {
            WHvGetVirtualProcessorRegisters(
                self.handle,
                index,
                names.as_ptr(),
                names.len() as u32,
                values.as_mut_ptr().cast(),
            )
        })
        .map_err(PartitionError::Api)?;
        Ok(values.into_iter().map(|value| value.0).collect())
    }

    pub fn register_u64(&self, index: u32, name: WHV_REGISTER_NAME) -> Result<u64, PartitionError> {
        let value = self.registers(index, &[name])?[0];
        // SAFETY: callers select a WHP register whose value is represented as Reg64.
        Ok(unsafe { value.Reg64 })
    }

    pub fn set_registers(
        &self,
        index: u32,
        names: &[WHV_REGISTER_NAME],
        values: &[WHV_REGISTER_VALUE],
    ) -> Result<(), PartitionError> {
        self.require_vcpu(index)?;
        if names.len() != values.len() {
            return Err(PartitionError::InvalidVcpu);
        }
        let values: Vec<_> = values.iter().copied().map(AlignedRegisterValue).collect();
        // SAFETY: names and values have equal, valid lengths for this synchronous call.
        result(unsafe {
            WHvSetVirtualProcessorRegisters(
                self.handle,
                index,
                names.as_ptr(),
                names.len() as u32,
                values.as_ptr().cast(),
            )
        })
        .map_err(PartitionError::Api)
    }

    #[cfg(target_arch = "x86_64")]
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

    #[cfg(target_arch = "x86_64")]
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

    #[cfg(target_arch = "x86_64")]
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

    #[cfg(target_arch = "aarch64")]
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

    fn require_vcpu(&self, index: u32) -> Result<(), PartitionError> {
        self.vcpus
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&index)
            .then_some(())
            .ok_or(PartitionError::InvalidVcpu)
    }

    #[cfg(target_arch = "aarch64")]
    fn configure_arm64_gic(&self) -> Result<(), PartitionError> {
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

    #[cfg(target_arch = "aarch64")]
    fn configure_arm64_vcpu(&self, index: u32) -> Result<(), PartitionError> {
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

    #[cfg(target_arch = "x86_64")]
    fn configure_x64_local_apic(&self) -> Result<(), PartitionError> {
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

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Default)]
struct Arm64RunVpExitContext {
    exit_reason: i32,
    reserved: u32,
    reserved1: u64,
    payload: [u64; 32],
}

#[cfg(target_arch = "aarch64")]
const _: () = assert!(size_of::<Arm64RunVpExitContext>() == 272);

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "aarch64")]
const _: () = assert!(size_of::<Arm64MemoryAccessContext>() == 64);

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "aarch64")]
const _: () = assert!(size_of::<Arm64ResetContext>() == 32);

impl Drop for Partition {
    fn drop(&mut self) {
        for index in self
            .vcpus
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            // SAFETY: each index was created in this partition and is deleted once.
            unsafe { WHvDeleteVirtualProcessor(self.handle, index) };
        }
        if self.mapped {
            // SAFETY: this is the exact GPA mapping created by Partition::new.
            unsafe { WHvUnmapGpaRange(self.handle, self.mapped_gpa, self.memory.size() as u64) };
        }
        // SAFETY: handle was returned by WHvCreatePartition and is deleted once here.
        unsafe { WHvDeletePartition(self.handle) };
    }
}

#[cfg(target_arch = "aarch64")]
const WHV_PARTITION_PROPERTY_CODE_ARM64_IC_PARAMETERS: i32 = 0x0000_1012;
#[cfg(target_arch = "aarch64")]
const WHV_CAPABILITY_CODE_GIC_LPI_INT_ID_BITS: i32 = 0x0000_2011;
#[cfg(target_arch = "aarch64")]
const ARM64_IC_EMULATION_MODE_GIC_V3: u32 = 1;
#[cfg(target_arch = "aarch64")]
const ARM64_GIC_REDISTRIBUTOR_STRIDE: u64 = 0x20_000;

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "aarch64")]
#[repr(C)]
struct Arm64IcParameters {
    emulation_mode: u32,
    reserved: u32,
    gic_v3: Arm64IcGicV3Parameters,
}

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "aarch64")]
const ARM64_INTERRUPT_ASSERTED: u64 = 1 << 34;

#[cfg(target_arch = "aarch64")]
const _: () = {
    assert!(size_of::<Arm64InterruptControl>() == 32);
    assert!(std::mem::offset_of!(Arm64InterruptControl, interrupt_control) == 8);
    assert!(ARM64_INTERRUPT_ASSERTED == 0x0000_0004_0000_0000);
};

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "x86_64")]
const E_FAIL: i32 = 0x8000_4005u32 as i32;

#[cfg(target_arch = "x86_64")]
fn encode_pending_invalid_opcode() -> u64 {
    1 | (3 << 1) | (6 << 16)
}

#[cfg(target_arch = "x86_64")]
pub struct Emulator {
    handle: *mut c_void,
}

#[cfg(target_arch = "x86_64")]
impl Emulator {
    pub fn new() -> Result<Self, WhpError> {
        let callbacks = WHV_EMULATOR_CALLBACKS {
            Size: size_of::<WHV_EMULATOR_CALLBACKS>() as u32,
            Reserved: 0,
            WHvEmulatorIoPortCallback: Some(emulate_io_port),
            WHvEmulatorMemoryCallback: Some(emulate_memory),
            WHvEmulatorGetVirtualProcessorRegisters: Some(emulate_get_registers),
            WHvEmulatorSetVirtualProcessorRegisters: Some(emulate_set_registers),
            WHvEmulatorTranslateGvaPage: Some(emulate_translate_gva_page),
        };
        let mut handle = std::ptr::null_mut();
        // SAFETY: callbacks lives for the creation call and all entries are valid functions.
        result(unsafe { WHvEmulatorCreateEmulator(&raw const callbacks, &raw mut handle) })?;
        Ok(Self { handle })
    }

    pub fn emulate_mmio(
        &self,
        context: &mut EmulationContext<'_>,
        exit: &WHV_RUN_VP_EXIT_CONTEXT,
    ) -> Result<(), PartitionError> {
        // SAFETY: MemoryAccess is active for the caller's memory-access exit.
        let memory_access = unsafe { exit.Anonymous.MemoryAccess };
        let mut status = WHV_EMULATOR_STATUS::default();
        // SAFETY: context remains valid throughout this synchronous call and its callbacks.
        result(unsafe {
            WHvEmulatorTryMmioEmulation(
                self.handle,
                std::ptr::from_mut(context).cast(),
                &raw const exit.VpContext,
                &raw const memory_access,
                &raw mut status,
            )
        })
        .map_err(PartitionError::Api)?;
        // SAFETY: WHvEmulatorTryMmioEmulation initialized the status union.
        complete_emulation(context, unsafe { status.AsUINT32 })
    }

    pub fn emulate_io(
        &self,
        context: &mut EmulationContext<'_>,
        exit: &WHV_RUN_VP_EXIT_CONTEXT,
    ) -> Result<(), PartitionError> {
        // SAFETY: IoPortAccess is active for the caller's I/O-port exit.
        let io_access = unsafe { exit.Anonymous.IoPortAccess };
        let mut status = WHV_EMULATOR_STATUS::default();
        // SAFETY: context remains valid throughout this synchronous call and its callbacks.
        result(unsafe {
            WHvEmulatorTryIoEmulation(
                self.handle,
                std::ptr::from_mut(context).cast(),
                &raw const exit.VpContext,
                &raw const io_access,
                &raw mut status,
            )
        })
        .map_err(PartitionError::Api)?;
        // SAFETY: WHvEmulatorTryIoEmulation initialized the status union.
        complete_emulation(context, unsafe { status.AsUINT32 })
    }
}

#[cfg(target_arch = "x86_64")]
fn complete_emulation(
    context: &mut EmulationContext<'_>,
    status: u32,
) -> Result<(), PartitionError> {
    const SUCCESS: u32 = 1;
    const INTERNAL_FAILURE: u32 = 1 << 1;
    const INTERRUPT_CAUSED_INTERCEPT: u32 = 1 << 8;
    const GUEST_CANNOT_BE_FAULTED: u32 = 1 << 9;
    if status & SUCCESS != 0 {
        return context.error.take().map_or(Ok(()), Err);
    }
    if let Some(error) = context.error.take() {
        return Err(error);
    }
    if status & GUEST_CANNOT_BE_FAULTED != 0 {
        return Err(PartitionError::Api(WhpError(E_FAIL)));
    }
    if status & INTERNAL_FAILURE != 0 {
        context.partition.inject_invalid_opcode(context.vcpu)?;
        return Ok(());
    }
    if status & INTERRUPT_CAUSED_INTERCEPT != 0 {
        return Ok(());
    }
    Err(PartitionError::Api(WhpError(E_FAIL)))
}

#[cfg(target_arch = "x86_64")]
impl Drop for Emulator {
    fn drop(&mut self) {
        // SAFETY: handle was returned by WHvEmulatorCreateEmulator and is dropped once.
        unsafe { WHvEmulatorDestroyEmulator(self.handle) };
    }
}

#[cfg(target_arch = "x86_64")]
pub struct EmulationContext<'a> {
    partition: &'a Partition,
    vcpu: u32,
    memory: &'a mut MmioCallback<'a>,
    io: &'a mut PioCallback<'a>,
    error: Option<PartitionError>,
}

#[cfg(target_arch = "x86_64")]
impl<'a> EmulationContext<'a> {
    pub fn new(
        partition: &'a Partition,
        vcpu: u32,
        memory: &'a mut MmioCallback<'a>,
        io: &'a mut PioCallback<'a>,
    ) -> Self {
        Self {
            partition,
            vcpu,
            memory,
            io,
            error: None,
        }
    }
}

#[cfg(target_arch = "x86_64")]
type MmioCallback<'a> = dyn FnMut(u64, bool, &mut [u8]) -> Result<(), PartitionError> + 'a;
#[cfg(target_arch = "x86_64")]
type PioCallback<'a> = dyn FnMut(u16, bool, u8, &mut u32) -> Result<(), PartitionError> + 'a;

#[cfg(target_arch = "x86_64")]
unsafe extern "system" fn emulate_memory(
    context: *const c_void,
    access: *mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
) -> i32 {
    // SAFETY: WHP supplies the EmulationContext passed to emulate_mmio.
    let context = unsafe { &mut *context.cast_mut().cast::<EmulationContext<'_>>() };
    // SAFETY: WHP supplies one initialized memory-access descriptor.
    let access = unsafe { &mut *access };
    let length = usize::from(access.AccessSize);
    if length > access.Data.len() {
        context.error = Some(PartitionError::Api(WhpError(E_FAIL)));
        return E_FAIL;
    }
    let bytes = &mut access.Data[..length];
    match (context.memory)(access.GpaAddress, access.Direction != 0, bytes) {
        Ok(()) => 0,
        Err(error) => {
            context.error = Some(error);
            E_FAIL
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe extern "system" fn emulate_io_port(
    context: *const c_void,
    access: *mut WHV_EMULATOR_IO_ACCESS_INFO,
) -> i32 {
    // SAFETY: WHP supplies the EmulationContext passed to emulate_io.
    let context = unsafe { &mut *context.cast_mut().cast::<EmulationContext<'_>>() };
    // SAFETY: WHP supplies one initialized I/O-port descriptor.
    let access = unsafe { &mut *access };
    let width = match access.AccessSize {
        1 => 1,
        2 => 2,
        4 => 4,
        _ => {
            context.error = Some(PartitionError::Api(WhpError(E_FAIL)));
            return E_FAIL;
        }
    };
    match (context.io)(access.Port, access.Direction != 0, width, &mut access.Data) {
        Ok(()) => 0,
        Err(error) => {
            context.error = Some(error);
            E_FAIL
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe extern "system" fn emulate_get_registers(
    context: *const c_void,
    names: *const WHV_REGISTER_NAME,
    count: u32,
    values: *mut WHV_REGISTER_VALUE,
) -> i32 {
    // SAFETY: WHP supplies the EmulationContext passed to emulate_mmio.
    let context = unsafe { &mut *context.cast_mut().cast::<EmulationContext<'_>>() };
    // SAFETY: WHP supplies count valid register names and output slots.
    let names = unsafe { std::slice::from_raw_parts(names, count as usize) };
    match context.partition.registers(context.vcpu, names) {
        Ok(registers) => {
            // SAFETY: WHP allocated count output slots; registers has the same length.
            unsafe { values.copy_from_nonoverlapping(registers.as_ptr(), registers.len()) };
            0
        }
        Err(error) => {
            context.error = Some(error);
            E_FAIL
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe extern "system" fn emulate_set_registers(
    context: *const c_void,
    names: *const WHV_REGISTER_NAME,
    count: u32,
    values: *const WHV_REGISTER_VALUE,
) -> i32 {
    // SAFETY: WHP supplies the EmulationContext passed to emulate_mmio.
    let context = unsafe { &mut *context.cast_mut().cast::<EmulationContext<'_>>() };
    // SAFETY: WHP supplies count valid register names and values.
    let names = unsafe { std::slice::from_raw_parts(names, count as usize) };
    // SAFETY: WHP supplies count valid register names and values.
    let values = unsafe { std::slice::from_raw_parts(values, count as usize) };
    match context.partition.set_registers(context.vcpu, names, values) {
        Ok(()) => 0,
        Err(error) => {
            context.error = Some(error);
            E_FAIL
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe extern "system" fn emulate_translate_gva_page(
    context: *const c_void,
    gva: u64,
    flags: WHV_TRANSLATE_GVA_FLAGS,
    result_code: *mut WHV_TRANSLATE_GVA_RESULT_CODE,
    gpa: *mut u64,
) -> i32 {
    // SAFETY: WHP supplies the EmulationContext passed to emulate_mmio.
    let context = unsafe { &mut *context.cast_mut().cast::<EmulationContext<'_>>() };
    let mut translation = WHV_TRANSLATE_GVA_RESULT::default();
    // SAFETY: result_code and gpa are WHP-provided output pointers for this callback.
    match result(unsafe {
        WHvTranslateGva(
            context.partition.handle,
            context.vcpu,
            gva,
            flags,
            &raw mut translation,
            gpa,
        )
    }) {
        Ok(()) => {
            // SAFETY: result_code is a valid WHP output pointer.
            unsafe { result_code.write(translation.ResultCode) };
            0
        }
        Err(error) => {
            context.error = Some(PartitionError::Api(error));
            E_FAIL
        }
    }
}

/// A WHP vCPU exit. Memory exits retain the raw access flags for device dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunExit {
    MemoryAccess {
        gpa: u64,
        access_info: u32,
        pc: u64,
        cpsr: u64,
        syndrome: u64,
    },
    IoPortAccess,
    ApicEoi(u8),
    Reset {
        reboot: bool,
    },
    Halt,
    Canceled,
    Other(i32),
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

impl RunExit {
    #[cfg(target_arch = "aarch64")]
    fn from_reason(reason: i32) -> Self {
        const WHV_RUN_VP_EXIT_REASON_CANCELED: i32 = -1;
        match reason {
            WHV_RUN_VP_EXIT_REASON_CANCELED => Self::Canceled,
            reason => Self::Other(reason),
        }
    }

    #[cfg(target_arch = "aarch64")]
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

#[cfg(all(test, target_arch = "x86_64"))]
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
