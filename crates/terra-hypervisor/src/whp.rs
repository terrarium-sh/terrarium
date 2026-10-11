//! Windows Hypervisor Platform backend: one partition per VM.

#![allow(unsafe_code)]
#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::Vm;
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::Vm;

use crate::memory::GuestMemory;
use crate::vcpus::Kick;
use crate::vm::GicConfig;
use std::error::Error;
use std::fmt;
use std::mem::size_of;
use std::sync::Mutex;
use windows_sys::Win32::System::Hypervisor::{
    WHV_CAPABILITY, WHV_PARTITION_HANDLE, WHV_REGISTER_NAME, WHV_REGISTER_VALUE,
    WHvCancelRunVirtualProcessor,
    WHvCapabilityCodeHypervisorPresent as WHV_CAPABILITY_CODE_HYPERVISOR_PRESENT,
    WHvCreatePartition, WHvCreateVirtualProcessor, WHvDeletePartition, WHvDeleteVirtualProcessor,
    WHvGetCapability, WHvGetVirtualProcessorRegisters, WHvMapGpaRange,
    WHvMapGpaRangeFlagExecute as WHV_MAP_GPA_RANGE_FLAG_EXECUTE,
    WHvMapGpaRangeFlagRead as WHV_MAP_GPA_RANGE_FLAG_READ,
    WHvMapGpaRangeFlagWrite as WHV_MAP_GPA_RANGE_FLAG_WRITE,
    WHvPartitionPropertyCodeProcessorCount as WHV_PARTITION_PROPERTY_CODE_PROCESSOR_COUNT,
    WHvSetPartitionProperty, WHvSetVirtualProcessorRegisters, WHvSetupPartition, WHvUnmapGpaRange,
};

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
    #[cfg(target_arch = "aarch64")]
    Arm64Unsupported,
}

impl fmt::Display for AvailabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api(error) => error.fmt(formatter),
            Self::HypervisorDisabled => formatter.write_str(
                "Windows Hypervisor Platform is unavailable; enable the Windows Hypervisor Platform feature",
            ),
            #[cfg(target_arch = "aarch64")]
            Self::Arm64Unsupported => formatter.write_str(
                "this Windows Arm64 host needs Windows 11 24H2 build 26100.3915 or later with Windows Hypervisor Platform enabled",
            ),
        }
    }
}

impl Error for AvailabilityError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineError {
    Availability(AvailabilityError),
    InvalidMemorySize,
    #[cfg(target_arch = "aarch64")]
    InvalidGic,
    InvalidVcpu,
    #[cfg(target_arch = "x86_64")]
    Transport,
    Api(WhpError),
}

impl fmt::Display for MachineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Availability(error) => error.fmt(formatter),
            Self::InvalidMemorySize => {
                formatter.write_str("guest memory must be a nonzero multiple of 4096 bytes")
            }
            #[cfg(target_arch = "aarch64")]
            Self::InvalidGic => formatter.write_str("invalid ARM GIC layout"),
            Self::InvalidVcpu => {
                formatter.write_str("virtual processor index is outside the configured partition")
            }
            #[cfg(target_arch = "x86_64")]
            Self::Transport => formatter.write_str("VMM transport failed"),
            Self::Api(error) => error.fmt(formatter),
        }
    }
}

impl Error for MachineError {}

fn result(status: i32) -> Result<(), WhpError> {
    (status >= 0).ok_or(WhpError(status))
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
    aarch64::check_available()?;

    Ok(())
}

/// A configured WHP partition with guest-physical RAM ranges.
pub struct Machine {
    handle: WHV_PARTITION_HANDLE,
    memory: GuestMemory,
    vcpu_count: u32,
    mapped_ranges: Vec<(u64, u64)>,
    vcpus: Mutex<Vec<u32>>,
    #[cfg(target_arch = "aarch64")]
    gic: GicConfig,
}

impl Machine {
    #[must_use]
    pub fn memory(&self) -> GuestMemory {
        self.memory.clone()
    }

    pub fn new(
        memory: GuestMemory,
        vcpu_count: u32,
        gic: Option<GicConfig>,
    ) -> Result<Self, MachineError> {
        check_available().map_err(MachineError::Availability)?;
        if memory.ranges().iter().any(|range| {
            range.len == 0 || !range.addr.is_multiple_of(4096) || !range.len.is_multiple_of(4096)
        }) {
            return Err(MachineError::InvalidMemorySize);
        }
        if vcpu_count == 0 {
            return Err(MachineError::InvalidVcpu);
        }
        #[cfg(target_arch = "aarch64")]
        let gic = gic.ok_or(MachineError::InvalidGic)?;
        #[cfg(not(target_arch = "aarch64"))]
        let _ = gic;
        #[cfg(target_arch = "aarch64")]
        if gic.distributor_size == 0
            || gic.redistributor_size == 0
            || gic
                .distributor_base
                .checked_add(gic.distributor_size)
                .is_none()
            || gic
                .redistributor_base
                .checked_add(gic.redistributor_size)
                .is_none()
        {
            return Err(MachineError::InvalidGic);
        }
        let mut handle = 0;
        // SAFETY: handle points to storage for the output partition handle.
        result(unsafe { WHvCreatePartition(&raw mut handle) }).map_err(MachineError::Api)?;
        let mut partition = Self {
            handle,
            memory,
            vcpu_count,
            mapped_ranges: Vec::new(),
            vcpus: Mutex::new(Vec::new()),
            #[cfg(target_arch = "aarch64")]
            gic,
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
        .map_err(MachineError::Api)?;
        partition.configure_interrupt_controller()?;
        // SAFETY: the configured partition handle is valid until Machine drops it.
        result(unsafe { WHvSetupPartition(partition.handle) }).map_err(MachineError::Api)?;
        for (gpa, address, len) in partition.memory.host_ranges() {
            // SAFETY: GuestMemory owns the page-aligned source range until the partition unmaps it.
            result(unsafe {
                WHvMapGpaRange(
                    partition.handle,
                    address.cast(),
                    gpa,
                    len,
                    WHV_MAP_GPA_RANGE_FLAG_READ
                        | WHV_MAP_GPA_RANGE_FLAG_WRITE
                        | WHV_MAP_GPA_RANGE_FLAG_EXECUTE,
                )
            })
            .map_err(MachineError::Api)?;
            partition.mapped_ranges.push((gpa, len));
        }
        Ok(partition)
    }

    pub fn create_vcpu(&self, index: u32) -> Result<(), MachineError> {
        let mut vcpus = self
            .vcpus
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if index >= self.vcpu_count || vcpus.contains(&index) {
            return Err(MachineError::InvalidVcpu);
        }
        // SAFETY: index was validated against the configured processor count.
        result(unsafe { WHvCreateVirtualProcessor(self.handle, index, 0) })
            .map_err(MachineError::Api)?;
        #[cfg(target_arch = "aarch64")]
        if let Err(error) = self.configure_arm64_vcpu(index) {
            // SAFETY: this vCPU was just created in this partition.
            unsafe { WHvDeleteVirtualProcessor(self.handle, index) };
            return Err(error);
        }
        vcpus.push(index);
        Ok(())
    }

    pub fn cancel_vcpu(&self, index: u32) -> Result<(), MachineError> {
        self.require_vcpu(index)?;
        // SAFETY: index identifies a vCPU owned by this partition.
        result(unsafe { WHvCancelRunVirtualProcessor(self.handle, index, 0) })
            .map_err(MachineError::Api)
    }

    pub fn registers(
        &self,
        index: u32,
        names: &[WHV_REGISTER_NAME],
    ) -> Result<Vec<WHV_REGISTER_VALUE>, MachineError> {
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
        .map_err(MachineError::Api)?;
        Ok(values.into_iter().map(|value| value.0).collect())
    }

    #[cfg(any(target_arch = "aarch64", test))]
    pub fn register_u64(&self, index: u32, name: WHV_REGISTER_NAME) -> Result<u64, MachineError> {
        let value = self.registers(index, &[name])?[0];
        // SAFETY: callers select a WHP register whose value is represented as Reg64.
        Ok(unsafe { value.Reg64 })
    }

    pub fn set_registers(
        &self,
        index: u32,
        names: &[WHV_REGISTER_NAME],
        values: &[WHV_REGISTER_VALUE],
    ) -> Result<(), MachineError> {
        self.require_vcpu(index)?;
        if names.len() != values.len() {
            return Err(MachineError::InvalidVcpu);
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
        .map_err(MachineError::Api)
    }

    fn require_vcpu(&self, index: u32) -> Result<(), MachineError> {
        self.vcpus
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&index)
            .ok_or(MachineError::InvalidVcpu)
    }
}

impl Kick for Machine {
    fn kick(&self, vcpu: usize) {
        if let Ok(index) = u32::try_from(vcpu) {
            let _ = self.cancel_vcpu(index);
        }
    }
}

impl Drop for Machine {
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
        for (gpa, len) in self.mapped_ranges.drain(..) {
            // SAFETY: this is an exact GPA mapping created by Machine::new.
            unsafe { WHvUnmapGpaRange(self.handle, gpa, len) };
        }
        // SAFETY: handle was returned by WHvCreatePartition and is deleted once here.
        unsafe { WHvDeletePartition(self.handle) };
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
    #[cfg(target_arch = "x86_64")]
    IoPortAccess,
    #[cfg(target_arch = "x86_64")]
    ApicEoi(u8),
    #[cfg(target_arch = "aarch64")]
    Reset {
        reboot: bool,
    },
    #[cfg(target_arch = "x86_64")]
    Halt,
    Canceled,
    Other(i32),
}
