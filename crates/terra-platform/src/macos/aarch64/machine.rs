#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fmt;

use crate::memory::GuestMemory;
use crate::vm::{GicConfig as NativeGicConfig, VmConfig};
use applevisor::prelude::{
    ExitReason, GicConfig as HvGicConfig, GicEnabled, HypervisorError, MemPerms, PAGE_SIZE, Reg,
    SysReg, Vcpu, VcpuExit, VcpuHandle, VirtualMachine, VirtualMachineConfig,
    VirtualMachineInstance,
};
use applevisor_sys::hv_vm_map;

const GIC_SPI_OFFSET: u32 = 32;

#[derive(Debug)]
pub enum HvError {
    ProgramCounterOverflow,
    InvalidRegister,
    Memory,
    GicLayout,
    Hypervisor(HypervisorError),
}

impl fmt::Display for HvError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProgramCounterOverflow => formatter.write_str("program counter overflow"),
            Self::InvalidRegister => formatter.write_str("invalid ARM register"),
            Self::Memory => formatter.write_str("invalid guest memory"),
            Self::GicLayout => formatter.write_str("invalid GIC layout"),
            Self::Hypervisor(error) => write!(formatter, "Hypervisor.framework: {error}"),
        }
    }
}

impl std::error::Error for HvError {}

impl From<HypervisorError> for HvError {
    fn from(error: HypervisorError) -> Self {
        Self::Hypervisor(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunExit {
    Canceled,
    Timer,
    Exception {
        syndrome: u64,
        physical_address: u64,
    },
    Unknown,
}

/// One configured Apple Silicon VM. Hypervisor.framework permits one VM per process.
pub struct Machine {
    vm: VirtualMachineInstance<GicEnabled>,
    ram: GuestMemory,
}

/// A vCPU which stays on the thread that created it.
pub struct Cpu {
    vcpu: Vcpu,
}

impl Machine {
    pub fn new(config: &VmConfig) -> Result<Self, HvError> {
        let ram_size_usize = usize::try_from(config.ram_bytes).map_err(|_| HvError::Memory)?;
        if ram_size_usize == 0 || !config.ram_bytes.is_multiple_of(PAGE_SIZE as u64) {
            return Err(HvError::Memory);
        }
        let crate::vm::InterruptControllerConfig::Arm(gic) = &config.interrupt_controller else {
            return Err(HvError::GicLayout);
        };
        let gic = gic_layout(gic)?;
        let mut gic_config = HvGicConfig::new();
        gic_config.set_distributor_base(gic.distributor_base)?;
        gic_config.set_redistributor_base(gic.redistributor_base)?;
        let vm = VirtualMachine::with_gic(VirtualMachineConfig::new(), gic_config)?;
        let ram =
            GuestMemory::allocate_at(config.ram_base, config.ram_bytes).ok_or(HvError::Memory)?;
        let host_address = ram.host_address(config.ram_base).ok_or(HvError::Memory)?;
        // SAFETY: `ram` stays alive until after the Hypervisor.framework VM is destroyed.
        let result = unsafe {
            hv_vm_map(
                host_address.cast::<c_void>(),
                config.ram_base,
                ram_size_usize,
                u64::from(MemPerms::RWX),
            )
        };
        if result != 0 {
            return Err(HypervisorError::from(result).into());
        }
        Ok(Self { vm, ram })
    }

    /// Creates a powered-off CPU's execution context on its owning thread.
    pub fn create_secondary(&self, mpidr: u64, entry: u64, context: u64) -> Result<Cpu, HvError> {
        let vcpu = self.vm.vcpu_create()?;
        vcpu.set_reg(Reg::CPSR, terra_limits::ARM_PSTATE_EL1H_DAIF)?;
        vcpu.set_reg(Reg::PC, entry)?;
        vcpu.set_reg(Reg::X0, context)?;
        vcpu.set_sys_reg(SysReg::MPIDR_EL1, mpidr)?;
        Ok(Cpu { vcpu })
    }

    pub fn exit(&self, cpus: &[VcpuHandle]) -> Result<(), HvError> {
        self.vm.vcpus_exit(cpus)?;
        Ok(())
    }

    #[must_use]
    pub fn memory(&self) -> GuestMemory {
        self.ram.clone()
    }

    pub fn inject_interrupt(&self, irq: u32, level: bool) -> Result<(), String> {
        let intid = GIC_SPI_OFFSET
            .checked_add(irq)
            .ok_or_else(|| HvError::GicLayout.to_string())?;
        self.vm
            .gic_set_spi(intid, level)
            .map_err(|error| HvError::from(error).to_string())
    }
}

impl Cpu {
    pub fn set_arm_mmio_read(&self, register: Option<u8>, value: u64) -> Result<(), HvError> {
        if let Some(register) = register {
            let register = general_register(register).ok_or(HvError::InvalidRegister)?;
            self.vcpu.set_reg(register, value)?;
        }
        Ok(())
    }

    pub fn arm_register_value(&self, register: u8) -> Result<u64, HvError> {
        if register == 31 {
            return Ok(0);
        }
        self.vcpu
            .get_reg(general_register(register).ok_or(HvError::InvalidRegister)?)
            .map_err(Into::into)
    }

    pub fn set_reg(&self, register: Reg, value: u64) -> Result<(), HvError> {
        self.vcpu.set_reg(register, value)?;
        Ok(())
    }

    pub fn advance_pc(&self) -> Result<(), HvError> {
        let pc = self.vcpu.get_reg(Reg::PC)?;
        self.vcpu.set_reg(
            Reg::PC,
            pc.checked_add(4).ok_or(HvError::ProgramCounterOverflow)?,
        )?;
        Ok(())
    }

    pub fn run(&self) -> Result<RunExit, HvError> {
        self.vcpu.run()?;
        let exit = self.vcpu.get_exit_info();
        Ok(decode_exit(exit))
    }

    #[must_use]
    pub fn handle(&self) -> VcpuHandle {
        self.vcpu.get_handle()
    }
}

fn gic_layout(gic: &NativeGicConfig) -> Result<NativeGicConfig, HvError> {
    let distributor_size =
        u64::try_from(HvGicConfig::get_distributor_size()?).map_err(|_| HvError::GicLayout)?;
    let redistributor_size = u64::try_from(HvGicConfig::get_redistributor_region_size()?)
        .map_err(|_| HvError::GicLayout)?;
    let distributor_alignment = u64::try_from(HvGicConfig::get_distributor_base_alignment()?)
        .map_err(|_| HvError::GicLayout)?;
    let redistributor_alignment = u64::try_from(HvGicConfig::get_redistributor_base_alignment()?)
        .map_err(|_| HvError::GicLayout)?;
    if distributor_alignment == 0
        || redistributor_alignment == 0
        || !gic.distributor_base.is_multiple_of(distributor_alignment)
        || !gic
            .redistributor_base
            .is_multiple_of(redistributor_alignment)
        || gic.distributor_size < distributor_size
        || gic.redistributor_size < redistributor_size
    {
        return Err(HvError::GicLayout);
    }
    Ok(NativeGicConfig {
        distributor_size,
        redistributor_size,
        ..*gic
    })
}

fn decode_exit(exit: VcpuExit) -> RunExit {
    match exit.reason {
        ExitReason::CANCELED => RunExit::Canceled,
        ExitReason::VTIMER_ACTIVATED => RunExit::Timer,
        ExitReason::EXCEPTION => {
            let syndrome = exit.exception.syndrome;
            RunExit::Exception {
                syndrome,
                physical_address: exit.exception.physical_address,
            }
        }
        ExitReason::UNKNOWN => RunExit::Unknown,
    }
}

fn general_register(number: u8) -> Option<Reg> {
    match number {
        0 => Some(Reg::X0),
        1 => Some(Reg::X1),
        2 => Some(Reg::X2),
        3 => Some(Reg::X3),
        4 => Some(Reg::X4),
        5 => Some(Reg::X5),
        6 => Some(Reg::X6),
        7 => Some(Reg::X7),
        8 => Some(Reg::X8),
        9 => Some(Reg::X9),
        10 => Some(Reg::X10),
        11 => Some(Reg::X11),
        12 => Some(Reg::X12),
        13 => Some(Reg::X13),
        14 => Some(Reg::X14),
        15 => Some(Reg::X15),
        16 => Some(Reg::X16),
        17 => Some(Reg::X17),
        18 => Some(Reg::X18),
        19 => Some(Reg::X19),
        20 => Some(Reg::X20),
        21 => Some(Reg::X21),
        22 => Some(Reg::X22),
        23 => Some(Reg::X23),
        24 => Some(Reg::X24),
        25 => Some(Reg::X25),
        26 => Some(Reg::X26),
        27 => Some(Reg::X27),
        28 => Some(Reg::X28),
        29 => Some(Reg::X29),
        30 => Some(Reg::X30),
        _ => None,
    }
}
