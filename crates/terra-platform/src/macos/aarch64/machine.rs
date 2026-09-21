#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fmt;
use std::sync::Arc;

use applevisor::prelude::{
    ExitReason, GicConfig, GicEnabled, HypervisorError, MemPerms, PAGE_SIZE, Reg, SysReg, Vcpu,
    VcpuExit, VcpuHandle, VirtualMachine, VirtualMachineConfig, VirtualMachineInstance,
};
use applevisor_sys::hv_vm_map;
use vm_memory::{GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

use crate::aarch64::arm::{GIC_LAYOUT, GicLayout, RAM_BASE};

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
        write!(formatter, "{self:?}")
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
    ram: Arc<GuestMemoryMmap<()>>,
}

/// A vCPU which stays on the thread that created it.
pub struct Cpu {
    vcpu: Vcpu,
}

impl terra_runtime::component::vmm::VirtualMachine for Machine {
    fn memory(&self) -> wasmtime::Result<terra_runtime::memory::GuestRam> {
        terra_runtime::memory::GuestRam::from_shared(self.shared_ram())
            .ok_or_else(|| wasmtime::Error::msg("aliasing HVF RAM"))
    }
}

impl Machine {
    pub fn new(ram_size: u64) -> Result<Self, HvError> {
        let ram_size_usize = usize::try_from(ram_size).map_err(|_| HvError::Memory)?;
        if ram_size_usize == 0 || !ram_size.is_multiple_of(PAGE_SIZE as u64) {
            return Err(HvError::Memory);
        }
        let gic = gic_layout()?;
        let mut gic_config = GicConfig::new();
        gic_config.set_distributor_base(gic.distributor_base)?;
        gic_config.set_redistributor_base(gic.redistributor_base)?;
        let vm = VirtualMachine::with_gic(VirtualMachineConfig::new(), gic_config)?;
        let ram = Arc::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(RAM_BASE), ram_size_usize)])
                .map_err(|_| HvError::Memory)?,
        );
        let host_address = ram
            .get_host_address(GuestAddress(RAM_BASE))
            .map_err(|_| HvError::Memory)?;
        // SAFETY: `ram` stays alive until after the Hypervisor.framework VM is destroyed.
        let result = unsafe {
            hv_vm_map(
                host_address.cast::<c_void>(),
                RAM_BASE,
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
    pub fn shared_ram(&self) -> Arc<GuestMemoryMmap<()>> {
        Arc::clone(&self.ram)
    }

    pub fn set_irq(&self, irq: u32, level: bool) -> Result<(), HvError> {
        let intid = GIC_SPI_OFFSET.checked_add(irq).ok_or(HvError::GicLayout)?;
        self.vm.gic_set_spi(intid, level)?;
        Ok(())
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

fn gic_layout() -> Result<GicLayout, HvError> {
    let distributor_size =
        u64::try_from(GicConfig::get_distributor_size()?).map_err(|_| HvError::GicLayout)?;
    let redistributor_size = u64::try_from(GicConfig::get_redistributor_region_size()?)
        .map_err(|_| HvError::GicLayout)?;
    let distributor_alignment = u64::try_from(GicConfig::get_distributor_base_alignment()?)
        .map_err(|_| HvError::GicLayout)?;
    let redistributor_alignment = u64::try_from(GicConfig::get_redistributor_base_alignment()?)
        .map_err(|_| HvError::GicLayout)?;
    if distributor_alignment == 0
        || redistributor_alignment == 0
        || !GIC_LAYOUT
            .distributor_base
            .is_multiple_of(distributor_alignment)
        || !GIC_LAYOUT
            .redistributor_base
            .is_multiple_of(redistributor_alignment)
    {
        return Err(HvError::GicLayout);
    }
    Ok(GicLayout {
        distributor_size,
        redistributor_size,
        ..GIC_LAYOUT
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
