//! Native virtual-machine contracts.

use std::sync::Arc;

use crate::memory::GuestMemory;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptControllerConfig {
    X86,
    Arm(GicConfig),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GicConfig {
    pub distributor_base: u64,
    pub distributor_size: u64,
    pub redistributor_base: u64,
    pub redistributor_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmConfig {
    pub ram_base: u64,
    pub ram_bytes: u64,
    pub vcpus: u8,
    pub interrupt_controller: InterruptControllerConfig,
    pub irq_routes: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptMode {
    X86IrqLines,
    SoftwareIoapic,
    ArmIrqLines,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmCapabilities {
    pub interrupt_mode: InterruptMode,
    pub tsc_frequency: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootState {
    pub entry: u64,
    pub boot_argument: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioRead {
    pub address: u64,
    pub width: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioWrite {
    pub address: u64,
    pub width: u8,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PioRead {
    pub port: u16,
    pub length: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PioWrite {
    pub port: u16,
    pub length: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Msr {
    pub index: u32,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmException {
    pub address: u64,
    pub syndrome: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmRead {
    pub register: Option<u8>,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HvcResult {
    pub target: u8,
    pub status: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuStart {
    pub target: u8,
    pub entry: u64,
    pub context: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoApicAccess {
    pub offset: u8,
    pub width: u8,
    pub write: bool,
    pub value: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VcpuExit {
    Halt,
    Shutdown,
    Interrupted,
    MmioRead(MmioRead),
    MmioWrite(MmioWrite),
    PioRead(PioRead),
    PioWrite(PioWrite),
    Rdmsr(Msr),
    Wrmsr(Msr),
    ArmException(ArmException),
    ArmRegisterValue(u64),
    HvcResult(HvcResult),
    IoApicAccess(IoApicAccess),
    IoApicEoi(u8),
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VcpuAction {
    Start,
    Reenter,
    MmioRead(u64),
    PioZero,
    Rdmsr(u64),
    MsrFault,
    Wrmsr,
    ArmRead(ArmRead),
    ArmRegister(u8),
    HvcReturn(i64),
    CpuStart(CpuStart),
    CpuOff,
    SystemStop,
    IoApicValue(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VcpuOutcome {
    Shutdown,
    Stopped,
}

pub trait VcpuHandler: Send {
    fn exchange(&mut self, exit: VcpuExit) -> Result<VcpuAction, String>;

    fn finished(&mut self, outcome: VcpuOutcome);
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use crate::linux::kvm::aarch64::{
    machine::Machine as NativeMachine,
    worker::{KvmArmVm as NativePreparedVm, VcpuGroup as NativeVcpus},
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::linux::kvm::amd64::{
    kvm::Machine as NativeMachine,
    worker::{KvmX86Vm as NativePreparedVm, VcpuGroup as NativeVcpus},
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use crate::macos::aarch64::{
    machine::Machine as NativeMachine,
    worker::{MacArmVm as NativePreparedVm, VcpuGroup as NativeVcpus},
};
#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
use crate::windows::aarch64::worker::WindowsVm as NativePreparedVm;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use crate::windows::amd64::worker::WindowsVm as NativePreparedVm;
#[cfg(all(
    target_os = "windows",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use crate::windows::{whp::Partition as NativeMachine, worker::VcpuGroup as NativeVcpus};
#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "windows", target_arch = "aarch64")
)))]
use unsupported::{NativeMachine, NativePreparedVm, NativeVcpus};

pub struct PreparedVm(NativePreparedVm);

impl PreparedVm {
    pub fn create(config: &VmConfig, hard_stop: Option<fn() -> !>) -> Result<Self, String> {
        NativePreparedVm::create(config, hard_stop).map(Self)
    }

    pub fn capabilities() -> Result<VmCapabilities, String> {
        NativePreparedVm::capabilities()
    }

    #[must_use]
    pub fn handle(&self) -> VmHandle {
        self.0.handle()
    }

    pub fn start(
        self,
        boot: BootState,
        handlers: Vec<Box<dyn VcpuHandler>>,
    ) -> Result<RunningVcpus, String> {
        self.0.start(boot, handlers).map(RunningVcpus)
    }
}

pub struct RunningVcpus(NativeVcpus);

impl RunningVcpus {
    pub fn request_stop(&mut self) {
        self.0.request_stop();
    }
    pub fn join(&mut self) -> Result<Vec<Result<(), String>>, String> {
        self.0.join()
    }
}

#[derive(Clone)]
pub struct VmHandle(Arc<NativeMachine>);

impl VmHandle {
    #[cfg(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "windows",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    pub(crate) fn new(machine: Arc<NativeMachine>) -> Self {
        Self(machine)
    }

    #[must_use]
    pub fn memory(&self) -> GuestMemory {
        self.0.memory()
    }

    pub fn inject_interrupt(&self, irq: u32, level: bool) -> Result<(), String> {
        self.0.inject_interrupt(irq, level)
    }

    pub fn clear_interrupts(&self) -> Result<(), String> {
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        return self.0.clear_interrupts().map_err(|error| error.to_string());
        #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
        Ok(())
    }

    pub fn request_x86_interrupt(&self, vector: u8, destination: u8) -> Result<(), String> {
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        return self
            .0
            .request_x64_interrupt(vector, destination, false)
            .map_err(|error| error.to_string());
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            let _ = (vector, destination);
            Err("x86 interrupt injection is unavailable".to_owned())
        }
    }
}

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "windows", target_arch = "aarch64")
)))]
mod unsupported {
    use super::{BootState, GuestMemory, VcpuHandler, VmCapabilities, VmConfig, VmHandle};
    const UNSUPPORTED_HOST: &str = "VM execution requires Linux x86_64/aarch64, macOS Apple Silicon, or Windows x86_64/aarch64";

    pub(super) enum NativePreparedVm {}
    pub(super) enum NativeVcpus {}
    pub(super) enum NativeMachine {}

    impl NativePreparedVm {
        pub(super) fn create(_: &VmConfig, _: Option<fn() -> !>) -> Result<Self, String> {
            Err(UNSUPPORTED_HOST.to_owned())
        }
        pub(super) fn capabilities() -> Result<VmCapabilities, String> {
            Err(UNSUPPORTED_HOST.to_owned())
        }
        pub(super) fn handle(&self) -> VmHandle {
            match *self {}
        }
        pub(super) fn start(
            self,
            _: BootState,
            _: Vec<Box<dyn VcpuHandler>>,
        ) -> Result<NativeVcpus, String> {
            match self {}
        }
    }
    impl NativeMachine {
        pub(super) fn memory(&self) -> GuestMemory {
            match *self {}
        }
        pub(super) fn inject_interrupt(&self, _: u32, _: bool) -> Result<(), String> {
            match *self {}
        }
    }
    impl NativeVcpus {
        pub(super) fn request_stop(&mut self) {
            match *self {}
        }
        pub(super) fn join(&mut self) -> Result<Vec<Result<(), String>>, String> {
            match *self {}
        }
    }

    #[cfg(test)]
    mod tests {
        use super::UNSUPPORTED_HOST;
        use crate::vm::{InterruptControllerConfig, PreparedVm, VmConfig};

        #[test]
        fn capability_query_and_creation_reject_unsupported_hosts() {
            let config = VmConfig {
                ram_base: 0,
                ram_bytes: 4096,
                vcpus: 1,
                interrupt_controller: InterruptControllerConfig::X86,
                irq_routes: Vec::new(),
            };
            assert_eq!(PreparedVm::capabilities(), Err(UNSUPPORTED_HOST.to_owned()));
            assert_eq!(
                PreparedVm::create(&config, None).err().as_deref(),
                Some(UNSUPPORTED_HOST)
            );
        }
    }
}
