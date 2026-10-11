//! Native virtual-machine contracts.

use std::sync::Arc;

use crate::memory::GuestMemory;
use crate::vcpus::Vcpus;

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

    fn failed(&mut self, _error: &str) {}
}

pub(crate) fn report_vcpu_failure<T, E: std::fmt::Display>(
    id: impl std::fmt::Display,
    handler: &mut dyn VcpuHandler,
    outcome: Result<T, E>,
) -> Result<T, E> {
    if let Err(error) = &outcome {
        let error = format!("vCPU {id} failed: {error}");
        log::error!("{error}");
        handler.failed(&error);
    }
    outcome
}

#[cfg(target_os = "macos")]
use crate::hvf as backend;
#[cfg(target_os = "linux")]
use crate::kvm as backend;
#[cfg(windows)]
use crate::whp as backend;

pub struct PreparedVm(backend::Vm);

impl PreparedVm {
    pub fn create(config: &VmConfig, hard_stop: Option<fn() -> !>) -> Result<Self, String> {
        backend::Vm::create(config, hard_stop).map(Self)
    }

    pub fn capabilities() -> Result<VmCapabilities, String> {
        backend::Vm::capabilities()
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

pub struct RunningVcpus(Vcpus);

impl RunningVcpus {
    pub fn request_stop(&mut self) {
        self.0.request_stop();
    }
    pub fn join(&mut self) -> Result<Vec<Result<(), String>>, String> {
        self.0.join()
    }
}

#[derive(Clone)]
pub struct VmHandle(Arc<backend::Machine>);

impl VmHandle {
    pub(crate) fn new(machine: Arc<backend::Machine>) -> Self {
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
        self.0.clear_interrupts()
    }

    pub fn request_x86_interrupt(&self, vector: u8, destination: u8) -> Result<(), String> {
        self.0.request_x86_interrupt(vector, destination)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_errors_notify_once_and_successes_remain_successful() {
        #[derive(Default)]
        struct Handler(Vec<String>);
        impl VcpuHandler for Handler {
            fn exchange(&mut self, _: VcpuExit) -> Result<VcpuAction, String> {
                panic!("worker outcome must not resume the guest")
            }
            fn finished(&mut self, _: VcpuOutcome) {
                panic!("failure reporting must not send a successful outcome")
            }
            fn failed(&mut self, error: &str) {
                self.0.push(error.to_owned());
            }
        }
        let mut handler = Handler::default();
        let hardware_error = std::io::Error::other("boot register write failed");
        let hardware_outcome: Result<(), _> =
            report_vcpu_failure(0, &mut handler, Err(hardware_error));
        assert_eq!(
            hardware_outcome.unwrap_err().to_string(),
            "boot register write failed"
        );
        let emulation_outcome: Result<(), _> =
            report_vcpu_failure(1_u32, &mut handler, Err("WHP emulation failed".to_owned()));
        assert_eq!(emulation_outcome, Err("WHP emulation failed".to_owned()));
        assert_eq!(
            report_vcpu_failure(2, &mut handler, Ok::<_, String>(VcpuOutcome::Stopped)),
            Ok(VcpuOutcome::Stopped)
        );
        assert_eq!(
            handler.0,
            [
                "vCPU 0 failed: boot register write failed",
                "vCPU 1 failed: WHP emulation failed"
            ]
        );
    }
}
