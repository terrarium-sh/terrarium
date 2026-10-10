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

/// A load or store that faulted on device memory, decoded from its ARM data-abort syndrome into
/// the MMIO exit KVM and WHP on x86 already deliver decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmMmioAccess {
    width: u8,
    register: u8,
    is_write: bool,
    is_sign_extended: bool,
    is_64_bit_register: bool,
}

impl ArmMmioAccess {
    /// `Ok(None)` identifies an HVC call for the platform to handle.
    pub fn decode(syndrome: u64) -> Result<Option<Self>, String> {
        const EC: u64 = 0b11_1111 << 26;
        const DATA_ABORT_LOWER: u64 = 0x24 << 26;
        const DATA_ABORT_SAME: u64 = 0x25 << 26;
        const HVC64: u64 = 0x16 << 26;
        const ISV: u64 = 1 << 24;
        const SAS: u64 = 0b11 << 22;
        const SSE: u64 = 1 << 21;
        const SRT: u64 = 0b1_1111 << 16;
        const SF: u64 = 1 << 15;
        const WNR: u64 = 1 << 6;

        if syndrome & EC == HVC64 {
            return Ok(None);
        }
        if !matches!(syndrome & EC, DATA_ABORT_LOWER | DATA_ABORT_SAME) {
            return Err(format!("unexpected ARM exception (syndrome {syndrome:#x})"));
        }
        let width = 1_u8 << ((syndrome & SAS) >> 22);
        let is_64_bit_register = syndrome & SF != 0;
        if syndrome & ISV == 0 || (!is_64_bit_register && width == 8) {
            return Err(format!(
                "undecodable ARM data abort (syndrome {syndrome:#x})"
            ));
        }
        Ok(Some(Self {
            width,
            register: ((syndrome & SRT) >> 16) as u8,
            is_write: syndrome & WNR != 0,
            is_sign_extended: syndrome & SSE != 0,
            is_64_bit_register,
        }))
    }

    /// A store reads its source register through `read_register`; register 31 is the zero register.
    pub fn exit<E>(
        self,
        address: u64,
        read_register: impl FnOnce(u8) -> Result<u64, E>,
    ) -> Result<VcpuExit, E> {
        if !self.is_write {
            return Ok(VcpuExit::MmioRead(MmioRead {
                address,
                width: self.width,
            }));
        }
        let value = if self.register == 31 {
            0
        } else {
            read_register(self.register)?
        };
        Ok(VcpuExit::MmioWrite(MmioWrite {
            address,
            width: self.width,
            value: value & self.width_mask(),
        }))
    }

    /// The guest register write that completes the access; the caller then steps past the
    /// faulting instruction.
    pub fn complete(self, action: VcpuAction) -> Result<ArmRegisterWrite, String> {
        match action {
            VcpuAction::Reenter if self.is_write => Ok(ArmRegisterWrite {
                register: None,
                value: 0,
            }),
            VcpuAction::MmioRead(value) if !self.is_write => Ok(ArmRegisterWrite {
                register: (self.register != 31).then_some(self.register),
                value: self.load_value(value),
            }),
            VcpuAction::Start
            | VcpuAction::Reenter
            | VcpuAction::MmioRead(_)
            | VcpuAction::PioZero
            | VcpuAction::Rdmsr(_)
            | VcpuAction::MsrFault
            | VcpuAction::Wrmsr
            | VcpuAction::IoApicValue(_) => {
                Err(format!("unexpected ARM MMIO completion {action:?}"))
            }
        }
    }

    fn width_mask(self) -> u64 {
        u64::MAX >> (64 - u32::from(self.width) * 8)
    }

    fn load_value(self, value: u64) -> u64 {
        let value = value & self.width_mask();
        let value = if self.is_sign_extended {
            let shift = 64 - u32::from(self.width) * 8;
            ((value << shift).cast_signed() >> shift).cast_unsigned()
        } else {
            value
        };
        if self.is_64_bit_register {
            value
        } else {
            value & u64::from(u32::MAX)
        }
    }
}

#[cfg(test)]
mod arm_mmio_tests {
    use super::{ArmMmioAccess, ArmRegisterWrite, MmioRead, MmioWrite, VcpuAction, VcpuExit};

    const DATA_ABORT: u64 = 0x24 << 26;
    const ISV: u64 = 1 << 24;
    const SF: u64 = 1 << 15;
    const WNR: u64 = 1 << 6;

    /// Only decoded data aborts and platform-handled HVC calls can resume the guest;
    /// skipping another exception would drop a store or bypass a faulting instruction.
    #[test]
    fn decoding_accepts_decoded_data_aborts_and_rejects_undecodable_ones() {
        assert!(matches!(
            ArmMmioAccess::decode(DATA_ABORT | ISV | SF),
            Ok(Some(_))
        ));
        assert!(matches!(
            ArmMmioAccess::decode((0x25 << 26) | ISV | SF),
            Ok(Some(_))
        ));
        assert_eq!(ArmMmioAccess::decode(0x16 << 26), Ok(None));
        for unexpected in [ISV | SF, 0x01 << 26, 0x20 << 26, 0x21 << 26] {
            assert!(ArmMmioAccess::decode(unexpected).is_err());
        }
        for data_abort in [DATA_ABORT, 0x25 << 26] {
            for undecodable in [
                data_abort | SF,
                data_abort | SF | WNR,
                data_abort | ISV | (3 << 22),
                data_abort | ISV | (3 << 22) | WNR,
            ] {
                assert!(ArmMmioAccess::decode(undecodable).is_err());
            }
        }
    }

    #[test]
    fn stores_become_mmio_writes_of_the_masked_source_register() {
        let store = ArmMmioAccess::decode(DATA_ABORT | ISV | SF | WNR | (1 << 22) | (7 << 16))
            .unwrap()
            .unwrap();
        let mut reads = Vec::new();
        let exit = store
            .exit(0x1000, |register| {
                reads.push(register);
                Ok::<_, &'static str>(0x1234_5678)
            })
            .unwrap();
        assert_eq!(
            exit,
            VcpuExit::MmioWrite(MmioWrite {
                address: 0x1000,
                width: 2,
                value: 0x5678,
            })
        );
        assert_eq!(reads, [7]);
        let zero = ArmMmioAccess::decode(DATA_ABORT | ISV | SF | WNR | (31 << 16))
            .unwrap()
            .unwrap();
        assert_eq!(
            zero.exit(0x1000, |_| Err("the zero register is never read")),
            Ok(VcpuExit::MmioWrite(MmioWrite {
                address: 0x1000,
                width: 1,
                value: 0,
            }))
        );
        assert_eq!(
            store.complete(VcpuAction::Reenter),
            Ok(ArmRegisterWrite {
                register: None,
                value: 0,
            })
        );
        assert!(store.complete(VcpuAction::MmioRead(1)).is_err());
    }

    #[test]
    fn loads_fill_the_destination_register_at_its_width() {
        let load = |syndrome| {
            ArmMmioAccess::decode(DATA_ABORT | ISV | (4 << 16) | syndrome)
                .unwrap()
                .unwrap()
        };
        assert_eq!(
            load(SF).exit(0x2000, |_| Err::<u64, _>("loads read no register")),
            Ok(VcpuExit::MmioRead(MmioRead {
                address: 0x2000,
                width: 1,
            }))
        );
        let signed_byte = 1 << 21;
        for (syndrome, device_value, register_value) in [
            (SF | signed_byte, 0x80, u64::MAX - 0x7f),
            (signed_byte, 0x80, u64::from(u32::MAX - 0x7f)),
            (2 << 22, 0x1234_5678_9abc_def0, 0x9abc_def0),
        ] {
            assert_eq!(
                load(syndrome).complete(VcpuAction::MmioRead(device_value)),
                Ok(ArmRegisterWrite {
                    register: Some(4),
                    value: register_value,
                })
            );
        }
        let discarded = ArmMmioAccess::decode(DATA_ABORT | ISV | SF | (31 << 16))
            .unwrap()
            .unwrap();
        assert_eq!(
            discarded.complete(VcpuAction::MmioRead(9)),
            Ok(ArmRegisterWrite {
                register: None,
                value: 9,
            })
        );
        assert!(load(SF).complete(VcpuAction::Reenter).is_err());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmRegisterWrite {
    pub register: Option<u8>,
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

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(
        target_os = "windows",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "macos", target_arch = "aarch64")
))]
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

#[cfg(test)]
mod failure_tests {
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
