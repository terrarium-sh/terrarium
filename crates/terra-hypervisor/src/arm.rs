//! ARM guest exits that reach userspace undecoded: MMIO data aborts and PSCI calls.

use crate::vm::{MmioRead, MmioWrite, VcpuAction, VcpuExit};

/// A load or store that faulted on device memory, decoded from its ARM data-abort syndrome into
/// the MMIO exit KVM and WHP on x86 already deliver decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ArmMmioAccess {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ArmRegisterWrite {
    pub(crate) register: Option<u8>,
    pub(crate) value: u64,
}

/// An EL1 access to a debug OS register (`OSLAR_EL1`, `OSLSR_EL1`, `OSDLR_EL1`, `DBGPRCR_EL1`)
/// that Hypervisor.framework traps to the host through `MDCR_EL2.TDOSA`. Nothing in a VM without
/// a host debugger observes their state, so a completed access writes no register and reads zero.
#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ArmDebugOsAccess {
    read_register: Option<u8>,
}

#[cfg(any(target_os = "macos", test))]
impl ArmDebugOsAccess {
    /// `None` for exceptions that are not a trapped debug OS-register access.
    pub fn decode(syndrome: u64) -> Option<Self> {
        const EC: u64 = 0b11_1111 << 26;
        const SYS64_TRAP: u64 = 0x18 << 26;
        if syndrome & EC != SYS64_TRAP {
            return None;
        }
        let op0 = (syndrome >> 20) & 0b11;
        let op1 = (syndrome >> 14) & 0b111;
        let op2 = (syndrome >> 17) & 0b111;
        let crn = (syndrome >> 10) & 0b1111;
        let crm = (syndrome >> 1) & 0b1111;
        let is_debug_os = (op0, op1, crn, op2) == (2, 0, 1, 4) && matches!(crm, 0 | 1 | 3 | 4);
        if !is_debug_os {
            return None;
        }
        let is_read = syndrome & 1 != 0;
        let destination = ((syndrome >> 5) & 0b1_1111) as u8;
        Some(Self {
            read_register: (is_read && destination != 31).then_some(destination),
        })
    }

    /// The guest register write that completes the access.
    pub fn complete(self) -> ArmRegisterWrite {
        ArmRegisterWrite {
            register: self.read_register,
            value: 0,
        }
    }
}

/// ARM PSCI calls for hypervisors that exit to userspace on HVC.
#[cfg(any(target_os = "macos", test))]
pub(crate) mod psci {
    const VERSION: u64 = 0x8400_0000;
    const CPU_OFF: u64 = 0x8400_0002;
    const CPU_ON_32: u64 = 0x8400_0003;
    const CPU_ON: u64 = 0xc400_0003;
    const AFFINITY_INFO_32: u64 = 0x8400_0004;
    const AFFINITY_INFO: u64 = 0xc400_0004;
    const SYSTEM_OFF: u64 = 0x8400_0008;
    const SYSTEM_RESET: u64 = 0x8400_0009;
    const FEATURES: u64 = 0x8400_000a;

    const VERSION_1_0: i64 = 0x0001_0000;
    const SUCCESS: i64 = 0;
    const NOT_SUPPORTED: i64 = -1;
    const INVALID_PARAMETERS: i64 = -2;
    const DENIED: i64 = -3;
    const ALREADY_ON: i64 = -4;

    /// The guest registers x0..x3 of an HVC call.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PsciCall {
        pub function: u64,
        pub argument0: u64,
        pub argument1: u64,
        pub argument2: u64,
    }

    impl PsciCall {
        #[must_use]
        pub const fn from_registers([function, argument0, argument1, argument2]: [u64; 4]) -> Self {
            Self {
                function,
                argument0,
                argument1,
                argument2,
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PsciAction {
        Return(i64),
        StartCpu {
            target: usize,
            entry: u64,
            context: u64,
        },
        PowerOffCaller,
        StopMachine,
    }

    /// `powered_cpus[n]` is whether CPU `n` is on; `is_entry_valid` accepts a `CPU_ON` entry point.
    pub fn decide(
        call: PsciCall,
        powered_cpus: &[bool],
        is_entry_valid: impl FnOnce(u64) -> bool,
    ) -> PsciAction {
        let target = u8::try_from(call.argument0).ok().and_then(|target| {
            Some((usize::from(target), *powered_cpus.get(usize::from(target))?))
        });
        let status = match call.function {
            VERSION => VERSION_1_0,
            FEATURES => features(call.argument0),
            AFFINITY_INFO | AFFINITY_INFO_32 => match target {
                _ if call.argument1 != 0 => INVALID_PARAMETERS,
                Some((_, is_powered)) => i64::from(!is_powered),
                None => DENIED,
            },
            CPU_ON | CPU_ON_32 => match target {
                Some((_, true)) => ALREADY_ON,
                Some((target, false)) if is_entry_valid(call.argument1) => {
                    return PsciAction::StartCpu {
                        target,
                        entry: call.argument1,
                        context: call.argument2,
                    };
                }
                Some((_, false)) => INVALID_PARAMETERS,
                None => DENIED,
            },
            CPU_OFF => return PsciAction::PowerOffCaller,
            SYSTEM_OFF | SYSTEM_RESET => return PsciAction::StopMachine,
            _ => NOT_SUPPORTED,
        };
        PsciAction::Return(status)
    }

    fn features(function: u64) -> i64 {
        match function {
            VERSION | FEATURES | CPU_OFF | CPU_ON | CPU_ON_32 | AFFINITY_INFO
            | AFFINITY_INFO_32 | SYSTEM_OFF | SYSTEM_RESET => SUCCESS,
            _ => NOT_SUPPORTED,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn call(function: u64, argument0: u64, argument1: u64, argument2: u64) -> PsciCall {
            PsciCall::from_registers([function, argument0, argument1, argument2])
        }

        /// The boot CPU may turn itself off like any other, and then `CPU_ON` brings it back.
        #[test]
        fn cpu_on_restarts_the_boot_cpu_after_cpu_off() {
            assert_eq!(
                decide(call(CPU_ON, 0, 0x8000, 7), &[false, true], |_| true),
                PsciAction::StartCpu {
                    target: 0,
                    entry: 0x8000,
                    context: 7
                }
            );
            assert_eq!(
                decide(call(CPU_ON, 0, 0x8000, 7), &[true, true], |_| true),
                PsciAction::Return(ALREADY_ON)
            );
        }

        #[test]
        fn cpu_on_starts_an_unpowered_cpu_with_a_valid_entry() {
            assert_eq!(
                decide(call(CPU_ON, 1, 0x8000, 7), &[true, false], |_| true),
                PsciAction::StartCpu {
                    target: 1,
                    entry: 0x8000,
                    context: 7
                }
            );
            assert_eq!(
                decide(call(CPU_ON_32, 1, 0x8000, 7), &[true, false], |_| true),
                PsciAction::StartCpu {
                    target: 1,
                    entry: 0x8000,
                    context: 7
                }
            );
        }

        #[test]
        fn cpu_on_rejects_an_invalid_entry_without_stopping_the_machine() {
            assert_eq!(
                decide(call(CPU_ON, 1, 0x8002, 0), &[true, false], |_| false),
                PsciAction::Return(INVALID_PARAMETERS)
            );
        }

        #[test]
        fn cpu_on_reports_already_on_and_unknown_targets() {
            let never = |_| panic!("entry checked for a CPU that cannot start");
            assert_eq!(
                decide(call(CPU_ON, 1, 0x8000, 0), &[true, true], never),
                PsciAction::Return(ALREADY_ON)
            );
            assert_eq!(
                decide(call(CPU_ON, 1, 0x8000, 0), &[true], never),
                PsciAction::Return(DENIED)
            );
            assert_eq!(
                decide(call(CPU_ON, 0x1_0001, 0x8000, 0), &[true, false], never),
                PsciAction::Return(DENIED)
            );
        }

        #[test]
        fn affinity_info_reports_power_state() {
            let never = |_| false;
            for function in [AFFINITY_INFO, AFFINITY_INFO_32] {
                assert_eq!(
                    decide(call(function, 0, 0, 0), &[true, false], never),
                    PsciAction::Return(0)
                );
                assert_eq!(
                    decide(call(function, 1, 0, 0), &[true, false], never),
                    PsciAction::Return(1)
                );
                assert_eq!(
                    decide(call(function, 2, 0, 0), &[true, false], never),
                    PsciAction::Return(DENIED)
                );
                assert_eq!(
                    decide(call(function, 1, 1, 0), &[true, false], never),
                    PsciAction::Return(INVALID_PARAMETERS)
                );
            }
        }

        #[test]
        fn version_features_and_power_calls() {
            let decide = |call| decide(call, &[true], |_| false);
            assert_eq!(
                decide(call(VERSION, 0, 0, 0)),
                PsciAction::Return(0x0001_0000)
            );
            for function in [
                VERSION,
                FEATURES,
                CPU_OFF,
                CPU_ON,
                CPU_ON_32,
                AFFINITY_INFO,
                AFFINITY_INFO_32,
                SYSTEM_OFF,
                SYSTEM_RESET,
            ] {
                assert_eq!(
                    decide(call(FEATURES, function, 0, 0)),
                    PsciAction::Return(SUCCESS)
                );
            }
            assert_eq!(
                decide(call(FEATURES, 0x8400_0001, 0, 0)),
                PsciAction::Return(NOT_SUPPORTED)
            );
            assert_eq!(decide(call(CPU_OFF, 0, 0, 0)), PsciAction::PowerOffCaller);
            assert_eq!(decide(call(SYSTEM_OFF, 0, 0, 0)), PsciAction::StopMachine);
            assert_eq!(decide(call(SYSTEM_RESET, 0, 0, 0)), PsciAction::StopMachine);
            assert_eq!(
                decide(call(0x8400_0001, 0, 0, 0)),
                PsciAction::Return(NOT_SUPPORTED)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArmDebugOsAccess, ArmMmioAccess, ArmRegisterWrite, MmioRead, MmioWrite, VcpuAction,
        VcpuExit,
    };

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

    /// A Linux guest clears the OS lock with `msr osdlr_el1, xzr; msr oslar_el1, xzr`, and
    /// Hypervisor.framework traps both (syndrome 0x622807e6 seen on macOS 26); every trapped
    /// debug OS register must complete as a no-op write or a zero read, or the guest dies in
    /// early boot.
    #[test]
    fn debug_os_register_traps_complete_without_a_host_debugger() {
        let write = ArmDebugOsAccess::decode(0x6228_07e6).unwrap();
        assert_eq!(
            write.complete(),
            ArmRegisterWrite {
                register: None,
                value: 0,
            }
        );
        for oslar_or_dbgprcr in [0x6228_07e0, 0x6228_07e8] {
            assert_eq!(
                ArmDebugOsAccess::decode(oslar_or_dbgprcr)
                    .unwrap()
                    .complete(),
                ArmRegisterWrite {
                    register: None,
                    value: 0,
                }
            );
        }
        let read = ArmDebugOsAccess::decode(0x6228_0407).unwrap();
        assert_eq!(
            read.complete(),
            ArmRegisterWrite {
                register: Some(0),
                value: 0,
            }
        );
        for oslsr_or_dbgprcr in [0x6228_0403, 0x6228_0409] {
            assert!(ArmDebugOsAccess::decode(oslsr_or_dbgprcr).is_some());
        }
        let discarded = ArmDebugOsAccess::decode(0x6228_07e7).unwrap();
        assert_eq!(
            discarded.complete(),
            ArmRegisterWrite {
                register: None,
                value: 0,
            }
        );
    }

    /// Only the debug OS registers have no state to lose; another system-register trap or a
    /// data abort must stay undecoded so the vCPU keeps failing loudly.
    #[test]
    fn other_exceptions_are_not_debug_os_accesses() {
        for syndrome in [
            0x6228_0404, // a debug register outside the OS lock set
            0x6238_07e6, // OSDLR_EL1 under op0 = 3
            0x9000_0000, // data abort
            0x5800_0000, // HVC
        ] {
            assert!(
                ArmDebugOsAccess::decode(syndrome).is_none(),
                "{syndrome:#x}"
            );
        }
    }
}
