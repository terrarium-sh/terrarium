//! ARM PSCI calls for hypervisors that exit to userspace on HVC.

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
    let target = u8::try_from(call.argument0)
        .ok()
        .and_then(|target| Some((usize::from(target), *powered_cpus.get(usize::from(target))?)));
    let status = match call.function {
        VERSION => VERSION_1_0,
        FEATURES => features(call.argument0),
        AFFINITY_INFO | AFFINITY_INFO_32 => match target {
            _ if call.argument1 != 0 => INVALID_PARAMETERS,
            Some((_, is_powered)) => i64::from(!is_powered),
            None => DENIED,
        },
        CPU_ON | CPU_ON_32 => match target {
            Some((0, _) | (_, true)) => ALREADY_ON,
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
        VERSION | FEATURES | CPU_OFF | CPU_ON | CPU_ON_32 | AFFINITY_INFO | AFFINITY_INFO_32
        | SYSTEM_OFF | SYSTEM_RESET => SUCCESS,
        _ => NOT_SUPPORTED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(function: u64, argument0: u64, argument1: u64, argument2: u64) -> PsciCall {
        PsciCall::from_registers([function, argument0, argument1, argument2])
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
            decide(call(CPU_ON, 0, 0x8000, 0), &[false, false], never),
            PsciAction::Return(ALREADY_ON)
        );
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
