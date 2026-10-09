//! Runs vCPUs and architecture-specific exit handling.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({ world: "vmm", path: "wit", generate_all });
}

use bindings::{exports, terra};

mod lifecycle;
mod machine;

use terra::vmm::platform;

#[derive(Debug, Eq, PartialEq)]
enum Error {
    InvalidVcpu,
    BadArmExit,
    Platform(platform::Error),
}
const PSCI_CPU_OFF: u64 = 0x8400_0002;
const PSCI_CPU_ON: u64 = 0xc400_0003;
const PSCI_32_CPU_ON: u64 = 0x8400_0003;
const PSCI_AFFINITY_INFO: u64 = 0xc400_0004;
const PSCI_32_AFFINITY_INFO: u64 = 0x8400_0004;
const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
const PSCI_VERSION: u64 = 0x8400_0000;
const PSCI_FEATURES: u64 = 0x8400_000a;
const PSCI_SUCCESS: i64 = 0;
const PSCI_NOT_SUPPORTED: i64 = -1;
const PSCI_INVALID_PARAMETERS: i64 = -2;
const PSCI_DENIED: i64 = -3;
const PSCI_ALREADY_ON: i64 = -4;

const MSRS: [(u32, u64); 12] = [
    (0x10, 0),
    (0x1A0, 0),
    (0x277, 0x0007_0406_0007_0406),
    (0xC000_0080, 0x500),
    (0xC000_0081, 0),
    (0xC000_0082, 0),
    (0xC000_0083, 0),
    (0xC000_0084, 0),
    (0xC000_0100, 0),
    (0xC000_0101, 0),
    (0xC000_0102, 0),
    (0xC000_0103, 0),
];

/// Returns the vCPU's value for an emulated MSR; `None` means the guest gets a fault.
fn msr(msrs: &mut [(u32, u64)], index: u32) -> Option<&mut u64> {
    msrs.iter_mut()
        .find(|(candidate, _)| *candidate == index)
        .map(|(_, value)| value)
}

/// Completes an MMIO exit that loads no guest register.
const NO_ARM_READ: platform::ArmRead = platform::ArmRead {
    register: None,
    value: 0,
};

fn width_mask(width: u8) -> u64 {
    u64::MAX >> (64 - u32::from(width) * 8)
}

fn psci_features(function: u64) -> i64 {
    match function {
        PSCI_VERSION
        | PSCI_FEATURES
        | PSCI_CPU_OFF
        | PSCI_CPU_ON
        | PSCI_32_CPU_ON
        | PSCI_AFFINITY_INFO
        | PSCI_32_AFFINITY_INFO
        | PSCI_SYSTEM_OFF
        | PSCI_SYSTEM_RESET => PSCI_SUCCESS,
        _ => PSCI_NOT_SUPPORTED,
    }
}

fn psci_hvc(id: u8, hvc: Hvc) -> Result<platform::Completion, Error> {
    machine::with_powered_cpus(|powered_cpus| psci_hvc_for(powered_cpus, id, &hvc))?
}

fn psci_hvc_for(
    powered_cpus: &mut [bool],
    id: u8,
    hvc: &Hvc,
) -> Result<platform::Completion, Error> {
    let target = u8::try_from(hvc.argument0)
        .ok()
        .and_then(|target| Some((target, *powered_cpus.get(usize::from(target))?)));
    let status = match hvc.function {
        PSCI_VERSION => 0x0001_0000,
        PSCI_FEATURES => psci_features(hvc.argument0),
        PSCI_AFFINITY_INFO | PSCI_32_AFFINITY_INFO => match target {
            _ if hvc.argument1 != 0 => PSCI_INVALID_PARAMETERS,
            Some((_, powered)) => i64::from(!powered),
            None => PSCI_DENIED,
        },
        PSCI_CPU_ON | PSCI_32_CPU_ON => match target {
            Some((0, _) | (_, true)) => PSCI_ALREADY_ON,
            Some((target, false)) => {
                return Ok(platform::Completion::CpuStart(platform::CpuStart {
                    target,
                    entry: hvc.argument1,
                    context: hvc.argument2,
                }));
            }
            None => PSCI_DENIED,
        },
        PSCI_CPU_OFF => {
            *powered_cpus
                .get_mut(usize::from(id))
                .ok_or(Error::InvalidVcpu)? = false;
            return Ok(platform::Completion::CpuOff);
        }
        PSCI_SYSTEM_OFF | PSCI_SYSTEM_RESET => return Ok(platform::Completion::SystemStop),
        _ => PSCI_NOT_SUPPORTED,
    };
    Ok(platform::Completion::HvcReturn(status))
}

fn psci_start_result(result: platform::HvcResult) -> Result<platform::Completion, Error> {
    machine::with_powered_cpus(|powered_cpus| psci_start_result_for(powered_cpus, result))?
}

fn psci_start_result_for(
    powered_cpus: &mut [bool],
    result: platform::HvcResult,
) -> Result<platform::Completion, Error> {
    if result.status == PSCI_SUCCESS {
        *powered_cpus
            .get_mut(usize::from(result.target))
            .ok_or(Error::InvalidVcpu)? = true;
    }
    Ok(platform::Completion::HvcReturn(result.status))
}

async fn vcpu_access(address: u64, width: u8, value: u64, write: bool) -> u64 {
    terra::vmm::vmm_mmio_client::access(address, width, value, write).await
}

#[derive(Clone, Copy)]
struct Hvc {
    function: u64,
    argument0: u64,
    argument1: u64,
    argument2: u64,
}

async fn handle_arm_exception(
    id: u8,
    request: platform::ArmException,
) -> Result<platform::Completion, Error> {
    const HVC64: u64 = 0x16;
    if request.syndrome >> 26 == HVC64 {
        let (function, argument0, argument1, argument2) =
            request.hvc_registers.ok_or(Error::BadArmExit)?;
        let hvc = Hvc {
            function,
            argument0,
            argument1,
            argument2,
        };
        return psci_hvc(id, hvc);
    }
    let fields = arm_mmio_fields(request.syndrome)?;
    let value = if fields.write {
        request.write_value.ok_or(Error::BadArmExit)? & width_mask(fields.width)
    } else {
        0
    };
    let value = vcpu_access(request.address, fields.width, value, fields.write).await;
    let read = if fields.write || fields.register == 31 {
        NO_ARM_READ
    } else {
        platform::ArmRead {
            register: Some(fields.register),
            value: arm_load_value(value, fields.width, fields.sign_extend, fields.sf),
        }
    };
    Ok(platform::Completion::ArmRead(read))
}

async fn run_vcpu(cpu: platform::Vcpu, id: u8) -> Result<(), Error> {
    let mut msrs = MSRS;
    let mut completion = platform::Completion::Start;
    loop {
        let exit = match cpu.resume(completion).await {
            Ok(exit) => exit,
            Err(platform::Error::Cancelled) => return Ok(()),
            Err(error @ (platform::Error::Unavailable | platform::Error::BadExit)) => {
                return Err(Error::Platform(error));
            }
        };
        completion = match exit {
            platform::Exit::Halt | platform::Exit::Interrupted | platform::Exit::PioWrite(_) => {
                platform::Completion::Reenter
            }
            platform::Exit::Shutdown | platform::Exit::Stopped => return Ok(()),
            platform::Exit::MmioRead(request) => platform::Completion::MmioRead(
                vcpu_access(request.address, request.width, 0, false).await,
            ),
            platform::Exit::MmioWrite(request) => {
                vcpu_access(request.address, request.width, request.value, true).await;
                platform::Completion::Reenter
            }
            platform::Exit::PioRead(_) => platform::Completion::PioZero,
            platform::Exit::Rdmsr(request) => msr(&mut msrs, request.index)
                .map_or(platform::Completion::MsrFault, |value| {
                    platform::Completion::Rdmsr(*value)
                }),
            platform::Exit::Wrmsr(request) => {
                msr(&mut msrs, request.index).map_or(platform::Completion::MsrFault, |value| {
                    *value = request.value;
                    platform::Completion::Wrmsr
                })
            }
            platform::Exit::ArmException(request) => {
                match handle_arm_exception(id, request).await {
                    Ok(completion) => completion,
                    Err(Error::BadArmExit) => platform::Completion::ArmRead(NO_ARM_READ),
                    Err(error) => return Err(error),
                }
            }
            platform::Exit::HvcResult(result) => psci_start_result(result)?,
        };
        wit_bindgen::rt::async_support::yield_async().await;
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ArmMmioFields {
    width: u8,
    register: u8,
    write: bool,
    sign_extend: bool,
    sf: bool,
}

fn arm_mmio_fields(syndrome: u64) -> Result<ArmMmioFields, Error> {
    const EC: u64 = 0b11_1111 << 26;
    const DATA_ABORT_LOWER: u64 = 0x24 << 26;
    const DATA_ABORT_SAME: u64 = 0x25 << 26;
    const ISV: u64 = 1 << 24;
    const SAS: u64 = 0b11 << 22;
    const SSE: u64 = 1 << 21;
    const SRT: u64 = 0b1_1111 << 16;
    const SF: u64 = 1 << 15;
    const WNR: u64 = 1 << 6;

    if !matches!(syndrome & EC, DATA_ABORT_LOWER | DATA_ABORT_SAME) || syndrome & ISV == 0 {
        return Err(Error::BadArmExit);
    }
    let width = 1_u8 << u8::try_from((syndrome & SAS) >> 22).map_err(|_| Error::BadArmExit)?;
    let register = u8::try_from((syndrome & SRT) >> 16).map_err(|_| Error::BadArmExit)?;
    let write = syndrome & WNR != 0;
    let sf = syndrome & SF != 0;
    if !sf && width == 8 {
        return Err(Error::BadArmExit);
    }
    Ok(ArmMmioFields {
        width,
        register,
        write,
        sign_extend: syndrome & SSE != 0,
        sf,
    })
}

fn arm_load_value(value: u64, width: u8, sign_extend: bool, sf: bool) -> u64 {
    let value = value & width_mask(width);
    let value = if sign_extend {
        let shift = 64 - u32::from(width) * 8;
        ((value << shift).cast_signed() >> shift).cast_unsigned()
    } else {
        value
    };
    if sf {
        value
    } else {
        value & u64::from(u32::MAX)
    }
}

struct Dispatcher;

#[allow(unsafe_code)]
mod component_exports {
    use super::{Dispatcher, bindings};
    bindings::export!(Dispatcher with_types_in bindings);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msr_banks_are_fixed_and_independent() {
        let mut first = MSRS;
        let mut second = MSRS;
        assert_eq!(msr(&mut first, 0x277).copied(), Some(0x0007_0406_0007_0406));
        *msr(&mut first, 0xC000_0103).unwrap() = 7;
        assert_eq!(msr(&mut first, 0xC000_0103).copied(), Some(7));
        assert_eq!(msr(&mut second, 0xC000_0103).copied(), Some(0));
        assert_eq!(msr(&mut first, 0), None);
    }

    #[test]
    fn arm_loads_follow_the_destination_register_width() {
        assert_eq!(arm_load_value(0x80, 1, true, true), u64::MAX - 0x7f);
        assert_eq!(
            arm_load_value(0x80, 1, true, false),
            u64::from(u32::MAX - 0x7f)
        );
        assert_eq!(
            arm_load_value(0x1234_5678_9abc_def0, 4, false, false),
            0x9abc_def0
        );
    }

    #[test]
    fn arm_syndrome_requires_a_valid_data_abort() {
        const EC: u64 = 0x24 << 26;
        const ISV: u64 = 1 << 24;
        const SF: u64 = 1 << 15;
        const WNR: u64 = 1 << 6;
        let read = EC | ISV | SF | (4 << 16);
        assert_eq!(
            arm_mmio_fields(read),
            Ok(ArmMmioFields {
                width: 1,
                register: 4,
                write: false,
                sign_extend: false,
                sf: true,
            })
        );
        assert_eq!(
            arm_mmio_fields(read | WNR),
            Ok(ArmMmioFields {
                width: 1,
                register: 4,
                write: true,
                sign_extend: false,
                sf: true,
            })
        );
        assert_eq!(arm_mmio_fields(EC | SF), Err(Error::BadArmExit));
        assert_eq!(arm_mmio_fields(ISV | SF), Err(Error::BadArmExit));
        assert_eq!(
            arm_mmio_fields(EC | ISV | (3 << 22)),
            Err(Error::BadArmExit)
        );
        assert_eq!(
            arm_mmio_fields(EC | ISV | (3 << 22) | WNR),
            Err(Error::BadArmExit)
        );
    }

    #[test]
    fn psci_updates_cpu_state_only_after_native_start_succeeds() {
        let mut router = vec![true, false];
        let start = psci_hvc_for(
            &mut router,
            0,
            &Hvc {
                function: PSCI_CPU_ON,
                argument0: 1,
                argument1: 0x8000,
                argument2: 7,
            },
        )
        .expect("PSCI CPU on");
        let platform::Completion::CpuStart(start) = start else {
            panic!("expected CPU start");
        };
        assert_eq!((start.target, start.entry, start.context), (1, 0x8000, 7));
        assert!(!router[1]);
        assert!(matches!(
            psci_start_result_for(
                &mut router,
                platform::HvcResult {
                    target: 1,
                    status: -3,
                },
            ),
            Ok(platform::Completion::HvcReturn(-3))
        ));
        assert!(!router[1]);
        assert!(matches!(
            psci_start_result_for(
                &mut router,
                platform::HvcResult {
                    target: 1,
                    status: 0,
                },
            ),
            Ok(platform::Completion::HvcReturn(0))
        ));
        assert!(router[1]);
    }

    #[test]
    fn psci_rejects_an_invalid_cpu_without_failing_the_router() {
        let mut router = vec![true];
        let completion = psci_hvc_for(
            &mut router,
            0,
            &Hvc {
                function: PSCI_CPU_ON,
                argument0: 1,
                argument1: 0x8000,
                argument2: 0,
            },
        );
        assert!(matches!(
            completion,
            Ok(platform::Completion::HvcReturn(-3))
        ));
    }
}
