//! Runs vCPUs and architecture-specific exit handling.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({ world: "vmm", path: "wit", generate_all });
}

use bindings::{exports, terra};

mod lifecycle;
mod machine;

use std::sync::{LazyLock, Mutex};

use terra::mmio::platform;
use terra::mmio::types::Error;

const MAX_VCPUS: usize = terra_limits::MAX_VCPUS as usize;
const PSCI_CPU_OFF: u64 = 0x8400_0002;
const PSCI_CPU_ON: u64 = 0xc400_0003;
const PSCI_32_CPU_ON: u64 = 0x8400_0003;
const PSCI_AFFINITY_INFO: u64 = 0xc400_0004;
const PSCI_32_AFFINITY_INFO: u64 = 0x8400_0004;
const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
const PSCI_VERSION: u64 = 0x8400_0000;
const PSCI_FEATURES: u64 = 0x8400_000a;

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

#[derive(Clone)]
struct MsrBank {
    values: [u64; 12],
}

impl MsrBank {
    fn new() -> Self {
        Self {
            values: MSRS.map(|(_, default)| default),
        }
    }

    fn slot(index: u32) -> Result<usize, Error> {
        MSRS.iter()
            .position(|(candidate, _)| *candidate == index)
            .ok_or(Error::UnsupportedMsr)
    }

    fn read(&self, index: u32) -> Result<u64, Error> {
        Ok(self.values[Self::slot(index)?])
    }

    fn write(&mut self, index: u32, value: u64) -> Result<(), Error> {
        self.values[Self::slot(index)?] = value;
        Ok(())
    }
}

#[derive(Default)]
struct CpuState {
    vcpus: Option<Vec<Vcpu>>,
    started: bool,
}

#[derive(Clone)]
struct Vcpu {
    msrs: MsrBank,
    powered: bool,
}

static CPU_STATE: LazyLock<Mutex<CpuState>> = LazyLock::new(|| Mutex::new(CpuState::default()));

fn cpu_state() -> std::sync::MutexGuard<'static, CpuState> {
    CPU_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn vcpu_bank(state: &mut CpuState, vcpu: u8) -> Result<&mut MsrBank, Error> {
    state
        .vcpus
        .as_mut()
        .and_then(|vcpus| vcpus.get_mut(usize::from(vcpu)))
        .map(|vcpu| &mut vcpu.msrs)
        .ok_or(Error::InvalidVcpu)
}

fn start_vcpu(state: &mut CpuState, vcpu: u8) -> Result<(), Error> {
    vcpu_bank(state, vcpu)?;
    state.started = true;
    Ok(())
}

fn powered(state: &mut CpuState, vcpu: u8) -> Result<&mut bool, Error> {
    state
        .vcpus
        .as_mut()
        .and_then(|vcpus| vcpus.get_mut(usize::from(vcpu)))
        .map(|vcpu| &mut vcpu.powered)
        .ok_or(Error::InvalidVcpu)
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
        | PSCI_SYSTEM_RESET => 0,
        _ => -1,
    }
}

fn psci_hvc(id: u8, hvc: Hvc) -> Result<platform::Completion, Error> {
    let mut state = cpu_state();
    psci_hvc_for(&mut state, id, &hvc)
}

fn psci_hvc_for(state: &mut CpuState, id: u8, hvc: &Hvc) -> Result<platform::Completion, Error> {
    let status = match hvc.function {
        PSCI_VERSION => return Ok(platform::Completion::HvcReturn(0x0001_0000)),
        PSCI_FEATURES => {
            return Ok(platform::Completion::HvcReturn(psci_features(
                hvc.argument0,
            )));
        }
        PSCI_AFFINITY_INFO | PSCI_32_AFFINITY_INFO => {
            if hvc.argument1 != 0 {
                -2
            } else {
                let Ok(target) = u8::try_from(hvc.argument0) else {
                    return Ok(platform::Completion::HvcReturn(-3));
                };
                let Some(powered) = state
                    .vcpus
                    .as_mut()
                    .and_then(|vcpus| vcpus.get_mut(usize::from(target)))
                    .map(|vcpu| &mut vcpu.powered)
                else {
                    return Ok(platform::Completion::HvcReturn(-3));
                };
                i64::from(!*powered)
            }
        }
        PSCI_CPU_ON | PSCI_32_CPU_ON => {
            let Ok(target) = u8::try_from(hvc.argument0) else {
                return Ok(platform::Completion::HvcReturn(-3));
            };
            let Some(powered) = state
                .vcpus
                .as_mut()
                .and_then(|vcpus| vcpus.get_mut(usize::from(target)))
                .map(|vcpu| &mut vcpu.powered)
            else {
                return Ok(platform::Completion::HvcReturn(-3));
            };
            if target == 0 || *powered {
                -4
            } else {
                return Ok(platform::Completion::CpuStart(platform::CpuStart {
                    target,
                    entry: hvc.argument1,
                    context: hvc.argument2,
                }));
            }
        }
        PSCI_CPU_OFF => {
            *powered(state, id)? = false;
            return Ok(platform::Completion::CpuOff);
        }
        PSCI_SYSTEM_OFF | PSCI_SYSTEM_RESET => return Ok(platform::Completion::SystemStop),
        _ => -1,
    };
    Ok(platform::Completion::HvcReturn(status))
}

fn psci_start_result(result: platform::HvcResult) -> Result<platform::Completion, Error> {
    let mut state = cpu_state();
    psci_start_result_for(&mut state, result)
}

fn psci_start_result_for(
    state: &mut CpuState,
    result: platform::HvcResult,
) -> Result<platform::Completion, Error> {
    if result.status == 0 {
        *powered(state, result.target)? = true;
    }
    Ok(platform::Completion::HvcReturn(result.status))
}

async fn vcpu_access(address: u64, width: u8, value: u64, write: bool) -> Result<u64, Error> {
    match terra::mmio::vmm_mmio_client::access(address, width, value, write).await {
        Ok(value) => Ok(value),
        Err(Error::Unmapped | Error::BadWidth | Error::Overflow) => Ok(0),
        Err(
            error @ (Error::InvalidSlot
            | Error::InvalidVcpu
            | Error::UnsupportedMsr
            | Error::BadArmExit
            | Error::Overlap
            | Error::Busy
            | Error::Closed
            | Error::Device),
        ) => Err(error),
    }
}

#[derive(Clone, Copy)]
struct Hvc {
    function: u64,
    argument0: u64,
    argument1: u64,
    argument2: u64,
}

async fn read_arm_register(cpu: &platform::Vcpu, register: u8) -> Result<u64, Error> {
    if register == 31 {
        return Ok(0);
    }
    match cpu
        .resume(platform::Completion::ArmRegister(register))
        .await
    {
        Ok(platform::Exit::ArmRegisterValue(value)) => Ok(value),
        Ok(platform::Exit::Stopped) | Err(platform::Error::Cancelled) => Err(Error::Closed),
        Ok(
            platform::Exit::Halt
            | platform::Exit::Shutdown
            | platform::Exit::Interrupted
            | platform::Exit::MmioRead(_)
            | platform::Exit::MmioWrite(_)
            | platform::Exit::PioRead(_)
            | platform::Exit::PioWrite(_)
            | platform::Exit::Rdmsr(_)
            | platform::Exit::Wrmsr(_)
            | platform::Exit::ArmException(_)
            | platform::Exit::HvcResult(_),
        )
        | Err(platform::Error::Unavailable | platform::Error::BadExit) => Err(Error::BadArmExit),
    }
}

async fn handle_arm_exception(
    cpu: &platform::Vcpu,
    id: u8,
    request: platform::ArmException,
) -> Result<platform::Completion, Error> {
    const HVC64: u64 = 0x16;
    if request.syndrome >> 26 == HVC64 {
        let hvc = Hvc {
            function: read_arm_register(cpu, 0).await?,
            argument0: read_arm_register(cpu, 1).await?,
            argument1: read_arm_register(cpu, 2).await?,
            argument2: read_arm_register(cpu, 3).await?,
        };
        return psci_hvc(id, hvc);
    }
    let fields = arm_mmio_fields(request.syndrome)?;
    let value = if fields.write {
        read_arm_register(cpu, fields.register).await?
            & (u64::MAX >> (64 - u32::from(fields.width) * 8))
    } else {
        0
    };
    let value = vcpu_access(request.address, fields.width, value, fields.write).await?;
    let read = if fields.write || fields.register == 31 {
        platform::ArmRead {
            register: None,
            value: 0,
        }
    } else {
        platform::ArmRead {
            register: Some(fields.register),
            value: arm_load_value(value, fields.width, fields.sign_extend, fields.sf),
        }
    };
    Ok(platform::Completion::ArmRead(read))
}

async fn run_vcpu(cpu: platform::Vcpu, id: u8) -> Result<(), Error> {
    {
        let mut state = cpu_state();
        start_vcpu(&mut state, id)?;
    }
    let mut completion = platform::Completion::Start;
    loop {
        let exit = match cpu.resume(completion).await {
            Ok(exit) => exit,
            Err(platform::Error::Cancelled) => return Ok(()),
            Err(platform::Error::Unavailable | platform::Error::BadExit) => {
                return Err(Error::Device);
            }
        };
        completion = match exit {
            platform::Exit::Halt | platform::Exit::Interrupted | platform::Exit::PioWrite(_) => {
                platform::Completion::Reenter
            }
            platform::Exit::Shutdown | platform::Exit::Stopped => return Ok(()),
            platform::Exit::MmioRead(request) => platform::Completion::MmioRead(
                vcpu_access(request.address, request.width, 0, false).await?,
            ),
            platform::Exit::MmioWrite(request) => {
                vcpu_access(request.address, request.width, request.value, true).await?;
                platform::Completion::Reenter
            }
            platform::Exit::PioRead(_) => platform::Completion::PioZero,
            platform::Exit::Rdmsr(request) => {
                let mut state = cpu_state();
                match vcpu_bank(&mut state, id)?.read(request.index) {
                    Ok(value) => platform::Completion::Rdmsr(value),
                    Err(Error::UnsupportedMsr) => platform::Completion::MsrFault,
                    Err(error) => return Err(error),
                }
            }
            platform::Exit::Wrmsr(request) => {
                let mut state = cpu_state();
                match vcpu_bank(&mut state, id)?.write(request.index, request.value) {
                    Ok(()) => platform::Completion::Wrmsr,
                    Err(Error::UnsupportedMsr) => platform::Completion::MsrFault,
                    Err(error) => return Err(error),
                }
            }
            platform::Exit::ArmException(request) => {
                match handle_arm_exception(&cpu, id, request).await {
                    Ok(completion) => completion,
                    Err(Error::Closed) => return Ok(()),
                    Err(Error::BadArmExit) => platform::Completion::ArmRead(platform::ArmRead {
                        register: None,
                        value: 0,
                    }),
                    Err(error) => return Err(error),
                }
            }
            platform::Exit::ArmRegisterValue(_) => return Err(Error::BadArmExit),
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
    let bits = u32::from(width) * 8;
    let value = value & (u64::MAX >> (64 - bits));
    let value = if sign_extend {
        let shift = 64 - bits;
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

pub fn configure_vcpus(count: u8) -> Result<(), Error> {
    let count = usize::from(count);
    if count == 0 || count > MAX_VCPUS {
        return Err(Error::InvalidVcpu);
    }
    let mut state = cpu_state();
    if state.started || state.vcpus.is_some() {
        return Err(Error::Busy);
    }
    let mut vcpus = vec![
        Vcpu {
            msrs: MsrBank::new(),
            powered: false
        };
        count
    ];
    vcpus[0].powered = true;
    state.vcpus = Some(vcpus);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msr_banks_are_fixed_and_independent() {
        let mut first = MsrBank::new();
        let second = MsrBank::new();
        assert_eq!(first.read(0x277), Ok(0x0007_0406_0007_0406));
        assert_eq!(first.write(0xC000_0103, 7), Ok(()));
        assert_eq!(first.read(0xC000_0103), Ok(7));
        assert_eq!(second.read(0xC000_0103), Ok(0));
        assert_eq!(first.read(0), Err(Error::UnsupportedMsr));
        assert_eq!(first.write(0, 1), Err(Error::UnsupportedMsr));
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
        let mut router = CpuState {
            vcpus: Some(vec![
                Vcpu {
                    msrs: MsrBank::new(),
                    powered: true,
                },
                Vcpu {
                    msrs: MsrBank::new(),
                    powered: false,
                },
            ]),
            started: true,
        };
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
        assert!(!router.vcpus.as_ref().expect("CPU state")[1].powered);
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
        assert!(!router.vcpus.as_ref().expect("CPU state")[1].powered);
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
        assert!(router.vcpus.as_ref().expect("CPU state")[1].powered);
    }

    #[test]
    fn psci_rejects_an_invalid_cpu_without_failing_the_router() {
        let mut router = CpuState {
            vcpus: Some(vec![Vcpu {
                msrs: MsrBank::new(),
                powered: true,
            }]),
            started: true,
        };
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
