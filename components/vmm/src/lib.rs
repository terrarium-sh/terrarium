//! Runs vCPUs and handles machine-level exits.

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
    Platform(platform::Error),
}

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

async fn run_vcpu(cpu: platform::Vcpu) -> Result<(), Error> {
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
        };
        wit_bindgen::rt::async_support::yield_async().await;
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
}
