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

async fn run_vcpu(cpu: platform::Vcpu) -> Result<(), Error> {
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
