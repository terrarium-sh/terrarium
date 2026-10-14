//! Regenerates or checks the checked-in seccomp allowlists from per-role binaries.

use std::process::ExitCode;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    use clap::Parser as _;
    match terra_sandbox::generator::run(&terra_sandbox::generator::Options::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("seccomp-policy: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("seccomp-policy: generating Linux seccomp policies requires a Linux host");
    ExitCode::FAILURE
}
