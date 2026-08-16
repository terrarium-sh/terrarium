//! The `terra` binary: everything it does is [`terra::run`].

use std::process::ExitCode;

fn main() -> ExitCode {
    match terra::run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("terra: {e:#}");
            ExitCode::FAILURE
        }
    }
}
