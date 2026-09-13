//! The `terra` binary: everything it does is [`terra::run`].

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match terra::run().await {
        Ok(code) => code,
        Err(error) if terra::is_stdout_broken_pipe(&error) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("terra: {e:#}");
            ExitCode::FAILURE
        }
    }
}
