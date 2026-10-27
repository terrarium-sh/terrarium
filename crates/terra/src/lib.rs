//! `terra` - launch isolated microVMs for AI agents.
//!
//! Using a box has no verb: `terra [BOX]` starts it, or joins it if it is up.

// unwrap/expect/panic are denied workspace-wide via Cargo.toml; tests opt back in.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![deny(rustdoc::broken_intra_doc_links)]

mod approval;
pub mod cli;
mod cmd;
#[cfg(test)]
mod doc_tests;
mod logs;
mod name;
mod policy;
mod process;
pub mod recipe;

pub use render::render_error;
#[doc(hidden)]
pub use vm::boot::SETUP_VM_STOPPED_BEFORE_CONSOLE;
mod render;
#[doc(hidden)]
pub mod role;
mod session;
mod state;
mod sys;
mod vm;

use anyhow::{Context, Result};
use cli::Cmd;
use std::process::ExitCode;

/// The process exit code for a command's result: a closed stdout pipe is a quiet success.
#[must_use]
pub fn exit_code_of(result: Result<ExitCode>) -> ExitCode {
    match result {
        Ok(code) => code,
        Err(error) if error.downcast_ref::<render::StdoutBrokenPipe>().is_some() => {
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("terra: {}", render_error(&e));
            ExitCode::FAILURE
        }
    }
}

/// Runs `operation` on the process's tokio runtime, abandoning blocked host operations a second
/// after it finishes.
pub fn run_with_runtime<F, T>(operation: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let result = runtime.block_on(operation);
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
    result
}

/// A guest's or a child's exit status as the byte a process leaves with; wait
/// statuses are already 0-255, so anything else means we never got one.
#[must_use]
pub(crate) fn exit_status_byte(code: i32) -> u8 {
    u8::try_from(code).unwrap_or(1)
}

pub async fn run() -> Result<ExitCode> {
    sys::restrict_new_files();

    let is_at_a_terminal = sys::is_at_a_terminal();

    let args = cli::parse_or_exit();
    let cwd = std::env::current_dir().context("could not read current directory")?;
    let project_dir = sys::resolve_absolute_path(args.project.as_deref().unwrap_or(&cwd), &cwd)?;
    // The box is the command line's first word for every verb that takes one,
    // so it is read here rather than eight times over.
    let name = args.name.as_deref();
    match &args.cmd {
        None => cmd::start::run(name, &args.boot, &project_dir, is_at_a_terminal).await,
        Some(Cmd::Setup(a)) => cmd::setup::run(a, name, &project_dir, &cwd, is_at_a_terminal).await,
        Some(Cmd::Exec(a)) => cmd::exec::run(a, name, &project_dir, is_at_a_terminal).await,
        Some(Cmd::Sync(a)) => cmd::sync::run(a, name, &project_dir).await,
        Some(Cmd::Stop(a)) => cmd::stop::run(a, name, &project_dir),
        Some(Cmd::Storage(a)) => cmd::storage::run(a, name, &project_dir, is_at_a_terminal),
        Some(Cmd::Rm(a)) => cmd::rm::run(a, name, &project_dir),
        Some(Cmd::Show(a)) => cmd::show::run(a, name, &project_dir, &cwd),
        Some(Cmd::Ls(a)) => cmd::ls::run(a, &project_dir),
        Some(Cmd::Logs(a)) => cmd::logs::run(a, name, &project_dir),
        Some(Cmd::Sessions(a)) => cmd::sessions::run(a, name, &project_dir).await,
        Some(Cmd::Detach(a)) => cmd::detach::run(a, name, &project_dir).await,
        Some(Cmd::Completions(a)) => cmd::completions::run(a),
    }
}
