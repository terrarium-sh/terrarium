//! `terra` - launch isolated microVMs for AI agents.
//!
//! Using a box has no verb: `terra [BOX]` starts it, or joins it if it is up.

// unwrap/expect/panic are denied workspace-wide via Cargo.toml; tests opt back in.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod cli;
mod cmd;
pub mod config;
mod logs;
mod name;
mod policy;

#[cfg(feature = "fuzzing")]
pub use policy::network::runtime::BoxPolicy;
mod render;
mod resolve;
mod session;
mod state;
mod sys;
mod vm;

use anyhow::{Context, Result};
use cli::Cmd;
use std::process::ExitCode;

#[must_use]
pub fn is_stdout_broken_pipe(error: &anyhow::Error) -> bool {
    error.downcast_ref::<render::StdoutBrokenPipe>().is_some()
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

    // The background VM process (`terra __vm <dir>`): its parent settled the
    // box, the boot and the project directory, so the child re-resolves nothing
    // - not even its own cwd - and never reaches clap.
    if let Some(dir) = vm::boot::get_vm_process_box_dir() {
        return vm::boot::run_detached_vm(dir, is_at_a_terminal).await;
    }

    let args = cli::parse_or_exit();
    let cwd = std::env::current_dir().context("could not read current directory")?;
    let project_dir = sys::resolve_absolute_path(args.project.as_deref().unwrap_or(&cwd), &cwd)?;
    // The box is the command line's first word for every verb that takes one,
    // so it is read here rather than eight times over.
    let name = args.name.as_deref();
    match &args.cmd {
        None => cmd::start::run(name, &args.boot, &project_dir, &cwd, is_at_a_terminal).await,
        Some(Cmd::Setup(a)) => cmd::setup::run(a, name, &project_dir, &cwd, is_at_a_terminal),
        Some(Cmd::Exec(a)) => cmd::exec::run(a, name, &project_dir, is_at_a_terminal).await,
        Some(Cmd::Sync(a)) => cmd::sync::run(a, name, &project_dir).await,
        Some(Cmd::Stop(a)) => cmd::stop::run(a, name, &project_dir),
        Some(Cmd::Storage(a)) => cmd::storage::run(a, name, &project_dir),
        Some(Cmd::Rm(a)) => cmd::rm::run(a, name, &project_dir),
        Some(Cmd::Show(a)) => cmd::show::run(a, name, &project_dir, &cwd),
        Some(Cmd::Ls(a)) => cmd::ls::run(a, &project_dir),
        Some(Cmd::Logs(a)) => cmd::logs::run(a, name, &project_dir),
        Some(Cmd::Sessions(a)) => cmd::sessions::run(a, name, &project_dir).await,
        Some(Cmd::Detach(a)) => cmd::detach::run(a, name, &project_dir).await,
        Some(Cmd::Completions(a)) => cmd::completions::run(a),
    }
}
