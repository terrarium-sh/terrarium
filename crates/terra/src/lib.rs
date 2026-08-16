//! `terra` - launch isolated microVMs for AI agents via libkrun.
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
mod render;
mod resolve;
mod session;
mod state;
mod sys;
mod vm;

use anyhow::{Context, Result};
use cli::Cmd;
use cmd::put_get::Direction;
use std::process::ExitCode;

/// A guest's or a child's exit status as the byte a process leaves with; wait
/// statuses are already 0-255, so anything else means we never got one.
pub(crate) fn exit_status_byte(code: i32) -> u8 {
    u8::try_from(code).unwrap_or(1)
}

/// A guest's or a child's exit status as this process's own.
pub(crate) fn exit_code(code: i32) -> ExitCode {
    ExitCode::from(exit_status_byte(code))
}

pub fn run() -> Result<ExitCode> {
    sys::restrict_new_files();
    sys::scrub_smolvm_gateway_env();

    let at_a_terminal = sys::at_a_terminal();

    // The background VM process (`terra __vm <dir>`): its parent settled the
    // box, the boot and the project directory, so the child re-resolves nothing
    // - not even its own cwd - and never reaches clap.
    if let Some(dir) = vm::boot::get_vm_process_box_dir() {
        return vm::boot::run_detached_vm(dir, at_a_terminal);
    }

    let cli = cli::parse_or_exit();
    let cwd = std::env::current_dir().context("could not read current directory")?;
    let project_dir = sys::absolute(cli.project.as_deref().unwrap_or(&cwd), &cwd)?;
    // The box is the command line's first word for every verb that takes one,
    // so it is read here rather than eight times over.
    let name = cli.name.as_deref();
    match &cli.cmd {
        None => cmd::start::run(name, &cli.boot, &project_dir, at_a_terminal),
        Some(Cmd::Setup(a)) => cmd::setup::run(a, name, &project_dir, &cwd, at_a_terminal),
        Some(Cmd::Exec(a)) => cmd::exec::run(a, name, &project_dir, at_a_terminal),
        Some(Cmd::Put(a)) => cmd::put_get::run(a, Direction::IntoBox, name, &project_dir),
        Some(Cmd::Get(a)) => cmd::put_get::run(a, Direction::OutOfBox, name, &project_dir),
        Some(Cmd::Stop(a)) => cmd::stop::run(a, name, &project_dir),
        Some(Cmd::Storage(a)) => cmd::storage::run(a, name, &project_dir),
        Some(Cmd::Rm(a)) => cmd::rm::run(a, name, &project_dir),
        Some(Cmd::Show(a)) => cmd::show::run(a, name, &project_dir, &cwd),
        Some(Cmd::Ls(a)) => cmd::ls::run(a, &project_dir),
        Some(Cmd::Logs(a)) => cmd::logs::run(a, name, &project_dir),
    }
}
