//! `terra` - launch isolated microVMs for AI agents.
//!
//! Using a box has no verb: `terra [BOX]` starts it, or joins it if it is up.

// unwrap/expect/panic are denied workspace-wide via Cargo.toml; tests opt back in.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod cli;
mod cmd;
pub mod config;
#[cfg(test)]
mod doc_tests;
mod logs;
mod name;
mod policy;
mod process;

pub use render::render_error;
mod render;
mod resolve;
mod sandbox;
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

const WORKER_DESCRIPTORS: &[i32] = if cfg!(target_os = "macos") {
    &[3, 7, 9, 10, 11]
} else {
    &[3, 7]
};
const SELF_TEST_DESCRIPTORS: &[i32] = if cfg!(target_os = "macos") {
    &[3, 7, 9, 10, 11, 12, 13]
} else {
    &[3, 7]
};
const BROKER_DESCRIPTORS: &[i32] = if cfg!(target_os = "macos") {
    &[7, 8, 9]
} else {
    &[7, 8]
};
const PROBE_DESCRIPTORS: &[i32] = if cfg!(target_os = "macos") { &[9] } else { &[] };

#[must_use]
pub fn run_internal_role() -> Option<Result<ExitCode>> {
    let entrypoint = std::env::args_os().nth(1)?;
    sys::restrict_new_files();
    if entrypoint == sandbox::policy::WORKER_ARG {
        return Some(sandbox::policy::run_worker(
            &mut std::env::args_os().skip(2),
        ));
    }
    if entrypoint == terra_sandbox::LAUNCHER_WORKER_ARG {
        return Some(terra_sandbox::run_launcher_worker(
            std::env::args_os().skip(2),
        ));
    }
    if entrypoint == vm::supervisor::NETWORK_ARG {
        return Some(
            prepare_internal_role(terra_sandbox::Role::Network, BROKER_DESCRIPTORS)
                .and_then(|()| vm::supervisor::run_broker()),
        );
    }
    if entrypoint == vm::supervisor::SUPERVISOR_ARG {
        return Some(
            prepare_internal_role(terra_sandbox::Role::Supervisor, &[3]).and_then(|()| {
                let dir = std::env::args_os()
                    .nth(2)
                    .context("missing supervisor box directory")?;
                vm::supervisor::run(dir.into())
            }),
        );
    }
    if entrypoint == vm::boot::VM_PROCESS_FLAG_ARG
        && let Err(error) = prepare_internal_role(terra_sandbox::Role::Vm, WORKER_DESCRIPTORS)
    {
        return Some(Err(error));
    }
    if entrypoint == vm::supervisor::VM_SELF_TEST_ARG
        && let Err(error) = prepare_internal_role(terra_sandbox::Role::Vm, SELF_TEST_DESCRIPTORS)
    {
        return Some(Err(error));
    }
    if entrypoint == vm::supervisor::VM_NATIVE_PROBE_ARG {
        return Some(
            prepare_internal_role(terra_sandbox::Role::Vm, PROBE_DESCRIPTORS).and_then(|()| {
                vm::supervisor::run_vm_native_probe(
                    std::env::args()
                        .nth(2)
                        .context("missing native probe endpoint")?
                        .parse()?,
                )
            }),
        );
    }
    if entrypoint == vm::supervisor::NETWORK_NATIVE_PROBE_ARG {
        return Some(
            prepare_internal_role(terra_sandbox::Role::Network, PROBE_DESCRIPTORS).and_then(|()| {
                vm::supervisor::run_network_native_probe_worker(std::path::Path::new(
                    &std::env::args_os()
                        .nth(2)
                        .context("missing broker probe sentinel")?,
                ))
            }),
        );
    }
    None
}

fn prepare_internal_role(role: terra_sandbox::Role, kept: &[i32]) -> Result<()> {
    #[cfg(unix)]
    sys::close_unrelated_descriptors(kept)?;
    #[cfg(windows)]
    let _ = kept;
    terra_sandbox::verify_worker_role(role)
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
    if std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == vm::supervisor::VM_SELF_TEST_ARG)
    {
        let directory = std::env::args_os()
            .nth(2)
            .context("missing self-test worker directory")?;
        let ports = std::env::args()
            .skip(3)
            .map(|argument| argument.parse::<u16>())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let endpoints: [u16; 3] = ports
            .try_into()
            .map_err(|_| anyhow::anyhow!("self-test worker requires three ports"))?;
        return vm::run_host_self_test_worker(directory.into(), endpoints).await;
    }

    if std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == sandbox::policy::WORKER_ARG)
    {
        return sandbox::policy::run_worker(&mut std::env::args_os().skip(2));
    }

    if std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == terra_sandbox::LAUNCHER_WORKER_ARG)
    {
        return terra_sandbox::run_launcher_worker(std::env::args_os().skip(2));
    }

    // The background VM process (`terra __vm <dir>`): its parent settled the
    // box, the boot and the project directory, so the child re-resolves nothing
    // - not even its own cwd - and never reaches clap.
    if let Some(dir) = vm::boot::get_vm_process_box_dir() {
        return vm::boot::run_vm_process(dir, is_at_a_terminal).await;
    }

    let args = cli::parse_or_exit();
    let cwd = std::env::current_dir().context("could not read current directory")?;
    let project_dir = sys::resolve_absolute_path(args.project.as_deref().unwrap_or(&cwd), &cwd)?;
    // The box is the command line's first word for every verb that takes one,
    // so it is read here rather than eight times over.
    let name = args.name.as_deref();
    match &args.cmd {
        None => cmd::start::run(name, &args.boot, &project_dir, &cwd, is_at_a_terminal).await,
        Some(Cmd::Setup(a)) => cmd::setup::run(a, name, &project_dir, &cwd, is_at_a_terminal).await,
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
        Some(Cmd::SelfTest(a)) => cmd::self_test::run(a, &project_dir).await,
    }
}
