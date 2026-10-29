//! The internal processes terra runs as, one entry point each, so a binary calling only one
//! links only that process's code.

use crate::{exit_code_of, run_with_runtime, sys, vm};
use anyhow::{Context as _, Result};
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::ExitCode;
use terra_sandbox::Role;

const SUPERVISOR_DESCRIPTORS: &[i32] = &[3];
const NETWORK_DESCRIPTORS: &[i32] = if cfg!(target_os = "macos") {
    &[7, 8, 9]
} else {
    &[7, 8]
};
const VM_DESCRIPTORS: &[i32] = if cfg!(target_os = "macos") {
    &[3, 7, 9, 10, 11]
} else {
    &[3, 7, 10, 11]
};

fn prepare_internal_role(role: Role, kept: &[i32]) -> Result<()> {
    sys::restrict_new_files();
    #[cfg(unix)]
    sys::close_unrelated_descriptors(kept)?;
    #[cfg(windows)]
    let _ = kept;
    terra_sandbox::verify_worker_role(role)
}

/// The role entry point named by a process's first argument.
#[must_use]
pub fn from_argument(argument: &OsStr) -> Option<fn() -> ExitCode> {
    if argument == vm::supervisor::SUPERVISOR_ARG {
        Some(supervisor)
    } else if argument == vm::supervisor::NETWORK_ARG {
        Some(network)
    } else if argument == vm::boot::VM_PROCESS_FLAG_ARG {
        Some(vm)
    } else if argument == terra_sandbox::LAUNCHER_WORKER_ARG {
        Some(launcher_worker)
    } else {
        None
    }
}

#[must_use]
pub fn supervisor() -> ExitCode {
    exit_code_of(run_supervisor())
}

#[must_use]
pub fn network() -> ExitCode {
    exit_code_of(run_network())
}

#[must_use]
pub fn vm() -> ExitCode {
    exit_code_of(
        prepare_vm().and_then(|dir| {
            run_with_runtime(vm::boot::run_vm_process(dir, sys::is_at_a_terminal()))
        }),
    )
}

fn launcher_worker() -> ExitCode {
    sys::restrict_new_files();
    exit_code_of(terra_sandbox::run_launcher_worker(
        std::env::args_os().skip(2),
    ))
}

fn run_supervisor() -> Result<ExitCode> {
    prepare_internal_role(Role::Supervisor, SUPERVISOR_DESCRIPTORS)?;
    let dir = std::env::args_os()
        .nth(2)
        .context("missing supervisor box directory")?;
    vm::supervisor::run(dir.into())
}

fn run_network() -> Result<ExitCode> {
    prepare_internal_role(Role::Network, NETWORK_DESCRIPTORS)?;
    terra_sandbox::restrict_role(Role::Network)?;
    vm::supervisor::run_broker()
}

/// Runs before the VM's runtime starts: closing unrelated descriptors afterwards would close
/// the runtime's own.
fn prepare_vm() -> Result<PathBuf> {
    prepare_internal_role(Role::Vm, VM_DESCRIPTORS)?;
    terra_sandbox::restrict_role(Role::Vm)?;
    let dir = std::env::args_os()
        .nth(2)
        .context("missing VM box directory")?;
    Ok(dir.into())
}
