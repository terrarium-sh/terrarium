//! The unprivileged workload user: its IDs, and running processes as it.

use anyhow::Result;
use pty_process::blocking::{Command as PtyCommand, Pty};
use terra_protocol::{TermSize, WORKLOAD_ID};

pub(crate) fn spawn_on_pty(
    cmd: &str,
    args: &[String],
    term: TermSize,
    as_root: bool,
    workdir: Option<&str>,
    env: &std::collections::BTreeMap<String, String>,
) -> Result<(Pty, crate::reap::OwnedPidfd)> {
    let (pty, pts) = pty_process::blocking::open()?;
    let (rows, cols) = crate::term::session::clamp_term_size(term.rows, term.cols);
    pty.resize(pty_process::Size::new(rows, cols))?;
    let mut command = PtyCommand::new(cmd)
        .args(args)
        .env("HOME", terra_protocol::WORKLOAD_HOME);
    if let Some(workdir) = workdir {
        command = command.current_dir(workdir);
    }
    for (key, value) in env {
        command = command.env(key, value);
    }
    if !as_root {
        command = run_pty_command_as_workload(command);
    }
    let (_child, child_pidfd) = crate::reap::spawn_owned(|| command.spawn(pts))?;
    Ok((pty, child_pidfd))
}

pub(crate) fn workload_owner() -> (Option<rustix::process::Uid>, Option<rustix::process::Gid>) {
    (
        Some(rustix::process::Uid::from_raw(WORKLOAD_ID)),
        Some(rustix::process::Gid::from_raw(WORKLOAD_ID)),
    )
}

#[allow(unsafe_code)]
pub(crate) fn run_as_workload(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt as _;

    // SAFETY: a post-fork/pre-exec hook that only calls async-signal-safe
    // id-setting syscalls.
    unsafe {
        command.pre_exec(drop_privileges);
    }
}

#[allow(unsafe_code)]
pub(crate) fn run_pty_command_as_workload(command: PtyCommand) -> PtyCommand {
    // SAFETY: as in `run_as_workload`.
    unsafe { command.pre_exec(drop_privileges) }
}

fn drop_privileges() -> std::io::Result<()> {
    rustix::thread::set_thread_groups(&[])?;
    rustix::thread::set_thread_gid(rustix::process::Gid::from_raw(WORKLOAD_ID))?;
    rustix::thread::set_thread_uid(rustix::process::Uid::from_raw(WORKLOAD_ID))?;
    Ok(())
}
