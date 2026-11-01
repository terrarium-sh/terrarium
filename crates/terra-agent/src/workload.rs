//! The guest user a workload runs as, and handing processes and files to it.

use rustix::process::{Gid, Uid};
use terra_protocol::{Plan, WORKLOAD_ID};

const WORKLOAD_UID: Uid = Uid::from_raw_unchecked(WORKLOAD_ID);
const WORKLOAD_GID: Gid = Gid::from_raw_unchecked(WORKLOAD_ID);

/// The account a workload process runs as; the agent itself runs as root.
#[derive(Clone, Copy)]
pub(crate) enum GuestUser {
    Root,
    Workload,
}

impl GuestUser {
    pub(crate) const fn from_plan(plan: &Plan) -> Self {
        if plan.root {
            Self::Root
        } else {
            Self::Workload
        }
    }
}

/// Gives `created`, which the agent made as root, to `user`. Handing it to root changes nothing,
/// and a share refuses a chown to root.
pub(crate) fn hand_over(created: impl std::os::fd::AsFd, user: GuestUser) -> std::io::Result<()> {
    match user {
        GuestUser::Root => Ok(()),
        GuestUser::Workload => Ok(rustix::fs::fchown(
            created,
            Some(WORKLOAD_UID),
            Some(WORKLOAD_GID),
        )?),
    }
}

#[allow(unsafe_code)]
pub(crate) fn run_as(command: &mut std::process::Command, user: GuestUser) {
    use std::os::unix::process::CommandExt as _;

    match user {
        GuestUser::Root => {}
        // SAFETY: a post-fork/pre-exec hook that only calls async-signal-safe
        // id-setting syscalls.
        GuestUser::Workload => unsafe {
            command.pre_exec(drop_privileges);
        },
    }
}

fn drop_privileges() -> std::io::Result<()> {
    rustix::thread::set_thread_groups(&[])?;
    rustix::thread::set_thread_gid(WORKLOAD_GID)?;
    rustix::thread::set_thread_uid(WORKLOAD_UID)?;
    Ok(())
}
