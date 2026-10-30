//! Linux command confinement.

mod builtin_policy;
mod bwrap;
#[cfg(feature = "generator")]
pub mod generator;
mod seccomp;

pub use bwrap::{Confinement, prepare_launch};
pub use seccomp::restrict_role;

use super::{Access, Grant, Role};
use anyhow::Result;
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

pub type Resources = ();

pub(super) fn role_grants(role: Role) -> Vec<Grant> {
    let paths: &[&str] = match role {
        Role::Supervisor => &[],
        Role::Vm => &["/dev/kvm", "/etc/localtime"],
        Role::Network => &["/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"],
    };
    paths
        .iter()
        .filter(|path| Path::new(path).exists())
        .map(|&path| {
            let access = if path == "/dev/kvm" {
                Access::Device
            } else {
                Access::ReadOnly
            };
            Grant::new(path, access)
        })
        .collect()
}

/// `restrict_role` trusts Bubblewrap to have installed a worker's role filter.
pub(super) fn verify_confinement(_role: Role) -> Result<()> {
    anyhow::ensure!(
        rustix::thread::secure_computing_mode()? == rustix::thread::SecureComputingMode::Filter,
        "Linux sandbox worker runs without its seccomp role filter"
    );
    Ok(())
}

pub fn run_launcher_worker(arguments: impl Iterator<Item = OsString>) -> Result<ExitCode> {
    anyhow::ensure!(
        arguments.eq([OsString::from("--version")]),
        "terra {} accepts only --version",
        super::LAUNCHER_WORKER_ARG
    );
    let status = bwrap::embedded_command()?.arg("--version").status()?;
    Ok(ExitCode::from(
        u8::try_from(status.code().unwrap_or(1)).unwrap_or(1),
    ))
}
