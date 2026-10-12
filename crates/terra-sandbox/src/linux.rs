//! Linux command confinement.

mod builtin_policy;
mod bwrap;
pub mod seccomp;

pub use bwrap::{Confinement, prepare_launch};
pub use seccomp::{install_policy, resolve_policy};

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

pub fn verify_worker_role(_role: Role) -> Result<()> {
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
