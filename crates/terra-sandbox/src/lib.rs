//! Native host confinement for an explicitly granted command.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use anyhow::{Context as _, Result};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as backend;
#[cfg(target_os = "linux")]
pub use linux::seccomp;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as backend;
#[cfg(all(test, not(target_os = "macos")))]
#[path = "macos/policy.rs"]
mod macos_policy_tests;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as backend;

pub use backend::{install_policy, resolve_policy, run_launcher_worker, verify_worker_role};

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Supervisor,
    Vm,
    Network,
}

impl Role {
    pub const ALL: [Self; 3] = [Self::Supervisor, Self::Vm, Self::Network];
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Supervisor => "supervisor",
            Self::Vm => "vm",
            Self::Network => "network",
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyBundle {
    pub supervisor: Vec<u8>,
    pub vm: Vec<u8>,
    pub network: Vec<u8>,
}

impl PolicyBundle {
    fn try_from_roles(mut policy: impl FnMut(Role) -> Result<Vec<u8>>) -> Result<Self> {
        Ok(Self {
            supervisor: policy(Role::Supervisor)?,
            vm: policy(Role::Vm)?,
            network: policy(Role::Network)?,
        })
    }

    #[must_use]
    pub fn get(&self, role: Role) -> &[u8] {
        match role {
            Role::Supervisor => &self.supervisor,
            Role::Vm => &self.vm,
            Role::Network => &self.network,
        }
    }

    #[cfg(windows)]
    pub fn uses_app_container(&self, role: Role) -> Result<bool> {
        windows::uses_app_container(self.get(role), role)
    }
}

pub const LAUNCHER_WORKER_ARG: &str = "__sandbox_launcher";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Access {
    ReadOnly,
    ReadWrite,
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "native device grants require Linux")
    )]
    Device,
}

pub struct Grant {
    pub path: PathBuf,
    pub access: Access,
    pub directory: Option<File>,
}

impl Grant {
    pub fn new(path: impl Into<PathBuf>, access: Access) -> Self {
        Self {
            path: path.into(),
            access,
            directory: None,
        }
    }
}

pub struct Launch<'a> {
    pub role: Role,
    pub command: Command,
    /// Grants beyond the role's platform files and the read-only executable.
    pub grants: Vec<Grant>,
    /// Where macOS stages each signed worker bundle.
    pub staging_directory: &'a Path,
    /// `None` uses only the platform's mandatory role restrictions.
    pub policy: Option<&'a [u8]>,
}

pub struct PreparedLaunch {
    pub command: Command,
    /// `None` runs `command` unconfined.
    confinement: Option<backend::Confinement>,
}

/// Host resources a confined child needs until it exits.
pub struct LaunchResources {
    _retained: Option<backend::Resources>,
}

pub struct SpawnedLaunch {
    pub child: Child,
    pub pid: u32,
    pub resources: LaunchResources,
}

impl PreparedLaunch {
    #[must_use]
    pub const fn direct(command: Command) -> Self {
        Self {
            command,
            confinement: None,
        }
    }

    pub fn spawn(self, confirmation_timeout: Duration) -> Result<SpawnedLaunch> {
        let Self {
            mut command,
            confinement,
        } = self;
        let spawned = command.spawn();
        drop(command);
        let mut child = spawned.context("starting the worker process")?;
        let Some(confinement) = confinement else {
            return Ok(SpawnedLaunch {
                pid: child.id(),
                child,
                resources: LaunchResources { _retained: None },
            });
        };
        match confinement.confirm(&mut child, confirmation_timeout) {
            Ok((pid, retained)) => Ok(SpawnedLaunch {
                child,
                pid,
                resources: LaunchResources {
                    _retained: Some(retained),
                },
            }),
            Err(error) => {
                if terra_platform::process::kill_vm_child(&mut child).is_err() {
                    let _ = child.kill();
                }
                let _ = child.wait();
                Err(error)
            }
        }
    }
}

/// Confines `launch.command` to its grants; the worker dies with this process.
pub fn prepare_launch(mut launch: Launch<'_>) -> Result<PreparedLaunch> {
    let executable = Grant::new(launch.command.get_program(), Access::ReadOnly);
    launch.grants.extend(backend::role_grants(launch.role));
    launch.grants.push(executable);
    backend::prepare_launch(launch)
}

/// Gives `confined` only the variables `requested` sets explicitly.
#[cfg(unix)]
fn copy_explicit_environment(confined: &mut Command, requested: &Command) {
    confined.env_clear();
    for (name, value) in requested.get_envs() {
        if let Some(value) = value {
            confined.env(name, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    /// The build script compiles one fallback filter per terra-build role; a role
    /// missing there would leave the runtime without its embedded policy.
    #[test]
    fn build_script_roles_match_runtime_roles() {
        assert_eq!(
            terra_build::seccomp::Role::ALL.map(terra_build::seccomp::Role::name),
            Role::ALL.map(Role::name)
        );
    }

    #[test]
    fn direct_launch_preserves_command_and_reports_the_child_pid() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut launch = PreparedLaunch::direct(Command::new(std::env::current_exe()?));
        launch
            .command
            .arg("--list")
            .current_dir(directory.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let spawned = launch.spawn(Duration::ZERO)?;
        assert_eq!(spawned.pid, spawned.child.id());
        let output = spawned.child.wait_with_output()?;
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8(output.stdout)?
                .contains("tests::direct_launch_preserves_command_and_reports_the_child_pid")
        );
        Ok(())
    }
}
