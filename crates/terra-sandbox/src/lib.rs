//! Native host confinement for an explicitly granted command.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use anyhow::Result;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode};
use std::time::Duration;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::seccomp;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(all(test, not(target_os = "macos")))]
#[path = "macos/policy.rs"]
mod macos_policy_tests;
#[cfg(target_os = "windows")]
mod windows;

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
    #[cfg_attr(
        not(target_os = "linux"),
        allow(
            dead_code,
            reason = "role bundle generation and policy tests enumerate every role"
        )
    )]
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
    #[must_use]
    pub fn get(&self, role: Role) -> &[u8] {
        match role {
            Role::Supervisor => &self.supervisor,
            Role::Vm => &self.vm,
            Role::Network => &self.network,
        }
    }

    #[cfg(windows)]
    pub fn uses_app_container(&self, role: Role) -> anyhow::Result<bool> {
        windows::uses_app_container(self.get(role), role)
    }
}

pub const LAUNCHER_WORKER_ARG: &str = "__sandbox_launcher";
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub const DEFAULT_LAUNCHER: &str = "bwrap";
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub const DEFAULT_LAUNCHER: &str = "direct";

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

#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    allow(
        dead_code,
        reason = "filesystem grants require a supported native sandbox"
    )
)]
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

#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    allow(
        dead_code,
        reason = "confinement inputs require a supported native sandbox"
    )
)]
pub struct Launch<'a> {
    pub role: Role,
    pub command: Command,
    pub grants: Vec<Grant>,
    pub die_with_parent: bool,
    /// Where macOS stages each signed worker bundle.
    pub staging_directory: &'a Path,
    /// `None` uses only the platform's mandatory role restrictions.
    pub policy: Option<&'a [u8]>,
}

pub enum PreparedLaunch {
    Direct(Command),
    #[cfg(target_os = "linux")]
    Sandboxed(linux::PreparedLaunch),
    #[cfg(target_os = "macos")]
    Sandboxed(macos::PreparedLaunch),
    #[cfg(target_os = "windows")]
    Sandboxed(windows::PreparedLaunch),
}

pub struct SpawnedLaunch {
    pub child: Child,
    pub pid: u32,
    #[cfg(target_os = "windows")]
    pub trusted_directories: Vec<File>,
    #[cfg(target_os = "macos")]
    pub sandbox_bundle: Option<tempfile::TempDir>,
}

impl PreparedLaunch {
    pub fn command_mut(&mut self) -> &mut Command {
        match self {
            Self::Direct(command) => command,
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            Self::Sandboxed(launch) => &mut launch.command,
        }
    }

    pub fn spawn(self, identity_timeout: Duration) -> Result<SpawnedLaunch> {
        let _ = identity_timeout;
        match self {
            Self::Direct(mut command) => {
                let child = command.spawn()?;
                Ok(SpawnedLaunch {
                    pid: child.id(),
                    child,
                    #[cfg(target_os = "windows")]
                    trusted_directories: Vec::new(),
                    #[cfg(target_os = "macos")]
                    sandbox_bundle: None,
                })
            }
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            Self::Sandboxed(launch) => launch.spawn(identity_timeout),
        }
    }
}

pub fn prepare_launch(launch: Launch<'_>) -> Result<PreparedLaunch> {
    #[cfg(target_os = "linux")]
    return linux::prepare_launch(launch).map(PreparedLaunch::Sandboxed);
    #[cfg(target_os = "macos")]
    return macos::prepare_launch(launch).map(PreparedLaunch::Sandboxed);
    #[cfg(target_os = "windows")]
    return windows::prepare_launch(launch).map(PreparedLaunch::Sandboxed);
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        drop(launch);
        Err(unsupported_sandbox().into())
    }
}

pub fn resolve_policy(policy: Option<&Path>, allow_fallback: bool) -> Result<PolicyBundle> {
    #[cfg(target_os = "linux")]
    return linux::seccomp::resolve_policy(policy, allow_fallback);
    #[cfg(target_os = "macos")]
    return macos::resolve_policy(policy, allow_fallback);
    #[cfg(target_os = "windows")]
    return windows::resolve_policy(policy, allow_fallback);
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (policy, allow_fallback);
        Err(unsupported_sandbox().into())
    }
}

#[must_use]
pub fn role_grants(role: Role) -> Vec<Grant> {
    #[cfg(target_os = "linux")]
    return linux::role_grants(role);
    #[cfg(target_os = "macos")]
    return macos::role_grants(role);
    #[cfg(target_os = "windows")]
    return windows::role_grants(role);
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = role;
        Vec::new()
    }
}

#[cfg_attr(
    any(target_os = "linux", target_os = "macos", target_os = "windows"),
    allow(
        clippy::unnecessary_wraps,
        reason = "unsupported platforms return an error"
    )
)]
pub fn require_sandbox_support() -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    return Ok(());
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(unsupported_sandbox().into())
}

pub fn install_policy(policy: &[u8]) -> Result<()> {
    #[cfg(target_os = "linux")]
    return linux::seccomp::install_policy(policy);
    #[cfg(target_os = "macos")]
    return macos::install_policy(policy);
    #[cfg(target_os = "windows")]
    return windows::install_policy(policy);
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = policy;
        Err(unsupported_sandbox().into())
    }
}

#[cfg_attr(
    not(any(target_os = "macos", target_os = "windows")),
    allow(
        clippy::unnecessary_wraps,
        reason = "native role verification is fallible on macOS and Windows"
    )
)]
pub fn verify_worker_role(role: Role) -> Result<()> {
    #[cfg(target_os = "macos")]
    return macos::verify_worker_role(role);
    #[cfg(target_os = "windows")]
    return windows::verify_worker_role(role);
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = role;
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn unsupported_sandbox() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "native command confinement requires Linux, macOS, or Windows; choose direct or a custom launcher",
    )
}

pub fn run_launcher_worker(
    arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<ExitCode> {
    #[cfg(target_os = "linux")]
    {
        anyhow::ensure!(
            arguments.eq([std::ffi::OsString::from("--version")]),
            "terra {LAUNCHER_WORKER_ARG} accepts only --version"
        );
        let status = linux::embedded_command()?.arg("--version").status()?;
        Ok(ExitCode::from(
            u8::try_from(status.code().unwrap_or(1)).unwrap_or(1),
        ))
    }
    #[cfg(target_os = "macos")]
    return macos::run_launcher_worker(arguments);
    #[cfg(target_os = "windows")]
    return windows::run_launcher_worker(arguments);
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = arguments;
        Err(unsupported_sandbox().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[test]
    fn direct_launch_preserves_command_and_reports_the_child_pid() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut launch = PreparedLaunch::Direct(Command::new(std::env::current_exe()?));
        launch
            .command_mut()
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

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    #[test]
    fn unsupported_confinement_fails_before_running_the_command() {
        let error = prepare_launch(Launch {
            role: Role::Vm,
            command: Command::new("missing-workload"),
            grants: Vec::new(),
            die_with_parent: false,
            policy: None,
            staging_directory: &std::env::temp_dir(),
        })
        .err()
        .unwrap();
        for error in [
            error,
            resolve_policy(Some(Path::new("missing-policy")), true).unwrap_err(),
            resolve_policy(None, true).unwrap_err(),
            run_launcher_worker(["--version".into()].into_iter()).unwrap_err(),
        ] {
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::Unsupported
            );
        }
    }
}
