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
#[cfg(all(target_os = "linux", feature = "generator"))]
pub use linux::generator;
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
#[cfg(windows)]
pub use windows::LauncherSockets;

pub use backend::{restrict_role, run_launcher_worker, verify_worker_role};

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
            Self::Vm => terra_platform::process::sandbox_env::VM_ROLE,
            Self::Network => "network",
        }
    }
}

pub const LAUNCHER_WORKER_ARG: &str = "__sandbox_launcher";

/// Receives a launcher reply: an opened socket or the error that prevented it.
pub type SocketReply = Box<dyn FnOnce(std::io::Result<socket2::Socket>) + Send>;

/// Outbound sockets a host sandbox's trusted launcher opens for a worker it confines; only the
/// Windows broker receives them.
#[cfg(not(windows))]
pub enum LauncherSockets {}

#[cfg(not(windows))]
impl LauncherSockets {
    #[allow(clippy::unnecessary_wraps, reason = "matches the Windows signature")]
    pub fn claim() -> Result<Option<Self>> {
        Ok(None)
    }

    pub fn connect_tcp(&self, _: std::net::SocketAddr, _: SocketReply) {
        match *self {}
    }

    pub fn bind_udp(&self, _: socket2::Domain) -> std::io::Result<socket2::Socket> {
        match *self {}
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// Where macOS writes each worker's launch spec.
    pub staging_directory: &'a Path,
}

pub struct PreparedLaunch {
    pub command: Command,
    confinement: backend::Confinement,
}

/// Host resources a confined child needs until it exits.
pub struct LaunchResources {
    _retained: backend::Resources,
}

pub struct SpawnedLaunch {
    pub child: Child,
    pub pid: u32,
    pub resources: LaunchResources,
}

impl PreparedLaunch {
    pub fn spawn(self, confirmation_timeout: Duration) -> Result<SpawnedLaunch> {
        let Self {
            mut command,
            confinement,
        } = self;
        let spawned = command.spawn();
        drop(command);
        let mut child = spawned.context("starting the worker process")?;
        match confinement.confirm(&mut child, confirmation_timeout) {
            Ok((pid, retained)) => Ok(SpawnedLaunch {
                child,
                pid,
                resources: LaunchResources {
                    _retained: retained,
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

#[cfg_attr(
    target_os = "linux",
    allow(
        dead_code,
        reason = "only the macOS and Windows launchers read a worker spec"
    )
)]
pub(crate) const MAX_WORKER_SPEC_BYTES: u64 = 1 << 20;

#[cfg_attr(
    target_os = "linux",
    allow(
        dead_code,
        reason = "only the macOS and Windows launchers read a worker spec"
    )
)]
pub(crate) fn write_worker_spec(
    directory: &Path,
    spec: &impl serde::Serialize,
) -> Result<tempfile::NamedTempFile> {
    use std::io::Write as _;
    let bytes = serde_json::to_vec(spec)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_WORKER_SPEC_BYTES,
        "worker launch specification exceeds its size limit"
    );
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    terra_platform::filesystem::set_owner_only(file.path(), false)?;
    file.write_all(&bytes)?;
    file.flush()?;
    Ok(file)
}

#[cfg_attr(
    target_os = "linux",
    allow(
        dead_code,
        reason = "only the macOS and Windows launchers read a worker spec"
    )
)]
pub(crate) fn read_worker_spec<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_WORKER_SPEC_BYTES + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_WORKER_SPEC_BYTES,
        "worker launch specification exceeds its size limit"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The build script compiles one role filter per terra-build role; a role
    /// missing there would leave the runtime without its embedded policy.
    #[test]
    fn build_script_roles_match_runtime_roles() {
        assert_eq!(
            terra_build::seccomp::Role::ALL.map(terra_build::seccomp::Role::name),
            Role::ALL.map(Role::name)
        );
    }

    #[test]
    fn worker_spec_round_trips_through_an_owner_only_file() {
        let directory = tempfile::tempdir().unwrap();
        let spec = write_worker_spec(directory.path(), &vec![Role::Vm, Role::Network]).unwrap();
        assert!(spec.path().starts_with(directory.path()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                spec.path().metadata().unwrap().permissions().mode() & 0o077,
                0
            );
        }
        let read: Vec<Role> = read_worker_spec(spec.path()).unwrap();
        assert_eq!(read, [Role::Vm, Role::Network]);
    }

    #[test]
    fn worker_spec_over_its_limit_is_rejected_both_ways() {
        let directory = tempfile::tempdir().unwrap();
        let oversized = "x".repeat(usize::try_from(MAX_WORKER_SPEC_BYTES).unwrap());
        assert!(write_worker_spec(directory.path(), &oversized).is_err());
        let path = directory.path().join("oversized.json");
        std::fs::write(&path, format!("\"{oversized}\"")).unwrap();
        assert!(read_worker_spec::<String>(&path).is_err());
    }
}
