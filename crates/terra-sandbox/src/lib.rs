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

pub use backend::{restrict_role, run_launcher_worker};

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

/// Every worker launch is sandboxed, so only the unconfined supervisor runs without its
/// launcher's role; a worker then proves the confinement its launcher applied.
pub fn verify_worker_role(role: Role) -> Result<()> {
    let launched_role = std::env::var_os(terra_platform::process::sandbox_env::ROLE);
    if role == Role::Supervisor {
        anyhow::ensure!(
            launched_role.is_none(),
            "a sandboxed worker cannot run the supervisor"
        );
        return Ok(());
    }
    anyhow::ensure!(
        launched_role.is_some_and(|launched_role| launched_role == role.name()),
        "{} worker was not started by its sandbox launcher",
        role.name()
    );
    backend::verify_confinement(role)
}

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

/// Orders `grants` for backends where a later grant overrides an earlier one: a deeper path
/// applies last, and on the same path a read-only grant does, so the narrower grant wins.
#[cfg_attr(
    target_os = "macos",
    allow(dead_code, reason = "the macOS profile refuses overlapping grants")
)]
pub(crate) fn order_most_specific_last(grants: &mut [Grant]) {
    grants.sort_by_key(|grant| {
        (
            grant.path.components().count(),
            grant.access == Access::ReadOnly,
        )
    });
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

    /// Windows ACLs and bind mounts both let the last grant win, so a read-only grant nested
    /// in, or duplicating, a writable one must come after it whatever order the caller used.
    #[test]
    fn the_narrower_grant_applies_last() {
        let mut grants = vec![
            Grant::new("/share/secrets", Access::ReadOnly),
            Grant::new("/share", Access::ReadOnly),
            Grant::new("/share", Access::ReadWrite),
            Grant::new("/share/cache", Access::ReadWrite),
        ];
        order_most_specific_last(&mut grants);
        let order: Vec<_> = grants
            .iter()
            .map(|grant| (grant.path.to_str().unwrap(), grant.access))
            .collect();
        assert_eq!(
            order,
            [
                ("/share", Access::ReadWrite),
                ("/share", Access::ReadOnly),
                ("/share/cache", Access::ReadWrite),
                ("/share/secrets", Access::ReadOnly),
            ]
        );
    }

    /// The build script compiles one role filter per terra-build role; a role
    /// missing there would leave the runtime without its embedded policy.
    #[test]
    fn build_script_roles_match_runtime_roles() {
        assert_eq!(
            terra_build::seccomp::Role::ALL.map(terra_build::seccomp::Role::name),
            Role::ALL.map(Role::name)
        );
    }

    /// Every worker launch is sandboxed, so a VM or broker worker without its launcher's role
    /// has escaped its sandbox; only the unconfined supervisor runs without one.
    #[test]
    fn direct_workers_are_refused_but_the_supervisor_runs_unconfined() {
        verify_worker_role(Role::Supervisor).unwrap();
        for role in [Role::Vm, Role::Network] {
            assert!(verify_worker_role(role).is_err(), "{}", role.name());
        }
    }

    /// A worker that re-executes the supervisor entry point still carries its launcher's role,
    /// which the supervisor refuses.
    #[test]
    fn a_sandboxed_worker_cannot_run_the_supervisor() {
        const CHILD: &str = "TERRA_SANDBOX_SUPERVISOR_IN_WORKER_TEST";
        if std::env::var_os(CHILD).is_some() {
            assert!(verify_worker_role(Role::Supervisor).is_err());
            return;
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::a_sandboxed_worker_cannot_run_the_supervisor",
            ])
            .env(CHILD, "1")
            .env(terra_platform::process::sandbox_env::ROLE, Role::Vm.name())
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{output:?}"
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
