//! Native host confinement for an explicitly granted command.

use anyhow::Result;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode};
use std::time::Duration;

pub(crate) mod config;
#[cfg(target_os = "linux")]
mod linux;
pub(crate) mod policy;

pub(crate) use config::LauncherConfig;

pub(crate) const LAUNCHER_WORKER_ARG: &str = "__sandbox_launcher";
#[cfg(target_os = "linux")]
const DEFAULT_LAUNCHER: &str = "bwrap";
#[cfg(not(target_os = "linux"))]
const DEFAULT_LAUNCHER: &str = "direct";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    ReadOnly,
    ReadWrite,
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "native device grants require Linux")
    )]
    Device,
}

#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "filesystem grants are consumed only by the Linux backend"
    )
)]
pub(crate) struct Grant {
    pub(crate) path: PathBuf,
    pub(crate) access: Access,
    pub(crate) directory: Option<File>,
}

impl Grant {
    pub(crate) fn new(path: impl Into<PathBuf>, access: Access) -> Self {
        Self {
            path: path.into(),
            access,
            directory: None,
        }
    }
}

#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "confinement inputs are consumed only by the Linux backend"
    )
)]
pub(crate) struct Launch<'a> {
    pub(crate) command: Command,
    pub(crate) grants: Vec<Grant>,
    pub(crate) die_with_parent: bool,
    /// `None` installs no syscall filter.
    pub(crate) policy: Option<&'a [u8]>,
}

pub(crate) enum PreparedLaunch {
    Direct(Command),
    #[cfg(target_os = "linux")]
    Sandboxed(linux::PreparedLaunch),
}

pub(crate) struct SpawnedLaunch {
    pub(crate) child: Child,
    pub(crate) pid: u32,
}

impl PreparedLaunch {
    pub(crate) fn command_mut(&mut self) -> &mut Command {
        match self {
            Self::Direct(command) => command,
            #[cfg(target_os = "linux")]
            Self::Sandboxed(launch) => &mut launch.command,
        }
    }

    pub(crate) fn spawn(self, identity_timeout: Duration) -> Result<SpawnedLaunch> {
        let _ = identity_timeout;
        match self {
            Self::Direct(mut command) => {
                let child = command.spawn()?;
                Ok(SpawnedLaunch {
                    pid: child.id(),
                    child,
                })
            }
            #[cfg(target_os = "linux")]
            Self::Sandboxed(launch) => launch.spawn(identity_timeout),
        }
    }
}

pub(crate) fn prepare_launch(launch: Launch<'_>) -> Result<PreparedLaunch> {
    #[cfg(target_os = "linux")]
    return linux::prepare_launch(launch).map(PreparedLaunch::Sandboxed);
    #[cfg(not(target_os = "linux"))]
    {
        drop(launch);
        Err(unsupported_sandbox().into())
    }
}

pub(crate) fn resolve_policy(policy: Option<&Path>, allow_fallback: bool) -> Result<Vec<u8>> {
    #[cfg(target_os = "linux")]
    return linux::seccomp::resolve_policy(policy, allow_fallback);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (policy, allow_fallback);
        Err(unsupported_sandbox().into())
    }
}

pub(crate) fn host_runtime_grants() -> Vec<Grant> {
    #[cfg(target_os = "linux")]
    return linux::host_runtime_grants();
    #[cfg(not(target_os = "linux"))]
    Vec::new()
}

pub(crate) fn require_sandbox_support() -> Result<()> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(unsupported_sandbox().into())
    }
}

fn unsupported_sandbox() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "native command confinement requires a Linux host; choose direct or a custom launcher",
    )
}

pub(crate) fn run_launcher_worker(
    arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<ExitCode> {
    require_sandbox_support()?;
    anyhow::ensure!(
        arguments.eq([std::ffi::OsString::from("--version")]),
        "terra {LAUNCHER_WORKER_ARG} accepts only --version"
    );
    #[cfg(target_os = "linux")]
    {
        let status = linux::embedded_command()?.arg("--version").status()?;
        Ok(ExitCode::from(crate::exit_status_byte(
            status.code().unwrap_or(1),
        )))
    }
    #[cfg(not(target_os = "linux"))]
    Err(unsupported_sandbox().into())
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
            String::from_utf8(output.stdout)?.contains(
                "sandbox::tests::direct_launch_preserves_command_and_reports_the_child_pid"
            )
        );
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_confinement_fails_before_running_the_command() {
        let error = prepare_launch(Launch {
            command: Command::new("missing-workload"),
            grants: Vec::new(),
            die_with_parent: false,
            policy: None,
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
