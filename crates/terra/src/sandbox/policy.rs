//! Native policy enforcement and generation for caller-prepared commands.

#![cfg_attr(
    not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )),
    allow(
        dead_code,
        reason = "generation inputs are consumed only by supported backends"
    )
)]

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, ExitCode};
use std::time::Duration;

use anyhow::Result;
use serde::Serialize;

pub(crate) const WORKER_ARG: &str = "__sandbox_policy";

#[derive(Serialize)]
pub(crate) struct Validation<'a> {
    pub(crate) name: &'a str,
    pub(crate) reason: &'a str,
}

pub(crate) struct Workload<'a> {
    pub(crate) name: &'a str,
    pub(crate) scope: &'a str,
    pub(crate) vm_validated: bool,
    pub(crate) enforced_only: &'a [Validation<'a>],
}

pub(crate) struct Options<'a> {
    pub(crate) binary: &'a Path,
    pub(crate) output: &'a Path,
    pub(crate) diagnostics: &'a Path,
    pub(crate) timeout: Duration,
    pub(crate) workload: Workload<'a>,
}

#[derive(Clone, Copy)]
pub(crate) enum Phase<'a> {
    Collect { traces: &'a Path },
    Enforce { policy: &'a Path },
    Validate { name: &'a str, policy: &'a Path },
}

pub(crate) fn generate(
    options: &Options<'_>,
    prepare_launch: impl FnMut(Phase<'_>) -> Result<Command>,
) -> Result<()> {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    return super::generation::generate(options, prepare_launch);
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        let _ = (options, prepare_launch);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "policy generation requires native x86-64 or AArch64 Linux",
        )
        .into())
    }
}

pub(crate) fn trace_command(command: &Command, output: &Path) -> Result<Command> {
    require_policy_support()?;
    wrap_command(command, "trace", output)
}

/// `None` leaves the command unchanged.
#[cfg(test)]
pub(crate) fn enforce_command(command: Command, policy: Option<&Path>) -> Result<Command> {
    match policy {
        None => Ok(command),
        Some(policy) => {
            require_policy_support()?;
            wrap_command(&command, "enforce", policy)
        }
    }
}

pub(crate) fn require_policy_support() -> Result<()> {
    if cfg!(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )) {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "policy generation, enforcement and tracing require native x86-64 or AArch64 Linux",
        )
        .into())
    }
}

fn wrap_command(command: &Command, mode: &str, data: &Path) -> Result<Command> {
    let mut worker = Command::new(std::env::current_exe()?);
    worker
        .arg(WORKER_ARG)
        .arg(mode)
        .arg(data)
        .arg(command.get_program())
        .args(command.get_args());
    if let Some(directory) = command.get_current_dir() {
        worker.current_dir(directory);
    }
    for (name, value) in command.get_envs() {
        if let Some(value) = value {
            worker.env(name, value);
        } else {
            worker.env_remove(name);
        }
    }
    Ok(worker)
}

pub(crate) fn run_worker(arguments: &mut impl Iterator<Item = OsString>) -> Result<ExitCode> {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    return super::generation::run_worker(arguments);
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        let _ = arguments;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "policy workers require native x86-64 or AArch64 Linux",
        )
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn no_policy_keeps_the_original_command_on_every_platform() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut command = Command::new("workload");
        command
            .args(["a b", "$HOME"])
            .current_dir(directory.path())
            .env("GRANTED", "value")
            .env_remove("REMOVED");
        let command = enforce_command(command, None)?;
        assert_eq!(command.get_program(), "workload");
        assert_eq!(command.get_args().collect::<Vec<_>>(), ["a b", "$HOME"]);
        assert_eq!(command.get_current_dir(), Some(directory.path()));
        let environment: BTreeMap<_, _> = command.get_envs().collect();
        assert_eq!(
            environment[std::ffi::OsStr::new("GRANTED")],
            Some(std::ffi::OsStr::new("value"))
        );
        assert_eq!(environment[std::ffi::OsStr::new("REMOVED")], None);
        Ok(())
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn workers_preserve_literal_arguments_directory_and_explicit_environment() -> Result<()> {
        let root = tempfile::tempdir()?;
        for mode in ["trace", "enforce"] {
            let mut command = Command::new("/bin/program");
            command
                .args(["a b", "$HOME", "$(touch ignored)", "é"])
                .current_dir(root.path())
                .env("GRANTED", "value")
                .env_remove("REMOVED");
            let worker = match mode {
                "trace" => trace_command(&command, Path::new("/data"))?,
                "enforce" => enforce_command(command, Some(Path::new("/data")))?,
                _ => unreachable!(),
            };
            assert_eq!(worker.get_current_dir(), Some(root.path()));
            assert_eq!(
                worker.get_args().collect::<Vec<_>>(),
                [
                    WORKER_ARG,
                    mode,
                    "/data",
                    "/bin/program",
                    "a b",
                    "$HOME",
                    "$(touch ignored)",
                    "é"
                ]
            );
            let environment: BTreeMap<_, _> = worker.get_envs().collect();
            assert_eq!(
                environment[std::ffi::OsStr::new("GRANTED")],
                Some(std::ffi::OsStr::new("value"))
            );
            assert_eq!(environment[std::ffi::OsStr::new("REMOVED")], None);
        }
        Ok(())
    }

    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    #[test]
    fn unsupported_policies_fail_without_running_commands_or_creating_artifacts() -> Result<()> {
        let root = tempfile::tempdir()?;
        let command = Command::new("missing-workload");
        let error = enforce_command(command, Some(Path::new("missing-policy"))).unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::Unsupported
        );
        let error = trace_command(
            &Command::new("missing-workload"),
            Path::new("missing-trace"),
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::Unsupported
        );
        let output = root.path().join("policy");
        let diagnostics = root.path().join("diagnostics");
        let options = Options {
            binary: Path::new("missing-workload"),
            output: &output,
            diagnostics: &diagnostics,
            timeout: Duration::from_secs(1),
            workload: Workload {
                name: "custom",
                scope: "custom",
                vm_validated: true,
                enforced_only: &[],
            },
        };
        let error = generate(&options, |_| {
            panic!("unsupported generation prepared a workload")
        })
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::Unsupported
        );
        assert!(!output.exists() && !diagnostics.exists());
        Ok(())
    }
}
