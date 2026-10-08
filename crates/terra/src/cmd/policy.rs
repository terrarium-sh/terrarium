//! CLI inputs and foreground workloads for native policy generation.

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, ExitCode};
use std::time::Duration;

use anyhow::Result;

use crate::cli::{BootArgs, PolicyArgs};
use crate::sandbox::policy::{self, Options, Phase, Workload};
use crate::state::BoxRef;

pub(super) fn generate(
    args: &PolicyArgs,
    project: &Path,
    binary: &Path,
    workload: Workload<'_>,
    prepare_launch: impl FnMut(Phase<'_>) -> Result<Command>,
) -> Result<ExitCode> {
    let output = crate::sys::resolve_absolute_path(
        args.policy_output
            .as_deref()
            .unwrap_or(Path::new("terra-seccomp")),
        project,
    )?;
    let diagnostics = crate::sys::resolve_absolute_path(&args.policy_diagnostics, project)?;
    policy::generate(
        &Options {
            binary,
            output: &output,
            diagnostics: &diagnostics,
            timeout: Duration::from_secs(args.policy_timeout),
            workload,
        },
        prepare_launch,
    )?;
    Ok(ExitCode::SUCCESS)
}

pub(super) fn generate_foreground(args: &BootArgs, bx: &BoxRef) -> Result<ExitCode> {
    let binary = std::env::current_exe()?.canonicalize()?;
    let stage = tempfile::Builder::new().prefix("tf-").tempdir()?;
    let arguments = foreground_arguments(args, bx);
    generate(
        &args.policy,
        bx.get_project_dir(),
        &binary,
        Workload {
            name: "workload.foreground",
            scope: "guest",
            vm_validated: true,
            enforced_only: &[],
        },
        |phase| {
            prepare_foreground(
                &binary,
                &arguments,
                bx.get_project_dir(),
                stage.path(),
                phase,
            )
        },
    )
}

fn prepare_foreground(
    binary: &Path,
    arguments: &[OsString],
    project: &Path,
    stage: &Path,
    phase: Phase<'_>,
) -> Result<Command> {
    let mut command = Command::new(binary);
    command
        .args(arguments)
        .current_dir(project)
        .env_remove("TERRA_SYSCALL_TRACE")
        .env_remove("TERRA_SECCOMP_ENFORCED");
    let (mode, policy) = match phase {
        Phase::Collect { traces } => {
            command.env("TERRA_SYSCALL_TRACE", traces);
            ("collect", None)
        }
        Phase::Enforce { policy } => {
            command.env("TERRA_SECCOMP_ENFORCED", "1");
            ("enforce", Some(policy.to_path_buf()))
        }
        Phase::Validate { name, .. } => anyhow::bail!("unknown foreground validation: {name}"),
    };
    let config = stage.join(format!("{mode}.json"));
    crate::sandbox::config::write_policy_workload(&config, policy.as_deref())?;
    command
        .env("TERRA_SECCOMP_CONFIG", config)
        .env("TERRA_WORKLOAD_RUN_ID", stage.join(mode));
    match phase {
        Phase::Collect { traces } => policy::trace_command(&command, &traces.join("workload.json")),
        Phase::Enforce { .. } | Phase::Validate { .. } => Ok(command),
    }
}

fn foreground_arguments(args: &BootArgs, bx: &BoxRef) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from(bx.get_name()),
        OsString::from("--project"),
        bx.get_project_dir().as_os_str().to_owned(),
        OsString::from("--foreground"),
    ];
    if args.root {
        arguments.push("--root".into());
    }
    if let Some(timeout) = args.agent.agent_timeout {
        arguments.extend(["--agent-timeout".into(), timeout.to_string().into()]);
    }
    if !args.command.is_empty() {
        arguments.push("--".into());
        arguments.extend(args.command.iter().map(OsString::from));
    }
    arguments
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::config::{LauncherConfig, load_from};
    use clap::Parser as _;

    #[test]
    fn foreground_passes_keep_literal_arguments_without_recursion_and_deliver_policy() -> Result<()>
    {
        let cli = crate::cli::Cli::parse_from([
            "terra",
            "dev",
            "--generate-policy",
            "--root",
            "--agent-timeout",
            "42",
            "--",
            "printf",
            "a b",
            "--generate-policy",
            "$HOME",
        ]);
        let root = tempfile::tempdir()?;
        let bx = BoxRef::from_state_dir(root.path().join("box"), root.path());
        let arguments = foreground_arguments(&cli.boot, &bx);
        let forwarded = crate::cli::Cli::parse_from(
            std::iter::once(OsString::from("terra")).chain(arguments.clone()),
        );
        assert_eq!(forwarded.name.as_deref(), Some(bx.get_name()));
        assert_eq!(forwarded.project.as_deref(), Some(root.path()));
        assert!(forwarded.boot.foreground && forwarded.boot.root);
        assert_eq!(forwarded.boot.agent.agent_timeout, Some(42));
        assert!(!forwarded.boot.policy.generate_policy);
        assert_eq!(forwarded.boot.command, cli.boot.command);
        let candidate = root.path().join("candidate");
        for phase in [
            Phase::Collect {
                traces: root.path(),
            },
            Phase::Enforce { policy: &candidate },
        ] {
            let command = prepare_foreground(
                Path::new("/terra"),
                &arguments,
                root.path(),
                root.path(),
                phase,
            )?;
            let forwarded = command.get_args().collect::<Vec<_>>();
            match phase {
                Phase::Collect { .. } => assert_eq!(&forwarded[4..], arguments),
                Phase::Enforce { .. } | Phase::Validate { .. } => assert_eq!(forwarded, arguments),
            }
            assert_eq!(command.get_current_dir(), Some(root.path()));
        }
        assert_eq!(
            load_from(&root.path().join("collect.json"))?,
            LauncherConfig::Sandboxed {
                policy: None,
                allow_fallback: true,
            }
        );
        assert_eq!(
            load_from(&root.path().join("enforce.json"))?,
            LauncherConfig::Sandboxed {
                policy: Some(candidate),
                allow_fallback: false,
            }
        );
        Ok(())
    }
}
