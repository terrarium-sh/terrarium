use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::cli::{SelfTestArgs, SelfTestCommand};
use crate::process;

mod guest;

pub async fn run(args: &SelfTestArgs, project_dir: &Path) -> Result<ExitCode> {
    if let Some(command) = &args.command {
        return match command {
            SelfTestCommand::Host => run_host_probe().await,
            SelfTestCommand::Guest => {
                guest::run_suite(project_dir)?;
                Ok(ExitCode::SUCCESS)
            }
        };
    }
    if args.policy.generate_policy {
        return generate_policy(args, project_dir);
    }
    let status = Command::new(std::env::current_exe()?)
        .args(["self-test", "host"])
        .current_dir(project_dir)
        .status()
        .context("running host self-tests")?;
    if !status.success() || !args.validate_vm {
        return Ok(ExitCode::from(crate::exit_status_byte(
            status.code().unwrap_or(1),
        )));
    }
    process::install_interrupt_handler()?;
    let stage = tempfile::Builder::new().prefix("ts-").tempdir()?;
    let config = stage.path().join("launcher.json");
    crate::sandbox::config::write_resolved(&config)?;
    let diagnostics = create_diagnostics(&args.diagnostics, project_dir, "self-test-")?;
    let mut command = Command::new(std::env::current_exe()?);
    command.args(["self-test", "guest"]);
    prepare_self_test(&mut command, stage.path(), "guest-run")?;
    command.env("TERRA_SECCOMP_CONFIG", config);
    let log = diagnostics.join("self_test.built_in_guest.log");
    println!("self-test: built-in guest suite; log: {}", log.display());
    let result = process::run_logged(&mut command, Duration::from_secs(args.timeout), &log);
    let cleanup = cleanup_self_test_boxes(stage.path(), "guest-run");
    complete_self_test_cleanup(result, cleanup)?;
    println!("self-test: passed; diagnostics: {}", diagnostics.display());
    Ok(ExitCode::SUCCESS)
}

fn create_diagnostics(directory: &Path, project: &Path, prefix: &str) -> Result<PathBuf> {
    let directory = crate::sys::resolve_absolute_path(directory, project)?;
    std::fs::create_dir_all(&directory)?;
    Ok(tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(directory)?
        .keep())
}

fn prepare_self_test(command: &mut Command, stage: &Path, mode: &str) -> Result<()> {
    let directory = stage.join(mode);
    let home = directory.join("home");
    let project = directory.join("project");
    std::fs::create_dir_all(home.join(".terra"))?;
    std::fs::create_dir_all(&project)?;
    std::fs::write(home.join(".terra/config.yaml"), "vm:\n  init: direct\n")?;
    configure_self_test_environment(command, &directory);
    Ok(())
}

fn configure_self_test_environment(command: &mut Command, directory: &Path) {
    let home = directory.join("home");
    command
        .current_dir(directory.join("project"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("TMPDIR", directory)
        .env("TMP", directory)
        .env("TEMP", directory)
        .env_remove("TERRA_SECCOMP_CONFIG")
        .env_remove("TERRA_SYSCALL_TRACE")
        .env_remove("TERRA_SECCOMP_ENFORCED");
    tag_command(command, directory);
}

fn cleanup_self_test_boxes(stage: &Path, mode: &str) -> Result<()> {
    let directory = stage.join(mode);
    let box_home = directory.join("home/.terra/box");
    let projects = match std::fs::read_dir(&box_home) {
        Ok(projects) => projects,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("reading private self-test boxes"),
    };
    let binary = std::env::current_exe()?;
    let mut failures = Vec::new();
    for project in projects {
        let cleanup = project
            .map_err(anyhow::Error::from)
            .and_then(|project| cleanup_self_test_project(&binary, &directory, &project.path()));
        if let Err(error) = cleanup {
            failures.push(format!("{error:#}"));
        }
    }
    anyhow::ensure!(
        failures.is_empty(),
        "self-test box cleanup failed:\n{}",
        failures.join("\n")
    );
    Ok(())
}

fn cleanup_self_test_project(binary: &Path, directory: &Path, project_state: &Path) -> Result<()> {
    if !project_state.is_dir() {
        return Ok(());
    }
    let boxes = crate::state::list_boxes_in(project_state)?;
    if boxes.is_empty() {
        return Ok(());
    }
    let project = crate::state::read_origin(project_state)
        .with_context(|| format!("reading self-test origin in {}", project_state.display()))?;
    let mut failures = Vec::new();
    for (name, _) in boxes {
        let mut command = Command::new(binary);
        command
            .arg("--project")
            .arg(&project)
            .arg(&name)
            .args(["stop", "-t", "0"]);
        configure_self_test_environment(&mut command, directory);
        let cleanup =
            process::run_cleanup(&mut command, Duration::from_secs(30)).and_then(|output| {
                anyhow::ensure!(
                    output.status.success(),
                    "stopping self-test box {name}: {}\n{}\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                Ok(())
            });
        if let Err(error) = cleanup {
            failures.push(format!("{error:#}"));
        }
    }
    anyhow::ensure!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

fn complete_self_test_cleanup<T>(result: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(error.context(format!("{cleanup:#}"))),
    }
}

fn tag_command(command: &mut Command, directory: &Path) {
    command.env("TERRA_WORKLOAD_RUN_ID", directory.as_os_str());
}

fn generate_policy(args: &SelfTestArgs, project: &Path) -> Result<ExitCode> {
    use crate::sandbox::policy::{self, Phase, Validation, Workload};
    let binary = std::env::current_exe()?.canonicalize()?;
    let stage = tempfile::Builder::new().prefix("ts-").tempdir()?;
    let guest_validation = [Validation {
        name: "self_test.built_in_guest",
        reason: "Validate guest execution against the host-generated policy without broadening it.",
    }];
    let result = super::policy::generate(
        &args.policy,
        project,
        &binary,
        Workload {
            name: "self_test.host_components",
            scope: "host_components",
            vm_validated: args.validate_vm,
            enforced_only: if args.validate_vm {
                &guest_validation
            } else {
                &[]
            },
        },
        |phase| {
            let mut command = Command::new(&binary);
            match phase {
                Phase::Collect { traces } => {
                    command.args(["self-test", "host"]);
                    prepare_self_test(&mut command, stage.path(), "host-collect")?;
                    command.env("TERRA_SYSCALL_TRACE", traces);
                    policy::trace_command(&command, &traces.join("host.json"))
                }
                Phase::Enforce { policy: path } => {
                    let config = stage.path().join("launcher.json");
                    crate::sandbox::config::write_policy_workload(&config, Some(path))?;
                    command.args(["self-test", "host"]);
                    prepare_self_test(&mut command, stage.path(), "host-enforce")?;
                    command
                        .env("TERRA_SECCOMP_ENFORCED", "1")
                        .env("TERRA_SECCOMP_CONFIG", config);
                    Ok(command)
                }
                Phase::Validate { name, policy: path } => {
                    anyhow::ensure!(
                        name == "self_test.built_in_guest",
                        "unknown self-test validation: {name}"
                    );
                    let config = stage.path().join("launcher.json");
                    crate::sandbox::config::write_policy_workload(&config, Some(path))?;
                    command.args(["self-test", "guest"]);
                    prepare_self_test(&mut command, stage.path(), "guest-enforce")?;
                    command
                        .env("TERRA_SECCOMP_CONFIG", config)
                        .env("TERRA_SECCOMP_ENFORCED", "1");
                    Ok(command)
                }
            }
        },
    );
    complete_self_test_cleanup(
        result,
        cleanup_self_test_boxes(stage.path(), "guest-enforce"),
    )
}

async fn run_host_probe() -> Result<ExitCode> {
    let _ = crossterm::terminal::window_size();
    crate::vm::run_host_self_test().await?;
    println!("host self-tests passed");
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_reports_a_box_without_its_project_origin() -> Result<()> {
        let stage = tempfile::tempdir()?;
        cleanup_self_test_boxes(stage.path(), "guest-run")?;
        let project_state = stage
            .path()
            .join("guest-run")
            .join("home/.terra/box")
            .join("project");
        std::fs::create_dir_all(project_state.join("exercise"))?;
        let error = cleanup_self_test_boxes(stage.path(), "guest-run").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("reading self-test origin"), "{message}");
        assert!(
            message.contains(&project_state.display().to_string()),
            "{message}"
        );
        Ok(())
    }

    #[test]
    fn cleanup_failure_preserves_the_workload_failure() {
        let error = complete_self_test_cleanup::<()>(
            Err(anyhow::anyhow!("workload failed")),
            Err(anyhow::anyhow!("cleanup failed")),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("workload failed"), "{message}");
        assert!(message.contains("cleanup failed"), "{message}");
    }
}
