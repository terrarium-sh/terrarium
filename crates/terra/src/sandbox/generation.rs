//! Generate and validate Linux policies using caller-prepared workload commands.

mod policy;
mod trace;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};
use serde_json::{Value, json};

use crate::process;
use crate::sandbox::policy::{Options, Phase, Workload};
use terra_sandbox::Role;
use terra_sandbox::seccomp::{self, BUNDLE_FORMAT_VERSION, hash_bytes};
use trace::Trace;

#[allow(clippy::too_many_lines)]
pub(crate) fn generate(
    options: &Options<'_>,
    mut prepare_launch: impl FnMut(Phase<'_>) -> Result<Command>,
) -> Result<()> {
    process::install_interrupt_handler()?;
    validate_workload(options)?;
    let binary_hash = hash_file(options.binary)?;
    std::fs::create_dir_all(options.diagnostics)?;
    let diagnostics = tempfile::Builder::new()
        .prefix("policy-")
        .tempdir_in(options.diagnostics)?
        .keep();
    let stage = tempfile::Builder::new().prefix("tp-").tempdir()?;
    println!(
        "The selected workload runs twice: once for tracing and once under the generated policy. Writes and external effects can repeat."
    );
    println!("diagnostics: {}", diagnostics.display());
    let traces = stage.path().join("traces");
    std::fs::create_dir(&traces)?;
    let mut command = prepare_launch(Phase::Collect { traces: &traces })?;
    let collected = run_pass(
        &mut command,
        options.timeout,
        &diagnostics,
        "collect",
        options.workload.name,
    );
    let trace_diagnostics = diagnostics.join("traces");
    std::fs::create_dir(&trace_diagnostics)?;
    for entry in std::fs::read_dir(&traces)? {
        let entry = entry?;
        std::fs::copy(entry.path(), trace_diagnostics.join(entry.file_name()))?;
    }
    let collected = collected?;
    let observations = read_traces(&traces)?;
    let candidate = stage.path().join("validated");
    std::fs::create_dir(&candidate)?;
    let mut role_manifest = serde_json::Map::new();
    for role in Role::ALL {
        let observed = observations
            .roles
            .get(&role)
            .with_context(|| format!("missing required {} role coverage", role.name()))?;
        ensure!(
            observed.exec_count > 0 && !observed.calls.is_empty(),
            "missing verified {} worker execution",
            role.name()
        );
        let document = policy::build_policy(
            &observed.calls,
            &observed.ioctls,
            env!("TERRA_BUILD_TARGET"),
            &options.workload,
            role,
        )?;
        let bytes = serde_json::to_vec_pretty(&document)?;
        let bpf = policy::compile_bpf(&document)?;
        std::fs::write(
            candidate.join(format!("{}.seccomp.json", role.name())),
            &bytes,
        )?;
        std::fs::write(candidate.join(format!("{}.seccomp.bpf", role.name())), &bpf)?;
        role_manifest.insert(role.name().into(), json!({"policy_sha256": hash_bytes(&bytes), "bpf_sha256": hash_bytes(&bpf), "verified_execs": observed.exec_count, "coverage": document["workload_coverage"], "supplement_version": document["supplement_version"]}));
    }
    let mut manifest = json!({
        "format_version": BUNDLE_FORMAT_VERSION, "release_identity": env!("TERRA_VERSION"), "target": env!("TERRA_BUILD_TARGET"),
        "executable_sha256": binary_hash, "roles": role_manifest, "supplement_version": policy::SUPPLEMENT_VERSION,
        "policy_compiler": "seccompiler_0_5_0", "trace_workload_results": [collected],
        "trace_exclusions": options.workload.enforced_only,
        "validation": {"passed": false},
    });
    std::fs::write(
        candidate.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    let mut command = prepare_launch(Phase::Enforce { policy: &candidate })?;
    let mut results = vec![run_pass(
        &mut command,
        options.timeout,
        &diagnostics,
        "enforce",
        options.workload.name,
    )?];
    for validation in options.workload.enforced_only {
        let mut command = prepare_launch(Phase::Validate {
            name: validation.name,
            policy: &candidate,
        })?;
        results.push(run_pass(
            &mut command,
            options.timeout,
            &diagnostics,
            "validate",
            validation.name,
        )?);
    }
    crate::vm::supervisor::validate_enforcement(&candidate)?;
    validate_executable_identity(options.binary, &binary_hash)?;
    ensure!(!process::is_interrupted(), "policy generation interrupted");
    manifest["validation"] = json!({
            "passed": true,
            "scope": options.workload.scope,
            "vm_validated": options.workload.vm_validated,
            "workloads": results.iter().map(|result| result["name"].clone()).collect::<Vec<_>>(),
            "workload_results": results,
            "kernel": std::fs::read_to_string("/proc/sys/kernel/osrelease")?.trim(),
            "traced_execs": observations.exec_count,
            "traced_processes": observations.process_count,
            "negative_enforcement": ["vm_native_network", "broker_vm_grants"],
    });
    std::fs::write(
        candidate.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    std::fs::write(candidate.join(".validated"), format!("{binary_hash}\n"))?;
    publish(&candidate, options.output)?;
    println!("validated seccomp artifacts: {}", options.output.display());
    Ok(())
}

pub(crate) fn run_worker(mut arguments: impl Iterator<Item = OsString>) -> Result<ExitCode> {
    use std::os::unix::process::CommandExt as _;

    let mode = arguments
        .next()
        .context("missing sandbox policy worker mode")?;
    let data = PathBuf::from(
        arguments
            .next()
            .context("missing sandbox policy worker data")?,
    );
    let executable = arguments
        .next()
        .context("missing sandbox policy workload executable")?;
    let mut command = Command::new(executable);
    command.args(arguments);
    if mode == "trace" {
        trace::run(&mut command, &data)
    } else if mode == "enforce" {
        let policy = seccomp::read_policy(&data)?;
        seccomp::install_policy(&policy)?;
        Err(command.exec()).context("executing workload under seccomp")
    } else {
        anyhow::bail!(
            "unknown sandbox policy worker mode: {}",
            mode.to_string_lossy()
        )
    }
}

fn validate_workload(options: &Options<'_>) -> Result<()> {
    if options.workload.vm_validated {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .context("native /dev/kvm is unavailable; VM validation requires KVM")?;
    }
    let mut header = [0; 20];
    std::fs::File::open(options.binary)?.read_exact(&mut header)?;
    let machine = if cfg!(target_arch = "x86_64") {
        62
    } else {
        183
    };
    ensure!(
        &header[..6] == b"\x7fELF\x02\x01"
            && u16::from_le_bytes([header[18], header[19]]) == machine,
        "policy generation requires a native 64-bit Linux ELF executable"
    );
    Ok(())
}

fn run_pass(
    command: &mut Command,
    timeout: Duration,
    diagnostics: &Path,
    phase: &str,
    name: &str,
) -> Result<Value> {
    let log = diagnostics.join(format!("{phase}-{name}.log"));
    println!("{phase}: {name}; log: {}", log.display());
    let started = Instant::now();
    process::run_logged(command, timeout, &log)?;
    let result = json!({"name": name, "passed": true, "seconds": started.elapsed().as_secs_f64()});
    std::fs::write(
        diagnostics.join(format!("{phase}-{name}-results.json")),
        serde_json::to_vec_pretty(&vec![&result])?,
    )?;
    Ok(result)
}

fn read_traces(directory: &Path) -> Result<Trace> {
    let mut combined = Trace::default();
    let mut next_process = 0_u32;
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let trace: Trace = serde_json::from_reader(std::fs::File::open(entry.path())?)
            .with_context(|| format!("reading syscall trace {}", entry.path().display()))?;
        let mut processes = BTreeMap::new();
        for (source, destination) in [
            (trace.calls, &mut combined.calls),
            (trace.ioctls, &mut combined.ioctls),
        ] {
            for (call, pids) in source {
                for pid in pids {
                    let mapped = if let Some(mapped) = processes.get(&pid) {
                        *mapped
                    } else {
                        next_process = next_process
                            .checked_add(1)
                            .context("too many traced processes")?;
                        processes.insert(pid, next_process);
                        next_process
                    };
                    destination.entry(call).or_default().insert(mapped);
                }
            }
        }
        combined.exec_count += trace.exec_count;
        combined.process_count += trace.process_count;
        for (role, observed) in trace.roles {
            let destination = combined.roles.entry(role).or_default();
            destination.exec_count += observed.exec_count;
            for (source, target) in [
                (observed.calls, &mut destination.calls),
                (observed.ioctls, &mut destination.ioctls),
            ] {
                for (call, pids) in source {
                    for pid in pids {
                        let mapped = processes
                            .get(&pid)
                            .context("role observation lacks a traced process")?;
                        target.entry(call).or_default().insert(*mapped);
                    }
                }
            }
        }
    }
    ensure!(
        combined.exec_count > 0 && !combined.calls.is_empty(),
        "no workload syscall traces were captured"
    );
    Ok(combined)
}

fn hash_file(path: &Path) -> Result<String> {
    Ok(hash_bytes(&std::fs::read(path)?))
}

fn validate_executable_identity(binary: &Path, expected_hash: &str) -> Result<()> {
    ensure!(
        hash_file(binary)? == expected_hash,
        "workload executable changed during policy generation"
    );
    Ok(())
}

fn publish(candidate: &Path, output: &Path) -> Result<()> {
    let parent = output
        .parent()
        .context("policy output needs a parent directory")?;
    std::fs::create_dir_all(parent)?;
    match std::fs::symlink_metadata(output) {
        Ok(metadata) => ensure!(
            metadata.is_symlink(),
            "output path must be a generator-owned symlink: {}",
            output.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let generation = tempfile::Builder::new()
        .prefix(".terra-policy-")
        .tempdir_in(parent)?;
    for name in artifact_names() {
        std::fs::copy(candidate.join(&name), generation.path().join(name))?;
    }
    let pointer = tempfile::Builder::new()
        .prefix(".terra-policy-pointer-")
        .tempdir_in(parent)?;
    let link = pointer.path().join("current");
    std::os::unix::fs::symlink(
        generation
            .path()
            .file_name()
            .context("policy generation has no name")?,
        &link,
    )?;
    ensure!(!process::is_interrupted(), "policy generation interrupted");
    std::fs::rename(&link, output)?;
    let _ = generation.keep();
    Ok(())
}

fn artifact_names() -> Vec<String> {
    Role::ALL
        .into_iter()
        .flat_map(|role| {
            [
                format!("{}.seccomp.json", role.name()),
                format!("{}.seccomp.bpf", role.name()),
            ]
        })
        .chain(["manifest.json".into(), ".validated".into()])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn executable_identity_gate_rejects_a_changed_binary() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let binary = directory.path().join("terra");
        std::fs::write(&binary, b"traced executable")?;
        let expected_hash = hash_file(&binary)?;
        validate_executable_identity(&binary, &expected_hash)?;
        std::fs::write(&binary, b"different executable")?;
        let error = validate_executable_identity(&binary, &expected_hash).unwrap_err();
        assert!(error.to_string().contains("executable changed"));
        Ok(())
    }

    #[test]
    fn trace_groups_keep_processes_distinct_and_reject_empty_results() {
        let directory = tempfile::tempdir().unwrap();
        assert!(read_traces(directory.path()).is_err());
        for name in ["first", "second"] {
            let trace = Trace {
                calls: BTreeMap::from([(1, BTreeSet::from([5]))]),
                ioctls: BTreeMap::new(),
                exec_count: 1,
                process_count: 1,
                roles: BTreeMap::new(),
            };
            std::fs::write(
                directory.path().join(name),
                serde_json::to_vec(&trace).unwrap(),
            )
            .unwrap();
        }
        let merged = read_traces(directory.path()).unwrap();
        assert_eq!(merged.calls[&1].len(), 2);
        assert_eq!((merged.exec_count, merged.process_count), (2, 2));
    }

    #[test]
    fn failed_enforcement_keeps_the_previous_generation() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("current");
        std::os::unix::fs::symlink("previous", &output)?;
        let options = Options {
            binary: Path::new("/bin/true"),
            output: &output,
            diagnostics: directory.path(),
            timeout: Duration::from_secs(5),
            workload: Workload {
                name: "custom",
                scope: "custom",
                vm_validated: false,
                enforced_only: &[],
            },
        };
        let mut phases = Vec::new();
        let error = generate(&options, |phase| {
            Ok(match phase {
                Phase::Collect { traces } => {
                    phases.push("collect");
                    let observations = Trace {
                        calls: BTreeMap::from([(
                            u32::try_from(libc::SYS_read)?,
                            BTreeSet::from([1]),
                        )]),
                        ioctls: BTreeMap::new(),
                        exec_count: 1,
                        process_count: 1,
                        roles: Role::ALL
                            .into_iter()
                            .map(|role| {
                                (
                                    role,
                                    trace::RoleTrace {
                                        calls: BTreeMap::from([(
                                            u32::try_from(libc::SYS_read).unwrap(),
                                            BTreeSet::from([1]),
                                        )]),
                                        ioctls: BTreeMap::new(),
                                        exec_count: 1,
                                    },
                                )
                            })
                            .collect(),
                    };
                    std::fs::write(
                        traces.join("workload.json"),
                        serde_json::to_vec(&observations)?,
                    )?;
                    Command::new("/bin/true")
                }
                Phase::Enforce { policy } => {
                    phases.push("enforce");
                    seccomp::read_policy(&policy.join("vm.seccomp.bpf"))?;
                    Command::new("/bin/false")
                }
                Phase::Validate { .. } => unreachable!(),
            })
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("command failed"));
        assert_eq!(phases, ["collect", "enforce"]);
        assert_eq!(std::fs::read_link(output)?, Path::new("previous"));
        Ok(())
    }

    #[test]
    fn publication_replaces_complete_generations_and_preserves_previous_on_failure() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let candidate = directory.path().join("candidate");
        std::fs::create_dir(&candidate)?;
        let artifacts = artifact_names();
        for name in &artifacts {
            std::fs::write(candidate.join(name), format!("first:{name}"))?;
        }
        let output = directory.path().join("current");
        publish(&candidate, &output)?;
        let first_generation = std::fs::read_link(&output)?;
        for name in &artifacts {
            assert_eq!(
                std::fs::read_to_string(output.join(name))?,
                format!("first:{name}")
            );
            std::fs::write(candidate.join(name), format!("second:{name}"))?;
        }
        publish(&candidate, &output)?;
        let second_generation = std::fs::read_link(&output)?;
        assert_ne!(first_generation, second_generation);
        for missing in &artifacts {
            std::fs::remove_file(candidate.join(missing))?;
            assert!(publish(&candidate, &output).is_err());
            assert_eq!(std::fs::read_link(&output)?, second_generation);
            for name in &artifacts {
                assert_eq!(
                    std::fs::read_to_string(output.join(name))?,
                    format!("second:{name}")
                );
                assert_eq!(
                    std::fs::read_to_string(directory.path().join(&first_generation).join(name))?,
                    format!("first:{name}")
                );
            }
            std::fs::write(candidate.join(missing), format!("third:{missing}"))?;
        }
        assert!(publish(&candidate, &candidate).is_err());
        let regular_output = directory.path().join("regular-file");
        std::fs::write(&regular_output, b"keep")?;
        assert!(publish(&candidate, &regular_output).is_err());
        assert_eq!(std::fs::read(regular_output)?, b"keep");
        Ok(())
    }
}
