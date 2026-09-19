//! Native-hypervisor demand-memory regression.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MIB_KIB: u64 = 1024;
const SAMPLE_INTERVAL: Duration = Duration::from_millis(200);
const MEMORY_SETTLE_TIMEOUT: Duration = Duration::from_secs(15);

struct RunningBox {
    terra: PathBuf,
    home: PathBuf,
    project: PathBuf,
}

impl RunningBox {
    fn run(&self, args: &[&str]) -> String {
        let output = run_command(&self.terra, &self.home, args, Duration::from_secs(30));
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "terra command {args:?} exited {:?}: {stderr}",
            output.status.code()
        );
        stdout
    }

    fn exec(&self, args: &[&str]) -> String {
        let mut command = vec![
            "mem",
            "exec",
            "-T",
            "--agent-timeout",
            "15",
            "--project",
            self.project.to_str().unwrap(),
            "--",
        ];
        command.extend_from_slice(args);
        self.run(&command)
    }

    fn logs(&self) -> String {
        let project = self.project.to_str().unwrap();
        let output = run_command(
            &self.terra,
            &self.home,
            &["logs", "--project", project],
            Duration::from_secs(10),
        );
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

impl Drop for RunningBox {
    fn drop(&mut self) {
        let project = self.project.to_str().unwrap();
        let _ = run_command(
            &self.terra,
            &self.home,
            &["stop", "-t", "5", "--project", project],
            Duration::from_secs(10),
        );
    }
}

fn run_command(terra: &Path, home: &Path, args: &[&str], timeout: Duration) -> Output {
    let mut child = Command::new(terra)
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("running terra {args:?}: {error}"));
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().expect("collecting terra output"),
            Ok(None) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let output = child
                    .wait_with_output()
                    .expect("collecting timed-out terra output");
                panic!(
                    "terra command {args:?} exceeded {} seconds:\n{}{}",
                    timeout.as_secs(),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(error) => panic!("waiting for terra {args:?}: {error}"),
        }
    }
}

fn vm_pid(running: &RunningBox) -> u32 {
    let project = running.project.to_str().unwrap();
    let listing = running.run(&["ls", "--tsv", "--project", project]);
    let files = listing
        .lines()
        .find_map(|line| line.split('\t').nth(3))
        .unwrap_or_else(|| panic!("`terra ls --tsv` did not report box files:\n{listing}"));
    std::fs::read_to_string(Path::new(files).join("terra.pid"))
        .unwrap_or_else(|error| panic!("reading {files}/terra.pid: {error}"))
        .split_whitespace()
        .next()
        .expect("pid field")
        .parse()
        .unwrap_or_else(|error| panic!("parsing {files}/terra.pid: {error}"))
}

fn rss_kib(pid: u32) -> std::io::Result<u64> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_memory(),
    );
    system
        .process(pid)
        .map(|process| process.memory() / 1024)
        .ok_or_else(|| std::io::Error::other("VM process is absent"))
}

fn wait_for_rss(
    running: &RunningBox,
    pid: u32,
    description: &str,
    mut predicate: impl FnMut(u64) -> bool,
) -> u64 {
    let started = Instant::now();
    let mut samples = Vec::new();
    loop {
        match rss_kib(pid) {
            Ok(rss) => {
                samples.push(rss.to_string());
                if predicate(rss) {
                    return rss;
                }
            }
            Err(error) => samples.push(format!("error: {error}")),
        }
        assert!(
            started.elapsed() < MEMORY_SETTLE_TIMEOUT,
            "{description} after {} seconds; resident memory samples (KiB): {samples:?}\nbox logs:\n{}",
            MEMORY_SETTLE_TIMEOUT.as_secs(),
            running.logs()
        );
        thread::sleep(SAMPLE_INTERVAL);
    }
}

fn wait_for_idle_rss(running: &RunningBox, pid: u32) -> u64 {
    let mut previous = 0;
    let mut settled_since = Instant::now();
    wait_for_rss(
        running,
        pid,
        "idle demand-backed resident memory did not settle below 512 MiB",
        |rss| {
            if rss.abs_diff(previous) > 16 * MIB_KIB {
                previous = rss;
                settled_since = Instant::now();
            }
            rss < 512 * MIB_KIB && settled_since.elapsed() >= Duration::from_secs(3)
        },
    )
}

#[test]
#[ignore = "boots a real 2 GiB microVM and requires a native hypervisor: cargo test -p terra --test memory -- --ignored"]
fn guest_memory_grows_and_shrinks_with_its_working_set() {
    let terra = std::env::var_os("TERRA_BIN")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_terra")), PathBuf::from);
    assert!(
        terra.exists(),
        "terra binary not found: {}",
        terra.display()
    );

    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("h");
    let project = temp.path().join("p");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&project).unwrap();
    let recipe = project.join("mem.yaml");
    std::fs::write(
        &recipe,
        "hw: {cpus: 2, mem_mib: 2048}\nworkload:\n  entrypoint: /bin/sh\n  args: [-ec, 'while :; do sleep 60; done']\n",
    )
    .unwrap();

    let recipe_path = recipe.to_str().unwrap();
    let project_path = project.to_str().unwrap();
    let setup = run_command(
        &terra,
        &home,
        &[recipe_path, "setup", "--project", project_path],
        Duration::from_mins(1),
    );
    assert!(
        setup.status.success(),
        "setting up memory box failed:\n{}{}",
        String::from_utf8_lossy(&setup.stdout),
        String::from_utf8_lossy(&setup.stderr)
    );

    let running = RunningBox {
        terra,
        home,
        project: project.clone(),
    };
    running.run(&["mem", "-d", "--project", project_path]);
    running.exec(&["true"]);

    let pid = vm_pid(&running);
    let initial = wait_for_rss(
        &running,
        pid,
        "initial demand-backed resident memory did not settle below 512 MiB",
        |rss| rss < 512 * MIB_KIB,
    );

    for cycle in 1..=2 {
        let before = wait_for_idle_rss(&running, pid);
        running.exec(&[
            "dd",
            "if=/dev/zero",
            "of=/dev/shm/terra-memory-test",
            "bs=1M",
            "count=256",
        ]);
        let grown = wait_for_rss(
            &running,
            pid,
            &format!("resident memory did not grow by 128 MiB from {before} KiB in cycle {cycle}"),
            |rss| rss >= before + 128 * MIB_KIB,
        );
        running.exec(&["rm", "-f", "/dev/shm/terra-memory-test"]);
        let shrunk = wait_for_rss(
            &running,
            pid,
            &format!("resident memory did not release 128 MiB in cycle {cycle}"),
            |rss| rss + 128 * MIB_KIB <= grown,
        );
        println!(
            "cycle {cycle}: initial={initial} KiB, before={before} KiB, grown={grown} KiB, shrunk={shrunk} KiB"
        );
        assert!(
            grown >= before + 128 * MIB_KIB && shrunk + 128 * MIB_KIB <= grown,
            "cycle {cycle} did not grow then shrink: before={before} KiB, grown={grown} KiB, shrunk={shrunk} KiB, initial={initial} KiB"
        );
    }
}
