//! Bounded workload execution, output capture, and descendant cleanup.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::sys;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) fn is_interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}

#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) fn install_interrupt_handler() -> Result<()> {
    extern "C" fn interrupt(_signal: libc::c_int) {
        INTERRUPTED.store(true, Ordering::Relaxed);
    }
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: the handler only stores an atomic flag and has the signal callback ABI.
        if unsafe { libc::signal(signal, interrupt as *const () as libc::sighandler_t) }
            == libc::SIG_ERR
        {
            return Err(std::io::Error::last_os_error())
                .context("installing workload signal handler");
        }
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) fn install_interrupt_handler() -> Result<()> {
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
        SetConsoleCtrlHandler,
    };
    unsafe extern "system" fn interrupt(event: u32) -> i32 {
        match event {
            CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT
            | CTRL_SHUTDOWN_EVENT => {
                INTERRUPTED.store(true, Ordering::Relaxed);
                1
            }
            _ => 0,
        }
    }
    // SAFETY: the handler has the Windows console callback ABI and remains valid for the process.
    anyhow::ensure!(
        unsafe { SetConsoleCtrlHandler(Some(interrupt), 1) } != 0,
        "installing workload console handler: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

pub(crate) fn run_capture(command: &mut Command, timeout: Duration) -> Result<Output> {
    capture_output(command, timeout, true)
}

pub(crate) fn run_cleanup(command: &mut Command, timeout: Duration) -> Result<Output> {
    capture_output(command, timeout, false)
}

fn capture_output(command: &mut Command, timeout: Duration, can_interrupt: bool) -> Result<Output> {
    let mut stdout = tempfile::tempfile().context("creating workload stdout capture")?;
    let mut stderr = tempfile::tempfile().context("creating workload stderr capture")?;
    command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?);
    let mut child = SupervisedChild {
        child: command.spawn().context("starting workload command")?,
        guard: None,
        is_reaped: false,
    };
    let status = child.wait(timeout, can_interrupt)?;
    Ok(Output {
        status,
        stdout: read_capture(&mut stdout)?,
        stderr: read_capture(&mut stderr)?,
    })
}

pub(crate) fn run_logged(command: &mut Command, timeout: Duration, log: &Path) -> Result<()> {
    let mut tagged_processes = TaggedProcesses::from_command(command);
    let output = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(log)
        .with_context(|| format!("creating workload log {}", log.display()))?;
    command
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(output);
    let guard = sys::supervise_vm_child(command, true).context("supervising workload command")?;
    let mut child = SupervisedChild {
        child: command.spawn().context("starting workload command")?,
        guard,
        is_reaped: false,
    };
    if let Some(guard) = &child.guard {
        sys::attach_vm_child(guard, &child.child).context("attaching workload command")?;
    }
    let status = child
        .wait(timeout, true)
        .with_context(|| format!("workload log: {}", log.display()))?;
    drop(child);
    tagged_processes
        .finish()
        .with_context(|| format!("cleaning up workload processes; log: {}", log.display()))?;
    anyhow::ensure!(
        status.success(),
        "workload command failed with {status}; log: {}",
        log.display()
    );
    Ok(())
}

fn read_capture(file: &mut File) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut output = Vec::new();
    file.read_to_end(&mut output)?;
    Ok(output)
}

struct SupervisedChild {
    child: Child,
    guard: Option<sys::VmChildGuard>,
    is_reaped: bool,
}

impl SupervisedChild {
    fn wait(&mut self, timeout: Duration, can_interrupt: bool) -> Result<ExitStatus> {
        let deadline = sys::deadline_after(timeout);
        loop {
            anyhow::ensure!(!can_interrupt || !is_interrupted(), "workload interrupted");
            if let Some(status) = self
                .child
                .try_wait()
                .context("waiting for workload command")?
            {
                self.is_reaped = true;
                return Ok(status);
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "workload command timed out after {timeout:?}"
            );
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

impl Drop for SupervisedChild {
    fn drop(&mut self) {
        if !self.is_reaped {
            if self.guard.is_some() {
                let _ = sys::kill_vm_child(&mut self.child);
            } else {
                let _ = self.child.kill();
            }
        }
        self.guard.take();
        if !self.is_reaped {
            let deadline = sys::deadline_after(CLEANUP_TIMEOUT);
            while Instant::now() < deadline {
                match self.child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) => std::thread::sleep(POLL_INTERVAL),
                }
            }
        }
    }
}

struct TaggedProcesses {
    #[cfg(target_os = "linux")]
    run_id: Option<std::ffi::OsString>,
}

impl TaggedProcesses {
    fn from_command(command: &Command) -> Self {
        #[cfg(target_os = "linux")]
        {
            Self {
                run_id: command.get_envs().find_map(|(key, value)| {
                    (key == "TERRA_WORKLOAD_RUN_ID")
                        .then(|| value.map(ToOwned::to_owned))
                        .flatten()
                }),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = command;
            Self {}
        }
    }

    #[allow(
        clippy::unnecessary_wraps,
        clippy::unused_self,
        reason = "Linux cleanup uses the retained run id and can fail"
    )]
    fn finish(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            if let Some(run_id) = &self.run_id {
                cleanup_tagged_processes(run_id, sys::terminate_process)?;
            }
            self.run_id = None;
        }
        Ok(())
    }
}

impl Drop for TaggedProcesses {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(run_id) = &self.run_id {
            let _ = cleanup_tagged_processes(run_id, sys::terminate_process);
        }
    }
}

#[cfg(target_os = "linux")]
fn cleanup_tagged_processes(
    run_id: &std::ffi::OsStr,
    terminate: impl Fn(u32, Option<u64>) -> std::io::Result<sys::SignalResult>,
) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    if run_id.is_empty() {
        return Ok(());
    }
    let mut environment_entry = b"TERRA_WORKLOAD_RUN_ID=".to_vec();
    environment_entry.extend_from_slice(run_id.as_bytes());
    let deadline = sys::deadline_after(CLEANUP_TIMEOUT);
    let mut tagged_identities = std::collections::HashMap::new();
    loop {
        let entries = std::fs::read_dir("/proc").context("listing workload processes")?;
        let mut remaining = Vec::new();
        for entry in entries {
            let entry = entry.context("reading workload process entry")?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            if pid == std::process::id() {
                continue;
            }
            let Some(started_at) = sys::read_process_start_time(pid) else {
                anyhow::ensure!(
                    !tagged_identities.contains_key(&pid)
                        || !entry.path().try_exists().with_context(|| {
                            format!("checking owned workload process {pid}")
                        })?,
                    "cannot verify owned workload process {pid} identity"
                );
                continue;
            };
            let environment = match std::fs::read(entry.path().join("environ")) {
                Ok(environment) => environment,
                Err(error) => {
                    if tagged_identities.get(&pid) == Some(&started_at)
                        && error.kind() != std::io::ErrorKind::NotFound
                    {
                        return Err(error).with_context(|| {
                            format!("reading owned workload process {pid} environment")
                        });
                    }
                    continue;
                }
            };
            if environment
                .split(|byte| *byte == 0)
                .any(|entry| entry == environment_entry)
            {
                tagged_identities.insert(pid, started_at);
                remaining.push(pid);
                terminate(pid, Some(started_at))
                    .with_context(|| format!("terminating owned workload process {pid}"))?;
            }
        }
        if remaining.is_empty() {
            return Ok(());
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "owned workload processes survived cleanup: {remaining:?}"
        );
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::io::Write;

    fn build_test_command(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "process::tests::process_test_child",
                "--nocapture",
            ])
            .env("TERRA_TEST_PROCESS_MODE", mode);
        command
    }

    #[test]
    #[allow(unsafe_code)]
    fn process_test_child() {
        let Ok(mode) = std::env::var("TERRA_TEST_PROCESS_MODE") else {
            return;
        };
        match mode.as_str() {
            "output" => {
                std::io::stdout()
                    .write_all(&vec![b'o'; 1024 * 1024])
                    .unwrap();
                std::io::stderr()
                    .write_all(&vec![b'e'; 1024 * 1024])
                    .unwrap();
                std::process::exit(12);
            }
            "wait" => std::thread::sleep(Duration::from_secs(30)),
            #[cfg(unix)]
            "interrupt" => {
                install_interrupt_handler().unwrap();
                let directory = tempfile::tempdir().unwrap();
                let log = directory.path().join("interrupt.log");
                let signal = std::thread::spawn(|| {
                    std::thread::sleep(Duration::from_millis(200));
                    // SAFETY: getpid identifies this isolated test process; SIGTERM uses its installed handler.
                    assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGTERM) }, 0);
                });
                let error = run_logged(
                    &mut build_test_command("wait"),
                    Duration::from_secs(10),
                    &log,
                )
                .unwrap_err();
                signal.join().unwrap();
                assert!(format!("{error:#}").contains("interrupted"));
                let cleanup =
                    run_cleanup(&mut build_test_command("output"), Duration::from_secs(10))
                        .unwrap();
                assert_eq!(cleanup.status.code(), Some(12));
                let error =
                    run_cleanup(&mut build_test_command("wait"), Duration::from_millis(100))
                        .unwrap_err();
                assert!(error.to_string().contains("timed out"));
            }
            #[cfg(target_os = "linux")]
            "detach" => {
                let mut command = build_test_command("wait");
                assert!(
                    sys::supervise_vm_child(&mut command, false)
                        .unwrap()
                        .is_none()
                );
                #[expect(
                    clippy::zombie_processes,
                    reason = "the outer supervisor must clean up this detached descendant"
                )]
                let child = command.spawn().unwrap();
                std::fs::write(
                    std::env::var_os("TERRA_TEST_PROCESS_PID").unwrap(),
                    child.id().to_string(),
                )
                .unwrap();
            }
            _ => unreachable!("unknown child mode"),
        }
    }

    #[test]
    fn capture_handles_large_output_and_exit_status() {
        let output =
            run_capture(&mut build_test_command("output"), Duration::from_secs(10)).unwrap();
        assert_eq!(output.status.code(), Some(12));
        assert!(
            output
                .stdout
                .windows(1024 * 1024)
                .any(|bytes| bytes.iter().all(|byte| *byte == b'o'))
        );
        assert_eq!(output.stderr, vec![b'e'; 1024 * 1024]);
    }

    #[test]
    fn capture_timeout_kills_and_reaps_child() {
        let started = Instant::now();
        let error =
            run_capture(&mut build_test_command("wait"), Duration::from_millis(100)).unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn logged_failure_keeps_output_and_names_log() {
        let directory = tempfile::tempdir().unwrap();
        let log = directory.path().join("output.log");
        let error = run_logged(
            &mut build_test_command("output"),
            Duration::from_secs(10),
            &log,
        )
        .unwrap_err();
        assert!(error.to_string().contains("12"));
        assert!(error.to_string().contains(log.to_str().unwrap()));
        let output = std::fs::read(log).unwrap();
        assert!(output.contains(&b'o'));
        assert!(output.contains(&b'e'));
    }

    #[cfg(unix)]
    #[test]
    fn logged_interrupt_cleans_up_in_an_isolated_process() {
        let output = run_capture(
            &mut build_test_command("interrupt"),
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(output.status.success(), "{output:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capture_success_keeps_detached_children_for_the_outer_suite() {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("child.pid");
        let mut command = build_test_command("detach");
        command
            .env("TERRA_WORKLOAD_RUN_ID", directory.path())
            .env("TERRA_TEST_PROCESS_PID", &pid_file);
        let output = run_capture(&mut command, Duration::from_secs(10)).unwrap();
        let pid: u32 = std::fs::read_to_string(pid_file).unwrap().parse().unwrap();
        let started_at = sys::read_process_start_time(pid);
        let is_running = std::fs::read(format!("/proc/{pid}/environ"))
            .is_ok_and(|environment| !environment.is_empty());
        sys::terminate_process(pid, started_at).unwrap();
        assert!(output.status.success());
        assert!(is_running);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn logged_success_cleans_only_its_tagged_detached_children() {
        let directory = tempfile::tempdir().unwrap();
        let unrelated = build_test_command("wait").spawn().unwrap();
        let mut unrelated = SupervisedChild {
            child: unrelated,
            guard: None,
            is_reaped: false,
        };
        let pid_file = directory.path().join("child.pid");
        let log = directory.path().join("output.log");
        let mut command = build_test_command("detach");
        command
            .env("TERRA_WORKLOAD_RUN_ID", directory.path())
            .env("TERRA_TEST_PROCESS_PID", &pid_file);
        run_logged(&mut command, Duration::from_secs(10), &log).unwrap();
        let pid: u32 = std::fs::read_to_string(pid_file).unwrap().parse().unwrap();
        let deadline = sys::deadline_after(Duration::from_secs(2));
        loop {
            let environment = std::fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
            if environment.is_empty() {
                break;
            }
            assert!(Instant::now() < deadline, "tagged child survived");
            std::thread::sleep(POLL_INTERVAL);
        }
        assert!(unrelated.child.try_wait().unwrap().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tagged_cleanup_rejects_survivors_and_reports_signal_errors() {
        let directory = tempfile::tempdir().unwrap();
        let mut command = build_test_command("wait");
        command
            .env("TERRA_WORKLOAD_RUN_ID", directory.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = SupervisedChild {
            child: command.spawn().unwrap(),
            guard: None,
            is_reaped: false,
        };
        let error = cleanup_tagged_processes(directory.path().as_os_str(), |_, _| {
            Ok(sys::SignalResult::IdentityUnknown)
        })
        .unwrap_err();
        assert!(error.to_string().contains("survived cleanup"));
        assert!(error.to_string().contains(&child.child.id().to_string()));
        let error = cleanup_tagged_processes(directory.path().as_os_str(), |_, _| {
            Err(std::io::ErrorKind::PermissionDenied.into())
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("permission denied"));
        assert!(child.child.try_wait().unwrap().is_none());
    }
}
