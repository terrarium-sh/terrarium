//! Supervised child processes and the interrupt flag.

use std::process::{Child, ExitStatus};
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

/// Resolves on the first interrupt delivered after this call; one that arrived earlier shows in
/// [`is_interrupted`]. Call it inside a tokio runtime.
#[cfg(unix)]
pub(crate) fn interrupt_signal() -> Result<impl std::future::Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt()).context("watching SIGINT")?;
    let mut terminate = signal(SignalKind::terminate()).context("watching SIGTERM")?;
    let mut hangup = signal(SignalKind::hangup()).context("watching SIGHUP")?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
            _ = hangup.recv() => {}
        }
    })
}

/// Resolves on the first console interrupt delivered after this call; one that arrived earlier
/// shows in [`is_interrupted`]. Call it inside a tokio runtime.
#[cfg(windows)]
pub(crate) fn interrupt_signal() -> Result<impl std::future::Future<Output = ()>> {
    use tokio::signal::windows;
    let mut ctrl_c = windows::ctrl_c().context("watching Ctrl+C")?;
    let mut ctrl_break = windows::ctrl_break().context("watching Ctrl+Break")?;
    let mut ctrl_close = windows::ctrl_close().context("watching console close")?;
    let mut ctrl_logoff = windows::ctrl_logoff().context("watching logoff")?;
    let mut ctrl_shutdown = windows::ctrl_shutdown().context("watching shutdown")?;
    Ok(async move {
        tokio::select! {
            _ = ctrl_c.recv() => {}
            _ = ctrl_break.recv() => {}
            _ = ctrl_close.recv() => {}
            _ = ctrl_logoff.recv() => {}
            _ = ctrl_shutdown.recv() => {}
        }
    })
}

#[cfg(test)]
pub(crate) fn run_capture(
    command: &mut std::process::Command,
    timeout: std::time::Duration,
) -> Result<std::process::Output> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    use std::process::Stdio;

    fn read_capture(file: &mut std::fs::File) -> Result<Vec<u8>> {
        file.seek(SeekFrom::Start(0))?;
        let mut output = Vec::new();
        file.read_to_end(&mut output)?;
        Ok(output)
    }

    let mut stdout = tempfile::tempfile().context("creating workload stdout capture")?;
    let mut stderr = tempfile::tempfile().context("creating workload stderr capture")?;
    command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?);
    let mut child =
        SupervisedChild::new(command.spawn().context("starting workload command")?, None)?;
    let status = child.wait(timeout, true)?;
    Ok(std::process::Output {
        status,
        stdout: read_capture(&mut stdout)?,
        stderr: read_capture(&mut stderr)?,
    })
}

pub(crate) struct SupervisedChild {
    child: Child,
    guard: Option<sys::VmChildGuard>,
    _launch_resources: Option<terra_sandbox::LaunchResources>,
    is_reaped: bool,
}

impl SupervisedChild {
    #[cfg(test)]
    pub(crate) fn new(child: Child, guard: Option<sys::VmChildGuard>) -> Result<Self> {
        Self::attach(child, guard, None)
    }

    pub(crate) fn from_launch(
        spawned: terra_sandbox::SpawnedLaunch,
        guard: Option<sys::VmChildGuard>,
    ) -> Result<Self> {
        Self::attach(spawned.child, guard, Some(spawned.resources))
    }

    fn attach(
        child: Child,
        guard: Option<sys::VmChildGuard>,
        launch_resources: Option<terra_sandbox::LaunchResources>,
    ) -> Result<Self> {
        let supervised = Self {
            child,
            guard,
            _launch_resources: launch_resources,
            is_reaped: false,
        };
        if let Some(guard) = &supervised.guard {
            sys::attach_vm_child(guard, &supervised.child)?;
        }
        Ok(supervised)
    }

    pub(crate) fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.is_reaped = true;
        }
        Ok(status)
    }

    pub(crate) fn wait(&mut self, timeout: Duration, can_interrupt: bool) -> Result<ExitStatus> {
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

/// Resolves once `child` has exited, leaving it for the owner to reap.
pub(crate) fn exited(child: &Child) -> Result<impl std::future::Future<Output = ()> + use<>> {
    let block_until_exited = exit_waiter(child)?;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("child-exit".into())
        .spawn(move || {
            block_until_exited();
            let _ = sender.send(());
        })
        .context("starting child exit watcher")?;
    Ok(async move {
        let _ = receiver.await;
    })
}

/// Blocks until `child` exits without reaping it; returns early if it was already reaped.
#[cfg(unix)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "Windows duplicates the process handle, which can fail"
)]
fn exit_waiter(child: &Child) -> Result<impl FnOnce() + Send + use<>> {
    use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};
    let pid = Pid::from_child(child);
    Ok(move || {
        while matches!(
            waitid(
                WaitId::Pid(pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOWAIT
            ),
            Err(rustix::io::Errno::INTR)
        ) {}
    })
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn exit_waiter(child: &Child) -> Result<impl FnOnce() + Send + use<>> {
    use std::os::windows::io::{AsHandle as _, AsRawHandle as _};
    use windows_sys::Win32::System::Threading::{INFINITE, WaitForSingleObject};
    let handle = child
        .as_handle()
        .try_clone_to_owned()
        .context("duplicating child process handle")?;
    Ok(move || {
        // SAFETY: the duplicated handle stays open for this call.
        unsafe { WaitForSingleObject(handle.as_raw_handle(), INFINITE) };
    })
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::io::Write;
    use std::process::Command;

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
                let signal = std::thread::spawn(|| {
                    std::thread::sleep(Duration::from_millis(200));
                    // SAFETY: getpid identifies this isolated test process; SIGTERM uses its installed handler.
                    assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGTERM) }, 0);
                });
                let error = run_capture(&mut build_test_command("wait"), Duration::from_secs(10))
                    .unwrap_err();
                signal.join().unwrap();
                assert!(format!("{error:#}").contains("interrupted"));
            }
            #[cfg(unix)]
            "signal" => {
                install_interrupt_handler().unwrap();
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let interrupt = {
                    let _context = runtime.enter();
                    interrupt_signal().unwrap()
                };
                // SAFETY: getpid identifies this isolated test process; SIGTERM uses its installed handler.
                assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGTERM) }, 0);
                runtime
                    .block_on(async {
                        tokio::time::timeout(Duration::from_secs(5), interrupt).await
                    })
                    .unwrap();
                assert!(is_interrupted());
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

    /// The exit watcher stays pending while the child runs, resolves once it exits, and leaves
    /// the exit status for the owner to reap.
    #[test]
    fn exited_resolves_on_exit_and_leaves_the_child_to_reap() {
        use std::process::Stdio;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let running = build_test_command("wait")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let running = SupervisedChild::new(running, None).unwrap();
        let still_running = exited(&running.child).unwrap();
        assert!(
            runtime
                .block_on(async {
                    tokio::time::timeout(Duration::from_millis(200), still_running).await
                })
                .is_err()
        );
        drop(running);

        let mut exiting = build_test_command("output")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let has_exited = exited(&exiting).unwrap();
        runtime
            .block_on(async { tokio::time::timeout(Duration::from_secs(10), has_exited).await })
            .unwrap();
        assert_eq!(exiting.try_wait().unwrap().unwrap().code(), Some(12));
    }

    #[test]
    fn capture_timeout_kills_and_reaps_child() {
        let started = Instant::now();
        let error =
            run_capture(&mut build_test_command("wait"), Duration::from_millis(100)).unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    /// A signal resolves the interrupt future and, through the chained handler, still sets the
    /// interrupt flag.
    #[cfg(unix)]
    #[test]
    fn an_interrupt_signal_resolves_the_future_and_sets_the_flag_in_an_isolated_process() {
        let output =
            run_capture(&mut build_test_command("signal"), Duration::from_secs(10)).unwrap();
        assert!(output.status.success(), "{output:?}");
    }

    #[cfg(unix)]
    #[test]
    fn capture_interrupt_is_reported_in_an_isolated_process() {
        let output = run_capture(
            &mut build_test_command("interrupt"),
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(output.status.success(), "{output:?}");
    }
}
