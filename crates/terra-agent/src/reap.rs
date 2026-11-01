//! PID 1's orphan reaper.

use crate::lock_or_abort;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::process::{Child, Command, ExitStatus};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Where the reaper leaves an owned child's status if it collects it first.
type ExitSlot = Arc<Mutex<Option<ExitStatus>>>;

struct OwnedChild {
    pid: rustix::process::Pid,
    status: ExitSlot,
}

pub(crate) struct OwnedPidfd {
    pidfd: OwnedFd,
    leader: rustix::process::Pid,
    status: ExitSlot,
}

impl AsFd for OwnedPidfd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }
}

impl OwnedPidfd {
    pub(crate) fn leader(&self) -> rustix::process::Pid {
        self.leader
    }

    /// Signals the process group while preventing the orphan reaper from releasing its leader PID.
    pub(crate) fn signal_group(&self, sig: rustix::process::Signal) {
        let owned = lock_or_abort(&OWNED);
        if lock_or_abort(&self.status).is_none()
            && owned
                .iter()
                .any(|child| Arc::ptr_eq(&child.status, &self.status))
        {
            let _ = rustix::process::kill_process_group(self.leader, sig);
        }
        drop(owned);
        let _ = rustix::process::pidfd_send_signal(self, sig);
    }

    pub(crate) async fn stop_gracefully(&self, grace: std::time::Duration) {
        let _ = rustix::process::pidfd_send_signal(self, rustix::process::Signal::TERM);
        let ready = self.pidfd.try_clone().and_then(crate::into_async_fd);
        if let Ok(ready) = ready
            && matches!(
                tokio::time::timeout(grace, ready.readable()).await,
                Ok(Ok(_))
            )
        {
            return;
        }
        let _ = rustix::process::pidfd_send_signal(self, rustix::process::Signal::KILL);
    }
}

static OWNED: Mutex<Vec<OwnedChild>> = Mutex::new(Vec::new());

fn register_owned(owned: &mut Vec<OwnedChild>, pid: rustix::process::Pid) -> ExitSlot {
    let status = Arc::new(Mutex::new(None));
    owned.retain(|owned_child| owned_child.pid != pid);
    owned.push(OwnedChild {
        pid,
        status: status.clone(),
    });
    status
}

/// Spawns a child whose exit status is preserved even if reaped by the orphan reaper.
pub(crate) fn spawn_owned<E>(
    spawn: impl FnOnce() -> Result<Child, E>,
) -> Result<(Child, OwnedPidfd), E>
where
    E: From<std::io::Error>,
{
    let mut owned = lock_or_abort(&OWNED);
    let mut child = spawn()?;
    let pid = rustix::process::Pid::from_child(&child);
    let pidfd = match rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) {
        Ok(pidfd) => pidfd,
        Err(error) => {
            drop(owned);
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::from(error).into());
        }
    };
    let status = register_owned(&mut owned, pid);
    Ok((
        child,
        OwnedPidfd {
            pidfd,
            leader: pid,
            status,
        },
    ))
}

/// Runs `command` in its own process group; a timeout or cancellation kills the group, reaps it,
/// and becomes the error.
pub(crate) async fn run_or_kill(
    command: &mut Command,
    timeout: Duration,
    cancellation: &CancellationToken,
) -> std::io::Result<ExitStatus> {
    use std::os::unix::process::CommandExt as _;

    let (_child, pidfd) = spawn_owned(|| command.process_group(0).spawn())?;
    let interruption = tokio::select! {
        status = wait_owned(&pidfd) => return status,
        () = cancellation.cancelled() => {
            std::io::Error::new(std::io::ErrorKind::Interrupted, "command cancelled")
        }
        () = tokio::time::sleep(timeout) => std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("timed out after {timeout:?}"),
        ),
    };
    pidfd.signal_group(rustix::process::Signal::KILL);
    let _ = wait_owned(&pidfd).await;
    Err(interruption)
}

pub(crate) async fn wait_owned(pidfd: &OwnedPidfd) -> std::io::Result<ExitStatus> {
    let pidfd_ready = crate::into_async_fd(pidfd.pidfd.try_clone()?)?;
    loop {
        if let Some(status) = collect_status(pidfd)? {
            return Ok(status);
        }
        let mut ready = pidfd_ready.readable().await?;
        if let Some(status) = collect_status(pidfd)? {
            return Ok(status);
        }
        ready.clear_ready();
    }
}

fn collect_status(pidfd: &OwnedPidfd) -> std::io::Result<Option<ExitStatus>> {
    use std::os::unix::process::ExitStatusExt;

    let mut owned = lock_or_abort(&OWNED);
    let reaped = lock_or_abort(&pidfd.status).take();
    let status = match reaped {
        Some(status) => status,
        None => match rustix::process::waitid(
            rustix::process::WaitId::PidFd(pidfd.as_fd()),
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOHANG,
        ) {
            Ok(Some(status)) => {
                let raw = status
                    .exit_status()
                    .map(|code| code << 8)
                    .or_else(|| {
                        status
                            .terminating_signal()
                            .map(|signal| signal | if status.dumped() { 0x80 } else { 0 })
                    })
                    .ok_or_else(|| std::io::Error::other("child exited without a status"))?;
                ExitStatus::from_raw(raw)
            }
            Ok(None) | Err(rustix::io::Errno::CHILD) => return Ok(None),
            Err(error) => return Err(error.into()),
        },
    };
    owned.retain(|child| !Arc::ptr_eq(&child.status, &pidfd.status));
    Ok(Some(status))
}

pub(crate) async fn watch_orphans(cancellation: CancellationToken) {
    let Ok(mut signals) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
    else {
        return;
    };
    while reap_one_orphan() {}
    while matches!(
        cancellation.run_until_cancelled(signals.recv()).await,
        Some(Some(()))
    ) {
        while reap_one_orphan() {}
    }
}

fn reap_one_orphan() -> bool {
    let owned = lock_or_abort(&OWNED);
    let Ok(Some((pid, status))) = rustix::process::wait(rustix::process::WaitOptions::NOHANG)
    else {
        return false;
    };
    if let Some(child) = owned.iter().find(|c| c.pid == pid) {
        use std::os::unix::process::ExitStatusExt;
        *lock_or_abort(&child.status) = Some(ExitStatus::from_raw(status.as_raw()));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point: a child nobody waits on is reaped, and one the agent
    /// took through [`spawn_owned`] is left for its own caller to collect.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_orphan_is_reaped_and_an_owned_child_is_left_alone() {
        let (owned_child, pidfd) =
            spawn_owned(|| Command::new("/bin/sh").arg("-c").arg("exit 7").spawn()).unwrap();
        let orphan = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .unwrap();
        let orphan_pid = rustix::process::Pid::from_child(&orphan);
        std::mem::forget(orphan);

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let gone = |pid: rustix::process::Pid| {
            rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).is_err()
        };
        while !gone(orphan_pid) && std::time::Instant::now() < deadline {
            reap_one_orphan();
        }
        assert!(gone(orphan_pid), "the orphan was never reaped");

        assert_eq!(wait_owned(&pidfd).await.unwrap().code(), Some(7));
        assert!(
            !OWNED
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.pid == rustix::process::Pid::from_child(&owned_child)),
            "a collected child is still registered"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_owned_status_survives_the_reaper_before_its_waiter() {
        let (child, pidfd) =
            spawn_owned(|| Command::new("/bin/sh").arg("-c").arg("exit 7").spawn()).unwrap();
        let pid = rustix::process::Pid::from_child(&child);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            reap_one_orphan();
            if OWNED
                .lock()
                .unwrap()
                .iter()
                .any(|child| child.pid == pid && lock_or_abort(&child.status).is_some())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(wait_owned(&pidfd).await.unwrap().code(), Some(7));
    }

    #[test]
    fn pid_reuse_replaces_the_old_registration() {
        use std::os::unix::process::ExitStatusExt;

        let pid = rustix::process::Pid::from_raw(1).unwrap();
        let mut owned = Vec::new();
        let old_status = register_owned(&mut owned, pid);
        let new_status = register_owned(&mut owned, pid);

        assert_eq!(owned.len(), 1);
        assert!(Arc::ptr_eq(&owned[0].status, &new_status));
        assert!(!Arc::ptr_eq(&old_status, &new_status));

        *lock_or_abort(&old_status) = Some(ExitStatus::from_raw(7 << 8));
        assert_eq!(lock_or_abort(&old_status).unwrap().code(), Some(7));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_graceful_stop_ends_early_when_the_process_takes_the_signal() {
        let (_child, pidfd) = spawn_owned(|| {
            Command::new("/bin/sh")
                .arg("-c")
                .arg("trap 'exit 0' TERM; while true; do sleep 1; done")
                .spawn()
        })
        .unwrap();
        tokio::time::timeout(
            Duration::from_secs(10),
            pidfd.stop_gracefully(Duration::from_secs(30)),
        )
        .await
        .unwrap();
        wait_owned(&pidfd).await.unwrap();
    }

    fn shell(line: &str) -> Command {
        let mut command = Command::new("sh");
        command.arg("-c").arg(line);
        command
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_wedged_process_is_killed_and_reported_as_timed_out() {
        let start = std::time::Instant::now();
        let error = run_or_kill(
            &mut shell("sleep 600"),
            Duration::from_millis(300),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "waited {:?} on a process that never returns",
            start.elapsed()
        );
    }

    /// The command gets its own process group even when the caller forgot it, so the kill
    /// reaches what the command started.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_timed_out_process_takes_its_children_with_it() {
        let pid_file = crate::create_scratch_path("reap", "child");
        let _ = std::fs::remove_file(&pid_file);
        let mut command = shell(&format!(
            "sleep 600 & echo $! > {}; wait",
            pid_file.display()
        ));
        let cancellation = CancellationToken::new();
        let running = run_or_kill(&mut command, Duration::from_millis(500), &cancellation);
        let _ = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .expect("the kill missed the command's process group");
        let pid = crate::read_pid_file(&pid_file).await;
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while rustix::process::test_kill_process(pid).is_ok()
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(rustix::process::test_kill_process(pid).is_err());
        let _ = std::fs::remove_file(pid_file);
    }
}
