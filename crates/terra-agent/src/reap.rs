//! PID 1's orphan reaper.

use crate::mutex::lock_or_abort;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
#[cfg(test)]
use std::process::Command;
use std::process::{Child, ExitStatus};
use std::sync::{Arc, Mutex};
#[cfg(test)]
use std::time::Duration;

struct OwnedChild {
    pid: rustix::process::Pid,
    status: Arc<Mutex<Option<ExitStatus>>>,
}

pub struct OwnedPidfd {
    pidfd: OwnedFd,
    status: Arc<Mutex<Option<ExitStatus>>>,
}

impl OwnedPidfd {
    pub fn try_clone(&self) -> std::io::Result<OwnedFd> {
        self.pidfd.try_clone()
    }
}

impl AsFd for OwnedPidfd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }
}

/// Signals an owned process group while preventing the orphan reaper from releasing its leader PID.
pub fn signal_owned_process_group(
    pidfd: &OwnedPidfd,
    leader: rustix::process::Pid,
    sig: rustix::process::Signal,
) {
    let owned = lock_or_abort(&OWNED);
    if lock_or_abort(&pidfd.status).is_none()
        && owned
            .iter()
            .any(|child| Arc::ptr_eq(&child.status, &pidfd.status))
    {
        let _ = rustix::process::kill_process_group(leader, sig);
    }
    drop(owned);
    let _ = rustix::process::pidfd_send_signal(pidfd, sig);
}

static OWNED: Mutex<Vec<OwnedChild>> = Mutex::new(Vec::new());

fn register_owned(
    owned: &mut Vec<OwnedChild>,
    pid: rustix::process::Pid,
) -> Arc<Mutex<Option<ExitStatus>>> {
    let status = Arc::new(Mutex::new(None));
    owned.retain(|owned_child| owned_child.pid != pid);
    owned.push(OwnedChild {
        pid,
        status: status.clone(),
    });
    status
}

/// Spawns a child whose exit status is preserved even if reaped by the orphan reaper.
pub fn spawn_owned<E>(spawn: impl FnOnce() -> Result<Child, E>) -> Result<(Child, OwnedPidfd), E>
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
    Ok((child, OwnedPidfd { pidfd, status }))
}

pub async fn wait_owned(pidfd: &OwnedPidfd) -> std::io::Result<ExitStatus> {
    let pidfd_ready = tokio::io::unix::AsyncFd::new(pidfd.try_clone()?)?;
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
    if let Some(status) = lock_or_abort(&pidfd.status).take() {
        owned.retain(|child| !Arc::ptr_eq(&child.status, &pidfd.status));
        return Ok(Some(status));
    }
    match rustix::process::waitid(
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
            owned.retain(|child| !Arc::ptr_eq(&child.status, &pidfd.status));
            Ok(Some(ExitStatus::from_raw(raw)))
        }
        Ok(None) | Err(rustix::io::Errno::CHILD) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub async fn watch_orphans(cancellation: tokio_util::sync::CancellationToken) {
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
}
