//! PID 1's orphan reaper.
//!
//! Every outliving process is reparented here with no other waiter, so
//! without this a box leaks a zombie per backgrounded child until `fork`
//! fails guest-wide.

use crate::mutex::lock_or_abort;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
#[cfg(test)]
use std::process::Command;
use std::process::{Child, ExitStatus};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
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

/// Kills an owned process group while preventing the orphan reaper from releasing its leader PID.
pub fn kill_owned_process_group(pidfd: &OwnedPidfd, leader: rustix::process::Pid) {
    let owned = lock_or_abort(&OWNED);
    if lock_or_abort(&pidfd.status).is_none()
        && owned
            .iter()
            .any(|child| Arc::ptr_eq(&child.status, &pidfd.status))
    {
        let _ = rustix::process::kill_process_group(leader, rustix::process::Signal::KILL);
    }
    drop(owned);
    let _ = rustix::process::pidfd_send_signal(pidfd, rustix::process::Signal::KILL);
}

static OWNED: Mutex<Vec<OwnedChild>> = Mutex::new(Vec::new());
static REAPED: Condvar = Condvar::new();
const IDLE: Duration = Duration::from_millis(100);

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

/// Waits for a child registered with [`spawn_owned`].
pub fn wait_owned(pidfd: &OwnedPidfd) -> std::io::Result<ExitStatus> {
    use std::os::unix::process::ExitStatusExt;
    loop {
        let parked_status = lock_or_abort(&pidfd.status).take();
        if let Some(status) = parked_status {
            lock_or_abort(&OWNED).retain(|child| !Arc::ptr_eq(&child.status, &pidfd.status));
            return Ok(status);
        }
        match rustix::process::waitid(
            rustix::process::WaitId::PidFd(pidfd.as_fd()),
            rustix::process::WaitIdOptions::EXITED,
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
                lock_or_abort(&OWNED).retain(|child| !Arc::ptr_eq(&child.status, &pidfd.status));
                return Ok(ExitStatus::from_raw(raw));
            }
            Ok(None) => continue,
            Err(rustix::io::Errno::CHILD) => {}
            Err(error) => return Err(error.into()),
        }
        let mut owned = lock_or_abort(&OWNED);
        let parked_status = lock_or_abort(&pidfd.status).take();
        if let Some(status) = parked_status {
            owned.retain(|child| !Arc::ptr_eq(&child.status, &pidfd.status));
            return Ok(status);
        }
        owned = REAPED.wait(owned).unwrap_or_else(PoisonError::into_inner);
        drop(owned);
    }
}

/// Spawns a background thread that reaps orphaned processes.
pub fn watch_orphans() {
    std::thread::spawn(|| {
        loop {
            while reap_one_orphan() {}
            std::thread::sleep(IDLE);
        }
    });
}

/// Reaps one exited child, parking owned children's statuses. Returns true if a child was reaped.
fn reap_one_orphan() -> bool {
    let owned = lock_or_abort(&OWNED);
    let Ok(Some((pid, status))) = rustix::process::wait(rustix::process::WaitOptions::NOHANG)
    else {
        return false;
    };
    if let Some(child) = owned.iter().find(|c| c.pid == pid) {
        use std::os::unix::process::ExitStatusExt;
        *lock_or_abort(&child.status) = Some(ExitStatus::from_raw(status.as_raw()));
        REAPED.notify_all();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point: a child nobody waits on is reaped, and one the agent
    /// took through [`spawn_owned`] is left for its own caller to collect.
    #[test]
    fn an_orphan_is_reaped_and_an_owned_child_is_left_alone() {
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

        assert_eq!(wait_owned(&pidfd).unwrap().code(), Some(7));
        assert!(
            !OWNED
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.pid == rustix::process::Pid::from_child(&owned_child)),
            "a collected child is still registered"
        );
    }

    #[test]
    fn an_owned_status_survives_the_reaper_before_its_waiter() {
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
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(wait_owned(&pidfd).unwrap().code(), Some(7));
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
