//! PID 1's orphan reaper.
//!
//! Every outliving process is reparented here with no other waiter, so
//! without this a box leaks a zombie per backgrounded child until `fork`
//! fails guest-wide.

use crate::mutex::lock_recover;
use std::os::fd::OwnedFd;
#[cfg(test)]
use std::process::Command;
use std::process::{Child, ExitStatus};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Duration;

struct OwnedChild {
    pid: rustix::process::Pid,
    status: Option<rustix::process::WaitStatus>,
}

static OWNED: Mutex<Vec<OwnedChild>> = Mutex::new(Vec::new());
static REAPED: Condvar = Condvar::new();
const IDLE: Duration = Duration::from_millis(100);

/// Spawns a child whose exit status is preserved even if reaped by the orphan reaper.
pub fn spawn_owned<E>(spawn: impl FnOnce() -> Result<Child, E>) -> Result<(Child, OwnedFd), E>
where
    E: From<std::io::Error>,
{
    let mut owned = lock_recover(&OWNED);
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
    owned.push(OwnedChild { pid, status: None });
    Ok((child, pidfd))
}

/// Waits for a child registered with [`spawn_owned`].
pub fn wait_owned(child: &mut Child) -> std::io::Result<ExitStatus> {
    use std::os::unix::process::ExitStatusExt;
    let pid = rustix::process::Pid::from_child(child);
    if let Ok(status) = child.wait() {
        lock_recover(&OWNED).retain(|c| c.pid != pid);
        return Ok(status);
    }
    let mut owned = lock_recover(&OWNED);
    loop {
        if let Some(index) = owned.iter().position(|owned_child| owned_child.pid == pid)
            && let Some(status) = owned[index].status.take()
        {
            owned.swap_remove(index);
            return Ok(ExitStatus::from_raw(status.as_raw()));
        }
        owned = REAPED.wait(owned).unwrap_or_else(PoisonError::into_inner);
    }
}

/// Spawns a background thread that reaps orphaned processes.
/// Must start after [`crate::idmap`]'s child is reaped so its status is not consumed.
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
    let mut owned = lock_recover(&OWNED);
    let Ok(Some((pid, status))) = rustix::process::wait(rustix::process::WaitOptions::NOHANG)
    else {
        return false;
    };
    if let Some(child) = owned.iter_mut().find(|c| c.pid == pid) {
        child.status = Some(status);
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
        let (mut owned_child, _pidfd) =
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

        assert_eq!(wait_owned(&mut owned_child).unwrap().code(), Some(7));
        assert!(
            !OWNED
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.pid == rustix::process::Pid::from_child(&owned_child)),
            "a collected child is still registered"
        );
    }
}
