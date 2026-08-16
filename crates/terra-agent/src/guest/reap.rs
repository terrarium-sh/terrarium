//! PID 1's orphan reaper.
//!
//! Every process that outlives its parent is reparented to the agent, and
//! nothing else will ever wait on one, so without this a box leaks a zombie
//! per backgrounded child until `fork` fails guest-wide.

use std::collections::BTreeSet;
use std::process::{Child, Command, ExitStatus};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// Pids with a waiter of their own: the workload, each `terra exec`, each hook.
static OWNED: Mutex<BTreeSet<libc::pid_t>> = Mutex::new(BTreeSet::new());

/// How long the reaper waits after finding nothing to take.
const IDLE: Duration = Duration::from_millis(100);

fn owned() -> MutexGuard<'static, BTreeSet<libc::pid_t>> {
    OWNED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A pid as `waitpid` spells one. Every real pid fits; `-1` would mean "any
/// child", so a value that does not fit becomes a pid that matches nothing.
fn as_pid(pid: u32) -> libc::pid_t {
    libc::pid_t::try_from(pid).unwrap_or(libc::pid_t::MAX)
}

/// Spawn a child this agent waits on itself.
///
/// The registration happens under the lock the reaper takes before it reaps
/// anything, so a command that exits before this even returns still has its
/// status waiting for its own caller.
pub fn spawn_owned<E>(spawn: impl FnOnce() -> Result<Child, E>) -> Result<Child, E> {
    let mut owned = owned();
    let child = spawn()?;
    owned.insert(as_pid(child.id()));
    Ok(child)
}

/// Wait for a child taken by [`spawn_owned`], and let the reaper forget it.
pub fn wait_owned(child: &mut Child) -> std::io::Result<ExitStatus> {
    let pid = as_pid(child.id());
    let status = child.wait();
    owned().remove(&pid);
    status
}

/// [`spawn_owned`] then [`wait_owned`].
pub fn status_owned(cmd: &mut Command) -> std::io::Result<ExitStatus> {
    let mut child = spawn_owned(|| cmd.spawn())?;
    wait_owned(&mut child)
}

/// Reap orphans for the rest of the agent's life. Started once the fork in
/// [`crate::idmap`] has been reaped, which waits on a pid of its own.
pub fn watch_orphans() {
    std::thread::spawn(|| {
        loop {
            while reap_one_orphan() {}
            std::thread::sleep(IDLE);
        }
    });
}

/// Reap the zombie at the head of the queue if it is an orphan; `false` when
/// there is none, or when the one waiting belongs to somebody.
///
/// `WNOWAIT` reports a zombie without consuming it.
///
/// ponytail: an owned zombie masks whatever is queued behind it until its own
/// waiter takes it - and that waiter can be a while (a `terra exec` whose
/// output is still draining), during which no orphan is reaped at all. The
/// queue drains the moment it is taken; a real fix is a pid→status map fed by
/// `waitpid(-1)`, worth it only if reaping stalls show up in practice.
fn reap_one_orphan() -> bool {
    // SAFETY: `waitid` either fills `info` or reports nothing through `rc`.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            libc::P_ALL,
            0,
            &raw mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        )
    };
    // SAFETY: `si_pid` is set on every `WEXITED` report. It stays zero when
    // `WNOHANG` found nothing, which `rc` alone does not distinguish.
    let pid = unsafe { info.si_pid() };
    if rc != 0 || pid <= 0 || owned().contains(&pid) {
        return false;
    }
    // SAFETY: waits on our own child; a null status pointer is allowed.
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point: a child nobody waits on is reaped, and one the agent
    /// took through [`spawn_owned`] is left for its own caller to collect.
    #[test]
    fn an_orphan_is_reaped_and_an_owned_child_is_left_alone() {
        let mut owned_child =
            spawn_owned(|| Command::new("/bin/sh").arg("-c").arg("exit 7").spawn()).unwrap();
        let orphan = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .unwrap();
        let orphan_pid = as_pid(orphan.id());
        // Forget the handle so nothing but the reaper can wait on it - the
        // shape an actual reparented orphan arrives in.
        std::mem::forget(orphan);

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        // SAFETY: a `WNOHANG` wait on a pid that is ours until it is reaped.
        let gone = |pid| unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) } == -1;
        while !gone(orphan_pid) && std::time::Instant::now() < deadline {
            reap_one_orphan();
        }
        assert!(gone(orphan_pid), "the orphan was never reaped");

        // The owned child survived the sweep with its status intact - the
        // regression a blanket `waitpid(-1)` reaper would cause, and the reason
        // `terra exec` can still report what its command exited with.
        assert_eq!(wait_owned(&mut owned_child).unwrap().code(), Some(7));
        assert!(
            !owned().contains(&as_pid(owned_child.id())),
            "a collected child is still registered"
        );
    }
}
