//! Background commands restarted on failure (`daemons:` in the recipe).
//!
//! One thread per line; a line that exits 0 is done, anything else respawns
//! after a second. Each spawn's pidfd lives in a shared registry so
//! [`Daemons::stop`] can signal every live one without the reuse-after-reap
//! hazard of a pid.
//!
//! ponytail: restarts on non-zero with a fixed 1s backoff, and a daemon's
//! SIGTERM kills the shell, not what the shell started - the children live on
//! as orphans until the box stops. Per-daemon log files and process groups if
//! console interleaving or surviving children bite.

use std::os::fd::{AsRawFd, OwnedFd};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

type Pids = Arc<Mutex<Vec<OwnedFd>>>;

fn pids(m: &Mutex<Vec<OwnedFd>>) -> MutexGuard<'_, Vec<OwnedFd>> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Clone)]
pub struct Daemons {
    pids: Pids,
    stopping: Arc<AtomicBool>,
}

impl Daemons {
    pub fn request_stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        self.signal(libc::SIGTERM);
    }

    pub fn kill_stragglers(&self) {
        self.signal(libc::SIGKILL);
    }

    /// Whether every daemon has exited and been reaped.
    pub fn drained(&self) -> bool {
        pids(&self.pids).is_empty()
    }

    pub fn stop(&self, grace: Duration) {
        self.request_stop();
        let deadline = std::time::Instant::now() + grace;
        while !self.drained() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        self.kill_stragglers();
    }

    fn signal(&self, sig: libc::c_int) {
        for pidfd in pids(&self.pids).iter() {
            crate::init::pidfd_signal(pidfd, sig);
        }
    }
}

pub fn spawn_all(lines: &[String]) -> Daemons {
    let pids = Pids::default();
    let stopping = Arc::new(AtomicBool::new(false));
    for line in lines {
        let (pids, stopping) = (pids.clone(), stopping.clone());
        let line = line.clone();
        std::thread::spawn(move || supervise(&line, &pids, &stopping));
    }
    Daemons { pids, stopping }
}

fn supervise(line: &str, registry: &Pids, stopping: &AtomicBool) {
    loop {
        if stopping.load(Ordering::SeqCst) {
            return;
        }
        let mut child =
            match crate::reap::spawn_owned(|| Command::new("sh").arg("-c").arg(line).spawn()) {
                Ok(child) => child,
                Err(e) => {
                    eprintln!("terra: daemon `{line}` could not spawn ({e})");
                    if stopping.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(RESTART_DELAY);
                    continue;
                }
            };
        let pidfd = match crate::init::pidfd_open(child.id()) {
            Ok(fd) => fd,
            // A just-spawned child's pid is valid until it is reaped, so this
            // is the box out of fds or pidfds - not a pid that got away.
            Err(e) => {
                eprintln!("terra: daemon `{line}` has no pidfd ({e}) - it cannot be stopped");
                let _ = crate::reap::wait_owned(&mut child);
                std::thread::sleep(RESTART_DELAY);
                continue;
            }
        };
        let raw = pidfd.as_raw_fd();
        pids(registry).push(pidfd);
        let status = crate::reap::wait_owned(&mut child);
        pids(registry).retain(|p| p.as_raw_fd() != raw);
        if stopping.load(Ordering::SeqCst) {
            return;
        }
        match status {
            Ok(s) if s.success() => return,
            Ok(s) => eprintln!("terra: daemon `{line}` exited {s} - restarting"),
            Err(e) => eprintln!("terra: daemon `{line}` wait failed ({e})"),
        }
        std::thread::sleep(RESTART_DELAY);
    }
}

const RESTART_DELAY: Duration = Duration::from_secs(1);

#[cfg(test)]
mod tests {
    use super::*;

    /// A grace that would let a wedged test daemon linger is not worth waiting.
    const STOP_GRACE_TEST: Duration = Duration::from_secs(5);

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("terra-agent-daemon-{}-{name}", std::process::id()))
    }

    /// The point of the feature: a command that exits non-zero comes back,
    /// and one that exits 0 stays done.
    #[test]
    fn a_failing_daemon_restarts_and_a_clean_one_stays_done() {
        let file = scratch("restart-count");
        let _ = std::fs::remove_file(&file);
        let line = format!("echo x >> {}; exit 3", file.display());
        let daemons = spawn_all(&[line]);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let count = |file: &std::path::Path| {
            std::fs::read_to_string(file)
                .unwrap_or_default()
                .lines()
                .count()
        };
        while count(&file) < 2 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(count(&file) >= 2, "the failing daemon never restarted");
        daemons.stop(STOP_GRACE_TEST);

        let clean = scratch("clean");
        let _ = std::fs::remove_file(&clean);
        let daemons = spawn_all(&[format!("echo done > {}", clean.display())]);
        std::thread::sleep(Duration::from_millis(300));
        daemons.stop(STOP_GRACE_TEST);
        assert_eq!(
            std::fs::read_to_string(&clean).unwrap_or_default().trim(),
            "done"
        );
        // A clean exit is not a restart - a second wait on the same duration
        // must not have rewritten the file.
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            std::fs::read_to_string(&clean).unwrap_or_default().trim(),
            "done"
        );

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_file(&clean);
    }

    /// `stop()` ends a running daemon promptly - the workload's exit must not
    /// wait out a daemon that ignores the box's shutdown.
    #[test]
    fn stop_kills_a_running_daemon_promptly() {
        let daemons = spawn_all(&["sleep 600".to_string()]);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while daemons.pids.lock().unwrap().is_empty() {
            assert!(std::time::Instant::now() < deadline, "never spawned");
            std::thread::sleep(Duration::from_millis(10));
        }
        let start = std::time::Instant::now();
        daemons.stop(STOP_GRACE_TEST);
        assert!(
            start.elapsed() < STOP_GRACE_TEST,
            "stop waited {:?} on a running daemon",
            start.elapsed()
        );
    }

    /// A daemon that ignores SIGTERM gets its full grace, then is `SIGKILL`ed:
    /// the escalation is what the grace is for.
    #[test]
    fn a_straggler_is_killed_once_the_grace_runs_out() {
        let daemons = spawn_all(&["trap '' TERM; sleep 600".to_string()]);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while daemons.pids.lock().unwrap().is_empty() {
            assert!(std::time::Instant::now() < deadline, "never spawned");
            std::thread::sleep(Duration::from_millis(10));
        }
        let grace = Duration::from_millis(500);
        let start = std::time::Instant::now();
        daemons.stop(grace);
        assert!(
            start.elapsed() >= Duration::from_millis(450),
            "the straggler was not given its grace: {:?}",
            start.elapsed()
        );
        // The SIGKILL landed and the supervisor reaped the straggler.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !daemons.drained() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(daemons.drained(), "the straggler survived the escalation");
    }
}
