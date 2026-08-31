//! Background commands restarted on failure (`daemons:` in the recipe).
//!
//! ponytail: restarts on non-zero with a fixed 1s backoff, and a daemon's
//! SIGTERM kills the shell, not what the shell started - the children live on
//! as orphans until the box stops. Per-daemon log files and process groups if
//! console interleaving or surviving children bite.

use crate::mutex::lock_recover;
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

type PidFdRegistry = Arc<Mutex<Vec<OwnedFd>>>;

#[derive(Clone)]
pub struct Daemons {
    pidfds: PidFdRegistry,
    stopping: Arc<AtomicBool>,
}

impl Daemons {
    pub fn stop(&self, grace: Duration) {
        self.stopping.store(true, Ordering::SeqCst);
        self.signal(rustix::process::Signal::TERM);
        let deadline = std::time::Instant::now() + grace;
        while !lock_recover(&self.pidfds).is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        self.signal(rustix::process::Signal::KILL);
    }

    fn signal(&self, sig: rustix::process::Signal) {
        let pidfds = lock_recover(&self.pidfds)
            .iter()
            .filter_map(|pidfd| pidfd.try_clone().ok())
            .collect::<Vec<_>>();
        for pidfd in &pidfds {
            let _ = rustix::process::pidfd_send_signal(pidfd, sig);
        }
    }
}

pub fn spawn_all(lines: &[String], as_root: bool) -> Daemons {
    let pidfds = PidFdRegistry::default();
    let stopping = Arc::new(AtomicBool::new(false));
    for line in lines {
        let registry = pidfds.clone();
        let stopping = stopping.clone();
        let line = line.clone();
        std::thread::spawn(move || supervise(&line, &registry, &stopping, as_root));
    }
    Daemons { pidfds, stopping }
}

#[allow(unsafe_code)]
fn supervise(line: &str, registry: &PidFdRegistry, stopping: &AtomicBool, as_root: bool) {
    loop {
        if stopping.load(Ordering::SeqCst) {
            return;
        }
        let mut command = Command::new("sh");
        command.arg("-c").arg(line);
        if !as_root {
            use std::os::unix::process::CommandExt;
            // SAFETY: a post-fork/pre-exec hook that only calls async-signal-safe
            // id-setting syscalls.
            unsafe {
                command.pre_exec(crate::init::drop_privileges);
            }
        }
        let (mut child, pidfd) = match crate::reap::spawn_owned(|| command.spawn()) {
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
        let raw = pidfd.as_raw_fd();
        let own_clone = pidfd.try_clone().ok();
        let mut pidfds = lock_recover(registry);
        pidfds.push(pidfd);
        if stopping.load(Ordering::SeqCst)
            && let Some(own_clone) = own_clone
        {
            let _ = rustix::process::pidfd_send_signal(&own_clone, rustix::process::Signal::KILL);
        }
        drop(pidfds);
        let status = crate::reap::wait_owned(&mut child);
        lock_recover(registry).retain(|p| p.as_raw_fd() != raw);
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

    const STOP_GRACE_TEST: Duration = Duration::from_secs(5);

    fn create_scratch_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("terra-agent-daemon-{}-{name}", std::process::id()))
    }

    /// The point of the feature: a command that exits non-zero comes back,
    /// and one that exits 0 stays done.
    #[test]
    fn a_failing_daemon_restarts_and_a_clean_one_stays_done() {
        let file = create_scratch_path("restart-count");
        let _ = std::fs::remove_file(&file);
        let line = format!("echo x >> {}; exit 3", file.display());
        let daemons = spawn_all(&[line], true);
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

        let clean = create_scratch_path("clean");
        let _ = std::fs::remove_file(&clean);
        let daemons = spawn_all(&[format!("echo done > {}", clean.display())], true);
        std::thread::sleep(Duration::from_millis(300));
        daemons.stop(STOP_GRACE_TEST);
        assert_eq!(
            std::fs::read_to_string(&clean).unwrap_or_default().trim(),
            "done"
        );
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
        let daemons = spawn_all(&["sleep 600".to_string()], true);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while lock_recover(&daemons.pidfds).is_empty() {
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
        let daemons = spawn_all(&["trap '' TERM; sleep 600".to_string()], true);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while lock_recover(&daemons.pidfds).is_empty() {
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
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !lock_recover(&daemons.pidfds).is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            lock_recover(&daemons.pidfds).is_empty(),
            "the straggler survived the escalation"
        );
    }
}
