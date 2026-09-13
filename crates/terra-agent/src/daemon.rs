//! Background commands restarted on failure (`daemons:` in the recipe).
//!
//! ponytail: restarts on non-zero with a fixed 1s backoff, and a daemon's
//! SIGTERM kills the shell, not what the shell started - the children live on
//! as orphans until the box stops. Per-daemon log files and process groups if
//! console interleaving or surviving children bite.

use crate::mutex::lock_or_abort;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

type PidFdRegistry = Arc<Mutex<Vec<Arc<crate::reap::OwnedPidfd>>>>;

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
        while !lock_or_abort(&self.pidfds).is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        self.signal(rustix::process::Signal::KILL);
    }

    fn signal(&self, sig: rustix::process::Signal) {
        let pidfds = lock_or_abort(&self.pidfds)
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        for pidfd in &pidfds {
            let _ = rustix::process::pidfd_send_signal(pidfd, sig);
        }
    }
}

pub fn spawn_all(
    lines: &[String],
    as_root: bool,
    output: Option<&std::fs::File>,
) -> std::io::Result<Daemons> {
    let pidfds = PidFdRegistry::default();
    let stopping = Arc::new(AtomicBool::new(false));
    for line in lines {
        let registry = pidfds.clone();
        let stopping = stopping.clone();
        let line = line.clone();
        let output = output.map(std::fs::File::try_clone).transpose()?;
        std::thread::spawn(move || {
            supervise(&line, &registry, &stopping, as_root, output.as_ref());
        });
    }
    Ok(Daemons { pidfds, stopping })
}

#[allow(unsafe_code)]
fn supervise(
    line: &str,
    registry: &PidFdRegistry,
    stopping: &AtomicBool,
    as_root: bool,
    output: Option<&std::fs::File>,
) {
    loop {
        if stopping.load(Ordering::SeqCst) {
            return;
        }
        let mut command = Command::new("sh");
        command.arg("-c").arg(line);
        if let Some(output) = output {
            let (stdout, stderr) = match output
                .try_clone()
                .and_then(|stdout| output.try_clone().map(|stderr| (stdout, stderr)))
            {
                Ok(output) => output,
                Err(error) => {
                    eprintln!("terra: daemon `{line}` could not clone its output ({error})");
                    return;
                }
            };
            command
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(stderr));
        }
        if !as_root {
            use std::os::unix::process::CommandExt;
            // SAFETY: a post-fork/pre-exec hook that only calls async-signal-safe
            // id-setting syscalls.
            unsafe {
                command.pre_exec(crate::init::drop_privileges);
            }
        }
        let (_child, pidfd) = match crate::reap::spawn_owned(|| command.spawn()) {
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
        let pidfd = Arc::new(pidfd);
        let mut pidfds = lock_or_abort(registry);
        pidfds.push(pidfd.clone());
        if stopping.load(Ordering::SeqCst) {
            let _ = rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL);
        }
        drop(pidfds);
        let status = crate::reap::wait_owned(&pidfd);
        lock_or_abort(registry).retain(|registered| !Arc::ptr_eq(registered, &pidfd));
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

    /// The point of the feature: a command that exits non-zero comes back,
    /// and one that exits 0 stays done.
    #[test]
    fn a_failing_daemon_restarts_and_a_clean_one_stays_done() {
        let file = crate::create_scratch_path("daemon", "restart-count");
        let _ = std::fs::remove_file(&file);
        let line = format!("echo x >> {}; exit 3", file.display());
        let daemons = spawn_all(&[line], true, None).unwrap();
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

        let clean = crate::create_scratch_path("daemon", "clean");
        let _ = std::fs::remove_file(&clean);
        let daemons = spawn_all(&[format!("echo done > {}", clean.display())], true, None).unwrap();
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

    #[test]
    fn daemon_output_uses_the_supplied_stream() {
        let output = crate::create_scratch_path("daemon", "output");
        let _ = std::fs::remove_file(&output);
        let file = std::fs::File::create(&output).unwrap();
        let daemons = spawn_all(
            &["printf daemon-out; printf daemon-err >&2".to_string()],
            true,
            Some(&file),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::fs::read_to_string(&output).unwrap_or_default().len()
            < "daemon-outdaemon-err".len()
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        daemons.stop(STOP_GRACE_TEST);
        assert_eq!(
            std::fs::read_to_string(&output).unwrap_or_default(),
            "daemon-outdaemon-err"
        );
        let _ = std::fs::remove_file(&output);
    }

    /// `stop()` ends a running daemon promptly - the workload's exit must not
    /// wait out a daemon that ignores the box's shutdown.
    #[test]
    fn stop_kills_a_running_daemon_promptly() {
        let daemons = spawn_all(&["sleep 600".to_string()], true, None).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while lock_or_abort(&daemons.pidfds).is_empty() {
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
        let daemons = spawn_all(&["trap '' TERM; sleep 600".to_string()], true, None).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while lock_or_abort(&daemons.pidfds).is_empty() {
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
        while !lock_or_abort(&daemons.pidfds).is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            lock_or_abort(&daemons.pidfds).is_empty(),
            "the straggler survived the escalation"
        );
    }
}
