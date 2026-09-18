//! Background commands restarted on failure (`daemons:` in the recipe).

use crate::mutex::lock_or_abort;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
struct DaemonProcess {
    pidfd: Arc<crate::reap::OwnedPidfd>,
    leader: rustix::process::Pid,
}

type DaemonRegistry = Arc<Mutex<Vec<DaemonProcess>>>;

#[derive(Clone)]
pub struct Daemons {
    processes: DaemonRegistry,
    stopping: Arc<AtomicBool>,
}

impl Daemons {
    pub fn stop(&self, grace: Duration) {
        self.stopping.store(true, Ordering::SeqCst);
        self.signal(rustix::process::Signal::TERM);
        let deadline = std::time::Instant::now() + grace;
        while !lock_or_abort(&self.processes).is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        self.signal(rustix::process::Signal::KILL);
    }

    fn signal(&self, sig: rustix::process::Signal) {
        let processes = lock_or_abort(&self.processes)
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        for process in &processes {
            crate::reap::signal_owned_process_group(&process.pidfd, process.leader, sig);
        }
    }
}

pub fn spawn_all(
    lines: &[String],
    as_root: bool,
    output: Option<&std::fs::File>,
) -> std::io::Result<Daemons> {
    let processes = DaemonRegistry::default();
    let stopping = Arc::new(AtomicBool::new(false));
    for line in lines {
        let registry = processes.clone();
        let stopping = stopping.clone();
        let line = line.clone();
        let output = output.map(std::fs::File::try_clone).transpose()?;
        std::thread::spawn(move || {
            supervise(&line, &registry, &stopping, as_root, output.as_ref());
        });
    }
    Ok(Daemons {
        processes,
        stopping,
    })
}

#[allow(unsafe_code)]
fn supervise(
    line: &str,
    registry: &DaemonRegistry,
    stopping: &AtomicBool,
    as_root: bool,
    output: Option<&std::fs::File>,
) {
    loop {
        if stopping.load(Ordering::SeqCst) {
            return;
        }
        let mut command = Command::new("sh");
        command.arg("-c").arg(line).process_group(0);
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
            // SAFETY: a post-fork/pre-exec hook that only calls async-signal-safe
            // id-setting syscalls.
            unsafe {
                command.pre_exec(crate::init::drop_privileges);
            }
        }
        let (child, pidfd) = match crate::reap::spawn_owned(|| command.spawn()) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("terra: daemon `{line}` could not spawn ({e})");
                if stopping.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(RESTART_DELAY);
                continue;
            }
        };
        let leader = rustix::process::Pid::from_child(&child);
        let pidfd = Arc::new(pidfd);
        let process = DaemonProcess {
            pidfd: pidfd.clone(),
            leader,
        };
        let mut processes = lock_or_abort(registry);
        processes.push(process);
        if stopping.load(Ordering::SeqCst) {
            crate::reap::signal_owned_process_group(&pidfd, leader, rustix::process::Signal::KILL);
        }
        drop(processes);
        let status = crate::reap::wait_owned(&pidfd);
        let _ = rustix::process::kill_process_group(leader, rustix::process::Signal::KILL);
        lock_or_abort(registry).retain(|registered| !Arc::ptr_eq(&registered.pidfd, &pidfd));
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
        while lock_or_abort(&daemons.processes).is_empty() {
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
        while lock_or_abort(&daemons.processes).is_empty() {
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
        while !lock_or_abort(&daemons.processes).is_empty() && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            lock_or_abort(&daemons.processes).is_empty(),
            "the straggler survived the escalation"
        );
    }

    #[test]
    fn stop_kills_daemon_process_group_children() {
        let file = crate::create_scratch_path("daemon", "child-pid");
        let _ = std::fs::remove_file(&file);
        let line = format!("sh -c 'sleep 600' & echo $! > {}; wait", file.display());
        let daemons = spawn_all(&[line], true, None).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !file.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(file.exists(), "child pid file was never written");
        let child_pid_str = std::fs::read_to_string(&file).unwrap();
        let child_pid: i32 = child_pid_str.trim().parse().unwrap();
        let pid = rustix::process::Pid::from_raw(child_pid).unwrap();
        daemons.stop(STOP_GRACE_TEST);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while rustix::process::test_kill_process(pid).is_ok()
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            rustix::process::test_kill_process(pid).is_err(),
            "daemon process group child survived daemon stop"
        );
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn daemon_exiting_cleans_up_orphaned_process_group_children() {
        let file = crate::create_scratch_path("daemon", "exit-child-pid");
        let _ = std::fs::remove_file(&file);
        let line = format!("sh -c 'sleep 600' & echo $! > {}; exit 0", file.display());
        let daemons = spawn_all(&[line], true, None).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !file.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(file.exists(), "child pid file was never written");
        let child_pid_str = std::fs::read_to_string(&file).unwrap();
        let child_pid: i32 = child_pid_str.trim().parse().unwrap();
        let pid = rustix::process::Pid::from_raw(child_pid).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while rustix::process::test_kill_process(pid).is_ok()
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            rustix::process::test_kill_process(pid).is_err(),
            "daemon child survived leader exit"
        );
        let _ = std::fs::remove_file(&file);
        daemons.stop(STOP_GRACE_TEST);
    }

    #[test]
    fn stop_kills_straggler_daemon_process_group_children() {
        let file = crate::create_scratch_path("daemon", "straggler-child-pid");
        let _ = std::fs::remove_file(&file);
        let line = format!(
            "sh -c 'trap \"\" TERM; sleep 600' & echo $! > {}; wait",
            file.display()
        );
        let daemons = spawn_all(&[line], true, None).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !file.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(file.exists(), "child pid file was never written");
        let child_pid_str = std::fs::read_to_string(&file).unwrap();
        let child_pid: i32 = child_pid_str.trim().parse().unwrap();
        let pid = rustix::process::Pid::from_raw(child_pid).unwrap();
        daemons.stop(STOP_GRACE_TEST);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while rustix::process::test_kill_process(pid).is_ok()
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            rustix::process::test_kill_process(pid).is_err(),
            "straggler child survived daemon stop"
        );
        let _ = std::fs::remove_file(&file);
    }
}
