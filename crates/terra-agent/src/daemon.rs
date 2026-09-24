//! Background commands restarted on failure (`daemons:` in the recipe).

use crate::mutex::lock_or_abort;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

#[derive(Clone)]
struct DaemonProcess {
    pidfd: Arc<crate::reap::OwnedPidfd>,
    leader: rustix::process::Pid,
}

type DaemonRegistry = Arc<Mutex<Vec<DaemonProcess>>>;

#[derive(Clone)]
pub struct Daemons {
    processes: DaemonRegistry,
    cancellation: CancellationToken,
    supervisors: TaskTracker,
}

impl Daemons {
    pub async fn stop(&self, grace: Duration) {
        self.cancellation.cancel();
        self.signal(rustix::process::Signal::TERM);
        if tokio::time::timeout(grace, self.supervisors.wait())
            .await
            .is_err()
        {
            self.signal(rustix::process::Signal::KILL);
            self.supervisors.wait().await;
        }
    }

    fn signal(&self, sig: rustix::process::Signal) {
        let processes = lock_or_abort(&self.processes).clone();
        for process in &processes {
            crate::reap::signal_owned_process_group(&process.pidfd, process.leader, sig);
        }
    }
}

pub fn spawn_all(
    lines: &[String],
    as_root: bool,
    output: Option<&std::fs::File>,
    parent_cancellation: &CancellationToken,
    tasks: &TaskTracker,
) -> std::io::Result<Daemons> {
    let processes = DaemonRegistry::default();
    let cancellation = parent_cancellation.child_token();
    let daemon_specs = lines
        .iter()
        .map(|line| {
            Ok((
                line.clone(),
                output.map(std::fs::File::try_clone).transpose()?,
            ))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let supervisors = TaskTracker::new();
    for (line, output) in daemon_specs {
        let registry = processes.clone();
        let cancellation = cancellation.clone();
        supervisors.spawn(tasks.track_future(async move {
            supervise(&line, &registry, &cancellation, as_root, output.as_ref()).await;
        }));
    }
    supervisors.close();
    let daemons = Daemons {
        processes,
        cancellation,
        supervisors,
    };
    let parent_cancellation = parent_cancellation.clone();
    let on_shutdown = daemons.clone();
    tasks.spawn(async move {
        parent_cancellation.cancelled().await;
        on_shutdown
            .stop(Duration::from_secs(terra_protocol::DEFAULT_STOP_GRACE_SECS))
            .await;
    });
    Ok(daemons)
}

#[allow(unsafe_code)]
async fn supervise(
    line: &str,
    registry: &DaemonRegistry,
    cancellation: &CancellationToken,
    as_root: bool,
    output: Option<&std::fs::File>,
) {
    loop {
        if cancellation.is_cancelled() {
            return;
        }
        let mut command = Command::new("sh");
        command.arg("-c").arg(line).process_group(0);
        if let Some(output) = output {
            let (stdout, stderr) = match (output.try_clone(), output.try_clone()) {
                (Ok(stdout), Ok(stderr)) => (stdout, stderr),
                (Err(error), _) | (_, Err(error)) => {
                    eprintln!("terra-agent: daemon `{line}` could not clone its output ({error})");
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
                command.pre_exec(crate::workload::drop_privileges);
            }
        }
        let (child, pidfd) = match crate::reap::spawn_owned(|| command.spawn()) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("terra-agent: daemon `{line}` could not spawn ({e})");
                tokio::select! {
                    () = tokio::time::sleep(RESTART_DELAY) => {}
                    () = cancellation.cancelled() => return,
                }
                continue;
            }
        };
        let leader = rustix::process::Pid::from_child(&child);
        let pidfd = Arc::new(pidfd);
        let process = DaemonProcess {
            pidfd: pidfd.clone(),
            leader,
        };
        {
            let mut processes = lock_or_abort(registry);
            processes.push(process);
            if cancellation.is_cancelled() {
                crate::reap::signal_owned_process_group(
                    &pidfd,
                    leader,
                    rustix::process::Signal::TERM,
                );
            }
        }
        let status = tokio::select! {
            status = crate::reap::wait_owned(&pidfd) => status,
            () = cancellation.cancelled() => {
                crate::reap::signal_owned_process_group(
                    &pidfd,
                    leader,
                    rustix::process::Signal::TERM,
                );
                crate::reap::wait_owned(&pidfd).await
            }
        };
        let _ = rustix::process::kill_process_group(leader, rustix::process::Signal::KILL);
        lock_or_abort(registry).retain(|registered| !Arc::ptr_eq(&registered.pidfd, &pidfd));
        if cancellation.is_cancelled() {
            return;
        }
        match status {
            Ok(s) if s.success() => return,
            Ok(s) => eprintln!("terra-agent: daemon `{line}` exited {s} - restarting"),
            Err(e) => eprintln!("terra-agent: daemon `{line}` wait failed ({e})"),
        }
        tokio::select! {
            () = tokio::time::sleep(RESTART_DELAY) => {}
            () = cancellation.cancelled() => return,
        }
    }
}

const RESTART_DELAY: Duration = Duration::from_secs(1);

#[cfg(test)]
mod tests {
    use super::*;

    const STOP_GRACE_TEST: Duration = Duration::from_secs(5);

    fn spawn(lines: &[String], as_root: bool, output: Option<&std::fs::File>) -> Daemons {
        spawn_all(
            lines,
            as_root,
            output,
            &CancellationToken::new(),
            &TaskTracker::new(),
        )
        .unwrap()
    }

    async fn read_child_pid(path: &std::path::Path) -> rustix::process::Pid {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(pid) = std::fs::read_to_string(path)
                    .ok()
                    .and_then(|text| text.trim().parse().ok())
                    .and_then(rustix::process::Pid::from_raw)
                {
                    return pid;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("child pid file was never written")
    }

    /// The point of the feature: a command that exits non-zero comes back,
    /// and one that exits 0 stays done.
    #[tokio::test]
    async fn a_failing_daemon_restarts_and_a_clean_one_stays_done() {
        let file = crate::create_scratch_path("daemon", "restart-count");
        let _ = std::fs::remove_file(&file);
        let line = format!("echo x >> {}; exit 3", file.display());
        let daemons = spawn(&[line], true, None);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let count = |file: &std::path::Path| {
            std::fs::read_to_string(file)
                .unwrap_or_default()
                .lines()
                .count()
        };
        while count(&file) < 2 && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(count(&file) >= 2, "the failing daemon never restarted");
        daemons.stop(STOP_GRACE_TEST).await;

        let clean = crate::create_scratch_path("daemon", "clean");
        let _ = std::fs::remove_file(&clean);
        let daemons = spawn(&[format!("echo done > {}", clean.display())], true, None);
        tokio::time::sleep(Duration::from_millis(300)).await;
        daemons.stop(STOP_GRACE_TEST).await;
        assert_eq!(
            std::fs::read_to_string(&clean).unwrap_or_default().trim(),
            "done"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            std::fs::read_to_string(&clean).unwrap_or_default().trim(),
            "done"
        );

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_file(&clean);
    }

    #[tokio::test]
    async fn daemon_output_uses_the_supplied_stream() {
        let output = crate::create_scratch_path("daemon", "output");
        let _ = std::fs::remove_file(&output);
        let file = std::fs::File::create(&output).unwrap();
        let daemons = spawn(
            &["printf daemon-out; printf daemon-err >&2".to_string()],
            true,
            Some(&file),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::fs::read_to_string(&output).unwrap_or_default().len()
            < "daemon-outdaemon-err".len()
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        daemons.stop(STOP_GRACE_TEST).await;
        assert_eq!(
            std::fs::read_to_string(&output).unwrap_or_default(),
            "daemon-outdaemon-err"
        );
        let _ = std::fs::remove_file(&output);
    }

    /// `stop()` ends a running daemon promptly - the workload's exit must not
    /// wait out a daemon that ignores the box's shutdown.
    #[tokio::test]
    async fn stop_kills_a_running_daemon_promptly() {
        let daemons = spawn(&["sleep 600".to_string()], true, None);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while lock_or_abort(&daemons.processes).is_empty() {
            assert!(std::time::Instant::now() < deadline, "never spawned");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let start = std::time::Instant::now();
        daemons.stop(STOP_GRACE_TEST).await;
        assert!(
            start.elapsed() < STOP_GRACE_TEST,
            "stop waited {:?} on a running daemon",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn parent_cancellation_stops_a_running_daemon() {
        let parent = CancellationToken::new();
        let tasks = TaskTracker::new();
        let daemons = spawn_all(&["sleep 600".to_string()], true, None, &parent, &tasks).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while lock_or_abort(&daemons.processes).is_empty() {
            assert!(std::time::Instant::now() < deadline, "never spawned");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        parent.cancel();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !lock_or_abort(&daemons.processes).is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("parent cancellation did not stop the daemon");
        daemons.stop(Duration::ZERO).await;
    }

    /// A daemon that ignores SIGTERM gets its full grace, then is `SIGKILL`ed:
    /// the escalation is what the grace is for.
    #[tokio::test]
    async fn a_straggler_is_killed_once_the_grace_runs_out() {
        let daemons = spawn(&["trap '' TERM; sleep 600".to_string()], true, None);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while lock_or_abort(&daemons.processes).is_empty() {
            assert!(std::time::Instant::now() < deadline, "never spawned");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let grace = Duration::from_millis(500);
        let start = std::time::Instant::now();
        daemons.stop(grace).await;
        assert!(
            start.elapsed() >= Duration::from_millis(450),
            "the straggler was not given its grace: {:?}",
            start.elapsed()
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !lock_or_abort(&daemons.processes).is_empty() && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            lock_or_abort(&daemons.processes).is_empty(),
            "the straggler survived the escalation"
        );
    }

    #[tokio::test]
    async fn stop_kills_daemon_process_group_children() {
        let file = crate::create_scratch_path("daemon", "child-pid");
        let _ = std::fs::remove_file(&file);
        let line = format!("sh -c 'sleep 600' & echo $! > {}; wait", file.display());
        let daemons = spawn(&[line], true, None);
        let pid = read_child_pid(&file).await;
        daemons.stop(STOP_GRACE_TEST).await;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while rustix::process::test_kill_process(pid).is_ok()
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            rustix::process::test_kill_process(pid).is_err(),
            "daemon process group child survived daemon stop"
        );
        let _ = std::fs::remove_file(&file);
    }

    #[tokio::test]
    async fn daemon_exiting_cleans_up_orphaned_process_group_children() {
        let file = crate::create_scratch_path("daemon", "exit-child-pid");
        let _ = std::fs::remove_file(&file);
        let line = format!("sh -c 'sleep 600' & echo $! > {}; exit 0", file.display());
        let daemons = spawn(&[line], true, None);
        let pid = read_child_pid(&file).await;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while rustix::process::test_kill_process(pid).is_ok()
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            rustix::process::test_kill_process(pid).is_err(),
            "daemon child survived leader exit"
        );
        let _ = std::fs::remove_file(&file);
        daemons.stop(STOP_GRACE_TEST).await;
    }

    #[tokio::test]
    async fn stop_kills_straggler_daemon_process_group_children() {
        let file = crate::create_scratch_path("daemon", "straggler-child-pid");
        let _ = std::fs::remove_file(&file);
        let line = format!(
            "sh -c 'trap \"\" TERM; sleep 600' & echo $! > {}; wait",
            file.display()
        );
        let daemons = spawn(&[line], true, None);
        let pid = read_child_pid(&file).await;
        daemons.stop(STOP_GRACE_TEST).await;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while rustix::process::test_kill_process(pid).is_ok()
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            rustix::process::test_kill_process(pid).is_err(),
            "straggler child survived daemon stop"
        );
        let _ = std::fs::remove_file(&file);
    }
}
