//! Background commands restarted on failure (`daemons:` in the recipe).

use crate::lock_or_abort;
use crate::workload::GuestUser;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

type DaemonRegistry = Arc<Mutex<Vec<Arc<crate::reap::OwnedPidfd>>>>;

#[derive(Clone)]
pub(crate) struct Daemons {
    processes: DaemonRegistry,
    cancellation: CancellationToken,
    supervisors: TaskTracker,
}

impl Daemons {
    pub(crate) async fn stop(&self, grace: Duration) {
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
            process.signal_group(sig);
        }
    }
}

pub(crate) fn spawn_all(
    tasks: &TaskTracker,
    lines: &[String],
    user: GuestUser,
    terminal: BorrowedFd<'_>,
    parent_cancellation: &CancellationToken,
) -> std::io::Result<Daemons> {
    let processes = DaemonRegistry::default();
    let cancellation = parent_cancellation.child_token();
    let supervisors = TaskTracker::new();
    let terminals = lines
        .iter()
        .map(|_| terminal.try_clone_to_owned())
        .collect::<std::io::Result<Vec<_>>>()?;
    for (line, terminal) in lines.iter().zip(terminals) {
        let line = line.clone();
        let registry = processes.clone();
        let cancellation = cancellation.clone();
        supervisors.spawn(tasks.track_future(async move {
            supervise(&line, &registry, &cancellation, user, &terminal).await;
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
        on_shutdown.stop(crate::STOP_GRACE).await;
    });
    Ok(daemons)
}

async fn supervise(
    line: &str,
    registry: &DaemonRegistry,
    cancellation: &CancellationToken,
    user: GuestUser,
    terminal: &OwnedFd,
) {
    loop {
        if cancellation.is_cancelled() {
            return;
        }
        let mut command = match crate::recipe_shell_command(line, terminal.as_fd()) {
            Ok(command) => command,
            Err(error) => {
                eprintln!("terra-agent: daemon `{line}` could not clone its output ({error})");
                return;
            }
        };
        crate::workload::run_as(&mut command, user);
        let status = run_registered(&mut command, registry, cancellation).await;
        if cancellation.is_cancelled() {
            return;
        }
        match status {
            Ok(s) if s.success() => return,
            Ok(s) => eprintln!("terra-agent: daemon `{line}` exited {s} - restarting"),
            Err(e) => eprintln!("terra-agent: daemon `{line}` failed ({e}) - restarting"),
        }
        tokio::select! {
            () = tokio::time::sleep(RESTART_DELAY) => {}
            () = cancellation.cancelled() => return,
        }
    }
}

/// Runs the daemon once, registered so [`Daemons::stop`] can signal it.
async fn run_registered(
    command: &mut std::process::Command,
    registry: &DaemonRegistry,
    cancellation: &CancellationToken,
) -> std::io::Result<std::process::ExitStatus> {
    let (_, pidfd) = crate::reap::spawn_owned(|| command.spawn())?;
    let pidfd = Arc::new(pidfd);
    {
        let mut processes = lock_or_abort(registry);
        processes.push(pidfd.clone());
        if cancellation.is_cancelled() {
            pidfd.signal_group(rustix::process::Signal::TERM);
        }
    }
    let status = tokio::select! {
        status = crate::reap::wait_owned(&pidfd) => status,
        () = cancellation.cancelled() => {
            pidfd.signal_group(rustix::process::Signal::TERM);
            crate::reap::wait_owned(&pidfd).await
        }
    };
    let _ = rustix::process::kill_process_group(pidfd.leader(), rustix::process::Signal::KILL);
    lock_or_abort(registry).retain(|registered| !Arc::ptr_eq(registered, &pidfd));
    status
}

const RESTART_DELAY: Duration = Duration::from_secs(1);

#[cfg(test)]
mod tests {
    use super::*;

    const STOP_GRACE_TEST: Duration = Duration::from_secs(5);

    fn spawn_writing_to(lines: &[String], output: &std::fs::File) -> Daemons {
        spawn_all(
            &TaskTracker::new(),
            lines,
            GuestUser::Root,
            output.as_fd(),
            &CancellationToken::new(),
        )
        .unwrap()
    }

    fn spawn(lines: &[String]) -> Daemons {
        spawn_writing_to(lines, &std::fs::File::create("/dev/null").unwrap())
    }

    /// The point of the feature: a command that exits non-zero comes back,
    /// and one that exits 0 stays done.
    #[tokio::test]
    async fn a_failing_daemon_restarts_and_a_clean_one_stays_done() {
        let file = crate::create_scratch_path("daemon", "restart-count");
        let _ = std::fs::remove_file(&file);
        let line = format!("echo x >> {}; exit 3", file.display());
        let daemons = spawn(&[line]);
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
        let daemons = spawn(&[format!("echo done > {}", clean.display())]);
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
        let daemons = spawn_writing_to(
            &["printf daemon-out; printf daemon-err >&2".to_string()],
            &file,
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
        let daemons = spawn(&["sleep 600".to_string()]);
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
        let daemons = spawn_all(
            &tasks,
            &["sleep 600".to_string()],
            GuestUser::Root,
            std::fs::File::create("/dev/null").unwrap().as_fd(),
            &parent,
        )
        .unwrap();
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
        let ready = crate::create_scratch_path("daemon", "straggler-ready");
        let _ = std::fs::remove_file(&ready);
        let daemons = spawn(&[format!(
            "trap '' TERM; echo $$ > {}; sleep 600",
            ready.display()
        )]);
        let _ = crate::read_pid_file(&ready).await;
        std::fs::remove_file(&ready).unwrap();
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
        let daemons = spawn(&[line]);
        let pid = crate::read_pid_file(&file).await;
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
        let daemons = spawn(&[line]);
        let pid = crate::read_pid_file(&file).await;
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
        let daemons = spawn(&[line]);
        let pid = crate::read_pid_file(&file).await;
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
