use super::diagnostics::CHUNK_BYTES;
use crate::term::session::Session;
use anyhow::{Context, Result, bail};
use std::os::fd::OwnedFd;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub(crate) const OUTPUT_DRAIN_GRACE: Duration = Duration::from_secs(2);
pub(super) const HOOK_TIMEOUT: Duration = Duration::from_mins(5);

pub(super) async fn wait_for_child(
    child_pidfd: &crate::reap::OwnedPidfd,
    timeout: Duration,
    cancellation: &CancellationToken,
) -> std::io::Result<std::process::ExitStatus> {
    tokio::select! {
        status = crate::reap::wait_owned(child_pidfd) => return status,
        () = cancellation.cancelled() => {},
        () = tokio::time::sleep(timeout) => {},
    }
    child_pidfd.signal_group(rustix::process::Signal::KILL);
    let status = crate::reap::wait_owned(child_pidfd).await;
    if cancellation.is_cancelled() {
        Err(std::io::Error::other("command cancelled"))
    } else {
        status
    }
}

pub(super) async fn run(
    sh_cmd_line: &str,
    session: Option<&Arc<Session>>,
    cancellation: &CancellationToken,
) -> Result<()> {
    use std::os::unix::process::CommandExt as _;

    let mut command = Command::new("sh");
    command.arg("-c").arg(sh_cmd_line).process_group(0);
    if session.is_some() {
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());
    }
    let (mut child, child_pidfd) = crate::reap::spawn_owned(|| command.spawn())
        .with_context(|| format!("spawning hook `{sh_cmd_line}`"))?;
    let pumps = session.map(|session| {
        let cancellation = CancellationToken::new();
        let tasks = TaskTracker::new();
        for stream in [
            child.stdout.take().map(OwnedFd::from),
            child.stderr.take().map(OwnedFd::from),
        ]
        .into_iter()
        .flatten()
        {
            tasks.spawn(pump_output(stream, session.clone(), cancellation.clone()));
        }
        tasks.close();
        HookOutput {
            tasks,
            cancellation,
        }
    });
    let status = wait_for_child(&child_pidfd, HOOK_TIMEOUT, cancellation).await;
    if let Some(pumps) = pumps {
        drain_output(pumps).await;
    }
    let status = status?;
    if !status.success() {
        bail!("hook `{sh_cmd_line}` failed ({status})");
    }
    Ok(())
}

struct HookOutput {
    tasks: TaskTracker,
    cancellation: CancellationToken,
}

async fn pump_output(stream: OwnedFd, session: Arc<Session>, cancellation: CancellationToken) {
    cancellation
        .run_until_cancelled(async move {
            let Ok(mut stream) = crate::into_async_file(stream) else {
                return;
            };
            let mut bytes = [0; CHUNK_BYTES];
            let mut previous_cr = false;
            loop {
                use tokio::io::AsyncReadExt as _;
                match stream.read(&mut bytes).await {
                    Ok(0) | Err(_) => return,
                    Ok(len) => {
                        let mut terminal_bytes = Vec::with_capacity(len);
                        for byte in &bytes[..len] {
                            if *byte == b'\n' && !previous_cr {
                                terminal_bytes.push(b'\r');
                            }
                            terminal_bytes.push(*byte);
                            previous_cr = *byte == b'\r';
                        }
                        session.feed_output(&terminal_bytes).await;
                    }
                }
            }
        })
        .await;
}

async fn drain_output(output: HookOutput) {
    let HookOutput {
        tasks,
        cancellation,
    } = output;
    crate::wait_for_tasks_or_cancel(&tasks, &cancellation, OUTPUT_DRAIN_GRACE).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::run as run_hook;
    use crate::term::session::{ClientConn, Session};
    use std::fs;
    use std::fs::File;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_util::{sync::CancellationToken, task::TaskTracker};
    async fn hook_session() -> (Arc<Session>, UnixStream) {
        let (input, _sink) = UnixStream::pair().unwrap();
        let cancellation = CancellationToken::new();
        let tasks = TaskTracker::new();
        let session = Session::new(
            crate::into_async_file(File::from(OwnedFd::from(input))).unwrap(),
            &cancellation,
            &tasks,
        )
        .unwrap();
        let (host, guest) = UnixStream::pair().unwrap();
        let client = ClientConn::from_file(File::from(OwnedFd::from(guest))).unwrap();
        let _ = session.attach_client(&client).await;
        host.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut host = host;
        let _ = terra_protocol::read_frame::<terra_protocol::AgentOutput>(&mut host).unwrap();
        (session, host)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_start_hook_reaches_the_session_before_it_finishes() {
        let (session, mut host) = hook_session().await;
        let running = tokio::spawn({
            let session = session.clone();
            async move {
                run_hook(
                    "printf 'start\\n'; sleep 1; printf 'stop\\n' >&2",
                    Some(&session),
                    &CancellationToken::new(),
                )
                .await
            }
        });

        assert_eq!(
            terra_protocol::read_frame(&mut host).unwrap(),
            Some(terra_protocol::AgentOutput::Out(b"start\r\n".to_vec()))
        );
        assert!(
            !running.is_finished(),
            "the hook finished before its first output arrived"
        );
        running.await.unwrap().unwrap();
        assert_eq!(
            terra_protocol::read_frame(&mut host).unwrap(),
            Some(terra_protocol::AgentOutput::Out(b"stop\r\n".to_vec()))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failing_stop_hook_leaves_its_stderr_in_the_session() {
        let (session, mut host) = hook_session().await;
        let error = run_hook(
            "printf 'stopping\\n' >&2; exit 7",
            Some(&session),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("failed"), "{error}");
        assert_eq!(
            terra_protocol::read_frame(&mut host).unwrap(),
            Some(terra_protocol::AgentOutput::Out(b"stopping\r\n".to_vec()))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hook_descendant_cannot_hold_shutdown_on_its_output_pipe() {
        let (session, _host) = hook_session().await;
        let start = std::time::Instant::now();
        run_hook(
            "sleep 3 & printf done",
            Some(&session),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "hook output drain took {:?}",
            start.elapsed()
        );
    }
    fn spawn_group(line: &str) -> crate::reap::OwnedPidfd {
        use std::os::unix::process::CommandExt as _;

        let mut command = Command::new("sh");
        command.arg("-c").arg(line).process_group(0);
        crate::reap::spawn_owned(|| command.spawn()).unwrap().1
    }

    async fn wait_until_gone(pid: rustix::process::Pid) {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while rustix::process::test_kill_process(pid).is_ok()
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(rustix::process::test_kill_process(pid).is_err());
    }

    async fn read_pid(path: &std::path::Path) -> rustix::process::Pid {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(pid) = fs::read_to_string(path)
                .ok()
                .and_then(|text| text.trim().parse().ok())
                .and_then(rustix::process::Pid::from_raw)
            {
                return pid;
            }
            assert!(std::time::Instant::now() < deadline, "pid never written");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_wedged_pre_stop_hook_is_killed() {
        let start = std::time::Instant::now();
        let pidfd = spawn_group("sleep 600");
        let _ = wait_for_child(
            &pidfd,
            Duration::from_millis(300),
            &CancellationToken::new(),
        )
        .await;
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "hook waited {:?} on a hook that never returns",
            start.elapsed()
        );
        let start = std::time::Instant::now();
        run_hook("true", None, &CancellationToken::new())
            .await
            .unwrap();
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_timed_out_hook_kills_its_children() {
        let pid_file = crate::create_scratch_path("hook", "child");
        let _ = fs::remove_file(&pid_file);
        let pidfd = spawn_group(&format!(
            "sleep 600 & echo $! > {}; wait",
            pid_file.display()
        ));
        let pid = read_pid(&pid_file).await;
        wait_for_child(
            &pidfd,
            Duration::from_millis(100),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        wait_until_gone(pid).await;
        let _ = fs::remove_file(pid_file);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_a_hook_reaps_its_process_before_returning() {
        let cancellation = CancellationToken::new();
        let pid_file = crate::create_scratch_path("hook", "cancelled");
        let _ = fs::remove_file(&pid_file);
        let line = format!("echo $$ > {}; exec sleep 600", pid_file.display());
        let worker_cancellation = cancellation.clone();
        let worker = tokio::spawn(async move { run_hook(&line, None, &worker_cancellation).await });
        let pid = read_pid(&pid_file).await;
        cancellation.cancel();
        let error = tokio::time::timeout(Duration::from_secs(3), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("cancelled"), "{error}");
        assert!(rustix::process::test_kill_process(pid).is_err());
        let _ = fs::remove_file(pid_file);
    }
}
