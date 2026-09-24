use super::diagnostics::{CHUNK_BYTES, Diagnostics};
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
    child: &mut std::process::Child,
    child_pidfd: &crate::reap::OwnedPidfd,
    timeout: Option<Duration>,
    cancellation: &CancellationToken,
) -> std::io::Result<std::process::ExitStatus> {
    tokio::select! {
        status = crate::reap::wait_owned(child_pidfd) => return status,
        () = cancellation.cancelled() => {},
        () = async {
            match timeout {
                Some(timeout) => tokio::time::sleep(timeout).await,
                None => std::future::pending().await,
            }
        } => {},
    }
    crate::reap::signal_owned_process_group(
        child_pidfd,
        rustix::process::Pid::from_child(child),
        rustix::process::Signal::KILL,
    );
    let status = crate::reap::wait_owned(child_pidfd).await;
    if cancellation.is_cancelled() {
        Err(std::io::Error::other("command cancelled"))
    } else {
        status
    }
}

pub(super) async fn run(
    sh_cmd_line: &str,
    timeout: Option<Duration>,
    diagnostic: Option<&Diagnostics>,
    session: Option<&Arc<Session>>,
    cancellation: &CancellationToken,
) -> Result<()> {
    use std::os::unix::process::CommandExt as _;

    let mut command = Command::new("sh");
    command.arg("-c").arg(sh_cmd_line).process_group(0);
    if diagnostic.is_some() || session.is_some() {
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());
    }
    let (mut child, child_pidfd) = crate::reap::spawn_owned(|| command.spawn())
        .with_context(|| format!("spawning hook `{sh_cmd_line}`"))?;
    let pumps = if diagnostic.is_some() || session.is_some() {
        let cancellation = CancellationToken::new();
        let tasks = TaskTracker::new();
        for stream in [
            child.stdout.take().map(OwnedFd::from),
            child.stderr.take().map(OwnedFd::from),
        ]
        .into_iter()
        .flatten()
        {
            tasks.spawn(pump_output(
                stream,
                diagnostic.cloned(),
                session.cloned(),
                cancellation.clone(),
            ));
        }
        tasks.close();
        Some(HookOutput {
            tasks,
            cancellation,
        })
    } else {
        None
    };
    let status = wait_for_child(&mut child, &child_pidfd, timeout, cancellation).await;
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

async fn pump_output(
    stream: OwnedFd,
    diagnostic: Option<Diagnostics>,
    session: Option<Arc<Session>>,
    cancellation: CancellationToken,
) {
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
                        let bytes = &bytes[..len];
                        if let Some(session) = &session {
                            let mut terminal_bytes = Vec::with_capacity(bytes.len());
                            for byte in bytes {
                                if *byte == b'\n' && !previous_cr {
                                    terminal_bytes.push(b'\r');
                                }
                                terminal_bytes.push(*byte);
                                previous_cr = *byte == b'\r';
                            }
                            session.feed_output(&terminal_bytes).await;
                        }
                        if let Some(diagnostic) = &diagnostic {
                            diagnostic.record(bytes);
                        }
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
    if tokio::time::timeout(OUTPUT_DRAIN_GRACE, tasks.wait())
        .await
        .is_err()
    {
        cancellation.cancel();
        tasks.wait().await;
    }
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
    use terra_protocol::LifecycleEvent;
    use tokio_util::{sync::CancellationToken, task::TaskTracker};
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hook_output_reaches_diagnostics() {
        let (agent, mut host) = UnixStream::pair().unwrap();
        let diagnostics = Diagnostics::new(File::from(OwnedFd::from(agent))).unwrap();
        run_hook(
            "printf 'hook output\\n'",
            None,
            Some(&diagnostics),
            None,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        diagnostics.finish().await;

        assert_eq!(
            terra_protocol::read_frame(&mut host).unwrap(),
            Some(LifecycleEvent::Diagnostic {
                bytes: b"hook output\n".to_vec()
            })
        );
    }
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
        let client = ClientConn::from_vsock(File::from(OwnedFd::from(guest))).unwrap();
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
                    None,
                    None,
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
            None,
            None,
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
            None,
            None,
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_wedged_pre_stop_hook_is_killed() {
        let start = std::time::Instant::now();
        let _ = run_hook(
            "sleep 600",
            Some(Duration::from_millis(300)),
            None,
            None,
            &CancellationToken::new(),
        )
        .await;
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "hook waited {:?} on a hook that never returns",
            start.elapsed()
        );
        let start = std::time::Instant::now();
        run_hook(
            "true",
            Some(HOOK_TIMEOUT),
            None,
            None,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_timed_out_hook_kills_its_children() {
        let pid_file = crate::create_scratch_path("hook", "child");
        let _ = fs::remove_file(&pid_file);
        run_hook(
            &format!("sleep 600 & echo $! > {}; wait", pid_file.display()),
            Some(Duration::from_millis(100)),
            None,
            None,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
        let pid = rustix::process::Pid::from_raw(
            fs::read_to_string(&pid_file)
                .unwrap()
                .trim()
                .parse()
                .unwrap(),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while rustix::process::test_kill_process(pid).is_ok()
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(rustix::process::test_kill_process(pid).is_err());
        let _ = fs::remove_file(pid_file);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_a_hook_reaps_its_process_before_returning() {
        let cancellation = CancellationToken::new();
        let (agent, mut host) = UnixStream::pair().unwrap();
        let diagnostic = Diagnostics::new(File::from(OwnedFd::from(agent))).unwrap();
        let worker_cancellation = cancellation.clone();
        let worker = tokio::spawn(async move {
            let outcome = run_hook(
                "echo $$; exec sleep 600",
                None,
                Some(&diagnostic),
                None,
                &worker_cancellation,
            )
            .await;
            diagnostic.finish().await;
            outcome
        });
        let frame = terra_protocol::read_frame::<LifecycleEvent>(&mut host)
            .unwrap()
            .unwrap();
        let LifecycleEvent::Diagnostic { bytes } = frame else {
            panic!("unexpected event")
        };
        let pid = rustix::process::Pid::from_raw(
            String::from_utf8(bytes).unwrap().trim().parse().unwrap(),
        )
        .unwrap();
        cancellation.cancel();
        let error = tokio::time::timeout(Duration::from_secs(3), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("cancelled"), "{error}");
        assert!(rustix::process::test_kill_process(pid).is_err());
    }
}
