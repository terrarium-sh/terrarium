use super::config;
use super::diagnostics::Diagnostics;
use super::hooks::{self, HOOK_TIMEOUT, OUTPUT_DRAIN_GRACE};
use anyhow::{Context, Result, bail};
use pty_process::blocking::{Command as PtyCommand, Pts, Pty};
use std::fs::{self, File};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use terra_protocol::{DEFAULT_STOP_GRACE_SECS, Plan, PlanMode, TermSize, WORKLOAD_ID};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

struct SessionPty {
    session: Arc<crate::term::session::Session>,
    pts: Pts,
    drained: tokio::sync::oneshot::Receiver<()>,
}

pub(super) async fn execute(
    plan: &Plan,
    control: &File,
    diagnostic: &Diagnostics,
    stop: &CancellationToken,
    shutdown: &CancellationToken,
    tasks: &TaskTracker,
    clients: tokio::sync::mpsc::Receiver<File>,
) -> Result<i32> {
    restrict_ptrace();
    config::configure_network(&plan.net, stop).await?;
    crate::sync::ensure_directory(Path::new(terra_protocol::WORKLOAD_HOME), true)
        .with_context(|| format!("creating home {}", terra_protocol::WORKLOAD_HOME))?;
    if plan.mode == PlanMode::Create {
        let startup = crate::vsock::StartupGate::new();
        let SessionPty { session, .. } =
            start_session(plan, clients, startup, stop, shutdown, tasks).await?;
        crate::report_agent_ready(control).await?;
        let outcome = bake_if_stale(&plan.on_create, diagnostic, &session, stop).await;
        session.broadcast_exit(i32::from(outcome.is_err())).await;
        return outcome.map(|()| 0);
    }
    config::ensure_baked(&plan.on_create)?;
    config::mount_filesystems(plan)?;
    fs::write("/terra/README.md", &plan.sandbox_info).context("writing sandbox description")?;
    config::configure_user(plan.root, stop).await?;
    config::configure_sudo(plan.root, &plan.sudo)?;
    let startup = crate::vsock::StartupGate::new();
    let SessionPty {
        session,
        pts,
        drained,
    } = start_session(plan, clients, startup.clone(), stop, shutdown, tasks).await?;
    crate::report_agent_ready(control).await?;
    if !plan.on_start.is_empty() {
        session
            .feed_output(b"terra: running startup hooks\r\n")
            .await;
    }
    for line in &plan.on_start {
        if let Err(error) = hooks::run(line, Some(HOOK_TIMEOUT), None, Some(&session), stop).await {
            return Err(fail_startup(&startup, &session, error).await);
        }
    }
    let workdir = plan
        .workdir
        .clone()
        .unwrap_or_else(|| terra_protocol::WORKLOAD_HOME.to_owned());
    if let Err(error) = crate::sync::ensure_directory(Path::new(&workdir), !plan.root)
        .with_context(|| format!("creating workdir {workdir}"))
        .and_then(|()| {
            std::env::set_current_dir(&workdir)
                .with_context(|| format!("entering workdir {workdir}"))
        })
    {
        return Err(fail_startup(&startup, &session, error).await);
    }
    startup.ready();
    let mut drained = drained;
    let (code, daemons) = run_workload(plan, pts, &mut drained, stop, shutdown, tasks)
        .await
        .context("running the workload")?;
    if !plan.pre_stop.is_empty() {
        session.feed_output(b"terra: running stop hooks\r\n").await;
    }
    for line in &plan.pre_stop {
        if let Err(error) =
            hooks::run(line, Some(HOOK_TIMEOUT), None, Some(&session), shutdown).await
        {
            session
                .feed_output(format!("terra-agent: stop hook failed: {error:#}\r\n").as_bytes())
                .await;
        }
    }
    daemons
        .stop(Duration::from_secs(DEFAULT_STOP_GRACE_SECS))
        .await;
    session.broadcast_exit(code).await;
    Ok(code)
}

async fn fail_startup(
    startup: &crate::vsock::StartupGate,
    session: &crate::term::session::Session,
    error: anyhow::Error,
) -> anyhow::Error {
    startup.fail();
    session
        .feed_output(format!("terra-agent: init failed: {error:#}\r\n").as_bytes())
        .await;
    session.broadcast_exit(1).await;
    error
}

async fn bake_if_stale(
    on_create: &[String],
    diagnostic: &Diagnostics,
    session: &Arc<crate::term::session::Session>,
    stop: &CancellationToken,
) -> Result<()> {
    let recipe = on_create.join("\n");
    if config::is_baked(&recipe)? {
        return Ok(());
    }
    if !on_create.is_empty() {
        diagnostic.record(b"terra: baking on_create...\n");
    }
    for line in on_create {
        hooks::run(line, Some(HOOK_TIMEOUT), None, Some(session), stop).await?;
    }
    fs::write(terra_protocol::RECIPE_STAMP_PATH, &recipe)
        .with_context(|| format!("stamping {}", terra_protocol::RECIPE_STAMP_PATH))
}

fn restrict_ptrace() {
    const PATH: &str = "/proc/sys/kernel/yama/ptrace_scope";
    if let Err(error) = fs::write(PATH, "1\n") {
        eprintln!("terra-agent: warning: could not restrict ptrace ({PATH}): {error}");
    }
}

async fn start_session(
    plan: &Plan,
    clients: tokio::sync::mpsc::Receiver<File>,
    startup: crate::vsock::StartupGate,
    stop: &CancellationToken,
    shutdown: &CancellationToken,
    tasks: &TaskTracker,
) -> Result<SessionPty> {
    let (pty, pts) = pty_process::blocking::open()?;
    pty.resize(pty_process::Size::new(
        crate::term::session::DEFAULT_ROWS,
        crate::term::session::DEFAULT_COLS,
    ))?;
    let master: OwnedFd = pty.into();
    let reader = master.try_clone()?;
    let input = crate::into_async_file(master)?;
    let session = crate::term::session::Session::new(input, shutdown, tasks)?;
    let (initial_session, connected) = if plan.await_initial_session {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        (Some(sender), Some(receiver))
    } else {
        (None, None)
    };
    tasks.spawn(crate::vsock::serve_clients(
        session.clone(),
        clients,
        plan.root,
        initial_session,
        startup,
        shutdown.clone(),
    ));
    if let Some(connected) = connected {
        wait_for_initial_session(connected, stop).await?;
    }
    let (drained_tx, drained) = tokio::sync::oneshot::channel();
    let out_session = session.clone();
    let shutdown = shutdown.clone();
    tasks.spawn(async move {
        let _drained_tx = drained_tx;
        shutdown
            .run_until_cancelled(async move {
                let Ok(mut reader) = crate::into_async_file(reader) else {
                    return;
                };
                let mut bytes = [0; super::diagnostics::CHUNK_BYTES];
                loop {
                    use tokio::io::AsyncReadExt as _;
                    match reader.read(&mut bytes).await {
                        Ok(0) | Err(_) => return,
                        Ok(len) => out_session.feed_output(&bytes[..len]).await,
                    }
                }
            })
            .await;
    });
    Ok(SessionPty {
        session,
        pts,
        drained,
    })
}

#[allow(unsafe_code)]
async fn run_workload(
    plan: &Plan,
    pts: Pts,
    drained: &mut tokio::sync::oneshot::Receiver<()>,
    stop: &CancellationToken,
    shutdown: &CancellationToken,
    tasks: &TaskTracker,
) -> Result<(i32, crate::daemon::Daemons)> {
    let Some((cmd, args)) = plan.workload.split_first() else {
        bail!("empty workload argv");
    };
    let stop_grace = Duration::from_secs(DEFAULT_STOP_GRACE_SECS);
    let daemon_output = File::from(pts.as_fd().try_clone_to_owned()?);
    let daemons = crate::daemon::spawn_all(
        &plan.daemons,
        plan.root,
        Some(&daemon_output),
        shutdown,
        tasks,
    )?;
    drop(daemon_output);
    let mut command = PtyCommand::new(cmd).args(args);
    if !plan.root {
        // SAFETY: a post-fork/pre-exec hook that only calls async-signal-safe
        // id-setting syscalls.
        unsafe {
            command = command.pre_exec(drop_privileges);
        }
    }
    let (_child, child_pidfd) = match crate::reap::spawn_owned(|| command.spawn(pts)) {
        Ok(child) => child,
        Err(error) => {
            daemons.stop(stop_grace).await;
            return Err(error.into());
        }
    };
    let code = tokio::select! {
        code = crate::exec::wait_for_exit_code(&child_pidfd) => code,
        () = stop.cancelled() => {
            stop_gracefully(&child_pidfd, stop_grace).await;
            crate::exec::wait_for_exit_code(&child_pidfd).await
        }
    };
    let _ = tokio::time::timeout(OUTPUT_DRAIN_GRACE, drained).await;
    Ok((code, daemons))
}

async fn wait_for_initial_session(
    mut connected: tokio::sync::mpsc::Receiver<()>,
    stop: &CancellationToken,
) -> Result<()> {
    tokio::select! {
        () = stop.cancelled() => bail!("the host stopped the box before its foreground session connected"),
        connected = tokio::time::timeout(Duration::from_secs(30), connected.recv()) => match connected {
            Ok(Some(())) => Ok(()),
            Ok(None) => bail!("the foreground session listener stopped"),
            Err(_) => bail!("the foreground session did not connect within 30 seconds"),
        }
    }
}

#[allow(unsafe_code)]
pub(crate) fn spawn_on_pty(
    cmd: &str,
    args: &[String],
    term: TermSize,
    as_root: bool,
    home_env: Option<&str>,
    workdir: Option<&str>,
    env: &std::collections::BTreeMap<String, String>,
) -> Result<(Pty, std::process::Child, crate::reap::OwnedPidfd)> {
    let (pty, pts) = pty_process::blocking::open()?;
    pty.resize(pty_process::Size::new(
        term.rows.clamp(
            crate::term::session::MIN_ROWS,
            crate::term::session::MAX_ROWS,
        ),
        term.cols.clamp(
            crate::term::session::MIN_COLS,
            crate::term::session::MAX_COLS,
        ),
    ))?;
    let mut command = PtyCommand::new(cmd).args(args);
    if let Some(home_env) = home_env {
        command = command.env("HOME", home_env);
    }
    if let Some(workdir) = workdir {
        command = command.current_dir(workdir);
    }
    for (key, value) in env {
        command = command.env(key, value);
    }
    if !as_root {
        // SAFETY: a post-fork/pre-exec hook that only calls async-signal-safe
        // id-setting syscalls.
        unsafe {
            command = command.pre_exec(drop_privileges);
        }
    }
    let (child, child_pidfd) = crate::reap::spawn_owned(|| command.spawn(pts))?;
    Ok((pty, child, child_pidfd))
}

pub(crate) fn drop_privileges() -> std::io::Result<()> {
    rustix::thread::set_thread_groups(&[]).map_err(std::io::Error::from)?;
    rustix::thread::set_thread_gid(rustix::process::Gid::from_raw(WORKLOAD_ID))
        .map_err(std::io::Error::from)?;
    rustix::thread::set_thread_uid(rustix::process::Uid::from_raw(WORKLOAD_ID))
        .map_err(std::io::Error::from)
}

async fn stop_gracefully(workload: &crate::reap::OwnedPidfd, stop_grace: Duration) {
    let _ = rustix::process::pidfd_send_signal(workload, rustix::process::Signal::TERM);
    let ready = workload.try_clone().and_then(tokio::io::unix::AsyncFd::new);
    if let Ok(ready) = ready
        && matches!(
            tokio::time::timeout(stop_grace, ready.readable()).await,
            Ok(Ok(_))
        )
    {
        return;
    }
    let _ = rustix::process::pidfd_send_signal(workload, rustix::process::Signal::KILL);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watch_control;
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::Command;
    use std::time::Duration;
    use terra_protocol::STOP_SIGNAL;
    use tokio_util::sync::CancellationToken;
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stop_ends_early_when_the_workload_takes_the_signal() {
        let (_child, pidfd) = crate::reap::spawn_owned(|| {
            Command::new("/bin/sh")
                .arg("-c")
                .arg("trap 'exit 0' TERM; while true; do sleep 1; done")
                .spawn()
        })
        .unwrap();
        tokio::time::timeout(
            Duration::from_secs(10),
            stop_gracefully(&pidfd, Duration::from_secs(30)),
        )
        .await
        .unwrap();
        crate::reap::wait_owned(&pidfd).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stop_before_foreground_attach_does_not_start_the_workload() {
        let (mut host, guest) = UnixStream::pair().unwrap();
        let guest = File::from(OwnedFd::from(guest));
        let (_sender, connected) = tokio::sync::mpsc::channel(1);
        host.write_all(&[STOP_SIGNAL]).unwrap();

        let stop = CancellationToken::new();
        let shutdown = CancellationToken::new();
        let watcher = tokio::spawn(watch_control(
            crate::into_async_file(guest).unwrap(),
            stop.clone(),
            shutdown.clone(),
        ));
        let error = wait_for_initial_session(connected, &stop)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("stopped the box"), "{error}");
        shutdown.cancel();
        watcher.await.unwrap();
    }
}
