//! The running agent once it has entered the root: its link to the host and the setup or run boot it carries out.

use super::STOP_GRACE;
use super::bootstrap;
use super::config;
use super::diagnostics::Diagnostics;
use super::hooks::{self, OUTPUT_DRAIN_GRACE};
use super::into_async_file;
use super::services::{Server, StartupState};
use crate::term::session::Session;
use anyhow::{Context, Result, bail};
use pty_process::blocking::{Command as PtyCommand, Pts};
use std::fs::File;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use terra_protocol::{CLOCK_SYNC, LifecycleEvent, Plan, STOP_SIGNAL};
use tokio::sync::{mpsc, oneshot};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const INITIAL_SESSION_WAIT: Duration = Duration::from_secs(30);

/// The running agent: its link to the host, its shutdown signals and its background tasks.
pub(super) struct Agent {
    /// Fires when the host asks the box to stop.
    stop: CancellationToken,
    /// Fires when the agent tears down; background tasks end on it.
    shutdown: CancellationToken,
    tasks: TaskTracker,
    diagnostic: Diagnostics,
    control: File,
}

/// The box's console as a boot drives it.
struct Console {
    session: Arc<Session>,
    server: Server,
    /// Closes once the PTY output has all been copied into `session`.
    drained: oneshot::Receiver<()>,
}

impl Agent {
    pub(super) fn init(control: &File, diagnostic: File) -> Result<Self> {
        let control_reader = into_async_file(control.try_clone()?)?;
        let agent = Self {
            stop: CancellationToken::new(),
            shutdown: CancellationToken::new(),
            tasks: TaskTracker::new(),
            diagnostic: Diagnostics::new(diagnostic)?,
            control: control.try_clone()?,
        };
        agent
            .tasks
            .spawn(crate::reap::watch_orphans(agent.shutdown.clone()));
        agent.tasks.spawn(watch_control(
            control_reader,
            agent.stop.clone(),
            agent.shutdown.clone(),
        ));
        agent.diagnostic.record(b"agent received boot plan");
        agent.diagnostic.record_boot_stage("boot_plan_received");
        Ok(agent)
    }

    pub(super) async fn setup(&self, plan: &Plan, clients: mpsc::Receiver<File>) -> Result<i32> {
        self.prepare_guest(plan).await?;
        config::mount_volumes(plan)?;
        // A setup boot never starts the workload, so sync and exec are refused from the start.
        let (console, _) = self
            .start_console(plan, clients, StartupState::Refused)
            .await?;
        self.report_ready().await?;
        let created = self.run_on_create(plan, &console).await.map(|()| 0);
        console.exit(created).await
    }

    pub(super) async fn run(&self, plan: &Plan, clients: mpsc::Receiver<File>) -> Result<i32> {
        self.prepare_guest(plan).await?;
        config::mount_filesystems(plan)?;
        if !plan.root {
            config::prepare_runtime_dir()?;
        }
        let (mut console, pts) = self
            .start_console(plan, clients, StartupState::Pending)
            .await?;
        self.report_ready().await?;
        self.run_on_start(plan, &console).await?;
        let (code, daemons) = self
            .run_workload(plan, pts, &mut console)
            .await
            .context("running the workload")?;
        self.run_pre_stop(plan, &console).await;
        daemons.stop(STOP_GRACE).await;
        console.exit(Ok(code)).await
    }

    pub(super) async fn close(self, outcome: &Result<i32>) {
        self.shutdown.cancel();
        self.tasks.close();
        self.tasks.wait().await;
        if let Err(error) = outcome {
            self.diagnostic
                .record(format!("terra-agent: init failed: {error:#}").as_bytes());
        }
        self.diagnostic.finish().await;
    }

    async fn report_ready(&self) -> Result<()> {
        use tokio::io::AsyncWriteExt as _;
        let mut control = into_async_file(self.control.try_clone()?)?;
        terra_protocol::write_frame_async(&mut control, &LifecycleEvent::AgentReady)
            .await
            .context("reporting guest agent readiness")?;
        control
            .flush()
            .await
            .context("flushing guest agent readiness")
    }

    async fn prepare_guest(&self, plan: &Plan) -> Result<()> {
        config::restrict_ptrace();
        config::enable_loopback()?;
        crate::network::start(&self.tasks, plan, &self.shutdown, &self.diagnostic).await?;
        self.diagnostic.record_boot_stage("networking_ready");
        Ok(())
    }

    async fn start_console(
        &self,
        plan: &Plan,
        clients: mpsc::Receiver<File>,
        initial_state: StartupState,
    ) -> Result<(Console, Pts)> {
        let (master, pts) = open_pty()?;
        let reader = master.try_clone()?;
        let session = Session::new(&self.tasks, into_async_file(master)?, &self.shutdown)?;
        let (initial_session, connected) =
            plan.await_initial_session.then(|| mpsc::channel(1)).unzip();
        let server = crate::services::init_server(
            &self.tasks,
            session.clone(),
            clients,
            plan.root,
            initial_session,
            initial_state,
            &self.shutdown,
        );
        if let Some(connected) = connected {
            wait_for_initial_session(connected, &self.stop).await?;
        }
        let drained = forward_pty_output(&self.tasks, reader, session.clone(), &self.shutdown);
        let console = Console {
            session,
            server,
            drained,
        };
        Ok((console, pts))
    }

    async fn run_on_create(&self, plan: &Plan, console: &Console) -> Result<()> {
        self.diagnostic.record_boot_stage("hooks_start");
        if !plan.on_create.is_empty() {
            self.diagnostic.record(b"terra: baking on_create...\n");
        }
        console.run_hooks(&plan.on_create, &self.stop).await?;
        write_persistent_state(plan)?;
        self.diagnostic.record_boot_stage("workload_ready");
        Ok(())
    }

    async fn run_on_start(&self, plan: &Plan, console: &Console) -> Result<()> {
        if !plan.on_start.is_empty() {
            console.say("terra: running startup hooks").await;
        }
        self.diagnostic.record_boot_stage("hooks_start");
        let started = async {
            enter_workdir(plan)?;
            console.run_hooks(&plan.on_start, &self.stop).await
        }
        .await;
        console.finish_startup(started).await
    }

    async fn run_workload(
        &self,
        plan: &Plan,
        pts: Pts,
        console: &mut Console,
    ) -> Result<(i32, crate::daemon::Daemons)> {
        let command = workload_command(plan)?;
        let daemons = self.spawn_daemons(plan, &pts)?;
        let (_child, workload) = match crate::reap::spawn_owned(|| command.spawn(pts)) {
            Ok(child) => child,
            Err(error) => {
                daemons.stop(STOP_GRACE).await;
                return Err(error.into());
            }
        };
        self.diagnostic.record_boot_stage("workload_ready");
        let code = self.wait_for_workload(&workload).await;
        console.drain_output().await;
        Ok((code, daemons))
    }

    fn spawn_daemons(&self, plan: &Plan, pts: &Pts) -> std::io::Result<crate::daemon::Daemons> {
        let output = File::from(pts.as_fd().try_clone_to_owned()?);
        crate::daemon::spawn_all(
            &self.tasks,
            &plan.daemons,
            plan.root,
            Some(&output),
            &self.shutdown,
        )
    }

    async fn wait_for_workload(&self, workload: &crate::reap::OwnedPidfd) -> i32 {
        tokio::select! {
            code = crate::exec::wait_for_exit_code(workload) => code,
            () = self.stop.cancelled() => {
                workload.stop_gracefully(STOP_GRACE).await;
                crate::exec::wait_for_exit_code(workload).await
            }
        }
    }

    async fn run_pre_stop(&self, plan: &Plan, console: &Console) {
        if !plan.pre_stop.is_empty() {
            console.say("terra: running stop hooks").await;
        }
        for line in &plan.pre_stop {
            if let Err(error) = hooks::run(line, Some(&console.session), &self.shutdown).await {
                console
                    .say(&format!("terra-agent: stop hook failed: {error:#}"))
                    .await;
            }
        }
    }
}

impl Console {
    async fn say(&self, line: &str) {
        self.session
            .feed_output(format!("{line}\r\n").as_bytes())
            .await;
    }

    async fn run_hooks(&self, lines: &[String], cancellation: &CancellationToken) -> Result<()> {
        for line in lines {
            hooks::run(line, Some(&self.session), cancellation).await?;
        }
        Ok(())
    }

    /// Ends every attached client with the boot's exit code, 1 when the boot failed.
    async fn exit(&self, outcome: Result<i32>) -> Result<i32> {
        let code = match &outcome {
            Ok(code) => *code,
            Err(_) => 1,
        };
        self.session.broadcast_exit(code).await;
        outcome
    }

    /// Serves sync and exec once startup succeeded; otherwise refuses them and ends every client.
    async fn finish_startup(&self, started: Result<()>) -> Result<()> {
        match started {
            Ok(()) => {
                self.server.update_state(StartupState::Ready);
                Ok(())
            }
            Err(error) => {
                self.server.update_state(StartupState::Refused);
                self.say(&format!("terra-agent: init failed: {error:#}"))
                    .await;
                self.session.broadcast_exit(1).await;
                Err(error)
            }
        }
    }

    async fn drain_output(&mut self) {
        let _ = tokio::time::timeout(OUTPUT_DRAIN_GRACE, &mut self.drained).await;
    }
}

/// Creates what the recipe names in the root image; a run boot only finds it there.
fn write_persistent_state(plan: &Plan) -> Result<()> {
    terra_protocol::guest_root::link_per_boot_files(Path::new("/"))
        .context("restoring the per-boot links on_create replaced")?;
    config::prepare_mount_points(plan)?;
    if let Some(workdir) = &plan.workdir {
        crate::sync::ensure_directory(Path::new(workdir), crate::sync::Owner::Workload)
            .with_context(|| format!("creating workdir {workdir}"))?;
    }
    Ok(())
}

fn enter_workdir(plan: &Plan) -> Result<()> {
    let workdir = plan
        .workdir
        .as_deref()
        .unwrap_or(terra_protocol::WORKLOAD_HOME);
    crate::sync::ensure_directory(
        Path::new(workdir),
        crate::sync::Owner::for_workload(plan.root),
    )
    .with_context(|| format!("creating workdir {workdir}"))?;
    std::env::set_current_dir(workdir).with_context(|| format!("entering workdir {workdir}"))
}

fn workload_command(plan: &Plan) -> Result<PtyCommand> {
    let Some((cmd, args)) = plan.workload.split_first() else {
        bail!("empty workload argv");
    };
    let command = PtyCommand::new(cmd).args(args);
    Ok(if plan.root {
        command
    } else {
        crate::workload::run_pty_command_as_workload(command)
    })
}

fn open_pty() -> Result<(OwnedFd, Pts)> {
    let (pty, pts) = pty_process::blocking::open()?;
    pty.resize(pty_process::Size::new(
        crate::term::session::DEFAULT_ROWS,
        crate::term::session::DEFAULT_COLS,
    ))?;
    Ok((pty.into(), pts))
}

/// The returned receiver closes once the PTY output has all been copied into `session`.
fn forward_pty_output(
    tasks: &TaskTracker,
    reader: OwnedFd,
    session: Arc<Session>,
    shutdown: &CancellationToken,
) -> oneshot::Receiver<()> {
    let (drained, receiver) = oneshot::channel::<()>();
    let shutdown = shutdown.clone();
    tasks.spawn(async move {
        let _drained = drained;
        shutdown
            .run_until_cancelled(async {
                let Ok(mut reader) = into_async_file(reader) else {
                    return;
                };
                let mut bytes = [0; super::diagnostics::CHUNK_BYTES];
                loop {
                    use tokio::io::AsyncReadExt as _;
                    match reader.read(&mut bytes).await {
                        Ok(0) | Err(_) => return,
                        Ok(len) => session.feed_output(&bytes[..len]).await,
                    }
                }
            })
            .await;
    });
    receiver
}

async fn wait_for_initial_session(
    mut connected: mpsc::Receiver<()>,
    stop: &CancellationToken,
) -> Result<()> {
    tokio::select! {
        () = stop.cancelled() => bail!("the host stopped the box before its foreground session connected"),
        connected = tokio::time::timeout(INITIAL_SESSION_WAIT, connected.recv()) => match connected {
            Ok(Some(())) => Ok(()),
            Ok(None) => bail!("the foreground session listener stopped"),
            Err(_) => bail!(
                "the foreground session did not connect within {} seconds",
                INITIAL_SESSION_WAIT.as_secs()
            ),
        }
    }
}

pub(super) async fn watch_control(
    mut control: crate::AsyncFile,
    stop: CancellationToken,
    shutdown: CancellationToken,
) {
    use tokio::io::AsyncReadExt as _;
    shutdown
        .run_until_cancelled(async {
            let mut byte = [0u8; 1];
            loop {
                match control.read(&mut byte).await {
                    Ok(0) => break,
                    Ok(_) if byte[0] == STOP_SIGNAL => break,
                    Ok(_) if byte[0] == CLOCK_SYNC => {
                        if let Err(error) = bootstrap::read_clock_update(&mut control).await {
                            eprintln!("terra-agent: clock update failed ({error:#})");
                        }
                    }
                    Ok(_) => eprintln!("terra-agent: ignored invalid control command"),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        eprintln!(
                            "terra-agent: the control connection failed ({error}) - stopping"
                        );
                        break;
                    }
                }
            }
            stop.cancel();
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use terra_protocol::STOP_SIGNAL;

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

    #[tokio::test]
    async fn agent_readiness_uses_control_without_waiting_for_hooks() {
        let (guest, host) = UnixStream::pair().unwrap();
        let (diagnostic, _diagnostic_host) = UnixStream::pair().unwrap();
        let control = File::from(OwnedFd::from(guest));
        let mut host = crate::into_async_file(host).unwrap();
        // `init` would also start the orphan reaper, which collects other tests' children.
        let agent = Agent {
            stop: CancellationToken::new(),
            shutdown: CancellationToken::new(),
            tasks: TaskTracker::new(),
            diagnostic: Diagnostics::new(File::from(OwnedFd::from(diagnostic))).unwrap(),
            control,
        };
        agent.report_ready().await.unwrap();
        let event = terra_protocol::read_frame_async::<LifecycleEvent>(&mut host)
            .await
            .unwrap();
        assert_eq!(event, Some(LifecycleEvent::AgentReady));
        agent.close(&Ok(0)).await;
    }
}
