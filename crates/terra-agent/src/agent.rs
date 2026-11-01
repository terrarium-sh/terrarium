//! The running agent once it has entered the root: its link to the host and the setup or run boot it carries out.

use super::bootstrap;
use super::diagnostics::Diagnostics;
use super::into_async_file;
use super::services::{Server, StartupState};
use super::{OUTPUT_DRAIN_GRACE, STOP_GRACE};
use crate::session::Session;
use crate::workload::GuestUser;
use anyhow::{Context, Result, bail};
use pty_process::blocking::{Command as PtyCommand, Pts};
use rustix::termios::Termios;
use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use terra_protocol::{CLOCK_SYNC, LifecycleEvent, Plan, STOP_SIGNAL};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const INITIAL_SESSION_WAIT: Duration = Duration::from_secs(30);
const HOOK_TIMEOUT: Duration = Duration::from_mins(5);

/// The running agent: its link to the host, its shutdown signals and its background tasks.
pub(crate) struct Agent {
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
    /// The workload's controlling terminal; daemons, hooks and the agent write here too, so the
    /// session shows everything in the order it was written.
    pts: Pts,
    /// The terminal settings before the workload could change them.
    default_settings: Termios,
    /// Ends once the PTY output has all been copied into `session`.
    drained: JoinHandle<()>,
}

impl Agent {
    pub(crate) fn init(control: &File, diagnostic: File) -> Result<Self> {
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
        agent.diagnostic.record_boot_stage("boot_plan_received");
        Ok(agent)
    }

    pub(crate) async fn setup(&self, plan: &Plan, clients: mpsc::Receiver<File>) -> Result<i32> {
        self.prepare_guest(plan).await?;
        crate::mounts::mount_volumes(plan)?;
        // A setup boot never starts the workload, so sync and exec are refused from the start.
        let console = self
            .start_console(plan, clients, StartupState::Refused)
            .await?;
        self.report_ready().await?;
        let created = self.run_on_create(plan, &console).await.map(|()| 0);
        console.exit(created).await
    }

    pub(crate) async fn run(&self, plan: &Plan, clients: mpsc::Receiver<File>) -> Result<i32> {
        self.prepare_guest(plan).await?;
        crate::mounts::mount_shares_and_volumes(plan)?;
        let console = self
            .start_console(plan, clients, StartupState::Pending)
            .await?;
        self.report_ready().await?;
        let outcome = async {
            self.run_on_start(plan, &console).await?;
            let (code, daemons) = self
                .run_workload(plan, &console)
                .await
                .context("running the workload")?;
            self.run_pre_stop(plan, &console).await;
            daemons.stop(STOP_GRACE).await;
            Ok(code)
        }
        .await;
        console.exit(outcome).await
    }

    pub(crate) async fn close(self, outcome: &Result<i32>) {
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
        restrict_ptrace();
        crate::loopback::enable()?;
        crate::network::start(&self.tasks, plan, &self.shutdown, &self.diagnostic).await?;
        self.diagnostic.record_boot_stage("networking_ready");
        Ok(())
    }

    async fn start_console(
        &self,
        plan: &Plan,
        clients: mpsc::Receiver<File>,
        initial_state: StartupState,
    ) -> Result<Console> {
        let (master, pts) = open_pty()?;
        let default_settings = rustix::termios::tcgetattr(&pts)?;
        let reader = master.try_clone()?;
        let session = Session::new(&self.tasks, into_async_file(master)?, &self.shutdown)?;
        let (initial_session, connected) =
            plan.await_initial_session.then(|| mpsc::channel(1)).unzip();
        let server = crate::services::init_server(
            &self.tasks,
            session.clone(),
            clients,
            GuestUser::from_plan(plan),
            initial_session,
            initial_state,
            &self.shutdown,
        );
        if let Some(connected) = connected {
            wait_for_initial_session(connected, &self.stop).await?;
        }
        let drained = forward_pty_output(&self.tasks, reader, session.clone(), &self.shutdown);
        Ok(Console {
            session,
            server,
            pts,
            default_settings,
            drained,
        })
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
        console: &Console,
    ) -> Result<(i32, crate::daemon::Daemons)> {
        let mut command = workload_command(plan)?;
        let daemons = crate::daemon::spawn_all(
            &self.tasks,
            &plan.daemons,
            GuestUser::from_plan(plan),
            console.pts.as_fd(),
            &self.shutdown,
        )?;
        let (_child, workload) =
            match crate::reap::spawn_owned(|| command.spawn_borrowed(&console.pts)) {
                Ok(child) => child,
                Err(error) => {
                    daemons.stop(STOP_GRACE).await;
                    return Err(error.into());
                }
            };
        self.diagnostic.record_boot_stage("workload_ready");
        let code = self.wait_for_workload(&workload).await;
        console.restore_terminal();
        Ok((code, daemons))
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
        console.run_stop_hooks(&plan.pre_stop, &self.shutdown).await;
    }
}

impl Console {
    async fn say(&self, line: &str) {
        use std::io::Write as _;
        let line = format!("{line}\n");
        let Ok(terminal) = self.pts.as_fd().try_clone_to_owned() else {
            return;
        };
        // A full terminal blocks the write until the session catches up, so it runs off the
        // async threads.
        let _ =
            tokio::task::spawn_blocking(move || File::from(terminal).write_all(line.as_bytes()))
                .await;
    }

    async fn run_hooks(&self, lines: &[String], cancellation: &CancellationToken) -> Result<()> {
        for line in lines {
            run_hook(line, self.pts.as_fd(), cancellation).await?;
        }
        Ok(())
    }

    /// Runs every hook, reporting a failure on the console instead of stopping at it.
    async fn run_stop_hooks(&self, lines: &[String], cancellation: &CancellationToken) {
        for line in lines {
            if let Err(error) = run_hook(line, self.pts.as_fd(), cancellation).await {
                self.say(&format!("terra-agent: stop hook failed: {error:#}"))
                    .await;
            }
        }
    }

    /// Undoes what the workload changed, such as a raw mode it never left.
    fn restore_terminal(&self) {
        if let Err(error) = rustix::termios::tcsetattr(
            &self.pts,
            rustix::termios::OptionalActions::Now,
            &self.default_settings,
        ) {
            eprintln!("terra-agent: warning: could not restore the console terminal: {error}");
        }
    }

    /// Ends every attached client with the boot's exit code, [`crate::AGENT_FAILED`] when the boot
    /// failed, once the terminal's output has reached them.
    async fn exit(mut self, outcome: Result<i32>) -> Result<i32> {
        // The terminal reports end of output only once every write end is closed, the agent's
        // too; see console_output_reaches_clients_in_order_before_the_exit.
        drop(self.pts);
        let _ = tokio::time::timeout(OUTPUT_DRAIN_GRACE, &mut self.drained).await;
        let code = *outcome.as_ref().unwrap_or(&crate::AGENT_FAILED);
        self.session.broadcast_exit(code).await;
        outcome
    }

    /// Serves sync and exec once startup succeeded; otherwise refuses them.
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
                Err(error)
            }
        }
    }
}

fn restrict_ptrace() {
    const PATH: &str = "/proc/sys/kernel/yama/ptrace_scope";
    if let Err(error) = std::fs::write(PATH, "1\n") {
        eprintln!("terra-agent: warning: could not restrict ptrace ({PATH}): {error}");
    }
}

/// Creates what the recipe names in the root image; a run boot only finds it there.
fn write_persistent_state(plan: &Plan) -> Result<()> {
    terra_protocol::guest_root::link_per_boot_files(Path::new("/"))
        .context("restoring the per-boot links on_create replaced")?;
    crate::mounts::prepare_mount_points(plan)?;
    if let Some(workdir) = &plan.workdir {
        crate::sync::ensure_directory(Path::new(workdir), GuestUser::Workload)
            .with_context(|| format!("creating workdir {workdir}"))?;
    }
    Ok(())
}

fn enter_workdir(plan: &Plan) -> Result<()> {
    let workdir = plan
        .workdir
        .as_deref()
        .unwrap_or(terra_protocol::WORKLOAD_HOME);
    crate::sync::ensure_directory(Path::new(workdir), GuestUser::from_plan(plan))
        .with_context(|| format!("creating workdir {workdir}"))?;
    std::env::set_current_dir(workdir).with_context(|| format!("entering workdir {workdir}"))
}

async fn run_hook(
    line: &str,
    terminal: BorrowedFd<'_>,
    cancellation: &CancellationToken,
) -> Result<()> {
    let mut command = crate::recipe_shell_command(line, terminal)?;
    let status = crate::reap::run_or_kill(&mut command, HOOK_TIMEOUT, cancellation)
        .await
        .with_context(|| format!("hook `{line}`"))?;
    if !status.success() {
        bail!("hook `{line}` failed ({status})");
    }
    Ok(())
}

fn workload_command(plan: &Plan) -> Result<PtyCommand> {
    let Some((cmd, args)) = plan.workload.split_first() else {
        bail!("empty workload argv");
    };
    let mut command = std::process::Command::new(cmd);
    command.args(args);
    crate::workload::run_as(&mut command, GuestUser::from_plan(plan));
    Ok(command.into())
}

fn open_pty() -> Result<(OwnedFd, Pts)> {
    let (pty, pts) = pty_process::blocking::open()?;
    pty.resize(pty_process::Size::new(
        crate::session::DEFAULT_ROWS,
        crate::session::DEFAULT_COLS,
    ))?;
    Ok((pty.into(), pts))
}

fn forward_pty_output(
    tasks: &TaskTracker,
    reader: OwnedFd,
    session: Arc<Session>,
    shutdown: &CancellationToken,
) -> JoinHandle<()> {
    let shutdown = shutdown.clone();
    tasks.spawn(async move {
        shutdown
            .run_until_cancelled(async {
                let Ok(mut reader) = into_async_file(reader) else {
                    return;
                };
                let mut bytes = [0; 4096];
                loop {
                    use tokio::io::AsyncReadExt as _;
                    match reader.read(&mut bytes).await {
                        Ok(0) | Err(_) => return,
                        Ok(len) => session.feed_output(&bytes[..len]).await,
                    }
                }
            })
            .await;
    })
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

pub(crate) async fn watch_control(
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

    /// An agent without `init`'s orphan reaper, which would collect other tests' children, and
    /// the host ends of its control and diagnostic links.
    fn test_agent() -> (Agent, UnixStream, UnixStream) {
        let (guest, host) = UnixStream::pair().unwrap();
        let (diagnostic, diagnostic_host) = UnixStream::pair().unwrap();
        let agent = Agent {
            stop: CancellationToken::new(),
            shutdown: CancellationToken::new(),
            tasks: TaskTracker::new(),
            diagnostic: Diagnostics::new(File::from(OwnedFd::from(diagnostic))).unwrap(),
            control: File::from(OwnedFd::from(guest)),
        };
        (agent, host, diagnostic_host)
    }

    #[tokio::test]
    async fn agent_readiness_uses_control_without_waiting_for_hooks() {
        let (agent, host, _diagnostic_host) = test_agent();
        let mut host = crate::into_async_file(host).unwrap();
        agent.report_ready().await.unwrap();
        let event = terra_protocol::read_frame_async::<LifecycleEvent>(&mut host)
            .await
            .unwrap();
        assert_eq!(event, Some(LifecycleEvent::AgentReady));
        agent.close(&Ok(0)).await;
    }

    /// Hook output, the agent's own lines and the exit reach a client in the order they were
    /// written: a hook's last line, even without a newline, comes before the agent's next line,
    /// and the exit waits for both. A terminal the workload left raw is restored first, and the
    /// exit sees end of output instead of waiting out the grace, so no write end leaks.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn console_output_reaches_clients_in_order_before_the_exit() {
        use crate::session::ClientConn;

        let (agent, _control_host, _diagnostic_host) = test_agent();
        let (_clients, clients) = mpsc::channel(1);
        let console = agent
            .start_console(&Plan::bare_run(Vec::new()), clients, StartupState::Refused)
            .await
            .unwrap();
        let (mut host, guest) = UnixStream::pair().unwrap();
        let client = ClientConn::from_file(File::from(OwnedFd::from(guest))).unwrap();
        console.session.attach_client(&client).await.unwrap();

        let mut raw = rustix::termios::tcgetattr(&console.pts).unwrap();
        raw.make_raw();
        rustix::termios::tcsetattr(&console.pts, rustix::termios::OptionalActions::Now, &raw)
            .unwrap();
        console.restore_terminal();
        console
            .run_hooks(
                &["printf 'hook\\nlast'".to_string()],
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        console.say("agent line").await;
        let start = std::time::Instant::now();
        console.exit(Ok(3)).await.unwrap();
        assert!(
            start.elapsed() < OUTPUT_DRAIN_GRACE,
            "exit waited {:?} for the terminal",
            start.elapsed()
        );

        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut shown = Vec::new();
        let code = loop {
            match terra_protocol::read_frame(&mut host).unwrap() {
                Some(terra_protocol::AgentOutput::Out(bytes)) => shown.extend(bytes),
                Some(terra_protocol::AgentOutput::Exit { code }) => break code,
                frame => panic!("unexpected frame {frame:?}"),
            }
        };
        assert_eq!(
            String::from_utf8_lossy(&shown),
            "hook\r\nlastagent line\r\n"
        );
        assert_eq!(code, 3);
        agent.close(&Ok(0)).await;
    }

    /// A terminal like the console's, and the reading end the session forwarder would hold.
    fn open_terminal() -> (crate::AsyncFile, Pts) {
        let (pty, pts) = pty_process::blocking::open().unwrap();
        (crate::into_async_file(OwnedFd::from(pty)).unwrap(), pts)
    }

    async fn read_until(terminal: &mut crate::AsyncFile, expected: &[u8]) {
        use tokio::io::AsyncReadExt as _;

        let mut output = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut bytes = [0; 256];
            while !output.ends_with(expected) {
                let len = terminal.read(&mut bytes).await.unwrap();
                output.extend_from_slice(&bytes[..len]);
            }
        })
        .await
        .unwrap_or_else(|_| panic!("terminal showed {:?}", String::from_utf8_lossy(&output)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hook_writes_to_the_terminal_while_it_runs() {
        let (mut terminal, pts) = open_terminal();
        let running = tokio::spawn(async move {
            run_hook(
                "printf 'start\\n'; sleep 1; printf 'stop\\n' >&2",
                pts.as_fd(),
                &CancellationToken::new(),
            )
            .await
        });
        read_until(&mut terminal, b"start\r\n").await;
        assert!(
            !running.is_finished(),
            "the hook finished before its first output arrived"
        );
        running.await.unwrap().unwrap();
        read_until(&mut terminal, b"stop\r\n").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failing_stop_hook_leaves_its_stderr_on_the_terminal() {
        let (mut terminal, pts) = open_terminal();
        let error = run_hook(
            "printf 'stopping\\n' >&2; exit 7",
            pts.as_fd(),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("failed"), "{error}");
        read_until(&mut terminal, b"stopping\r\n").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hook_descendant_cannot_hold_the_hook_open() {
        let (_terminal, pts) = open_terminal();
        let start = std::time::Instant::now();
        run_hook(
            "sleep 3 & printf done",
            pts.as_fd(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "the hook took {:?}",
            start.elapsed()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_a_hook_reaps_its_process_before_returning() {
        let cancellation = CancellationToken::new();
        let pid_file = crate::create_scratch_path("hook", "cancelled");
        let _ = std::fs::remove_file(&pid_file);
        let line = format!("echo $$ > {}; exec sleep 600", pid_file.display());
        let worker_cancellation = cancellation.clone();
        let (_terminal, pts) = open_terminal();
        let worker =
            tokio::spawn(async move { run_hook(&line, pts.as_fd(), &worker_cancellation).await });
        let pid = crate::read_pid_file(&pid_file).await;
        cancellation.cancel();
        let error = tokio::time::timeout(Duration::from_secs(3), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(format!("{error:#}").contains("cancelled"), "{error:#}");
        assert!(rustix::process::test_kill_process(pid).is_err());
        let _ = std::fs::remove_file(pid_file);
    }
}
