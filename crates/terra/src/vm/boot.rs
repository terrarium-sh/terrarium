//! Booting a prepared box into its VM process.

use super::launcher_config::LauncherConfig;
use crate::cli::BootArgs;
use crate::session::{self, DETACH_KEY_NAME, SessionOutcome, pump_session};
use crate::state::BoxRef;
use crate::{config, sys};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// The background VM process's own first argv: `terra __vm <dir>` skips the
/// command line and takes its boot off stdin.
pub const VM_PROCESS_FLAG_ARG: &str = "__vm";

const DETACH_READY_DEADLINE: Duration =
    Duration::from_secs(terra_runtime::orchestration::GUEST_BOOT_TIMEOUT.as_secs() + 30);
const KILL_REAP_WAIT: Duration = Duration::from_secs(2);
const CONSOLE_DRAIN_WAIT: Duration = Duration::from_secs(2);
const MAX_BOOT_SPEC_BYTES: u64 = 64 << 20;
const REPLAY_LOG_TAIL_BYTES: u64 = 64 << 10;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BootSpec {
    pub cfg: config::Config,
    pub project_dir: PathBuf,
    pub root: bool,
    pub mode: terra_protocol::PlanMode,
    pub foreground: bool,
    #[serde(default)]
    pub builtin_bwrap: bool,
}

impl BootSpec {
    pub fn resolve(
        mut cfg: config::Config,
        args: &BootArgs,
        project_dir: PathBuf,
        boot: BootMode,
    ) -> Self {
        override_workload(&mut cfg, &args.command);
        Self {
            root: args.root,
            cfg,
            project_dir,
            mode: terra_protocol::PlanMode::Run,
            foreground: boot == BootMode::Foreground,
            builtin_bwrap: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum BootMode {
    Foreground,
    Detached,
    DetachedWithJoin,
}

pub fn get_vm_process_box_dir() -> Option<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    if args.next()? != VM_PROCESS_FLAG_ARG {
        return None;
    }
    args.next().map(PathBuf::from)
}

pub async fn start(
    spec: &BootSpec,
    bx: &BoxRef,
    boot: BootMode,
    run_lock: File,
    agent_timeout: Option<u64>,
    launcher: &LauncherConfig,
) -> Result<ExitCode> {
    match boot {
        BootMode::Detached => spawn_detached(bx, spec, run_lock, launcher),
        BootMode::Foreground => {
            eprintln!(
                "terra: starting {bx} in the foreground; `terra {} stop` stops it",
                bx.get_name()
            );
            print_mount_summary(&spec.cfg.mounts);
            spawn_foreground(bx, spec, run_lock, agent_timeout, launcher).await
        }
        BootMode::DetachedWithJoin => {
            spawn_and_attach(bx, spec, run_lock, agent_timeout, launcher).await
        }
    }
}

/// Join a running box's multiplexed terminal; the detach key detaches without
/// stopping the workload.
pub async fn attach(bx: &BoxRef, agent_timeout: Option<u64>) -> Result<ExitCode> {
    finish_session(bx, &pump_box_console(bx, agent_timeout).await?, None)
}

/// The caller keeps its lock while the isolated bake child uses a duplicate.
pub async fn run_bake(
    cfg: &config::Config,
    bx: &BoxRef,
    lock: &File,
    launcher: &LauncherConfig,
) -> Result<()> {
    let bake = BootSpec {
        cfg: cfg.clone(),
        project_dir: bx.get_project_dir().to_path_buf(),
        root: false,
        mode: terra_protocol::PlanMode::Create,
        foreground: false,
        builtin_bwrap: false,
    };
    eprintln!("terra: baking on_create for {bx} in an isolated VM (no shares)");
    let baking = BoxRef::mark_baking(lock).context("marking the on_create bake")?;
    let LaunchedVm { mut child, _guard } = spawn_vm_process(bx, &bake, lock, launcher)?;
    let deadline = Instant::now() + DETACH_READY_DEADLINE;
    let output = async {
        let stream =
            session::connect_to_agent(bx, terra_protocol::AgentService::Session, "bake", || {
                anyhow::ensure!(
                    child.try_wait()?.is_none(),
                    "the bake stopped before opening its console"
                );
                anyhow::ensure!(
                    Instant::now() < deadline,
                    "timed out opening the bake console"
                );
                Ok(())
            })
            .await?;
        session::pump_session_output(stream, &mut std::io::stdout()).await
    }
    .await;
    if output.is_err() {
        let _ = sys::kill_vm_child(&mut child);
    }
    let status = child.wait().context("waiting for the on_create bake")?;
    replay_logs(bx, status);
    output.context("streaming the on_create bake")?;
    if !status.success() {
        if let Some(signal) = sys::find_terminating_signal(status) {
            anyhow::bail!(
                "the on_create bake was killed (signal {signal}) before it finished.\n\
                 NOTE: a bake has no graceful stop - e.g. `terra stop` or the OOM killer \
                 both land as a plain signal"
            );
        }
        anyhow::bail!(
            "the on_create bake failed - fix the recipe, then `terra {} setup` re-runs \
             it (`--rebuild` for a clean slate); agent diagnostics are in diagnostics.log",
            bx.get_name()
        );
    }
    baking.clear().context("clearing bake mark")?;
    crate::vm::image::staged_write(&bx.get_dir().join(crate::state::BAKE_STAMP), |_| Ok(()))
        .with_context(|| {
            format!(
                "recording {}",
                bx.get_dir().join(crate::state::BAKE_STAMP).display()
            )
        })?;
    Ok(())
}

pub async fn run_vm_process(dir: PathBuf, is_at_a_terminal: bool) -> Result<ExitCode> {
    sys::validate_host_root()?;
    // A real child's stdin is the parent's pipe; a person who typed `terra
    // __vm` at a shell would otherwise sit in a silent read of their terminal.
    anyhow::ensure!(
        !is_at_a_terminal,
        "`terra {VM_PROCESS_FLAG_ARG}` is terra's own spelling of the background VM process - \
         it is spawned by a boot, not typed (`terra <box> -d` starts one)"
    );
    let spec = read_boot_spec(std::io::stdin().lock())?;
    let bx = BoxRef::from_state_dir(dir, &spec.project_dir);
    // The box arrives already locked, on a descriptor the boot dup'd into
    // place: nothing is taken here, so there is no race to lose and no window
    // in which a second terra could boot over this box.
    let lock = sys::claim_inherited_lock(&bx.get_dir().join(crate::state::PID_FILE)).context(
        "no run lock was handed to this process - a VM process is spawned by a boot, \
         not started by hand",
    )?;
    crate::vm::run(&spec, &bx, &lock, write_agent_ready).await
}

async fn pump_box_console(bx: &BoxRef, agent_timeout: Option<u64>) -> Result<SessionOutcome> {
    let stream = session::connect_to_agent(
        bx,
        terra_protocol::AgentService::Session,
        "session",
        session::wait_while_running(bx, agent_timeout),
    )
    .await?;
    pump_session(stream).await
}

async fn supervise_foreground(
    bx: &BoxRef,
    vm: impl std::future::Future<Output = Result<ExitCode>>,
    console: impl std::future::Future<Output = Result<SessionOutcome>>,
) -> Result<ExitCode> {
    tokio::pin!(vm, console);
    tokio::select! {
        result = &mut vm => {
            let status = result?;
            let _ = tokio::time::timeout(CONSOLE_DRAIN_WAIT, &mut console).await;
            Ok(status)
        }
        result = &mut console => {
            match result {
                Ok(SessionOutcome::Detached) => eprintln!("terra: console detached; {bx} still runs under this foreground command"),
                Ok(SessionOutcome::Exited(_) | SessionOutcome::Closed) => {}
                Err(error) => eprintln!("terra: console failed: {error:#}; {bx} still runs under this foreground command"),
            }
            vm.await
        }
    }
}

fn print_mount_summary(mounts: &[config::Mount]) {
    if mounts.is_empty() {
        eprintln!("terra: mounts: none (no host filesystem in the sandbox)");
    } else {
        for mount in mounts {
            eprintln!("terra: mount: {}", crate::render::format_mount_line(mount));
        }
    }
}

/// Spawn the VM and attach to its console. This process is only the
/// session's first client - but it is still the child's parent, so the
/// workload's exit code comes through unless you detach.
async fn spawn_and_attach(
    bx: &BoxRef,
    spec: &BootSpec,
    run_lock: File,
    agent_timeout: Option<u64>,
    launcher: &LauncherConfig,
) -> Result<ExitCode> {
    eprintln!(
        "terra: starting {bx} - {DETACH_KEY_NAME} detaches, `terra {} stop` stops it",
        bx.get_name()
    );
    print_mount_summary(&spec.cfg.mounts);
    let LaunchedVm { mut child, _guard } = spawn_vm_process(bx, spec, &run_lock, launcher)?;
    // The child owns the lock from here on; a copy held by this client would
    // keep the box reading as running, VM or no VM.
    drop(run_lock);

    let mut wait_for_agent = session::wait_while_running(bx, agent_timeout);
    let deadline = Instant::now() + DETACH_READY_DEADLINE;
    let joined =
        session::connect_to_agent(bx, terra_protocol::AgentService::Session, "session", || {
            wait_for_agent()?;
            anyhow::ensure!(
                Instant::now() < deadline,
                "timed out opening the VM console"
            );
            anyhow::ensure!(
                child.try_wait().context("checking on the VM")?.is_none(),
                "{bx} stopped before it had a session to join"
            );
            Ok(())
        })
        .await;
    let stream = match joined {
        Ok(stream) => stream,
        Err(e) => {
            // A VM that ends before any session was a fast workload or a
            // failed boot - either way its exit code is the answer.
            let Some(status) = child.try_wait().context("checking on the VM")? else {
                let _ = kill_and_reap_vm(child);
                let _ = write_boot_logs(bx, &mut std::io::stderr().lock());
                return Err(e);
            };
            replay_logs(bx, status);
            return Ok(ExitCode::from(compute_vm_child_exit_byte(bx, status)));
        }
    };

    let outcome = pump_session(stream).await?;
    finish_session(bx, &outcome, Some(&mut child))
}

fn spawn_detached(
    bx: &BoxRef,
    spec: &BootSpec,
    run_lock: File,
    launcher: &LauncherConfig,
) -> Result<ExitCode> {
    let LaunchedVm { child, _guard } = spawn_vm_process(bx, spec, &run_lock, launcher)?;
    drop(run_lock);
    wait_for_detached_agent(bx, child, DETACH_READY_DEADLINE)
}

fn wait_for_detached_agent(bx: &BoxRef, mut child: Child, timeout: Duration) -> Result<ExitCode> {
    let notification = start_ready_reader(&mut child)
        .and_then(|receiver| {
            receiver
                .recv_timeout(timeout)
                .context("waiting for VM startup notification")
        })
        .and_then(std::convert::identity);
    let (startup_pipe_closed, failure) = match notification {
        Ok(true) => {
            eprintln!(
                "terra: started {bx} detached (pid {}); agent ready; logs: {}",
                bx.read_vm_process()
                    .map_or(child.id(), |process| process.pid),
                bx.build_logs_command()
            );
            return Ok(ExitCode::SUCCESS);
        }
        Ok(false) => (
            true,
            "closed its startup pipe before reporting guest agent readiness".to_owned(),
        ),
        Err(error) => (
            false,
            format!(
                "never reported guest agent readiness (startup deadline {} seconds): {error:#}",
                timeout.as_secs()
            ),
        ),
    };
    let status = if startup_pipe_closed {
        wait_for_child_exit(&mut child, KILL_REAP_WAIT)?
    } else {
        None
    };
    let status = match status {
        Some(status) => Ok(status),
        None => kill_and_reap_vm(child),
    };
    let _ = write_boot_logs(bx, &mut std::io::stderr().lock());
    eprintln!("terra: {bx} {failure}; see `{}`", bx.build_logs_command());
    let status = status?;
    Ok(ExitCode::from(
        compute_vm_child_exit_byte(bx, status).max(1),
    ))
}

struct LaunchedVm {
    child: Child,
    _guard: Option<sys::VmChildGuard>,
}

fn spawn_vm_process(
    bx: &BoxRef,
    spec: &BootSpec,
    lock: &File,
    launcher: &LauncherConfig,
) -> Result<LaunchedVm> {
    super::launcher::validate_assets(launcher, spec, bx)?;
    bx.clear_host_pid()
        .context("clearing previous VM identity")?;
    let exe = std::env::current_exe().context("locating the terra binary")?;
    let mut child_spec = spec.clone();
    child_spec.builtin_bwrap = matches!(launcher, LauncherConfig::Bwrap { .. });
    let json = encode_boot_spec(&child_spec)?;
    super::resources::prepare_volumes(&child_spec, bx)?;
    let diagnostics = sys::create_regular_file(&bx.get_dir().join("launcher.log"))
        .context("opening VM launcher diagnostics")?;
    let mut inherited_files = Vec::new();
    #[cfg(target_os = "linux")]
    let mut bwrap_info = None;
    let mut cmd = match launcher {
        LauncherConfig::Direct => {
            let mut command = Command::new(&exe);
            command.arg(VM_PROCESS_FLAG_ARG).arg(bx.get_dir());
            command
        }
        LauncherConfig::Custom(init) => super::launcher::custom_command(init, &exe, spec, bx)?,
        LauncherConfig::Bwrap {
            policy,
            allow_fallback,
        } => {
            #[cfg(target_os = "linux")]
            {
                use std::io::{Seek, Write};
                let validated =
                    super::launcher_policy::resolve(policy.as_deref(), *allow_fallback)?;
                let mut file = tempfile::tempfile().context("opening private seccomp policy")?;
                file.write_all(&validated.bpf)?;
                file.rewind()?;
                let (reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
                let writer = File::from(writer);
                let identity =
                    sys::create_regular_file(&bx.get_dir().join(crate::state::HOST_PID_FILE))
                        .context("preparing protected VM identity")?;
                let mut command = super::bwrap::command(spec, bx, &exe, 5, 6)?;
                inherited_files.push(sys::pass_bwrap_info(&mut command, &writer)?);
                bwrap_info = Some((File::from(reader), identity));
                inherited_files.push(sys::pass_seccomp(&mut command, &file)?);
                command
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (policy, allow_fallback);
                anyhow::bail!("vm.init: bwrap requires Linux; configure a native custom launcher");
            }
        }
    };
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(diagnostics);
    let guard = sys::supervise_vm_child(
        &mut cmd,
        spec.foreground || spec.mode == terra_protocol::PlanMode::Create,
    )?;
    inherited_files.push(sys::pass_lock(&mut cmd, lock)?);
    let spawned = cmd.spawn();
    drop(inherited_files);
    let mut child = spawned
        .context("starting the configured VM launcher; check vm.init and launcher diagnostics")?;
    if let Some(guard) = &guard
        && let Err(error) = sys::attach_vm_child(guard, &child)
    {
        let _ = sys::kill_vm_child(&mut child);
        let _ = child.wait();
        return Err(error).context("attaching foreground VM supervision");
    }
    #[cfg(target_os = "linux")]
    if let Some((reader, identity)) = bwrap_info
        && let Err(error) = publish_bwrap_pid(reader, bx, lock, &identity, spec.mode)
    {
        let _ = kill_and_reap_vm(child);
        let _ = write_boot_logs(bx, &mut std::io::stderr().lock());
        return Err(error);
    }
    if let Err(error) = send_startup_input(&mut child, json) {
        let _ = sys::kill_vm_child(&mut child);
        let _ = child.wait();
        return Err(error).context("starting process startup writer");
    }
    Ok(LaunchedVm {
        child,
        _guard: guard,
    })
}

fn send_startup_input(child: &mut Child, json: Vec<u8>) -> Result<()> {
    let mut stdin = child.stdin.take().context("opening process startup pipe")?;
    std::thread::Builder::new()
        .name("process-startup-input".into())
        .spawn(move || {
            use std::io::Write;
            // A launcher that exits or ignores stdin must not block the startup deadline.
            let _ = stdin.write_all(&json);
        })
        .context("starting process startup writer")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn publish_bwrap_pid(
    reader: File,
    bx: &BoxRef,
    lock: &File,
    identity: &File,
    mode: terra_protocol::PlanMode,
) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct ChildInfo {
        #[serde(rename = "child-pid")]
        child_pid: u32,
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("bwrap-identity".into())
        .spawn(move || {
            let mut bytes = Vec::new();
            let result = reader
                .take(4097)
                .read_to_end(&mut bytes)
                .context("reading Bubblewrap child identity")
                .and_then(|_| {
                    anyhow::ensure!(
                        bytes.len() <= 4096,
                        "Bubblewrap identity exceeds 4096 bytes"
                    );
                    serde_json::from_slice::<ChildInfo>(&bytes)
                        .context("decoding Bubblewrap child identity")
                });
            let _ = sender.send(result);
        })
        .context("starting Bubblewrap identity reader")?;
    let info = receiver
        .recv_timeout(DETACH_READY_DEADLINE)
        .context("waiting for Bubblewrap child identity")??;
    BoxRef::publish_pid(
        identity,
        info.child_pid,
        mode == terra_protocol::PlanMode::Create,
    )
    .with_context(|| format!("publishing protected host VM identity for {bx}"))?;
    BoxRef::publish_pid(
        lock,
        info.child_pid,
        mode == terra_protocol::PlanMode::Create,
    )
    .with_context(|| format!("publishing host VM identity for {bx}"))
}

fn start_ready_reader(child: &mut Child) -> Result<std::sync::mpsc::Receiver<Result<bool>>> {
    let ready = child.stdout.take().context("opening VM startup pipe")?;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("vm-startup".into())
        .spawn(move || {
            let _ = sender.send(read_agent_ready(ready));
        })
        .context("starting VM startup reader")?;
    Ok(receiver)
}

async fn spawn_foreground(
    bx: &BoxRef,
    spec: &BootSpec,
    run_lock: File,
    agent_timeout: Option<u64>,
    launcher: &LauncherConfig,
) -> Result<ExitCode> {
    let LaunchedVm { mut child, _guard } = spawn_vm_process(bx, spec, &run_lock, launcher)?;
    drop(run_lock);
    #[cfg(unix)]
    let ready = relay_foreground_stop(bx).and_then(|()| start_ready_reader(&mut child));
    #[cfg(not(unix))]
    let ready = start_ready_reader(&mut child);
    let ready = match ready {
        Ok(ready) => ready,
        Err(error) => {
            let _ = kill_and_reap_vm(child);
            return Err(error);
        }
    };
    let deadline = Instant::now() + DETACH_READY_DEADLINE;
    let vm = async {
        let mut is_ready = false;
        loop {
            if let Some(status) = child.try_wait().context("waiting for foreground VM")? {
                replay_logs(bx, status);
                return Ok(ExitCode::from(compute_vm_child_exit_byte(bx, status)));
            }
            if !is_ready {
                match ready.try_recv() {
                    Ok(notification) => {
                        anyhow::ensure!(
                            notification?,
                            "VM closed its startup pipe before readiness"
                        );
                        is_ready = true;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        anyhow::bail!("VM startup reader disconnected")
                    }
                }
                anyhow::ensure!(
                    is_ready || Instant::now() < deadline,
                    "timed out waiting for VM startup notification"
                );
            }
            tokio::time::sleep(sys::POLL).await;
        }
    };
    let result = supervise_foreground(bx, vm, pump_box_console(bx, agent_timeout)).await;
    if result.is_err() {
        let _ = kill_and_reap_vm(child);
        let _ = write_boot_logs(bx, &mut std::io::stderr().lock());
    }
    result
}

#[cfg(unix)]
fn relay_foreground_stop(bx: &BoxRef) -> Result<()> {
    use terra_platform::io::local::LocalStream;
    let (host, mut receiver) = LocalStream::pair().context("creating foreground stop channel")?;
    let bx = bx.clone();
    std::thread::Builder::new()
        .name("foreground-stop".into())
        .spawn(move || {
            let mut byte = [0];
            if receiver.read_exact(&mut byte).is_ok() && byte == [terra_protocol::STOP_SIGNAL] {
                let _ = crate::cmd::stop::stop_and_wait(
                    &bx,
                    Duration::from_secs(crate::cli::DEFAULT_STOP_TIMEOUT_SECS),
                    crate::cmd::stop::SetupAction::Stop,
                );
            }
        })
        .context("starting foreground stop relay")?;
    sys::register_stop_channel(host.into());
    sys::install_stop_signal_handlers();
    Ok(())
}

fn finish_session(
    bx: &BoxRef,
    outcome: &SessionOutcome,
    owner: Option<&mut Child>,
) -> Result<ExitCode> {
    match outcome {
        SessionOutcome::Detached => {
            eprintln!(
                "\nterra: detached - {bx} keeps running (`terra {}` rejoins)",
                bx.get_name()
            );
            Ok(ExitCode::SUCCESS)
        }
        SessionOutcome::Exited(code) => {
            if let Some(child) = owner {
                let _ = child.wait();
            }
            Ok(ExitCode::from(crate::exit_status_byte(*code)))
        }
        // Closed with no status: the VM was killed (`terra rm --force`) or
        // died. Reported as a failure, because a script cannot tell that from
        // a clean success.
        SessionOutcome::Closed => {
            if let Some(child) = owner {
                let _ = child.wait();
            }
            anyhow::bail!("{bx} stopped without reporting a status - its VM was killed or died")
        }
    }
}

fn encode_boot_spec(spec: &BootSpec) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(spec).context("encoding the boot for the VM process")?;
    anyhow::ensure!(
        json.len() as u64 <= MAX_BOOT_SPEC_BYTES,
        "boot specification exceeds {MAX_BOOT_SPEC_BYTES} bytes; reduce the recipe or environment"
    );
    Ok(json)
}

fn read_boot_spec(reader: impl Read) -> Result<BootSpec> {
    let mut json = Vec::new();
    reader
        .take(MAX_BOOT_SPEC_BYTES + 1)
        .read_to_end(&mut json)
        .context("reading the boot to run")?;
    anyhow::ensure!(
        json.len() as u64 <= MAX_BOOT_SPEC_BYTES,
        "boot specification exceeds {MAX_BOOT_SPEC_BYTES} bytes; reduce the recipe or environment"
    );
    serde_json::from_slice(&json).context("decoding the boot to run")
}

fn override_workload(cfg: &mut config::Config, command: &[String]) {
    if let Some((entrypoint, args)) = command.split_first() {
        cfg.workload.entrypoint = PathBuf::from(entrypoint);
        cfg.workload.args = args.to_vec();
    }
}

fn write_agent_ready() {
    use std::io::Write as _;
    let mut startup = std::io::stdout().lock();
    let _ = startup
        .write_all(&[terra_protocol::AGENT_READY_NOTIFICATION])
        .and_then(|()| startup.flush());
}

fn read_agent_ready(mut reader: impl Read) -> Result<bool> {
    let mut ready = [0];
    match reader.read_exact(&mut ready) {
        Ok(()) if ready == [terra_protocol::AGENT_READY_NOTIFICATION] => Ok(true),
        Ok(()) => anyhow::bail!("invalid VM startup notification"),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error).context("reading VM startup notification"),
    }
}

fn kill_and_reap_vm(mut child: Child) -> Result<ExitStatus> {
    if let Some(status) = child.try_wait().context("checking failed VM startup")? {
        return Ok(status);
    }
    sys::kill_vm_child(&mut child).context("killing VM after failed startup")?;
    if let Some(status) = wait_for_child_exit(&mut child, KILL_REAP_WAIT)? {
        return Ok(status);
    }
    let pid = child.id();
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    anyhow::bail!(
        "VM process {pid} did not exit within {} seconds after being killed",
        KILL_REAP_WAIT.as_secs()
    )
}

fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().context("reaping failed VM startup")? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(
            crate::sys::POLL.min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

fn compute_vm_child_exit_byte(bx: &BoxRef, status: std::process::ExitStatus) -> u8 {
    if let Some(signal) = sys::find_terminating_signal(status) {
        eprintln!("terra: {bx}'s VM was killed (signal {signal})");
        return crate::exit_status_byte(128 + signal);
    }
    crate::exit_status_byte(status.code().unwrap_or(1))
}

fn replay_logs(bx: &BoxRef, status: std::process::ExitStatus) {
    if !status.success() {
        let _ = write_boot_logs(bx, &mut std::io::stderr().lock());
    }
}

fn write_boot_logs(bx: &BoxRef, output: &mut impl std::io::Write) -> std::io::Result<()> {
    for (label, path) in [
        ("launcher diagnostics", bx.get_dir().join("launcher.log")),
        ("host log", bx.get_dir().join(crate::state::LOG_FILE)),
        (
            "guest diagnostics",
            bx.get_dir().join(crate::state::DIAGNOSTICS_LOG),
        ),
    ] {
        let tail = read_log_tail(&path);
        if !tail.is_empty() {
            writeln!(output, "terra: {label}:\n{tail}")?;
        } else if label == "guest diagnostics" {
            writeln!(
                output,
                "terra: no guest diagnostics were received; inspect the host log for boot failures"
            )?;
        }
    }
    Ok(())
}

fn read_log_tail(path: &Path) -> String {
    use std::io::{Read, Seek, SeekFrom};
    // Plain open, symlinks followed: the log name is terra's own symlink to
    // the appender's current generation.
    let Ok(mut f) = std::fs::File::open(path) else {
        return String::new();
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or_default();
    let omitted = len.saturating_sub(REPLAY_LOG_TAIL_BYTES);
    let mut tail = Vec::new();
    if f.seek(SeekFrom::Start(omitted)).is_err()
        || f.take(REPLAY_LOG_TAIL_BYTES)
            .read_to_end(&mut tail)
            .is_err()
    {
        return String::new();
    }
    // Lossy: the tail starts mid-stream, so it can open inside a character.
    let text = String::from_utf8_lossy(&tail)
        .split('\n')
        .map(crate::render::escape_printable)
        .collect::<Vec<_>>()
        .join("\n");
    if omitted == 0 {
        return text;
    }
    format!(
        "terra: (the first {omitted} bytes are left out here - \
         `terra logs` has the whole log)\n{text}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn bubblewrap_identity_publishes_the_host_pid_before_boot() {
        use std::io::{Seek, Write};
        let directory = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(directory.path().to_path_buf(), directory.path());
        let lock = File::create(directory.path().join(crate::state::PID_FILE)).unwrap();
        let identity = File::create(directory.path().join(crate::state::HOST_PID_FILE)).unwrap();
        let mut info = tempfile::tempfile().unwrap();
        write!(info, "{{\"child-pid\":{}}}", std::process::id()).unwrap();
        info.rewind().unwrap();
        publish_bwrap_pid(info, &bx, &lock, &identity, terra_protocol::PlanMode::Run).unwrap();
        let process = bx.read_vm_process().unwrap();
        assert_eq!(process.pid, std::process::id());
        assert_eq!(
            process.process_identity,
            sys::read_process_start_time(std::process::id())
        );
        for invalid in [
            b"{}".as_slice(),
            b"{\"child-pid\":4294967295}",
            &[b' '; 4097],
        ] {
            let mut info = tempfile::tempfile().unwrap();
            info.write_all(invalid).unwrap();
            info.rewind().unwrap();
            assert!(
                publish_bwrap_pid(info, &bx, &lock, &identity, terra_protocol::PlanMode::Run)
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn foreground_console_completion_never_replaces_the_vm_result() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().to_path_buf(), dir.path());
        for outcome in [
            Ok(SessionOutcome::Detached),
            Ok(SessionOutcome::Exited(0)),
            Ok(SessionOutcome::Closed),
            Err(anyhow::anyhow!("console failed")),
        ] {
            let vm = async {
                tokio::task::yield_now().await;
                Ok(ExitCode::from(7))
            };
            let status = supervise_foreground(&bx, vm, std::future::ready(outcome))
                .await
                .unwrap();
            assert_eq!(status, ExitCode::from(7));
        }
    }

    #[tokio::test]
    async fn foreground_vm_completion_drains_the_console_but_never_waits_forever() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().to_path_buf(), dir.path());
        let drained = std::cell::Cell::new(false);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let vm = async {
            sender.send(()).unwrap();
            Ok(ExitCode::from(7))
        };
        let console = async {
            receiver.await.unwrap();
            tokio::task::yield_now().await;
            drained.set(true);
            Ok(SessionOutcome::Exited(7))
        };
        assert_eq!(
            supervise_foreground(&bx, vm, console).await.unwrap(),
            ExitCode::from(7)
        );
        assert!(drained.get());

        let status = tokio::time::timeout(
            CONSOLE_DRAIN_WAIT + Duration::from_secs(1),
            supervise_foreground(
                &bx,
                std::future::ready(Ok(ExitCode::SUCCESS)),
                std::future::pending(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(status, ExitCode::SUCCESS);

        let error = tokio::time::timeout(
            Duration::from_secs(1),
            supervise_foreground(
                &bx,
                std::future::ready(Err(anyhow::anyhow!("VM failed"))),
                std::future::pending(),
            ),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.to_string(), "VM failed");
    }

    /// A failure replays the *end* of a log, never the whole of it: a bake's
    /// `apk add` output runs to megabytes, and the line that says what broke is
    /// the last one. What is left out is said out loud, so nobody reads a
    /// truncated log as the whole story.
    #[test]
    fn a_replayed_log_is_bounded_and_says_what_it_left_out() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join(crate::state::LOG_FILE);

        // A short log comes back whole and unannotated.
        std::fs::write(&log, b"the only line\n").unwrap();
        assert_eq!(read_log_tail(&log), "the only line\n");

        // A long one keeps its ending - which is where a failure reports.
        let mut content = vec![b'Q'; usize::try_from(REPLAY_LOG_TAIL_BYTES).unwrap() * 2];
        content.extend_from_slice(b"hook `apk add nope` failed\n");
        std::fs::write(&log, &content).unwrap();
        let tail = read_log_tail(&log);
        assert!(tail.ends_with("hook `apk add nope` failed\n"), "{tail}");
        assert!(
            u64::try_from(tail.len()).unwrap() < REPLAY_LOG_TAIL_BYTES + 200,
            "replayed {} bytes of a {}-byte log",
            tail.len(),
            content.len()
        );
        assert!(tail.contains("left out here"), "{tail}");
        assert!(tail.contains("terra logs"), "the way to the rest: {tail}");

        // A log that is not there replays as nothing, not as an error: the
        // caller is already reporting something of its own.
        assert!(read_log_tail(&dir.path().join("absent.log")).is_empty());
    }

    #[test]
    fn automatic_log_replay_escapes_terminal_controls() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("log");
        std::fs::write(&log, b"before\n\x1b]52;c;secret\x07\rhidden\n").unwrap();
        let tail = read_log_tail(&log);
        assert!(tail.starts_with("before\n"));
        assert!(tail.ends_with("hidden\n"));
        assert!(!tail.chars().any(|c| c.is_control() && c != '\n'));
        assert!(tail.contains("secret"));
    }

    #[test]
    fn missing_guest_logs_do_not_hide_host_boot_failure() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().to_path_buf(), dir.path());
        std::fs::write(
            dir.path().join(crate::state::LOG_FILE),
            b"vCPU 0 failed: KVM_RUN\n",
        )
        .unwrap();
        let mut output = Vec::new();
        write_boot_logs(&bx, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("vCPU 0 failed: KVM_RUN"));
        assert!(output.contains("no guest diagnostics were received"));
    }

    #[test]
    fn detached_start_requires_an_explicit_agent_ready_notification() {
        assert!(read_agent_ready(b"R".as_slice()).unwrap());
        assert!(!read_agent_ready(b"".as_slice()).unwrap());
        assert!(read_agent_ready(b"X".as_slice()).is_err());
    }

    #[test]
    fn detached_deadline_in_developer_docs_matches_supervision() {
        let docs = include_str!("../../../../README.dev.md");
        assert!(docs.contains(&format!(
            "bounded to {} seconds",
            DETACH_READY_DEADLINE.as_secs()
        )));
        assert!(docs.contains(&format!("{} seconds for reaping", KILL_REAP_WAIT.as_secs())));
    }

    #[test]
    #[cfg(unix)]
    fn detached_start_bounds_a_stopped_child_and_preserves_exit_status() {
        let directory = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(directory.path().to_path_buf(), directory.path());
        for (script, timeout, expected) in [
            ("kill -STOP $$", Duration::from_millis(50), 137),
            ("exit 23", Duration::from_secs(5), 23),
            ("kill -TERM $$", Duration::from_secs(5), 143),
            ("exit 0", Duration::from_secs(5), 1),
            ("exec 1>&-; kill -STOP $$", Duration::from_secs(5), 137),
        ] {
            let child = Command::new("/bin/sh")
                .args(["-c", script])
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let started = Instant::now();
            let code = wait_for_detached_agent(&bx, child, timeout).unwrap();
            assert_eq!(code, ExitCode::from(expected), "{script}");
            assert!(started.elapsed() < Duration::from_secs(5), "{script}");
        }
    }

    #[test]
    fn oversized_boot_input_stops_reading_at_the_limit() {
        let mut input = std::io::repeat(b' ').take(MAX_BOOT_SPEC_BYTES + 2);
        let error = read_boot_spec(&mut input).err().unwrap().to_string();
        assert!(error.contains("boot specification exceeds"), "{error}");
        assert_eq!(input.limit(), 1);
    }

    /// The child is handed a boot and resolves nothing of its own, so what
    /// crosses that pipe has to be the whole of one - env included, and the
    /// recipe as the parent resolved it rather than a path to re-read.
    #[test]
    fn a_boot_survives_the_trip_to_the_background_process() {
        use clap::Parser;
        let cfg: config::Config = yaml_serde::from_str(
            "hw:\n  cpus: 4\n  mem_mib: 2048\nenv:\n  API_KEY: sk-secret\n\
             workload:\n  entrypoint: /bin/sh\n",
        )
        .unwrap();
        let boot = crate::cli::Cli::parse_from(["terra", "--", "npm", "test"]).boot;

        let spec = BootSpec::resolve(cfg, &boot, PathBuf::from("/proj"), BootMode::Detached);
        let back = read_boot_spec(serde_json::to_vec(&spec).unwrap().as_slice()).unwrap();

        assert_eq!(
            back.project_dir,
            PathBuf::from("/proj"),
            "the child re-resolves nothing, its own cwd included"
        );
        assert_eq!(back.cfg.hw.cpus, 4, "the recipe's hardware crosses whole");
        assert_eq!(back.cfg.hw.mem_mib, 2048);
        assert_eq!(back.cfg.env["API_KEY"], "sk-secret");
        assert_eq!(back.cfg.workload.entrypoint, PathBuf::from("npm"));
        assert_eq!(back.cfg.workload.args, ["test"]);
    }

    /// Foreground supervision and the workload's terminal use the same flag,
    /// derived from the resolved boot mode.
    #[test]
    fn the_spec_takes_foreground_supervision_from_the_boot_mode() {
        use clap::Parser;
        let foreground_of = |flags: &[&str], boot| {
            let argv: Vec<&str> = std::iter::once("terra")
                .chain(flags.iter().copied())
                .collect();
            BootSpec::resolve(
                yaml_serde::from_str("{}").unwrap(),
                &crate::cli::Cli::parse_from(argv).boot,
                PathBuf::from("/proj"),
                boot,
            )
            .foreground
        };

        assert!(foreground_of(&["--foreground"], BootMode::Foreground));
        for spawned in [BootMode::Detached, BootMode::DetachedWithJoin] {
            assert!(!foreground_of(&[], spawned), "{spawned:?}");
            assert!(!foreground_of(&["--foreground"], spawned), "{spawned:?}");
        }
    }

    #[test]
    fn trailing_args_override_the_workload() {
        use clap::Parser;
        let c = crate::cli::Cli::parse_from(["terra", "--", "npm", "test", "--watch"]);
        assert!(c.cmd.is_none(), "using a box has no verb");
        assert_eq!(c.boot.command, ["npm", "test", "--watch"]);

        let mut cfg: config::Config = yaml_serde::from_str("{}").unwrap();
        override_workload(&mut cfg, &c.boot.command);
        assert_eq!(cfg.workload.entrypoint, PathBuf::from("npm"));
        assert_eq!(cfg.workload.args, ["test", "--watch"]);

        let mut cfg: config::Config = yaml_serde::from_str("{}").unwrap();
        override_workload(&mut cfg, &[]);
        assert_eq!(cfg.workload, config::Workload::default());
    }
}
