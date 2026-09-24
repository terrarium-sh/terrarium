//! Booting a prepared box into its VM process.

use crate::cli::BootArgs;
use crate::session::{self, DETACH_KEY_NAME, SessionOutcome, pump_session};
use crate::state::BoxRef;
use crate::{config, sys};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitCode, ExitStatus};
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
) -> Result<ExitCode> {
    match boot {
        BootMode::Detached => spawn_detached(bx, spec, run_lock),
        BootMode::Foreground => {
            eprintln!(
                "terra: starting {bx} in the foreground; `terra {} stop` stops it",
                bx.get_name()
            );
            print_mount_summary(&spec.cfg.mounts);
            run_in_process(bx, spec, &run_lock, agent_timeout).await
        }
        BootMode::DetachedWithJoin => spawn_and_attach(bx, spec, run_lock, agent_timeout).await,
    }
}

/// Join a running box's multiplexed terminal; the detach key detaches without
/// stopping the workload.
pub async fn attach(bx: &BoxRef, agent_timeout: Option<u64>) -> Result<ExitCode> {
    finish_session(bx, &pump_box_console(bx, agent_timeout).await?, None)
}

/// The caller keeps its lock while the isolated bake child uses a duplicate.
pub async fn run_bake(cfg: &config::Config, bx: &BoxRef, lock: &File) -> Result<()> {
    let bake = BootSpec {
        cfg: cfg.clone(),
        project_dir: bx.get_project_dir().to_path_buf(),
        root: false,
        mode: terra_protocol::PlanMode::Create,
        foreground: false,
    };
    eprintln!("terra: baking on_create for {bx} in an isolated VM (no shares)");
    let baking = BoxRef::mark_baking(lock).context("marking the on_create bake")?;
    let mut child = spawn_vm_process(bx, &bake, lock)?;
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
        let _ = child.kill();
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
    run_in_process(&bx, &spec, &lock, None).await
}

async fn run_in_process(
    bx: &BoxRef,
    spec: &BootSpec,
    lock: &File,
    agent_timeout: Option<u64>,
) -> Result<ExitCode> {
    if spec.foreground {
        let vm = Box::pin(crate::vm::run(spec, bx, lock, || {}));
        let console = pump_box_console(bx, agent_timeout);
        supervise_foreground(bx, vm, console)
            .await
            .inspect_err(|error| log::error!("VM failed: {error:#}"))
    } else {
        crate::vm::run(spec, bx, lock, write_agent_ready)
            .await
            .inspect_err(|error| log::error!("VM failed: {error:#}"))
    }
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
                Ok(SessionOutcome::Detached) => eprintln!("terra: console detached; {bx} still runs in this foreground process"),
                Ok(SessionOutcome::Exited(_) | SessionOutcome::Closed) => {}
                Err(error) => eprintln!("terra: console failed: {error:#}; {bx} still runs in this foreground process"),
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
) -> Result<ExitCode> {
    eprintln!(
        "terra: starting {bx} - {DETACH_KEY_NAME} detaches, `terra {} stop` stops it",
        bx.get_name()
    );
    print_mount_summary(&spec.cfg.mounts);
    let mut child = spawn_vm_process(bx, spec, &run_lock)?;
    // The child owns the lock from here on; a copy held by this client would
    // keep the box reading as running, VM or no VM.
    drop(run_lock);

    let mut wait_for_agent = session::wait_while_running(bx, agent_timeout);
    let joined =
        session::connect_to_agent(bx, terra_protocol::AgentService::Session, "session", || {
            wait_for_agent()?;
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
                let _ = write_boot_logs(bx, &mut std::io::stderr().lock());
                return Err(e);
            };
            replay_logs(bx, status);
            return Ok(ExitCode::from(compute_vm_child_exit_byte(bx, status)));
        }
    };

    finish_session(bx, &pump_session(stream).await?, Some(&mut child))
}

fn spawn_detached(bx: &BoxRef, spec: &BootSpec, run_lock: File) -> Result<ExitCode> {
    let child = spawn_vm_process(bx, spec, &run_lock)?;
    drop(run_lock);
    wait_for_detached_agent(bx, child, DETACH_READY_DEADLINE)
}

fn wait_for_detached_agent(bx: &BoxRef, mut child: Child, timeout: Duration) -> Result<ExitCode> {
    let ready = child.stdout.take().context("opening VM startup pipe")?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::Builder::new()
        .name("vm-startup".into())
        .spawn(move || {
            let _ = sender.send(read_agent_ready(ready));
        });
    let notification = reader
        .context("starting VM startup reader")
        .and_then(|_| {
            receiver
                .recv_timeout(timeout)
                .context("waiting for VM startup notification")
        })
        .and_then(std::convert::identity);
    let (startup_pipe_closed, failure) = match notification {
        Ok(true) => {
            eprintln!(
                "terra: started {bx} detached (pid {}); agent ready; logs: {}",
                child.id(),
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

/// We pass the boot through stdin, a pipe - not argv (any user can read
/// `/proc/<pid>/cmdline`) or the environment (it lands in core dumps). The
/// pipe is read once and exists nowhere else.
fn spawn_vm_process(bx: &BoxRef, spec: &BootSpec, lock: &File) -> Result<std::process::Child> {
    use std::process::{Command, Stdio};
    let exe = std::env::current_exe().context("locating the terra binary")?;
    let json = serde_json::to_string(spec).context("encoding the boot for the VM process")?;
    anyhow::ensure!(
        json.len() as u64 <= MAX_BOOT_SPEC_BYTES,
        "boot specification exceeds {MAX_BOOT_SPEC_BYTES} bytes; reduce the recipe or environment"
    );
    let mut cmd = Command::new(exe);
    cmd.arg(VM_PROCESS_FLAG_ARG)
        .arg(bx.get_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    sys::detach(&mut cmd);
    let inheritance = sys::pass_lock(&mut cmd, lock)?;
    let spawned = cmd.spawn();
    drop(inheritance);
    let mut child = spawned.context("starting the background terra")?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        // EPIPE here means the child already died; its exit reports the cause.
        let _ = stdin.write_all(json.as_bytes());
    }
    Ok(child)
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
    child.kill().context("killing VM after failed startup")?;
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
        use std::process::{Command, Stdio};
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

    /// Running the VM in this process is one fact with two spellings - the
    /// [`BootMode`] a boot runs under, and the flag the VM process reads off
    /// its spec - so the spec takes it from the mode rather than deciding it
    /// again from the flags. Two derivations can disagree, and nothing would
    /// say so: the console and the workload's terminal both turn on this, and
    /// a boot with them pointed different ways is a silent misbehaviour, not
    /// an error.
    #[test]
    fn the_spec_takes_running_in_this_process_from_the_boot_mode() {
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
            // The mode is what decides, so the flag alone cannot make a VM
            // that is being spawned believe it runs here.
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
