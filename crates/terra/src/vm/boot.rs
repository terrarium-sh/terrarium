//! Booting a prepared box into its VM process.

use crate::cli::BootArgs;
use crate::session::{self, DETACH_KEY_NAME, SessionOutcome, pump_session};
use crate::state::BoxRef;
use crate::sys::POLL;
use crate::{config, sys};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitCode};
use std::time::{Duration, Instant};
use terra_platform::io::local::AsyncLocalStream;

/// The background VM process's own first argv: `terra __vm <dir>` skips the
/// command line and takes its boot off stdin.
pub const VM_PROCESS_FLAG_ARG: &str = "__vm";

pub fn get_vm_process_box_dir() -> Option<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    if args.next()? != VM_PROCESS_FLAG_ARG {
        return None;
    }
    args.next().map(PathBuf::from)
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BootSpec {
    /// The recipe with this boot's flag overrides folded in
    pub cfg: config::Config,
    /// The box's project directory
    pub project_dir: PathBuf,
    pub root: bool,
    pub mode: terra_protocol::PlanMode,
    pub foreground: bool,
}

impl BootSpec {
    /// fold this boot's flag overrides into the pinned recipe
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

const DETACH_CONFIRM_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BOOT_SPEC_BYTES: u64 = 64 << 20;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum BootMode {
    Foreground,
    Detached,
    DetachedWithJoin,
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
        BootMode::DetachedWithJoin | BootMode::Foreground => {
            run_attached(bx, spec, run_lock, agent_timeout).await
        }
    }
}

/// The caller keeps its lock while the isolated bake child uses a duplicate.
pub fn run_bake(cfg: &config::Config, bx: &BoxRef, lock: &File) -> Result<()> {
    let bake = BootSpec {
        cfg: cfg.clone(),
        project_dir: bx.get_project_dir().to_path_buf(),
        root: false,
        mode: terra_protocol::PlanMode::Create,
        // never in-process
        foreground: false,
    };
    eprintln!(
        "terra: baking on_create for {bx} in an isolated VM (no shares) - \
         `terra {} logs --diagnostics --follow` follows it",
        bx.get_name()
    );
    // Marked for as long as the bake holds the box: it serves no agent port, so
    // a second terra finding the lock held must not offer a session to join.
    let baking = bx.mark_baking(lock);
    let mut child = spawn_vm_process(bx, &bake, lock)?;
    let status = child.wait().context("waiting for the on_create bake")?;
    if !status.success() {
        replay_logs(bx, status);
        if let Some(signal) = sys::find_terminating_signal(status) {
            anyhow::bail!(
                "the on_create bake was killed (signal {signal}) before it finished.\n\
                 NOTE: a bake has no graceful stop - e.g. `terra stop` or the OOM killer \
                 both land as a plain signal"
            );
        }
        anyhow::bail!(
            "the on_create bake failed - fix the recipe, then `terra {} setup` re-runs \
             it (`--rebuild` for a clean slate); the guest console is in diagnostics.log",
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

pub async fn run_detached_vm(dir: PathBuf, is_at_a_terminal: bool) -> Result<ExitCode> {
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
    crate::vm::run(&spec, &bx, &lock)
        .await
        .inspect_err(|error| log::error!("VM failed: {error:#}"))
}

fn validate_boot_spec_size(bytes: usize) -> Result<()> {
    anyhow::ensure!(
        bytes as u64 <= MAX_BOOT_SPEC_BYTES,
        "boot specification exceeds {MAX_BOOT_SPEC_BYTES} bytes; reduce the recipe or environment"
    );
    Ok(())
}

fn read_boot_spec(reader: impl Read) -> Result<BootSpec> {
    let mut json = Vec::new();
    reader
        .take(MAX_BOOT_SPEC_BYTES + 1)
        .read_to_end(&mut json)
        .context("reading the boot to run")?;
    validate_boot_spec_size(json.len())?;
    serde_json::from_slice(&json).context("decoding the boot to run")
}

fn override_workload(cfg: &mut config::Config, command: &[String]) {
    if let Some((entrypoint, args)) = command.split_first() {
        cfg.workload.entrypoint = PathBuf::from(entrypoint);
        cfg.workload.args = args.to_vec();
    }
}

/// We pass the boot through stdin, a pipe - not argv (any user can read
/// `/proc/<pid>/cmdline`) or the environment (it lands in core dumps). The
/// pipe is read once and exists nowhere else.
fn spawn_vm_process(bx: &BoxRef, spec: &BootSpec, lock: &File) -> Result<std::process::Child> {
    use std::process::{Command, Stdio};
    let exe = std::env::current_exe().context("locating the terra binary")?;
    let json = serde_json::to_string(spec).context("encoding the boot for the VM process")?;
    validate_boot_spec_size(json.len())?;
    let mut cmd = Command::new(exe);
    cmd.arg(VM_PROCESS_FLAG_ARG)
        .arg(bx.get_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
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

const REPLAY_LOG_TAIL_BYTES: u64 = 64 << 10; // 64 KiB

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

/// Replay the tail of the VM's log after a failure - a box that ended well
/// said what it had to say through its session. The status is the caller's to
/// decide: each caller's failure means something different.
fn replay_logs(bx: &BoxRef, status: std::process::ExitStatus) {
    if !status.success() {
        for (label, path) in [
            ("host log", bx.get_dir().join(crate::state::LOG_FILE)),
            (
                "guest diagnostics",
                bx.get_dir().join(crate::state::DIAGNOSTICS_LOG),
            ),
        ] {
            let tail = read_log_tail(&path);
            if !tail.is_empty() {
                eprint!("terra: {label}:\n{tail}");
            }
        }
    }
}

fn compute_vm_child_exit_byte(bx: &BoxRef, status: std::process::ExitStatus) -> u8 {
    if let Some(signal) = sys::find_terminating_signal(status) {
        eprintln!("terra: {bx}'s VM was killed (signal {signal})");
        return crate::exit_status_byte(128 + signal);
    }
    crate::exit_status_byte(status.code().unwrap_or(1))
}

fn claims_the_box(bx: &BoxRef, child_pid: u32) -> bool {
    bx.read_vm_process().is_some_and(|vm| vm.pid == child_pid)
}

fn compute_detached_exit_byte(bx: &BoxRef, child_pid: u32, status: std::process::ExitStatus) -> u8 {
    replay_logs(bx, status);
    if claims_the_box(bx, child_pid) {
        return 0;
    }
    if !status.success() {
        eprintln!("terra: {bx} failed to start");
    }
    compute_vm_child_exit_byte(bx, status)
}

/// Spawn the VM and leave it - a child that exits before claiming the box is
/// reported with its logs and exit code
fn spawn_detached(bx: &BoxRef, spec: &BootSpec, run_lock: File) -> Result<ExitCode> {
    let mut child = spawn_vm_process(bx, spec, &run_lock)?;
    // The child holds the same lock now, and this process is about to leave -
    // keeping a copy would leave the box reading as running after the VM died.
    drop(run_lock);

    let deadline = Instant::now() + DETACH_CONFIRM_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().context("checking on the VM")? {
            return Ok(ExitCode::from(compute_detached_exit_byte(
                bx,
                child.id(),
                status,
            )));
        }
        if claims_the_box(bx, child.id()) || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(POLL);
    }
    // "Started" is claimed only once the child has published its pid -
    // before that no command can find the box, and saying "started" would
    // send someone to `terra stop` for nothing. The unclaimed case succeeds
    // too: the VM is running, which is all `-d` asked for.
    if claims_the_box(bx, child.id()) {
        eprintln!(
            "terra: started {bx} detached (pid {}); logs: {}",
            child.id(),
            bx.build_logs_command()
        );
    } else {
        eprintln!(
            "terra: {bx} is still starting after {}s and has not claimed the box yet \
             (pid {}); logs: {}",
            DETACH_CONFIRM_TIMEOUT.as_secs(),
            child.id(),
            bx.build_logs_command()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn reap(owner: Option<&mut Child>) {
    if let Some(child) = owner {
        let _ = child.wait();
    }
}

async fn join_session(
    bx: &BoxRef,
    stream: AsyncLocalStream,
    owner: Option<&mut Child>,
) -> Result<ExitCode> {
    match pump_session(stream).await? {
        SessionOutcome::Detached => {
            eprintln!(
                "\nterra: detached - {bx} keeps running (`terra {}` rejoins)",
                bx.get_name()
            );
            Ok(ExitCode::SUCCESS)
        }
        SessionOutcome::Exited(code) => {
            reap(owner);
            Ok(ExitCode::from(crate::exit_status_byte(code)))
        }
        // Closed with no status: the VM was killed (`terra rm --force`) or
        // died. Reported as a failure, because a script cannot tell that from
        // a clean success.
        SessionOutcome::Closed => {
            reap(owner);
            anyhow::bail!("{bx} stopped without reporting a status - its VM was killed or died")
        }
    }
}

/// Spawn the VM and attach to its console. This process is only the
/// session's first client - but it is still the child's parent, so the
/// workload's exit code comes through unless you detach.
async fn run_attached(
    bx: &BoxRef,
    spec: &BootSpec,
    run_lock: File,
    agent_timeout: Option<u64>,
) -> Result<ExitCode> {
    eprintln!(
        "terra: starting {bx} - {DETACH_KEY_NAME} detaches, `terra {} stop` stops it",
        bx.get_name()
    );
    // The sandbox's view is worth a line on the terminal - the boot banner
    // only lands in the log.
    if spec.cfg.mounts.is_empty() {
        eprintln!("terra: mounts: none (no host filesystem in the sandbox)");
    } else {
        for mount in &spec.cfg.mounts {
            eprintln!("terra: mount: {}", crate::render::format_mount_line(mount));
        }
    }
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
                return Err(e);
            };
            replay_logs(bx, status);
            return Ok(ExitCode::from(compute_vm_child_exit_byte(bx, status)));
        }
    };

    join_session(bx, stream, Some(&mut child)).await
}

/// Join a running box's multiplexed terminal; the detach key detaches without
/// stopping the workload. Waits for the session rather than taking the
/// socket's word for it: a box can hold its lock long before there is anything
/// to join.
pub async fn attach(bx: &BoxRef, agent_timeout: Option<u64>) -> Result<ExitCode> {
    let mut wait_for_agent = session::wait_while_running(bx, agent_timeout);
    let stream =
        session::connect_to_agent(bx, terra_protocol::AgentService::Session, "session", || {
            wait_for_agent()
        })
        .await?;
    join_session(bx, stream, None).await
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A detached child that exited *without ever claiming the box* never
    /// started, and says so with the child's own status. Which side of
    /// [`spawn_detached`]'s deadline the death lands on is timing, so every
    /// look at the child answers through here - a second look that reported
    /// plain "started" made `terra <box> -d` exit 0 with nothing running.
    ///
    /// A child that *did* claim the box first is the other case: a workload
    /// fast enough to finish inside the window, where "started" is the honest
    /// answer whatever it exited with.
    #[test]
    fn a_detached_child_that_never_claimed_the_box_is_a_failed_start() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().join("dev"), dir.path());
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        let exited_with = |code: u8| {
            use std::io::Write as _;
            let mut child = sys::build_test_child_command().spawn().unwrap();
            child.stdin.take().unwrap().write_all(&[code]).unwrap();
            child.wait().unwrap()
        };

        // Never claimed: the child's own status, failure and all.
        assert_eq!(compute_detached_exit_byte(&bx, 4242, exited_with(3)), 3);
        assert_eq!(compute_detached_exit_byte(&bx, 4242, exited_with(0)), 0);

        // A child a host signal took has no code of its own: the shell's
        // 128+signal spelling, not a bare 1 that reads as the workload's.
        #[cfg(unix)]
        {
            let killed = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg("kill -KILL $$")
                .status()
                .unwrap();
            assert_eq!(compute_detached_exit_byte(&bx, 4242, killed), 128 + 9);
        }

        // Claimed, then finished - a fast workload, reported as started.
        let lock = bx.lock_run().unwrap();
        bx.publish_pid(&lock, 4242, false);
        assert_eq!(compute_detached_exit_byte(&bx, 4242, exited_with(3)), 0);
        // …and a *different* pid in the file is somebody else's box, not this
        // child's claim.
        assert_eq!(compute_detached_exit_byte(&bx, 5353, exited_with(3)), 3);
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
