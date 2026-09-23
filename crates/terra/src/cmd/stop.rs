//! Stopping a box: ask the guest to shut down, wait out the grace, kill what is
//! still there.

use crate::state::{BoxRef, Holder, VmProcess};
use crate::sys;
use anyhow::{Context, Result};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

enum StopAttempt {
    AlreadyStopped,
    StoppedGracefully,
    NeedsForce(VmProcess),
}

fn request_stop(bx: &BoxRef, deadline: Instant, setup_action: SetupAction) -> Result<StopAttempt> {
    loop {
        match bx.get_holder() {
            Holder::Free => return Ok(StopAttempt::AlreadyStopped),
            Holder::SettingUp if matches!(setup_action, SetupAction::Refuse) => {
                return Err(bx.setup_holds_it());
            }
            Holder::SettingUp => {
                return bx
                    .read_vm_process()
                    .map(StopAttempt::NeedsForce)
                    .ok_or_else(|| bx.setup_holds_it());
            }
            Holder::Running => {}
        }
        match bx.request_stop() {
            Ok(()) => {
                eprintln!("terra: stopping {bx}");
                break;
            }
            Err(error) if can_retry_stop(&error) => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(sys::POLL);
    }
    if wait_until_stopped(bx, deadline) {
        return Ok(StopAttempt::StoppedGracefully);
    }
    bx.read_vm_process()
        .map(StopAttempt::NeedsForce)
        .with_context(|| {
            format!("{bx} is running but its VM published no pid to signal before the wait ran out")
        })
}

fn can_retry_stop(error: &anyhow::Error) -> bool {
    use std::io::ErrorKind;

    error.downcast_ref::<std::io::Error>().is_some_and(|error| {
        matches!(
            error.kind(),
            ErrorKind::NotFound
                | ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionReset
                | ErrorKind::BrokenPipe
        )
    })
}

const KILL_REAP_WAIT: Duration = Duration::from_secs(2);

fn wait_until_stopped(bx: &BoxRef, deadline: Instant) -> bool {
    loop {
        if !bx.get_holder().holds() {
            return true;
        }
        // An instant, not a duration: each hop that re-derives the deadline
        // spends a little of the wait.
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(sys::POLL);
    }
}

#[derive(Debug)]
pub(crate) enum StopOutcome {
    AlreadyStopped,
    StoppedGracefully,
    Killed,
    /// The published pid did not identify the process holding this box.
    IdentityUnknown,
    /// Still holding the box after `SIGKILL` - a VM process wedged in the
    /// kernel.
    Wedged,
}

#[derive(Clone, Copy)]
pub(crate) enum SetupAction {
    Refuse,
    Stop,
}

pub(crate) fn stop_and_wait(
    bx: &BoxRef,
    grace: Duration,
    setup_action: SetupAction,
) -> Result<StopOutcome> {
    let deadline = sys::deadline_after(grace);
    let vm = match request_stop(bx, deadline, setup_action)? {
        StopAttempt::AlreadyStopped => return Ok(StopOutcome::AlreadyStopped),
        StopAttempt::StoppedGracefully => return Ok(StopOutcome::StoppedGracefully),
        StopAttempt::NeedsForce(vm) => vm,
    };
    eprintln!("terra: forcing {bx} to stop (pid {})", vm.pid);
    let signal_result = sys::terminate_process(vm.pid, vm.process_identity)
        .with_context(|| format!("killing the VM process (pid {}) of {bx}", vm.pid))?;
    if signal_result == sys::SignalResult::IdentityUnknown {
        return Ok(StopOutcome::IdentityUnknown);
    }
    Ok(if wait_until_stopped(bx, Instant::now() + KILL_REAP_WAIT) {
        StopOutcome::Killed
    } else {
        StopOutcome::Wedged
    })
}

pub fn run(
    args: &crate::cli::StopArgs,
    name: Option<&str>,
    project_dir: &Path,
) -> Result<ExitCode> {
    let bx = &crate::resolve::resolve_pinned_box(project_dir, name)?;
    let stopped = stop_and_wait(bx, Duration::from_secs(args.timeout), SetupAction::Refuse)
        .context("could not stop the box - `terra rm --force` takes it away regardless")?;
    match stopped {
        StopOutcome::AlreadyStopped => eprintln!("terra: {bx} is already stopped"),
        StopOutcome::StoppedGracefully | StopOutcome::Killed => eprintln!("terra: {bx} stopped"),
        StopOutcome::IdentityUnknown => {
            anyhow::bail!("{bx} is still held but its VM process identity is unknown")
        }
        StopOutcome::Wedged => anyhow::bail!(
            "{bx} is still running after SIGKILL - its VM process is wedged in the kernel"
        ),
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::io::Read as _;
    #[cfg(unix)]
    use std::process::{Child, Command, Stdio};

    /// A box on disk under a home of this test's own - which has to be in
    /// place before the box is resolved, since that is when its directory is
    /// settled.
    fn create_box_in(dir: &Path) -> (BoxRef, crate::sys::TestHome) {
        let home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir, "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        (bx, home)
    }

    /// A child holding the box exactly as a VM process does - on the inherited
    /// lock descriptor - with its pid published. `shell` decides what it does
    /// about SIGTERM, and must echo a byte once it has: a signal that arrives
    /// while the shell is still starting is taken at the default disposition,
    /// so without the handshake a child meant to ignore SIGTERM dies of it.
    #[cfg(unix)]
    fn spawn_vm_child(bx: &BoxRef, shell: &str) -> Child {
        let lock = bx.lock_run().unwrap();
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(shell).stdout(Stdio::piped());
        let inheritance = sys::pass_lock(&mut cmd, &lock).unwrap();
        let mut child = cmd.spawn().unwrap();
        drop(inheritance);
        bx.publish_pid(&lock, child.id(), false);
        // From here the child alone holds the box, as it does after a boot.
        drop(lock);
        let mut up = [0u8; 1];
        child
            .stdout
            .as_mut()
            .expect("the child's stdout is piped")
            .read_exact(&mut up)
            .expect("the child never reported that it was up");
        child
    }

    /// Nothing to stop is not a failure: `terra stop` is what a script runs
    /// before it removes a box, and a box that is already down has met that ask.
    #[test]
    fn a_box_nobody_holds_is_already_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _home) = create_box_in(dir.path());
        assert!(matches!(
            stop_and_wait(&bx, Duration::from_secs(0), SetupAction::Refuse).unwrap(),
            StopOutcome::AlreadyStopped
        ));
    }

    /// A box held by a VM that never published a pid has nothing to signal, and
    /// that is not the same as a box that is stopped - `terra rm --force` reads
    /// the two apart to decide whether it is taking a box away from a live VM.
    /// The gap is waited out first: a boot holds the lock before it publishes.
    #[test]
    fn a_holder_that_published_no_pid_is_waited_out_and_then_named() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _home) = create_box_in(dir.path());
        // `lock_run` empties the file, so this is a box held with no pid in it.
        let _held = bx.lock_run().unwrap();
        assert_eq!(bx.read_vm_process(), None);

        let err = stop_and_wait(&bx, Duration::from_millis(200), SetupAction::Refuse)
            .expect_err("a box held with no pid to signal must not read as stopped")
            .to_string();
        assert!(err.contains("published no pid"), "{err}");
    }

    /// A bake marks its box and serves nothing to talk to, so waiting it out
    /// reads as a hang for exactly as long as the bake takes. A mark with no
    /// published pid refuses immediately, saying what actually holds the box.
    #[test]
    fn a_bake_mark_with_no_pid_refuses_without_waiting_out_the_grace() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _home) = create_box_in(dir.path());
        let lock = bx.lock_run().unwrap();
        let marked = bx.mark_baking(&lock);
        assert_eq!(bx.read_vm_process(), None, "the mark precedes any child");

        // Long enough that a regression to wait-it-out would fail the test run
        // long before this grace expires.
        let err = format!(
            "{:#}",
            stop_and_wait(&bx, Duration::from_mins(1), SetupAction::Refuse)
                .expect_err("a bake is refused")
        );
        assert!(err.contains("being set up"), "{err}");
        drop(marked);
    }

    #[test]
    fn a_bake_with_a_published_pid_refuses_stop_but_allows_forced_removal() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _home) = create_box_in(dir.path());
        let lock = bx.lock_run().unwrap();
        let marked = bx.mark_baking(&lock);
        let mut child = sys::build_test_child_command().spawn().unwrap();
        bx.publish_pid(&lock, child.id(), true);
        assert!(matches!(bx.get_holder(), Holder::SettingUp));
        let error = stop_and_wait(&bx, Duration::ZERO, SetupAction::Refuse)
            .expect_err("stop must leave setup running");
        assert!(error.to_string().contains("being set up"));
        assert!(child.try_wait().unwrap().is_none());
        let outcome = stop_and_wait(&bx, Duration::ZERO, SetupAction::Stop).unwrap();
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        assert!(matches!(outcome, StopOutcome::Wedged));
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            assert!(matches!(outcome, StopOutcome::IdentityUnknown));
            assert!(child.try_wait().unwrap().is_none());
            child.kill().unwrap();
        }
        assert!(!child.wait().unwrap().success());
        drop(marked);
    }

    /// The socket identifies the box even without a usable published process identity.
    /// A stop during startup waits for the listener rather than signalling a numeric PID.
    #[test]
    fn graceful_stop_waits_for_the_control_socket_and_releases_the_box() {
        use std::io::Read as _;
        use terra_platform::io::local::LocalListener;

        for (pid_line, delay) in [
            (std::process::id().to_string(), Duration::ZERO),
            (String::new(), Duration::ZERO),
            ("malformed".to_owned(), Duration::ZERO),
            (String::new(), Duration::from_millis(200)),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (bx, _home) = create_box_in(dir.path());
            let lock = bx.lock_run().unwrap();
            BoxRef::rewrite_lock_line(&lock, &pid_line).unwrap();
            let path = bx.get_dir().join(crate::state::CONTROL_SOCKET);
            let server = std::thread::spawn(move || {
                std::thread::sleep(delay);
                let listener = LocalListener::bind(path).unwrap();
                let (mut stream, _) = listener.accept().unwrap();
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                assert_eq!(byte, [terra_protocol::STOP_SIGNAL]);
                drop(lock);
            });
            assert!(matches!(
                stop_and_wait(&bx, Duration::from_secs(5), SetupAction::Refuse).unwrap(),
                StopOutcome::StoppedGracefully
            ));
            server.join().unwrap();
            assert!(!bx.get_holder().holds());
        }
    }

    #[test]
    fn forced_stop_reads_pid_metadata_after_the_grace_period() {
        use std::io::Read as _;
        use terra_platform::io::local::LocalListener;

        let dir = tempfile::tempdir().unwrap();
        let (bx, _home) = create_box_in(dir.path());
        let lock = bx.lock_run().unwrap();
        BoxRef::rewrite_lock_line(&lock, "100").unwrap();
        let listener =
            LocalListener::bind(bx.get_dir().join(crate::state::CONTROL_SOCKET)).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            assert_eq!(byte, [terra_protocol::STOP_SIGNAL]);
            BoxRef::rewrite_lock_line(&lock, "200").unwrap();
            lock
        });
        let attempt = request_stop(
            &bx,
            sys::deadline_after(Duration::from_millis(200)),
            SetupAction::Refuse,
        )
        .unwrap();
        let _lock = server.join().unwrap();
        assert!(matches!(
            attempt,
            StopAttempt::NeedsForce(VmProcess { pid: 200, .. })
        ));
    }

    /// An unavailable control socket still permits identity-bound forced termination.
    #[test]
    #[cfg(unix)]
    fn a_vm_without_a_control_socket_is_killed_once_the_grace_runs_out() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _home) = create_box_in(dir.path());
        let mut child = spawn_vm_child(&bx, "trap '' TERM; echo up; exec sleep 30");

        assert!(matches!(
            stop_and_wait(&bx, Duration::from_millis(300), SetupAction::Refuse).unwrap(),
            StopOutcome::Killed
        ));
        assert!(!bx.get_holder().holds(), "the box is still held");
        child.wait().unwrap();
    }
}
