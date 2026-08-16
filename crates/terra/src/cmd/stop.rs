//! Stopping a box: ask the guest to shut down, wait out the grace, kill what is
//! still there.

use crate::state::BoxRef;
use crate::sys;
use anyhow::{Context, Result};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

fn signal_vm(bx: &BoxRef, signal: sys::VmSignal) -> Result<Option<u32>> {
    let Some(pid) = bx.vm_pid() else {
        return Ok(None);
    };
    sys::signal_pid(pid, signal)
        .with_context(|| format!("signalling the VM process (pid {pid}) of {bx}"))?;
    Ok(Some(pid))
}

/// Hand back the pid the graceful stop was asked of; `Ok(None)` means the box
/// was already stopped.
fn request_stop(bx: &BoxRef, deadline: Instant) -> Result<Option<u32>> {
    loop {
        if !bx.holder().holds() {
            return Ok(None);
        }
        if let Some(pid) = signal_vm(bx, sys::VmSignal::GracefulStop)? {
            return Ok(Some(pid));
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "{bx} is running but its VM published no pid to signal before the wait ran out"
        );
        std::thread::sleep(sys::POLL);
    }
}

const KILL_REAP_WAIT: Duration = Duration::from_secs(2);

fn wait_until_stopped(bx: &BoxRef, deadline: Instant) -> bool {
    loop {
        if !bx.holder().holds() {
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
    /// Still holding the box after `SIGKILL` - a VM process wedged in the
    /// kernel.
    Wedged,
}

pub(crate) fn stop_and_wait(bx: &BoxRef, grace: Duration) -> Result<StopOutcome> {
    let deadline = sys::deadline_after(grace);
    let Some(pid) = request_stop(bx, deadline)? else {
        return Ok(StopOutcome::AlreadyStopped);
    };
    eprintln!("terra: stopping {bx} (pid {pid})");
    if wait_until_stopped(bx, deadline) {
        return Ok(StopOutcome::StoppedGracefully);
    }
    eprintln!(
        "terra: {bx} did not stop within {}s - killing pid {pid}",
        grace.as_secs()
    );
    signal_vm(bx, sys::VmSignal::ForcedStop)?;
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
    let stopped = stop_and_wait(bx, Duration::from_secs(args.wait))
        .context("could not stop the box - `terra rm --force` takes it away regardless")?;
    match stopped {
        StopOutcome::AlreadyStopped => eprintln!("terra: {bx} is already stopped"),
        StopOutcome::StoppedGracefully | StopOutcome::Killed => eprintln!("terra: {bx} stopped"),
        StopOutcome::Wedged => anyhow::bail!(
            "{bx} is still running after SIGKILL - its VM process is wedged in the kernel"
        ),
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::process::{Child, Command, Stdio};

    /// A box on disk under a home of this test's own - which has to be in
    /// place before the box is resolved, since that is when its directory is
    /// settled.
    fn box_in(dir: &Path) -> (BoxRef, crate::sys::TestHome) {
        let home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir, "dev").unwrap();
        std::fs::create_dir_all(bx.dir()).unwrap();
        (bx, home)
    }

    /// A child holding the box exactly as a VM process does - on the inherited
    /// lock descriptor - with its pid published. `shell` decides what it does
    /// about SIGTERM, and must echo a byte once it has: a signal that arrives
    /// while the shell is still starting is taken at the default disposition,
    /// so without the handshake a child meant to ignore SIGTERM dies of it.
    fn vm_child(bx: &BoxRef, shell: &str) -> Child {
        let lock = bx.lock_run().unwrap();
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(shell).stdout(Stdio::piped());
        sys::pass_lock(&mut cmd, &lock);
        let mut child = cmd.spawn().unwrap();
        bx.publish_pid(child.id(), false);
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
        let (bx, _home) = box_in(dir.path());
        assert!(matches!(
            stop_and_wait(&bx, Duration::from_secs(0)).unwrap(),
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
        let (bx, _home) = box_in(dir.path());
        // `lock_run` empties the file, so this is a box held with no pid in it.
        let _held = bx.lock_run().unwrap();
        assert_eq!(bx.vm_pid(), None);

        let err = stop_and_wait(&bx, Duration::from_millis(200))
            .expect_err("a box held with no pid to signal must not read as stopped")
            .to_string();
        assert!(err.contains("published no pid"), "{err}");
    }

    /// The graceful path end to end: the published pid is signalled, and the
    /// box being let go is what says the stop landed - the lock, not the
    /// signal's own return, which says only that it was delivered.
    #[test]
    fn a_vm_that_takes_the_signal_stops_gracefully() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _home) = box_in(dir.path());
        let mut child = vm_child(&bx, "echo up; exec sleep 30");

        assert!(matches!(
            stop_and_wait(&bx, Duration::from_secs(10)).unwrap(),
            StopOutcome::StoppedGracefully
        ));
        assert!(!bx.holder().holds(), "the box is still held");
        child.wait().unwrap();
    }

    /// A VM that will not take SIGTERM is killed once the grace runs out, and
    /// the outcome says which of the two happened: `terra stop` reports both as
    /// stopped, but a `pre_stop` that never ran is the difference between a
    /// clean shutdown and a workload cut off mid-write.
    ///
    /// An ignored SIGTERM survives `exec`, so it is `sleep` itself that refuses
    /// the signal here rather than a shell that would have to forward it.
    #[test]
    fn a_vm_that_ignores_the_signal_is_killed_once_the_grace_runs_out() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _home) = box_in(dir.path());
        let mut child = vm_child(&bx, "trap '' TERM; echo up; exec sleep 30");

        assert!(matches!(
            stop_and_wait(&bx, Duration::from_millis(300)).unwrap(),
            StopOutcome::Killed
        ));
        assert!(!bx.holder().holds(), "the box is still held");
        child.wait().unwrap();
    }
}
