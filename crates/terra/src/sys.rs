//! Platform glue: everything terra needs that std does not spell portably -
//! and the home directory every other path in terra hangs off.
//!
//! The portable half is here; a host's own half is `sys/<host>.rs`. The
//! `pub use` below is the surface such a file owes, so one it misses fails to
//! compile naming the item.
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};

#[cfg(unix)]
#[path = "sys/unix.rs"]
mod imp;

// Adding a host: write `sys/<host>.rs` providing everything the `pub use`
// below names, declare it as `imp` is declared above, and widen this guard.
#[cfg(not(unix))]
compile_error!(
    "terra has no platform layer for this target - add crates/terra/src/sys/<host>.rs, \
     for which crates/terra/src/sys/unix.rs is the worked example"
);

pub use imp::{
    MAX_SOCK_PATH, claim_inherited_lock, create_no_symlinks, detach, disk_usage,
    install_stop_signal_handlers, is_host_root, mode_of, open_no_symlinks, open_null, owner_only,
    pass_lock, pid_exists, point_stdio_at, process_start_time, register_stop_channel,
    restrict_new_files, set_open_file_mode, share_owner, signal_pid, terminating_signal,
};

pub const POLL: std::time::Duration = std::time::Duration::from_millis(100);

/// The moment `wait` from now runs out, clamped to ~136 years.
#[must_use]
pub(crate) fn deadline_after(wait: std::time::Duration) -> std::time::Instant {
    std::time::Instant::now() + wait.min(std::time::Duration::from_secs(u64::from(u32::MAX)))
}

/// What a stop asks of the VM process - terra's own two words, so a host
/// answers the same question however it delivers the answer.
#[derive(Copy, Clone, Debug)]
pub enum VmSignal {
    /// Ask the guest to shut down: `pre_stop`, then the VM exits.
    GracefulStop,
    /// Take the process without asking - the escape hatch for a wedged one.
    ForcedStop,
}

pub(crate) const NO_HOME_ERROR_MESSAGE: &str = "no home directory, so no ~/.terra (set HOME)";

pub(crate) fn home_dir() -> anyhow::Result<PathBuf> {
    use anyhow::Context as _;
    #[cfg(test)]
    if let Some(home) = TEST_HOME.with_borrow(Clone::clone) {
        return Ok(home);
    }
    std::env::home_dir().context(NO_HOME_ERROR_MESSAGE)
}

pub fn absolute(p: &Path, cwd: &Path) -> anyhow::Result<PathBuf> {
    use anyhow::Context as _;
    let joined = cwd.join(p);
    std::path::absolute(&joined).with_context(|| format!("resolving path {:?}", joined.display()))
}

/// Whether stdin is a terminal. Read once and passed down, so a test can
/// drive either side without a terminal.
#[must_use]
pub fn at_a_terminal() -> bool {
    crossterm::tty::IsTty::is_tty(&std::io::stdin())
}

pub fn dir_entries(dir: &Path) -> impl Iterator<Item = std::fs::DirEntry> {
    std::fs::read_dir(dir).into_iter().flatten().flatten()
}

/// Drop `SMOLVM_PUBLISH_ADDR` before the gateway's port listeners read it: it
/// would move published ports off the host loopback onto any address the
/// environment names.
pub fn scrub_smolvm_gateway_env() {
    // SAFETY: no other thread has been started yet (this is the first thing
    // `main` does), so there is no concurrent reader of the environment.
    unsafe { std::env::remove_var("SMOLVM_PUBLISH_ADDR") };
}

#[cfg(test)]
thread_local! {
    static TEST_HOME: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// A home directory of this test's own, held in a thread-local rather than
/// passed as a parameter, which would reach half the crate to serve nothing
/// but the tests.
///
/// Moving the home moves the settings file with it, so both ends of this drop
/// what was read from the home being left (see [`crate::state::settings`]).
#[cfg(test)]
pub(crate) struct TestHome(tempfile::TempDir);

#[cfg(test)]
impl TestHome {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().expect("a temporary home for this test");
        TEST_HOME.with_borrow_mut(|home| *home = Some(dir.path().to_path_buf()));
        crate::state::forget_settings();
        Self(dir)
    }

    pub(crate) fn path(&self) -> &Path {
        self.0.path()
    }
}

#[cfg(test)]
impl Drop for TestHome {
    fn drop(&mut self) {
        TEST_HOME.with_borrow_mut(|home| *home = None);
        crate::state::forget_settings();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--wait` and `--agent-timeout` take any u64, and `Instant + Duration`
    /// panics on overflow - so `terra stop --wait 18446744073709551615` must
    /// clamp to "forever" rather than take terra down mid-stop.
    #[test]
    fn an_absurd_wait_becomes_a_far_deadline_not_a_panic() {
        let now = std::time::Instant::now();
        let forever = deadline_after(std::time::Duration::from_secs(u64::MAX));
        assert!(forever > now);
        assert!(deadline_after(std::time::Duration::from_secs(1)) < forever);
    }
}
