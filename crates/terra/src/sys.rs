//! Platform glue: everything terra needs that std does not spell portably -
//! and the home directory every other path in terra hangs off.
//!
//! The portable half is here; a host's own half is `sys/<host>.rs`. The
//! `pub use` below is the surface such a file owes, so one it misses fails to
//! compile naming the item.
use std::path::{Path, PathBuf};

#[cfg(unix)]
#[path = "sys/unix.rs"]
mod imp;

#[cfg(windows)]
#[path = "sys/windows.rs"]
mod imp;

#[cfg(not(any(unix, windows)))]
compile_error!(
    "terra has no platform layer for this target - add crates/terra/src/sys/<host>.rs, \
     for which crates/terra/src/sys/unix.rs is the worked example"
);

#[cfg(windows)]
pub(crate) use imp::file_handle_matches_path;
pub use imp::is_host_root;
#[cfg(unix)]
pub use imp::register_stop_channel;
pub use imp::{
    MAX_SOCK_PATH, claim_inherited_lock, detach, find_terminating_signal, holds_run_lock,
    host_addresses, install_stop_signal_handlers, pass_lock, pid_exists, read_process_start_time,
    restrict_new_files, set_open_file_mode, set_owner_only, signal_pid, try_lock_run,
};

pub(crate) fn validate_host_root() -> anyhow::Result<()> {
    validate_host_root_for(
        is_host_root(),
        std::env::var_os("TERRA_ALLOW_ROOT").is_some_and(|value| value == "1"),
    )
}

fn validate_host_root_for(is_host_root: bool, root_override: bool) -> anyhow::Result<()> {
    anyhow::ensure!(
        !is_host_root || root_override,
        "running terra as host root is disabled with the component VMM - run as an unprivileged user or set TERRA_ALLOW_ROOT=1 to proceed"
    );
    Ok(())
}

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

/// Whether the published process identity accepted a signal.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SignalResult {
    Sent,
    IdentityUnknown,
}

pub(crate) fn resolve_home_dir() -> anyhow::Result<PathBuf> {
    use anyhow::Context as _;
    // A test's own home: see [`test_paths`].
    #[cfg(test)]
    if let Some(home) = test_paths::get_test_home() {
        return Ok(home);
    }
    let home = std::env::home_dir().context("no home directory, so no ~/.terra (set HOME)")?;
    anyhow::ensure!(home.is_absolute(), "HOME must be an absolute path");
    Ok(home)
}

/// The paths we guard may not exist yet when they're checked, and a symlink
/// must not sneak a protected path past under a different name. So resolve as
/// much as the disk actually has, and keep the rest as written.
#[must_use]
pub(crate) fn canonicalize_existing_prefix(p: &Path) -> PathBuf {
    let (mut existing, mut rest) = (p.to_path_buf(), PathBuf::new());
    loop {
        if let Ok(resolved) = std::fs::canonicalize(&existing) {
            return if rest.as_os_str().is_empty() {
                resolved
            } else {
                resolved.join(rest)
            };
        }
        let Some(name) = existing.file_name().map(PathBuf::from) else {
            return p.to_path_buf();
        };
        rest = if rest.as_os_str().is_empty() {
            name
        } else {
            name.join(rest)
        };
        if !existing.pop() {
            return p.to_path_buf();
        }
    }
}

pub fn resolve_absolute_path(path: &Path, cwd: &Path) -> anyhow::Result<PathBuf> {
    use anyhow::Context as _;
    let joined = cwd.join(path);
    std::path::absolute(&joined).with_context(|| format!("resolving path {:?}", joined.display()))
}

/// Read once and passed down, so a test can drive either side without a
/// terminal.
#[must_use]
pub fn is_at_a_terminal() -> bool {
    crossterm::tty::IsTty::is_tty(&std::io::stdin())
}

#[cfg(test)]
mod test_paths;

#[cfg(test)]
pub(crate) use test_paths::TestHome;

pub fn open_regular_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits().cast_signed());
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("expected a regular file"));
    }
    Ok(file)
}

pub fn create_regular_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits().cast_signed());
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("expected a regular file"));
    }
    file.set_len(0)?;
    Ok(file)
}

pub(crate) fn reserve_staging_directory(
    parent: &Path,
    prefix: &str,
) -> anyhow::Result<(PathBuf, String)> {
    use anyhow::Context;
    let mut attempt = 0_u64;
    loop {
        let name = format!(".{prefix}.{}.{attempt}", std::process::id());
        let path = parent.join(&name);
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok((path, name)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt = attempt
                    .checked_add(1)
                    .context("too many staging directories")?;
            }
            Err(error) => return Err(error).context("creating staging directory"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_root_needs_an_override() {
        let error = validate_host_root_for(true, false).unwrap_err();
        assert!(error.to_string().contains("TERRA_ALLOW_ROOT=1"));
        assert!(validate_host_root_for(true, true).is_ok());
        assert!(validate_host_root_for(false, false).is_ok());
    }

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
