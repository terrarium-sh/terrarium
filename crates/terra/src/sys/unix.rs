//! The Unix hosts. Variance *within* the family - `openat2` on Linux,
//! `sun_path`'s length on Darwin - is settled here, so a host joins this file
//! rather than starting another one.
#![allow(unsafe_code)]

use super::VmSignal;
use std::fs::File;
use std::io::Result;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Max usable `AF_UNIX` socket path length: `sun_path` minus its NUL - 103 on
/// Darwin/BSD, 107 elsewhere.
#[cfg(target_vendor = "apple")]
pub const MAX_SOCK_PATH: usize = 103;
#[cfg(not(target_vendor = "apple"))]
pub const MAX_SOCK_PATH: usize = 107;

pub fn restrict_new_files() {
    // SAFETY: `umask` swaps this process's own mask and cannot fail.
    unsafe {
        libc::umask(0o077);
    }
}

pub fn open_null() -> Result<File> {
    File::open("/dev/null")
}

/// Open for reading, refusing a symlink at **any** component (`openat2` with
/// `RESOLVE_NO_SYMLINKS`).
#[cfg(target_os = "linux")]
pub fn open_no_symlinks(path: &Path) -> Result<File> {
    terra_agent::no_symlinks::open_raw(path, libc::O_RDONLY, 0).map_err(|e| explain(e, path))
}

/// Create or truncate for writing, under the same rule as [`open_no_symlinks`].
#[cfg(target_os = "linux")]
pub fn create_no_symlinks(path: &Path) -> Result<File> {
    terra_agent::no_symlinks::create_raw(path).map_err(|e| explain(e, path))
}

/// The two errnos this open reports read as nonsense as written ("Too many
/// levels of symbolic links" for one symlink; "Function not implemented" for an
/// open).
#[cfg(target_os = "linux")]
fn explain(err: std::io::Error, path: &Path) -> std::io::Error {
    match err.raw_os_error() {
        Some(libc::ELOOP) => std::io::Error::other(format!(
            "{} passes through a symlink, and terra does not follow one on a host path \
             a sandbox may have planted - name the resolved path instead",
            path.display()
        )),
        Some(libc::ENOSYS) => std::io::Error::other(
            "this kernel has no openat2 (Linux 5.6+), which is how terra keeps a symlink \
             planted in a share from redirecting a copy",
        ),
        _ => err,
    }
}

#[cfg(not(target_os = "linux"))]
use std::{fs::OpenOptions, io, path::PathBuf};

#[cfg(not(target_os = "linux"))]
pub fn open_no_symlinks(path: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    open_no_symlinks_best_effort(path, &mut opts)
}

#[cfg(not(target_os = "linux"))]
pub fn create_no_symlinks(path: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    open_no_symlinks_best_effort(path, &mut opts)
}

/// Non-Linux stand-in for the `openat2` no-symlinks contract - best effort:
/// a link swapped in between a component's check and the open slips through,
/// the window Linux closes in-kernel.
#[cfg(not(target_os = "linux"))]
fn open_no_symlinks_best_effort(path: &Path, opts: &mut OpenOptions) -> Result<File> {
    let mut walked = PathBuf::new();
    for component in path.components() {
        walked.push(component);
        if walked.as_path() == path {
            break; // the leaf: `O_NOFOLLOW` below is its own guard
        }
        let meta = std::fs::symlink_metadata(&walked)?;
        if meta.file_type().is_symlink() {
            return Err(io::Error::other(format!(
                "{} passes through a symlink, and terra does not follow one on a host path \
                 a sandbox may have planted - name the resolved path instead",
                path.display()
            )));
        }
        if !meta.is_dir() {
            return Err(io::Error::other(format!(
                "{} is not a directory",
                walked.display()
            )));
        }
    }
    use std::os::unix::fs::OpenOptionsExt;
    opts.custom_flags(libc::O_NOFOLLOW);
    opts.open(path)
}

/// Through the handle rather than the path: the path may have become a symlink
/// since it was opened.
pub fn set_open_file_mode(file: &File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(mode))
}

/// Restrict an existing path to its owner: `0700` for a directory, `0600` for a
/// file.
pub fn owner_only(path: &Path, dir: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if dir { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Taken from the open file's metadata rather than a path, because a second
/// `stat` could describe a different inode the guest swapped in.
pub fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

/// What a file costs the disk it is on: `st_blocks` counts 512-byte blocks by
/// POSIX, whatever the filesystem's own block size says.
pub fn disk_usage(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.blocks() * 512
}

/// Give the child its own process group, so Ctrl-C in the starting terminal
/// does not reach the VM.
pub fn detach(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0);
}

/// The descriptor a boot hands its VM process the box's run lock on, already
/// held.
const LOCK_FD: std::os::fd::RawFd = 3;

/// Hand `lock` to the spawned child as [`LOCK_FD`]. A duplicate descriptor
/// holds the same `flock`, released only when every one of them closes.
pub fn pass_lock(cmd: &mut Command, lock: &File) {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let fd = lock.as_raw_fd();
    // SAFETY: the closure runs between fork and exec, where only
    // async-signal-safe calls are allowed - `dup2` and `fcntl` are both.
    unsafe {
        cmd.pre_exec(move || {
            // `dup2` onto the same number is a no-op that leaves CLOEXEC set,
            // and the lock is commonly opened as fd 3 already.
            let rc = if fd == LOCK_FD {
                libc::fcntl(fd, libc::F_SETFD, 0)
            } else {
                libc::dup2(fd, LOCK_FD)
            };
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// The run lock a boot passed down, or `None` when [`LOCK_FD`] is not the file
/// `expected` names - which is what `terra __vm` typed at a shell looks like.
/// Identity is checked rather than assumed: running the VM without really
/// holding the box would let a second one boot over it.
pub fn claim_inherited_lock(expected: &Path) -> Option<File> {
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::MetadataExt;
    // SAFETY: `pass_lock` dup'd this descriptor into place before exec and
    // nothing else in this process owns it. A closed or wrong one fails the
    // check below, and the `File` closing it on drop is the right outcome.
    let file = unsafe { File::from_raw_fd(LOCK_FD) };
    let same = file
        .metadata()
        .ok()
        .zip(std::fs::metadata(expected).ok())
        .is_some_and(|(got, want)| got.dev() == want.dev() && got.ino() == want.ino());
    same.then_some(file)
}

/// The signal a child was killed by, or `None` if it exited on its own.
pub fn terminating_signal(status: std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

/// Whether the kernel lists a process under this pid. A staging temp's writer
/// is always this user's own terra, so `EPERM` - the number worn by another
/// user's process by now - still reads as alive.
pub fn pid_exists(pid: u32) -> bool {
    let Ok(target) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 delivers nothing; the call only reports reachability.
    let rc = unsafe { libc::kill(target, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// `/proc/<pid>/stat`'s starttime (field 22), in clock ticks since boot: two
/// processes can wear one pid in sequence, never one starttime. `None` where
/// there is no stat to read.
pub fn process_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The comm field may hold spaces and parentheses of its own, so field
    // counting resumes after its last `)`; state (field 3) is first here, and
    // starttime (field 22) is the 20th token from there.
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// A `None` starttime, from a pid file written before starttimes were, passes
/// as current - there is nothing recorded to check the live process against.
fn published_process_is_current(pid: u32, published_start_time: Option<u64>) -> bool {
    match published_start_time {
        None => true,
        Some(published) => process_start_time(pid) == Some(published),
    }
}

/// Two outcomes are `Ok` without a signal delivered: `ESRCH` - the process is
/// already gone - and a starttime no longer matching what was published,
/// which is a stranger wearing the pid now.
pub fn signal_pid(pid: u32, published_start_time: Option<u64>, signal: VmSignal) -> Result<()> {
    let sig = match signal {
        VmSignal::GracefulStop => libc::SIGTERM,
        VmSignal::ForcedStop => libc::SIGKILL,
    };
    let Ok(target) = libc::pid_t::try_from(pid) else {
        return Err(std::io::Error::other(format!(
            "{pid} is not a process id, so nothing was signalled \
             (the box's {} holds something that is not a pid)",
            crate::state::PID_FILE
        )));
    };
    if !published_process_is_current(pid, published_start_time) {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if let Some(delivered) = pidfd_signal(target, sig) {
        return delivered;
    }
    // SAFETY: a plain signal to another process; nothing of ours is passed or written.
    if unsafe { libc::kill(target, sig) } == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(err)
}

/// The pidfd pins the process from open to delivery, so no recycle between
/// the starttime check and the signal can redirect it. `None` when the
/// kernel lacks the pidfd calls.
#[cfg(target_os = "linux")]
fn pidfd_signal(target: libc::pid_t, sig: libc::c_int) -> Option<Result<()>> {
    // SAFETY: both syscalls take plain numbers and descriptors we close below;
    // `null` for the info pointer asks for the default delivery semantics.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, target, 0u32) };
    if fd < 0 {
        return None;
    }
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd,
            sig,
            std::ptr::null::<libc::c_void>(),
            0u32,
        )
    };
    let err = std::io::Error::last_os_error();
    // SAFETY: `fd` came from `pidfd_open` above and nothing else owns it.
    unsafe { libc::syscall(libc::SYS_close, fd) };
    Some(match rc {
        0 => Ok(()),
        _ if err.raw_os_error() == Some(libc::ESRCH) => Ok(()),
        _ => Err(err),
    })
}

/// `-1` while no control connection is registered, and the swap out is what
/// sends exactly once. Never closed: a signal lands at a moment no code
/// chose, so an fd a handler may still be writing to must never be recycled
/// onto something else.
static STOP_FD: AtomicI32 = AtomicI32::new(-1);

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Async-signal-safe: one atomic and one `write`. The write cannot block -
/// the plan frame before it was `write_all`'d to completion, so the socket
/// has room for one byte.
fn send_stop() {
    let fd = STOP_FD.swap(-1, Ordering::SeqCst);
    if fd < 0 {
        return;
    }
    let byte = [terra_agent::STOP_SIGNAL];
    // SAFETY: `fd` is the control connection, open for the rest of this
    // process's life (see [`STOP_FD`]); one byte from a live buffer.
    unsafe { libc::write(fd, byte.as_ptr().cast(), 1) };
}

/// Both statics are `SeqCst` for the one interleaving that matters: if the
/// handler reads [`STOP_FD`] before this store, this call reads
/// [`STOP_REQUESTED`] after the handler's, so whichever ran first, the other
/// sends.
pub fn register_stop_channel(channel: std::os::fd::OwnedFd) {
    use std::os::fd::IntoRawFd;
    STOP_FD.store(channel.into_raw_fd(), Ordering::SeqCst);
    if STOP_REQUESTED.load(Ordering::SeqCst) {
        send_stop();
    }
}

/// SIGINT/SIGTERM/SIGHUP ask the guest for its graceful stop - a host
/// shutdown and a closed `--foreground` terminal included. Detached boxes
/// hear none of this: [`detach`] puts them in their own process group, past
/// any terminal's reach.
pub fn install_stop_signal_handlers() {
    // SAFETY: `handler` does atomic stores and one `write`, both
    // async-signal-safe; nothing else about these calls can fail on us.
    unsafe {
        libc::signal(libc::SIGINT, handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, handler as *const () as libc::sighandler_t);
    }
}

extern "C" fn handler(_sig: libc::c_int) {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
    send_stop();
}

#[must_use]
pub fn is_host_root() -> bool {
    // SAFETY: a plain read of this process's own uid, which cannot fail.
    unsafe { libc::getuid() == 0 }
}

/// The host uid and gid a share's backing files will carry: this process's
/// own. `None` as root - real ids pass through virtiofs whole, nothing to map.
#[must_use]
pub fn share_owner() -> Option<(u32, u32)> {
    // SAFETY: plain reads of this process's own ids, which cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    (uid != 0).then_some((uid, gid))
}

/// Point this process's stdout and stderr at `file`, so every writer that
/// reaches them follows - a panic included.
pub fn point_stdio_at(file: &File) -> Result<()> {
    use std::os::fd::AsRawFd;
    let fd = file.as_raw_fd();
    // SAFETY: `fd` is open for the duration of both calls; `dup2` closes the old
    // 1/2 and installs a copy of it, leaving `file` itself free to drop.
    if unsafe { libc::dup2(fd, 1) } < 0 || unsafe { libc::dup2(fd, 2) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs::OpenOptions;

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("terra-sys-{}-{name}", std::process::id()))
    }

    /// A run that has already gone is what `terra stop` wanted, so `ESRCH` is not
    /// an error - and `rm --force`, which kills after a stop it just asked for,
    /// races exactly this.
    #[test]
    fn signalling_a_process_that_is_already_gone_is_not_an_error() {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .unwrap();
        let pid = child.id();
        child.wait().unwrap(); // reaped: the pid names nothing at all now
        assert!(signal_pid(pid, None, VmSignal::GracefulStop).is_ok());
        assert!(signal_pid(pid, None, VmSignal::ForcedStop).is_ok());
    }

    /// The pid file outlives its VM by however long it takes a boot to empty
    /// it, and the kernel hands that number to strangers in between. A stored
    /// starttime that no longer matches is exactly such a stranger: signalled
    /// with nothing - `Ok`, because "already gone" is the truth about the box -
    /// while the same pid with *its* starttime takes the signal.
    #[test]
    fn a_recycled_pid_is_left_alone_and_the_real_one_is_signalled() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let started_at = process_start_time(pid).expect("a live child has a stat");

        // One tick off is nobody's process as far as the check is concerned.
        signal_pid(pid, Some(started_at + 1), VmSignal::GracefulStop).unwrap();
        assert!(
            child.try_wait().unwrap().is_none(),
            "a living child was signalled through a recycled identity"
        );

        // The published starttime is the one that reaches it; `sleep` dies of
        // SIGTERM outright.
        signal_pid(pid, Some(started_at), VmSignal::GracefulStop).unwrap();
        child.wait().unwrap();

        // …and once gone, any starttime reads as already-gone rather than
        // reaching whoever wears the pid now.
        assert!(signal_pid(pid, Some(started_at), VmSignal::ForcedStop).is_ok());
    }

    /// A pid too large for `pid_t` used to convert to `-1`, and `kill(-1)`
    /// signals every process this user can reach - `terra rm --force` on a box
    /// whose pid file held a large number would have killed the session that
    /// typed it.
    #[test]
    fn a_number_that_is_not_a_pid_signals_nothing() {
        for not_a_pid in [u32::MAX, u32::MAX / 2 + 1] {
            for signal in [VmSignal::GracefulStop, VmSignal::ForcedStop] {
                let err = signal_pid(not_a_pid, None, signal)
                    .expect_err("a number past pid_t must not be signalled")
                    .to_string();
                assert!(err.contains("not a process id"), "{err}");
            }
        }
        // The largest real pid is still signalled - as ESRCH, which is `Ok`.
        assert!(signal_pid(u32::MAX / 2, None, VmSignal::GracefulStop).is_ok());
    }

    /// The starttime field is counted from the end of the comm field, which
    /// the kernel pads with whatever the process's name made of it - spaces
    /// included.
    #[test]
    fn process_start_time_reads_field_22_wherever_the_comm_ends() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let started_at = process_start_time(pid).expect("a live child has a stat");
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(started_at > 0);
        assert_eq!(process_start_time(u32::MAX - 1), None, "no stat, no answer");
    }

    /// The stop byte leaves from the signal handler itself, and a signal that
    /// lands *before* the guest has dialled its control port is not lost: the
    /// channel is registered afterwards and sends what was latched. That
    /// ordering is the whole reason [`STOP_REQUESTED`] still exists, and it is
    /// the case a thread polling the flag used to cover for free.
    ///
    /// These statics are process-global, so this is the one test that touches
    /// them.
    #[test]
    fn a_stop_signalled_before_the_channel_opens_is_sent_when_it_does() {
        use std::io::Read;
        let (guest, host) = std::os::unix::net::UnixStream::pair().unwrap();

        // No channel yet: latched, and nothing on the wire to send it on.
        handler(libc::SIGTERM);
        assert!(STOP_REQUESTED.load(Ordering::SeqCst));
        assert_eq!(
            STOP_FD.load(Ordering::SeqCst),
            -1,
            "a channel appeared out of nowhere"
        );

        register_stop_channel(std::os::fd::OwnedFd::from(host));
        let mut byte = [0u8; 1];
        (&guest).read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], terra_agent::STOP_SIGNAL);

        // A second signal does not put a second byte on the connection - the
        // guest reads one and starts `pre_stop`.
        handler(libc::SIGINT);
        guest
            .set_read_timeout(Some(std::time::Duration::from_millis(50)))
            .unwrap();
        assert!(
            (&guest).read_exact(&mut byte).is_err(),
            "a repeated signal wrote a second stop byte"
        );
    }

    /// The box's run lock is handed to the VM process on a descriptor, never
    /// released and re-taken: a boot that dropped it first left a window in
    /// which a second terra could take the box and boot over the filesystem
    /// this one is about to start. The window is invisible from outside - it
    /// shows up only as two VMs on one disk image - so it is pinned here.
    #[test]
    fn a_passed_lock_survives_the_handover_and_dies_with_the_child() {
        use std::fs::TryLockError;
        let path = scratch("handover.pid");
        let _ = std::fs::remove_file(&path);
        let lock = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        lock.try_lock().unwrap();

        // A child that holds whatever it inherited until its stdin closes.
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("read line")
            .stdin(std::process::Stdio::piped());
        pass_lock(&mut cmd, &lock);
        let mut child = cmd.spawn().unwrap();

        // The taker lets go: from here the box is held by the child alone.
        drop(lock);
        let probe = OpenOptions::new().read(true).open(&path).unwrap();
        assert!(
            matches!(probe.try_lock_shared(), Err(TryLockError::WouldBlock)),
            "the box was unlocked the moment the boot dropped its copy"
        );

        drop(child.stdin.take());
        child.wait().unwrap();
        // …and it is the child's death that frees it, so it never goes stale.
        assert!(
            probe.try_lock_shared().is_ok(),
            "the lock outlived the process holding it"
        );
        let _ = probe.unlock();
        let _ = std::fs::remove_file(&path);
    }

    /// The host end of `terra put`/`get` opens a path the *guest* can have prepared:
    /// both directions commonly sit in a read-write share, where guest root
    /// creates real host symlinks. The leaf alone is not enough - a symlinked
    /// *parent* is the one that escapes the share.
    #[test]
    fn neither_direction_resolves_through_a_symlink() {
        let real = scratch("private");
        let link = scratch("share-reports");
        let _ = std::fs::remove_dir_all(&real);
        let _ = std::fs::remove_file(&link);
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("key.pem"), b"SECRET").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // (a) a symlinked parent, on both directions.
        let err = create_no_symlinks(&link.join("pwned.sh"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("symlink"), "{err}");
        assert!(!real.join("pwned.sh").exists(), "the write escaped");
        assert!(open_no_symlinks(&link.join("key.pem")).is_err());

        // (b) the leaf itself, which `O_NOFOLLOW` already caught.
        assert!(open_no_symlinks(&link).is_err());

        // …and an ordinary path through real directories still works.
        assert!(open_no_symlinks(&real.join("key.pem")).is_ok());
        assert!(create_no_symlinks(&real.join("fine.txt")).is_ok());

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&real);
    }
}
