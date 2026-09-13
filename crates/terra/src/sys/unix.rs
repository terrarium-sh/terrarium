//! Unix process, file and control-channel operations.
use super::VmSignal;
use std::fs::File;
use std::io::Result;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

pub fn try_lock_run(path: &Path) -> std::result::Result<File, std::fs::TryLockError> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(std::fs::TryLockError::Error)?;
    file.try_lock()?;
    Ok(file)
}

pub fn holds_run_lock(path: &Path) -> bool {
    let Ok(file) = std::fs::OpenOptions::new().read(true).open(path) else {
        return false;
    };
    match file.try_lock_shared() {
        Ok(()) => {
            let _ = file.unlock();
            false
        }
        Err(std::fs::TryLockError::WouldBlock) => true,
        Err(std::fs::TryLockError::Error(_)) => false,
    }
}

#[allow(unsafe_code)]
pub fn host_addresses() -> Result<Vec<std::net::IpAddr>> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let mut first = std::ptr::null_mut();
    // SAFETY: `first` is writable and `freeifaddrs` releases exactly the list returned on success.
    if unsafe { libc::getifaddrs(&raw mut first) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut addresses = Vec::new();
    let mut current = first;
    while !current.is_null() {
        // SAFETY: every node up to the null terminator belongs to the list returned above.
        let entry = unsafe { &*current };
        if !entry.ifa_addr.is_null() {
            // SAFETY: `ifa_addr` has the family selected by `sa_family`.
            let address = unsafe {
                match i32::from((*entry.ifa_addr).sa_family) {
                    libc::AF_INET => {
                        let socket = &*entry.ifa_addr.cast::<libc::sockaddr_in>();
                        Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                            socket.sin_addr.s_addr,
                        ))))
                    }
                    libc::AF_INET6 => {
                        let socket = &*entry.ifa_addr.cast::<libc::sockaddr_in6>();
                        Some(IpAddr::V6(Ipv6Addr::from(socket.sin6_addr.s6_addr)))
                    }
                    _ => None,
                }
            };
            if let Some(address) = address {
                addresses.push(address.to_canonical());
            }
        }
        current = entry.ifa_next;
    }
    // SAFETY: `first` is the allocation returned by `getifaddrs`.
    unsafe { libc::freeifaddrs(first) };
    addresses.sort_unstable();
    addresses.dedup();
    Ok(addresses)
}

/// Max usable `AF_UNIX` socket path length: `sun_path` minus its NUL - 103 on
/// Darwin/BSD, 107 elsewhere.
#[cfg(target_vendor = "apple")]
pub const MAX_SOCK_PATH: usize = 103;
#[cfg(not(target_vendor = "apple"))]
pub const MAX_SOCK_PATH: usize = 107;

pub fn restrict_new_files() {
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
}

/// Through the handle rather than the path: the path may have become a symlink
/// since it was opened.
pub fn set_open_file_mode(file: &File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(mode))
}

/// Restrict an existing path to its owner: `0700` for a directory, `0600` for a
/// file.
pub fn set_owner_only(path: &Path, dir: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if dir { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
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
#[allow(unsafe_code)]
pub fn pass_lock(cmd: &mut Command, lock: &File) -> Result<File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let inherited = lock.try_clone()?;
    let fd = inherited.as_raw_fd();
    // SAFETY: the closure runs between fork and exec, where only
    // async-signal-safe calls are allowed - `dup2` and `fcntl` are both.
    unsafe {
        cmd.pre_exec(move || {
            let borrowed = rustix::fd::BorrowedFd::borrow_raw(fd);
            // `dup2` onto the same number is a no-op that leaves CLOEXEC set,
            // and the lock is commonly opened as fd 3 already.
            if fd == LOCK_FD {
                rustix::io::fcntl_setfd(borrowed, rustix::io::FdFlags::empty())
                    .map_err(std::io::Error::from)?;
            } else {
                if libc::dup2(fd, LOCK_FD) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let target = rustix::fd::BorrowedFd::borrow_raw(LOCK_FD);
                rustix::io::fcntl_setfd(target, rustix::io::FdFlags::empty())
                    .map_err(std::io::Error::from)?;
            }
            Ok(())
        });
    }
    Ok(inherited)
}

/// The run lock a boot passed down, or `None` when [`LOCK_FD`] is not the file
/// `expected` names - which is what `terra __vm` typed at a shell looks like.
/// Identity is checked rather than assumed: running the VM without really
/// holding the box would let a second one boot over it.
#[allow(unsafe_code)]
pub fn claim_inherited_lock(expected: &Path) -> Option<File> {
    use std::os::fd::FromRawFd;
    let same = fd_opens_file(LOCK_FD, expected);
    same.then(|| {
        // SAFETY: fd 3 is ours (dup'd in by `pass_lock` before exec) and the
        // check above already proved it is the box's lock.
        let file = unsafe { File::from_raw_fd(LOCK_FD) };
        rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::CLOEXEC).ok()?;
        file.try_lock().ok()?;
        Some(file)
    })
    .flatten()
}

/// Whether the descriptor `fd` opens the file `path` names, compared through
/// dev+ino without taking `fd` over.
#[allow(unsafe_code)]
fn fd_opens_file(fd: i32, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mut opened = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat accepts invalid descriptor numbers and initializes the writable output only on success.
    if unsafe { libc::fstat(fd, opened.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: fstat succeeded and initialized the stat value.
    let opened = unsafe { opened.assume_init() };
    let want = std::fs::metadata(path).ok();
    #[allow(
        clippy::unnecessary_cast,
        clippy::cast_sign_loss,
        reason = "matches std MetadataExt device ID conversion on Unix hosts"
    )]
    want.is_some_and(|want| want.dev() == opened.st_dev as u64 && want.ino() == opened.st_ino)
}

/// The signal a child was killed by, or `None` if it exited on its own.
pub fn find_terminating_signal(status: std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

/// Whether the kernel lists a process under this pid - what a staging-temp
/// sweep needs to know before it deletes a dead writer's leftovers. `getpgid`
/// reads any process the way `kill(0)` does, without a permission check.
pub fn pid_exists(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    let Some(pid) = rustix::process::Pid::from_raw(pid) else {
        return false;
    };
    rustix::process::getpgid(Some(pid)).is_ok()
}

/// Process start identity: Linux clock ticks since boot, or Darwin wall-clock
/// microseconds. Two processes can wear one pid in sequence, never one starttime.
#[cfg_attr(target_os = "macos", allow(unsafe_code))]
pub fn read_process_start_time(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
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
    #[cfg(target_os = "macos")]
    {
        let pid = i32::try_from(pid).ok()?;
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
        let size = i32::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
        // SAFETY: the buffer has the size required by PROC_PIDTBSDINFO.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if written != size {
            return None;
        }
        // SAFETY: proc_pidinfo initialized the complete structure.
        let info = unsafe { info.assume_init() };
        info.pbi_start_tvsec
            .checked_mul(1_000_000)?
            .checked_add(info.pbi_start_tvusec)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

fn published_process_is_current(pid: u32, published_start_time: Option<u64>) -> bool {
    match published_start_time {
        None => false,
        Some(published) => read_process_start_time(pid) == Some(published),
    }
}

/// `IdentityUnknown` means the process is gone or its published identity cannot be verified.
pub fn signal_pid(
    pid: u32,
    published_start_time: Option<u64>,
    signal: VmSignal,
) -> Result<super::SignalResult> {
    let sig = match signal {
        VmSignal::GracefulStop => rustix::process::Signal::TERM,
        VmSignal::ForcedStop => rustix::process::Signal::KILL,
    };
    let Ok(target) = i32::try_from(pid) else {
        return Err(std::io::Error::other(format!(
            "{pid} is not a process id, so nothing was signalled \
             (the box's {} holds something that is not a pid)",
            crate::state::PID_FILE
        )));
    };
    let Some(target) = rustix::process::Pid::from_raw(target) else {
        return Err(std::io::Error::other(format!(
            "{pid} is not a process id, so nothing was signalled"
        )));
    };
    #[cfg(target_os = "linux")]
    if let Ok(fd) = rustix::process::pidfd_open(target, rustix::process::PidfdFlags::empty()) {
        if !published_process_is_current(pid, published_start_time) {
            return Ok(super::SignalResult::IdentityUnknown);
        }
        return match rustix::process::pidfd_send_signal(&fd, sig) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(super::SignalResult::Sent),
            Err(e) => Err(std::io::Error::from(e)),
        };
    }
    if !published_process_is_current(pid, published_start_time) {
        return Ok(super::SignalResult::IdentityUnknown);
    }
    match rustix::process::kill_process(target, sig) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(super::SignalResult::Sent),
        Err(e) => Err(std::io::Error::from(e)),
    }
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
#[allow(unsafe_code)]
fn send_stop() {
    let fd = STOP_FD.swap(-1, Ordering::SeqCst);
    if fd < 0 {
        return;
    }
    let byte = [terra_protocol::STOP_SIGNAL];
    // SAFETY: `fd` is the control connection, open for the rest of this
    // process's life (see [`STOP_FD`]); one byte from a live buffer.
    unsafe {
        let fd = rustix::fd::BorrowedFd::borrow_raw(fd);
        let _ = rustix::io::write(fd, &byte);
    }
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
#[allow(unsafe_code)]
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
    rustix::process::getuid().as_raw() == 0
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::sys::SignalResult;
    use std::fs::OpenOptions;

    fn create_scratch_path(name: &str) -> std::path::PathBuf {
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
        assert_eq!(
            signal_pid(pid, None, VmSignal::GracefulStop).unwrap(),
            SignalResult::IdentityUnknown
        );
        assert_eq!(
            signal_pid(pid, None, VmSignal::ForcedStop).unwrap(),
            SignalResult::IdentityUnknown
        );
    }

    /// The pid file outlives its VM by however long it takes a boot to empty
    /// it, and the kernel hands that number to strangers in between. A stored
    /// starttime that no longer matches is exactly such a stranger: signalled
    /// with nothing - `Ok`, because "already gone" is the truth about the box -
    /// while the same pid with *its* starttime takes the signal.
    #[test]
    fn an_unverified_pid_is_left_alone_and_the_real_one_is_signalled() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let started_at = read_process_start_time(pid).expect("a live child has a stat");

        assert_eq!(
            signal_pid(pid, None, VmSignal::ForcedStop).unwrap(),
            SignalResult::IdentityUnknown
        );
        assert!(child.try_wait().unwrap().is_none());

        // One tick off is nobody's process as far as the check is concerned.
        assert_eq!(
            signal_pid(pid, Some(started_at + 1), VmSignal::GracefulStop).unwrap(),
            SignalResult::IdentityUnknown
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "a living child was signalled through a recycled identity"
        );

        // The published starttime is the one that reaches it; `sleep` dies of
        // SIGTERM outright.
        assert_eq!(
            signal_pid(pid, Some(started_at), VmSignal::GracefulStop).unwrap(),
            SignalResult::Sent
        );
        child.wait().unwrap();

        // …and once gone, any starttime reads as already-gone rather than
        // reaching whoever wears the pid now.
        assert_eq!(
            signal_pid(pid, Some(started_at), VmSignal::ForcedStop).unwrap(),
            SignalResult::IdentityUnknown
        );
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
        let started_at = read_process_start_time(pid).expect("a live child has a stat");
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(started_at > 0);
        assert_eq!(
            read_process_start_time(u32::MAX - 1),
            None,
            "no stat, no answer"
        );
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
        assert_eq!(byte[0], terra_protocol::STOP_SIGNAL);

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
        let path = create_scratch_path("handover.pid");
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
        let inheritance = pass_lock(&mut cmd, &lock).unwrap();
        let mut child = cmd.spawn().unwrap();
        drop(inheritance);

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

    /// The lock descriptor is claimed only when it really opens the pid file:
    /// an unrelated fd 3 - what `terra __vm` typed at a shell inherits from
    /// whatever spawned it - must read as not-the-lock, or a VM would run
    /// without holding the box.
    #[test]
    fn the_handed_lock_descriptor_is_matched_by_identity() {
        use std::os::fd::AsRawFd;
        let lock_path = create_scratch_path("identity.pid");
        let _ = std::fs::remove_file(&lock_path);
        let lock = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .unwrap();
        let unrelated_path = create_scratch_path("not-a-lock.txt");
        std::fs::write(&unrelated_path, b"x").unwrap();
        let unrelated = std::fs::File::open(&unrelated_path).unwrap();

        assert!(fd_opens_file(lock.as_raw_fd(), &lock_path));
        assert!(!fd_opens_file(-1, &lock_path));
        assert!(!fd_opens_file(i32::MAX, &lock_path));
        assert!(
            !fd_opens_file(unrelated.as_raw_fd(), &lock_path),
            "an unrelated descriptor passed as the box's lock"
        );
    }
}
