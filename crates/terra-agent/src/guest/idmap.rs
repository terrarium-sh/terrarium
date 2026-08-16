//! The idmapped share mount: the guest half of terra's ownership model.
//!
//! virtiofs on an unprivileged host serves every write as the launching user
//! and reports that user's host ids back; the map set here translates both
//! directions at the mount boundary, and guest root maps to itself. Everything
//! this rests on ships pinned with terra, so a failure here is a bug, not a
//! host to accommodate, and the boot fails loudly.

use anyhow::{Context, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use terra_agent::{WORKLOAD_GID, WORKLOAD_UID};

/// linux/mount.h - in the locked libc only for gnu targets, and the agent
/// builds for musl.
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;

/// A user namespace holding the shares' map - guest root and the workload user
/// on the inside, real root and the launching user on the host side. A
/// namespace needs a task to exist, so a child is forked and parked in
/// `pause()` until the namespace fd is open, then killed and reaped; the fd
/// alone keeps the namespace alive after it.
///
/// Must run **before** the chroot: `unshare(CLONE_NEWUSER)` is refused with
/// `EPERM` from a process whose root is not its mount namespace's.
#[allow(clippy::similar_names)] // uid/gid pairs are inherently close
pub fn owner_userns((host_uid, host_gid): (u32, u32)) -> Result<OwnedFd> {
    let (ready_r, ready_w) = pipe()?;
    // SAFETY: `fork` is sound here - this runs before the agent's serving
    // threads exist, and the child touches only raw syscalls before `_exit`
    // regardless.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error()).context("forking for the share namespace");
    }
    if pid == 0 {
        // SAFETY: async-signal-safe syscalls only. Parked in `pause()` until
        // the parent's SIGKILL - which cannot hang, unlike waiting to be
        // released over a pipe.
        unsafe {
            if libc::unshare(libc::CLONE_NEWUSER) == 0
                && libc::write(ready_w.as_raw_fd(), [1u8].as_ptr().cast(), 1) == 1
            {
                loop {
                    libc::pause();
                }
            }
            libc::_exit(1);
        }
    }
    // The child's end: dropped here so a child that dies without writing is
    // an EOF on `ready_r` rather than a read blocking forever.
    drop(ready_w);

    let mut byte = [0u8; 1];
    // SAFETY: one byte into a valid buffer from an open pipe.
    let ready = unsafe { libc::read(ready_r.as_raw_fd(), byte.as_mut_ptr().cast(), 1) } == 1;
    let userns = if ready {
        let write_map = |file: &str, text: String| {
            std::fs::write(format!("/proc/{pid}/{file}"), text)
                .with_context(|| format!("writing the share namespace's {file}"))
        };
        // Ascending and non-overlapping, as the kernel demands: guest root to
        // real root, the workload user to the launching user. `host_uid` is
        // never 0 here - a root host maps nothing (see `sys::share_owner`
        // host-side).
        write_map("uid_map", format!("0 0 1\n{WORKLOAD_UID} {host_uid} 1"))
            .and_then(|()| write_map("gid_map", format!("0 0 1\n{WORKLOAD_GID} {host_gid} 1")))
            .and_then(|()| {
                std::fs::File::open(format!("/proc/{pid}/ns/user"))
                    .context("opening the share namespace fd")
                    .map(OwnedFd::from)
            })
    } else {
        Err(anyhow::anyhow!(
            "the share-namespace child could not unshare a user namespace"
        ))
    };
    // SAFETY: `pid` is our own un-reaped child, so it cannot have been recycled.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    reap(pid);
    userns
}

/// Reattach the mount at `target` with the owner map - set on a detached
/// clone, since the kernel allows that only there.
pub fn remount_idmapped(target: &str, userns: &OwnedFd) -> Result<()> {
    let target_c = std::ffi::CString::new(target)?;
    // The FUSE INIT handshake is asynchronous: `mount` returns before the
    // reply that clears the superblock's no-idmap flag is processed, and the
    // `mount_setattr` below then fails `EINVAL`. Every FUSE request waits out
    // the handshake, so one `statfs` - never answered from cache - orders the
    // idmap after it.
    let mut sfs = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `statfs` fills the buffer on success; failure is reported by rc.
    if unsafe { libc::statfs(target_c.as_ptr(), sfs.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("statfs {target}"));
    }
    // SAFETY: yields a new fd holding a detached clone of the mount at `target`.
    let tree = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            target_c.as_ptr(),
            libc::OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint,
        )
    };
    if tree < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("open_tree {target}"));
    }
    // SAFETY: the fd was returned to us alone, and a valid fd fits the cast.
    let tree = unsafe { OwnedFd::from_raw_fd(libc::c_int::try_from(tree)?) };

    let attr = libc::mount_attr {
        attr_set: libc::MOUNT_ATTR_IDMAP,
        attr_clr: 0,
        propagation: 0,
        userns_fd: u64::try_from(userns.as_raw_fd())?,
    };
    // SAFETY: `AT_EMPTY_PATH` addresses the tree fd itself; `attr` outlives the call.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            tree.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            &raw const attr,
            size_of::<libc::mount_attr>(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("setting the idmap on {target}"));
    }
    // The plain mount goes first: moving on top of it would only stack over it.
    // SAFETY: detaches the mount at a NUL-terminated path.
    if unsafe { libc::umount2(target_c.as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("umount {target}"));
    }
    // SAFETY: attaches the tree fd at `target`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            tree.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_FDCWD,
            target_c.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("moving the idmapped mount onto {target}"));
    }
    Ok(())
}

fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: fills the two fds or fails; `O_CLOEXEC` keeps them out of execs.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error()).context("creating a pipe");
    }
    // SAFETY: fresh fds owned by nothing else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn reap(pid: libc::pid_t) {
    // SAFETY: waits on our own child; the null status pointer is allowed.
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The forked child is parked until the parent kills it, so *every* exit
    /// from [`owner_userns`] - the ones that give up included - has to take it
    /// down before it waits, or `waitpid` never returns.
    ///
    /// A regression here is a box that hangs mid-boot with nothing on the
    /// console, which is why this asserts on a deadline rather than joining: a
    /// suite that hangs is worse than one that fails. What the call *returns*
    /// depends on privilege - unprivileged the map write is refused, as root it
    /// is not - so only finishing is under test.
    #[test]
    fn owner_userns_gives_up_rather_than_hanging() {
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(owner_userns((1000, 1000)).is_ok());
        });
        assert!(
            finished
                .recv_timeout(std::time::Duration::from_secs(20))
                .is_ok(),
            "owner_userns never returned - its parked child was not released"
        );
    }
}
