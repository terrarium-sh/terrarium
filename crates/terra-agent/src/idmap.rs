//! The idmapped share mount: translates host user ids at the mount boundary.

use anyhow::{Context, Result};
use std::ffi::{c_long, c_ulong};
use std::os::fd::{AsRawFd, OwnedFd};
use terra_shared::contract::{ShareOwner, WORKLOAD_ID};

/// Creates a user namespace holding the shares' id map.
/// Must run before chroot: `unshare(CLONE_NEWUSER)` returns `EPERM` once root diverges.
#[allow(unsafe_code)]
pub fn create_owner_userns(owner: ShareOwner) -> Result<OwnedFd> {
    let (ready_r, ready_w) = rustix::pipe::pipe().map_err(std::io::Error::from)?;
    // SAFETY: `kernel_fork` is sound here - this runs before the agent's serving
    // threads exist, and the child touches only raw syscalls before exit
    // regardless.
    let pid = match unsafe { rustix::runtime::kernel_fork() }
        .context("forking for the share namespace")?
    {
        rustix::runtime::Fork::Child(_) => {
            // SAFETY: async-signal-safe syscalls only. Parked in `pause()` until
            // the parent's SIGKILL - which cannot hang, unlike waiting to be
            // released over a pipe.
            if unsafe { rustix::thread::unshare_unsafe(rustix::thread::UnshareFlags::NEWUSER) }
                .is_ok()
                && rustix::io::write(&ready_w, &[1u8]) == Ok(1)
            {
                loop {
                    rustix::event::pause();
                }
            }
            rustix::runtime::exit_group(1)
        }
        rustix::runtime::Fork::ParentOf(pid) => pid,
    };
    drop(ready_w);

    let mut byte = [0u8; 1];
    let ready = rustix::io::read(&ready_r, &mut byte) == Ok(1);
    let userns = if ready {
        let write_map = |file: &str, text: String| {
            std::fs::write(format!("/proc/{pid}/{file}"), text)
                .with_context(|| format!("writing the share namespace's {file}"))
        };
        write_map("uid_map", format!("0 0 1\n{WORKLOAD_ID} {} 1", owner.uid))
            .and_then(|()| write_map("gid_map", format!("0 0 1\n{WORKLOAD_ID} {} 1", owner.gid)))
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
    let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
    let _ = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty());
    userns
}

/// Reattaches the mount at `target` with the owner map applied to a detached clone.
pub fn remount_idmapped(target: &str, userns: &OwnedFd) -> Result<()> {
    // FUSE INIT is asynchronous; mount returns before the superblock clears no-idmap.
    // An uncached statfs waits out the handshake before mount_setattr.
    rustix::fs::statfs(target)
        .map_err(std::io::Error::from)
        .with_context(|| format!("statfs {target}"))?;
    let tree = rustix::mount::open_tree(
        rustix::fs::CWD,
        target,
        rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
            | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC,
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("open_tree {target}"))?;

    mount_setattr(&tree, userns)
        .map_err(std::io::Error::from)
        .with_context(|| format!("setting the idmap on {target}"))?;
    // Unmount the plain mount first so move_mount replaces it instead of stacking over it.
    rustix::mount::unmount(target, rustix::mount::UnmountFlags::DETACH)
        .map_err(std::io::Error::from)
        .with_context(|| format!("umount {target}"))?;
    rustix::mount::move_mount(
        &tree,
        "",
        rustix::fs::CWD,
        target,
        rustix::mount::MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("moving the idmapped mount onto {target}"))
}

#[allow(unsafe_code)]
unsafe extern "C" {
    #[link_name = "syscall"]
    fn invoke_syscall(number: c_long, ...) -> c_long;
}

#[allow(unsafe_code)]
#[allow(clippy::cast_sign_loss)]
fn mount_setattr(tree: &OwnedFd, userns: &OwnedFd) -> rustix::io::Result<()> {
    let attr = linux_raw_sys::general::mount_attr {
        attr_set: u64::from(rustix::mount::MountAttrFlags::MOUNT_ATTR_IDMAP.bits()),
        attr_clr: 0,
        propagation: 0,
        userns_fd: userns.as_raw_fd() as u64,
    };
    // SAFETY: The syscall number and arguments match Linux's mount_setattr ABI;
    // the path and attribute pointers remain valid for the call's duration.
    let result = unsafe {
        invoke_syscall(
            c_long::from(linux_raw_sys::general::__NR_mount_setattr),
            c_long::from(tree.as_raw_fd()),
            c"".as_ptr(),
            c_ulong::from(rustix::mount::OpenTreeFlags::AT_EMPTY_PATH.bits()),
            std::ptr::from_ref(&attr),
            std::mem::size_of_val(&attr) as c_ulong,
        )
    };
    if result == -1 {
        let error = std::io::Error::last_os_error();
        Err(rustix::io::Errno::from_io_error(&error).unwrap_or(rustix::io::Errno::IO))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The forked child is parked until the parent kills it, so *every* exit
    /// from [`create_owner_userns`] - the ones that give up included - has to take it
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
            let _ = done.send(
                create_owner_userns(ShareOwner {
                    uid: 1000,
                    gid: 1000,
                })
                .is_ok(),
            );
        });
        assert!(
            finished
                .recv_timeout(std::time::Duration::from_secs(20))
                .is_ok(),
            "owner_userns never returned - its parked child was not released"
        );
    }
}
