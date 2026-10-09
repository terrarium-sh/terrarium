//! Unix child-process handoff and supervision.

use std::fs::File;
use std::io::Result;
use std::process::Command;

#[allow(unsafe_code)]
pub fn detach(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: setsid is async-signal-safe between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            rustix::process::setsid()
                .map(|_| ())
                .map_err(std::io::Error::from)
        });
    }
}

#[allow(unsafe_code)]
fn duplicate_above_handoff(file: &impl std::os::fd::AsRawFd) -> Result<File> {
    use std::os::fd::FromRawFd;
    // SAFETY: fcntl duplicates an open descriptor; File takes ownership only on success.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 16) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful fcntl returned a new descriptor owned only here.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[allow(unsafe_code)]
pub fn pass_descriptor(
    cmd: &mut Command,
    file: &impl std::os::fd::AsRawFd,
    target: i32,
) -> Result<File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let inherited = duplicate_above_handoff(file)?;
    let source = inherited.as_raw_fd();
    // SAFETY: dup2 is async-signal-safe between fork and exec; source remains open until spawn.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(source, target) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(inherited)
}

pub struct VmChildGuard {
    _write: File,
    _read: File,
}

pub fn pass_ipc(
    command: &mut Command,
    stream: &std::os::unix::net::UnixStream,
    target: i32,
) -> Result<std::os::unix::net::UnixStream> {
    Ok(std::os::unix::net::UnixStream::from(
        std::os::fd::OwnedFd::from(pass_descriptor(command, stream, target)?),
    ))
}

#[allow(unsafe_code)]
pub fn claim_ipc(fd: i32) -> Result<std::os::unix::net::UnixStream> {
    use std::os::fd::FromRawFd;
    // SAFETY: fcntl checks the inherited descriptor before ownership is claimed.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the launcher transfers this live descriptor exclusively to the worker.
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    if rustix::net::sockopt::socket_type(&stream).map_err(std::io::Error::from)?
        != rustix::net::SocketType::STREAM
    {
        return Err(std::io::Error::other(
            "inherited IPC is not a stream socket",
        ));
    }
    stream.peer_addr()?;
    rustix::io::fcntl_setfd(&stream, rustix::io::FdFlags::CLOEXEC).map_err(std::io::Error::from)?;
    Ok(stream)
}

#[allow(unsafe_code)]
pub fn supervise_vm_child(cmd: &mut Command, foreground: bool) -> Result<Option<VmChildGuard>> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    if !foreground {
        detach(cmd);
        return Ok(None);
    }
    detach(cmd);
    let mut ends = [0; 2];
    // SAFETY: pipe initializes both integer descriptors on success.
    if unsafe { libc::pipe(ends.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful pipe returned two distinct owned descriptors.
    let read = unsafe { File::from_raw_fd(ends[0]) };
    // SAFETY: the write descriptor is the other owned pipe endpoint.
    let write = unsafe { File::from_raw_fd(ends[1]) };
    rustix::io::fcntl_setfd(&read, rustix::io::FdFlags::CLOEXEC).map_err(std::io::Error::from)?;
    rustix::io::fcntl_setfd(&write, rustix::io::FdFlags::CLOEXEC).map_err(std::io::Error::from)?;
    let inherited_read = duplicate_above_handoff(&read)?;
    let inherited_write = duplicate_above_handoff(&write)?;
    let read_fd = inherited_read.as_raw_fd();
    let write_fd = inherited_write.as_raw_fd();
    #[cfg(target_os = "linux")]
    // SAFETY: getpid reads the current process identity without pointers.
    let parent_pid = unsafe { libc::getpid() };
    // SAFETY: getdtablesize reads the current descriptor limit without pointers.
    let max_fd = unsafe { libc::getdtablesize() };
    // SAFETY: fork, close, read, kill, and _exit are async-signal-safe after Command's fork.
    unsafe {
        cmd.pre_exec(move || {
            #[cfg(target_os = "linux")]
            {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent_pid {
                    return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
                }
            }
            let watchdog = libc::fork();
            if watchdog < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if watchdog == 0 {
                #[cfg(target_os = "linux")]
                let closed_ranges = libc::syscall(
                    libc::SYS_close_range,
                    0_u32,
                    (read_fd - 1).cast_unsigned(),
                    0_u32,
                ) == 0
                    && libc::syscall(
                        libc::SYS_close_range,
                        (read_fd + 1).cast_unsigned(),
                        u32::MAX,
                        0_u32,
                    ) == 0;
                #[cfg(not(target_os = "linux"))]
                let closed_ranges = false;
                if !closed_ranges {
                    for fd in 0..max_fd {
                        if fd != read_fd {
                            libc::close(fd);
                        }
                    }
                }
                let mut byte = 0_u8;
                loop {
                    let count = libc::read(read_fd, (&raw mut byte).cast(), 1);
                    if count == 0 {
                        libc::kill(-libc::getpgrp(), libc::SIGKILL);
                        libc::_exit(0);
                    }
                    if count < 0 {
                        libc::_exit(1);
                    }
                }
            }
            libc::close(read_fd);
            libc::close(write_fd);
            Ok(())
        });
    }
    Ok(Some(VmChildGuard {
        _write: inherited_write,
        _read: inherited_read,
    }))
}

#[allow(clippy::unnecessary_wraps, reason = "matches fallible Windows setup")]
pub fn attach_vm_child(_guard: &VmChildGuard, _child: &std::process::Child) -> Result<()> {
    Ok(())
}

#[allow(unsafe_code)]
pub fn kill_vm_child(child: &mut std::process::Child) -> Result<()> {
    let pid = i32::try_from(child.id()).map_err(std::io::Error::other)?;
    // SAFETY: an unreaped child cannot have its PID reused; signal the group only if it owns it.
    let group = unsafe { libc::getpgid(pid) };
    if group == pid {
        // SAFETY: the unreaped child is the group leader, so its PID cannot be reused.
        if unsafe { libc::kill(-pid, libc::SIGKILL) } == 0 {
            return Ok(());
        }
        return Err(std::io::Error::last_os_error());
    }
    child.kill()
}
