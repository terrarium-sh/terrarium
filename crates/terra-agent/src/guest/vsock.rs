//! Guest-side vsock: outbound to the host for the boot plan/stop signal;
//! inbound for `terra attach`. Raw libc - less code than a crate.
//!
//! Every socket here is `SOCK_CLOEXEC`. The agent execs untrusted code - the
//! workload, and every hook - and `Command` rewires only stdio, so a
//! descriptor without it survives into them: a workload holding the control
//! connection could win the race for the graceful-stop byte, and one holding a
//! listener could `accept()` the host's connections directly, walking past the
//! [`is_host_peer`] check below (which only ever sees peers the *agent*
//! accepts).
// `svm_*` mirrors the kernel's `sockaddr_vm` field names verbatim.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::struct_field_names
)]

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// The well-known vsock CID of the host, as seen from inside the guest.
pub const VMADDR_CID_HOST: u32 = 2;

const AF_VSOCK: libc::c_int = 40;
const VMADDR_CID_ANY: u32 = u32::MAX;

#[repr(C)]
struct SockaddrVm {
    svm_family: libc::sa_family_t,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

pub struct VsockListener {
    fd: OwnedFd,
}

/// A connected vsock stream. Backed by a [`std::fs::File`], which supplies
/// `Read`/`Write`/`try_clone` - the raw reads and writes work on any stream
/// fd, which is what lets tests drive the agent's services over a socketpair.
pub struct VsockStream {
    f: std::fs::File,
}

/// A fresh `AF_VSOCK` socket and the address to bind or connect it to. Both
/// directions go through here, so the `sockaddr` is built - and sized - once.
fn vsock_socket(cid: u32, port: u32) -> std::io::Result<(OwnedFd, SockaddrVm)> {
    // SAFETY: plain socket creation; the result is checked before use.
    let raw = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a fresh fd owned by nothing else.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    Ok((
        fd,
        SockaddrVm {
            svm_family: AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: cid,
            svm_zero: [0; 4],
        },
    ))
}

/// `&addr as *const sockaddr` plus its length, the pair every call below wants.
fn addr_ptr(addr: &SockaddrVm) -> (*const libc::sockaddr, libc::socklen_t) {
    (
        std::ptr::from_ref(addr).cast::<libc::sockaddr>(),
        std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
    )
}

impl VsockListener {
    pub fn bind(port: u32) -> std::io::Result<Self> {
        let (fd, addr) = vsock_socket(VMADDR_CID_ANY, port)?;
        let (ptr, len) = addr_ptr(&addr);
        // SAFETY: a live fd and a sized sockaddr; failures are reported by rc.
        unsafe {
            if libc::bind(fd.as_raw_fd(), ptr, len) < 0 || libc::listen(fd.as_raw_fd(), 8) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(Self { fd })
    }

    /// Accept the next connection **from the host**, refusing every other peer.
    ///
    /// The listener must bind [`VMADDR_CID_ANY`] to receive the host's
    /// connections at all, and the guest kernel has vsock loopback - a
    /// guest-local peer arrives as `VMADDR_CID_LOCAL` or the guest's own CID,
    /// and is dropped before the caller ever sees it.
    pub fn accept(&self) -> std::io::Result<VsockStream> {
        loop {
            let (stream, cid) = self.accept_any()?;
            if is_host_peer(cid) {
                return Ok(stream);
            }
            eprintln!("terra-agent: refused a vsock connection from inside the guest (cid {cid})");
            drop(stream);
        }
    }

    /// One accepted connection and the peer's CID, whoever it is.
    fn accept_any(&self) -> std::io::Result<(VsockStream, u32)> {
        // SAFETY: an all-zero sockaddr buffer for the kernel to fill.
        let mut peer: SockaddrVm = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<SockaddrVm>() as libc::socklen_t;
        // `accept4`, not `accept`: an accepted connection does not inherit the
        // listener's flags (see the module doc on `SOCK_CLOEXEC`).
        // SAFETY: a live listener fd, a sized peer buffer, checked rc.
        let raw = unsafe {
            libc::accept4(
                self.fd.as_raw_fd(),
                std::ptr::from_mut(&mut peer).cast::<libc::sockaddr>(),
                &raw mut len,
                libc::SOCK_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a fresh fd owned by nothing else.
        let stream = VsockStream {
            f: unsafe { std::fs::File::from_raw_fd(raw) },
        };
        // A short address never names the host: answer a CID no peer can be
        // (`u32::MAX` is `VMADDR_CID_ANY`), so the caller refuses it.
        if (len as usize) < std::mem::size_of::<SockaddrVm>() {
            return Ok((stream, u32::MAX));
        }
        Ok((stream, peer.svm_cid))
    }
}

/// Whether an accepted peer is the host, and so allowed to drive the agent.
const fn is_host_peer(cid: u32) -> bool {
    cid == VMADDR_CID_HOST
}

impl VsockStream {
    /// Dial `port` on `cid` (use [`VMADDR_CID_HOST`] for the host).
    pub fn connect(cid: u32, port: u32) -> std::io::Result<Self> {
        let (fd, addr) = vsock_socket(cid, port)?;
        let (ptr, len) = addr_ptr(&addr);
        // SAFETY: a live fd and a sized sockaddr; failure is reported by rc.
        if unsafe { libc::connect(fd.as_raw_fd(), ptr, len) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { f: fd.into() })
    }

    pub fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            f: self.f.try_clone()?,
        })
    }

    /// Shut the socket down. Unlike dropping a clone, this reaches every
    /// duplicate at once - it acts on the socket, not the descriptor - which is
    /// what unblocks a reader thread holding its own clone. Best-effort: the
    /// socket may already be gone.
    pub fn shutdown(&self, how: std::net::Shutdown) {
        let how = match how {
            std::net::Shutdown::Read => libc::SHUT_RD,
            std::net::Shutdown::Write => libc::SHUT_WR,
            std::net::Shutdown::Both => libc::SHUT_RDWR,
        };
        // SAFETY: a plain shutdown on a live fd; the result is deliberately ignored.
        unsafe { libc::shutdown(self.f.as_raw_fd(), how) };
    }
}

impl From<OwnedFd> for VsockStream {
    fn from(fd: OwnedFd) -> Self {
        Self { f: fd.into() }
    }
}

impl std::io::Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.f.read(buf)
    }
}

impl std::io::Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.f.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.f.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The agent's ports are reachable from inside the guest (the kernel has
    /// vsock loopback), and both of them act with init's privileges - the file
    /// port reads and writes as root, the session port carries the workload's
    /// terminal. Only the host may drive them.
    const VMADDR_CID_HYPERVISOR: u32 = 0;
    const VMADDR_CID_LOCAL: u32 = 1;

    #[test]
    fn only_the_host_may_drive_the_agent() {
        assert!(is_host_peer(VMADDR_CID_HOST));
        for guest_side in [VMADDR_CID_HYPERVISOR, VMADDR_CID_LOCAL, 3, 42, u32::MAX] {
            assert!(
                !is_host_peer(guest_side),
                "cid {guest_side} is not the host"
            );
        }
    }
}
