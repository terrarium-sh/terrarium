//! Guest-side vsock: outbound to the host for the boot plan/stop signal;
//! inbound for the agent port - the accept loop, the hello, and the dispatch
//! to each service. Raw libc - less code than a crate.
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

use crate::term::session::{ClientSink, Session};
use crate::term::tty::set_winsize;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Duration;
use terra_shared::{
    AGENT_HELLO, AgentOutput, AgentService, ClientInput, ControlReply, ControlRequest,
};

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

// ---- the agent port --------------------------------------------------------

/// Backoff after a failed `accept` (see [`accept_failed`]).
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// Answer the agent port for as long as the workload runs.
///
/// The port was claimed before any guest code ran (see `init::execute`);
/// this is only the accept loop. Every connection opens with [`say_hello`] and
/// one [`AgentService`] byte from the client selects what the connection is for.
pub(crate) fn serve_agent_port(
    session: &Arc<Session>,
    listener: VsockListener,
    master_fd: RawFd,
    root: bool,
) {
    let session = session.clone();
    std::thread::spawn(move || {
        loop {
            match listener.accept() {
                // A thread per connection: the service byte is the client's to
                // send, and one that never does must not stall the next accept.
                Ok(conn) => {
                    let session = session.clone();
                    std::thread::spawn(move || dispatch(&session, conn, master_fd, root));
                }
                Err(e) => accept_failed(&e),
            }
        }
    });
}

fn dispatch(session: &Arc<Session>, mut conn: VsockStream, master_fd: RawFd, root: bool) {
    // Hello before anything the service writes (a session's screen repaint,
    // say): it has to be the first byte on the connection, not the second.
    if !say_hello(&mut conn) {
        return;
    }
    let mut service = [0u8; 1];
    if conn.read_exact(&mut service).is_err() {
        return; // gone before asking for anything: a host probe, dropped
    }
    match AgentService::from_byte(service[0]) {
        Some(AgentService::Session) => serve_client(session, conn, master_fd),
        Some(AgentService::SessionControl) => serve_session_control(session, conn, master_fd),
        Some(AgentService::Files) => crate::files::serve_file_op(conn, root),
        Some(AgentService::Exec) => crate::exec::serve_exec(conn, root),
        None => eprintln!(
            "terra-agent: unknown service byte {:#04x} - dropping the connection",
            service[0]
        ),
    }
}

/// Announce the agent to a client that has just connected - [`AGENT_HELLO`],
/// ahead of whatever the connection serves. `false` means the client is already
/// gone, which is ordinary: the host drops connections it opened too early.
#[must_use]
fn say_hello(conn: &mut VsockStream) -> bool {
    conn.write_all(&[AGENT_HELLO])
        .and_then(|()| conn.flush())
        .is_ok()
}

/// An accept loop cannot give up - the port is the agent's only way of being
/// reached - but it must not spin either: a persistent error (`EMFILE`, say)
/// would otherwise busy-loop guest PID 1 and flood the console with it.
fn accept_failed(e: &impl std::fmt::Display) {
    eprintln!("terra-agent: accept failed: {e}");
    std::thread::sleep(ACCEPT_RETRY);
}

/// One `terra` client's downstream: [`AgentOutput`] frames, and a socket that
/// is shut down when the session drops it. Closing the writer's clone alone
/// would not do it - the reader thread below holds another, so the host would
/// see a frozen terminal instead of EOF.
struct FramedClient(VsockStream);

impl FramedClient {
    fn send(&mut self, frame: &AgentOutput) -> std::io::Result<()> {
        self.0
            .write_all(&frame.encode())
            .and_then(|()| self.0.flush())
    }
}

impl ClientSink for FramedClient {
    fn out(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.send(&AgentOutput::Out(bytes.to_vec()))
    }
    fn exit(&mut self, code: i32) -> std::io::Result<()> {
        self.send(&AgentOutput::Exit(code))
    }
    fn detached(&mut self) -> std::io::Result<()> {
        self.send(&AgentOutput::Detached)
    }
}

impl Drop for FramedClient {
    fn drop(&mut self) {
        self.0.shutdown(std::net::Shutdown::Both);
    }
}

/// Attach one `terra` client to the session and forward its framed input -
/// keystrokes and resizes - until its connection ends.
fn serve_client(session: &Arc<Session>, conn: VsockStream, master_fd: RawFd) {
    let Ok(reader) = conn.try_clone() else { return };
    let id = session.attach(FramedClient(conn));

    let session = session.clone();
    std::thread::spawn(move || {
        let mut reader = reader;
        loop {
            match ClientInput::read(&mut reader) {
                Ok(Some(ClientInput::Keys(b))) => {
                    if session.send_input(&b).is_err() {
                        break;
                    }
                }
                // Only an exec client sends this: a session's stdin ends when
                // its connection closes, which is the escape key.
                Ok(Some(ClientInput::Eof)) => {}
                Ok(Some(ClientInput::Resize { rows, cols })) => {
                    // No size (a pty with EOF'd input, a pipe) arrives as 0×0,
                    // and vt100 panics on it; a zero size is not worth applying
                    // anyway.
                    if rows > 0
                        && cols > 0
                        && let Some((r, c)) = session.set_client_size(id, rows, cols)
                    {
                        set_winsize(master_fd, r, c);
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
        if let Some((r, c)) = session.detach_client(id) {
            set_winsize(master_fd, r, c);
        }
    });
}

/// Serve one session-management ask - list the clients or drop one -
/// without attaching as a client itself.
fn serve_session_control(session: &Arc<Session>, mut conn: VsockStream, master_fd: RawFd) {
    let reply = |conn: &mut VsockStream, rep: &ControlReply| {
        conn.write_all(&rep.encode()).and_then(|()| conn.flush())
    };
    match ControlRequest::read(&mut conn) {
        Ok(Some(ControlRequest::List)) => {
            for (id, size) in session.list_clients() {
                let (rows, cols) = size.unwrap_or((0, 0));
                if reply(&mut conn, &ControlReply::Client { id, rows, cols }).is_err() {
                    return;
                }
            }
            let _ = reply(&mut conn, &ControlReply::Done);
        }
        Ok(Some(ControlRequest::Detach { id })) => {
            if session.list_clients().iter().any(|(cid, _)| *cid == id) {
                if let Some((r, c)) = session.detach_client(id) {
                    set_winsize(master_fd, r, c);
                }
                let _ = reply(&mut conn, &ControlReply::Detached { id });
            } else {
                let _ = reply(&mut conn, &ControlReply::Missing { id });
            }
        }
        Ok(Some(ControlRequest::DetachAll)) => {
            let ids: Vec<u64> = session
                .list_clients()
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            if let Some((r, c)) = session.detach_all_clients() {
                set_winsize(master_fd, r, c);
            }
            for id in ids {
                if reply(&mut conn, &ControlReply::Detached { id }).is_err() {
                    return;
                }
            }
            let _ = reply(&mut conn, &ControlReply::Done);
        }
        Ok(None) | Err(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

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

    /// A sink that never blocks and never fails: what a client's writer thread
    /// drains into when the test only cares about the listing.
    struct Quiet;
    impl ClientSink for Quiet {
        fn out(&mut self, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn exit(&mut self, _: i32) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A session with `n` attached clients and an input sink that goes nowhere.
    fn session_with(n: usize) -> Arc<Session> {
        let input: crate::term::session::Sink = Arc::new(std::sync::Mutex::new(std::io::sink()));
        let session = Session::new(input);
        for _ in 0..n {
            let _ = session.attach(Quiet);
        }
        session
    }

    /// Drive one [`serve_session_control`] over a socketpair, the way the file
    /// and exec services are driven. `master_fd` is a non-tty fd: the
    /// TIOCSWINSZ ioctl fails on it and is ignored, exactly as it is for a
    /// client whose terminal died mid-session.
    fn do_control(session: &Arc<Session>, req: &ControlRequest) -> Vec<ControlReply> {
        let null = std::fs::File::open("/dev/null").unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let server = VsockStream::from(std::os::fd::OwnedFd::from(server));
        let session = session.clone();
        let agent =
            std::thread::spawn(move || serve_session_control(&session, server, null.as_raw_fd()));
        client.write_all(&req.encode()).unwrap();
        let mut reps = Vec::new();
        while let Some(rep) = ControlReply::read(&mut client).unwrap() {
            let done = matches!(rep, ControlReply::Done);
            reps.push(rep);
            if done {
                break;
            }
        }
        agent.join().unwrap();
        reps
    }

    #[test]
    fn the_control_service_lists_the_clients() {
        let session = session_with(2);
        session.set_client_size(0, 30, 100);
        assert_eq!(
            do_control(&session, &ControlRequest::List),
            vec![
                ControlReply::Client {
                    id: 0,
                    rows: 30,
                    cols: 100
                },
                ControlReply::Client {
                    id: 1,
                    rows: 0,
                    cols: 0
                },
                ControlReply::Done,
            ]
        );
        // The ask did not disturb the session.
        assert_eq!(session.list_clients().len(), 2);
    }

    /// The answer to a detach is about the client's existence, not its size:
    /// dropping a client that did not constrain the shared size must still read
    /// as detached, or `terra detach` would call a successful cleanup "missing".
    #[test]
    fn the_control_service_detaches_one_client() {
        let session = session_with(2);
        session.set_client_size(0, 30, 100);
        session.set_client_size(1, 50, 200);

        assert_eq!(
            do_control(&session, &ControlRequest::Detach { id: 1 }),
            vec![ControlReply::Detached { id: 1 }]
        );
        assert_eq!(session.list_clients(), vec![(0, Some((30, 100)))]);
    }

    #[test]
    fn detaching_an_unknown_id_answers_missing() {
        let session = session_with(1);
        assert_eq!(
            do_control(&session, &ControlRequest::Detach { id: 7 }),
            vec![ControlReply::Missing { id: 7 }]
        );
        assert_eq!(
            session.list_clients().len(),
            1,
            "the unknown id took nothing"
        );
    }

    #[test]
    fn detach_all_drops_every_client() {
        let session = session_with(3);
        assert_eq!(
            do_control(&session, &ControlRequest::DetachAll),
            vec![
                ControlReply::Detached { id: 0 },
                ControlReply::Detached { id: 1 },
                ControlReply::Detached { id: 2 },
                ControlReply::Done,
            ]
        );
        assert_eq!(session.list_clients(), vec![]);
    }
}
