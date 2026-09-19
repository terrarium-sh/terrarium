//! Guest-side vsock: outbound to host for boot/control, inbound for agent services.
//!
//! Sockets use `SOCK_CLOEXEC` to prevent child processes from inheriting control connections or listeners.
// `svm_*` mirrors the kernel's `sockaddr_vm` field names verbatim.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::struct_field_names
)]

use crate::term::session::{ClientConn, DetachOutcome, Session};
use crate::term::tty::set_winsize;
use rustix::net::addr::{SocketAddrArg, SocketAddrLen, SocketAddrOpaque};
use rustix::net::{
    AddressFamily, SocketFlags, SocketType, acceptfrom_with, bind, listen, socket_with,
};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{OwnedFd, RawFd};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use terra_protocol::{
    AGENT_HELLO, AgentService, ClientInput, ControlReply, ControlRequest, TermSize, encode_frame,
    read_frame,
};

/// Well-known vsock CID of the host from inside the guest.
pub const VMADDR_CID_HOST: u32 = 2;

const ACCEPT_RETRY: Duration = Duration::from_millis(100);
const REFUSED_CONNECTION_LOG_INTERVAL: Duration = Duration::from_secs(1);
const STARTUP_WAIT: Duration = Duration::from_mins(5);

pub(crate) struct StartupGate {
    state: Mutex<StartupState>,
    changed: Condvar,
}

enum StartupState {
    Pending,
    Ready,
    Failed,
}

impl StartupGate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(StartupState::Pending),
            changed: Condvar::new(),
        })
    }

    pub(crate) fn ready(&self) {
        if let Ok(mut state) = self.state.lock() {
            *state = StartupState::Ready;
            self.changed.notify_all();
        }
    }

    pub(crate) fn fail(&self) {
        if let Ok(mut state) = self.state.lock() {
            *state = StartupState::Failed;
            self.changed.notify_all();
        }
    }

    fn wait(&self) -> bool {
        let Ok(state) = self.state.lock() else {
            return false;
        };
        let Ok((state, _)) = self
            .changed
            .wait_timeout_while(state, STARTUP_WAIT, |state| {
                matches!(state, StartupState::Pending)
            })
        else {
            return false;
        };
        matches!(*state, StartupState::Ready)
    }
}

#[repr(C)]
struct SockaddrVm {
    svm_family: rustix::net::RawAddressFamily,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

pub struct VsockListener {
    fd: OwnedFd,
    last_refusal: Mutex<Option<Instant>>,
}

fn create_vsock_socket(cid: u32, port: u32) -> std::io::Result<(OwnedFd, SockaddrVm)> {
    let fd = socket_with(
        AddressFamily::VSOCK,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
    Ok((
        fd,
        SockaddrVm {
            svm_family: AddressFamily::VSOCK.as_raw(),
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: cid,
            svm_zero: [0; 4],
        },
    ))
}

// SAFETY: `f` gets a pointer to this exact `SockaddrVm`, readable for its
// full size for the call's duration - a valid `sockaddr_vm` of that length.
#[allow(unsafe_code)]
unsafe impl SocketAddrArg for SockaddrVm {
    unsafe fn with_sockaddr<R>(
        &self,
        f: impl FnOnce(*const SocketAddrOpaque, SocketAddrLen) -> R,
    ) -> R {
        f(
            std::ptr::from_ref(self).cast(),
            std::mem::size_of::<Self>() as SocketAddrLen,
        )
    }
}

impl VsockListener {
    pub fn bind(port: u32) -> std::io::Result<Self> {
        let (fd, addr) = create_vsock_socket(u32::MAX /* any */, port)?;
        bind(&fd, &addr)?;
        listen(&fd, 8)?;
        Ok(Self {
            fd,
            last_refusal: Mutex::new(None),
        })
    }

    /// Accepts the next connection from the host, refusing other peers.
    /// Guest kernel supports vsock loopback; local connections must be rejected.
    #[allow(unsafe_code)]
    fn accept_host(&self) -> std::io::Result<File> {
        loop {
            let (fd, peer) = acceptfrom_with(&self.fd, SocketFlags::CLOEXEC)?;
            let file = File::from(fd);
            let cid = peer
                .filter(|peer| {
                    peer.address_family() == AddressFamily::VSOCK
                        && peer.addr_len() as usize >= std::mem::size_of::<SockaddrVm>()
                })
                .map_or(u32::MAX, |peer| {
                    // SAFETY: the family and length identify a complete sockaddr_vm
                    // returned by the kernel.
                    unsafe { std::ptr::read_unaligned(peer.as_ptr().cast::<SockaddrVm>()) }.svm_cid
                });
            if cid == VMADDR_CID_HOST {
                return Ok(file);
            }
            drop(file);
            let now = Instant::now();
            let mut last_refusal = crate::mutex::lock_or_abort(&self.last_refusal);
            if last_refusal
                .is_none_or(|last| now.duration_since(last) >= REFUSED_CONNECTION_LOG_INTERVAL)
            {
                eprintln!(
                    "terra-agent: refused vsock connection from inside the guest (cid {cid})"
                );
                *last_refusal = Some(now);
            }
        }
    }
}

pub fn connect(cid: u32, port: u32) -> std::io::Result<File> {
    let (fd, addr) = create_vsock_socket(cid, port)?;
    rustix::net::connect(&fd, &addr)?;
    Ok(File::from(fd))
}

/// Spawns a background thread serving the agent port until the workload exits.
pub(crate) fn serve_agent_port(
    session: &Arc<Session>,
    listener: VsockListener,
    master_fd: RawFd,
    workload_is_root: bool,
    initial_session: Option<std::sync::mpsc::SyncSender<()>>,
    startup: Arc<StartupGate>,
) {
    let session = session.clone();
    std::thread::spawn(move || {
        loop {
            let conn = match listener.accept_host() {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("terra-agent: accept failed: {e}");
                    std::thread::sleep(ACCEPT_RETRY);
                    continue;
                }
            };
            let initial_session = initial_session.clone();
            let session = session.clone();
            let startup = startup.clone();
            std::thread::spawn(move || {
                // Hello must be the first byte on the connection before any service output.
                let mut conn = conn;
                if conn
                    .write_all(&AGENT_HELLO)
                    .and_then(|()| conn.flush())
                    .is_err()
                {
                    return;
                }
                let mut service_byte = [0u8; 1];
                if rustix::net::sockopt::set_socket_timeout(
                    &conn,
                    rustix::net::sockopt::Timeout::Recv,
                    Some(Duration::from_secs(5)),
                )
                .is_err()
                {
                    return;
                }
                if conn.read_exact(&mut service_byte).is_err() {
                    return;
                }
                if rustix::net::sockopt::set_socket_timeout(
                    &conn,
                    rustix::net::sockopt::Timeout::Recv,
                    None,
                )
                .is_err()
                {
                    return;
                }
                match AgentService::from_byte(service_byte[0]) {
                    Some(AgentService::Session) => {
                        serve_client(&session, conn, master_fd, initial_session.as_ref());
                    }
                    Some(AgentService::SessionControl) => {
                        serve_session_control(&session, conn, master_fd);
                    }
                    Some(AgentService::Files) if startup.wait() => {
                        if crate::vsock::set_socket_timeouts(&conn, Duration::from_secs(30))
                            .is_err()
                        {
                            return;
                        }
                        crate::files::serve_sync_session(conn, workload_is_root);
                    }
                    Some(AgentService::Exec) if startup.wait() => {
                        crate::exec::serve_exec(conn, workload_is_root);
                    }
                    Some(AgentService::Files | AgentService::Exec) => {}
                    None => eprintln!(
                        "terra-agent: unknown service byte {:#04x} - dropping the connection",
                        service_byte[0]
                    ),
                }
            });
        }
    });
}

/// Attach one `terra` client to the session and forward its framed input -
/// keystrokes and resizes - until its connection ends.
fn serve_client(
    session: &Arc<Session>,
    conn: File,
    master_fd: RawFd,
    initial_session: Option<&std::sync::mpsc::SyncSender<()>>,
) {
    let Ok(mut reader) = conn.try_clone() else {
        return;
    };
    let Ok(client) = ClientConn::from_vsock(conn) else {
        return;
    };
    let Some(id) = session.attach_client(&client) else {
        return;
    };
    if let Some(initial_session) = initial_session {
        let _ = initial_session.try_send(());
    }

    loop {
        match read_frame::<ClientInput>(&mut reader) {
            Ok(Some(ClientInput::Keys(bytes))) => {
                if session.send_input(&bytes).is_err() {
                    break;
                }
            }
            Ok(Some(ClientInput::Eof)) => {}
            Ok(Some(ClientInput::Resize(TermSize { rows, cols }))) => {
                // vt100 panics on 0x0 size; ignore empty sizes.
                if rows > 0
                    && cols > 0
                    && let Some((rows, cols)) = session.set_client_size(id, rows, cols)
                {
                    set_session_winsize(master_fd, rows, cols);
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
    if let DetachOutcome::Detached {
        size: Some((rows, cols)),
    } = session.detach_client(id)
    {
        set_session_winsize(master_fd, rows, cols);
    }
}

fn serve_session_control(session: &Arc<Session>, mut conn: File, master_fd: RawFd) {
    if set_socket_timeouts(&conn, Duration::from_secs(30)).is_err() {
        return;
    }
    let send_reply = |conn: &mut File, reply: &ControlReply| {
        let bytes = encode_frame(reply)?;
        conn.write_all(&bytes).and_then(|()| conn.flush())
    };
    match read_frame::<ControlRequest>(&mut conn) {
        Ok(Some(ControlRequest::List)) => {
            for (id, size) in session.list_clients() {
                let size = size.map(|(rows, cols)| TermSize { rows, cols });
                if send_reply(&mut conn, &ControlReply::Client { id, size }).is_err() {
                    return;
                }
            }
            let _ = send_reply(&mut conn, &ControlReply::Done);
        }
        Ok(Some(ControlRequest::Detach { id })) => match session.detach_client(id) {
            DetachOutcome::Detached { size } => {
                if let Some((rows, cols)) = size {
                    set_session_winsize(master_fd, rows, cols);
                }
                let _ = send_reply(&mut conn, &ControlReply::Detached { id });
            }
            DetachOutcome::Missing => {
                let _ = send_reply(&mut conn, &ControlReply::Missing { id });
            }
        },
        Ok(Some(ControlRequest::DetachAll)) => {
            let (ids, size) = session.detach_all_clients();
            if let Some((rows, cols)) = size {
                set_session_winsize(master_fd, rows, cols);
            }
            for id in ids {
                if send_reply(&mut conn, &ControlReply::Detached { id }).is_err() {
                    return;
                }
            }
            let _ = send_reply(&mut conn, &ControlReply::Done);
        }
        Ok(None) | Err(_) => {}
    }
}

#[allow(unsafe_code)]
fn set_session_winsize(master_fd: RawFd, rows: u16, cols: u16) {
    // SAFETY: `master_fd` is the live PTY master owned by the session input sink.
    set_winsize(
        unsafe { std::os::fd::BorrowedFd::borrow_raw(master_fd) },
        rows,
        cols,
    );
}

pub(crate) fn set_socket_timeouts(
    conn: &impl std::os::fd::AsFd,
    duration: Duration,
) -> std::io::Result<()> {
    for timeout in [
        rustix::net::sockopt::Timeout::Recv,
        rustix::net::sockopt::Timeout::Send,
    ] {
        rustix::net::sockopt::set_socket_timeout(conn, timeout, Some(duration))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    fn create_session_with_clients(n: usize) -> Arc<Session> {
        let input: crate::term::session::Sink = Arc::new(std::sync::Mutex::new(std::io::sink()));
        let session = Session::new(input);
        for _ in 0..n {
            let (client, server) = UnixStream::pair().unwrap();
            let _ = client;
            let client =
                ClientConn::from_vsock(File::from(std::os::fd::OwnedFd::from(server))).unwrap();
            let _ = session.attach_client(&client);
        }
        session
    }

    #[test]
    fn requests_wait_for_startup_or_fail_with_it() {
        let startup = StartupGate::new();
        let waiting = {
            let startup = startup.clone();
            std::thread::spawn(move || startup.wait())
        };
        std::thread::sleep(Duration::from_millis(20));
        startup.ready();
        assert!(waiting.join().unwrap());

        let startup = StartupGate::new();
        startup.fail();
        assert!(!startup.wait());
    }

    fn run_control_request(session: &Arc<Session>, req: &ControlRequest) -> Vec<ControlReply> {
        let null = std::fs::File::open("/dev/null").unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let server = File::from(std::os::fd::OwnedFd::from(server));
        let session = session.clone();
        let agent =
            std::thread::spawn(move || serve_session_control(&session, server, null.as_raw_fd()));
        client
            .write_all(&terra_protocol::encode_frame(req).unwrap())
            .unwrap();
        let mut reps = Vec::new();
        while let Some(rep) = read_frame::<ControlReply>(&mut client).unwrap() {
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
        let session = create_session_with_clients(2);
        session.set_client_size(0, 30, 100);
        assert_eq!(
            run_control_request(&session, &ControlRequest::List),
            vec![
                ControlReply::Client {
                    id: 0,
                    size: Some(TermSize {
                        rows: 30,
                        cols: 100
                    })
                },
                ControlReply::Client { id: 1, size: None },
                ControlReply::Done,
            ]
        );
        assert_eq!(session.list_clients().len(), 2);
    }

    /// The answer to a detach is about the client's existence, not its size:
    /// dropping a client that did not constrain the shared size must still read
    /// as detached, or `terra detach` would call a successful cleanup "missing".
    #[test]
    fn the_control_service_detaches_one_client() {
        let session = create_session_with_clients(2);
        session.set_client_size(0, 30, 100);
        session.set_client_size(1, 50, 200);

        assert_eq!(
            run_control_request(&session, &ControlRequest::Detach { id: 1 }),
            vec![ControlReply::Detached { id: 1 }]
        );
        assert_eq!(session.list_clients(), vec![(0, Some((30, 100)))]);
    }

    #[test]
    fn detaching_an_unknown_id_answers_missing() {
        let session = create_session_with_clients(1);
        assert_eq!(
            run_control_request(&session, &ControlRequest::Detach { id: 7 }),
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
        let session = create_session_with_clients(3);
        assert_eq!(
            run_control_request(&session, &ControlRequest::DetachAll),
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
