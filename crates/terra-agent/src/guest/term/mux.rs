//! PTY spawn, vsock transport, accept loop, and graceful-stop watcher.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::similar_names,
    clippy::struct_field_names
)]

use crate::term::session::{ClientSink, ConsoleSink, DEFAULT_COLS, DEFAULT_ROWS, Session, Sink};
use crate::term::tty::{set_raw, set_winsize, winsize};
use crate::vsock::{VsockListener, VsockStream};
use anyhow::{Result, bail};
use pty_process::blocking::{Command, Pty};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use terra_agent::{
    AGENT_HELLO, AgentOutput, AgentService, ClientInput, STOP_SIGNAL, WORKLOAD_GID, WORKLOAD_UID,
};

/// Grace period before SIGKILL after SIGTERM; shorter than Docker's 10s
/// because a sandbox is shorter-lived.
const STOP_GRACE: Duration = Duration::from_secs(5);

/// Backoff after a failed `accept` (see [`accept_failed`]).
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

const CONSOLE_REATTACH_POLL: Duration = Duration::from_millis(500);

/// How long the workload's last output is given to cross the PTY after the
/// process itself has gone - see the drain in [`run_workload`]. Bounded because
/// EOF may never come: a backgrounded grandchild can hold the slave open for as
/// long as it likes, and the box still has to stop.
const OUTPUT_DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Spawn `cmd` on a fresh PTY of the given size. The slave end is dropped on
/// return, so the master EOFs when the command exits.
pub(crate) fn spawn_on_pty(
    cmd: &str,
    args: &[String],
    rows: u16,
    cols: u16,
    as_root: bool,
    home: Option<&str>,
) -> Result<(Pty, std::process::Child)> {
    let (pty, pts) = pty_process::blocking::open()?;
    pty.resize(pty_process::Size::new(rows.max(1), cols.max(1)))?;
    let mut command = Command::new(cmd).args(args);
    if let Some(home) = home {
        command = command.env("HOME", home);
    }
    // init stays root for cleanup.
    if !as_root {
        // SAFETY: a post-fork/pre-exec hook that only calls async-signal-safe
        // id-setting syscalls.
        command = unsafe { command.pre_exec(drop_privileges) };
    }
    let child = crate::reap::spawn_owned(|| command.spawn(pts))?;
    Ok((pty, child))
}

/// Spawn `argv` on a PTY and multiplex it until it exits, handing back the
/// status it ended with and the session its clients are attached to. Watches
/// the control connection for [`STOP_SIGNAL`] to stop gracefully.
///
/// The session outlives this call: the status is owed to every attached client
/// too, so the caller runs [`Session::broadcast_exit`] once the box is really
/// done.
pub fn run_workload(
    argv: &[String],
    control: VsockStream,
    root: bool,
    port: VsockListener,
    on_console: bool,
) -> Result<(i32, Arc<Session>)> {
    let Some((cmd, args)) = argv.split_first() else {
        bail!("empty workload argv");
    };
    let (pty, mut child) = spawn_on_pty(cmd, args, DEFAULT_ROWS, DEFAULT_COLS, root, None)?;
    let child_pid = child.id();

    // Split PTY master into separate read/write fds to avoid contention.
    let master: OwnedFd = pty.into();
    let reader = master.try_clone()?;
    let input_file = std::fs::File::from(master);
    // A raw fd for TIOCSWINSZ; valid while `input_file` (held by the session)
    // lives. Any fd on the pty master works for the ioctl.
    let master_fd = input_file.as_raw_fd();
    let input: Sink = Arc::new(Mutex::new(input_file));

    // The console is attached *before* the pump below: a one-shot printing
    // more than a screenful into an empty session would have the overflow
    // replaced by the repaint [`Session::attach`] sends.
    let session = Session::new(input);
    if on_console {
        attach_console(&session, master_fd);
    }

    // Never joined - a join can hang (see [`OUTPUT_DRAIN_GRACE`]). `drained`
    // is the bounded stand-in: the sender lives in the pump thread, so the
    // channel disconnects the moment the pump ends.
    let (drained_tx, drained) = std::sync::mpsc::channel::<()>();
    let out_session = session.clone();
    std::thread::spawn(move || {
        let _drained_tx = drained_tx;
        let mut reader = std::fs::File::from(reader);
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => out_session.feed_output(&buf[..n]),
            }
        }
    });

    serve_agent_port(&session, port, master_fd, root);

    // Interactive shells ignore SIGTERM, so the watcher escalates to SIGKILL
    // after the grace period. Signals go through a pidfd, which the kernel
    // pins to *this* child: once the workload is reaped its pid is the
    // kernel's to hand out again, and a `pre_stop` hook starts moments later -
    // a signal by pid could land on whatever now holds the number. The flag
    // only keeps the messages honest.
    let exited = Arc::new(std::sync::atomic::AtomicBool::new(false));
    match pidfd_open(child_pid) {
        Ok(pidfd) => {
            let exited = exited.clone();
            let mut control = control;
            std::thread::spawn(move || {
                let mut byte = [0u8; 1];
                loop {
                    match control.read(&mut byte) {
                        Ok(0) => break, // host disconnected: the VM is orphaned, stop
                        Ok(_) if byte[0] == STOP_SIGNAL => break,
                        Ok(_) => {} // a stray byte is not a stop
                        // EINTR is a retry, not a disconnect: treating any read
                        // error as a stop used to SIGTERM the workload on it.
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(e) => {
                            eprintln!(
                                "terra-agent: the control connection failed ({e}) - stopping"
                            );
                            break;
                        }
                    }
                }
                pidfd_signal(&pidfd, libc::SIGTERM);
                std::thread::sleep(STOP_GRACE);
                if !exited.load(std::sync::atomic::Ordering::SeqCst) {
                    eprintln!(
                        "terra-agent: workload ignored SIGTERM after {}s - killing it",
                        STOP_GRACE.as_secs()
                    );
                    pidfd_signal(&pidfd, libc::SIGKILL);
                }
            });
        }
        // The pinned guest kernel has pidfds; without one the box still runs,
        // it just cannot be stopped gracefully (the host kills it after its
        // `--wait`).
        Err(e) => eprintln!(
            "terra-agent: warning: no pidfd for the workload ({e}) - a graceful stop cannot reach it"
        ),
    }

    // PID 1's own exit tells the host nothing - libkrun reports every clean
    // shutdown the same way - so the status is carried out deliberately, over
    // the control connection (see [`terra_agent::send_exit_status`]).
    let code = crate::exec::exit_code(&mut child);
    exited.store(true, std::sync::atomic::Ordering::SeqCst);

    // The workload's last bytes are commonly still in the PTY when it is
    // reaped, and the pump that carries them into the session runs on a thread
    // of its own. [`Session::broadcast_exit`] takes every client away moments
    // after this returns, so without this wait a one-shot fast enough to finish
    // before its own output was pumped (`echo x; exit 7`) left `terra logs`
    // with a boot banner and no output at all.
    let _ = drained.recv_timeout(OUTPUT_DRAIN_GRACE);
    Ok((code, session))
}

/// A pidfd for the workload - the handle the stop watcher signals through.
fn pidfd_open(pid: u32) -> std::io::Result<OwnedFd> {
    let pid = libc::pid_t::try_from(pid).map_err(std::io::Error::other)?;
    // SAFETY: `pidfd_open` takes a pid and flags, and returns a new fd or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    let fd = libc::c_int::try_from(fd).map_err(std::io::Error::other)?;
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a fresh fd owned by nothing else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Signal through a pidfd.
fn pidfd_signal(pidfd: &OwnedFd, sig: libc::c_int) {
    // SAFETY: a live fd, a null siginfo (same as `kill`), and no flags.
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        );
    }
}

/// Answer the agent port for as long as the workload runs.
///
/// The port was claimed before any guest code ran (see [`crate::init::execute`]);
/// this is only the accept loop. Every connection opens with [`say_hello`] and
/// one [`AgentService`] byte from the client selects what the connection is for.
fn serve_agent_port(session: &Arc<Session>, listener: VsockListener, master_fd: RawFd, root: bool) {
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
    use std::io::Write;
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

/// Drop to the workload user post-fork. Order matters: gid before uid, or we
/// lose the privilege to set the uid.
pub fn drop_privileges() -> std::io::Result<()> {
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setgid(WORKLOAD_GID) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setuid(WORKLOAD_UID) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
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
    use std::io::Write;
    let reply = |conn: &mut VsockStream, rep: &terra_agent::ControlReply| {
        conn.write_all(&rep.encode()).and_then(|()| conn.flush())
    };
    match terra_agent::ControlRequest::read(&mut conn) {
        Ok(Some(terra_agent::ControlRequest::List)) => {
            for (id, size) in session.list_clients() {
                let (rows, cols) = size.unwrap_or((0, 0));
                if reply(
                    &mut conn,
                    &terra_agent::ControlReply::Client { id, rows, cols },
                )
                .is_err()
                {
                    return;
                }
            }
            let _ = reply(&mut conn, &terra_agent::ControlReply::Done);
        }
        Ok(Some(terra_agent::ControlRequest::Detach { id })) => {
            if session.list_clients().iter().any(|(cid, _)| *cid == id) {
                if let Some((r, c)) = session.detach_client(id) {
                    set_winsize(master_fd, r, c);
                }
                let _ = reply(&mut conn, &terra_agent::ControlReply::Detached { id });
            } else {
                let _ = reply(&mut conn, &terra_agent::ControlReply::Missing { id });
            }
        }
        Ok(Some(terra_agent::ControlRequest::DetachAll)) => {
            let ids: Vec<u64> = session
                .list_clients()
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            if let Some((r, c)) = session.detach_all_clients() {
                set_winsize(master_fd, r, c);
            }
            for id in ids {
                if reply(&mut conn, &terra_agent::ControlReply::Detached { id }).is_err() {
                    return;
                }
            }
            let _ = reply(&mut conn, &terra_agent::ControlReply::Done);
        }
        Ok(None) | Err(_) => {}
    }
}

/// Attach fd 0/1 as a client: broadcast output to stdout, forward stdin keys.
fn attach_console(session: &Arc<Session>, master_fd: RawFd) {
    set_raw(0);
    let id = session.attach(ConsoleSink(std::io::stdout()));
    // hvc0 on an interactive host reports a real size; a headless console
    // reports none.
    if let Some((rows, cols)) = winsize(0)
        && let Some((r, c)) = session.set_client_size(id, rows, cols)
    {
        set_winsize(master_fd, r, c);
    }

    // Watch for a console dropped for a full outbox and re-attach it.
    let watcher = session.clone();
    std::thread::spawn(move || {
        let mut id = id;
        loop {
            std::thread::sleep(CONSOLE_REATTACH_POLL);
            if !watcher.list_clients().iter().any(|(live, _)| *live == id) {
                id = watcher.attach(ConsoleSink(std::io::stdout()));
                if let Some((rows, cols)) = winsize(0)
                    && let Some((r, c)) = watcher.set_client_size(id, rows, cols)
                {
                    set_winsize(master_fd, r, c);
                }
            }
        }
    });

    let session = session.clone();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 8192];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if session.send_input(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

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
        let input: Sink = Arc::new(Mutex::new(std::io::sink()));
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
    fn do_control(
        session: &Arc<Session>,
        req: &terra_agent::ControlRequest,
    ) -> Vec<terra_agent::ControlReply> {
        let null = std::fs::File::open("/dev/null").unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let server = VsockStream::from(std::os::fd::OwnedFd::from(server));
        let session = session.clone();
        let agent =
            std::thread::spawn(move || serve_session_control(&session, server, null.as_raw_fd()));
        client.write_all(&req.encode()).unwrap();
        let mut reps = Vec::new();
        while let Some(rep) = terra_agent::ControlReply::read(&mut client).unwrap() {
            let done = matches!(rep, terra_agent::ControlReply::Done);
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
            do_control(&session, &terra_agent::ControlRequest::List),
            vec![
                terra_agent::ControlReply::Client {
                    id: 0,
                    rows: 30,
                    cols: 100
                },
                terra_agent::ControlReply::Client {
                    id: 1,
                    rows: 0,
                    cols: 0
                },
                terra_agent::ControlReply::Done,
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
            do_control(&session, &terra_agent::ControlRequest::Detach { id: 1 }),
            vec![terra_agent::ControlReply::Detached { id: 1 }]
        );
        assert_eq!(session.list_clients(), vec![(0, Some((30, 100)))]);
    }

    #[test]
    fn detaching_an_unknown_id_answers_missing() {
        let session = session_with(1);
        assert_eq!(
            do_control(&session, &terra_agent::ControlRequest::Detach { id: 7 }),
            vec![terra_agent::ControlReply::Missing { id: 7 }]
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
            do_control(&session, &terra_agent::ControlRequest::DetachAll),
            vec![
                terra_agent::ControlReply::Detached { id: 0 },
                terra_agent::ControlReply::Detached { id: 1 },
                terra_agent::ControlReply::Detached { id: 2 },
                terra_agent::ControlReply::Done,
            ]
        );
        assert_eq!(session.list_clients(), vec![]);
    }
}
