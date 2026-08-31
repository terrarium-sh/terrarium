//! The host end of the agent's ports: how terra reaches one, and how it pumps
//! bytes between that port and the user's terminal.

use crate::state::{BoxRef, Holder};
use crate::sys::POLL;
use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use terra_shared::contract::{self, AgentOutput, AgentService, ClientInput, TermSize};

const AGENT_HELLO_WAIT_TIMEOUT: Duration = Duration::from_millis(500);
const CONTROL_REPLY_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_SESSION_CLIENTS: usize = 1024;
const SILENT_BOOT_GRACE: Duration = Duration::from_secs(15);

pub fn read_terminal_size() -> Option<TermSize> {
    let (cols, rows) = crossterm::terminal::size().ok()?;
    (rows > 0 && cols > 0).then_some(TermSize { rows, cols })
}

pub const DEFAULT_TERMINAL_SIZE: TermSize = TermSize { rows: 24, cols: 80 };

/// A control byte, not a bare letter the workload wants.
/// NOTE: Not ESC - every arrow key sends that
pub const DETACH_KEY: u8 = 0x1C;

const SHELL_SIGPIPE_STATUS: i32 = 128 + rustix::process::Signal::PIPE.as_raw();

pub const DETACH_KEY_NAME: &str = "Ctrl-\\";

#[derive(Debug, PartialEq, Eq)]
pub enum SessionOutcome {
    Detached,
    Exited(i32),
    Closed,
}

/// Connect to the agent and select `service`, returning the stream once the
/// agent's hello has been consumed and the service byte written. Retried until
/// then: libkrun binds the socket before guest PID 1 runs, and a stale socket
/// outlives the stopped VM.
pub fn connect_to_agent(
    bx: &BoxRef,
    service: AgentService,
    what: &str,
    mut still_waiting: impl FnMut() -> Result<()>,
) -> Result<UnixStream> {
    let sock = bx.get_dir().join(crate::state::AGENT_SOCKET);
    let mut hint_at = Some(Instant::now() + SILENT_BOOT_GRACE);
    loop {
        if hint_at.is_some_and(|at| Instant::now() > at) {
            hint_at = None;
            eprintln!(
                "terra: still waiting for {bx}'s {what} - `{}` shows the boot so far",
                bx.build_logs_command()
            );
        }
        still_waiting()?;
        if let Ok(stream) = UnixStream::connect(&sock) {
            if stream
                .set_read_timeout(Some(AGENT_HELLO_WAIT_TIMEOUT))
                .is_err()
            {
                continue;
            }
            let mut magic = [0];
            if (&stream).read_exact(&mut magic).is_ok() {
                anyhow::ensure!(
                    magic[0] == contract::AGENT_HELLO[0],
                    "the agent in {bx} does not speak this terra's protocol - \
                     `terra stop` it and start it again on this build"
                );
                let mut version = [0];
                if (&stream).read_exact(&mut version).is_err() {
                    continue;
                }
                anyhow::ensure!(
                    version[0] == contract::AGENT_PROTOCOL_VERSION,
                    "the agent in {bx} does not speak this terra's protocol - \
                     `terra stop` it and start it again on this build"
                );
                if stream.set_read_timeout(None).is_err() {
                    continue;
                }
                if (&stream).write_all(&[service.to_byte()]).is_ok() {
                    return Ok(stream);
                }
            }
        }
        std::thread::sleep(POLL);
    }
}

pub fn connect_to_running_agent(
    bx: &BoxRef,
    verb: &str,
    service: AgentService,
    what: &str,
    timeout: Option<u64>,
) -> Result<UnixStream> {
    ensure_running(bx, verb)?;
    connect_to_agent(bx, service, what, wait_while_running(bx, timeout))
}

pub fn still_serving(bx: &BoxRef, stopped: &str) -> Result<()> {
    match bx.get_holder() {
        Holder::Running => Ok(()),
        Holder::SettingUp => Err(bx.setup_holds_it()),
        Holder::Free => Err(anyhow::anyhow!("{bx} {stopped}")),
    }
}

fn ensure_running(bx: &BoxRef, verb: &str) -> Result<()> {
    still_serving(
        bx,
        &format!(
            "is not running - `terra {verb}` talks to the live agent \
             (`terra {} -d` first)",
            bx.get_name()
        ),
    )
}

fn wait_while_running(bx: &BoxRef, timeout: Option<u64>) -> impl FnMut() -> Result<()> {
    let deadline =
        timeout.map(|secs| (crate::sys::deadline_after(Duration::from_secs(secs)), secs));
    move || {
        still_serving(bx, "stopped before its agent answered")?;
        if let Some((deadline, secs)) = deadline {
            anyhow::ensure!(
                Instant::now() < deadline,
                "{bx}'s agent did not answer within the --agent-timeout of {secs}s \
                 (still booting, or baking `on_create`?)"
            );
        }
        Ok(())
    }
}

/// One attached client of a box's session, as `terra <box> sessions` shows it.
#[derive(Debug, PartialEq, Eq)]
pub struct SessionClient {
    pub id: u64,
    pub reported_term_size: Option<TermSize>,
}

fn request_control(
    bx: &BoxRef,
    verb: &str,
    req: &contract::ControlRequest,
    agent_timeout: Option<u64>,
    ctx: &'static str,
) -> Result<UnixStream> {
    let stream = connect_to_running_agent(
        bx,
        verb,
        contract::AgentService::SessionControl,
        "session control service",
        agent_timeout,
    )?;
    stream
        .set_read_timeout(Some(CONTROL_REPLY_TIMEOUT))
        .context("setting the session control read timeout")?;
    let bytes = contract::encode_frame(req).context(ctx)?;
    (&stream).write_all(&bytes).context(ctx)?;
    Ok(stream)
}

pub fn list_clients(bx: &BoxRef, agent_timeout: Option<u64>) -> Result<Vec<SessionClient>> {
    let mut stream = request_control(
        bx,
        "sessions",
        &contract::ControlRequest::List,
        agent_timeout,
        "asking for the session's clients",
    )?;
    let mut clients = Vec::new();
    loop {
        match contract::read_frame::<contract::ControlReply>(&mut stream) {
            Ok(Some(contract::ControlReply::Client { id, size })) => {
                if clients.len() == MAX_SESSION_CLIENTS {
                    anyhow::bail!("the agent sent more than {MAX_SESSION_CLIENTS} session clients");
                }
                clients.push(SessionClient {
                    id,
                    reported_term_size: size,
                });
            }
            Ok(Some(contract::ControlReply::Done)) => return Ok(clients),
            Ok(Some(
                contract::ControlReply::Detached { .. } | contract::ControlReply::Missing { .. },
            )) => anyhow::bail!("the agent answered a listing with a detach reply"),
            Ok(None) => anyhow::bail!("{bx} stopped before its agent listed the session"),
            Err(e) => return Err(e).context("reading the session listing"),
        }
    }
}

pub fn detach_client(bx: &BoxRef, client_id: u64, agent_timeout: Option<u64>) -> Result<()> {
    let mut stream = request_control(
        bx,
        "detach",
        &contract::ControlRequest::Detach { id: client_id },
        agent_timeout,
        "asking to detach a client",
    )?;
    match contract::read_frame::<contract::ControlReply>(&mut stream) {
        Ok(Some(contract::ControlReply::Detached { .. })) => Ok(()),
        Ok(Some(contract::ControlReply::Missing { .. })) => {
            anyhow::bail!("no client {client_id} is attached to {bx}")
        }
        Ok(Some(contract::ControlReply::Client { .. } | contract::ControlReply::Done)) => {
            anyhow::bail!("the agent answered a detach with a listing reply")
        }
        Ok(None) => anyhow::bail!("{bx} stopped before its agent answered the detach"),
        Err(e) => Err(e).context("reading the detach reply"),
    }
}

pub fn detach_all(bx: &BoxRef, agent_timeout: Option<u64>) -> Result<u64> {
    let mut stream = request_control(
        bx,
        "detach",
        &contract::ControlRequest::DetachAll,
        agent_timeout,
        "asking to detach every client",
    )?;
    let mut detached = 0;
    loop {
        match contract::read_frame::<contract::ControlReply>(&mut stream) {
            Ok(Some(contract::ControlReply::Detached { .. })) => {
                if detached == MAX_SESSION_CLIENTS as u64 {
                    anyhow::bail!("the agent sent more than {MAX_SESSION_CLIENTS} detach replies");
                }
                detached += 1;
            }
            Ok(Some(contract::ControlReply::Done)) => return Ok(detached),
            Ok(Some(
                contract::ControlReply::Client { .. } | contract::ControlReply::Missing { .. },
            )) => anyhow::bail!("the agent answered a detach with a listing reply"),
            Ok(None) => anyhow::bail!("{bx} stopped before its agent answered the detach"),
            Err(e) => return Err(e).context("reading the detach replies"),
        }
    }
}

#[derive(Clone, Copy)]
enum StdinEndAction {
    CloseSocket,
    /// An EOF frame rather than a close: closing would take the read half,
    /// and with it the output and exit status still to come. What EOF means
    /// is the agent's call - it knows whether the command got a PTY.
    SendEof,
}

fn send_frame(writer: &Mutex<UnixStream>, msg: &ClientInput) -> bool {
    // A poisoned lock means a panic mid-write, which may have left a
    // half-written frame - appending more would corrupt the stream.
    let Ok(mut w) = writer.lock() else {
        return false;
    };
    let Ok(bytes) = contract::encode_frame(msg) else {
        return false;
    };
    w.write_all(&bytes).and_then(|()| w.flush()).is_ok()
}

/// Send the current terminal size when it differs from `last`; `false` means
/// the writer is gone.
fn report_size(writer: &Mutex<UnixStream>, last: &mut Option<TermSize>) -> bool {
    let Some(s) = read_terminal_size() else {
        return true;
    };
    if *last == Some(s) {
        return true;
    }
    *last = Some(s);
    send_frame(writer, &ClientInput::Resize(s))
}

/// A resize is noticed by polling the size on a timer - one `POLL` late, the
/// price of not owning the console input a crossterm event reader would
/// compete with the stdin thread for.
fn spawn_resize_reporter(
    writer: Arc<Mutex<UnixStream>>,
    completed: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut last = None;
        while !completed.load(Ordering::SeqCst) {
            if !report_size(&writer, &mut last) {
                break;
            }
            std::thread::sleep(POLL);
        }
    })
}

fn spawn_stdin_reader(
    writer: Arc<Mutex<UnixStream>>,
    escape: Option<u8>,
    action: StdinEndAction,
    completed: Arc<AtomicBool>,
) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let detached = Arc::new(AtomicBool::new(false));
    let detached_flag = detached.clone();
    let thread = std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        while !completed.load(Ordering::SeqCst) {
            if !input_is_ready(&stdin) {
                continue;
            }
            let Ok(n @ 1..) = stdin.read(&mut buf) else {
                break;
            };
            let escape_at = escape.and_then(|e| buf[..n].iter().position(|b| *b == e));
            let keys = &buf[..escape_at.unwrap_or(n)];
            if !keys.is_empty() && !send_frame(&writer, &ClientInput::Keys(keys.to_vec())) {
                break;
            }
            if escape_at.is_some() {
                detached_flag.store(true, Ordering::SeqCst);
                break;
            }
        }
        match action {
            StdinEndAction::CloseSocket => {
                // Shut down even on a poisoned lock: closing is the safe
                // direction, and skipping it would block the session's reader
                // forever.
                let _ = writer
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .shutdown(Shutdown::Both);
            }
            StdinEndAction::SendEof => {
                send_frame(&writer, &ClientInput::Eof);
            }
        }
    });
    (detached, thread)
}

#[allow(unsafe_code)]
fn input_is_ready(fd: impl AsFd) -> bool {
    use rustix::event::{FdSetElement, Timespec, fd_set_bound, fd_set_insert, fd_set_num_elements};

    let fd = fd.as_fd().as_raw_fd();
    let mut read_fds = vec![FdSetElement::default(); fd_set_num_elements(1, fd + 1)];
    fd_set_insert(&mut read_fds, fd);
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: POLL.subsec_nanos().into(),
    };
    // SAFETY: stdin remains open while `select` waits on its descriptor.
    unsafe {
        rustix::event::select(
            fd_set_bound(&read_fds),
            Some(&mut read_fds),
            None,
            None,
            Some(&timeout),
        )
    }
    .is_ok_and(|ready| ready > 0)
}

struct InputThreads {
    detached: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
    stdin: Option<std::thread::JoinHandle<()>>,
    resize: Option<std::thread::JoinHandle<()>>,
}

impl InputThreads {
    fn stop(self, stream: &UnixStream) {
        self.completed.store(true, Ordering::SeqCst);
        let _ = stream.shutdown(Shutdown::Both);
        if let Some(stdin) = self.stdin {
            let _ = stdin.join();
        }
        if let Some(resize) = self.resize {
            let _ = resize.join();
        }
    }
}

/// The stdin and resize threads of one session, sharing the write half behind
/// a mutex so their frames cannot interleave. The returned flag is set when
/// the detach byte ended input.
fn spawn_input_threads(
    stream: &UnixStream,
    escape: Option<u8>,
    action: StdinEndAction,
    report_resizes: bool,
) -> Result<InputThreads> {
    let writer = Arc::new(Mutex::new(
        stream.try_clone().context("cloning attach socket")?,
    ));
    let completed = Arc::new(AtomicBool::new(false));
    // A piped exec has no terminal whose size could change.
    let resize = report_resizes.then(|| spawn_resize_reporter(writer.clone(), completed.clone()));
    let (detached, stdin) = spawn_stdin_reader(writer, escape, action, completed.clone());
    Ok(InputThreads {
        detached,
        completed,
        stdin: Some(stdin),
        resize,
    })
}

enum PumpResult {
    Exit(i32),
    Detached,
    Closed,
    Sigpipe,
}

fn pump_output(
    mut reader: impl Read,
    out: &mut dyn Write,
    mut err: Option<&mut dyn Write>,
    ctx: &'static str,
) -> Result<PumpResult> {
    loop {
        match contract::read_frame::<AgentOutput>(&mut reader) {
            Ok(Some(AgentOutput::Out(b))) => {
                if out.write_all(&b).and_then(|()| out.flush()).is_err() {
                    return Ok(PumpResult::Sigpipe);
                }
            }
            Ok(Some(AgentOutput::Err(b))) => {
                let sink: &mut dyn Write = match &mut err {
                    Some(e) => *e as &mut dyn Write,
                    None => out as &mut dyn Write,
                };
                if sink.write_all(&b).and_then(|()| sink.flush()).is_err() {
                    return Ok(PumpResult::Sigpipe);
                }
            }
            Ok(Some(AgentOutput::Exit { code: c })) => return Ok(PumpResult::Exit(c)),
            Ok(Some(AgentOutput::Detached)) => return Ok(PumpResult::Detached),
            Ok(None) => return Ok(PumpResult::Closed),
            Err(e) => return Err(e).context(ctx),
        }
    }
}

/// Run one exec to completion and hand back the command's exit status.
///
/// `tty` says the command got a PTY, which is when this end needs raw mode
/// too: without it the local terminal would hold keystrokes until a newline
/// and turn Ctrl-C into a signal for terra itself. A piped exec keeps stderr
/// in its own frame, so redirecting it away still works.
pub fn pump_exec(stream: &UnixStream, tty: bool) -> Result<i32> {
    let _raw = tty.then(RawTerminal::enable);
    let threads = spawn_input_threads(stream, None, StdinEndAction::SendEof, tty)?;
    let result = pump_exec_output(stream, &mut std::io::stdout(), &mut std::io::stderr());
    threads.stop(stream);
    result
}

fn pump_exec_output(reader: impl Read, out: &mut impl Write, err: &mut impl Write) -> Result<i32> {
    match pump_output(
        reader,
        out as &mut dyn Write,
        Some(err as &mut dyn Write),
        "reading the command's output",
    )? {
        PumpResult::Exit(c) => Ok(c),
        PumpResult::Sigpipe => Ok(SHELL_SIGPIPE_STATUS),
        PumpResult::Detached => anyhow::bail!("the box answered an exec with a detach"),
        PumpResult::Closed => anyhow::bail!("the box stopped before the command finished"),
    }
}

pub fn pump_session(stream: &UnixStream) -> Result<SessionOutcome> {
    let _raw = RawTerminal::enable();
    let threads = spawn_input_threads(stream, Some(DETACH_KEY), StdinEndAction::CloseSocket, true)?;
    let ended = pump_session_output(stream, &mut std::io::stdout());
    let detached = threads.detached.load(Ordering::SeqCst);
    threads.stop(stream);
    if detached {
        return Ok(SessionOutcome::Detached);
    }
    ended
}

fn pump_session_output(reader: impl Read, out: &mut impl Write) -> Result<SessionOutcome> {
    match pump_output(
        reader,
        out as &mut dyn Write,
        None,
        "reading the box's terminal",
    )? {
        PumpResult::Exit(c) => Ok(SessionOutcome::Exited(c)),
        PumpResult::Detached | PumpResult::Sigpipe => Ok(SessionOutcome::Detached),
        PumpResult::Closed => Ok(SessionOutcome::Closed),
    }
}

struct RawTerminal {
    enabled: bool,
}
impl RawTerminal {
    #[must_use]
    fn enable() -> Self {
        Self {
            enabled: crossterm::terminal::enable_raw_mode().is_ok(),
        }
    }
}
impl Drop for RawTerminal {
    fn drop(&mut self) {
        if self.enabled {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn input_readiness_waits_for_a_byte() {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        assert!(!input_is_ready(&reader));
        writer.write_all(b"x").unwrap();
        assert!(input_is_ready(&reader));
    }

    /// A box on disk, held as a running one, with a fake agent bound to its
    /// socket. The fake speaks just enough of the wire for the host's side to
    /// be driven: hello, the `SessionControl` byte, the request the host
    /// actually sends, and the canned replies - so the retry loop, the hello
    /// check, and the frame parsing all run for real.
    fn spawn_fake_agent(
        project_dir: &std::path::Path,
        expected: contract::ControlRequest,
        replies: Vec<contract::ControlReply>,
    ) -> (
        BoxRef,
        std::fs::File,
        crate::sys::TestHome,
        std::thread::JoinHandle<()>,
    ) {
        let home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(project_dir, "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        let lock = bx.lock_run().unwrap();
        let listener = UnixListener::bind(bx.get_dir().join(crate::state::AGENT_SOCKET)).unwrap();
        let agent = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.write_all(&contract::AGENT_HELLO).unwrap();
            let mut service = [0u8; 1];
            conn.read_exact(&mut service).unwrap();
            assert_eq!(
                service[0],
                contract::AgentService::SessionControl.to_byte(),
                "the host dialed a different service"
            );
            assert_eq!(
                contract::read_frame::<contract::ControlRequest>(&mut conn).unwrap(),
                Some(expected),
                "the host sent a different request"
            );
            for rep in replies {
                conn.write_all(&contract::encode_frame(&rep).unwrap())
                    .unwrap();
            }
            conn.flush().unwrap();
        });
        (bx, lock, home, agent)
    }

    #[test]
    fn an_agent_on_a_different_protocol_is_refused() {
        let home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(home.get_path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        let _lock = bx.lock_run().unwrap();
        let listener = UnixListener::bind(bx.get_dir().join(crate::state::AGENT_SOCKET)).unwrap();
        let agent = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.write_all(&[
                contract::AGENT_HELLO[0],
                contract::AGENT_PROTOCOL_VERSION.wrapping_add(1),
            ])
            .unwrap();
        });

        let error = connect_to_agent(&bx, contract::AgentService::Session, "session", || Ok(()))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not speak this terra's protocol"),
            "{error}"
        );
        agent.join().unwrap();
    }

    /// `terra <box> sessions` reads the roster the agent sends, including
    /// clients that reported no terminal size.
    #[test]
    fn list_clients_parses_the_roster_and_keeps_nosize_clients() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _lock, _home, agent) = spawn_fake_agent(
            dir.path(),
            contract::ControlRequest::List,
            vec![
                contract::ControlReply::Client {
                    id: 0,
                    size: Some(TermSize {
                        rows: 30,
                        cols: 100,
                    }),
                },
                contract::ControlReply::Client { id: 1, size: None },
                contract::ControlReply::Done,
            ],
        );
        assert_eq!(
            list_clients(&bx, None).unwrap(),
            vec![
                SessionClient {
                    id: 0,
                    reported_term_size: Some(TermSize {
                        rows: 30,
                        cols: 100
                    })
                },
                SessionClient {
                    id: 1,
                    reported_term_size: None
                },
            ]
        );
        agent.join().unwrap();
    }

    /// The guest answers a detach of a client that was never there with
    /// `Missing`, and the host says so rather than pretending the cleanup
    /// happened.
    #[test]
    fn detach_client_reports_missing() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _lock, _home, agent) = spawn_fake_agent(
            dir.path(),
            contract::ControlRequest::Detach { id: 9 },
            vec![contract::ControlReply::Missing { id: 9 }],
        );
        let err = detach_client(&bx, 9, None).unwrap_err().to_string();
        assert!(err.contains("no client 9"), "{err}");
        assert!(err.contains("dev"), "{err}");
        agent.join().unwrap();
    }

    /// `detach --all` counts what the guest dropped - the number `terra`
    /// prints.
    #[test]
    fn detach_all_counts_the_detached() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _lock, _home, agent) = spawn_fake_agent(
            dir.path(),
            contract::ControlRequest::DetachAll,
            vec![
                contract::ControlReply::Detached { id: 0 },
                contract::ControlReply::Detached { id: 1 },
                contract::ControlReply::Done,
            ],
        );
        assert_eq!(detach_all(&bx, None).unwrap(), 2);
        agent.join().unwrap();
    }

    /// An empty session is answered with just `Done` - nothing dropped is
    /// still an honest answer, not an error.
    #[test]
    fn detach_all_on_an_empty_session_counts_zero() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _lock, _home, agent) = spawn_fake_agent(
            dir.path(),
            contract::ControlRequest::DetachAll,
            vec![contract::ControlReply::Done],
        );
        assert_eq!(detach_all(&bx, None).unwrap(), 0);
        agent.join().unwrap();
    }

    /// The one answer a stopped box has: the verb names the live agent as the
    /// thing the box has to be booted for, the same message every agent-bound
    /// verb gives, so a script sees one spelling of "not running".
    #[test]
    fn a_stopped_box_refuses_sessions_and_detach() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();

        let err = list_clients(&bx, None).unwrap_err().to_string();
        assert!(err.contains("is not running"), "{err}");
        assert!(err.contains("terra dev -d"), "{err}");
        assert!(detach_client(&bx, 1, None).is_err());
        assert!(detach_all(&bx, None).is_err());
    }

    /// A pipe whose reader has gone.
    struct ClosedPipe;
    impl Write for ClosedPipe {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A bake holds the box's lock but binds no agent port, so a box mid-`terra
    /// setup` answers "running" to every check and then never answers at all:
    /// `terra exec` and `terra put`/`get` used to sit on a socket nothing would bind
    /// until the bake ended, and then report that the box had stopped.
    ///
    /// Both halves are here, because the wait is the one that outlived the
    /// fix: a bake the box was already in is refused at the door, and one that
    /// takes the box *mid-wait* is refused the next time the wait looks. Every
    /// waiter for an agent port reads [`still_serving`], `attach` included, so
    /// there is one answer rather than one per verb.
    #[test]
    fn a_box_mid_bake_is_refused_rather_than_waited_on() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        let lock = bx.lock_run().unwrap();

        let baking = bx.mark_baking(&lock);
        for verb in ["exec", "cp"] {
            let err = ensure_running(&bx, verb).unwrap_err().to_string();
            assert_eq!(err, bx.setup_holds_it().to_string(), "{verb}");
        }

        drop(baking);
        assert!(ensure_running(&bx, "exec").is_ok());

        let mut still_waiting = wait_while_running(&bx, None);
        assert!(still_waiting().is_ok(), "a served box is waited on");
        let baking = bx.mark_baking(&lock);
        let err = still_waiting()
            .expect_err("a bake that took the box mid-wait was waited out")
            .to_string();
        assert_eq!(err, bx.setup_holds_it().to_string());
        drop(baking);
        assert!(still_waiting().is_ok());

        // The lock's release is deferred while a concurrently forked test
        // child holds the pid-file fd between its fork and its exec; wait the
        // microseconds out so the box reads as stopped.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while bx.get_holder() != crate::state::Holder::Free && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        drop(lock);
        let err = still_waiting().unwrap_err().to_string();
        assert!(err.contains("stopped before its agent answered"), "{err}");
    }

    /// `terra exec … | head -1` closes this end's stdout while the guest
    /// command keeps writing. Rust ignores SIGPIPE, so the write just fails -
    /// and the failure used to be discarded, which left the pump copying a
    /// stream nobody reads until the command happened to finish: `tail -f`
    /// through a pipe hung forever. The status is the one a shell reports for
    /// a command SIGPIPE took.
    #[test]
    fn an_exec_whose_reader_left_ends_rather_than_pumping_into_a_closed_pipe() {
        // More output than any reader took, and no exit frame within it: only
        // noticing the closed sink can end this.
        let flood = |make_output: fn(Vec<u8>) -> AgentOutput| -> Vec<u8> {
            std::iter::repeat_with(|| {
                contract::encode_frame(&make_output(b"tick\n".to_vec())).unwrap()
            })
            .take(64)
            .flatten()
            .collect()
        };

        let status = pump_exec_output(
            std::io::Cursor::new(flood(AgentOutput::Out)),
            &mut ClosedPipe,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(status, SHELL_SIGPIPE_STATUS);
        // stderr is the same pipe under `2>&1 | head`, so it ends the same way.
        let status = pump_exec_output(
            std::io::Cursor::new(flood(AgentOutput::Err)),
            &mut Vec::new(),
            &mut ClosedPipe,
        )
        .unwrap();
        assert_eq!(status, SHELL_SIGPIPE_STATUS);

        // A reader that is still there gets everything, and the command's own
        // status - which is what must not be replaced by the one above.
        let mut out = Vec::new();
        let mut err = Vec::new();
        let wire: Vec<u8> = [
            AgentOutput::Out(b"built\n".to_vec()),
            AgentOutput::Err(b"warned\n".to_vec()),
            AgentOutput::Exit { code: 3 },
        ]
        .iter()
        .flat_map(|f| contract::encode_frame(f).unwrap())
        .collect();
        let status = pump_exec_output(std::io::Cursor::new(wire), &mut out, &mut err).unwrap();
        assert_eq!(
            (status, out.as_slice(), err.as_slice()),
            (3, &b"built\n"[..], &b"warned\n"[..])
        );
    }

    /// A session's reader can leave too (`terra dev | tee log`, and tee died),
    /// and the pump used to swallow the failed write and keep copying a
    /// stream nobody reads until the workload ended: the same hang the exec
    /// pump refuses, fixed there and not here. The reader leaving is this
    /// client leaving, so the session detaches and the box keeps running.
    #[test]
    fn a_session_whose_reader_left_detaches_rather_than_pumping_forever() {
        // No exit frame within it: only noticing the closed sink can end this.
        let flood: Vec<u8> = std::iter::repeat_with(|| {
            contract::encode_frame(&AgentOutput::Out(b"tick\n".to_vec())).unwrap()
        })
        .take(64)
        .flatten()
        .collect();
        let outcome = pump_session_output(std::io::Cursor::new(flood), &mut ClosedPipe).unwrap();
        assert_eq!(outcome, SessionOutcome::Detached);
    }

    #[test]
    fn the_escape_key_is_named_the_way_a_terminal_spells_it() {
        assert_eq!(DETACH_KEY_NAME, "Ctrl-\\");
        assert_ne!(DETACH_KEY, 0x1B);
    }

    /// A session ends on the workload's status, and the difference between
    /// hearing one and not hearing one is what a joiner exits with: a box that
    /// finished is not the same event as a VM that was killed under it, and a
    /// bare EOF used to be the only spelling of both.
    #[test]
    fn a_session_ends_on_the_status_it_was_given_or_says_it_never_got_one() {
        let session = |frames: &[AgentOutput]| {
            let wire: Vec<u8> = frames
                .iter()
                .flat_map(|f| contract::encode_frame(f).unwrap())
                .collect();
            let mut shown = Vec::new();
            let outcome = pump_session_output(std::io::Cursor::new(wire), &mut shown).unwrap();
            (outcome, shown)
        };

        let (outcome, shown) = session(&[
            AgentOutput::Out(b"building\n".to_vec()),
            AgentOutput::Exit { code: 3 },
        ]);
        assert_eq!(outcome, SessionOutcome::Exited(3));
        assert_eq!(shown, b"building\n", "the terminal output must still land");

        assert_eq!(
            session(&[AgentOutput::Exit { code: 0 }]).0,
            SessionOutcome::Exited(0)
        );

        assert_eq!(session(&[]).0, SessionOutcome::Closed);
        assert_eq!(
            session(&[AgentOutput::Out(b"half a boot\n".to_vec())]).0,
            SessionOutcome::Closed
        );

        let mut truncated =
            contract::encode_frame(&AgentOutput::Out(b"0123456789".to_vec())).unwrap();
        truncated.truncate(7);
        assert!(
            pump_session_output(std::io::Cursor::new(truncated), &mut Vec::new()).is_err(),
            "a truncated frame must not read as a clean end"
        );
    }

    /// `terra <box> detach` drops the client from the agent's side: the frame
    /// it sends turns the EOF that follows into a detach, so the kicked
    /// terminal reads "detached, box keeps running" rather than "box died" -
    /// the same outcome as the detach key, and what lets a script tell the two
    /// apart. An exec is never detached, so there the frame is a protocol
    /// error.
    #[test]
    fn a_detach_frame_ends_the_session_as_a_detach() {
        let wire: Vec<u8> = [AgentOutput::Out(b"bye\n".to_vec()), AgentOutput::Detached]
            .iter()
            .flat_map(|f| contract::encode_frame(f).unwrap())
            .collect();
        let mut shown = Vec::new();
        let outcome = pump_session_output(std::io::Cursor::new(wire), &mut shown).unwrap();
        assert_eq!(outcome, SessionOutcome::Detached);
        assert_eq!(
            shown, b"bye\n",
            "the output before the detach must still land"
        );

        let err = pump_exec_output(
            std::io::Cursor::new(contract::encode_frame(&AgentOutput::Detached).unwrap()),
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("detach"), "{err}");
    }
}
