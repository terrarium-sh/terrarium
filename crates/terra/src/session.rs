//! The host end of the agent's ports: how terra reaches one, and how it pumps
//! bytes between that port and the user's terminal.

use crate::state::{BoxRef, Holder};
use crate::sys::POLL;
use anyhow::{Context, Result};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::AsFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use terra_platform::io::local::AsyncLocalStream;
use terra_protocol::{self as protocol, AgentOutput, AgentService, ClientInput, TermSize};

const AGENT_HELLO_WAIT_TIMEOUT: Duration = Duration::from_millis(500);
const CONTROL_READ_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_SESSION_CLIENTS: usize = 1024;
const MAX_CONTROL_REPLY_FRAME_BYTES: usize = 4096;
const SILENT_BOOT_GRACE: Duration = Duration::from_secs(15);

pub fn read_terminal_size() -> Option<TermSize> {
    let (cols, rows) = crossterm::terminal::size().ok()?;
    (rows > 0 && cols > 0).then_some(TermSize { rows, cols })
}

pub const DEFAULT_TERMINAL_SIZE: TermSize = TermSize { rows: 24, cols: 80 };

/// A control byte, not a bare letter the workload wants.
/// NOTE: Not ESC - every arrow key sends that
pub const DETACH_KEY: u8 = 0x1C;

#[cfg(unix)]
const SHELL_SIGPIPE_STATUS: i32 = 128 + rustix::process::Signal::PIPE.as_raw();
#[cfg(windows)]
const SHELL_SIGPIPE_STATUS: i32 = 1;

pub const DETACH_KEY_NAME: &str = "Ctrl-\\";

#[derive(Debug, PartialEq, Eq)]
pub enum SessionOutcome {
    Detached,
    Exited(i32),
    Closed,
}

/// Connect to the agent and select `service`, returning the stream once the
/// agent's hello has been consumed and the service frame written. Retried until
/// then: the VMM binds the socket before guest PID 1 runs, and a stale socket
/// outlives the stopped VM.
pub async fn connect_to_agent(
    bx: &BoxRef,
    service: AgentService,
    what: &str,
    mut still_waiting: impl FnMut() -> Result<()>,
) -> Result<AsyncLocalStream> {
    let sock = bx.get_dir().join(crate::state::AGENT_SOCKET);
    let mut hint_at = Some(Instant::now() + SILENT_BOOT_GRACE);
    let mut last_connect_error = None;
    loop {
        if hint_at.is_some_and(|at| Instant::now() > at) {
            hint_at = None;
            eprintln!(
                "terra: still waiting for {bx}'s {what} - `{} --diagnostics --follow` shows the guest boot",
                bx.build_logs_command()
            );
        }
        if let Err(error) = still_waiting() {
            if let Some(last_connect_error) = last_connect_error {
                return Err(error)
                    .context(format!("last connection attempt: {last_connect_error}"));
            }
            return Err(error);
        }
        match tokio::time::timeout(AGENT_HELLO_WAIT_TIMEOUT, AsyncLocalStream::connect(&sock)).await
        {
            Err(_) => last_connect_error = Some("connection attempt timed out".to_owned()),
            Ok(Err(error)) => last_connect_error = Some(error.to_string()),
            Ok(Ok(mut stream)) => {
                let mut magic = [0];
                if tokio::time::timeout(
                    AGENT_HELLO_WAIT_TIMEOUT,
                    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut magic),
                )
                .await
                .is_ok_and(|result| result.is_ok())
                {
                    anyhow::ensure!(
                        magic[0] == protocol::AGENT_HELLO[0],
                        "the agent in {bx} does not speak this terra's protocol - \
                     `terra {name} stop` and start it again on this build",
                        name = bx.get_name()
                    );
                    let mut version = [0];
                    if tokio::time::timeout(
                        AGENT_HELLO_WAIT_TIMEOUT,
                        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut version),
                    )
                    .await
                    .is_err()
                    {
                        continue;
                    }
                    anyhow::ensure!(
                        version[0] == protocol::AGENT_PROTOCOL_VERSION,
                        "the agent in {bx} does not speak this terra's protocol - \
                     `terra {name} stop` and start it again on this build",
                        name = bx.get_name()
                    );
                    if protocol::write_frame_async(&mut stream, &service)
                        .await
                        .is_ok()
                    {
                        return Ok(stream);
                    }
                }
            }
        }
        tokio::time::sleep(POLL).await;
    }
}

pub async fn connect_to_running_agent(
    bx: &BoxRef,
    verb: &str,
    service: AgentService,
    what: &str,
    timeout: Option<u64>,
) -> Result<AsyncLocalStream> {
    ensure_running(bx, verb)?;
    connect_to_agent(bx, service, what, wait_while_running(bx, timeout)).await
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

pub(crate) fn wait_while_running(bx: &BoxRef, timeout: Option<u64>) -> impl FnMut() -> Result<()> {
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

async fn request_control(
    bx: &BoxRef,
    verb: &str,
    req: &protocol::ControlRequest,
    agent_timeout: Option<u64>,
    ctx: &'static str,
) -> Result<AsyncLocalStream> {
    let mut stream = connect_to_running_agent(
        bx,
        verb,
        protocol::AgentService::SessionControl,
        "session control service",
        agent_timeout,
    )
    .await?;
    protocol::write_frame_async(&mut stream, req)
        .await
        .context(ctx)?;
    Ok(stream)
}

pub async fn list_clients(bx: &BoxRef, agent_timeout: Option<u64>) -> Result<Vec<SessionClient>> {
    let mut stream = request_control(
        bx,
        "sessions",
        &protocol::ControlRequest::List,
        agent_timeout,
        "asking for the session's clients",
    )
    .await?;
    let mut clients = Vec::new();
    loop {
        match tokio::time::timeout(
            CONTROL_READ_TIMEOUT,
            protocol::read_frame_async_with_limit::<protocol::ControlReply>(
                &mut stream,
                MAX_CONTROL_REPLY_FRAME_BYTES,
            ),
        )
        .await
        .map_err(|_| anyhow::anyhow!("reading the session listing timed out"))?
        {
            Ok(Some(protocol::ControlReply::Client { id, size })) => {
                if clients.len() == MAX_SESSION_CLIENTS {
                    anyhow::bail!("the agent sent more than {MAX_SESSION_CLIENTS} session clients");
                }
                clients.push(SessionClient {
                    id,
                    reported_term_size: size,
                });
            }
            Ok(Some(protocol::ControlReply::Done)) => return Ok(clients),
            Ok(Some(
                protocol::ControlReply::Detached { .. } | protocol::ControlReply::Missing { .. },
            )) => anyhow::bail!("the agent answered a listing with a detach reply"),
            Ok(None) => anyhow::bail!("{bx} stopped before its agent listed the session"),
            Err(e) => return Err(e).context("reading the session listing"),
        }
    }
}

pub async fn detach_client(bx: &BoxRef, client_id: u64, agent_timeout: Option<u64>) -> Result<()> {
    let mut stream = request_control(
        bx,
        "detach",
        &protocol::ControlRequest::Detach { id: client_id },
        agent_timeout,
        "asking to detach a client",
    )
    .await?;
    match tokio::time::timeout(
        CONTROL_READ_TIMEOUT,
        protocol::read_frame_async_with_limit::<protocol::ControlReply>(
            &mut stream,
            MAX_CONTROL_REPLY_FRAME_BYTES,
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("reading the detach reply timed out"))?
    {
        Ok(Some(protocol::ControlReply::Detached { id })) if id == client_id => Ok(()),
        Ok(Some(protocol::ControlReply::Missing { id })) if id == client_id => {
            anyhow::bail!("no client {client_id} is attached to {bx}")
        }
        Ok(Some(
            protocol::ControlReply::Detached { id } | protocol::ControlReply::Missing { id },
        )) => {
            anyhow::bail!("the agent answered detach for client {client_id} with client {id}");
        }
        Ok(Some(protocol::ControlReply::Client { .. } | protocol::ControlReply::Done)) => {
            anyhow::bail!("the agent answered a detach with a listing reply")
        }
        Ok(None) => anyhow::bail!("{bx} stopped before its agent answered the detach"),
        Err(e) => Err(e).context("reading the detach reply"),
    }
}

pub async fn detach_all(bx: &BoxRef, agent_timeout: Option<u64>) -> Result<u64> {
    let mut stream = request_control(
        bx,
        "detach",
        &protocol::ControlRequest::DetachAll,
        agent_timeout,
        "asking to detach every client",
    )
    .await?;
    let mut detached = 0;
    loop {
        match tokio::time::timeout(
            CONTROL_READ_TIMEOUT,
            protocol::read_frame_async_with_limit::<protocol::ControlReply>(
                &mut stream,
                MAX_CONTROL_REPLY_FRAME_BYTES,
            ),
        )
        .await
        .map_err(|_| anyhow::anyhow!("reading the detach replies timed out"))?
        {
            Ok(Some(protocol::ControlReply::Detached { .. })) => {
                if detached == MAX_SESSION_CLIENTS as u64 {
                    anyhow::bail!("the agent sent more than {MAX_SESSION_CLIENTS} detach replies");
                }
                detached += 1;
            }
            Ok(Some(protocol::ControlReply::Done)) => return Ok(detached),
            Ok(Some(
                protocol::ControlReply::Client { .. } | protocol::ControlReply::Missing { .. },
            )) => anyhow::bail!("the agent answered a detach with a listing reply"),
            Ok(None) => anyhow::bail!("{bx} stopped before its agent answered the detach"),
            Err(e) => return Err(e).context("reading the detach replies"),
        }
    }
}

enum Input {
    Frame(ClientInput),
    Detach,
}

struct InputReader {
    completed: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for InputReader {
    fn drop(&mut self) {
        self.completed.store(true, Ordering::SeqCst);
    }
}

impl InputReader {
    async fn stop(mut self) {
        self.completed.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = tokio::task::spawn_blocking(move || thread.join()).await;
        }
    }
}

fn spawn_stdin_reader(escape: Option<u8>, sender: tokio::sync::mpsc::Sender<Input>) -> InputReader {
    let completed = Arc::new(AtomicBool::new(false));
    let stopped = completed.clone();
    let thread = std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        while !stopped.load(Ordering::SeqCst) {
            if !input_is_ready(&stdin) {
                #[cfg(windows)]
                std::thread::sleep(POLL);
                continue;
            }
            let n = match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            let escape_at = escape.and_then(|key| buf[..n].iter().position(|byte| *byte == key));
            let keys = &buf[..escape_at.unwrap_or(n)];
            if !keys.is_empty()
                && sender
                    .blocking_send(Input::Frame(ClientInput::Keys(keys.to_vec())))
                    .is_err()
            {
                return;
            }
            if escape_at.is_some() {
                let _ = sender.blocking_send(Input::Detach);
                return;
            }
        }
        let _ = sender.blocking_send(Input::Frame(ClientInput::Eof));
    });
    InputReader {
        completed,
        thread: Some(thread),
    }
}

#[cfg(unix)]
fn input_is_ready(fd: impl AsFd) -> bool {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    let mut read_fds = [PollFd::new(&fd, PollFlags::IN)];
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: POLL.subsec_nanos().into(),
    };
    poll(&mut read_fds, Some(&timeout)).is_ok_and(|ready| ready > 0)
}

#[allow(unsafe_code)]
#[cfg(windows)]
fn input_is_ready(_stdin: &std::io::Stdin) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};
    use windows_sys::Win32::System::Console::GetNumberOfConsoleInputEvents;
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;

    let handle = std::io::stdin().as_raw_handle();
    // SAFETY: stdin owns this handle for the duration of the probe and all output pointers are
    // writable locals.
    unsafe {
        if GetFileType(handle) == FILE_TYPE_PIPE {
            let mut available = 0;
            return PeekNamedPipe(
                handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &raw mut available,
                std::ptr::null_mut(),
            ) != 0
                && available > 0;
        }
        let mut events = 0;
        GetNumberOfConsoleInputEvents(handle, &raw mut events) != 0 && events > 0
    }
}

enum PumpResult {
    Exit(i32),
    Detached,
    Closed,
    Sigpipe,
}

async fn output_loop(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    out: &mut dyn Write,
    mut err: Option<&mut dyn Write>,
    ctx: &'static str,
) -> Result<PumpResult> {
    loop {
        match protocol::read_frame_async::<AgentOutput>(reader).await {
            Ok(Some(AgentOutput::Out(bytes))) => {
                if out.write_all(&bytes).and_then(|()| out.flush()).is_err() {
                    return Ok(PumpResult::Sigpipe);
                }
            }
            Ok(Some(AgentOutput::Err(bytes))) => {
                let sink: &mut dyn Write = match &mut err {
                    Some(err) => *err,
                    None => out,
                };
                if sink.write_all(&bytes).and_then(|()| sink.flush()).is_err() {
                    return Ok(PumpResult::Sigpipe);
                }
            }
            Ok(Some(AgentOutput::Exit { code })) => return Ok(PumpResult::Exit(code)),
            Ok(Some(AgentOutput::Detached)) => return Ok(PumpResult::Detached),
            Ok(None) => return Ok(PumpResult::Closed),
            Err(error) => return Err(error).context(ctx),
        }
    }
}

async fn input_loop(
    mut writer: impl tokio::io::AsyncWrite + Unpin,
    mut input: tokio::sync::mpsc::Receiver<Input>,
    report_resizes: bool,
) -> Result<PumpResult> {
    let mut input_open = true;
    let mut last_size = None;
    let mut resize = tokio::time::interval(POLL);
    resize.tick().await;
    loop {
        tokio::select! {
            message = input.recv(), if input_open => match message {
                Some(Input::Frame(input)) => protocol::write_frame_async(&mut writer, &input)
                    .await
                    .context("sending terminal input")?,
                Some(Input::Detach) => {
                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut writer).await;
                    return Ok(PumpResult::Detached);
                }
                None => input_open = false,
            },
            _ = resize.tick(), if report_resizes => {
                if let Some(size) = read_terminal_size().filter(|size| Some(*size) != last_size) {
                    last_size = Some(size);
                    protocol::write_frame_async(&mut writer, &ClientInput::Resize(size))
                        .await
                        .context("sending terminal size")?;
                }
            },
            else => std::future::pending::<()>().await,
        }
    }
}

async fn pump_stream(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    writer: impl tokio::io::AsyncWrite + Send + Unpin + 'static,
    input: tokio::sync::mpsc::Receiver<Input>,
    report_resizes: bool,
    out: &mut dyn Write,
    err: Option<&mut dyn Write>,
    ctx: &'static str,
) -> Result<PumpResult> {
    let mut input_loops = tokio::task::JoinSet::new();
    input_loops.spawn(input_loop(writer, input, report_resizes));
    let result = tokio::select! {
        biased;
        result = output_loop(&mut reader, out, err, ctx) => result,
        result = input_loops.join_next() => match result {
            Some(Ok(result)) => result,
            Some(Err(error)) => Err(error).context("joining terminal input worker"),
            None => Err(anyhow::anyhow!("terminal input worker ended unexpectedly")),
        },
    };
    input_loops.shutdown().await;
    result
}

async fn pump_output(
    reader: tokio::io::ReadHalf<AsyncLocalStream>,
    writer: tokio::io::WriteHalf<AsyncLocalStream>,
    escape: Option<u8>,
    report_resizes: bool,
    out: &mut dyn Write,
    err: Option<&mut dyn Write>,
    ctx: &'static str,
) -> Result<PumpResult> {
    let (input_sender, input) = tokio::sync::mpsc::channel(16);
    let input_reader = spawn_stdin_reader(escape, input_sender);
    let result = pump_stream(reader, writer, input, report_resizes, out, err, ctx).await;
    input_reader.stop().await;
    result
}

/// Run one exec to completion and hand back the command's exit status.
///
/// `tty` says the command got a PTY, which is when this end needs raw mode
/// too: without it the local terminal would hold keystrokes until a newline
/// and turn Ctrl-C into a signal for terra itself. A piped exec keeps stderr
/// in its own frame, so redirecting it away still works.
pub async fn pump_exec(stream: AsyncLocalStream, tty: bool) -> Result<i32> {
    let _raw = tty.then(RawTerminal::enable);
    let (reader, writer) = tokio::io::split(stream);
    match pump_output(
        reader,
        writer,
        None,
        tty,
        &mut std::io::stdout(),
        Some(&mut std::io::stderr()),
        "reading the command's output",
    )
    .await?
    {
        PumpResult::Exit(code) => Ok(code),
        PumpResult::Sigpipe => Ok(SHELL_SIGPIPE_STATUS),
        PumpResult::Detached => anyhow::bail!("the box answered an exec with a detach"),
        PumpResult::Closed => anyhow::bail!("the box stopped before the command finished"),
    }
}

#[cfg(test)]
async fn pump_exec_output(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    out: &mut impl Write,
    err: &mut impl Write,
) -> Result<i32> {
    match output_loop(
        &mut reader,
        out as &mut dyn Write,
        Some(err as &mut dyn Write),
        "reading the command's output",
    )
    .await?
    {
        PumpResult::Exit(c) => Ok(c),
        PumpResult::Sigpipe => Ok(SHELL_SIGPIPE_STATUS),
        PumpResult::Detached => anyhow::bail!("the box answered an exec with a detach"),
        PumpResult::Closed => anyhow::bail!("the box stopped before the command finished"),
    }
}

pub async fn pump_session(stream: AsyncLocalStream) -> Result<SessionOutcome> {
    let _raw = RawTerminal::enable();
    let (reader, writer) = tokio::io::split(stream);
    match pump_output(
        reader,
        writer,
        Some(DETACH_KEY),
        true,
        &mut std::io::stdout(),
        None,
        "reading the box's terminal",
    )
    .await?
    {
        PumpResult::Exit(code) => Ok(SessionOutcome::Exited(code)),
        PumpResult::Detached | PumpResult::Sigpipe => Ok(SessionOutcome::Detached),
        PumpResult::Closed => Ok(SessionOutcome::Closed),
    }
}

#[cfg(test)]
async fn pump_session_output(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    out: &mut impl Write,
) -> Result<SessionOutcome> {
    match output_loop(
        &mut reader,
        out as &mut dyn Write,
        None,
        "reading the box's terminal",
    )
    .await?
    {
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
    use terra_platform::io::local::LocalListener;

    async fn frame_reader(bytes: Vec<u8>) -> tokio::io::DuplexStream {
        use tokio::io::AsyncWriteExt as _;

        let (mut writer, reader) = tokio::io::duplex(bytes.len().max(1));
        writer.write_all(&bytes).await.unwrap();
        writer.shutdown().await.unwrap();
        reader
    }

    async fn session_output(frames: &[AgentOutput]) -> (SessionOutcome, Vec<u8>) {
        let wire = frames
            .iter()
            .flat_map(|frame| protocol::encode_frame(frame).unwrap())
            .collect();
        let mut shown = Vec::new();
        let outcome = pump_session_output(frame_reader(wire).await, &mut shown)
            .await
            .unwrap();
        (outcome, shown)
    }

    #[cfg(unix)]
    #[test]
    fn input_readiness_waits_for_a_byte() {
        let (mut writer, reader) = terra_platform::io::local::LocalStream::pair().unwrap();
        assert!(!input_is_ready(&reader));
        writer.write_all(b"x").unwrap();
        assert!(input_is_ready(&reader));
    }

    #[cfg(unix)]
    #[test]
    fn input_readiness_reports_eof() {
        let (writer, mut reader) = terra_platform::io::local::LocalStream::pair().unwrap();
        drop(writer);
        assert!(input_is_ready(&reader));
        assert_eq!(reader.read(&mut [0]).unwrap(), 0);
    }

    /// A box on disk, held as a running one, with a fake agent bound to its
    /// socket. The fake speaks just enough of the wire for the host's side to
    /// be driven: hello, the `SessionControl` frame, the request the host
    /// actually sends, and the canned replies - so the retry loop, the hello
    /// check, and the frame parsing all run for real.
    fn spawn_fake_agent(
        project_dir: &std::path::Path,
        expected: protocol::ControlRequest,
        replies: Vec<protocol::ControlReply>,
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
        let listener = LocalListener::bind(bx.get_dir().join(crate::state::AGENT_SOCKET)).unwrap();
        let agent = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.write_all(&protocol::AGENT_HELLO).unwrap();
            assert_eq!(
                protocol::read_frame::<protocol::AgentService>(&mut conn).unwrap(),
                Some(protocol::AgentService::SessionControl),
                "the host dialed a different service"
            );
            assert_eq!(
                protocol::read_frame::<protocol::ControlRequest>(&mut conn).unwrap(),
                Some(expected),
                "the host sent a different request"
            );
            for rep in replies {
                conn.write_all(&protocol::encode_frame(&rep).unwrap())
                    .unwrap();
            }
            conn.flush().unwrap();
        });
        (bx, lock, home, agent)
    }

    #[tokio::test]
    async fn an_agent_on_a_different_protocol_is_refused() {
        let home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(home.get_path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        let _lock = bx.lock_run().unwrap();
        let listener = LocalListener::bind(bx.get_dir().join(crate::state::AGENT_SOCKET)).unwrap();
        let agent = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.write_all(&[
                protocol::AGENT_HELLO[0],
                protocol::AGENT_PROTOCOL_VERSION.wrapping_add(1),
            ])
            .unwrap();
        });

        let Err(error) =
            connect_to_agent(&bx, protocol::AgentService::Session, "session", || Ok(())).await
        else {
            panic!("accepted incompatible agent");
        };
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
    #[tokio::test]
    async fn list_clients_parses_the_roster_and_keeps_nosize_clients() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _lock, _home, agent) = spawn_fake_agent(
            dir.path(),
            protocol::ControlRequest::List,
            vec![
                protocol::ControlReply::Client {
                    id: 0,
                    size: Some(TermSize {
                        rows: 30,
                        cols: 100,
                    }),
                },
                protocol::ControlReply::Client { id: 1, size: None },
                protocol::ControlReply::Done,
            ],
        );
        assert_eq!(
            list_clients(&bx, None).await.unwrap(),
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

    #[tokio::test]
    async fn detach_replies_must_name_the_requested_client() {
        for reply in [
            protocol::ControlReply::Detached { id: 8 },
            protocol::ControlReply::Missing { id: 8 },
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (bx, _lock, _home, agent) = spawn_fake_agent(
                dir.path(),
                protocol::ControlRequest::Detach { id: 9 },
                vec![reply],
            );
            let error = detach_client(&bx, 9, None).await.unwrap_err().to_string();
            assert!(error.contains("client 9 with client 8"), "{error}");
            agent.join().unwrap();
        }
    }

    /// The guest answers a detach of a client that was never there with
    /// `Missing`, and the host says so rather than pretending the cleanup
    /// happened.
    #[tokio::test]
    async fn detach_client_reports_missing() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _lock, _home, agent) = spawn_fake_agent(
            dir.path(),
            protocol::ControlRequest::Detach { id: 9 },
            vec![protocol::ControlReply::Missing { id: 9 }],
        );
        let err = detach_client(&bx, 9, None).await.unwrap_err().to_string();
        assert!(err.contains("no client 9"), "{err}");
        assert!(err.contains("dev"), "{err}");
        agent.join().unwrap();
    }

    /// `detach --all` counts what the guest dropped - the number `terra`
    /// prints.
    #[tokio::test]
    async fn detach_all_counts_the_detached() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _lock, _home, agent) = spawn_fake_agent(
            dir.path(),
            protocol::ControlRequest::DetachAll,
            vec![
                protocol::ControlReply::Detached { id: 0 },
                protocol::ControlReply::Detached { id: 1 },
                protocol::ControlReply::Done,
            ],
        );
        assert_eq!(detach_all(&bx, None).await.unwrap(), 2);
        agent.join().unwrap();
    }

    /// An empty session is answered with just `Done` - nothing dropped is
    /// still an honest answer, not an error.
    #[tokio::test]
    async fn detach_all_on_an_empty_session_counts_zero() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _lock, _home, agent) = spawn_fake_agent(
            dir.path(),
            protocol::ControlRequest::DetachAll,
            vec![protocol::ControlReply::Done],
        );
        assert_eq!(detach_all(&bx, None).await.unwrap(), 0);
        agent.join().unwrap();
    }

    /// The one answer a stopped box has: the verb names the live agent as the
    /// thing the box has to be booted for, the same message every agent-bound
    /// verb gives, so a script sees one spelling of "not running".
    #[tokio::test]
    async fn a_stopped_box_refuses_sessions_and_detach() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();

        let err = list_clients(&bx, None).await.unwrap_err().to_string();
        assert!(err.contains("is not running"), "{err}");
        assert!(err.contains("terra dev -d"), "{err}");
        assert!(detach_client(&bx, 1, None).await.is_err());
        assert!(detach_all(&bx, None).await.is_err());
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
        for verb in ["exec", "sync"] {
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
    #[tokio::test]
    async fn an_exec_whose_reader_left_ends_rather_than_pumping_into_a_closed_pipe() {
        // More output than any reader took, and no exit frame within it: only
        // noticing the closed sink can end this.
        let flood = |make_output: fn(Vec<u8>) -> AgentOutput| -> Vec<u8> {
            std::iter::repeat_with(|| {
                protocol::encode_frame(&make_output(b"tick\n".to_vec())).unwrap()
            })
            .take(64)
            .flatten()
            .collect()
        };

        let status = pump_exec_output(
            frame_reader(flood(AgentOutput::Out)).await,
            &mut ClosedPipe,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert_eq!(status, SHELL_SIGPIPE_STATUS);
        // stderr is the same pipe under `2>&1 | head`, so it ends the same way.
        let status = pump_exec_output(
            frame_reader(flood(AgentOutput::Err)).await,
            &mut Vec::new(),
            &mut ClosedPipe,
        )
        .await
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
        .flat_map(|f| protocol::encode_frame(f).unwrap())
        .collect();
        let status = pump_exec_output(frame_reader(wire).await, &mut out, &mut err)
            .await
            .unwrap();
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
    #[tokio::test]
    async fn a_session_whose_reader_left_detaches_rather_than_pumping_forever() {
        // No exit frame within it: only noticing the closed sink can end this.
        let flood: Vec<u8> = std::iter::repeat_with(|| {
            protocol::encode_frame(&AgentOutput::Out(b"tick\n".to_vec())).unwrap()
        })
        .take(64)
        .flatten()
        .collect();
        let outcome = pump_session_output(frame_reader(flood).await, &mut ClosedPipe)
            .await
            .unwrap();
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
    #[tokio::test]
    async fn a_session_ends_on_the_status_it_was_given_or_says_it_never_got_one() {
        let (outcome, shown) = session_output(&[
            AgentOutput::Out(b"building\n".to_vec()),
            AgentOutput::Exit { code: 3 },
        ])
        .await;
        assert_eq!(outcome, SessionOutcome::Exited(3));
        assert_eq!(shown, b"building\n", "the terminal output must still land");

        assert_eq!(
            session_output(&[AgentOutput::Exit { code: 0 }]).await.0,
            SessionOutcome::Exited(0)
        );

        assert_eq!(session_output(&[]).await.0, SessionOutcome::Closed);
        assert_eq!(
            session_output(&[AgentOutput::Out(b"half a boot\n".to_vec())])
                .await
                .0,
            SessionOutcome::Closed
        );

        let mut truncated =
            protocol::encode_frame(&AgentOutput::Out(b"0123456789".to_vec())).unwrap();
        truncated.truncate(7);
        assert!(
            pump_session_output(frame_reader(truncated).await, &mut Vec::new())
                .await
                .is_err(),
            "a truncated frame must not read as a clean end"
        );
    }

    /// `terra <box> detach` drops the client from the agent's side: the frame
    /// it sends turns the EOF that follows into a detach, so the kicked
    /// terminal reads "detached, box keeps running" rather than "box died" -
    /// the same outcome as the detach key, and what lets a script tell the two
    /// apart. An exec is never detached, so there the frame is a protocol
    /// error.
    #[tokio::test]
    async fn a_detach_frame_ends_the_session_as_a_detach() {
        let wire: Vec<u8> = [AgentOutput::Out(b"bye\n".to_vec()), AgentOutput::Detached]
            .iter()
            .flat_map(|f| protocol::encode_frame(f).unwrap())
            .collect();
        let mut shown = Vec::new();
        let outcome = pump_session_output(frame_reader(wire).await, &mut shown)
            .await
            .unwrap();
        assert_eq!(outcome, SessionOutcome::Detached);
        assert_eq!(
            shown, b"bye\n",
            "the output before the detach must still land"
        );

        let err = pump_exec_output(
            frame_reader(protocol::encode_frame(&AgentOutput::Detached).unwrap()).await,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("detach"), "{err}");
    }

    #[tokio::test]
    async fn input_keeps_a_fragmented_output_frame_intact() {
        use tokio::io::AsyncWriteExt as _;

        let (host, mut peer) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(host);
        let (input_sender, input) = tokio::sync::mpsc::channel(1);
        let (fragment_sent, fragment_seen) = tokio::sync::oneshot::channel();
        let peer_task = tokio::spawn(async move {
            let output = protocol::encode_frame(&AgentOutput::Out(b"hello\n".to_vec())).unwrap();
            peer.write_all(&output[..2]).await.unwrap();
            fragment_sent.send(()).unwrap();
            assert_eq!(
                protocol::read_frame_async(&mut peer).await.unwrap(),
                Some(ClientInput::Keys(b"input".to_vec()))
            );
            peer.write_all(&output[2..]).await.unwrap();
            protocol::write_frame_async(&mut peer, &AgentOutput::Exit { code: 7 })
                .await
                .unwrap();
        });
        fragment_seen.await.unwrap();
        input_sender
            .send(Input::Frame(ClientInput::Keys(b"input".to_vec())))
            .await
            .unwrap();

        let mut shown = Vec::new();
        assert!(matches!(
            pump_stream(
                reader,
                writer,
                input,
                false,
                &mut shown,
                None,
                "reading output"
            )
            .await,
            Ok(PumpResult::Exit(7))
        ));
        assert_eq!(shown, b"hello\n");
        peer_task.await.unwrap();
    }

    #[tokio::test]
    async fn exit_stops_a_writer_blocked_by_full_input() {
        let (host, mut peer) = tokio::io::duplex(1);
        let (reader, writer) = tokio::io::split(host);
        let (input_sender, input) = tokio::sync::mpsc::channel(1);
        input_sender
            .send(Input::Frame(ClientInput::Keys(vec![0; 1024])))
            .await
            .unwrap();
        let (can_exit, wait_for_input) = tokio::sync::oneshot::channel();
        let producer = async move {
            tokio::task::yield_now().await;
            input_sender
                .send(Input::Frame(ClientInput::Keys(vec![1; 1024])))
                .await
                .unwrap();
            can_exit.send(()).unwrap();
            input_sender
                .send(Input::Frame(ClientInput::Keys(vec![2; 1024])))
                .await
        };
        let peer_task = async move {
            wait_for_input.await.unwrap();
            protocol::write_frame_async(&mut peer, &AgentOutput::Exit { code: 0 })
                .await
                .unwrap();
        };
        let mut shown = Vec::new();
        let complete = tokio::time::timeout(Duration::from_secs(1), async {
            let (result, producer, peer) = tokio::join!(
                pump_stream(
                    reader,
                    writer,
                    input,
                    false,
                    &mut shown,
                    None,
                    "reading output"
                ),
                producer,
                peer_task,
            );
            (result, producer, peer)
        })
        .await
        .expect("exit did not stop the blocked input writer");

        assert!(matches!(complete.0, Ok(PumpResult::Exit(0))));
        assert!(complete.1.is_err());
    }
}
