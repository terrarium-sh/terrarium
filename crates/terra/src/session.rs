//! The host end of the agent's ports: how terra reaches one, and how it pumps
//! bytes between that port and the user's terminal.

use crate::state::{BoxRef, Holder};
use crate::sys::{self, POLL};
use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use terra_agent::{AgentOutput, AgentService, ClientInput, TermSize};

const AGENT_HELLO_WAIT_TIMEOUT: Duration = Duration::from_millis(500);

const SILENT_BOOT_GRACE: Duration = Duration::from_secs(15);

pub fn terminal_size() -> Option<TermSize> {
    let (cols, rows) = crossterm::terminal::size().ok()?;
    (rows > 0 && cols > 0).then_some(TermSize { rows, cols })
}

pub const DEFAULT_TERMINAL_SIZE: TermSize = TermSize { rows: 24, cols: 80 };

/// A control byte, not a bare letter the workload wants.
/// NOTE: Not ESC - every arrow key sends that
pub const DETACH_KEY: u8 = 0x1C;

const SHELL_SIGPIPE_STATUS: i32 = 128 + libc::SIGPIPE;

pub fn detach_key_name() -> String {
    format!("Ctrl-{}", (DETACH_KEY | 0x40) as char)
}

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
    let sock = bx.agent_sock();
    let mut hint_at = Some(Instant::now() + SILENT_BOOT_GRACE);
    loop {
        if hint_at.is_some_and(|at| Instant::now() > at) {
            hint_at = None;
            eprintln!(
                "terra: still waiting for {bx}'s {what} - `{}` shows the boot so far",
                bx.logs_command()
            );
        }
        still_waiting()?;
        if let Ok(stream) = UnixStream::connect(&sock) {
            let _ = stream.set_read_timeout(Some(AGENT_HELLO_WAIT_TIMEOUT));
            let mut hello = [0u8; 1];
            if let Ok(1) = (&stream).read(&mut hello) {
                anyhow::ensure!(
                    hello[0] == terra_agent::AGENT_HELLO,
                    "the agent in {bx} does not speak this terra's protocol - \
                     `terra stop` it and start it again on this build"
                );
                let _ = stream.set_read_timeout(None);
                (&stream)
                    .write_all(&[service as u8])
                    .with_context(|| format!("asking {bx}'s agent for its {what}"))?;
                return Ok(stream);
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
    match bx.holder() {
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
            bx.name()
        ),
    )
}

fn wait_while_running(bx: &BoxRef, timeout: Option<u64>) -> impl FnMut() -> Result<()> {
    let deadline = timeout.map(|secs| (sys::deadline_after(Duration::from_secs(secs)), secs));
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
    w.write_all(&msg.encode()).and_then(|()| w.flush()).is_ok()
}

/// Polled rather than driven by SIGWINCH: sending a frame takes the writer's
/// mutex and allocates, neither of which a signal handler may do.
fn spawn_resize_reporter(writer: Arc<Mutex<UnixStream>>) {
    std::thread::spawn(move || {
        let mut last = None;
        loop {
            if let Some(size) = terminal_size()
                && last != Some(size)
            {
                last = Some(size);
                let resize = ClientInput::Resize {
                    rows: size.rows,
                    cols: size.cols,
                };
                if !send_frame(&writer, &resize) {
                    break;
                }
            }
            std::thread::sleep(POLL);
        }
    });
}

fn spawn_stdin_reader(
    writer: Arc<Mutex<UnixStream>>,
    escape: Option<u8>,
    action: StdinEndAction,
) -> Arc<AtomicBool> {
    let detached = Arc::new(AtomicBool::new(false));
    let detached_flag = detached.clone();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        while let Ok(n @ 1..) = stdin.read(&mut buf) {
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
    detached
}

/// The stdin and resize threads of one session, sharing the write half behind
/// a mutex so their frames cannot interleave. The returned flag is set when
/// the detach byte ended input.
fn spawn_input_threads(
    stream: &UnixStream,
    escape: Option<u8>,
    action: StdinEndAction,
    report_resizes: bool,
) -> Result<Arc<AtomicBool>> {
    let writer = Arc::new(Mutex::new(
        stream.try_clone().context("cloning attach socket")?,
    ));
    // A piped exec has no terminal whose size could change.
    if report_resizes {
        spawn_resize_reporter(writer.clone());
    }
    Ok(spawn_stdin_reader(writer, escape, action))
}

/// Write one chunk of the command's output; `false` means the reader left,
/// which ends the pump.
fn write_chunk(sink: &mut impl Write, bytes: &[u8]) -> bool {
    sink.write_all(bytes).and_then(|()| sink.flush()).is_ok()
}

/// Run one exec to completion and hand back the command's exit status.
///
/// `tty` says the command got a PTY, which is when this end needs raw mode
/// too: without it the local terminal would hold keystrokes until a newline
/// and turn Ctrl-C into a signal for terra itself. A piped exec keeps stderr
/// in its own frame, so redirecting it away still works.
pub fn pump_exec(stream: &UnixStream, tty: bool) -> Result<i32> {
    let _raw_terminal_context = tty.then(RawTerminal::enable);
    let _never_detaches = spawn_input_threads(stream, None, StdinEndAction::SendEof, tty)?;

    pump_exec_output(stream, &mut std::io::stdout(), &mut std::io::stderr())
}

/// Copy one command's output to `out` and `err` until it ends, and hand back
/// the exit status.
///
/// Split out so the frame handling can be tested without a terminal or the
/// stdin threads that go with a real exec.
fn pump_exec_output(
    mut reader: impl Read,
    out: &mut impl Write,
    err: &mut impl Write,
) -> Result<i32> {
    // Every chunk is flushed as it arrives: a TUI's repaints rarely end in a
    // newline, so line buffering would hold them back.
    loop {
        match AgentOutput::read(&mut reader) {
            Ok(Some(AgentOutput::Out(bytes))) => {
                if !write_chunk(out, &bytes) {
                    return Ok(SHELL_SIGPIPE_STATUS);
                }
            }
            Ok(Some(AgentOutput::Err(bytes))) => {
                if !write_chunk(err, &bytes) {
                    return Ok(SHELL_SIGPIPE_STATUS);
                }
            }
            Ok(Some(AgentOutput::Exit(code))) => return Ok(code),
            // A stream that ends without an exit frame means the box died
            // mid-command; success would hide that from scripts checking exit
            // codes.
            Ok(None) => anyhow::bail!("the box stopped before the command finished"),
            Err(e) => return Err(e).context("reading the command's output"),
        }
    }
}

/// Run the session until the detach key is pressed or the stream ends.
pub fn pump_session(stream: &UnixStream) -> Result<SessionOutcome> {
    let _raw_terminal_context = RawTerminal::enable();
    let detached =
        spawn_input_threads(stream, Some(DETACH_KEY), StdinEndAction::CloseSocket, true)?;

    let ended = pump_session_output(stream, &mut std::io::stdout());
    // The detach key wins over anything the stream did next: the close is the
    // detach, so the EOF that follows is this client leaving, not the box
    // stopping.
    if detached.load(Ordering::SeqCst) {
        return Ok(SessionOutcome::Detached);
    }
    ended
}

/// Copy one session's output to `out` until it ends, and say how it ended.
fn pump_session_output(mut reader: impl Read, out: &mut impl Write) -> Result<SessionOutcome> {
    // Flushed per chunk, as an exec's is.
    loop {
        match AgentOutput::read(&mut reader) {
            Ok(Some(AgentOutput::Out(bytes) | AgentOutput::Err(bytes))) => {
                if !write_chunk(out, &bytes) {
                    return Ok(SessionOutcome::Detached);
                }
            }
            Ok(Some(AgentOutput::Exit(code))) => return Ok(SessionOutcome::Exited(code)),
            Ok(None) => return Ok(SessionOutcome::Closed),
            // An unreadable stream is not a workload that ended: say so rather
            // than hand back a status nobody sent.
            Err(e) => return Err(e).context("reading the box's terminal"),
        }
    }
}

struct RawTerminal {
    enabled: bool,
}

impl RawTerminal {
    /// Raw mode for as long as the returned guard lives: dropping it puts the
    /// terminal back, so an error path can't leave the shell wedged.
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
        std::fs::create_dir_all(bx.dir()).unwrap();
        let lock = bx.lock_run().unwrap();

        let baking = bx.mark_baking(&lock);
        for verb in ["exec", "cp"] {
            let err = ensure_running(&bx, verb).unwrap_err().to_string();
            assert_eq!(err, bx.setup_holds_it().to_string(), "{verb}");
        }

        // The mark goes with the bake, and what is left is an ordinary held box.
        drop(baking);
        assert!(ensure_running(&bx, "exec").is_ok());

        // …and a `terra setup` that takes the box after the wait has begun is
        // the same refusal: the box is still held, so a wait asking only
        // whether anyone holds it sat through the whole bake.
        let mut still_waiting = wait_while_running(&bx, None);
        assert!(still_waiting().is_ok(), "a served box is waited on");
        let baking = bx.mark_baking(&lock);
        let err = still_waiting()
            .expect_err("a bake that took the box mid-wait was waited out")
            .to_string();
        assert_eq!(err, bx.setup_holds_it().to_string());
        drop(baking);
        assert!(still_waiting().is_ok());

        // A box nobody holds is the other end of it, and reads as a stop.
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
        let flood = |frame: fn(Vec<u8>) -> AgentOutput| -> Vec<u8> {
            std::iter::repeat_with(|| frame(b"tick\n".to_vec()))
                .take(64)
                .flat_map(|f| f.encode())
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
            AgentOutput::Exit(3),
        ]
        .iter()
        .flat_map(AgentOutput::encode)
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
        let flood: Vec<u8> = std::iter::repeat_with(|| AgentOutput::Out(b"tick\n".to_vec()))
            .take(64)
            .flat_map(|f| f.encode())
            .collect();
        let outcome = pump_session_output(std::io::Cursor::new(flood), &mut ClosedPipe).unwrap();
        assert_eq!(outcome, SessionOutcome::Detached);
    }

    #[test]
    fn the_escape_key_is_named_the_way_a_terminal_spells_it() {
        assert_eq!(detach_key_name(), "Ctrl-\\");
        // Not ESC, which every arrow key sends.
        assert_ne!(DETACH_KEY, 0x1B);
    }

    /// A session ends on the workload's status, and the difference between
    /// hearing one and not hearing one is what a joiner exits with: a box that
    /// finished is not the same event as a VM that was killed under it, and a
    /// bare EOF used to be the only spelling of both.
    #[test]
    fn a_session_ends_on_the_status_it_was_given_or_says_it_never_got_one() {
        let session = |frames: &[AgentOutput]| {
            let wire: Vec<u8> = frames.iter().flat_map(AgentOutput::encode).collect();
            let mut shown = Vec::new();
            let outcome = pump_session_output(std::io::Cursor::new(wire), &mut shown).unwrap();
            (outcome, shown)
        };

        // Output, then the status the workload ended with.
        let (outcome, shown) = session(&[
            AgentOutput::Out(b"building\n".to_vec()),
            AgentOutput::Exit(3),
        ]);
        assert_eq!(outcome, SessionOutcome::Exited(3));
        assert_eq!(shown, b"building\n", "the terminal output must still land");

        // A success is a status like any other, not the absence of one.
        assert_eq!(
            session(&[AgentOutput::Exit(0)]).0,
            SessionOutcome::Exited(0)
        );

        // The stream ending with nothing behind it: the VM went away.
        assert_eq!(session(&[]).0, SessionOutcome::Closed);
        assert_eq!(
            session(&[AgentOutput::Out(b"half a boot\n".to_vec())]).0,
            SessionOutcome::Closed
        );

        // A frame cut mid-payload is a broken stream, never a status.
        let mut truncated = AgentOutput::Out(b"0123456789".to_vec()).encode();
        truncated.truncate(7);
        assert!(
            pump_session_output(std::io::Cursor::new(truncated), &mut Vec::new()).is_err(),
            "a truncated frame must not read as a clean end"
        );
    }
}
