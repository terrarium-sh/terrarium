//! The agent's exec service: one `terra exec` per connection - one PTY (or one
//! pair of pipes), one process, one exit status. What sets it apart from a
//! session is documented on [`terra_shared::AgentService`].

use crate::term::session::{MAX_COLS, MAX_ROWS, MIN_COLS, MIN_ROWS};
use crate::term::tty::set_winsize;
use crate::vsock::VsockStream;
use anyhow::Result;
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use terra_shared::{AgentOutput, ClientInput, ExecRequest, TermSize};

/// What an exec reports when the command could not be started at all - 127 is
/// the shell's "command not found", which is what this almost always is.
const EXEC_NOT_RUN: i32 = 127;

/// What an exec reports when the command *started* but the plumbing around it
/// failed and it was killed - 126, the shell's "found but could not run", so a
/// script can tell it from a command that never existed.
const EXEC_ABANDONED: i32 = 126;

/// One `terra exec`: a framed [`ExecRequest`], then a terminal or a pair of
/// pipes of its own until the command exits.
///
/// `workload_root` is what the *box* runs as; an exec into a `--root` box is
/// root either way, since that box never created the `terri` user.
///
/// A root-capable channel, deliberately: the file port already writes any path
/// as init, so this is not new authority - and unlike a `sudo:` grant it is
/// host-initiated only (see the host-CID check on accept).
pub fn serve_exec(mut conn: VsockStream, workload_root: bool) {
    let Ok(req) = terra_shared::read_frame::<ExecRequest>(&mut conn) else {
        return;
    };
    let Some((cmd, args)) = req.argv.split_first() else {
        let _ = send_exec(&mut conn, &AgentOutput::Exit(EXEC_NOT_RUN));
        return;
    };
    let as_root = req.as_root || workload_root;
    match req.tty {
        Some(TermSize { rows, cols }) => exec_on_pty(conn, rows, cols, cmd, args, as_root),
        None => exec_on_pipes(conn, cmd, args, as_root),
    }
}

fn send_exec<C: std::io::Write>(conn: &mut C, frame: &AgentOutput) -> bool {
    conn.write_all(&frame.encode()).is_ok()
}

/// The command could not be started: say so where the person will see it
/// (`\r\n` on a PTY, because the client's terminal is raw there).
fn exec_failed<C: std::io::Write>(conn: &mut C, cmd: &str, e: &anyhow::Error, tty: bool) {
    // `{e}`, not `{e:#}`: `pty_process::Error` already renders the io error it
    // wraps, so the chained form said it twice.
    let message = if tty {
        AgentOutput::Out(format!("terra: cannot run {cmd}: {e}\r\n").into_bytes())
    } else {
        AgentOutput::Err(format!("terra: cannot run {cmd}: {e}\n").into_bytes())
    };
    send_exec(conn, &message);
    send_exec(conn, &AgentOutput::Exit(EXEC_NOT_RUN));
}

/// The command started, but the plumbing around it did not - so nothing will
/// ever pump its output or collect its status. Take it down rather than leave it
/// running unattended, and still answer: the host is owed exactly one frame it
/// can `exit` with, and without it a script sees "the box stopped" instead.
fn exec_abandoned<C: std::io::Write>(conn: &mut C, child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = crate::reap::wait_owned(child);
    send_exec(conn, &AgentOutput::Exit(EXEC_ABANDONED));
}

/// The command's exit status - `128 + signal` for a signal death, as the shell
/// spells it - or [`EXEC_NOT_RUN`] when there is no status to report at all.
/// The one reading of a child's status: an exec's, and the workload's own
/// (in `init::run_workload`), so a box and a command spell a signal death
/// the same way.
#[must_use]
pub(crate) fn exit_code(child: &mut std::process::Child) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    crate::reap::wait_owned(child)
        .ok()
        .and_then(|s| s.code().or_else(|| s.signal().map(|sig| 128 + sig)))
        .unwrap_or(EXEC_NOT_RUN)
}

/// An interactive exec: one PTY, one process, output and errors interleaved on
/// the single stream a terminal has.
///
/// ponytail: returns when the PTY closes, so a command that leaves a child
/// holding the terminal (`sh -c 'daemon &'`) keeps the exec attached - the same
/// ceiling the workload's run has, and the same one `ssh` is famous for. Closing the
/// master from the reaper thread would fix it and would race every read here;
/// worth it only if backgrounding through exec turns out to be common.
fn exec_on_pty(
    mut conn: VsockStream,
    rows: u16,
    cols: u16,
    cmd: &str,
    args: &[String],
    as_root: bool,
) {
    use std::io::Write;

    let home = terra_shared::workload_home();
    let (pty, mut child) =
        match crate::init::spawn_on_pty(cmd, args, rows, cols, as_root, Some(&home)) {
            Ok(pair) => pair,
            Err(e) => return exec_failed(&mut conn, cmd, &e, true),
        };

    let master: OwnedFd = pty.into();
    let Ok(reader) = master.try_clone() else {
        return exec_abandoned(&mut conn, &mut child);
    };
    let mut input = std::fs::File::from(master);
    let master_fd = input.as_raw_fd();

    // Client -> PTY, on its own thread: keystrokes, resizes, end of input. It
    // ends when the host closes the connection, which it does once it has the
    // exit status.
    let Ok(mut from_host) = conn.try_clone() else {
        return exec_abandoned(&mut conn, &mut child);
    };
    std::thread::spawn(move || {
        loop {
            match ClientInput::read(&mut from_host) {
                Ok(Some(ClientInput::Keys(b))) => {
                    if input.write_all(&b).and_then(|()| input.flush()).is_err() {
                        break;
                    }
                }
                Ok(Some(ClientInput::Resize { rows, cols })) if rows > 0 && cols > 0 => {
                    set_winsize(
                        master_fd,
                        rows.clamp(MIN_ROWS, MAX_ROWS),
                        cols.clamp(MIN_COLS, MAX_COLS),
                    );
                }
                Ok(Some(ClientInput::Resize { .. })) => {}
                // A PTY cannot be half-closed, so end-of-input is the byte a real
                // terminal sends for it. The line discipline turns it into EOF for
                // a command reading in canonical mode.
                Ok(Some(ClientInput::Eof)) => {
                    let _ = input.write_all(&[0x04]).and_then(|()| input.flush());
                }
                Ok(None) | Err(_) => break,
            }
        }
    });

    // PTY -> client, on this thread, so the exit status below cannot overtake the
    // output it belongs to: one writer, in order.
    let mut reader = std::fs::File::from(reader);
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if !send_exec(&mut conn, &AgentOutput::Out(buf[..n].to_vec())) {
                    break;
                }
            }
        }
    }
    send_exec(&mut conn, &AgentOutput::Exit(exit_code(&mut child)));
    // Unblock the input thread, which holds a clone of this socket and the PTY
    // master: without this a host that keeps the connection open leaks both.
    conn.shutdown(std::net::Shutdown::Read);
}

/// A non-interactive exec: plain pipes, so the command's bytes reach the host
/// unaltered and its two output streams stay apart.
fn exec_on_pipes(mut conn: VsockStream, cmd: &str, args: &[String], as_root: bool) {
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    let started = (|| -> Result<std::process::Child> {
        let mut command = std::process::Command::new(cmd);
        command
            .args(args)
            .env("HOME", terra_shared::workload_home())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if !as_root {
            // SAFETY: as in `spawn_on_pty` - async-signal-safe id-setting only.
            unsafe {
                command.pre_exec(crate::init::drop_privileges);
            }
        }
        Ok(crate::reap::spawn_owned(|| command.spawn())?)
    })();
    let mut child = match started {
        Ok(child) => child,
        Err(e) => return exec_failed(&mut conn, cmd, &e, false),
    };

    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return exec_abandoned(&mut conn, &mut child);
    };

    // Client -> the command's stdin. Unlike the PTY path this can be closed for
    // real, which is what makes `… | terra exec dev -- cat` terminate.
    let Ok(mut from_host) = conn.try_clone() else {
        return exec_abandoned(&mut conn, &mut child);
    };
    std::thread::spawn(move || {
        let mut open = Some(stdin);
        loop {
            match ClientInput::read(&mut from_host) {
                Ok(Some(ClientInput::Keys(b))) => {
                    let Some(w) = open.as_mut() else { continue };
                    if w.write_all(&b).and_then(|()| w.flush()).is_err() {
                        break;
                    }
                }
                Ok(Some(ClientInput::Eof)) => drop(open.take()),
                // No terminal, so nothing has a size.
                Ok(Some(ClientInput::Resize { .. })) => {}
                Ok(None) | Err(_) => break,
            }
        }
    });

    // Both output streams share one socket, so they share one lock - and the
    // exit status is sent only after both have ended, so it cannot overtake the
    // bytes it belongs to.
    let out = Arc::new(Mutex::new(conn));
    let o = pump(stdout, out.clone(), AgentOutput::Out);
    let e = pump(stderr, out.clone(), AgentOutput::Err);
    let _ = o.join();
    let _ = e.join();

    let code = exit_code(&mut child);
    let mut w = out
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    send_exec(&mut *w, &AgentOutput::Exit(code));
    // Unblock the input thread, which holds a clone of this socket: without
    // this a host that keeps the connection open leaks a thread per exec.
    w.shutdown(std::net::Shutdown::Read);
}

/// Forward one output stream to the shared socket, each chunk wrapped by
/// `wrap` - [`AgentOutput::Out`] or [`AgentOutput::Err`].
fn pump<R: Read + Send + 'static>(
    mut src: R,
    out: Arc<Mutex<VsockStream>>,
    wrap: fn(Vec<u8>) -> AgentOutput,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match src.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut w = out
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if !send_exec(&mut *w, &wrap(buf[..n].to_vec())) {
                        break;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    /// What [`do_exec`] reports when no exit frame arrived before the deadline.
    /// Not a status any command can return, so a test cannot mistake it for one.
    const NO_EXIT: i32 = i32::MIN;

    /// Ceiling on one harness exec.
    ///
    /// A regression here is usually a *hang* rather than a wrong answer - take
    /// away the stdin close and `cat` reads forever - and a suite that hangs is
    /// worse than one that fails. Verified by mutation: every check below fails,
    /// none of them hang.
    const HARNESS_TIMEOUT: Duration = Duration::from_secs(20);

    /// Drive one [`serve_exec`] over a socketpair, the way `do_op` drives the
    /// file port. Returns what came back on each stream and the exit status.
    ///
    /// `workload_root` is always true, so `as_root` is too and the privilege drop
    /// is skipped: the test process is not root, and `setuid(1000)` from it fails
    /// with EPERM. What that costs is coverage of the drop itself, which needs a
    /// real box - the boot suite asserts `id -u` on both sides of it.
    fn do_exec(argv: &[&str], is_tty: bool, stdin: &[u8]) -> (Vec<u8>, Vec<u8>, i32) {
        let req = ExecRequest {
            argv: argv.iter().map(ToString::to_string).collect(),
            as_root: false,
            tty: is_tty.then_some(TermSize { rows: 24, cols: 80 }),
        };
        let (mut client, server) = UnixStream::pair().unwrap();
        client.set_read_timeout(Some(HARNESS_TIMEOUT)).unwrap();
        let server = VsockStream::from(std::os::fd::OwnedFd::from(server));
        let agent = std::thread::spawn(move || serve_exec(server, true));
        client
            .write_all(&terra_shared::frame(&req).unwrap())
            .unwrap();
        if !stdin.is_empty() {
            client
                .write_all(&ClientInput::Keys(stdin.to_vec()).encode())
                .unwrap();
        }
        // Always, so a command reading stdin terminates rather than hanging the
        // suite - which is the behaviour under test in one of these.
        client.write_all(&ClientInput::Eof.encode()).unwrap();

        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = loop {
            match AgentOutput::read(&mut client) {
                Ok(Some(AgentOutput::Out(b))) => out.extend_from_slice(&b),
                Ok(Some(AgentOutput::Err(b))) => err.extend_from_slice(&b),
                Ok(Some(AgentOutput::Exit(c))) => break c,
                // A detach frame is just a dead exec connection: no status, same failure.
                Ok(Some(AgentOutput::Detached) | None) | Err(_) => break NO_EXIT,
            }
        };
        // Joining would hang on exactly the regressions the deadline exists to
        // catch, since `serve_exec` is still waiting on a child that will not
        // exit. Only join when the command really finished; otherwise let the
        // thread and its child go with the test process.
        if code != NO_EXIT {
            agent.join().unwrap();
        }
        (out, err, code)
    }

    /// A pipe exec is the scripted one, and every one of these is something a
    /// PTY would have broken: it merges stderr into stdout, rewrites `\n` as
    /// `\r\n`, and echoes its input back. `terra exec dev -- cat f > out` needs
    /// all three not to happen.
    #[test]
    fn a_pipe_exec_keeps_the_streams_apart_and_the_bytes_intact() {
        let (out, err, code) = do_exec(&["sh", "-c", "echo OUT; echo ERR >&2; exit 3"], false, b"");
        assert_eq!(String::from_utf8_lossy(&out), "OUT\n");
        assert_eq!(String::from_utf8_lossy(&err), "ERR\n");
        assert_eq!(code, 3, "the command's own status must come back");

        // No CRLF translation, and no echo of what was fed in.
        let (out, _, code) = do_exec(&["printf", "a\nb\n"], false, b"unread input");
        assert_eq!(out, b"a\nb\n");
        assert_eq!(code, 0);
    }

    /// The end of the host's stdin has to reach the command as a real EOF, or a
    /// reader never returns. This is what [`ClientInput::Eof`] exists for: the
    /// host cannot send the `\x04` itself, because on a pipe that byte is data.
    #[test]
    fn a_pipe_exec_closes_stdin_so_a_reader_terminates() {
        let (out, _, code) = do_exec(&["cat"], false, b"payload\n");
        assert_eq!(out, b"payload\n");
        assert_eq!(code, 0, "cat did not see EOF");
    }

    /// The interactive half. A PTY is what makes an exec'd shell usable, and the
    /// three things it does to the stream are exactly the ones the pipe path must
    /// not: `isatty` answers yes, and `\n` comes back as `\r\n`.
    #[test]
    fn a_tty_exec_gets_a_real_terminal() {
        let (out, err, code) = do_exec(
            &["sh", "-c", "test -t 1 && echo yes; echo ERR >&2; exit 3"],
            true,
            b"",
        );
        let seen = String::from_utf8_lossy(&out);
        assert!(seen.contains("yes"), "not a terminal: {seen:?}");
        assert!(seen.contains("\r\n"), "no cooked-mode CRLF: {seen:?}");
        // A terminal has one stream, so stderr arrives interleaved rather than
        // on its own frames - the opposite of the pipe case above, deliberately.
        assert!(seen.contains("ERR"), "stderr should interleave: {seen:?}");
        assert!(err.is_empty(), "a PTY exec has no separate stderr: {err:?}");
        // Asserted on a *failing* command: the two paths reap their child
        // separately, so a status this one hardcoded would pass unnoticed
        // against a command that succeeds.
        assert_eq!(code, 3, "a PTY exec must report the command's own status");
    }

    /// A command killed by a signal reports `128 + signal`, the shell's own
    /// spelling - not 127, which claims the command never ran.
    #[test]
    fn a_signal_killed_command_reports_128_plus_the_signal() {
        for tty in [false, true] {
            let (_, _, code) = do_exec(&["sh", "-c", "kill -TERM $$"], tty, b"");
            assert_eq!(code, 128 + libc::SIGTERM, "tty={tty}");
        }
    }

    /// A command that cannot start still owes the caller an exit status - and
    /// 127 rather than 0, since a script's `&&` hangs off it. Terra's own
    /// diagnostic goes down stderr on a pipe exec, so `terra exec … > out`
    /// keeps the output file clean; a PTY has only the one stream.
    #[test]
    fn an_exec_that_cannot_start_reports_127() {
        let (out, err, code) = do_exec(&["/no/such/command"], false, b"");
        assert_eq!(code, EXEC_NOT_RUN);
        assert!(
            String::from_utf8_lossy(&err).contains("cannot run"),
            "the reason should reach stderr, not the output: {out:?} / {err:?}"
        );
        assert!(out.is_empty(), "{out:?}");

        let (out, _, code) = do_exec(&["/no/such/command"], true, b"");
        assert_eq!(code, EXEC_NOT_RUN);
        assert!(
            String::from_utf8_lossy(&out).contains("cannot run"),
            "the reason should reach the terminal"
        );

        // …and an empty argv, which no CLI can produce but the wire can.
        let (_, _, code) = do_exec(&[], false, b"");
        assert_eq!(code, EXEC_NOT_RUN);
    }

    /// HOME is the one thing a command does not inherit correctly: PID 1's is
    /// the *workload's*, so an exec sets it again for itself - the same
    /// `/home/terri` whether it runs as root or not. (`do_exec` runs as root,
    /// per its note.)
    #[test]
    fn an_exec_gets_the_workloads_home() {
        let (out, _, code) = do_exec(&["sh", "-c", "echo $HOME"], false, b"");
        assert_eq!(String::from_utf8_lossy(&out), "/home/terri\n");
        assert_eq!(code, 0);
    }
}
