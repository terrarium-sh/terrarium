//! The agent's exec service: one command execution per connection.

use crate::term::session::{MAX_COLS, MAX_ROWS, MIN_COLS, MIN_ROWS};
use crate::term::tty::set_winsize;
use std::fmt::Display;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::mpsc;
use terra_shared::contract::{
    AgentOutput, ClientInput, ExecRequest, TermSize, encode_frame, read_frame,
};

const EXEC_NOT_RUN: i32 = 127;

/// Executes a command request until exit.
///
/// A root-capable channel, deliberately: host-initiated only, matching the file port's authority.
pub fn serve_exec(mut conn: File, workload_root: bool) {
    let Ok(Some(req)) = read_frame::<ExecRequest>(&mut conn) else {
        let _ = send_exec(&mut conn, &AgentOutput::Exit { code: EXEC_NOT_RUN });
        return;
    };
    let Some((cmd, args)) = req.argv.split_first() else {
        let _ = send_exec(&mut conn, &AgentOutput::Exit { code: EXEC_NOT_RUN });
        return;
    };
    let as_root = req.as_root || workload_root;
    match req.tty {
        Some(TermSize { rows, cols }) => run_exec_on_pty(conn, rows, cols, cmd, args, as_root),
        None => run_exec_on_pipes(conn, cmd, args, as_root),
    }
}

fn send_exec<C: std::io::Write>(conn: &mut C, msg: &AgentOutput) -> bool {
    let Ok(bytes) = encode_frame(msg) else {
        return false;
    };
    conn.write_all(&bytes).is_ok()
}

fn report_exec_failure<C: std::io::Write>(conn: &mut C, cmd: &str, e: impl Display, tty: bool) {
    // `{e}`, not `{e:#}`: `pty_process::Error` already renders the io error it
    // wraps, so the chained form said it twice.
    let message = if tty {
        AgentOutput::Out(format!("terra: cannot run {cmd}: {e}\r\n").into_bytes())
    } else {
        AgentOutput::Err(format!("terra: cannot run {cmd}: {e}\n").into_bytes())
    };
    send_exec(conn, &message);
    send_exec(conn, &AgentOutput::Exit { code: EXEC_NOT_RUN });
}

fn abort_exec<C: std::io::Write>(
    conn: &mut C,
    child: &mut std::process::Child,
    child_pidfd: &OwnedFd,
) {
    let _ = rustix::process::pidfd_send_signal(child_pidfd, rustix::process::Signal::KILL);
    let _ = crate::reap::wait_owned(child);
    send_exec(conn, &AgentOutput::Exit { code: EXEC_NOT_RUN });
}

#[allow(unsafe_code)]
fn pump_input(mut src: File, out: impl Write, master_fd: Option<RawFd>, child_pidfd: OwnedFd) {
    let mut stdin = Some(out);
    loop {
        match read_frame::<ClientInput>(&mut src) {
            Ok(Some(ClientInput::Keys(b))) => {
                if stdin.as_mut().is_some_and(|out| out.write_all(&b).is_err()) {
                    break;
                }
            }
            Ok(Some(ClientInput::Resize(TermSize { rows, cols }))) => {
                if let Some(master_fd) = master_fd
                    && rows > 0
                    && cols > 0
                {
                    set_winsize(
                        // SAFETY: `master_fd` is the live PTY master owned by the input thread's
                        // `File`, which outlives this borrow.
                        unsafe { std::os::fd::BorrowedFd::borrow_raw(master_fd) },
                        rows.clamp(MIN_ROWS, MAX_ROWS),
                        cols.clamp(MIN_COLS, MAX_COLS),
                    );
                }
            }
            Ok(Some(ClientInput::Eof)) => match master_fd {
                Some(_) => {
                    if let Some(out) = stdin.as_mut() {
                        let _ = out.write_all(&[0x04]);
                    }
                }
                None => drop(stdin.take()),
            },
            Ok(None) | Err(_) => {
                break;
            }
        }
    }
    let _ = rustix::process::pidfd_send_signal(child_pidfd, rustix::process::Signal::KILL);
}

#[must_use]
pub(crate) fn wait_for_exit_code(child: &mut std::process::Child) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    crate::reap::wait_owned(child)
        .ok()
        .and_then(|s| s.code().or_else(|| s.signal().map(|sig| 128 + sig)))
        .unwrap_or(EXEC_NOT_RUN)
}

/// ponytail: returns when the PTY closes, so a command that leaves a child
/// holding the terminal (`sh -c 'daemon &'`) keeps the exec attached - the same
/// ceiling the workload's run has, and the same one `ssh` is famous for. Closing the
/// master from the reaper thread would fix it and would race every read here;
/// worth it only if backgrounding through exec turns out to be common.
fn run_exec_on_pty(
    mut conn: File,
    rows: u16,
    cols: u16,
    cmd: &str,
    args: &[String],
    as_root: bool,
) {
    let (pty, mut child, child_pidfd) = match crate::init::spawn_on_pty(
        cmd,
        args,
        rows,
        cols,
        as_root,
        Some(terra_shared::contract::WORKLOAD_HOME),
    ) {
        Ok(pair) => pair,
        Err(e) => return report_exec_failure(&mut conn, cmd, e, true),
    };

    let master: OwnedFd = pty.into();
    let Ok(reader) = master.try_clone() else {
        return abort_exec(&mut conn, &mut child, &child_pidfd);
    };
    let input = std::fs::File::from(master);
    let master_fd = input.as_raw_fd();

    let Ok(from_host) = conn.try_clone() else {
        return abort_exec(&mut conn, &mut child, &child_pidfd);
    };
    let Ok(input_pidfd) = child_pidfd.try_clone() else {
        return abort_exec(&mut conn, &mut child, &child_pidfd);
    };
    let input = std::thread::spawn(move || {
        pump_input(from_host, input, Some(master_fd), input_pidfd);
    });

    let mut reader = std::fs::File::from(reader);
    let output_ok = pump_copy(&mut reader, |chunk| {
        send_exec(&mut conn, &AgentOutput::Out(chunk.to_vec()))
    });
    if !output_ok {
        abort_exec(&mut conn, &mut child, &child_pidfd);
        let _ = rustix::net::shutdown(&conn, rustix::net::Shutdown::Both);
        let _ = input.join();
        return;
    }
    send_exec(
        &mut conn,
        &AgentOutput::Exit {
            code: wait_for_exit_code(&mut child),
        },
    );
    // Without this, a host keeping the connection open would leak the socket and PTY master.
    let _ = rustix::net::shutdown(&conn, rustix::net::Shutdown::Read);
    let _ = input.join();
}

#[allow(unsafe_code)]
fn run_exec_on_pipes(mut conn: File, cmd: &str, args: &[String], as_root: bool) {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    let mut command = std::process::Command::new(cmd);
    command
        .args(args)
        .env("HOME", terra_shared::contract::WORKLOAD_HOME)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if !as_root {
        // SAFETY: as in `spawn_on_pty` - async-signal-safe id-setting only.
        unsafe {
            command.pre_exec(crate::init::drop_privileges);
        }
    }
    let (mut child, child_pidfd) = match crate::reap::spawn_owned(|| command.spawn()) {
        Ok(child) => child,
        Err(e) => return report_exec_failure(&mut conn, cmd, e, false),
    };

    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return abort_exec(&mut conn, &mut child, &child_pidfd);
    };

    let Ok(from_host) = conn.try_clone() else {
        return abort_exec(&mut conn, &mut child, &child_pidfd);
    };
    let Ok(input_pidfd) = child_pidfd.try_clone() else {
        return abort_exec(&mut conn, &mut child, &child_pidfd);
    };
    let input = std::thread::spawn(move || pump_input(from_host, stdin, None, input_pidfd));

    let (output_tx, output_rx) = mpsc::sync_channel(16);
    let output_writer = std::thread::spawn(move || {
        let mut conn = conn;
        let output_ok = output_rx
            .into_iter()
            .all(|message| send_exec(&mut conn, &message));
        (conn, output_ok)
    });
    let stdout_pump = pump_stream(stdout, output_tx.clone(), AgentOutput::Out);
    let stderr_pump = pump_stream(stderr, output_tx, AgentOutput::Err);
    let stdout_ok = stdout_pump.join().unwrap_or(false);
    let stderr_ok = stderr_pump.join().unwrap_or(false);
    let Ok((mut conn, output_ok)) = output_writer.join() else {
        let _ = rustix::process::pidfd_send_signal(&child_pidfd, rustix::process::Signal::KILL);
        let _ = crate::reap::wait_owned(&mut child);
        let _ = input.join();
        return;
    };
    if !stdout_ok || !stderr_ok || !output_ok {
        let _ = rustix::process::pidfd_send_signal(&child_pidfd, rustix::process::Signal::KILL);
        let _ = crate::reap::wait_owned(&mut child);
        send_exec(&mut conn, &AgentOutput::Exit { code: EXEC_NOT_RUN });
        let _ = rustix::net::shutdown(&conn, rustix::net::Shutdown::Both);
        let _ = input.join();
        return;
    }

    let code = wait_for_exit_code(&mut child);
    send_exec(&mut conn, &AgentOutput::Exit { code });
    // Without this, a host keeping the connection open would leak a thread.
    let _ = rustix::net::shutdown(&conn, rustix::net::Shutdown::Read);
    let _ = input.join();
}

fn pump_stream<R: Read + Send + 'static>(
    src: R,
    output_tx: mpsc::SyncSender<AgentOutput>,
    wrap: fn(Vec<u8>) -> AgentOutput,
) -> std::thread::JoinHandle<bool> {
    std::thread::spawn(move || pump_copy(src, |chunk| output_tx.send(wrap(chunk.to_vec())).is_ok()))
}

pub(crate) fn pump_copy<R: Read, F: FnMut(&[u8]) -> bool>(mut src: R, mut write: F) -> bool {
    let mut buf = [0u8; 8192];
    loop {
        match src.read(&mut buf) {
            Ok(n) => {
                if n == 0 {
                    return true;
                }
                if !write(&buf[..n]) {
                    return false;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    const NO_EXIT: i32 = i32::MIN;
    const HARNESS_TIMEOUT: Duration = Duration::from_secs(20);

    struct InterruptedOnce {
        interrupted: bool,
    }

    impl Read for InterruptedOnce {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
            }
            buf[0] = b'x';
            Ok(1)
        }
    }

    #[test]
    fn pump_copy_retries_interrupted_reads() {
        let mut output = Vec::new();
        assert!(!pump_copy(
            InterruptedOnce { interrupted: false },
            |chunk| {
                output.extend_from_slice(chunk);
                false
            }
        ));
        assert_eq!(output, b"x");
    }

    fn run_exec_request(argv: &[&str], is_tty: bool, stdin: &[u8]) -> (Vec<u8>, Vec<u8>, i32) {
        let req = ExecRequest {
            argv: argv.iter().map(ToString::to_string).collect(),
            as_root: false,
            tty: is_tty.then_some(TermSize { rows: 24, cols: 80 }),
        };
        let (mut client, server) = UnixStream::pair().unwrap();
        client.set_read_timeout(Some(HARNESS_TIMEOUT)).unwrap();
        let server = File::from(std::os::fd::OwnedFd::from(server));
        let agent = std::thread::spawn(move || serve_exec(server, true));
        client
            .write_all(&terra_shared::contract::encode_frame(&req).unwrap())
            .unwrap();
        if !stdin.is_empty() {
            client
                .write_all(
                    &terra_shared::contract::encode_frame(&ClientInput::Keys(stdin.to_vec()))
                        .unwrap(),
                )
                .unwrap();
        }
        client
            .write_all(&terra_shared::contract::encode_frame(&ClientInput::Eof).unwrap())
            .unwrap();

        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = loop {
            match read_frame::<AgentOutput>(&mut client) {
                Ok(Some(AgentOutput::Out(b))) => out.extend_from_slice(&b),
                Ok(Some(AgentOutput::Err(b))) => err.extend_from_slice(&b),
                Ok(Some(AgentOutput::Exit { code: c })) => break c,
                Ok(Some(AgentOutput::Detached) | None) | Err(_) => break NO_EXIT,
            }
        };
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
        let (out, err, code) =
            run_exec_request(&["sh", "-c", "echo OUT; echo ERR >&2; exit 3"], false, b"");
        assert_eq!(String::from_utf8_lossy(&out), "OUT\n");
        assert_eq!(String::from_utf8_lossy(&err), "ERR\n");
        assert_eq!(code, 3, "the command's own status must come back");

        let (out, _, code) = run_exec_request(&["printf", "a\nb\n"], false, b"unread input");
        assert_eq!(out, b"a\nb\n");
        assert_eq!(code, 0);
    }

    /// The end of the host's stdin has to reach the command as a real EOF, or a
    /// reader never returns. This is what [`ClientInput::Eof`] exists for: the
    /// host cannot send the `\x04` itself, because on a pipe that byte is data.
    #[test]
    fn a_pipe_exec_closes_stdin_so_a_reader_terminates() {
        let (out, _, code) = run_exec_request(&["cat"], false, b"payload\n");
        assert_eq!(out, b"payload\n");
        assert_eq!(code, 0, "cat did not see EOF");
    }

    #[test]
    fn a_pipe_exec_kills_a_quiet_child_when_the_host_disconnects_after_eof() {
        let mut command = std::process::Command::new("sh");
        command
            .arg("-c")
            .arg("trap '' TERM; while :; do :; done")
            .stdin(std::process::Stdio::piped());
        let (mut child, pidfd) = crate::reap::spawn_owned(|| command.spawn()).unwrap();
        let stdin = child.stdin.take().unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let server = File::from(std::os::fd::OwnedFd::from(server));
        let input_pidfd = pidfd.try_clone().unwrap();
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            pump_input(server, stdin, None, input_pidfd);
            let _ = done_tx.send(());
        });

        client
            .write_all(&encode_frame(&ClientInput::Eof).unwrap())
            .unwrap();
        let finished_after_eof = done_rx.recv_timeout(Duration::from_millis(100)).is_ok();
        drop(client);
        done_rx.recv_timeout(HARNESS_TIMEOUT).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let killed_on_disconnect = child.try_wait().unwrap().is_some();
        if !killed_on_disconnect {
            let _ = rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL);
        }
        let _ = crate::reap::wait_owned(&mut child);

        assert!(!finished_after_eof, "the input thread stopped at EOF");
        assert!(killed_on_disconnect, "the child survived the disconnect");
    }

    /// The interactive half. A PTY is what makes an exec'd shell usable, and the
    /// three things it does to the stream are exactly the ones the pipe path must
    /// not: `isatty` answers yes, and `\n` comes back as `\r\n`.
    #[test]
    fn a_tty_exec_gets_a_real_terminal() {
        let (out, err, code) = run_exec_request(
            &["sh", "-c", "test -t 1 && echo yes; echo ERR >&2; exit 3"],
            true,
            b"",
        );
        let seen = String::from_utf8_lossy(&out);
        assert!(seen.contains("yes"), "not a terminal: {seen:?}");
        assert!(seen.contains("\r\n"), "no cooked-mode CRLF: {seen:?}");
        assert!(seen.contains("ERR"), "stderr should interleave: {seen:?}");
        assert!(err.is_empty(), "a PTY exec has no separate stderr: {err:?}");
        assert_eq!(code, 3, "a PTY exec must report the command's own status");
    }

    /// A command killed by a signal reports `128 + signal`, the shell's own
    /// spelling - not 127, which claims the command never ran.
    #[test]
    fn a_signal_killed_command_reports_128_plus_the_signal() {
        for tty in [false, true] {
            let (_, _, code) = run_exec_request(&["sh", "-c", "kill -TERM $$"], tty, b"");
            assert_eq!(
                code,
                128 + rustix::process::Signal::TERM.as_raw(),
                "tty={tty}"
            );
        }
    }

    /// A command that cannot start still owes the caller an exit status - and
    /// 127 rather than 0, since a script's `&&` hangs off it. Terra's own
    /// diagnostic goes down stderr on a pipe exec, so `terra exec … > out`
    /// keeps the output file clean; a PTY has only the one stream.
    #[test]
    fn an_exec_that_cannot_start_reports_127() {
        let (out, err, code) = run_exec_request(&["/no/such/command"], false, b"");
        assert_eq!(code, EXEC_NOT_RUN);
        assert!(
            String::from_utf8_lossy(&err).contains("cannot run"),
            "the reason should reach stderr, not the output: {out:?} / {err:?}"
        );
        assert!(out.is_empty(), "{out:?}");

        let (out, _, code) = run_exec_request(&["/no/such/command"], true, b"");
        assert_eq!(code, EXEC_NOT_RUN);
        assert!(
            String::from_utf8_lossy(&out).contains("cannot run"),
            "the reason should reach the terminal"
        );

        let (_, _, code) = run_exec_request(&[], false, b"");
        assert_eq!(code, EXEC_NOT_RUN);
    }

    /// HOME is the one thing a command does not inherit correctly: PID 1's is
    /// the *workload's*, so an exec sets it again for itself - the same
    /// `/home/terri` whether it runs as root or not. (`run_exec_request` runs as root,
    /// per its note.)
    #[test]
    fn an_exec_gets_the_workloads_home() {
        let (out, _, code) = run_exec_request(&["sh", "-c", "echo $HOME"], false, b"");
        assert_eq!(String::from_utf8_lossy(&out), "/home/terri\n");
        assert_eq!(code, 0);
    }
}
