//! The agent's exec service: one command execution per connection.

use crate::term::session::{MAX_COLS, MAX_ROWS, MIN_COLS, MIN_ROWS};
use crate::term::tty::set_winsize;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
#[cfg(test)]
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use terra_protocol::{AgentOutput, ClientInput, ExecRequest, TermSize, encode_frame, read_frame};

const EXEC_NOT_RUN: i32 = 127;
const EXEC_SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Executes a command request until exit.
///
/// A root-capable channel, deliberately: host-initiated only, matching the file port's authority.
pub fn serve_exec(mut conn: File, workload_root: bool) {
    if crate::vsock::set_socket_timeouts(&conn, EXEC_SETUP_TIMEOUT).is_err() {
        return;
    }
    let Ok(Some(req)) = read_frame::<ExecRequest>(&mut conn) else {
        let _ = send_exec(&mut conn, &AgentOutput::Exit { code: EXEC_NOT_RUN });
        return;
    };
    if rustix::net::sockopt::set_socket_timeout(&conn, rustix::net::sockopt::Timeout::Recv, None)
        .is_err()
    {
        return;
    }
    let Some((cmd, args)) = req.argv.split_first() else {
        let _ = send_exec(&mut conn, &AgentOutput::Exit { code: EXEC_NOT_RUN });
        return;
    };
    let as_root = req.as_root || workload_root;
    match req.tty {
        Some(term) => {
            run_exec_on_pty(
                conn,
                term,
                cmd,
                args,
                as_root,
                req.workdir.as_deref(),
                &req.env,
            );
        }
        None => {
            run_exec_on_pipes(conn, cmd, args, as_root, req.workdir.as_deref(), &req.env);
        }
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

fn abort_exec<C: std::io::Write>(conn: &mut C, child_pidfd: &crate::reap::OwnedPidfd) {
    let _ = rustix::process::pidfd_send_signal(child_pidfd, rustix::process::Signal::KILL);
    let _ = crate::reap::wait_owned(child_pidfd);
    send_exec(conn, &AgentOutput::Exit { code: EXEC_NOT_RUN });
}

#[allow(unsafe_code)]
fn pump_input(
    mut src: File,
    out: impl Write + AsFd,
    master_fd: Option<RawFd>,
    child_pidfd: OwnedFd,
) {
    let mut stdin = Some(out);
    loop {
        match read_frame::<ClientInput>(&mut src) {
            Ok(Some(ClientInput::Keys(b))) => {
                if stdin
                    .as_mut()
                    .is_some_and(|out| write_input(&src, out, &child_pidfd, &b).is_err())
                {
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
                        let _ = write_input(&src, out, &child_pidfd, &[0x04]);
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

fn write_input(
    src: &File,
    out: &mut (impl Write + AsFd),
    child_pidfd: &OwnedFd,
    mut bytes: &[u8],
) -> std::io::Result<()> {
    use rustix::event::{PollFd, PollFlags, poll};

    let flags = rustix::fs::fcntl_getfl(&mut *out)?;
    rustix::fs::fcntl_setfl(&mut *out, flags | rustix::fs::OFlags::NONBLOCK)?;
    while !bytes.is_empty() {
        let mut fds = [
            PollFd::new(src, PollFlags::empty()),
            PollFd::new(out, PollFlags::OUT),
            PollFd::new(child_pidfd, PollFlags::IN),
        ];
        match poll(&mut fds, None) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
        if !fds[0].revents().is_empty() || !fds[2].revents().is_empty() {
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        match out.write(bytes) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[must_use]
pub(crate) fn wait_for_exit_code(pidfd: &crate::reap::OwnedPidfd) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    crate::reap::wait_owned(pidfd)
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
    term: TermSize,
    cmd: &str,
    args: &[String],
    as_root: bool,
    workdir: Option<&str>,
    env: &BTreeMap<String, String>,
) {
    let (pty, _child, child_pidfd) = match crate::init::spawn_on_pty(
        cmd,
        args,
        term,
        as_root,
        Some(terra_protocol::WORKLOAD_HOME),
        workdir,
        env,
    ) {
        Ok(pair) => pair,
        Err(e) => return report_exec_failure(&mut conn, cmd, e, true),
    };

    let master: OwnedFd = pty.into();
    let Ok(reader) = master.try_clone() else {
        return abort_exec(&mut conn, &child_pidfd);
    };
    let input = std::fs::File::from(master);
    let master_fd = input.as_raw_fd();

    let Ok(from_host) = conn.try_clone() else {
        return abort_exec(&mut conn, &child_pidfd);
    };
    let Ok(input_pidfd) = child_pidfd.try_clone() else {
        return abort_exec(&mut conn, &child_pidfd);
    };
    let input = std::thread::spawn(move || {
        pump_input(from_host, input, Some(master_fd), input_pidfd);
    });

    let mut reader = std::fs::File::from(reader);
    let output_ok = pump_pty_output(&mut reader, |chunk| {
        send_exec(&mut conn, &AgentOutput::Out(chunk.to_vec()))
    });
    if !output_ok {
        abort_exec(&mut conn, &child_pidfd);
        let _ = rustix::net::shutdown(&conn, rustix::net::Shutdown::Both);
        let _ = input.join();
        return;
    }
    send_exec(
        &mut conn,
        &AgentOutput::Exit {
            code: wait_for_exit_code(&child_pidfd),
        },
    );
    // Without this, a host keeping the connection open would leak the socket and PTY master.
    let _ = rustix::net::shutdown(&conn, rustix::net::Shutdown::Read);
    let _ = input.join();
}

#[allow(unsafe_code)]
fn run_exec_on_pipes(
    mut conn: File,
    cmd: &str,
    args: &[String],
    as_root: bool,
    workdir: Option<&str>,
    env: &BTreeMap<String, String>,
) {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    let mut command = std::process::Command::new(cmd);
    command
        .args(args)
        .env("HOME", terra_protocol::WORKLOAD_HOME)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(workdir) = workdir {
        command.current_dir(workdir);
    }
    for (k, v) in env {
        command.env(k, v);
    }
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
        return abort_exec(&mut conn, &child_pidfd);
    };

    let Ok(from_host) = conn.try_clone() else {
        return abort_exec(&mut conn, &child_pidfd);
    };
    let Ok(input_pidfd) = child_pidfd.try_clone() else {
        return abort_exec(&mut conn, &child_pidfd);
    };
    let input = std::thread::spawn(move || pump_input(from_host, stdin, None, input_pidfd));

    let conn = Arc::new(Mutex::new(conn));
    let child_pidfd = Arc::new(child_pidfd);
    let stdout_pump = pump_stream(stdout, conn.clone(), AgentOutput::Out, child_pidfd.clone());
    let stderr_pump = pump_stream(stderr, conn.clone(), AgentOutput::Err, child_pidfd.clone());
    let stdout_ok = stdout_pump.join().unwrap_or(false);
    let stderr_ok = stderr_pump.join().unwrap_or(false);
    let mut conn = crate::mutex::lock_or_abort(&conn);
    if !stdout_ok || !stderr_ok {
        let _ = rustix::process::pidfd_send_signal(&child_pidfd, rustix::process::Signal::KILL);
        let _ = crate::reap::wait_owned(&child_pidfd);
        send_exec(&mut *conn, &AgentOutput::Exit { code: EXEC_NOT_RUN });
        let _ = rustix::net::shutdown(&*conn, rustix::net::Shutdown::Both);
        let _ = input.join();
        return;
    }

    let code = wait_for_exit_code(&child_pidfd);
    send_exec(&mut *conn, &AgentOutput::Exit { code });
    // Without this, a host keeping the connection open would leak a thread.
    let _ = rustix::net::shutdown(&*conn, rustix::net::Shutdown::Read);
    let _ = input.join();
}

fn pump_stream<R: Read + AsFd + Send + 'static>(
    mut src: R,
    conn: Arc<Mutex<File>>,
    wrap: fn(Vec<u8>) -> AgentOutput,
    child_pidfd: Arc<crate::reap::OwnedPidfd>,
) -> std::thread::JoinHandle<bool> {
    std::thread::spawn(move || {
        let result = pump_pipe_output(&mut src, &child_pidfd, |chunk| {
            let mut conn = crate::mutex::lock_or_abort(&conn);
            send_exec(&mut *conn, &wrap(chunk.to_vec()))
        });
        if !result {
            let _ =
                rustix::process::pidfd_send_signal(&*child_pidfd, rustix::process::Signal::KILL);
        }
        result
    })
}

fn pump_pipe_output<R: Read + AsFd>(
    src: &mut R,
    child_pidfd: &crate::reap::OwnedPidfd,
    mut write: impl FnMut(&[u8]) -> bool,
) -> bool {
    use rustix::event::{PollFd, PollFlags, poll};
    let mut deadline: Option<std::time::Instant> = None;
    let mut bytes = [0; 8192];
    loop {
        let timeout = if let Some(deadline) = deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return true;
            }
            Some(rustix::event::Timespec::try_from(remaining).unwrap_or_default())
        } else {
            None
        };
        let mut fds = [
            PollFd::new(&*src, PollFlags::IN),
            PollFd::new(child_pidfd, PollFlags::IN),
        ];
        let watched = if deadline.is_some() {
            &mut fds[..1]
        } else {
            &mut fds[..]
        };
        match poll(watched, timeout.as_ref()) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return false,
        }
        if deadline.is_none() && !fds[1].revents().is_empty() {
            deadline = Some(std::time::Instant::now() + crate::init::OUTPUT_DRAIN_GRACE);
        }
        if fds[0].revents().is_empty() {
            continue;
        }
        match src.read(&mut bytes) {
            Ok(0) => return true,
            Ok(count) if !write(&bytes[..count]) => return false,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
}

fn pump_pty_output<R: Read + AsFd, F: FnMut(&[u8]) -> bool>(mut src: R, mut write: F) -> bool {
    use rustix::event::{PollFd, PollFlags, poll};

    let mut buf = [0u8; 8192];
    loop {
        match src.read(&mut buf) {
            Ok(0) => return true,
            Ok(count) if !write(&buf[..count]) => return false,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let mut fds = [PollFd::new(&src, PollFlags::IN)];
                match poll(&mut fds, None) {
                    Ok(_) | Err(rustix::io::Errno::INTR) => {}
                    Err(_) => return false,
                }
            }
            Err(error) if error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error()) => {
                return true;
            }
            Err(_) => return false,
        }
    }
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
            Err(_) => return false,
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
    fn pipe_exec_finishes_when_a_descendant_keeps_output_open() {
        let started = std::time::Instant::now();
        let (out, err, code) = run_exec_request(
            &["sh", "-c", "sleep 5 & printf done; printf err >&2; exit 7"],
            false,
            &[],
        );
        assert_eq!((out, err, code), (b"done".to_vec(), b"err".to_vec(), 7));
        assert!(started.elapsed() < Duration::from_secs(4));
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

    struct ReadError;

    impl Read for ReadError {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("read failed"))
        }
    }

    #[test]
    fn pump_copy_reports_read_errors() {
        assert!(!pump_copy(ReadError, |_| true));
    }

    fn run_exec_request(argv: &[&str], is_tty: bool, stdin: &[u8]) -> (Vec<u8>, Vec<u8>, i32) {
        run_exec_request_with_env(argv, is_tty, stdin, BTreeMap::new())
    }

    fn run_exec_request_with_env(
        argv: &[&str],
        is_tty: bool,
        stdin: &[u8],
        env: BTreeMap<String, String>,
    ) -> (Vec<u8>, Vec<u8>, i32) {
        let req = ExecRequest {
            argv: argv.iter().map(ToString::to_string).collect(),
            as_root: false,
            tty: is_tty.then_some(TermSize { rows: 24, cols: 80 }),
            workdir: None,
            env,
        };
        let (mut client, server) = UnixStream::pair().unwrap();
        client.set_read_timeout(Some(HARNESS_TIMEOUT)).unwrap();
        let server = File::from(std::os::fd::OwnedFd::from(server));
        let agent = std::thread::spawn(move || serve_exec(server, true));
        client
            .write_all(&terra_protocol::encode_frame(&req).unwrap())
            .unwrap();
        if !stdin.is_empty() {
            client
                .write_all(
                    &terra_protocol::encode_frame(&ClientInput::Keys(stdin.to_vec())).unwrap(),
                )
                .unwrap();
        }
        let _ = client.write_all(&terra_protocol::encode_frame(&ClientInput::Eof).unwrap());

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
        let killed_on_disconnect = matches!(
            rustix::process::waitid(
                rustix::process::WaitId::PidFd(pidfd.as_fd()),
                rustix::process::WaitIdOptions::EXITED
                    | rustix::process::WaitIdOptions::NOHANG
                    | rustix::process::WaitIdOptions::NOWAIT,
            ),
            Ok(Some(_)) | Err(rustix::io::Errno::CHILD)
        );
        if !killed_on_disconnect {
            let _ = rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL);
        }
        let _ = crate::reap::wait_owned(&pidfd);

        assert!(!finished_after_eof, "the input thread stopped at EOF");
        assert!(killed_on_disconnect, "the child survived the disconnect");
    }

    #[test]
    fn a_full_stdin_pipe_does_not_hold_the_input_thread_after_disconnect() {
        let mut command = std::process::Command::new("sh");
        command
            .arg("-c")
            .arg("while :; do sleep 1; done")
            .stdin(std::process::Stdio::piped());
        let (mut child, pidfd) = crate::reap::spawn_owned(|| command.spawn()).unwrap();
        let stdin = child.stdin.take().unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        client.set_write_timeout(Some(HARNESS_TIMEOUT)).unwrap();
        let server = File::from(std::os::fd::OwnedFd::from(server));
        let input_pidfd = pidfd.try_clone().unwrap();
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            pump_input(server, stdin, None, input_pidfd);
            let _ = done_tx.send(());
        });

        client
            .write_all(&encode_frame(&ClientInput::Keys(vec![b'x'; 1 << 20])).unwrap())
            .unwrap();
        drop(client);
        done_rx.recv_timeout(HARNESS_TIMEOUT).unwrap();
        let _ = crate::reap::wait_owned(&pidfd);
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

    #[test]
    fn a_tty_exec_delivers_input_to_its_command() {
        let (out, _, code) = run_exec_request(&["cat"], true, b"payload\n");
        assert!(
            out.windows(b"payload".len())
                .any(|bytes| bytes == b"payload")
        );
        assert_eq!(code, 0);
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

    #[test]
    fn an_exec_overlays_supplied_env_over_inherited_env() {
        let mut env = BTreeMap::new();
        env.insert("SUPPLIED_VAR".to_string(), "from_exec".to_string());
        env.insert("HOME".to_string(), "/custom/exec/home".to_string());

        let (out, _, code) = run_exec_request_with_env(
            &[
                "sh",
                "-c",
                "echo $SUPPLIED_VAR; echo $HOME; test -n \"$PATH\" && echo has_path",
            ],
            false,
            b"",
            env.clone(),
        );
        assert_eq!(code, 0);
        let out_str = String::from_utf8_lossy(&out);
        assert_eq!(out_str, "from_exec\n/custom/exec/home\nhas_path\n");

        let (out, _, code) = run_exec_request_with_env(
            &[
                "sh",
                "-c",
                "echo $SUPPLIED_VAR; echo $HOME; test -n \"$PATH\" && echo has_path",
            ],
            true,
            b"",
            env,
        );
        assert_eq!(code, 0);
        let out_str = String::from_utf8_lossy(&out);
        assert!(out_str.contains("from_exec"));
        assert!(out_str.contains("/custom/exec/home"));
        assert!(out_str.contains("has_path"));
    }
}
