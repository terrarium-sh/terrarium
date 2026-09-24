//! The agent's exec service: one command execution per connection.

use crate::AsyncFile;
use crate::term::session::{MAX_COLS, MAX_ROWS, MIN_COLS, MIN_ROWS};
use crate::term::tty::set_winsize;
use std::fmt::Display;
use std::os::fd::AsFd;
use std::sync::Arc;
use std::time::Duration;
use terra_protocol::{AgentOutput, ClientInput, ExecRequest, TermSize};
use terra_protocol::{read_frame_async as read_frame, write_frame_async as write_frame};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, watch};
use tokio_util::sync::CancellationToken;

const EXEC_NOT_RUN: i32 = 127;
const EXEC_SETUP_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn serve_exec(conn: AsyncFile, workload_root: bool, cancel: CancellationToken) {
    let Ok(disconnect) = conn
        .get_ref()
        .get_ref()
        .try_clone()
        .and_then(tokio::io::unix::AsyncFd::new)
    else {
        return;
    };
    let (mut reader, mut writer) = tokio::io::split(conn);
    let req = tokio::select! {
        biased;
        () = cancel.cancelled() => return,
        result = tokio::time::timeout(EXEC_SETUP_TIMEOUT, read_frame::<ExecRequest>(&mut reader)) => {
            if let Ok(Ok(Some(req))) = result {
                req
            } else {
                let _ = write_exec(&mut writer, &AgentOutput::Exit { code: EXEC_NOT_RUN }, &cancel).await;
                return;
            }
        }
    };
    Box::pin(run_exec(
        reader,
        writer,
        &req,
        workload_root,
        disconnect,
        cancel,
    ))
    .await;
}

async fn run_exec<R: AsyncRead + Unpin + Send + 'static, W: AsyncWrite + Unpin + Send + 'static>(
    reader: R,
    writer_conn: W,
    req: &ExecRequest,
    workload_root: bool,
    disconnect: tokio::io::unix::AsyncFd<std::fs::File>,
    cancel: CancellationToken,
) {
    let Some((cmd, args)) = req.argv.split_first() else {
        return;
    };
    let is_tty = req.tty.is_some();
    let spawned = if let Some(term) = req.tty {
        spawn_pty(cmd, args, req, workload_root, term)
    } else {
        spawn_pipes(cmd, args, req, workload_root)
    };
    let running = match spawned {
        Ok(running) => running,
        Err(SpawnFailure::Launch(error)) => {
            report_exec_failure(writer_conn, cmd, error, is_tty, &cancel).await;
            return;
        }
        Err(SpawnFailure::Setup(process)) => {
            process.abort(writer_conn, &cancel).await;
            return;
        }
    };

    let writer = Mutex::new(writer_conn);
    let (input_stop, input_task) = spawn_input_pump(
        reader,
        running.stdin,
        is_tty,
        running.process.clone(),
        disconnect,
        &cancel,
    );

    let code = match running.output {
        ExecOutput::Pty(output) => {
            drive_pty_output(output, &writer, &running.process, &cancel).await
        }
        ExecOutput::Pipes { stdout, stderr } => {
            Box::pin(drive_pipe_output(
                stdout,
                stderr,
                &writer,
                &running.process,
                &cancel,
            ))
            .await
        }
    };
    input_stop.cancel();
    let _ = input_task.await;
    let _ = write_output(&writer, AgentOutput::Exit { code }, &cancel).await;
}

#[derive(Clone)]
struct ProcessGroup {
    pidfd: Arc<crate::reap::OwnedPidfd>,
    leader: rustix::process::Pid,
}

impl ProcessGroup {
    fn new(pidfd: crate::reap::OwnedPidfd, leader: rustix::process::Pid) -> Self {
        Self {
            pidfd: Arc::new(pidfd),
            leader,
        }
    }

    fn kill(&self) {
        crate::reap::signal_owned_process_group(
            &self.pidfd,
            self.leader,
            rustix::process::Signal::KILL,
        );
    }

    async fn wait(&self) -> i32 {
        wait_for_exit_code(&self.pidfd).await
    }

    async fn abort<W: AsyncWrite + Unpin>(self, mut conn: W, cancel: &CancellationToken) {
        self.kill();
        let _ = crate::reap::wait_owned(&self.pidfd).await;
        let _ = write_exec(&mut conn, &AgentOutput::Exit { code: EXEC_NOT_RUN }, cancel).await;
    }
}

struct RunningProcess {
    process: ProcessGroup,
    stdin: AsyncFile,
    output: ExecOutput,
}

enum SpawnFailure {
    Launch(String),
    Setup(ProcessGroup),
}

fn spawn_pty(
    cmd: &str,
    args: &[String],
    req: &ExecRequest,
    workload_root: bool,
    term: TermSize,
) -> Result<RunningProcess, SpawnFailure> {
    let (pty, child, child_pidfd) = match crate::workload::spawn_on_pty(
        cmd,
        args,
        term,
        req.as_root || workload_root,
        Some(terra_protocol::WORKLOAD_HOME),
        req.workdir.as_deref(),
        &req.env,
    ) {
        Ok(child) => child,
        Err(error) => {
            return Err(SpawnFailure::Launch(error.to_string()));
        }
    };
    let leader = rustix::process::Pid::from_child(&child);
    let process = ProcessGroup::new(child_pidfd, leader);
    let master: std::os::fd::OwnedFd = pty.into();
    let Ok(output_master) = master.try_clone() else {
        return Err(SpawnFailure::Setup(process));
    };
    let (Ok(stdin), Ok(output)) = (
        crate::into_async_file(master),
        crate::into_async_file(output_master),
    ) else {
        return Err(SpawnFailure::Setup(process));
    };
    Ok(RunningProcess {
        process,
        stdin,
        output: ExecOutput::Pty(output),
    })
}

#[allow(unsafe_code)]
fn spawn_pipes(
    cmd: &str,
    args: &[String],
    req: &ExecRequest,
    workload_root: bool,
) -> Result<RunningProcess, SpawnFailure> {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    let mut command = std::process::Command::new(cmd);
    command
        .args(args)
        .process_group(0)
        .env("HOME", terra_protocol::WORKLOAD_HOME)
        .envs(&req.env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(workdir) = req.workdir.as_deref() {
        command.current_dir(workdir);
    }
    if !(req.as_root || workload_root) {
        // SAFETY: as in `spawn_on_pty` - async-signal-safe id-setting only.
        unsafe {
            command.pre_exec(crate::workload::drop_privileges);
        }
    }
    let (mut child, child_pidfd) = match crate::reap::spawn_owned(|| command.spawn()) {
        Ok(child) => child,
        Err(error) => {
            return Err(SpawnFailure::Launch(error.to_string()));
        }
    };
    let leader = rustix::process::Pid::from_child(&child);
    let process = ProcessGroup::new(child_pidfd, leader);
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return Err(SpawnFailure::Setup(process));
    };
    let (Ok(stdin), Ok(stdout), Ok(stderr)) = (
        crate::into_async_file(stdin),
        crate::into_async_file(stdout),
        crate::into_async_file(stderr),
    ) else {
        return Err(SpawnFailure::Setup(process));
    };
    Ok(RunningProcess {
        process,
        stdin,
        output: ExecOutput::Pipes { stdout, stderr },
    })
}

fn spawn_input_pump<R: AsyncRead + Unpin + Send + 'static>(
    reader: R,
    stdin: AsyncFile,
    is_tty: bool,
    process: ProcessGroup,
    disconnect: tokio::io::unix::AsyncFd<std::fs::File>,
    cancel: &CancellationToken,
) -> (CancellationToken, tokio::task::JoinHandle<()>) {
    let input_stop = cancel.child_token();
    let input_cancel = input_stop.clone();
    let handle = tokio::spawn(async move {
        let mut reader = reader;
        pump_input(
            &mut reader,
            stdin,
            is_tty,
            &process,
            &disconnect,
            input_cancel,
        )
        .await;
    });
    (input_stop, handle)
}

async fn pump_input<R: AsyncRead + Unpin>(
    reader: &mut R,
    stdin: AsyncFile,
    is_tty: bool,
    process: &ProcessGroup,
    monitor: &tokio::io::unix::AsyncFd<std::fs::File>,
    cancel: CancellationToken,
) {
    let forward = async {
        let mut stdin = Some(stdin);
        while let Some(input) = read_frame(reader).await? {
            match input {
                ClientInput::Keys(bytes) => {
                    if let Some(stdin) = stdin.as_mut() {
                        stdin.write_all(&bytes).await?;
                    }
                }
                ClientInput::Resize(TermSize { rows, cols }) if is_tty && rows > 0 && cols > 0 => {
                    if let Some(stdin) = stdin.as_ref() {
                        set_winsize(
                            stdin.get_ref().as_fd(),
                            rows.clamp(MIN_ROWS, MAX_ROWS),
                            cols.clamp(MIN_COLS, MAX_COLS),
                        );
                    }
                }
                ClientInput::Resize(_) => {}
                ClientInput::Eof if is_tty => {
                    if let Some(stdin) = stdin.as_mut() {
                        stdin.write_all(&[0x04]).await?;
                    }
                }
                ClientInput::Eof => drop(stdin.take()),
            }
        }
        std::io::Result::Ok(())
    };
    tokio::select! {
        biased;
        () = cancel.cancelled() => {},
        _ = forward => {},
        _ = wait_read_closed(monitor) => {},
    }
    process.kill();
}

async fn wait_read_closed(
    monitor: &tokio::io::unix::AsyncFd<std::fs::File>,
) -> std::io::Result<()> {
    loop {
        let mut readiness = monitor.readable().await?;
        if readiness.ready().is_read_closed() {
            return Ok(());
        }
        readiness.clear_ready();
    }
}

enum ExecOutput {
    Pty(AsyncFile),
    Pipes {
        stdout: AsyncFile,
        stderr: AsyncFile,
    },
}

async fn drive_pty_output<W: AsyncWrite + Unpin>(
    output: AsyncFile,
    writer: &Mutex<W>,
    process: &ProcessGroup,
    cancel: &CancellationToken,
) -> i32 {
    let output_ok = tokio::select! {
        biased;
        () = cancel.cancelled() => false,
        output_ok = pty_output(output, writer, cancel.clone()) => output_ok,
    };
    if !output_ok {
        process.kill();
    }
    process.wait().await
}

async fn drive_pipe_output<W: AsyncWrite + Unpin>(
    stdout: AsyncFile,
    stderr: AsyncFile,
    writer: &Mutex<W>,
    process: &ProcessGroup,
    cancel: &CancellationToken,
) -> i32 {
    let (exited_tx, exited_rx) = watch::channel(false);
    let waiter_process = process.clone();
    let waiter = tokio::spawn(async move {
        let status = crate::reap::wait_owned(&waiter_process.pidfd).await;
        let _ = exited_tx.send(true);
        status
    });
    let output = tokio::try_join!(
        pipe_output(
            stdout,
            writer,
            AgentOutput::Out,
            exited_rx.clone(),
            cancel.clone(),
        ),
        pipe_output(stderr, writer, AgentOutput::Err, exited_rx, cancel.clone()),
    );
    if output.is_err() {
        process.kill();
    }
    let code = exit_code(
        waiter
            .await
            .unwrap_or_else(|_| Err(std::io::Error::other("child waiter failed"))),
    );
    if output.is_ok() { code } else { EXEC_NOT_RUN }
}

async fn pipe_output<R: AsyncRead + Unpin>(
    mut source: R,
    writer: &Mutex<impl AsyncWrite + Unpin>,
    wrap: fn(Vec<u8>) -> AgentOutput,
    mut exited: watch::Receiver<bool>,
    cancel: CancellationToken,
) -> Result<(), ()> {
    let mut deadline = None;
    let mut bytes = [0; 8192];
    loop {
        let read = async {
            match deadline {
                Some(deadline) => tokio::time::timeout_at(deadline, source.read(&mut bytes))
                    .await
                    .unwrap_or(Ok(0)),
                None => source.read(&mut bytes).await,
            }
        };
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(()),
            result = read => match result {
                Ok(0) => return Ok(()),
                Ok(count) if !write_output(writer, wrap(bytes[..count].to_vec()), &cancel).await => return Err(()),
                Ok(_) => {},
                Err(_) => return Err(()),
            },
            result = exited.changed(), if deadline.is_none() => {
                if result.is_err() || *exited.borrow() {
                    deadline = Some(tokio::time::Instant::now() + crate::hooks::OUTPUT_DRAIN_GRACE);
                }
            },
        }
    }
}

async fn pty_output<R: AsyncRead + Unpin>(
    mut source: R,
    writer: &Mutex<impl AsyncWrite + Unpin>,
    cancel: CancellationToken,
) -> bool {
    let mut bytes = [0; 8192];
    loop {
        match source.read(&mut bytes).await {
            Ok(0) => return true,
            Err(error) if error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error()) => {
                return true;
            }
            Ok(count)
                if !write_output(writer, AgentOutput::Out(bytes[..count].to_vec()), &cancel)
                    .await =>
            {
                return false;
            }
            Ok(_) => {}
            Err(_) => return false,
        }
    }
}

async fn write_exec<W: AsyncWrite + Unpin>(
    conn: &mut W,
    msg: &AgentOutput,
    cancel: &CancellationToken,
) -> bool {
    tokio::select! {
        biased;
        () = cancel.cancelled() => false,
        result = tokio::time::timeout(EXEC_SETUP_TIMEOUT, write_frame(conn, msg)) => matches!(result, Ok(Ok(()))),
    }
}

async fn write_output<W: AsyncWrite + Unpin>(
    writer: &Mutex<W>,
    msg: AgentOutput,
    cancel: &CancellationToken,
) -> bool {
    let mut writer = writer.lock().await;
    write_exec(&mut *writer, &msg, cancel).await
}

async fn report_exec_failure<W: AsyncWrite + Unpin>(
    conn: W,
    cmd: &str,
    error: impl Display,
    tty: bool,
    cancel: &CancellationToken,
) {
    let mut conn = conn;
    let output = if tty {
        AgentOutput::Out(format!("terra: cannot run {cmd}: {error}\r\n").into_bytes())
    } else {
        AgentOutput::Err(format!("terra: cannot run {cmd}: {error}\n").into_bytes())
    };
    let _ = write_exec(&mut conn, &output, cancel).await;
    let _ = write_exec(&mut conn, &AgentOutput::Exit { code: EXEC_NOT_RUN }, cancel).await;
}

#[must_use]
fn exit_code(status: std::io::Result<std::process::ExitStatus>) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .ok()
        .and_then(|status| {
            status
                .code()
                .or_else(|| status.signal().map(|signal| 128 + signal))
        })
        .unwrap_or(EXEC_NOT_RUN)
}

pub(crate) async fn wait_for_exit_code(pidfd: &crate::reap::OwnedPidfd) -> i32 {
    exit_code(crate::reap::wait_owned(pidfd).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::io::Write as _;
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;

    const NO_EXIT: i32 = i32::MIN;
    const HARNESS_TIMEOUT: Duration = Duration::from_secs(20);

    async fn run_exec_request(
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
        let agent = tokio::spawn(serve_exec(
            crate::into_async_file(server).unwrap(),
            true,
            CancellationToken::new(),
        ));
        let mut input = terra_protocol::encode_frame(&req).unwrap();
        if !stdin.is_empty() {
            input.extend(terra_protocol::encode_frame(&ClientInput::Keys(stdin.to_vec())).unwrap());
        }
        input.extend(terra_protocol::encode_frame(&ClientInput::Eof).unwrap());
        client.write_all(&input).unwrap();
        let result = read_exec_output(&mut client);
        if result.2 != NO_EXIT {
            agent.await.unwrap();
        }
        result
    }

    fn read_exec_output(client: &mut UnixStream) -> (Vec<u8>, Vec<u8>, i32) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = loop {
            match terra_protocol::read_frame::<AgentOutput>(client) {
                Ok(Some(AgentOutput::Out(bytes))) => out.extend_from_slice(&bytes),
                Ok(Some(AgentOutput::Err(bytes))) => err.extend_from_slice(&bytes),
                Ok(Some(AgentOutput::Exit { code })) => break code,
                Ok(Some(AgentOutput::Detached) | None) | Err(_) => break NO_EXIT,
            }
        };
        (out, err, code)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pipe_exec_finishes_when_a_descendant_keeps_output_open() {
        let started = std::time::Instant::now();
        let (out, err, code) = run_exec_request(
            &["sh", "-c", "sleep 5 & printf done; printf err >&2; exit 7"],
            false,
            b"",
            BTreeMap::new(),
        )
        .await;
        assert_eq!((out, err, code), (b"done".to_vec(), b"err".to_vec(), 7));
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pipe_exec_kills_the_child_when_output_disconnects() {
        let request = ExecRequest {
            argv: vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf out; exec sleep 600".to_string(),
            ],
            as_root: false,
            tty: None,
            workdir: None,
            env: BTreeMap::new(),
        };
        let (mut client, server) = UnixStream::pair().unwrap();
        let agent = tokio::spawn(serve_exec(
            crate::into_async_file(server).unwrap(),
            true,
            CancellationToken::new(),
        ));
        client
            .write_all(&terra_protocol::encode_frame(&request).unwrap())
            .unwrap();
        client.shutdown(Shutdown::Read).unwrap();

        tokio::time::timeout(Duration::from_secs(3), agent)
            .await
            .expect("agent waited for stderr after output disconnected")
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_stops_an_exec_connection_waiting_for_its_request() {
        let (_client, server) = UnixStream::pair().unwrap();
        let cancel = CancellationToken::new();
        let agent = tokio::spawn(serve_exec(
            crate::into_async_file(server).unwrap(),
            true,
            cancel.clone(),
        ));
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(3), agent)
            .await
            .expect("exec service did not stop while waiting for its request")
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_kills_the_exec_process_group_and_closes_the_connection() {
        for is_tty in [false, true] {
            let request = ExecRequest {
                argv: vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    "sleep 600 & echo $!; wait".to_string(),
                ],
                as_root: false,
                tty: is_tty.then_some(TermSize { rows: 24, cols: 80 }),
                workdir: None,
                env: BTreeMap::new(),
            };
            let (mut client, server) = UnixStream::pair().unwrap();
            client.set_read_timeout(Some(HARNESS_TIMEOUT)).unwrap();
            let cancel = CancellationToken::new();
            let agent = tokio::spawn(serve_exec(
                crate::into_async_file(server).unwrap(),
                true,
                cancel.clone(),
            ));
            client
                .write_all(&terra_protocol::encode_frame(&request).unwrap())
                .unwrap();
            let Some(AgentOutput::Out(pid)) = terra_protocol::read_frame(&mut client).unwrap()
            else {
                panic!("exec did not report its child pid");
            };
            let pid = String::from_utf8(pid).unwrap().trim().parse().unwrap();
            let pid = rustix::process::Pid::from_raw(pid).unwrap();

            cancel.cancel();
            tokio::time::timeout(Duration::from_secs(3), agent)
                .await
                .expect("exec service did not stop after cancellation")
                .unwrap();
            assert_eq!(
                terra_protocol::read_frame::<AgentOutput>(&mut client).unwrap(),
                None
            );
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            while rustix::process::test_kill_process(pid).is_ok()
                && tokio::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(rustix::process::test_kill_process(pid).is_err());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pipe_exec_keeps_streams_and_bytes_intact() {
        let (out, err, code) = run_exec_request(
            &["sh", "-c", "echo OUT; echo ERR >&2; exit 3"],
            false,
            b"",
            BTreeMap::new(),
        )
        .await;
        assert_eq!((out, err, code), (b"OUT\n".to_vec(), b"ERR\n".to_vec(), 3));

        let (out, _, code) = run_exec_request(
            &["printf", "a\nb\n"],
            false,
            b"unread input",
            BTreeMap::new(),
        )
        .await;
        assert_eq!((out, code), (b"a\nb\n".to_vec(), 0));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pipe_exec_closes_stdin() {
        let (out, _, code) = run_exec_request(&["cat"], false, b"payload\n", BTreeMap::new()).await;
        assert_eq!((out, code), (b"payload\n".to_vec(), 0));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pipe_input_kills_a_quiet_child_after_host_disconnect() {
        let mut command = std::process::Command::new("sh");
        command
            .arg("-c")
            .arg("trap '' TERM; while :; do :; done")
            .stdin(std::process::Stdio::piped());
        let (mut child, pidfd) = crate::reap::spawn_owned(|| command.spawn()).unwrap();
        let stdin = crate::into_async_file(child.stdin.take().unwrap()).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let monitor = tokio::io::unix::AsyncFd::new(File::from(std::os::fd::OwnedFd::from(
            server.try_clone().unwrap(),
        )))
        .unwrap();
        let mut server =
            crate::into_async_file(File::from(std::os::fd::OwnedFd::from(server))).unwrap();
        let pidfd = Arc::new(pidfd);
        let process = ProcessGroup {
            pidfd: pidfd.clone(),
            leader: rustix::process::Pid::from_child(&child),
        };
        let cancel = CancellationToken::new();
        let mut pump = tokio::spawn(async move {
            pump_input(&mut server, stdin, false, &process, &monitor, cancel).await;
        });

        client
            .write_all(&terra_protocol::encode_frame(&ClientInput::Eof).unwrap())
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut pump)
                .await
                .is_err()
        );
        drop(client);
        tokio::time::timeout(HARNESS_TIMEOUT, &mut pump)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(HARNESS_TIMEOUT, crate::reap::wait_owned(&pidfd))
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tty_exec_gets_a_terminal_and_input() {
        let (out, err, code) = run_exec_request(
            &["sh", "-c", "test -t 1 && echo yes; echo ERR >&2; exit 3"],
            true,
            b"",
            BTreeMap::new(),
        )
        .await;
        let output = String::from_utf8_lossy(&out);
        assert!(output.contains("yes") && output.contains("\r\n") && output.contains("ERR"));
        assert!(err.is_empty());
        assert_eq!(code, 3);

        let (out, _, code) = run_exec_request(&["cat"], true, b"payload\n", BTreeMap::new()).await;
        assert!(
            out.windows(b"payload".len())
                .any(|bytes| bytes == b"payload")
        );
        assert_eq!(code, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn signal_exit_and_failed_start_report_codes() {
        for tty in [false, true] {
            let (_, _, code) =
                run_exec_request(&["sh", "-c", "kill -TERM $$"], tty, b"", BTreeMap::new()).await;
            assert_eq!(code, 128 + rustix::process::Signal::TERM.as_raw());
        }

        let (out, err, code) =
            run_exec_request(&["/no/such/command"], false, b"", BTreeMap::new()).await;
        assert_eq!(code, EXEC_NOT_RUN);
        assert!(out.is_empty());
        assert!(String::from_utf8_lossy(&err).contains("cannot run"));

        let (out, _, code) =
            run_exec_request(&["/no/such/command"], true, b"", BTreeMap::new()).await;
        assert_eq!(code, EXEC_NOT_RUN);
        assert!(String::from_utf8_lossy(&out).contains("cannot run"));

        assert_eq!(
            run_exec_request(&[], false, b"", BTreeMap::new()).await.2,
            EXEC_NOT_RUN
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exec_sets_home_and_overlays_environment() {
        let (out, _, code) =
            run_exec_request(&["sh", "-c", "echo $HOME"], false, b"", BTreeMap::new()).await;
        assert_eq!((out, code), (b"/home/terri\n".to_vec(), 0));

        let mut env = BTreeMap::new();
        env.insert("SUPPLIED_VAR".to_string(), "from_exec".to_string());
        env.insert("HOME".to_string(), "/custom/exec/home".to_string());
        for tty in [false, true] {
            let (out, _, code) = run_exec_request(
                &[
                    "sh",
                    "-c",
                    "echo $SUPPLIED_VAR; echo $HOME; test -n \"$PATH\" && echo has_path",
                ],
                tty,
                b"",
                env.clone(),
            )
            .await;
            assert_eq!(code, 0);
            let output = String::from_utf8_lossy(&out);
            assert!(output.contains("from_exec"));
            assert!(output.contains("/custom/exec/home"));
            assert!(output.contains("has_path"));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn buffered_and_fragmented_input_is_not_discarded() {
        let req = ExecRequest {
            argv: vec![
                "sh".to_string(),
                "-c".to_string(),
                "sleep .1; cat".to_string(),
            ],
            as_root: false,
            tty: None,
            workdir: None,
            env: BTreeMap::new(),
        };
        let first = vec![b'a'; 512 * 1024];
        let second = b"second frame".to_vec();
        let (mut client, server) = UnixStream::pair().unwrap();
        client.set_read_timeout(Some(HARNESS_TIMEOUT)).unwrap();
        let agent = tokio::spawn(serve_exec(
            crate::into_async_file(server).unwrap(),
            true,
            CancellationToken::new(),
        ));
        client
            .write_all(&terra_protocol::encode_frame(&req).unwrap())
            .unwrap();
        client
            .write_all(&terra_protocol::encode_frame(&ClientInput::Keys(first.clone())).unwrap())
            .unwrap();
        let second_frame =
            terra_protocol::encode_frame(&ClientInput::Keys(second.clone())).unwrap();
        client.write_all(&second_frame[..2]).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        client.write_all(&second_frame[2..]).unwrap();
        client
            .write_all(&terra_protocol::encode_frame(&ClientInput::Eof).unwrap())
            .unwrap();
        let (out, err, code) = read_exec_output(&mut client);
        agent.await.unwrap();
        let mut expected = first;
        expected.extend(second);
        assert_eq!((out, err, code), (expected, Vec::new(), 0));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disconnect_is_detected_with_unread_input() {
        let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut sender = crate::into_async_file(sender).unwrap();
        let receiver =
            tokio::io::unix::AsyncFd::new(File::from(std::os::fd::OwnedFd::from(receiver)))
                .unwrap();
        sender.write_all(b"unread").await.unwrap();
        let watching = tokio::spawn(async move { wait_read_closed(&receiver).await });
        tokio::task::yield_now().await;
        assert!(!watching.is_finished());
        drop(sender);
        tokio::time::timeout(std::time::Duration::from_secs(5), watching)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
