//! The agent's exec service: one command execution per connection.

use crate::AsyncFile;
use crate::reap::OwnedPidfd;
use crate::session::{clamp_term_size, requested_term_size, set_winsize};
use crate::workload::GuestUser;
use std::os::fd::AsFd;
use std::time::Duration;
use terra_protocol::{AgentOutput, ClientInput, ExecRequest, TermSize};
use terra_protocol::{read_frame_async as read_frame, write_frame_async as write_frame};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, watch};
use tokio_util::sync::CancellationToken;

const EXEC_NOT_RUN: i32 = 127;
const FRAME_TIMEOUT: Duration = Duration::from_secs(30);
const OUTPUT_READ_BYTES: usize = 64 << 10;

pub(crate) async fn serve_exec(
    conn: AsyncFile,
    workload_user: GuestUser,
    cancellation: CancellationToken,
) {
    let Ok(disconnect) = conn.get_ref().try_clone().and_then(crate::into_async_fd) else {
        return;
    };
    let (mut reader, mut writer) = tokio::io::split(conn);
    let req = tokio::select! {
        biased;
        () = cancellation.cancelled() => return,
        result = tokio::time::timeout(FRAME_TIMEOUT, read_frame::<ExecRequest>(&mut reader)) => result,
    };
    let code = if let Ok(Ok(Some(req))) = req {
        Box::pin(run_exec(
            reader,
            &mut writer,
            &req,
            workload_user,
            disconnect,
            &cancellation,
        ))
        .await
    } else {
        EXEC_NOT_RUN
    };
    let _ = send_output(&mut writer, &AgentOutput::Exit { code }, &cancellation).await;
}

async fn run_exec<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    writer: &mut W,
    req: &ExecRequest,
    workload_user: GuestUser,
    disconnect: tokio::io::unix::AsyncFd<std::fs::File>,
    cancellation: &CancellationToken,
) -> i32 {
    let Some((cmd, args)) = req.argv.split_first() else {
        return EXEC_NOT_RUN;
    };
    let user = if req.as_root {
        GuestUser::Root
    } else {
        workload_user
    };
    let is_tty = req.tty.is_some();
    let command = exec_command(cmd, args, req, user);
    let spawned = match req.tty {
        Some(term) => spawn_pty(command, term),
        None => spawn_pipes(command),
    };
    let running = match spawned {
        Ok(running) => running,
        Err(error) => {
            report_exec_failure(writer, cmd, &error, is_tty, cancellation).await;
            return EXEC_NOT_RUN;
        }
    };

    let writer = Mutex::new(writer);
    let input = pump_input(
        &mut reader,
        running.stdin,
        is_tty,
        &running.process,
        &disconnect,
    );
    let output = drive_output(running.output, &writer, &running.process, cancellation);
    tokio::pin!(input, output);
    tokio::select! {
        code = &mut output => code,
        () = &mut input => output.await,
    }
}

struct RunningProcess {
    process: OwnedPidfd,
    stdin: AsyncFile,
    output: ExecOutput,
}

fn spawn_pty(command: std::process::Command, term: TermSize) -> anyhow::Result<RunningProcess> {
    let (pty, pts) = pty_process::blocking::open()?;
    let (rows, cols) = clamp_term_size(term.rows, term.cols);
    pty.resize(pty_process::Size::new(rows, cols))?;
    let master: std::os::fd::OwnedFd = pty.into();
    let output = crate::into_async_file(master.try_clone()?)?;
    let stdin = crate::into_async_file(master)?;
    let command = pty_process::blocking::Command::from(command);
    let (_child, process) = crate::reap::spawn_owned(|| command.spawn(pts))?;
    Ok(RunningProcess {
        process,
        stdin,
        output: ExecOutput::Pty(output),
    })
}

fn spawn_pipes(mut command: std::process::Command) -> anyhow::Result<RunningProcess> {
    use std::os::unix::process::CommandExt;

    let (child_stdin, stdin) = std::io::pipe()?;
    let (stdout, child_stdout) = std::io::pipe()?;
    let (stderr, child_stderr) = std::io::pipe()?;
    let (stdin, stdout, stderr) = (
        crate::into_async_file(stdin)?,
        crate::into_async_file(stdout)?,
        crate::into_async_file(stderr)?,
    );
    command
        .process_group(0)
        .stdin(child_stdin)
        .stdout(child_stdout)
        .stderr(child_stderr);
    let (_child, process) = crate::reap::spawn_owned(|| command.spawn())?;
    Ok(RunningProcess {
        process,
        stdin,
        output: ExecOutput::Pipes { stdout, stderr },
    })
}

fn exec_command(
    cmd: &str,
    args: &[String],
    req: &ExecRequest,
    user: GuestUser,
) -> std::process::Command {
    let mut command = std::process::Command::new(cmd);
    command
        .args(args)
        .env("HOME", terra_protocol::WORKLOAD_HOME)
        .envs(&req.env);
    if let Some(workdir) = req.workdir.as_deref() {
        command.current_dir(workdir);
    }
    crate::workload::run_as(&mut command, user);
    command
}

async fn pump_input<R: AsyncRead + Unpin>(
    reader: &mut R,
    stdin: AsyncFile,
    is_tty: bool,
    process: &OwnedPidfd,
    disconnect: &tokio::io::unix::AsyncFd<std::fs::File>,
) {
    let forward = async {
        let mut stdin = Some(stdin);
        while let Ok(Some(input)) = read_frame(reader).await {
            let bytes = match input {
                ClientInput::Keys(bytes) => bytes,
                ClientInput::Resize(size) => {
                    if is_tty
                        && let Some((rows, cols)) = requested_term_size(size)
                        && let Some(stdin) = stdin.as_ref()
                    {
                        set_winsize(stdin.get_ref().as_fd(), rows, cols);
                    }
                    continue;
                }
                ClientInput::Eof if is_tty => vec![0x04],
                ClientInput::Eof => {
                    drop(stdin.take());
                    continue;
                }
            };
            if let Some(child_stdin) = stdin.as_mut()
                && let Err(error) = child_stdin.write_all(&bytes).await
            {
                if error.kind() != std::io::ErrorKind::BrokenPipe {
                    return;
                }
                drop(stdin.take());
            }
        }
    };
    tokio::select! {
        () = forward => {},
        _ = wait_read_closed(disconnect) => {},
    }
    process.signal_group(rustix::process::Signal::KILL);
}

async fn wait_read_closed(
    disconnect: &tokio::io::unix::AsyncFd<std::fs::File>,
) -> std::io::Result<()> {
    loop {
        let mut readiness = disconnect.readable().await?;
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

async fn drive_output<W: AsyncWrite + Unpin>(
    output: ExecOutput,
    writer: &Mutex<W>,
    process: &OwnedPidfd,
    cancellation: &CancellationToken,
) -> i32 {
    let (exited_tx, exited) = watch::channel(false);
    let wait = async {
        let status = crate::reap::wait_owned(process).await;
        let _ = exited_tx.send(true);
        status
    };
    let pump = async {
        let pumped = match output {
            ExecOutput::Pty(output) => {
                pump_output(output, writer, AgentOutput::Out, exited, cancellation).await
            }
            ExecOutput::Pipes { stdout, stderr } => tokio::try_join!(
                pump_output(
                    stdout,
                    writer,
                    AgentOutput::Out,
                    exited.clone(),
                    cancellation
                ),
                pump_output(stderr, writer, AgentOutput::Err, exited, cancellation),
            )
            .map(|_| ()),
        };
        if pumped.is_err() {
            process.signal_group(rustix::process::Signal::KILL);
        }
        pumped
    };
    match tokio::join!(wait, pump) {
        (status, Ok(())) => exit_code(status),
        (_, Err(())) => EXEC_NOT_RUN,
    }
}

async fn pump_output<R: AsyncRead + Unpin>(
    mut source: R,
    writer: &Mutex<impl AsyncWrite + Unpin>,
    wrap: fn(Vec<u8>) -> AgentOutput,
    mut exited: watch::Receiver<bool>,
    cancellation: &CancellationToken,
) -> Result<(), ()> {
    let drained = async {
        let _ = exited.wait_for(|&has_exited| has_exited).await;
        tokio::time::sleep(crate::OUTPUT_DRAIN_GRACE).await;
    };
    tokio::pin!(drained);
    let mut bytes = vec![0; OUTPUT_READ_BYTES];
    loop {
        let read = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(()),
            () = &mut drained => return Ok(()),
            read = source.read(&mut bytes) => read,
        };
        let count = match read {
            Ok(0) => return Ok(()),
            Ok(count) => count,
            // A pty master reads EIO once no slave fd is open.
            Err(error) if error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error()) => {
                return Ok(());
            }
            Err(_) => return Err(()),
        };
        send_output(
            &mut *writer.lock().await,
            &wrap(bytes[..count].to_vec()),
            cancellation,
        )
        .await?;
    }
}

async fn send_output<W: AsyncWrite + Unpin>(
    conn: &mut W,
    msg: &AgentOutput,
    cancellation: &CancellationToken,
) -> Result<(), ()> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(()),
        result = tokio::time::timeout(FRAME_TIMEOUT, write_frame(conn, msg)) => match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) | Err(_) => Err(()),
        },
    }
}

async fn report_exec_failure<W: AsyncWrite + Unpin>(
    conn: &mut W,
    cmd: &str,
    error: &anyhow::Error,
    is_tty: bool,
    cancellation: &CancellationToken,
) {
    let message = format!("terra: cannot run {cmd}: {error}");
    let output = if is_tty {
        AgentOutput::Out(format!("{message}\r\n").into_bytes())
    } else {
        AgentOutput::Err(format!("{message}\n").into_bytes())
    };
    let _ = send_output(conn, &output, cancellation).await;
}

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

pub(crate) async fn wait_for_exit_code(pidfd: &OwnedPidfd) -> i32 {
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

    fn exec_request(argv: &[&str], is_tty: bool) -> ExecRequest {
        ExecRequest {
            argv: argv.iter().map(ToString::to_string).collect(),
            as_root: false,
            tty: is_tty.then_some(TermSize { rows: 24, cols: 80 }),
            workdir: None,
            env: BTreeMap::new(),
        }
    }

    /// Serves one exec connection and sends it `request`.
    fn start_exec(
        request: &ExecRequest,
        cancellation: &CancellationToken,
    ) -> (UnixStream, tokio::task::JoinHandle<()>) {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.set_read_timeout(Some(HARNESS_TIMEOUT)).unwrap();
        let agent = tokio::spawn(serve_exec(
            crate::into_async_file(server).unwrap(),
            GuestUser::Root,
            cancellation.clone(),
        ));
        client
            .write_all(&terra_protocol::encode_frame(request).unwrap())
            .unwrap();
        (client, agent)
    }

    async fn run_exec_request(request: &ExecRequest, stdin: &[u8]) -> (Vec<u8>, Vec<u8>, i32) {
        let (mut client, agent) = start_exec(request, &CancellationToken::new());
        let mut input = Vec::new();
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
            &exec_request(
                &["sh", "-c", "sleep 5 & printf done; printf err >&2; exit 7"],
                false,
            ),
            b"",
        )
        .await;
        assert_eq!((out, err, code), (b"done".to_vec(), b"err".to_vec(), 7));
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exec_finishes_while_a_descendant_floods_output() {
        for is_tty in [false, true] {
            let started = std::time::Instant::now();
            let (_, _, code) =
                run_exec_request(&exec_request(&["sh", "-c", "yes & exit 3"], is_tty), b"").await;
            assert_eq!(code, 3);
            assert!(started.elapsed() < Duration::from_secs(4));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tty_exec_finishes_when_a_descendant_keeps_output_open() {
        let started = std::time::Instant::now();
        let (out, err, code) = run_exec_request(
            &exec_request(
                &["sh", "-c", "trap '' HUP; sleep 6 & printf done; exit 7"],
                true,
            ),
            b"",
        )
        .await;
        assert_eq!((out, err, code), (b"done".to_vec(), Vec::new(), 7));
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[tokio::test]
    async fn output_grace_preserves_frames_with_continuously_ready_source() {
        let (sender, mut receiver) = tokio::io::duplex(1024);
        let reader = tokio::spawn(async move {
            let mut frames = 0;
            while let Some(frame) = read_frame::<AgentOutput>(&mut receiver).await.unwrap() {
                assert_eq!(frame, AgentOutput::Out(vec![b'x'; OUTPUT_READ_BYTES]));
                frames += 1;
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            frames
        });
        let (_, exited) = watch::channel(true);
        let started = std::time::Instant::now();
        let writer = Mutex::new(sender);
        tokio::time::timeout(
            Duration::from_secs(4),
            pump_output(
                tokio::io::repeat(b'x'),
                &writer,
                AgentOutput::Out,
                exited,
                &CancellationToken::new(),
            ),
        )
        .await
        .expect("continuously ready output ignored the child's exit")
        .unwrap();
        drop(writer);
        assert!(reader.await.unwrap() > 1);
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pipe_exec_discards_closed_stdin_and_keeps_monitoring_host_disconnect() {
        for disconnect_host in [false, true] {
            let command = if disconnect_host {
                "exec 0<&-; printf ready; exec sleep 600"
            } else {
                "exec 0<&-; printf ready; sleep .1; printf done; exit 7"
            };
            let (mut client, mut agent) = start_exec(
                &exec_request(&["sh", "-c", command], false),
                &CancellationToken::new(),
            );
            assert_eq!(
                terra_protocol::read_frame::<AgentOutput>(&mut client).unwrap(),
                Some(AgentOutput::Out(b"ready".to_vec()))
            );
            for bytes in [b"ignored first".as_slice(), b"ignored second".as_slice()] {
                client
                    .write_all(
                        &terra_protocol::encode_frame(&ClientInput::Keys(bytes.to_vec())).unwrap(),
                    )
                    .unwrap();
            }
            if disconnect_host {
                assert!(
                    tokio::time::timeout(Duration::from_millis(100), &mut agent)
                        .await
                        .is_err()
                );
                drop(client);
                tokio::time::timeout(Duration::from_secs(3), agent)
                    .await
                    .expect("closed child stdin disabled host-disconnect cleanup")
                    .unwrap();
            } else {
                assert_eq!(
                    read_exec_output(&mut client),
                    (b"done".to_vec(), Vec::new(), 7)
                );
                agent.await.unwrap();
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pipe_exec_kills_the_child_when_output_disconnects() {
        let (client, agent) = start_exec(
            &exec_request(&["sh", "-c", "printf out; exec sleep 600"], false),
            &CancellationToken::new(),
        );
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
            GuestUser::Root,
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
            let cancel = CancellationToken::new();
            let (mut client, agent) = start_exec(
                &exec_request(&["sh", "-c", "sleep 600 & echo $!; wait"], is_tty),
                &cancel,
            );
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
            &exec_request(&["sh", "-c", "echo OUT; echo ERR >&2; exit 3"], false),
            b"",
        )
        .await;
        assert_eq!((out, err, code), (b"OUT\n".to_vec(), b"ERR\n".to_vec(), 3));

        let (out, _, code) =
            run_exec_request(&exec_request(&["printf", "a\nb\n"], false), b"unread input").await;
        assert_eq!((out, code), (b"a\nb\n".to_vec(), 0));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pipe_exec_closes_stdin() {
        let (out, _, code) = run_exec_request(&exec_request(&["cat"], false), b"payload\n").await;
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
        let monitor = crate::into_async_fd(server.try_clone().unwrap()).unwrap();
        let mut server =
            crate::into_async_file(File::from(std::os::fd::OwnedFd::from(server))).unwrap();
        let pidfd = Arc::new(pidfd);
        let process = pidfd.clone();
        let mut pump = tokio::spawn(async move {
            pump_input(&mut server, stdin, false, &process, &monitor).await;
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

    /// A child that never reads stdin leaves the input pump stuck writing once the pipe fills, so
    /// no further frame is read; only the read-closed watch sees the host go and kills the child.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn host_disconnect_kills_a_child_whose_stdin_is_full() {
        let mut command = std::process::Command::new("sh");
        command
            .arg("-c")
            .arg("trap '' TERM; while :; do :; done")
            .stdin(std::process::Stdio::piped());
        let (mut child, pidfd) = crate::reap::spawn_owned(|| command.spawn()).unwrap();
        let stdin = crate::into_async_file(child.stdin.take().unwrap()).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let monitor = crate::into_async_fd(server.try_clone().unwrap()).unwrap();
        let mut server =
            crate::into_async_file(File::from(std::os::fd::OwnedFd::from(server))).unwrap();
        let pidfd = Arc::new(pidfd);
        let process = pidfd.clone();
        let mut pump = tokio::spawn(async move {
            pump_input(&mut server, stdin, false, &process, &monitor).await;
        });

        let host = std::thread::spawn(move || {
            let frame =
                terra_protocol::encode_frame(&ClientInput::Keys(vec![b'x'; 16 << 10])).unwrap();
            for _ in 0..10 {
                if client.write_all(&frame).is_err() {
                    break;
                }
            }
        });
        tokio::time::timeout(HARNESS_TIMEOUT, &mut pump)
            .await
            .expect("the pump kept writing to a child that never reads")
            .unwrap();
        host.join().unwrap();
        tokio::time::timeout(HARNESS_TIMEOUT, crate::reap::wait_owned(&pidfd))
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tty_exec_gets_a_terminal_and_input() {
        let (out, err, code) = run_exec_request(
            &exec_request(
                &["sh", "-c", "test -t 1 && echo yes; echo ERR >&2; exit 3"],
                true,
            ),
            b"",
        )
        .await;
        let output = String::from_utf8_lossy(&out);
        assert!(output.contains("yes") && output.contains("\r\n") && output.contains("ERR"));
        assert_eq!(err, [] as [u8; 0]);
        assert_eq!(code, 3);

        let (out, _, code) = run_exec_request(&exec_request(&["cat"], true), b"payload\n").await;
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
                run_exec_request(&exec_request(&["sh", "-c", "kill -TERM $$"], tty), b"").await;
            assert_eq!(code, 128 + rustix::process::Signal::TERM.as_raw());
        }

        let (out, err, code) =
            run_exec_request(&exec_request(&["/no/such/command"], false), b"").await;
        assert_eq!(code, EXEC_NOT_RUN);
        assert_eq!(out, [] as [u8; 0]);
        assert!(String::from_utf8_lossy(&err).contains("cannot run"));

        let (out, _, code) =
            run_exec_request(&exec_request(&["/no/such/command"], true), b"").await;
        assert_eq!(code, EXEC_NOT_RUN);
        assert!(String::from_utf8_lossy(&out).contains("cannot run"));

        assert_eq!(
            run_exec_request(&exec_request(&[], false), b"").await.2,
            EXEC_NOT_RUN
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exec_sets_home_and_overlays_environment() {
        let (out, _, code) =
            run_exec_request(&exec_request(&["sh", "-c", "echo $HOME"], false), b"").await;
        assert_eq!((out, code), (b"/home/terri\n".to_vec(), 0));

        let mut env = BTreeMap::new();
        env.insert("SUPPLIED_VAR".to_string(), "from_exec".to_string());
        env.insert("HOME".to_string(), "/custom/exec/home".to_string());
        for tty in [false, true] {
            let request = ExecRequest {
                env: env.clone(),
                ..exec_request(
                    &[
                        "sh",
                        "-c",
                        "echo $SUPPLIED_VAR; echo $HOME; test -n \"$PATH\" && echo has_path",
                    ],
                    tty,
                )
            };
            let (out, _, code) = run_exec_request(&request, b"").await;
            assert_eq!(code, 0);
            let output = String::from_utf8_lossy(&out);
            assert!(output.contains("from_exec"));
            assert!(output.contains("/custom/exec/home"));
            assert!(output.contains("has_path"));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn buffered_and_fragmented_input_is_not_discarded() {
        let first = vec![b'a'; 512 * 1024];
        let second = b"second frame".to_vec();
        let (mut client, agent) = start_exec(
            &exec_request(&["sh", "-c", "sleep .1; cat"], false),
            &CancellationToken::new(),
        );
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
        let receiver = crate::into_async_fd(receiver).unwrap();
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
