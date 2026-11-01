//! The guest agent, PID 1 in every box; it only exists on Linux.
#![cfg(target_os = "linux")]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
mod agent;
mod bootstrap;
mod daemon;
mod diagnostics;
mod exec;
mod loopback;
mod mounts;
mod mux;
mod network;
mod reap;
mod services;
mod session;
mod sync;
mod workload;

use {
    agent::Agent,
    anyhow::Result,
    std::{
        fs::{self, File},
        io::Write,
    },
    terra_protocol::{LifecycleEvent, Plan, PlanMode},
};

/// A non-blocking descriptor on tokio's reactor, read and written as a tokio stream.
struct AsyncFile(tokio::io::unix::AsyncFd<File>);

impl AsyncFile {
    fn get_ref(&self) -> &File {
        self.0.get_ref()
    }

    fn into_inner(self) -> File {
        self.0.into_inner()
    }
}

impl tokio::io::AsyncRead for AsyncFile {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::io::Read as _;
        loop {
            let mut ready = std::task::ready!(self.0.poll_read_ready(context))?;
            if let Ok(read) = ready.try_io(|fd| fd.get_ref().read(buffer.initialize_unfilled())) {
                buffer.advance(read?);
                return std::task::Poll::Ready(Ok(()));
            }
        }
    }
}

impl tokio::io::AsyncWrite for AsyncFile {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        loop {
            let mut ready = std::task::ready!(self.0.poll_write_ready(context))?;
            if let Ok(written) = ready.try_io(|fd| fd.get_ref().write(bytes)) {
                return std::task::Poll::Ready(written);
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

fn into_async_file(file: impl Into<std::os::fd::OwnedFd>) -> std::io::Result<AsyncFile> {
    let file = file.into();
    rustix::io::ioctl_fionbio(&file, true)?;
    into_async_fd(file).map(AsyncFile)
}

#[allow(unsafe_code)]
fn into_async_fd(
    fd: impl Into<std::os::fd::OwnedFd>,
) -> std::io::Result<tokio::io::unix::AsyncFd<File>> {
    // SAFETY: the `AsyncFd` owns the `File`, and no caller swaps it through `get_mut`, so the
    // registered descriptor stays open and unchanged until the `AsyncFd` drops.
    unsafe { tokio::io::unix::AsyncFd::register(File::from(fd.into())) }
        .map_err(std::io::Error::from)
}

/// A hook or daemon line, run by the shell in its own process group with its output on `terminal`.
fn recipe_shell_command(
    line: &str,
    terminal: std::os::fd::BorrowedFd<'_>,
) -> std::io::Result<std::process::Command> {
    use std::os::unix::process::CommandExt as _;

    let mut command = std::process::Command::new("sh");
    command
        .arg("-c")
        .arg(line)
        .process_group(0)
        .stdout(terminal.try_clone_to_owned()?)
        .stderr(terminal.try_clone_to_owned()?);
    Ok(command)
}

fn lock_or_abort<T: ?Sized>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(_) => std::process::abort(),
    }
}

const AGENT_FAILED: i32 = 1;

/// How long a finished process's output still reaches the client; a descendant can hold its
/// pipe or terminal open forever.
const OUTPUT_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// How long the workload and daemons get between `TERM` and `KILL`.
const STOP_GRACE: std::time::Duration =
    std::time::Duration::from_secs(terra_protocol::DEFAULT_STOP_GRACE_SECS);

/// Enters the guest root, carries out the boot plan, reports its exit and powers the VM off.
pub fn run() -> ! {
    let failed = boot_and_report();
    if let Err(error) = rustix::system::reboot(rustix::system::RebootCommand::PowerOff) {
        eprintln!("terra-agent: could not power off after reporting exit status: {error}");
    }
    std::process::exit(i32::from(failed))
}

/// Carries out the boot and reports its exit; `true` means the boot failed.
// A fixed count: the agent's own load does not grow with the box's vCPUs.
#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn boot_and_report() -> bool {
    let (outcome, host_link) = match bootstrap::enter_root() {
        Ok((
            plan,
            mux::Streams {
                control,
                diagnostic,
                clients,
                driver: mux,
            },
        )) => {
            let outcome = run_agent(&plan, &control, diagnostic, clients).await;
            let cleanup = bootstrap::leave_filesystems_clean(&plan);
            let outcome = outcome.and_then(|code| cleanup.map(|()| code));
            if let Ok(flags) = rustix::fs::fcntl_getfl(&control) {
                let _ = rustix::fs::fcntl_setfl(&control, flags & !rustix::fs::OFlags::NONBLOCK);
            }
            (outcome, Some((control, mux)))
        }
        Err(error) => (Err(error), None),
    };
    if let Err(error) = &outcome {
        let message = format!("terra-agent: init failed: {error:#}\n");
        eprint!("{message}");
        if let Ok(mut kernel_log) = fs::OpenOptions::new().write(true).open("/dev/kmsg") {
            let _ = kernel_log.write_all(message.as_bytes());
        }
    }
    let code = *outcome.as_ref().unwrap_or(&AGENT_FAILED);
    // Disk sync precedes the report so host teardown can safely race it.
    rustix::fs::sync();
    if let Some((mut control, mux)) = host_link {
        match write_exit_report(&mut control, code) {
            // Keep virtio alive for the exit frame until the host closes the carrier.
            Ok(()) => mux.wait().await,
            Err(error) => eprintln!(
                "terra-agent: warning: could not report the exit status ({code}): {error}"
            ),
        }
    }
    outcome.is_err()
}

async fn run_agent(
    plan: &Plan,
    control: &File,
    diagnostic: File,
    clients: tokio::sync::mpsc::Receiver<File>,
) -> Result<i32> {
    let agent = Agent::init(control, diagnostic)?;
    let outcome = match plan.mode {
        PlanMode::Create => agent.setup(plan, clients).await,
        PlanMode::Run => agent.run(plan, clients).await,
    };
    agent.close(&outcome).await;
    outcome
}

fn write_exit_report(writer: &mut impl Write, code: i32) -> std::io::Result<()> {
    let frame = terra_protocol::encode_frame(&LifecycleEvent::Exit { code })?;
    writer.write_all(&frame).and_then(|()| writer.flush())
}

/// The pid a test's child wrote to `path`, once it is there.
#[cfg(test)]
async fn read_pid_file(path: &std::path::Path) -> rustix::process::Pid {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(pid) = fs::read_to_string(path)
                .ok()
                .and_then(|text| text.trim().parse().ok())
                .and_then(rustix::process::Pid::from_raw)
            {
                return pid;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the child never wrote its pid")
}

#[cfg(test)]
fn create_scratch_path(module: &str, name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "terra-agent-{module}-{}-{name}",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::write as write_diagnostic;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn events_exit_report_and_diagnostic_are_framed() {
        let (mut agent, mut host) = UnixStream::pair().unwrap();
        let mut diagnostic =
            crate::into_async_file(File::from(OwnedFd::from(agent.try_clone().unwrap()))).unwrap();
        write_diagnostic(&mut diagnostic, b"hook output".to_vec())
            .await
            .unwrap();
        drop(diagnostic);
        write_exit_report(&mut agent, 23).unwrap();

        assert_eq!(
            terra_protocol::read_frame(&mut host).unwrap(),
            Some(LifecycleEvent::Diagnostic {
                bytes: b"hook output".to_vec()
            })
        );
        assert_eq!(
            terra_protocol::read_frame(&mut host).unwrap(),
            Some(LifecycleEvent::Exit { code: 23 })
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_socket_transfers_more_than_its_buffer_without_blocking() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let mut sender = crate::into_async_file(sender).unwrap();
        let mut receiver = crate::into_async_file(receiver).unwrap();
        let payload = vec![42; 1 << 20];
        let sending = tokio::spawn(async move {
            sender.write_all(&payload).await.unwrap();
            rustix::net::shutdown(sender.get_ref(), rustix::net::Shutdown::Write).unwrap();
        });
        let mut output = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            receiver.read_to_end(&mut output).await.unwrap();
            sending.await.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(output, vec![42; 1 << 20]);
    }
}
