//! The guest agent, PID 1 in every box; it only exists on Linux.
#![cfg(target_os = "linux")]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
mod agent;
mod bootstrap;
mod config;
mod daemon;
mod diagnostics;
mod exec;
mod hooks;
mod mutex;
mod mux;
mod network;
mod reap;
mod services;
mod sync;
mod term {
    pub mod session;
    pub mod tty;
}
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

type AsyncFile = tokio_util::compat::Compat<async_io::Async<File>>;

fn into_async_file(file: impl Into<std::os::fd::OwnedFd>) -> std::io::Result<AsyncFile> {
    use tokio_util::compat::FuturesAsyncReadCompatExt;
    async_io::Async::new(File::from(file.into())).map(FuturesAsyncReadCompatExt::compat)
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

async fn wait_for_tasks_or_cancel(
    tasks: &tokio_util::task::TaskTracker,
    cancellation: &tokio_util::sync::CancellationToken,
    grace: std::time::Duration,
) {
    if tokio::time::timeout(grace, tasks.wait()).await.is_err() {
        cancellation.cancel();
        tasks.wait().await;
    }
}

const AGENT_FAILED: i32 = 1;

/// How long the workload and daemons get between `TERM` and `KILL`.
const STOP_GRACE: std::time::Duration =
    std::time::Duration::from_secs(terra_protocol::DEFAULT_STOP_GRACE_SECS);

/// Enters the guest root, carries out the boot plan, reports its exit and powers the VM off.
pub fn run() -> ! {
    let (control, outcome, mux) = match bootstrap::enter_root() {
        Ok((
            plan,
            mux::Streams {
                control,
                diagnostic,
                clients,
                driver: mux,
            },
        )) => {
            let outcome = run_agent(&plan, &control, diagnostic, clients);
            let cleanup = bootstrap::leave_filesystems_clean(&plan);
            let outcome = outcome.and_then(|code| cleanup.map(|()| code));
            if let Ok(flags) = rustix::fs::fcntl_getfl(&control) {
                let _ = rustix::fs::fcntl_setfl(&control, flags & !rustix::fs::OFlags::NONBLOCK);
            }
            (Some(control), outcome, Some(mux))
        }
        Err(error) => (None, Err(error), None),
    };
    if let Err(error) = &outcome {
        eprintln!("terra-agent: init failed: {error:#}");
        if let Ok(mut kernel_log) = fs::OpenOptions::new().write(true).open("/dev/kmsg") {
            let _ =
                kernel_log.write_all(format!("terra-agent: init failed: {error:#}\n").as_bytes());
        }
    }
    let code = *outcome.as_ref().unwrap_or(&AGENT_FAILED);
    // Disk sync precedes the report so host teardown can safely race it.
    rustix::fs::sync();
    if let Some(mut control) = control {
        if let Err(error) = write_exit_report(&mut control, code) {
            eprintln!("terra-agent: warning: could not report the exit status ({code}): {error}");
        } else if let Some(mux) = mux {
            // Keep virtio alive for the exit frame until the host closes the carrier.
            mux.wait();
        }
    }
    if let Err(error) = rustix::system::reboot(rustix::system::RebootCommand::PowerOff) {
        eprintln!("terra-agent: could not power off after reporting exit status: {error}");
    }
    std::process::exit(i32::from(outcome.is_err()))
}

#[tokio::main]
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

    #[test]
    fn exit_report_is_framed_before_shutdown() {
        let mut agent = Vec::new();
        write_exit_report(&mut agent, 23).unwrap();
        assert_eq!(
            terra_protocol::read_frame::<LifecycleEvent>(&mut agent.as_slice()).unwrap(),
            Some(LifecycleEvent::Exit { code: 23 })
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn events_exit_report_and_diagnostic_are_framed() {
        let (mut agent, mut host) = UnixStream::pair().unwrap();
        let mut diagnostic =
            crate::into_async_file(File::from(OwnedFd::from(agent.try_clone().unwrap()))).unwrap();
        write_diagnostic(&mut diagnostic, b"hook output")
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
