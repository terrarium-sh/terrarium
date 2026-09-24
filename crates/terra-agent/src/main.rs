//! Guest agent entrypoint: PID 1.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#[cfg(target_os = "linux")]
mod bootstrap;
#[cfg(target_os = "linux")]
mod config;
#[cfg(target_os = "linux")]
mod daemon;
#[cfg(target_os = "linux")]
mod diagnostics;
#[cfg(target_os = "linux")]
mod exec;
#[cfg(target_os = "linux")]
mod hooks;
#[cfg(target_os = "linux")]
mod mutex;
#[cfg(target_os = "linux")]
mod mux;
#[cfg(target_os = "linux")]
mod reap;
#[cfg(target_os = "linux")]
mod sync;
#[cfg(target_os = "linux")]
mod term {
    pub mod session;
    pub mod tty;
}
#[cfg(all(test, target_os = "linux"))]
mod tests;
#[cfg(target_os = "linux")]
mod vsock;
#[cfg(target_os = "linux")]
mod workload;

#[cfg(target_os = "linux")]
use {
    anyhow::Result,
    diagnostics::Diagnostics,
    std::{
        fs::{self, File},
        io::Write,
    },
    terra_protocol::{CLOCK_SYNC, LifecycleEvent, Plan, STOP_SIGNAL},
    tokio_util::{sync::CancellationToken, task::TaskTracker},
};

#[cfg(target_os = "linux")]
type AsyncFile = tokio_util::compat::Compat<async_io::Async<File>>;

#[cfg(target_os = "linux")]
fn into_async_file(file: impl Into<std::os::fd::OwnedFd>) -> std::io::Result<AsyncFile> {
    use tokio_util::compat::FuturesAsyncReadCompatExt;
    async_io::Async::new(File::from(file.into())).map(FuturesAsyncReadCompatExt::compat)
}

#[cfg(target_os = "linux")]
const AGENT_FAILED: i32 = 1;

#[cfg(target_os = "linux")]
fn main() -> ! {
    let (control, outcome, mux) = match bootstrap::enter_root() {
        Ok(bootstrap::Boot {
            plan,
            control,
            diagnostic,
            clients,
            mux,
        }) => {
            let outcome = run_agent(&plan, &control, diagnostic, clients);
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

#[cfg(target_os = "linux")]
#[tokio::main]
async fn run_agent(
    plan: &Plan,
    control: &File,
    diagnostic: File,
    clients: tokio::sync::mpsc::Receiver<File>,
) -> Result<i32> {
    let control_reader = crate::into_async_file(control.try_clone()?)?;
    let diagnostic = Diagnostics::new(diagnostic)?;
    let stop = CancellationToken::new();
    let shutdown = CancellationToken::new();
    let tasks = TaskTracker::new();
    tasks.spawn(crate::reap::watch_orphans(shutdown.clone()));
    tasks.spawn(watch_control(
        control_reader,
        stop.clone(),
        shutdown.clone(),
    ));
    diagnostic.record(b"agent received boot plan");
    let outcome = workload::execute(
        plan,
        control,
        &diagnostic,
        &stop,
        &shutdown,
        &tasks,
        clients,
    )
    .await;
    shutdown.cancel();
    tasks.close();
    tasks.wait().await;
    if let Err(error) = &outcome {
        diagnostic.record(format!("terra-agent: init failed: {error:#}").as_bytes());
    }
    diagnostic.finish().await;
    outcome
}

#[cfg(target_os = "linux")]
async fn report_agent_ready(control: &File) -> Result<()> {
    use anyhow::Context as _;
    use tokio::io::AsyncWriteExt as _;
    let mut control = into_async_file(control.try_clone()?)?;
    let frame = terra_protocol::encode_frame(&LifecycleEvent::AgentReady)?;
    control
        .write_all(&frame)
        .await
        .context("reporting guest agent readiness")?;
    control
        .flush()
        .await
        .context("flushing guest agent readiness")
}

#[cfg(target_os = "linux")]
fn write_exit_report(writer: &mut impl Write, code: i32) -> std::io::Result<()> {
    let frame = terra_protocol::encode_frame(&LifecycleEvent::Exit { code })?;
    writer.write_all(&frame).and_then(|()| writer.flush())
}

#[cfg(target_os = "linux")]
async fn watch_control(
    mut control: crate::AsyncFile,
    stop: CancellationToken,
    shutdown: CancellationToken,
) {
    use tokio::io::AsyncReadExt as _;
    shutdown
        .run_until_cancelled(async {
            let mut byte = [0u8; 1];
            loop {
                match control.read(&mut byte).await {
                    Ok(0) => break,
                    Ok(_) if byte[0] == STOP_SIGNAL => break,
                    Ok(_) if byte[0] == CLOCK_SYNC => {
                        if let Err(error) = bootstrap::read_clock_update(&mut control).await {
                            eprintln!("terra-agent: clock update failed ({error:#})");
                        }
                    }
                    Ok(_) => eprintln!("terra-agent: ignored invalid control command"),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        eprintln!(
                            "terra-agent: the control connection failed ({error}) - stopping"
                        );
                        break;
                    }
                }
            }
            stop.cancel();
        })
        .await;
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("terra-agent only runs on Linux");
    std::process::exit(1);
}

#[cfg(all(test, target_os = "linux"))]
fn create_scratch_path(module: &str, name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "terra-agent-{module}-{}-{name}",
        std::process::id()
    ))
}
