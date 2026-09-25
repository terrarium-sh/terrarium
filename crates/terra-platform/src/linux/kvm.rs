//! Linux Kernel Virtual Machine backends.

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "x86_64")]
pub mod amd64;

use crate::linux::runner::{PthreadPublication, install_kick_handler, unblock_kick_signal};
use crate::vm::{BootState, VcpuHandler, VcpuOutcome};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;
use std::{error, fmt};

pub const STOP_DEADLINE: Duration = Duration::from_secs(5);

pub(crate) enum VcpuCommand {
    Start(Box<dyn VcpuHandler>, BootState),
    Stop,
}

#[derive(Debug)]
pub enum KvmError {
    #[cfg(target_arch = "x86_64")]
    ApiVersion(i32),
    #[cfg(target_arch = "x86_64")]
    MissingCap(&'static str),
    #[cfg(target_arch = "x86_64")]
    NoVcpus,
    BadVcpuCount(usize),
    Memory(&'static str),
    Kvm(kvm_ioctls::Error),
    Operation(&'static str, kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    Bsp(amd64::arch::ArchError),
    #[cfg(target_arch = "x86_64")]
    Dispatch(amd64::kvm::DispatchError),
    #[cfg(target_arch = "aarch64")]
    InvalidInterruptController,
    #[cfg(target_arch = "aarch64")]
    TooManyDevices,
    #[cfg(target_arch = "aarch64")]
    UnexpectedExit(&'static str),
    Timeout,
    ThreadGone,
    KickHandler(std::io::Error),
    Handler(String),
}

impl From<kvm_ioctls::Error> for KvmError {
    fn from(error: kvm_ioctls::Error) -> Self {
        Self::Kvm(error)
    }
}

#[cfg(target_arch = "x86_64")]
impl From<amd64::kvm::DispatchError> for KvmError {
    fn from(error: amd64::kvm::DispatchError) -> Self {
        Self::Dispatch(error)
    }
}

impl fmt::Display for KvmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(target_arch = "x86_64")]
            Self::ApiVersion(version) => write!(formatter, "unsupported KVM API version {version}"),
            #[cfg(target_arch = "x86_64")]
            Self::MissingCap(capability) => {
                write!(formatter, "missing KVM capability {capability}")
            }
            #[cfg(target_arch = "x86_64")]
            Self::NoVcpus => formatter.write_str("KVM supports no vCPUs"),
            Self::BadVcpuCount(count) => write!(formatter, "invalid vCPU count: {count}"),
            Self::Memory(operation) => write!(formatter, "KVM memory {operation} failed"),
            Self::Kvm(error) => write!(formatter, "KVM error: {error}"),
            Self::Operation(operation, error) => write!(formatter, "{operation}: {error}"),
            #[cfg(target_arch = "x86_64")]
            Self::Bsp(error) => write!(formatter, "configuring x86 boot CPU: {error}"),
            #[cfg(target_arch = "x86_64")]
            Self::Dispatch(error) => write!(formatter, "KVM exit dispatch failed: {error}"),
            Self::Timeout => formatter.write_str("KVM vCPU stop timed out"),
            Self::ThreadGone => formatter.write_str("KVM vCPU thread exited"),
            Self::KickHandler(error) => {
                write!(formatter, "installing KVM vCPU kick handler: {error}")
            }
            #[cfg(target_arch = "aarch64")]
            Self::InvalidInterruptController => {
                formatter.write_str("ARM interrupt controller required")
            }
            #[cfg(target_arch = "aarch64")]
            Self::TooManyDevices => formatter.write_str("too many ARM devices"),
            #[cfg(target_arch = "aarch64")]
            Self::UnexpectedExit(exit) => write!(formatter, "unexpected KVM vCPU exit: {exit}"),
            Self::Handler(error) => write!(formatter, "vCPU handler: {error}"),
        }
    }
}

impl error::Error for KvmError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Kvm(error) | Self::Operation(_, error) => Some(error),
            #[cfg(target_arch = "x86_64")]
            Self::Bsp(error) => Some(error),
            #[cfg(target_arch = "x86_64")]
            Self::Dispatch(error) => Some(error),
            Self::KickHandler(error) => Some(error),
            #[cfg(target_arch = "x86_64")]
            Self::ApiVersion(_) | Self::MissingCap(_) | Self::NoVcpus => None,
            #[cfg(target_arch = "aarch64")]
            Self::InvalidInterruptController | Self::TooManyDevices | Self::UnexpectedExit(_) => {
                None
            }
            Self::BadVcpuCount(_)
            | Self::Memory(_)
            | Self::Timeout
            | Self::ThreadGone
            | Self::Handler(_) => None,
        }
    }
}

/// Handle to a running vCPU thread.
pub struct VcpuHandle {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    runner: PthreadPublication,
    done: mpsc::Receiver<Result<VcpuOutcome, KvmError>>,
}

fn spawn_runner(
    id: u64,
    run: impl FnOnce(&AtomicBool) -> Result<VcpuOutcome, KvmError> + Send + 'static,
) -> Result<VcpuHandle, KvmError> {
    install_kick_handler().map_err(KvmError::KickHandler)?;
    let stop = Arc::new(AtomicBool::new(false));
    let runner = PthreadPublication::new();
    let (done_tx, done_rx) = mpsc::channel();
    let stop_child = Arc::clone(&stop);
    let runner_child = runner.clone();
    let thread = std::thread::Builder::new()
        .name(format!("vcpu-{id}"))
        .spawn(move || {
            let outcome = unblock_kick_signal()
                .map_err(KvmError::KickHandler)
                .and_then(|()| {
                    let _published = runner_child.publish();
                    run(&stop_child)
                });
            finish_runner(&runner_child, &done_tx, outcome);
        })
        .map_err(|_| KvmError::ThreadGone)?;
    Ok(VcpuHandle {
        stop,
        thread: Some(thread),
        runner,
        done: done_rx,
    })
}

/// Wait for setup before returning; x86 APs must be ready before the BSP can send SIPIs.
pub fn spawn_configured_vcpu_ready(
    id: u64,
    run: impl FnOnce(&AtomicBool, &mpsc::SyncSender<()>) -> Result<VcpuOutcome, KvmError>
    + Send
    + 'static,
) -> Result<VcpuHandle, KvmError> {
    let (ready_tx, ready_rx) = mpsc::sync_channel(0);
    let mut handle = spawn_runner(id, move |stop| run(stop, &ready_tx))?;
    match ready_rx.recv_timeout(STOP_DEADLINE) {
        Ok(()) => Ok(handle),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(KvmError::Timeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            handle.stop(STOP_DEADLINE)?;
            Err(KvmError::ThreadGone)
        }
    }
}

fn finish_runner(
    runner: &PthreadPublication,
    done: &mpsc::Sender<Result<VcpuOutcome, KvmError>>,
    outcome: Result<VcpuOutcome, KvmError>,
) {
    runner.clear();
    let _ = done.send(outcome);
}

impl VcpuHandle {
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.runner.kick();
    }

    /// A timeout retains the thread handle so the caller can reap it later.
    pub fn stop(&mut self, deadline: Duration) -> Result<VcpuOutcome, KvmError> {
        self.request_stop();
        let start = std::time::Instant::now();
        while start.elapsed() < deadline {
            self.runner.kick();
            let remaining = deadline.saturating_sub(start.elapsed());
            let wait = remaining.min(Duration::from_millis(20));
            match self.done.recv_timeout(wait) {
                Ok(outcome) => {
                    if let Some(thread) = self.thread.take() {
                        let _ = thread.join();
                    }
                    return outcome;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    if let Some(thread) = self.thread.take() {
                        let _ = thread.join();
                    }
                    return Err(KvmError::ThreadGone);
                }
            }
        }
        Err(KvmError::Timeout)
    }
}

impl Drop for VcpuHandle {
    fn drop(&mut self) {
        let _ = self.stop(STOP_DEADLINE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_command_wakes_a_runner_waiting_to_start() {
        let (sender, receiver) = mpsc::channel();
        let mut handle = spawn_configured_vcpu_ready(0, move |stop, ready| {
            ready.send(()).unwrap();
            assert!(matches!(receiver.recv().unwrap(), VcpuCommand::Stop));
            assert!(stop.load(Ordering::Acquire));
            Ok(VcpuOutcome::Stopped)
        })
        .unwrap();
        handle.request_stop();
        sender.send(VcpuCommand::Stop).unwrap();
        assert_eq!(handle.stop(STOP_DEADLINE).unwrap(), VcpuOutcome::Stopped);
        assert!(handle.thread.is_none());
    }

    #[test]
    fn setup_failure_is_returned_before_readiness() {
        assert!(matches!(
            spawn_configured_vcpu_ready(0, |_, _| Err(KvmError::Memory("setup"))),
            Err(KvmError::Memory("setup"))
        ));
    }

    #[test]
    fn runner_panics_are_reaped_before_and_after_readiness() {
        assert!(matches!(
            spawn_configured_vcpu_ready(0, |_, _| panic!("setup failed")),
            Err(KvmError::ThreadGone)
        ));
        let mut handle = spawn_configured_vcpu_ready(0, |_, ready| {
            ready.send(()).unwrap();
            panic!("runner failed");
        })
        .unwrap();
        assert!(matches!(
            handle.stop(STOP_DEADLINE),
            Err(KvmError::ThreadGone)
        ));
        assert!(handle.thread.is_none());
        assert!(!handle.runner.is_published());
    }

    #[test]
    fn runner_unpublishes_before_reporting_its_outcome() {
        let runner = PthreadPublication::new();
        let _published = runner.publish();
        let (done_tx, done) = mpsc::channel();
        finish_runner(&runner, &done_tx, Ok(VcpuOutcome::Stopped));
        assert!(matches!(
            done.recv().expect("outcome"),
            Ok(VcpuOutcome::Stopped)
        ));
        assert!(!runner.is_published());
    }

    #[test]
    fn dropping_a_publication_clone_keeps_a_live_runner_kickable() {
        let runner = PthreadPublication::new();
        let _published = runner.publish();
        drop(runner.clone());
        assert!(runner.is_published());
    }

    #[test]
    fn publication_guard_clears_its_runner() {
        let runner = PthreadPublication::new();
        let published = runner.publish();
        assert!(runner.is_published());
        drop(published);
        assert!(!runner.is_published());
    }

    #[test]
    fn publication_guard_clears_during_unwind() {
        let runner = PthreadPublication::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _published = runner.publish();
            panic!("runner failed");
        }));
        assert!(result.is_err());
        assert!(!runner.is_published());
    }

    #[test]
    fn stop_timeout_keeps_the_runner_for_later_reap() {
        let resource = Arc::new(());
        let resource_lifetime = Arc::downgrade(&resource);
        let release = Arc::new(AtomicBool::new(false));
        let runner_release = Arc::clone(&release);
        let mut handle = spawn_runner(0, move |_| {
            while !runner_release.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            drop(resource);
            Ok(VcpuOutcome::Stopped)
        })
        .unwrap();
        while !handle.runner.is_published() {
            std::thread::yield_now();
        }
        assert!(matches!(
            handle.stop(Duration::ZERO),
            Err(KvmError::Timeout)
        ));
        assert!(handle.thread.is_some());
        assert!(resource_lifetime.upgrade().is_some());
        release.store(true, Ordering::Release);
        assert_eq!(
            handle.stop(Duration::from_secs(1)).expect("reap"),
            VcpuOutcome::Stopped
        );
        assert!(resource_lifetime.upgrade().is_none());
    }

    #[test]
    fn dropping_a_live_handle_reaps_its_runner() {
        let completed = Arc::new(AtomicBool::new(false));
        let runner_completed = Arc::clone(&completed);
        let handle = spawn_runner(0, move |stop| {
            while !stop.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            runner_completed.store(true, Ordering::Release);
            Ok(VcpuOutcome::Stopped)
        })
        .unwrap();
        drop(handle);
        assert!(completed.load(Ordering::Acquire));
    }

    #[test]
    fn runner_failure_is_reaped_and_unpublished() {
        let mut handle = spawn_runner(0, |_| Err(KvmError::ThreadGone)).unwrap();
        assert!(matches!(
            handle.stop(Duration::from_secs(1)),
            Err(KvmError::ThreadGone)
        ));
        assert!(handle.thread.is_none());
        assert!(!handle.runner.is_published());
    }
}
