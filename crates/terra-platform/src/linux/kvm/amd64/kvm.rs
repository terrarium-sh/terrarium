//! Native x86 KVM resources, exit conversion and vCPU thread ownership.

#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use kvm_bindings::{KVM_API_VERSION, kvm_userspace_memory_region};
use kvm_ioctls::{Cap, Kvm, VcpuExit, VcpuFd, VmFd};
use vm_memory::{GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

use crate::machine::{Layout, MAX_VCPUS};
use crate::runner::{PthreadPublication, install_kick_handler, unblock_kick_signal};
use terra_runtime::component::vmm::{Completion, Exit, NativeVcpu, platform};

/// Largest PIO transfer completed in one exit (the `kvm_run` buffer).
pub const MAX_IO_BYTES: usize = 8192;
/// Largest MMIO transfer: architecturally 1/2/4/8 bytes.
pub const MAX_MMIO_BYTES: usize = 8;
/// How long `stop` waits for a kicked vCPU before giving up.
pub const STOP_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum KvmError {
    ApiVersion(i32),
    MissingCap(&'static str),
    NoVcpus,
    BadVcpuCount(usize),
    Memory(&'static str),
    Kvm(kvm_ioctls::Error),
    Dispatch(DispatchError),
    Timeout,
    ThreadGone,
    KickHandler(std::io::Error),
    Component(String),
}

impl From<wasmtime::Error> for KvmError {
    fn from(error: wasmtime::Error) -> Self {
        Self::Component(format!("{error:#}"))
    }
}

impl From<kvm_ioctls::Error> for KvmError {
    fn from(error: kvm_ioctls::Error) -> Self {
        Self::Kvm(error)
    }
}

impl From<DispatchError> for KvmError {
    fn from(error: DispatchError) -> Self {
        Self::Dispatch(error)
    }
}

pub fn open() -> Result<Kvm, KvmError> {
    let kvm = Kvm::new()?;
    let api = u32::try_from(kvm.get_api_version()).map_err(|_| KvmError::ApiVersion(-1))?;
    if api != KVM_API_VERSION {
        return Err(KvmError::ApiVersion(kvm.get_api_version()));
    }
    if !kvm.check_extension(Cap::UserMemory) {
        return Err(KvmError::MissingCap("KVM_CAP_USER_MEMORY"));
    }
    let max_vcpus = kvm.get_max_vcpus();
    if kvm.get_nr_vcpus() == 0 || max_vcpus == 0 {
        return Err(KvmError::NoVcpus);
    }
    Ok(kvm)
}

/// One static machine: VM fd plus owned guest RAM. Field order is the
/// drop order: the VM closes before its RAM unmaps. The mapping is
/// reference-counted so device stores can alias it: the VM fd still
/// closes first, and the pages outlive every runner and device.
pub struct Machine {
    vm: VmFd,
    ram: Arc<GuestMemoryMmap>,
}

impl terra_runtime::component::vmm::VirtualMachine for Machine {
    fn memory(&self) -> wasmtime::Result<terra_runtime::memory::GuestRam> {
        terra_runtime::memory::GuestRam::from_shared(self.shared_ram())
            .ok_or_else(|| wasmtime::Error::msg("aliasing KVM guest RAM"))
    }
}

impl Machine {
    /// Create the VM, map the layout's RAM as slot 0, and check the vCPU
    /// count against both the static ceiling and the host limit. KVM
    /// resources are created here, never in a parent and transferred.
    pub fn new(kvm: &Kvm, layout: &Layout, vcpu_count: usize) -> Result<Self, KvmError> {
        if vcpu_count == 0 || vcpu_count > MAX_VCPUS {
            return Err(KvmError::BadVcpuCount(vcpu_count));
        }
        if vcpu_count > kvm.get_max_vcpus() {
            return Err(KvmError::BadVcpuCount(vcpu_count));
        }
        let vm = kvm.create_vm()?;
        let ram_size =
            usize::try_from(layout.ram_size()).map_err(|_| KvmError::Memory("ram-size"))?;
        let ram = Arc::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), ram_size)])
                .map_err(|_| KvmError::Memory("map"))?,
        );
        let host_addr = ram
            .get_host_address(GuestAddress(0))
            .map_err(|_| KvmError::Memory("host-addr"))?;
        let region = kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: layout.ram_size(),
            userspace_addr: host_addr as u64,
        };
        // SAFETY: `host_addr` is the base of the live `vm-memory` mapping
        // held in `self.ram`; slot 0 is unique; size matches the mapping;
        // `Machine` drops `vm` before `ram` and outlives every runner, so
        // KVM never touches unmapped memory.
        unsafe { vm.set_user_memory_region(region)? };
        Ok(Self { vm, ram })
    }

    pub fn create_vcpu(&self, id: u64) -> Result<VcpuFd, KvmError> {
        Ok(self.vm.create_vcpu(id)?)
    }

    #[must_use]
    pub fn vm_fd(&self) -> &VmFd {
        &self.vm
    }

    /// Alias the guest mapping for a device store. The device's memory
    /// imports then operate on this VM's RAM under the same bounds, not
    /// on a private copy.
    #[must_use]
    pub fn shared_ram(&self) -> Arc<GuestMemoryMmap> {
        Arc::clone(&self.ram)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    Unexpected(&'static str),
    /// Entry/hardware failure or an exit newer than this crate release.
    Fatal(&'static str, u64),
    TooLarge,
}

/// Outcome reported by a runner thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VcpuOutcome {
    Shutdown,
    Stopped,
}

fn trace_exit(exit: &str) {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *ENABLED.get_or_init(|| std::env::var_os("TERRA_BOOT_TRACE").is_some()) {
        eprintln!("BOOT TRACE {exit}");
    }
}

fn component_completion(vcpu: &NativeVcpu, exit: Exit) -> Result<Completion, KvmError> {
    vcpu.exchange(exit)
        .map_err(|error| KvmError::Component(format!("vCPU component: {error:#}")))
}

fn require_reentry(completion: Completion) -> Result<(), KvmError> {
    matches!(completion, Completion::Reenter)
        .then_some(())
        .ok_or_else(|| KvmError::Component("vCPU completion must reenter".to_owned()))
}

fn mmio_width(length: usize) -> Result<u8, KvmError> {
    match length {
        1 | 2 | 4 | 8 => {
            u8::try_from(length).map_err(|_| KvmError::Dispatch(DispatchError::TooLarge))
        }
        _ => Err(KvmError::Dispatch(DispatchError::TooLarge)),
    }
}

fn pio_length(length: usize) -> Result<u32, KvmError> {
    if length > MAX_IO_BYTES {
        return Err(KvmError::Dispatch(DispatchError::TooLarge));
    }
    u32::try_from(length).map_err(|_| KvmError::Dispatch(DispatchError::TooLarge))
}

fn mmio_value(bytes: &[u8]) -> Result<u64, KvmError> {
    let mut value = [0; MAX_MMIO_BYTES];
    value
        .get_mut(..bytes.len())
        .ok_or(KvmError::Dispatch(DispatchError::TooLarge))?
        .copy_from_slice(bytes);
    Ok(u64::from_le_bytes(value))
}

fn unexpected_completion(expected: &'static str) -> KvmError {
    KvmError::Component(format!("vCPU completion must be {expected}"))
}

#[allow(clippy::too_many_lines)]
fn dispatch_kernel_exit(
    component: &NativeVcpu,
    stop: &AtomicBool,
    exit: VcpuExit<'_>,
) -> Result<Option<VcpuOutcome>, KvmError> {
    match exit {
        VcpuExit::IoIn(port, data) => {
            let completion = component_completion(
                component,
                Exit::PioRead(platform::PioRead {
                    port,
                    length: pio_length(data.len())?,
                }),
            )?;
            if !matches!(completion, Completion::PioZero) {
                return Err(unexpected_completion("pio-zero"));
            }
            data.fill(0);
        }
        VcpuExit::IoOut(port, data) => {
            require_reentry(component_completion(
                component,
                Exit::PioWrite(platform::PioWrite {
                    port,
                    length: pio_length(data.len())?,
                }),
            )?)?;
        }
        VcpuExit::MmioRead(address, data) => {
            let width = mmio_width(data.len())?;
            let completion = component_completion(
                component,
                Exit::MmioRead(platform::MmioRead { address, width }),
            )?;
            let Completion::MmioRead(value) = completion else {
                return Err(unexpected_completion("mmio-read"));
            };
            data.copy_from_slice(&value.to_le_bytes()[..usize::from(width)]);
        }
        VcpuExit::MmioWrite(address, data) => {
            let width = mmio_width(data.len())?;
            require_reentry(component_completion(
                component,
                Exit::MmioWrite(platform::MmioWrite {
                    address,
                    width,
                    value: mmio_value(data)?,
                }),
            )?)?;
        }
        VcpuExit::X86Rdmsr(msr) => {
            trace_exit("rdmsr");
            let completion = component_completion(
                component,
                Exit::Rdmsr(platform::Msr {
                    index: msr.index,
                    value: 0,
                }),
            )?;
            match completion {
                Completion::Rdmsr(value) => {
                    *msr.data = value;
                    *msr.error = 0;
                }
                Completion::MsrFault => *msr.error = 1,
                _ => return Err(unexpected_completion("rdmsr")),
            }
        }
        VcpuExit::X86Wrmsr(msr) => {
            trace_exit("wrmsr");
            match component_completion(
                component,
                Exit::Wrmsr(platform::Msr {
                    index: msr.index,
                    value: msr.data,
                }),
            )? {
                Completion::Wrmsr => *msr.error = 0,
                Completion::MsrFault => *msr.error = 1,
                _ => return Err(unexpected_completion("wrmsr")),
            }
        }
        VcpuExit::Hlt => {
            trace_exit("hlt");
            require_reentry(component_completion(component, Exit::Halt)?)?;
        }
        VcpuExit::Intr | VcpuExit::IoapicEoi(_) => {
            if stop.load(Ordering::Acquire) {
                return Ok(Some(VcpuOutcome::Stopped));
            }
            trace_exit("interrupted");
            require_reentry(component_completion(component, Exit::Interrupted)?)?;
        }
        VcpuExit::Shutdown => {
            let _ = component.exchange(Exit::Shutdown);
            return Ok(Some(VcpuOutcome::Shutdown));
        }
        VcpuExit::FailEntry(reason, _) => {
            return Err(KvmError::Dispatch(DispatchError::Fatal(
                "fail-entry",
                reason,
            )));
        }
        VcpuExit::InternalError => {
            return Err(KvmError::Dispatch(DispatchError::Fatal(
                "internal-error",
                0,
            )));
        }
        VcpuExit::Unsupported(code) => {
            return Err(KvmError::Dispatch(DispatchError::Fatal(
                "unsupported-exit",
                u64::from(code),
            )));
        }
        VcpuExit::Unknown => return Err(KvmError::Dispatch(DispatchError::Unexpected("unknown"))),
        VcpuExit::Exception => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("exception")));
        }
        VcpuExit::Hypercall(_) => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("hypercall")));
        }
        VcpuExit::Debug(_) => return Err(KvmError::Dispatch(DispatchError::Unexpected("debug"))),
        VcpuExit::IrqWindowOpen => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected(
                "irq-window-open",
            )));
        }
        VcpuExit::SetTpr => return Err(KvmError::Dispatch(DispatchError::Unexpected("set-tpr"))),
        VcpuExit::TprAccess => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("tpr-access")));
        }
        VcpuExit::S390Sieic => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("s390-sieic")));
        }
        VcpuExit::S390Reset => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("s390-reset")));
        }
        VcpuExit::Dcr => return Err(KvmError::Dispatch(DispatchError::Unexpected("dcr"))),
        VcpuExit::Nmi => return Err(KvmError::Dispatch(DispatchError::Unexpected("nmi"))),
        VcpuExit::Osi => return Err(KvmError::Dispatch(DispatchError::Unexpected("osi"))),
        VcpuExit::PaprHcall => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("papr-hcall")));
        }
        VcpuExit::S390Ucontrol => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected(
                "s390-ucontrol",
            )));
        }
        VcpuExit::Watchdog => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("watchdog")));
        }
        VcpuExit::S390Tsch => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("s390-tsch")));
        }
        VcpuExit::Epr => return Err(KvmError::Dispatch(DispatchError::Unexpected("epr"))),
        VcpuExit::SystemEvent(_, _) => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected(
                "system-event",
            )));
        }
        VcpuExit::S390Stsi => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("s390-stsi")));
        }
        VcpuExit::Hyperv => return Err(KvmError::Dispatch(DispatchError::Unexpected("hyperv"))),
        VcpuExit::MemoryFault { .. } => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected(
                "memory-fault",
            )));
        }
    }
    Ok(None)
}

/// Run one Linux KVM vCPU through the scoped Wasm VMM bridge. Native code only
/// turns KVM's borrowed exit buffers into typed values and applies validated
/// completions before reentering KVM.
pub fn run_kernel_vcpu(
    vcpu: &mut VcpuFd,
    stop: &AtomicBool,
    component: &NativeVcpu,
) -> Result<VcpuOutcome, KvmError> {
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(VcpuOutcome::Stopped);
        }
        match vcpu.run() {
            Ok(exit) => {
                if let Some(outcome) = dispatch_kernel_exit(component, stop, exit)? {
                    return Ok(outcome);
                }
            }
            Err(error) if error.errno() == libc::EINTR || error.errno() == libc::EAGAIN => {
                if stop.load(Ordering::Acquire) {
                    return Ok(VcpuOutcome::Stopped);
                }
            }
            Err(error) => return Err(KvmError::Kvm(error)),
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
    machine: Arc<Machine>,
    id: u64,
    run: impl FnOnce(&mut VcpuFd, &AtomicBool) -> Result<VcpuOutcome, KvmError> + Send + 'static,
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
                    machine
                        .create_vcpu(id)
                        .and_then(|mut vcpu| run(&mut vcpu, &stop_child))
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

/// Spawn a vCPU and wait until `run` has completed setup and published its
/// readiness. Callers use this for APs before allowing a BSP to send SIPIs.
pub fn spawn_configured_vcpu_ready(
    machine: Arc<Machine>,
    id: u64,
    run: impl FnOnce(&mut VcpuFd, &AtomicBool, &mpsc::SyncSender<()>) -> Result<VcpuOutcome, KvmError>
    + Send
    + 'static,
) -> Result<VcpuHandle, KvmError> {
    let (ready_tx, ready_rx) = mpsc::sync_channel(0);
    let handle = spawn_runner(machine, id, move |vcpu, stop| run(vcpu, stop, &ready_tx))?;
    ready_rx
        .recv_timeout(STOP_DEADLINE)
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => KvmError::Timeout,
            mpsc::RecvTimeoutError::Disconnected => KvmError::ThreadGone,
        })?;
    Ok(handle)
}

/// Park an application processor until the guest sends INIT/SIPI.
#[cfg(target_arch = "x86_64")]
pub fn park_ap(vcpu: &VcpuFd) -> Result<(), KvmError> {
    vcpu.set_mp_state(kvm_bindings::kvm_mp_state {
        mp_state: kvm_bindings::KVM_MP_STATE_UNINITIALIZED,
    })?;
    Ok(())
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

    pub fn stop_callback(&self) -> impl FnOnce() + Send + 'static {
        let stop = Arc::clone(&self.stop);
        let runner = self.runner.clone();
        move || {
            stop.store(true, Ordering::Release);
            runner.kick();
        }
    }

    /// Bounded stop: flag, repeated kicks, then wait for the runner's
    /// outcome up to the deadline. Borrows so a timeout keeps the join
    /// handle for a later reap instead of detaching a live thread. The
    /// VM/RAM stays alive via the runner's `Arc<Machine>` until it exits.
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

    fn test_handle(
        run: impl FnOnce(&AtomicBool) -> Result<VcpuOutcome, KvmError> + Send + 'static,
    ) -> VcpuHandle {
        install_kick_handler().expect("install SIGUSR1 handler");
        let stop = Arc::new(AtomicBool::new(false));
        let runner = PthreadPublication::new();
        let (done_tx, done) = mpsc::channel();
        let stop_child = Arc::clone(&stop);
        let runner_child = runner.clone();
        let thread = std::thread::spawn(move || {
            let _published = runner_child.publish();
            finish_runner(&runner_child, &done_tx, run(&stop_child));
        });
        VcpuHandle {
            stop,
            thread: Some(thread),
            runner,
            done,
        }
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
        let release = Arc::new(AtomicBool::new(false));
        let runner_release = Arc::clone(&release);
        let mut handle = test_handle(move |_| {
            while !runner_release.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            Ok(VcpuOutcome::Stopped)
        });
        while !handle.runner.is_published() {
            std::thread::yield_now();
        }
        assert!(matches!(
            handle.stop(Duration::ZERO),
            Err(KvmError::Timeout)
        ));
        assert!(handle.thread.is_some());
        release.store(true, Ordering::Release);
        assert_eq!(
            handle.stop(Duration::from_secs(1)).expect("reap"),
            VcpuOutcome::Stopped
        );
    }

    #[test]
    fn dropping_a_live_handle_reaps_its_runner() {
        let completed = Arc::new(AtomicBool::new(false));
        let runner_completed = Arc::clone(&completed);
        let handle = test_handle(move |stop| {
            while !stop.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            runner_completed.store(true, Ordering::Release);
            Ok(VcpuOutcome::Stopped)
        });
        drop(handle);
        assert!(completed.load(Ordering::Acquire));
    }

    #[test]
    fn runner_failure_is_reaped_and_unpublished() {
        let mut handle = test_handle(|_| Err(KvmError::ThreadGone));
        assert!(matches!(
            handle.stop(Duration::from_secs(1)),
            Err(KvmError::ThreadGone)
        ));
        assert!(handle.thread.is_none());
        assert!(!handle.runner.is_published());
    }

    #[test]
    fn oversized_transfers_rejected() {
        assert!(mmio_width(9).is_err());
        assert!(mmio_value(&[0; MAX_MMIO_BYTES + 1]).is_err());
        assert!(pio_length(MAX_IO_BYTES + 1).is_err());
    }
}
