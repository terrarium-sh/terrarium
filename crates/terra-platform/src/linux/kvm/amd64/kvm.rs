//! Native x86 KVM resources, exit conversion and vCPU thread ownership.

#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};

use std::{error, fmt};

use super::super::KvmError;

use crate::memory::GuestMemory;
use crate::vm::{
    MmioRead, MmioWrite, Msr, PioRead, PioWrite, VcpuAction, VcpuExit, VcpuHandler, VcpuOutcome,
};
use kvm_bindings::{KVM_API_VERSION, kvm_userspace_memory_region};
use kvm_ioctls::{Cap, Kvm, VcpuExit as KvmVcpuExit, VcpuFd, VmFd};

/// Largest PIO transfer completed in one exit (the `kvm_run` buffer).
pub const MAX_IO_BYTES: usize = 8192;
/// Largest MMIO transfer: architecturally 1/2/4/8 bytes.
pub const MAX_MMIO_BYTES: usize = 8;

impl fmt::Display for DispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unexpected(exit) => write!(formatter, "unexpected exit {exit}"),
            Self::Fatal(exit, code) => write!(formatter, "fatal exit {exit} ({code:#x})"),
            Self::TooLarge => formatter.write_str("exit payload is too large"),
            Self::Internal(suberror, data) => write!(
                formatter,
                "KVM internal error {suberror:#x}, data {data:x?}"
            ),
        }
    }
}

impl error::Error for DispatchError {}

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
    ram: GuestMemory,
}

fn validate_ram_range(base: u64, len: u64) -> Result<(), KvmError> {
    let end = base
        .checked_add(len)
        .ok_or(KvmError::Memory("range overflow"))?;
    if base < terra_limits::X86_KVM_TSS_ADDR + 3 * terra_limits::RAM_PAGE_SIZE
        && end > terra_limits::X86_KVM_IDENTITY_MAP_ADDR
    {
        return Err(KvmError::Memory("overlaps reserved Intel KVM pages"));
    }
    Ok(())
}

impl Machine {
    /// Create the VM and map its RAM.
    pub fn new(
        kvm: &Kvm,
        ram_base: u64,
        ram_bytes: u64,
        vcpu_count: usize,
    ) -> Result<Self, KvmError> {
        if vcpu_count == 0 {
            return Err(KvmError::BadVcpuCount(vcpu_count));
        }
        if vcpu_count > kvm.get_max_vcpus() {
            return Err(KvmError::BadVcpuCount(vcpu_count));
        }
        let vm = kvm
            .create_vm()
            .map_err(|e| KvmError::Operation("KVM_CREATE_VM", e))?;
        vm.set_tss_address(
            usize::try_from(terra_limits::X86_KVM_TSS_ADDR)
                .map_err(|_| KvmError::Memory("TSS address"))?,
        )
        .map_err(|e| KvmError::Operation("KVM_SET_TSS_ADDR", e))?;
        vm.set_identity_map_address(terra_limits::X86_KVM_IDENTITY_MAP_ADDR)
            .map_err(|e| KvmError::Operation("KVM_SET_IDENTITY_MAP_ADDR", e))?;
        let ram = if ram_base == terra_limits::X86_RAM_BASE {
            GuestMemory::allocate_x86_ram(ram_bytes)
        } else {
            GuestMemory::allocate_at(ram_base, ram_bytes)
        }
        .ok_or(KvmError::Memory("map"))?;
        let machine = Self { vm, ram };
        for (slot, range) in machine.ram.ranges().into_iter().enumerate() {
            validate_ram_range(range.addr, range.len)?;
            let host_addr = machine
                .ram
                .host_address(range.addr)
                .ok_or(KvmError::Memory("host-addr"))?;
            let region = kvm_userspace_memory_region {
                slot: u32::try_from(slot).map_err(|_| KvmError::Memory("slot"))?,
                flags: 0,
                guest_phys_addr: range.addr,
                memory_size: range.len,
                userspace_addr: host_addr as u64,
            };
            // SAFETY: `host_addr` is the base of the live mapping owned by `machine.ram`.
            unsafe { machine.vm.set_user_memory_region(region) }
                .map_err(|e| KvmError::Operation("KVM_SET_USER_MEMORY_REGION", e))?;
        }
        Ok(machine)
    }

    pub fn create_vcpu(&self, id: u64) -> Result<VcpuFd, KvmError> {
        self.vm
            .create_vcpu(id)
            .map_err(|e| KvmError::Operation("KVM_CREATE_VCPU", e))
    }

    #[must_use]
    pub fn vm_fd(&self) -> &VmFd {
        &self.vm
    }

    pub fn inject_interrupt(&self, irq: u32, level: bool) -> Result<(), String> {
        self.vm_fd()
            .set_irq_line(irq, level)
            .map_err(|error| format!("KVM interrupt: {error}"))
    }

    #[must_use]
    pub fn memory(&self) -> GuestMemory {
        self.ram.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    Unexpected(&'static str),
    /// Entry/hardware failure or an exit newer than this crate release.
    Fatal(&'static str, u64),
    Internal(u32, Vec<u64>),
    TooLarge,
}

fn trace_exit(exit: &str) {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *ENABLED.get_or_init(|| std::env::var_os("TERRA_BOOT_TRACE").is_some()) {
        eprintln!("BOOT TRACE {exit}");
    }
}

fn handler_action(handler: &mut dyn VcpuHandler, exit: VcpuExit) -> Result<VcpuAction, KvmError> {
    handler
        .exchange(exit)
        .map_err(|error| KvmError::Handler(format!("vCPU handler: {error}")))
}

fn require_reentry(action: VcpuAction) -> Result<(), KvmError> {
    matches!(action, VcpuAction::Reenter)
        .then_some(())
        .ok_or_else(|| KvmError::Handler("vCPU action must reenter".to_owned()))
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

fn unexpected_action(expected: &'static str) -> KvmError {
    KvmError::Handler(format!("vCPU action must be {expected}"))
}

#[allow(clippy::too_many_lines)]
fn dispatch_kernel_exit(
    handler: &mut dyn VcpuHandler,
    stop: &AtomicBool,
    exit: KvmVcpuExit<'_>,
) -> Result<Option<VcpuOutcome>, KvmError> {
    match exit {
        KvmVcpuExit::IoIn(port, data) => {
            let action = handler_action(
                handler,
                VcpuExit::PioRead(PioRead {
                    port,
                    length: pio_length(data.len())?,
                }),
            )?;
            if !matches!(action, VcpuAction::PioZero) {
                return Err(unexpected_action("pio-zero"));
            }
            data.fill(0);
        }
        KvmVcpuExit::IoOut(port, data) => {
            require_reentry(handler_action(
                handler,
                VcpuExit::PioWrite(PioWrite {
                    port,
                    length: pio_length(data.len())?,
                }),
            )?)?;
        }
        KvmVcpuExit::MmioRead(address, data) => {
            let width = mmio_width(data.len())?;
            let action = handler_action(handler, VcpuExit::MmioRead(MmioRead { address, width }))?;
            let VcpuAction::MmioRead(value) = action else {
                return Err(unexpected_action("mmio-read"));
            };
            data.copy_from_slice(&value.to_le_bytes()[..usize::from(width)]);
        }
        KvmVcpuExit::MmioWrite(address, data) => {
            let width = mmio_width(data.len())?;
            require_reentry(handler_action(
                handler,
                VcpuExit::MmioWrite(MmioWrite {
                    address,
                    width,
                    value: mmio_value(data)?,
                }),
            )?)?;
        }
        KvmVcpuExit::X86Rdmsr(msr) => {
            trace_exit("rdmsr");
            let action = handler_action(
                handler,
                VcpuExit::Rdmsr(Msr {
                    index: msr.index,
                    value: 0,
                }),
            )?;
            match action {
                VcpuAction::Rdmsr(value) => {
                    *msr.data = value;
                    *msr.error = 0;
                }
                VcpuAction::MsrFault => *msr.error = 1,
                _ => return Err(unexpected_action("rdmsr")),
            }
        }
        KvmVcpuExit::X86Wrmsr(msr) => {
            trace_exit("wrmsr");
            match handler_action(
                handler,
                VcpuExit::Wrmsr(Msr {
                    index: msr.index,
                    value: msr.data,
                }),
            )? {
                VcpuAction::Wrmsr => *msr.error = 0,
                VcpuAction::MsrFault => *msr.error = 1,
                _ => return Err(unexpected_action("wrmsr")),
            }
        }
        KvmVcpuExit::Hlt => {
            trace_exit("hlt");
            require_reentry(handler_action(handler, VcpuExit::Halt)?)?;
        }
        KvmVcpuExit::Intr | KvmVcpuExit::IoapicEoi(_) => {
            if stop.load(Ordering::Acquire) {
                return Ok(Some(VcpuOutcome::Stopped));
            }
            trace_exit("interrupted");
            require_reentry(handler_action(handler, VcpuExit::Interrupted)?)?;
        }
        KvmVcpuExit::Shutdown => {
            let _ = handler.exchange(VcpuExit::Shutdown);
            return Ok(Some(VcpuOutcome::Shutdown));
        }
        KvmVcpuExit::FailEntry(reason, _) => {
            return Err(KvmError::Dispatch(DispatchError::Fatal(
                "fail-entry",
                reason,
            )));
        }
        KvmVcpuExit::InternalError => {
            return Err(KvmError::Dispatch(DispatchError::Fatal(
                "internal-error",
                0,
            )));
        }
        KvmVcpuExit::Unsupported(code) => {
            return Err(KvmError::Dispatch(DispatchError::Fatal(
                "unsupported-exit",
                u64::from(code),
            )));
        }
        KvmVcpuExit::Unknown => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("unknown")));
        }
        KvmVcpuExit::Exception => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("exception")));
        }
        KvmVcpuExit::Hypercall(_) => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("hypercall")));
        }
        KvmVcpuExit::Debug(_) => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("debug")));
        }
        KvmVcpuExit::IrqWindowOpen => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected(
                "irq-window-open",
            )));
        }
        KvmVcpuExit::SetTpr => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("set-tpr")));
        }
        KvmVcpuExit::TprAccess => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("tpr-access")));
        }
        KvmVcpuExit::S390Sieic => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("s390-sieic")));
        }
        KvmVcpuExit::S390Reset => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("s390-reset")));
        }
        KvmVcpuExit::Dcr => return Err(KvmError::Dispatch(DispatchError::Unexpected("dcr"))),
        KvmVcpuExit::Nmi => return Err(KvmError::Dispatch(DispatchError::Unexpected("nmi"))),
        KvmVcpuExit::Osi => return Err(KvmError::Dispatch(DispatchError::Unexpected("osi"))),
        KvmVcpuExit::PaprHcall => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("papr-hcall")));
        }
        KvmVcpuExit::S390Ucontrol => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected(
                "s390-ucontrol",
            )));
        }
        KvmVcpuExit::Watchdog => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("watchdog")));
        }
        KvmVcpuExit::S390Tsch => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("s390-tsch")));
        }
        KvmVcpuExit::Epr => return Err(KvmError::Dispatch(DispatchError::Unexpected("epr"))),
        KvmVcpuExit::SystemEvent(_, _) => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected(
                "system-event",
            )));
        }
        KvmVcpuExit::S390Stsi => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected("s390-stsi")));
        }
        KvmVcpuExit::Hyperv => return Err(KvmError::Dispatch(DispatchError::Unexpected("hyperv"))),
        KvmVcpuExit::MemoryFault { .. } => {
            return Err(KvmError::Dispatch(DispatchError::Unexpected(
                "memory-fault",
            )));
        }
    }
    Ok(None)
}

/// Run one Linux KVM vCPU through its platform handler.
pub fn run_kernel_vcpu(
    vcpu: &mut VcpuFd,
    stop: &AtomicBool,
    handler: &mut dyn VcpuHandler,
) -> Result<VcpuOutcome, KvmError> {
    loop {
        if stop.load(Ordering::Acquire) {
            let outcome = VcpuOutcome::Stopped;
            handler.finished(outcome);
            return Ok(outcome);
        }
        match vcpu.run() {
            Ok(KvmVcpuExit::InternalError) => {
                // SAFETY: KVM_EXIT_INTERNAL_ERROR selects the internal member of kvm_run.
                let internal = unsafe { vcpu.get_kvm_run().__bindgen_anon_1.internal };
                let count = usize::try_from(internal.ndata)
                    .unwrap_or(internal.data.len())
                    .min(internal.data.len());
                return Err(DispatchError::Internal(
                    internal.suberror,
                    internal.data[..count].to_vec(),
                )
                .into());
            }
            Ok(exit) => {
                if let Some(outcome) = dispatch_kernel_exit(handler, stop, exit)? {
                    handler.finished(outcome);
                    return Ok(outcome);
                }
            }
            Err(error) if error.errno() == libc::EINTR || error.errno() == libc::EAGAIN => {
                if stop.load(Ordering::Acquire) {
                    let outcome = VcpuOutcome::Stopped;
                    handler.finished(outcome);
                    return Ok(outcome);
                }
            }
            Err(error) => return Err(KvmError::Operation("KVM_RUN", error)),
        }
    }
}

/// Park an application processor until the guest sends INIT/SIPI.
#[cfg(target_arch = "x86_64")]
pub fn park_ap(vcpu: &VcpuFd) -> Result<(), KvmError> {
    vcpu.set_mp_state(kvm_bindings::kvm_mp_state {
        mp_state: kvm_bindings::KVM_MP_STATE_UNINITIALIZED,
    })
    .map_err(|e| KvmError::Operation("KVM_SET_MP_STATE", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intel_kvm_pages_are_outside_guest_ram() {
        for bytes in [512 << 20, 4 << 30, 64 << 30] {
            for range in terra_limits::x86_ram_layout(bytes).unwrap().regions() {
                validate_ram_range(range.base, range.size).unwrap();
            }
        }
        for base in [
            terra_limits::X86_KVM_IDENTITY_MAP_ADDR,
            terra_limits::X86_KVM_TSS_ADDR,
        ] {
            assert!(validate_ram_range(base, terra_limits::RAM_PAGE_SIZE).is_err());
        }
    }

    #[test]
    fn oversized_transfers_rejected() {
        assert!(mmio_width(9).is_err());
        assert!(mmio_value(&[0; MAX_MMIO_BYTES + 1]).is_err());
        assert!(pio_length(MAX_IO_BYTES + 1).is_err());
    }

    #[test]
    fn boot_cpu_setup_keeps_the_kvm_error() {
        let error = KvmError::Bsp(super::super::arch::ArchError::IrqOutOfRange(24));
        assert!(error.to_string().contains("IRQ 24"));
    }
}
