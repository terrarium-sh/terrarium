//! Linux KVM backend.

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod kick;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::{Machine, Vm};
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::{Machine, Vm};

use std::{error, fmt};

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
    IrqOutOfRange(u32),
    #[cfg(target_arch = "aarch64")]
    InvalidInterruptController,
    UnexpectedExit(&'static str),
    /// Entry/hardware failure or an exit newer than this crate release.
    #[cfg(target_arch = "x86_64")]
    FatalExit(&'static str, u64),
    #[cfg(target_arch = "x86_64")]
    InternalError(u32, Vec<u64>),
    #[cfg(target_arch = "x86_64")]
    ExitTooLarge,
    KickHandler(std::io::Error),
    Handler(String),
}

impl From<kvm_ioctls::Error> for KvmError {
    fn from(error: kvm_ioctls::Error) -> Self {
        Self::Kvm(error)
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
            Self::IrqOutOfRange(irq) => {
                write!(formatter, "IRQ {irq} is outside the interrupt controller")
            }
            #[cfg(target_arch = "aarch64")]
            Self::InvalidInterruptController => {
                formatter.write_str("ARM interrupt controller required")
            }
            Self::UnexpectedExit(exit) => write!(formatter, "unexpected KVM exit {exit}"),
            #[cfg(target_arch = "x86_64")]
            Self::FatalExit(exit, code) => write!(formatter, "fatal KVM exit {exit} ({code:#x})"),
            #[cfg(target_arch = "x86_64")]
            Self::InternalError(suberror, data) => write!(
                formatter,
                "KVM internal error {suberror:#x}, data {data:x?}"
            ),
            #[cfg(target_arch = "x86_64")]
            Self::ExitTooLarge => formatter.write_str("KVM exit payload is too large"),
            Self::KickHandler(error) => {
                write!(formatter, "installing KVM vCPU kick handler: {error}")
            }
            Self::Handler(error) => write!(formatter, "vCPU handler: {error}"),
        }
    }
}

impl error::Error for KvmError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Kvm(error) | Self::Operation(_, error) => Some(error),
            Self::KickHandler(error) => Some(error),
            #[cfg(target_arch = "x86_64")]
            Self::ApiVersion(_)
            | Self::MissingCap(_)
            | Self::NoVcpus
            | Self::FatalExit(..)
            | Self::InternalError(..)
            | Self::ExitTooLarge => None,
            #[cfg(target_arch = "aarch64")]
            Self::InvalidInterruptController => None,
            Self::BadVcpuCount(_)
            | Self::Memory(_)
            | Self::IrqOutOfRange(_)
            | Self::UnexpectedExit(_)
            | Self::Handler(_) => None,
        }
    }
}
