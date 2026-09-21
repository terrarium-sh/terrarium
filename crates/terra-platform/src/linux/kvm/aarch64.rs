//! Linux/KVM backend for `AArch64` guests.

#[derive(Debug)]
pub enum ArmWorkerError {
    BadVcpuCount(usize),
    InvalidInterruptController,
    TooManyDevices,
    Memory,
    Kvm(kvm_ioctls::Error),
    Native(String),
    ThreadGone,
    KickHandler(std::io::Error),
    Timeout,
    UnexpectedExit(&'static str),
}

impl From<kvm_ioctls::Error> for ArmWorkerError {
    fn from(error: kvm_ioctls::Error) -> Self {
        Self::Kvm(error)
    }
}

impl std::fmt::Display for ArmWorkerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadVcpuCount(count) => write!(formatter, "invalid vCPU count: {count}"),
            Self::InvalidInterruptController => {
                formatter.write_str("ARM interrupt controller required")
            }
            Self::TooManyDevices => formatter.write_str("too many ARM devices"),
            Self::Memory => formatter.write_str("invalid ARM guest memory"),
            Self::Kvm(error) => write!(formatter, "KVM: {error}"),
            Self::Native(error) => formatter.write_str(error),
            Self::ThreadGone => formatter.write_str("ARM vCPU thread disappeared"),
            Self::KickHandler(error) => write!(formatter, "installing KVM kick handler: {error}"),
            Self::Timeout => formatter.write_str("ARM vCPU stop timed out"),
            Self::UnexpectedExit(exit) => write!(formatter, "unexpected ARM vCPU exit: {exit}"),
        }
    }
}

impl std::error::Error for ArmWorkerError {}

pub(crate) mod machine;
pub mod worker;
