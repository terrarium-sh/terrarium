pub mod agent;
pub(crate) mod bindings;
pub mod block;
pub(crate) mod clocks;
pub mod context;
pub mod fs;
pub mod interrupt_controller;
pub mod mem;
pub mod mmio;
pub mod network;
pub mod relay;
pub mod vmm;
pub mod vsock;

/// Whether a disk or share grant lets the guest write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessMode {
    ReadOnly,
    ReadWrite,
}

impl AccessMode {
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        matches!(self, Self::ReadOnly)
    }
}

pub(crate) fn recorded_failure(failure: &std::sync::Mutex<Option<String>>) -> Option<String> {
    failure
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

pub type InterruptCallback = std::sync::Arc<dyn Fn(bool) -> wasmtime::Result<()> + Send + Sync>;

mod device_loop;

pub use mmio::MmioDevice;

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct StandaloneDevice {
    device: MmioDevice,
    _runtime: std::sync::Arc<crate::box_runtime::BoxRuntimeHandle>,
}

#[cfg(test)]
impl std::ops::Deref for StandaloneDevice {
    type Target = MmioDevice;
    fn deref(&self) -> &Self::Target {
        &self.device
    }
}
