pub(crate) mod bindings;
pub mod block;
pub(crate) mod clocks;
pub mod context;
pub mod fs;
pub mod interrupt_controller;
pub mod mem;
pub mod mmio;
pub mod network;
pub mod policy;
pub(crate) mod relay;
pub mod vmm;
pub mod vsock;

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
