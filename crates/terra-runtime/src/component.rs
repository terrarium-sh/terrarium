pub mod block;
pub mod context;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub mod fs;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub mod mem;
pub mod network;
pub mod policy;
pub mod relay;
pub mod vmm;
pub mod vsock;

pub type Interrupt = std::sync::Arc<dyn Fn(bool) -> wasmtime::Result<()> + Send + Sync>;

mod worker;

pub use vmm::mmio::MmioDevice as DeviceChannel;

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone)]
pub struct StandaloneDevice {
    device: DeviceChannel,
    _runtime: std::sync::Arc<crate::box_runtime::BoxRuntimeHandle>,
}

#[cfg(any(test, feature = "test-support"))]
impl std::ops::Deref for StandaloneDevice {
    type Target = DeviceChannel;
    fn deref(&self) -> &Self::Target {
        &self.device
    }
}
