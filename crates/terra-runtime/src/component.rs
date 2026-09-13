pub mod block;
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

#[derive(Clone)]
pub struct DeviceChannel {
    mmio: vmm::mmio::MmioDevice,
    _runtime: Option<std::sync::Arc<crate::box_runtime::BoxRuntimeHandle>>,
}

impl DeviceChannel {
    #[must_use]
    pub fn failure(&self) -> Option<String> {
        self.mmio.failure()
    }

    #[must_use]
    pub fn request_counts(&self) -> (u64, u64) {
        self.mmio.request_counts()
    }

    pub fn read(&self, offset: u64, len: usize) -> wasmtime::Result<Vec<u8>> {
        self.mmio.read(offset, len)
    }

    pub fn write(&self, offset: u64, bytes: &[u8]) -> wasmtime::Result<()> {
        self.mmio.write(offset, bytes)
    }

    pub fn close(&self) -> wasmtime::Result<()> {
        self.mmio.close()
    }

    pub async fn map_mmio(
        &self,
        runtime: &mut crate::box_runtime::BoxRuntime,
        base: u64,
        size: u64,
    ) -> wasmtime::Result<()> {
        self.mmio.map(runtime, base, size).await
    }
    pub fn reset(&self) -> wasmtime::Result<()> {
        self.mmio.reset()
    }
}
