use crate::component::context::{DeviceContext, DeviceHost};
use wasmtime::Engine;
use wasmtime_wasi::{WasiCtxView, WasiView};

use wasmtime::{Store, StoreLimits, StoreLimitsBuilder};

pub struct StandaloneHost<H> {
    host: H,
    limits: StoreLimits,
}

impl<H> std::ops::Deref for StandaloneHost<H> {
    type Target = H;

    fn deref(&self) -> &H {
        &self.host
    }
}

impl<H> std::ops::DerefMut for StandaloneHost<H> {
    fn deref_mut(&mut self) -> &mut H {
        &mut self.host
    }
}

impl<H> AsMut<H> for StandaloneHost<H> {
    fn as_mut(&mut self) -> &mut H {
        &mut self.host
    }
}

impl<H: WasiView> WasiView for StandaloneHost<H> {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        self.host.ctx()
    }
}

impl<H: DeviceHost> DeviceHost for StandaloneHost<H> {
    fn context(&mut self) -> &mut DeviceContext {
        self.host.context()
    }
}

#[must_use]
pub fn device_store<H: DeviceHost>(engine: &Engine, host: H) -> Store<StandaloneHost<H>> {
    device_store_with_limits(
        engine,
        host,
        crate::box_runtime::store::ComponentMemoryLimits::default(),
    )
}

/// Store for one standalone device with a per-linear-memory limit.
#[must_use]
pub fn device_store_with_limits<H: DeviceHost>(
    engine: &Engine,
    host: H,
    limits: crate::box_runtime::store::ComponentMemoryLimits,
) -> Store<StandaloneHost<H>> {
    let limits = StoreLimitsBuilder::new()
        .memory_size(limits.component_bytes())
        .table_elements(1024)
        .instances(16)
        .memories(4)
        .tables(8)
        .build();
    let mut store = Store::new(engine, StandaloneHost { host, limits });
    store.set_hostcall_fuel(terra_limits::MAX_COMPONENT_HOSTCALL_BYTES);
    store.set_epoch_deadline(1);
    store.limiter(|host| &mut host.limits);
    store
}

#[cfg(test)]
mod tests {
    #[test]
    fn standalone_device_store_applies_per_memory_limit() {
        use wasmtime::ResourceLimiter as _;

        let engine = crate::engine::device_engine().expect("engine");
        let limits = crate::box_runtime::store::ComponentMemoryLimits::new(16 << 20)
            .expect("component limits");
        let mut store = super::device_store_with_limits(
            &engine,
            super::DeviceContext::new(4096).expect("RAM"),
            limits,
        );
        let memory =
            wasmtime::Memory::new(&mut store, wasmtime::MemoryType::new(256, None)).unwrap();
        assert!(memory.grow(&mut store, 1).is_err());
        assert_eq!(memory.size(&store), 256);
        wasmtime::Memory::new(&mut store, wasmtime::MemoryType::new(256, None)).unwrap();
        assert!(wasmtime::Memory::new(&mut store, wasmtime::MemoryType::new(257, None)).is_err());
        let limits = &mut store.data_mut().limits;
        assert!(limits.table_growing(0, 1024, None).unwrap());
        assert!(!limits.table_growing(0, 1025, None).unwrap());
        assert_eq!(
            (limits.instances(), limits.memories(), limits.tables()),
            (16, 4, 8)
        );
    }
}
