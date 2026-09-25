//! Component store state and per-store resource accounting.

use crate::component::context::{DeviceContext, DeviceHost};
use wasmtime::component::ResourceTable;
use wasmtime::{Engine, ResourceLimiter, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

pub const DEFAULT_COMPONENT_MEMORY_MIB: u32 = 16;

#[derive(Clone, Copy, Debug)]
pub struct ComponentMemoryLimits {
    component_bytes: usize,
    network_override: Option<usize>,
}

impl ComponentMemoryLimits {
    pub fn new(component_bytes: usize) -> wasmtime::Result<Self> {
        wasmtime::ensure!(
            component_bytes >= STORE_MEMORY_BYTES,
            "increase the component memory limit to at least {DEFAULT_COMPONENT_MEMORY_MIB} MiB"
        );
        Ok(Self {
            component_bytes,
            network_override: None,
        })
    }

    pub fn with_network_memory(mut self, bytes: usize) -> wasmtime::Result<Self> {
        wasmtime::ensure!(
            bytes >= STORE_MEMORY_BYTES,
            "increase the network component memory limit to at least {DEFAULT_COMPONENT_MEMORY_MIB} MiB"
        );
        self.network_override = Some(bytes);
        Ok(self)
    }

    pub fn admission_bytes(self) -> wasmtime::Result<usize> {
        // Include root, temporary boot, and policy stores alongside the admitted workers.
        self.component_bytes
            .checked_mul(super::MAX_BOX_COMPONENT_WORKERS + 2)
            .and_then(|bytes| bytes.checked_add(self.network_bytes().max(self.component_bytes)))
            .ok_or_else(|| wasmtime::Error::msg("component memory reservation overflow"))
    }

    #[must_use]
    pub fn network_bytes(self) -> usize {
        self.network_override.unwrap_or(self.component_bytes)
    }

    #[must_use]
    pub fn component_bytes(self) -> usize {
        self.component_bytes
    }
}

impl Default for ComponentMemoryLimits {
    fn default() -> Self {
        Self {
            component_bytes: STORE_MEMORY_BYTES,
            network_override: None,
        }
    }
}
/// Guest linear memory ceiling per device store. Debug components
/// start near 17 pages; release/opt builds shrink. Re-measure before
/// treating this as a budget.
pub const STORE_MEMORY_BYTES: usize =
    (crate::box_runtime::store::DEFAULT_COMPONENT_MEMORY_MIB as usize) << 20;
const COMPONENT_EPOCH_DEADLINE: u64 = 10;

pub trait StoreHost: WasiView + 'static {
    fn retire(self)
    where
        Self: Sized,
    {
        drop(self);
    }
}

pub struct RootHost {
    pub(crate) platform: crate::component::vmm::PlatformHost,
    pub(crate) lifecycle: crate::component::vmm::lifecycle::LifecycleHost,
    pub(crate) mmio_client: Option<crate::component::mmio::Client>,
    ctx: WasiCtx,
    table: ResourceTable,
}

pub type BoxHost = StoreState<RootHost>;

pub struct StoreState<H: StoreHost> {
    host: Option<H>,
    component_memory_limit: usize,
    wasm_memory_bytes: usize,
    pending_memory_growth: usize,
    memory_limits: ComponentMemoryLimits,
}

impl<H: StoreHost> StoreState<H> {
    pub(super) fn with_limits(host: H, memory_limits: ComponentMemoryLimits) -> Self {
        Self {
            host: Some(host),
            component_memory_limit: memory_limits.component_bytes(),
            wasm_memory_bytes: 0,
            pending_memory_growth: 0,
            memory_limits,
        }
    }

    pub(crate) fn network_memory_limit(&self) -> usize {
        self.memory_limits.network_bytes()
    }

    pub(crate) fn use_network_memory_limit(&mut self) {
        self.component_memory_limit = self.network_memory_limit();
    }

    pub(super) fn memory_limits(&self) -> ComponentMemoryLimits {
        self.memory_limits
    }
}

impl<H: StoreHost> std::ops::Deref for StoreState<H> {
    type Target = H;
    #[allow(clippy::expect_used)]
    fn deref(&self) -> &H {
        self.host
            .as_ref()
            .expect("host is present until store drop")
    }
}
impl<H: StoreHost> std::ops::DerefMut for StoreState<H> {
    #[allow(clippy::expect_used)]
    fn deref_mut(&mut self) -> &mut H {
        self.host
            .as_mut()
            .expect("host is present until store drop")
    }
}
impl<H: StoreHost> AsMut<H> for StoreState<H> {
    fn as_mut(&mut self) -> &mut H {
        self
    }
}
impl<H: StoreHost> WasiView for StoreState<H> {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        (**self).ctx()
    }
}
impl<H: StoreHost + DeviceHost> DeviceHost for StoreState<H> {
    fn context(&mut self) -> &mut DeviceContext {
        (**self).context()
    }
}
impl<H: StoreHost> Drop for StoreState<H> {
    fn drop(&mut self) {
        if let Some(host) = self.host.take() {
            host.retire();
        }
    }
}

impl RootHost {
    #[must_use]
    pub fn new() -> Self {
        let lifecycle = crate::component::vmm::lifecycle::LifecycleHost::new();
        Self {
            platform: crate::component::vmm::PlatformHost::with_native_teardown(
                lifecycle.native_teardown(),
            ),
            lifecycle,
            mmio_client: None,
            ctx: WasiCtxBuilder::new()
                .max_random_size(crate::MAX_SINGLE_BYTES)
                .allow_tcp(false)
                .allow_udp(false)
                .allow_ip_name_lookup(false)
                .build(),
            table: ResourceTable::new(),
        }
    }
}
impl Default for RootHost {
    fn default() -> Self {
        Self::new()
    }
}

impl StoreHost for crate::component::vmm::boot::BootHost {}

impl StoreHost for RootHost {
    fn retire(self) {
        let teardown = self.lifecycle.native_teardown();
        if teardown.has_work() {
            teardown.start();
        }
    }
}
impl StoreHost for DeviceContext {}
impl BoxHost {
    #[must_use]
    pub fn new() -> Self {
        Self::with_memory_limits(ComponentMemoryLimits::default())
    }

    #[must_use]
    pub fn with_memory_limits(limits: ComponentMemoryLimits) -> Self {
        Self::with_limits(RootHost::new(), limits)
    }
}
impl WasiView for RootHost {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}
impl Default for BoxHost {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: StoreHost> ResourceLimiter for StoreState<H> {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.pending_memory_growth = 0;
        let Some(growth) = desired.checked_sub(current) else {
            return Ok(false);
        };
        if self
            .wasm_memory_bytes
            .checked_add(growth)
            .is_none_or(|total| total > self.component_memory_limit)
        {
            return Ok(false);
        }
        self.wasm_memory_bytes += growth;
        self.pending_memory_growth = growth;
        Ok(true)
    }

    fn memory_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        let _ = error;
        self.wasm_memory_bytes = self
            .wasm_memory_bytes
            .saturating_sub(self.pending_memory_growth);
        self.pending_memory_growth = 0;
        Ok(())
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= 1024)
    }

    fn instances(&self) -> usize {
        16
    }

    fn memories(&self) -> usize {
        4
    }

    fn tables(&self) -> usize {
        8
    }
}

pub(super) fn create_store<H: StoreHost>(
    engine: &Engine,
    host: StoreState<H>,
) -> Store<StoreState<H>> {
    let mut store = Store::new(engine, host);
    store.set_hostcall_fuel(terra_limits::MAX_COMPONENT_HOSTCALL_BYTES);
    store.set_epoch_deadline(COMPONENT_EPOCH_DEADLINE);
    store.epoch_deadline_async_yield_and_update(COMPONENT_EPOCH_DEADLINE);
    store.limiter(|host| host);
    store
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hostcall_limit_sums_all_lifted_arguments() {
        use wasmtime::component::{Component, Linker};
        let engine = crate::engine::device_engine().unwrap();
        let component = Component::new(&engine, r#"(component
            (import "copy" (func $copy (param "a" (list u8)) (param "b" (list u8)) (result u32)))
            (core module $memory (memory (export "memory") 1))
            (core instance $memory (instantiate $memory))
            (alias core export $memory "memory" (core memory $memory))
            (core func $copy (canon lower (func $copy) (memory $memory)))
            (core module $caller
                (import "host" "copy" (func $copy (param i32 i32 i32 i32) (result i32)))
                (func (export "copy") (param i32) (result i32)
                    i32.const 0 local.get 0 i32.const 0 local.get 0 call $copy))
            (core instance $caller (instantiate $caller (with "host" (instance (export "copy" (func $copy))))))
            (func (export "copy") (param "bytes" u32) (result u32)
                (canon lift (core func $caller "copy"))))"#).unwrap();
        let mut linker = Linker::<BoxHost>::new(&engine);
        linker
            .root()
            .func_wrap("copy", |_, (a, b): (Vec<u8>, Vec<u8>)| {
                Ok((u32::try_from(a.len() + b.len()).unwrap(),))
            })
            .unwrap();
        for bytes in [32768, 32769] {
            let mut store = create_store(&engine, BoxHost::new());
            let instance = linker
                .instantiate_async(&mut store, &component)
                .await
                .unwrap();
            let copy = instance
                .get_typed_func::<(u32,), (u32,)>(&mut store, "copy")
                .unwrap();
            let copied = copy.call_async(&mut store, (bytes,)).await;
            if bytes == 32768 {
                assert_eq!(copied.unwrap(), (65536,));
            } else {
                let error = copied.unwrap_err();
                assert!(format!("{error:#}").contains("fuel"), "{error:#}");
            }
        }
    }

    #[test]
    fn resource_limits_apply_per_independent_store() {
        let host = BoxHost::new();

        assert_eq!(ResourceLimiter::instances(&host), 16);
        assert_eq!(ResourceLimiter::memories(&host), 4);
        assert_eq!(ResourceLimiter::tables(&host), 8);
    }

    #[test]
    fn concurrent_streams_do_not_exhaust_the_host_resource_budget() {
        use wasmtime::component::StreamReader;

        let engine = crate::engine::device_engine().unwrap();
        let mut store = create_store(&engine, BoxHost::new());
        for _ in 0..2 {
            let mut streams = Vec::new();
            for _ in 0..128 {
                for _ in 0..2 {
                    streams.push(StreamReader::new(&mut store, Vec::<u8>::new()).unwrap());
                }
            }
            for mut stream in streams {
                stream.close(&mut store).unwrap();
            }
            assert!(store.concurrent_resource_table().unwrap().is_empty());
        }
    }

    #[test]
    fn component_memory_limit_sums_memories_and_releases_failed_growth() {
        let mut host = BoxHost::new();
        assert!(
            ResourceLimiter::memory_growing(
                &mut host,
                0,
                crate::box_runtime::store::STORE_MEMORY_BYTES,
                None,
            )
            .expect("first memory reservation")
        );
        ResourceLimiter::memory_grow_failed(&mut host, wasmtime::Error::msg("allocation"))
            .expect("allocation failure rolls back");
        assert_eq!(host.wasm_memory_bytes, 0);

        assert!(
            ResourceLimiter::memory_growing(
                &mut host,
                0,
                crate::box_runtime::store::STORE_MEMORY_BYTES,
                None
            )
            .unwrap()
        );
        assert!(!ResourceLimiter::memory_growing(&mut host, 0, 65_536, None).unwrap());
    }

    #[test]
    fn failed_growth_releases_only_its_reservation() {
        let mut host = BoxHost::new();
        assert!(
            ResourceLimiter::memory_growing(&mut host, 0, 4096, None).expect("memory reservation")
        );
        assert!(
            ResourceLimiter::memory_growing(&mut host, 4096, 8192, None)
                .expect("incremental memory reservation")
        );
        ResourceLimiter::memory_grow_failed(
            &mut host,
            wasmtime::Error::msg("memory growth exceeds memory type's limits"),
        )
        .expect("memory type rejection");
        assert_eq!(host.wasm_memory_bytes, 4096);
        assert!(
            !ResourceLimiter::memory_growing(
                &mut host,
                0,
                crate::box_runtime::store::STORE_MEMORY_BYTES + 1,
                None,
            )
            .expect("per-memory cap")
        );
    }

    #[test]
    fn component_limits_can_be_raised_and_invalid_limits_are_rejected() {
        assert!(ComponentMemoryLimits::new(0).is_err());
        let mut host = BoxHost::with_memory_limits(
            ComponentMemoryLimits::new(STORE_MEMORY_BYTES * 2).unwrap(),
        );
        assert!(
            ResourceLimiter::memory_growing(&mut host, 0, STORE_MEMORY_BYTES * 2, None).unwrap()
        );
    }

    #[test]
    fn admission_accounts_for_all_stores_and_network_overrides() {
        let limits = ComponentMemoryLimits::default();
        let baseline = limits.admission_bytes().unwrap();
        assert_eq!(
            baseline,
            (super::super::MAX_BOX_COMPONENT_WORKERS + 3) * STORE_MEMORY_BYTES
        );
        assert_eq!(
            limits
                .with_network_memory(64 << 20)
                .unwrap()
                .admission_bytes()
                .unwrap(),
            baseline + (48 << 20)
        );
        let raised = ComponentMemoryLimits::new(32 << 20).unwrap();
        assert_eq!(raised.admission_bytes().unwrap(), baseline * 2);
        assert_eq!(
            raised
                .with_network_memory(16 << 20)
                .unwrap()
                .admission_bytes()
                .unwrap(),
            baseline * 2
        );
        assert!(
            ComponentMemoryLimits::new(usize::MAX)
                .unwrap()
                .admission_bytes()
                .is_err()
        );
    }

    #[test]
    fn network_override_preserves_other_store_limits() {
        let limits = ComponentMemoryLimits::new(16 << 20)
            .unwrap()
            .with_network_memory(32 << 20)
            .unwrap();
        let mut ordinary = BoxHost::with_memory_limits(limits);
        let mut network = BoxHost::with_memory_limits(limits);
        network.use_network_memory_limit();
        assert!(!ResourceLimiter::memory_growing(&mut ordinary, 0, 17 << 20, None).unwrap());
        assert!(ResourceLimiter::memory_growing(&mut network, 0, 32 << 20, None).unwrap());
        assert!(!ResourceLimiter::memory_growing(&mut network, 32 << 20, 33 << 20, None).unwrap());
        assert!(ResourceLimiter::memory_growing(&mut ordinary, 0, 16 << 20, None).unwrap());
    }
}
