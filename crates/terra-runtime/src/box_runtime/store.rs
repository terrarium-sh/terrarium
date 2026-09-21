//! Component store state and per-store and box-wide resource accounting.

use crate::component::context::{DeviceContext, DeviceHost};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use wasmtime::component::ResourceTable;
use wasmtime::{Engine, ResourceLimiter, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

pub const DEFAULT_COMPONENT_MEMORY_MIB: u32 = 16;
pub const DEFAULT_TOTAL_MEMORY_MIB: u32 = 128;
pub const BOX_WASM_MEMORY_BYTES: usize = (DEFAULT_TOTAL_MEMORY_MIB as usize) << 20;

#[derive(Clone, Copy, Debug)]
pub struct ComponentMemoryLimits {
    component_bytes: usize,
    total_bytes: usize,
}

impl ComponentMemoryLimits {
    pub fn new(component_bytes: usize, total_bytes: usize) -> wasmtime::Result<Self> {
        wasmtime::ensure!(
            component_bytes > 0 && component_bytes <= total_bytes,
            "component memory limit must be positive and no larger than the total memory limit"
        );
        Ok(Self {
            component_bytes,
            total_bytes,
        })
    }

    /// Returns the remaining device limits and the reserved policy memory bytes.
    pub fn reserve_policy(self) -> wasmtime::Result<(Self, usize)> {
        let remaining = self.total_bytes.checked_sub(self.component_bytes)
            .filter(|remaining| *remaining > 0)
            .ok_or_else(|| wasmtime::Error::msg("network policy needs a separate component budget; increase components.total_memory_mib above components.memory_mib"))?;
        Ok((
            Self::new(self.component_bytes.min(remaining), remaining)?,
            self.component_bytes,
        ))
    }

    #[must_use]
    pub fn total_bytes(self) -> usize {
        self.total_bytes
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
            total_bytes: BOX_WASM_MEMORY_BYTES,
        }
    }
}
/// Guest linear memory ceiling per device store. Debug components
/// start near 17 pages; release/opt builds shrink. Re-measure before
/// treating this as a budget.
pub const STORE_MEMORY_BYTES: usize =
    (crate::box_runtime::store::DEFAULT_COMPONENT_MEMORY_MIB as usize) << 20;
const COMPONENT_EPOCH_DEADLINE: u64 = 10;

pub(super) struct BoxMemoryBudget {
    limits: ComponentMemoryLimits,
    reserved: AtomicUsize,
}

impl BoxMemoryBudget {
    fn new(limits: ComponentMemoryLimits) -> Self {
        Self {
            limits,
            reserved: AtomicUsize::new(0),
        }
    }

    fn reserve(&self, bytes: usize) -> bool {
        self.reserved
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|next| *next <= self.limits.total_bytes)
            })
            .is_ok()
    }

    fn release(&self, bytes: usize) {
        let _ = self
            .reserved
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(bytes)
            });
    }

    #[cfg(test)]
    pub(super) fn reserved(&self) -> usize {
        self.reserved.load(Ordering::Acquire)
    }
}

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
    ctx: WasiCtx,
    table: ResourceTable,
}

pub type BoxHost = StoreState<RootHost>;

pub struct StoreState<H: StoreHost> {
    host: Option<H>,
    wasm_memory_bytes: usize,
    pending_memory_growth: usize,
    memory_budget: Arc<BoxMemoryBudget>,
}

impl<H: StoreHost> StoreState<H> {
    pub(super) fn with_budget(host: H, memory_budget: Arc<BoxMemoryBudget>) -> Self {
        Self {
            host: Some(host),
            wasm_memory_bytes: 0,
            pending_memory_growth: 0,
            memory_budget,
        }
    }

    pub(super) fn memory_budget(&self) -> &Arc<BoxMemoryBudget> {
        &self.memory_budget
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
        self.memory_budget.release(self.wasm_memory_bytes);
    }
}

impl RootHost {
    #[must_use]
    pub fn new() -> Self {
        let mut router_table = ResourceTable::new();
        router_table.set_max_capacity(crate::component::context::MAX_DEVICE_RESOURCES);
        let lifecycle = crate::component::vmm::lifecycle::LifecycleHost::new();
        Self {
            platform: crate::component::vmm::PlatformHost::with_native_teardown(
                lifecycle.native_teardown(),
            ),
            lifecycle,
            ctx: WasiCtxBuilder::new()
                .max_random_size(crate::MAX_SINGLE_BYTES)
                .allow_tcp(false)
                .allow_udp(false)
                .allow_ip_name_lookup(false)
                .build(),
            table: router_table,
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
        Self::with_budget(RootHost::new(), Arc::new(BoxMemoryBudget::new(limits)))
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
            .is_none_or(|total| total > self.memory_budget.limits.component_bytes)
            || !self.memory_budget.reserve(growth)
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
        self.memory_budget.release(self.pending_memory_growth);
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
    store.set_epoch_deadline(COMPONENT_EPOCH_DEADLINE);
    store.epoch_deadline_async_yield_and_update(COMPONENT_EPOCH_DEADLINE);
    store.limiter(|host| host);
    store
}

pub mod test_support {
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
            let limits = crate::box_runtime::store::ComponentMemoryLimits::new(65_536, 65_536)
                .expect("component limits");
            let mut store = super::device_store_with_limits(
                &engine,
                super::DeviceContext::new(4096).expect("RAM"),
                limits,
            );
            let memory =
                wasmtime::Memory::new(&mut store, wasmtime::MemoryType::new(1, None)).unwrap();
            assert!(memory.grow(&mut store, 1).is_err());
            assert_eq!(memory.size(&store), 1);
            wasmtime::Memory::new(&mut store, wasmtime::MemoryType::new(1, None)).unwrap();
            assert!(wasmtime::Memory::new(&mut store, wasmtime::MemoryType::new(2, None)).is_err());
            let limits = &mut store.data_mut().limits;
            assert!(limits.table_growing(0, 1024, None).unwrap());
            assert!(!limits.table_growing(0, 1025, None).unwrap());
            assert_eq!(
                (limits.instances(), limits.memories(), limits.tables()),
                (16, 4, 8)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_limits_apply_per_independent_store() {
        let host = BoxHost::new();

        assert_eq!(ResourceLimiter::instances(&host), 16);
        assert_eq!(ResourceLimiter::memories(&host), 4);
        assert_eq!(ResourceLimiter::tables(&host), 8);
    }

    #[test]
    fn router_host_resources_have_a_native_limit() {
        let mut host = BoxHost::new();
        for _ in 0..crate::component::context::MAX_DEVICE_RESOURCES {
            host.table.push(0_u8).expect("resource slot");
        }
        assert!(host.table.push(0_u8).is_err());
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
        assert_eq!(host.memory_budget.reserved(), 4096);
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
        assert!(ComponentMemoryLimits::new(0, 1).is_err());
        assert!(ComponentMemoryLimits::new(2, 1).is_err());
        let mut host = BoxHost::with_memory_limits(
            ComponentMemoryLimits::new(STORE_MEMORY_BYTES * 2, BOX_WASM_MEMORY_BYTES).unwrap(),
        );
        assert!(
            ResourceLimiter::memory_growing(&mut host, 0, STORE_MEMORY_BYTES * 2, None).unwrap()
        );
    }

    #[test]
    fn policy_memory_reservation_preserves_the_total_box_limit() {
        let limits = ComponentMemoryLimits::new(16 << 20, 128 << 20).unwrap();
        let (remaining, policy_bytes) = limits.reserve_policy().unwrap();
        assert_eq!(policy_bytes, 16 << 20);
        assert_eq!(remaining.total_bytes() + policy_bytes, limits.total_bytes());
        assert!(
            ComponentMemoryLimits::new(16 << 20, 16 << 20)
                .unwrap()
                .reserve_policy()
                .is_err()
        );
    }
}
