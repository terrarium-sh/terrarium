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
    pub(crate) mmio_client: Option<crate::component::mmio::Client>,
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
            mmio_client: None,
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
    store.set_hostcall_fuel(terra_limits::MAX_COMPONENT_HOSTCALL_BYTES);
    if let Some(table) = store.concurrent_resource_table() {
        table.set_max_capacity(crate::component::context::MAX_DEVICE_RESOURCES);
    }
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
