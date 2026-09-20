//! Bounded component stores for one Terra box.

use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::{sync::watch, task::JoinSet};
use tokio_util::task::AbortOnDropHandle;

use wasmtime::component::{Accessor, ResourceTable};
use wasmtime::{Engine, ResourceLimiter, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::engine::{COMPONENT_EPOCH_DEADLINE, DeviceContext, DeviceHost, STORE_MEMORY_BYTES};

pub const BOX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_BOX_COMPONENTS: usize = terra_limits::MAX_DEVICES;
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
const MAX_BOX_COMPONENT_LOOPS: usize =
    MAX_BOX_COMPONENTS * 3 + terra_limits::MAX_VCPUS as usize + 2;
const EPOCH_TICK_INTERVAL: Duration = Duration::from_millis(10);

/// Keeps the runtime engine's epoch interruption advancing.
struct EpochClock {
    stop: Arc<AtomicBool>,
    ticker: Option<std::thread::JoinHandle<()>>,
}

impl EpochClock {
    fn start(engine: Engine) -> wasmtime::Result<Arc<Self>> {
        let stop = Arc::new(AtomicBool::new(false));
        let ticker =
            crate::engine::spawn_epoch_ticker(engine, EPOCH_TICK_INTERVAL, Arc::clone(&stop))
                .ok_or_else(|| wasmtime::Error::msg("starting epoch ticker"))?;
        Ok(Arc::new(Self {
            stop,
            ticker: Some(ticker),
        }))
    }
}

impl Drop for EpochClock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(ticker) = self.ticker.take() {
            let _ = ticker.join();
        }
    }
}

struct BoxMemoryBudget {
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
    fn reserved(&self) -> usize {
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
        router_table.set_max_capacity(crate::engine::MAX_DEVICE_RESOURCES);
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
        Self {
            host: Some(RootHost::new()),
            wasm_memory_bytes: 0,
            pending_memory_growth: 0,
            memory_budget: Arc::new(BoxMemoryBudget::new(limits)),
        }
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

/// A long-running device loop borrowing its component store through an accessor.
pub type ComponentLoop<T = BoxHost> = Box<
    dyn for<'a> FnOnce(
            &'a Accessor<T>,
        ) -> Pin<Box<dyn Future<Output = wasmtime::Result<()>> + Send + 'a>>
        + Send,
>;

/// Builds a box's root store and device workers.
pub struct BoxRuntime {
    pub store: Store<BoxHost>,
    pub(crate) mmio: Option<crate::component::vmm::mmio::Router>,
    epoch_clock: Arc<EpochClock>,
    memory_budget: Arc<BoxMemoryBudget>,
    shutdown: watch::Sender<bool>,
    children: Vec<WorkerTask>,
    component_loops: Vec<ComponentLoop>,
}

pub struct PreparedBoxRuntime {
    store: Store<BoxHost>,
    _epoch_clock: Arc<EpochClock>,
    shutdown: watch::Sender<bool>,
    children: Vec<WorkerTask>,
    component_loops: Vec<ComponentLoop>,
    failure: Option<Arc<std::sync::Mutex<Option<String>>>>,
}

pub struct DeviceWorker<H: StoreHost> {
    pub store: Store<StoreState<H>>,
    epoch_clock: Arc<EpochClock>,
    component_loops: Vec<ComponentLoop<StoreState<H>>>,
}

pub(crate) struct WorkerTask {
    run: Pin<Box<dyn Future<Output = wasmtime::Result<()>> + Send>>,
    executor: Option<tokio::runtime::Handle>,
    epoch_clock: Arc<EpochClock>,
    memory_budget: Arc<BoxMemoryBudget>,
    loop_count: usize,
}

impl WorkerTask {
    pub(crate) fn run_on(
        mut self,
        executor: tokio::runtime::Handle,
        owner: impl Send + 'static,
    ) -> Self {
        self.executor = Some(executor);
        self.run = Box::pin(async move {
            let _owner = owner;
            self.run.await
        });
        self
    }
}

fn create_store<H: StoreHost>(engine: &Engine, host: StoreState<H>) -> Store<StoreState<H>> {
    let mut store = Store::new(engine, host);
    store.set_epoch_deadline(COMPONENT_EPOCH_DEADLINE);
    store.epoch_deadline_async_yield_and_update(COMPONENT_EPOCH_DEADLINE);
    store.limiter(|host| host);
    store
}

/// Owns a running box runtime. Dropping it stops every component loop.
pub struct BoxRuntimeHandle(AbortOnDropHandle<wasmtime::Result<()>>);

impl BoxRuntimeHandle {
    pub fn abort(&self) {
        self.0.abort();
    }

    pub async fn join(self) -> wasmtime::Result<()> {
        self.join_until(tokio::time::Instant::now() + BOX_SHUTDOWN_TIMEOUT)
            .await
    }

    pub async fn join_until(mut self, deadline: tokio::time::Instant) -> wasmtime::Result<()> {
        self.wait_for_task(deadline).await
    }

    pub async fn abort_and_join(self) {
        self.abort_and_join_until(tokio::time::Instant::now() + BOX_SHUTDOWN_TIMEOUT)
            .await;
    }

    pub async fn abort_and_join_until(mut self, deadline: tokio::time::Instant) {
        self.abort();
        let _ = self.wait_for_task(deadline).await;
    }

    async fn wait_for_task(&mut self, deadline: tokio::time::Instant) -> wasmtime::Result<()> {
        let task = &mut self.0;
        let result = tokio::time::timeout_at(deadline, &mut *task)
            .await
            .map_err(|_| {
                task.abort();
                wasmtime::Error::msg("box runtime shutdown timed out")
            })?;
        result.map_err(|error| wasmtime::Error::msg(format!("box runtime task: {error}")))?
    }
}

impl BoxRuntime {
    #[cfg(test)]
    pub(crate) fn reserved_component_memory(&self) -> usize {
        self.memory_budget.reserved()
    }

    pub fn new(engine: &Engine, host: BoxHost) -> wasmtime::Result<Self> {
        let memory_budget = Arc::clone(&host.memory_budget);
        let epoch_clock = EpochClock::start(engine.clone())?;
        let (shutdown, _) = watch::channel(false);
        Ok(Self {
            store: create_store(engine, host),
            mmio: None,
            epoch_clock,
            memory_budget,
            shutdown,
            children: Vec::new(),
            component_loops: Vec::new(),
        })
    }

    pub fn new_child<H: StoreHost>(&self, host: H) -> DeviceWorker<H> {
        self.child_factory()(host)
    }

    pub(crate) fn child_factory<H: StoreHost>(
        &self,
    ) -> impl FnOnce(H) -> DeviceWorker<H> + Send + 'static {
        let memory_budget = Arc::clone(&self.memory_budget);
        let epoch_clock = Arc::clone(&self.epoch_clock);
        let engine = self.store.engine().clone();
        move |host| DeviceWorker {
            store: create_store(
                &engine,
                StoreState {
                    host: Some(host),
                    wasm_memory_bytes: 0,
                    pending_memory_growth: 0,
                    memory_budget,
                },
            ),
            epoch_clock,
            component_loops: Vec::new(),
        }
    }

    pub fn attach_child<H: StoreHost>(&mut self, child: DeviceWorker<H>) -> wasmtime::Result<()> {
        wasmtime::ensure!(
            self.component_count() < MAX_BOX_COMPONENTS,
            "box has too many components"
        );
        let child = child.prepare(self.shutdown.subscribe());
        self.attach_worker(child)
    }

    pub(crate) fn attach_worker(&mut self, child: WorkerTask) -> wasmtime::Result<()> {
        wasmtime::ensure!(
            Arc::ptr_eq(&self.epoch_clock, &child.epoch_clock)
                && Arc::ptr_eq(&self.memory_budget, &child.memory_budget),
            "child runtime belongs to another box"
        );
        wasmtime::ensure!(
            self.children.len() < MAX_BOX_COMPONENTS,
            "box has too many components"
        );
        wasmtime::ensure!(
            self.registered_loop_count() + child.loop_count <= MAX_BOX_COMPONENT_LOOPS,
            "box has too many component loops"
        );
        self.children.push(child);
        Ok(())
    }

    pub(crate) fn component_count(&self) -> usize {
        self.children.len()
            + self
                .mmio
                .as_ref()
                .map_or(0, crate::component::vmm::mmio::Router::unprepared_count)
    }

    #[must_use]
    pub fn has_component(&self, kind: crate::component::vmm::machine::DeviceKind) -> bool {
        self.mmio
            .as_ref()
            .is_some_and(|router| router.has_component(kind))
    }

    pub(crate) fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    pub fn register_loop(&mut self, component_loop: ComponentLoop) -> wasmtime::Result<()> {
        if self.registered_loop_count() >= MAX_BOX_COMPONENT_LOOPS {
            return Err(wasmtime::Error::msg("box has too many component loops"));
        }
        self.component_loops.push(component_loop);
        Ok(())
    }

    fn registered_loop_count(&self) -> usize {
        self.component_loops.len()
            + self
                .children
                .iter()
                .map(|child| child.loop_count)
                .sum::<usize>()
    }

    pub async fn prepare(self) -> wasmtime::Result<PreparedBoxRuntime> {
        self.validate_runtime_start()?;
        self.prepare_devices().await?.finish()
    }

    pub(crate) fn finish(mut self) -> wasmtime::Result<PreparedBoxRuntime> {
        self.validate_runtime_start()?;
        let failure = if let Some(router) = self.mmio.take() {
            let crate::component::vmm::mmio::Router {
                bridge,
                entrypoint,
                failure,
                ..
            } = router;
            if self.store.data().platform.is_machine_running() {
                self.register_loop(entrypoint)?;
            }
            self.component_loops.push(bridge);
            Some(failure)
        } else {
            None
        };
        Ok(PreparedBoxRuntime {
            store: self.store,
            _epoch_clock: self.epoch_clock,
            shutdown: self.shutdown,
            children: self.children,
            component_loops: self.component_loops,
            failure,
        })
    }

    #[must_use]
    pub fn lifecycle_notifier(&self) -> crate::component::vmm::lifecycle::LifecycleNotifier {
        self.store.data().lifecycle.notifier()
    }

    #[must_use]
    pub fn native_teardown(&self) -> crate::component::vmm::teardown::NativeTeardown {
        self.store.data().lifecycle.native_teardown()
    }
}

impl PreparedBoxRuntime {
    #[must_use]
    pub fn lifecycle_notifier(&self) -> crate::component::vmm::lifecycle::LifecycleNotifier {
        self.store.data().lifecycle.notifier()
    }

    #[must_use]
    pub fn native_teardown(&self) -> crate::component::vmm::teardown::NativeTeardown {
        self.store.data().lifecycle.native_teardown()
    }

    #[must_use]
    pub fn start(self) -> BoxRuntimeHandle {
        BoxRuntimeHandle(AbortOnDropHandle::new(tokio::spawn(Self::run_group(self))))
    }

    async fn run_group(mut root: Self) -> wasmtime::Result<()> {
        enum StoreRole {
            Root,
            Child,
        }

        let lifecycle = root.store.data().lifecycle.notifier();
        let failure = root.failure.take();
        let mut workers = JoinSet::new();
        for child in std::mem::take(&mut root.children) {
            workers.spawn_on(
                child.run,
                &child
                    .executor
                    .unwrap_or_else(tokio::runtime::Handle::current),
            );
        }
        let shutdown = root.shutdown.clone();
        let result = async {
            let root_events =
                futures_util::stream::once(root.run()).map(|result| (StoreRole::Root, result));
            let child_events = futures_util::stream::unfold(&mut workers, |workers| async {
                workers.join_next().await.map(|result| {
                    let result = result
                        .map_err(|error| wasmtime::Error::msg(format!("box worker task: {error}")))
                        .and_then(std::convert::identity);
                    ((StoreRole::Child, result), workers)
                })
            });
            let events = futures_util::stream::select(root_events, child_events);
            tokio::pin!(events);
            let mut deadline = None;
            loop {
                let event = if let Some(deadline) = deadline {
                    tokio::time::timeout_at(deadline, events.next())
                        .await
                        .map_err(|_| wasmtime::Error::msg("box runtime shutdown timed out"))?
                } else {
                    events.next().await
                };
                let Some((role, result)) = event else {
                    return Ok(());
                };
                result?;
                match role {
                    StoreRole::Root => {
                        shutdown.send_replace(true);
                        deadline = Some(lifecycle.begin_shutdown().into());
                    }
                    StoreRole::Child => {}
                }
            }
        }
        .await;
        if let Err(error) = &result {
            if let Some(failure) = &failure {
                crate::component::vmm::mmio::Router::record_failure_in(failure, error);
            }
            lifecycle.component_failed();
            lifecycle.publish_outcome(crate::component::vmm::lifecycle::Outcome::ComponentFailed);
        }
        workers.shutdown().await;
        if result.is_err()
            && let Err(error) = root.recover_native().await
        {
            log::warn!("native recovery after component failure: {error:#}");
        }
        result
    }

    async fn recover_native(&mut self) -> wasmtime::Result<()> {
        self.store
            .data()
            .lifecycle
            .native_teardown()
            .wait_until_finished()
            .await
            .map_err(wasmtime::Error::msg)
    }

    async fn run(&mut self) -> wasmtime::Result<()> {
        let loops = std::mem::take(&mut self.component_loops);
        run_store(&mut self.store, loops, None).await
    }
}

impl<H: StoreHost> DeviceWorker<H> {
    pub fn register_loop(
        &mut self,
        component_loop: ComponentLoop<StoreState<H>>,
    ) -> wasmtime::Result<()> {
        wasmtime::ensure!(
            self.component_loops.len() < MAX_BOX_COMPONENT_LOOPS,
            "box has too many component loops"
        );
        self.component_loops.push(component_loop);
        Ok(())
    }

    pub(crate) fn prepare(mut self, shutdown: watch::Receiver<bool>) -> WorkerTask {
        WorkerTask {
            executor: None,
            epoch_clock: Arc::clone(&self.epoch_clock),
            memory_budget: Arc::clone(&self.store.data().memory_budget),
            loop_count: self.component_loops.len(),
            run: Box::pin(async move { self.run(shutdown).await }),
        }
    }

    async fn run(&mut self, shutdown: watch::Receiver<bool>) -> wasmtime::Result<()> {
        run_store(
            &mut self.store,
            std::mem::take(&mut self.component_loops),
            Some(shutdown),
        )
        .await
    }
}

async fn run_store<T: Send + 'static>(
    store: &mut Store<T>,
    loops: Vec<ComponentLoop<T>>,
    shutdown: Option<watch::Receiver<bool>>,
) -> wasmtime::Result<()> {
    wasmtime::ensure!(!loops.is_empty(), "box runtime has no component loops");
    store
        .run_concurrent(async move |accessor| {
            let mut running: FuturesUnordered<_> = loops
                .into_iter()
                .map(|component_loop| component_loop(accessor))
                .collect();
            while let Some(result) = running.next().await {
                result?;
            }
            if let Some(mut shutdown) = shutdown {
                while !*shutdown.borrow_and_update() {
                    shutdown
                        .changed()
                        .await
                        .map_err(|_| wasmtime::Error::msg("box runtime shutdown signal closed"))?;
                }
            }
            Ok(())
        })
        .await?
}

#[cfg(test)]
mod tests;
