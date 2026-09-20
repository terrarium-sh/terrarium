//! Bounded component stores for one Terra box.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::task::Poll;
use std::time::Duration;

use tokio::{sync::watch, task::JoinSet};

use wasmtime::component::{Accessor, ResourceTable};
use wasmtime::{Engine, ResourceLimiter, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::component::fs::host::FsHost;
use crate::component::mem::host::MemHost;
use crate::engine::{COMPONENT_EPOCH_DEADLINE, DeviceHost, STORE_MEMORY_BYTES};

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
const MAX_BOX_COMPONENT_LOOPS: usize = MAX_BOX_COMPONENTS * 3 + 32 + 2;
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

/// All host state reachable by components belonging to one box.
pub struct BoxHost {
    pub block: Vec<DeviceHost>,
    pub network: Vec<DeviceHost>,
    pub vsock: Vec<DeviceHost>,
    pub filesystems: Vec<FsHost>,
    pub memory: Vec<MemHost>,
    pub(crate) boot: crate::component::vmm::boot::BootHost,
    pub(crate) platform: crate::component::vmm::PlatformHost,
    pub(crate) lifecycle: crate::component::vmm::lifecycle::LifecycleHost,
    router_ctx: WasiCtx,
    router_table: ResourceTable,
    wasm_memory_bytes: usize,
    pending_memory_growth: usize,
    memory_budget: Arc<BoxMemoryBudget>,
}

struct DropRecovery {
    filesystems: Vec<FsHost>,
    machine: Option<crate::component::vmm::virtualization::MachineRecovery>,
    devices: Vec<crate::component::vmm::teardown::DeviceShutdown>,
    interrupts: Option<crate::component::vmm::teardown::NativeCleanup>,
}

impl Drop for DropRecovery {
    fn drop(&mut self) {
        if self.machine.is_some()
            || !self.devices.is_empty()
            || self.interrupts.is_some()
            || !self.filesystems.is_empty()
        {
            start_drop_recovery(Self {
                filesystems: std::mem::take(&mut self.filesystems),
                machine: self.machine.take(),
                devices: std::mem::take(&mut self.devices),
                interrupts: self.interrupts.take(),
            });
        }
    }
}

async fn finish_native_recovery(mut recovery: DropRecovery) -> wasmtime::Result<()> {
    if let Some(machine) = recovery.machine.as_ref()
        && let Err(error) = machine.wait().await
    {
        // ponytail: retain live VM resources after a failed join; release when the platform can prove vCPUs stopped.
        std::mem::forget(recovery);
        return Err(error);
    }
    recovery.machine = None;
    let mut result = Ok(());
    for device in &recovery.devices {
        if let Err(error) = device.wait_until_closed().await {
            result = Err(wasmtime::Error::msg(error));
        }
    }
    recovery.devices.clear();
    if let Some(interrupts) = &recovery.interrupts
        && let Err(error) = interrupts.wait_until_finished().await
    {
        result = Err(wasmtime::Error::msg(error));
    }
    recovery.interrupts = None;
    drop(std::mem::take(&mut recovery.filesystems));
    result
}

fn run_drop_recovery(recovery: &Mutex<Option<DropRecovery>>) {
    let recovery = recovery
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(recovery) = recovery {
        if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            let _ = runtime.block_on(finish_native_recovery(recovery));
        } else {
            // ponytail: failed runtime creation retains VM resources; retry cleanup if this becomes recoverable.
            std::mem::forget(recovery);
        }
    }
}

fn start_drop_recovery(recovery: DropRecovery) {
    let recovery = Arc::new(Mutex::new(Some(recovery)));
    let worker_recovery = Arc::clone(&recovery);
    if std::thread::Builder::new()
        .spawn(move || run_drop_recovery(&worker_recovery))
        .is_err()
    {
        // Keep native resources alive if no cleanup thread can be started.
        std::mem::forget(recovery);
    }
}

impl BoxHost {
    #[must_use]
    pub fn new() -> Self {
        Self::with_memory_limits(ComponentMemoryLimits::default())
    }

    #[must_use]
    pub fn with_memory_limits(limits: ComponentMemoryLimits) -> Self {
        let mut router_table = ResourceTable::new();
        router_table.set_max_capacity(crate::engine::MAX_DEVICE_RESOURCES);
        Self {
            block: Vec::new(),
            network: Vec::new(),
            vsock: Vec::new(),
            filesystems: Vec::new(),
            memory: Vec::new(),
            boot: crate::component::vmm::boot::BootHost::default(),
            platform: crate::component::vmm::PlatformHost::default(),
            lifecycle: crate::component::vmm::lifecycle::LifecycleHost::new(),
            router_ctx: WasiCtxBuilder::new()
                .max_random_size(crate::MAX_SINGLE_BYTES)
                .allow_tcp(false)
                .allow_udp(false)
                .allow_ip_name_lookup(false)
                .build(),
            router_table,
            wasm_memory_bytes: 0,
            pending_memory_growth: 0,
            memory_budget: Arc::new(BoxMemoryBudget::new(limits)),
        }
    }

    #[allow(clippy::expect_used, clippy::missing_panics_doc)]
    pub fn vsock_device(&mut self) -> &mut DeviceHost {
        self.vsock
            .first_mut()
            .expect("vsock component host must be registered before instantiation")
    }

    pub fn vsock_cli(&mut self) -> wasmtime_wasi::cli::WasiCliCtxView<'_> {
        wasmtime_wasi::cli::WasiCliView::cli(Self::vsock_device(self))
    }

    pub fn vsock_clocks(&mut self) -> wasmtime_wasi::clocks::WasiClocksCtxView<'_> {
        wasmtime_wasi::clocks::WasiClocksView::clocks(Self::vsock_device(self))
    }

    pub fn vsock_random(&mut self) -> &mut wasmtime_wasi::random::WasiRandomCtx {
        wasmtime_wasi::random::WasiRandomView::random(Self::vsock_device(self))
    }

    pub fn vsock_service(&mut self) -> &mut crate::component::vsock::host::VsockHostService {
        self.vsock_device().vsock_service_mut()
    }

    fn rebind(
        &mut self,
        memory_budget: Arc<BoxMemoryBudget>,
        lifecycle: crate::component::vmm::lifecycle::LifecycleHost,
    ) -> wasmtime::Result<()> {
        if self.wasm_memory_bytes != 0 || self.pending_memory_growth != 0 {
            return Err(wasmtime::Error::msg("child host already has Wasm memory"));
        }
        self.memory_budget = memory_budget;
        self.lifecycle = lifecycle;
        Ok(())
    }

    fn component_count(&self) -> usize {
        self.block
            .len()
            .saturating_add(self.network.len())
            .saturating_add(self.vsock.len())
            .saturating_add(self.filesystems.len())
            .saturating_add(self.memory.len())
    }
}

impl Drop for BoxHost {
    fn drop(&mut self) {
        let machine = self.platform.take_recovery_reaper().ok().flatten();
        let (devices, interrupts) = self.lifecycle.take_shutdowns();
        if machine.is_some()
            || !devices.is_empty()
            || interrupts.is_some()
            || !self.filesystems.is_empty()
        {
            start_drop_recovery(DropRecovery {
                filesystems: std::mem::take(&mut self.filesystems),
                machine,
                devices,
                interrupts,
            });
        }
        self.memory_budget.release(self.wasm_memory_bytes);
    }
}

impl WasiView for BoxHost {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.router_ctx,
            table: &mut self.router_table,
        }
    }
}

impl Default for BoxHost {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceLimiter for BoxHost {
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
pub type ComponentLoop = Box<
    dyn for<'a> FnOnce(
            &'a Accessor<BoxHost>,
        ) -> Pin<Box<dyn Future<Output = wasmtime::Result<()>> + Send + 'a>>
        + Send,
>;

type RunningLoop<'a> = Pin<Box<dyn Future<Output = wasmtime::Result<()>> + Send + 'a>>;

/// Owns a box's root store and its device child stores.
pub struct BoxRuntime {
    pub store: Store<BoxHost>,
    pub(crate) filesystem_runtime: Option<crate::component::fs::FilesystemRuntime>,
    pub(crate) mmio: Option<crate::component::vmm::mmio::Router>,
    epoch_clock: Arc<EpochClock>,
    memory_budget: Arc<BoxMemoryBudget>,
    shutdown: watch::Sender<bool>,
    children: Vec<BoxRuntime>,
    pub(crate) pending_workers: Vec<crate::component::vmm::mmio::PendingWorker>,
    component_loops: Vec<ComponentLoop>,
}

/// Owns a running box runtime. Dropping it stops every component loop.
pub struct BoxRuntimeHandle(Option<tokio::task::JoinHandle<wasmtime::Result<()>>>);

impl BoxRuntimeHandle {
    pub fn abort(&self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }

    pub async fn join(mut self) -> wasmtime::Result<()> {
        self.wait_for_task(BOX_SHUTDOWN_TIMEOUT, false).await
    }

    pub async fn abort_and_join(mut self) {
        let _ = self.wait_for_task(BOX_SHUTDOWN_TIMEOUT, true).await;
    }

    async fn wait_for_task(&mut self, timeout: Duration, abort: bool) -> wasmtime::Result<()> {
        let (result, timed_out) = {
            let task = self
                .0
                .as_mut()
                .ok_or_else(|| wasmtime::Error::msg("box runtime already joined"))?;
            if abort {
                task.abort();
            }
            let result = tokio::time::timeout(timeout, &mut *task).await;
            if result.is_err() && !abort {
                task.abort();
                (tokio::time::timeout(timeout, &mut *task).await, true)
            } else {
                (result, false)
            }
        };
        if timed_out {
            if result.is_ok() {
                let _ = self.0.take();
            }
            return Err(wasmtime::Error::msg("box runtime shutdown timed out"));
        }
        let result = result.map_err(|_| wasmtime::Error::msg("box runtime shutdown timed out"))?;
        let _ = self.0.take();
        result.map_err(|error| wasmtime::Error::msg(format!("box runtime task: {error}")))?
    }
}

impl Drop for BoxRuntimeHandle {
    fn drop(&mut self) {
        self.abort();
    }
}

impl BoxRuntime {
    #[cfg(test)]
    pub(crate) fn reserved_component_memory(&self) -> usize {
        self.memory_budget.reserved()
    }

    pub fn new(engine: &Engine, host: BoxHost) -> wasmtime::Result<Self> {
        let memory_budget = Arc::clone(&host.memory_budget);
        Self::new_with_resources(
            engine,
            host,
            EpochClock::start(engine.clone())?,
            memory_budget,
        )
    }

    fn new_with_resources(
        engine: &Engine,
        host: BoxHost,
        epoch_clock: Arc<EpochClock>,
        memory_budget: Arc<BoxMemoryBudget>,
    ) -> wasmtime::Result<Self> {
        if host.component_count() > MAX_BOX_COMPONENTS {
            return Err(wasmtime::Error::msg("box has too many components"));
        }
        let mut store = Store::new(engine, host);
        store.set_epoch_deadline(COMPONENT_EPOCH_DEADLINE);
        store.epoch_deadline_async_yield_and_update(COMPONENT_EPOCH_DEADLINE);
        store.limiter(|host| host);
        let (shutdown, _) = watch::channel(false);
        Ok(Self {
            store,
            filesystem_runtime: None,
            mmio: None,
            epoch_clock,
            memory_budget,
            shutdown,
            children: Vec::new(),
            pending_workers: Vec::new(),
            component_loops: Vec::new(),
        })
    }

    pub fn new_child(&self, host: BoxHost) -> wasmtime::Result<Self> {
        self.child_factory()(host)
    }

    pub(crate) fn child_factory(
        &self,
    ) -> impl FnOnce(BoxHost) -> wasmtime::Result<Self> + Send + 'static {
        let notifier = self.lifecycle_notifier();
        let memory_budget = Arc::clone(&self.memory_budget);
        let epoch_clock = Arc::clone(&self.epoch_clock);
        let engine = self.store.engine().clone();
        move |mut host| {
            let lifecycle =
                crate::component::vmm::lifecycle::LifecycleHost::from_notifier(notifier);
            host.rebind(Arc::clone(&memory_budget), lifecycle)?;
            Self::new_with_resources(&engine, host, epoch_clock, memory_budget)
        }
    }

    pub fn attach_child(&mut self, child: BoxRuntime) -> wasmtime::Result<()> {
        if !child.children.is_empty()
            || !Arc::ptr_eq(&self.epoch_clock, &child.epoch_clock)
            || !Arc::ptr_eq(&self.memory_budget, &child.memory_budget)
        {
            return Err(wasmtime::Error::msg("child runtime belongs to another box"));
        }
        if self.children.len() >= MAX_BOX_COMPONENTS
            || self
                .component_count()
                .checked_add(child.component_count())
                .is_none_or(|count| count > MAX_BOX_COMPONENTS)
        {
            return Err(wasmtime::Error::msg("box has too many components"));
        }
        if self.registered_loop_count() + child.registered_loop_count() > MAX_BOX_COMPONENT_LOOPS {
            return Err(wasmtime::Error::msg("box has too many component loops"));
        }
        self.children.push(child);
        Ok(())
    }

    pub(crate) fn component_count(&self) -> usize {
        self.store
            .data()
            .component_count()
            .saturating_add(self.children.iter().map(Self::component_count).sum())
            .saturating_add(self.pending_workers.len())
    }

    #[must_use]
    pub fn has_component(&self, kind: crate::component::vmm::machine::DeviceKind) -> bool {
        self.pending_workers
            .iter()
            .any(|worker| worker.kind == kind)
            || match kind {
                crate::component::vmm::machine::DeviceKind::Block => {
                    !self.store.data().block.is_empty()
                }
                crate::component::vmm::machine::DeviceKind::Net => {
                    !self.store.data().network.is_empty()
                }
                crate::component::vmm::machine::DeviceKind::Vsock => {
                    !self.store.data().vsock.is_empty()
                }
                crate::component::vmm::machine::DeviceKind::Fs => {
                    !self.store.data().filesystems.is_empty()
                }
                crate::component::vmm::machine::DeviceKind::Memory => {
                    !self.store.data().memory.is_empty()
                }
            }
            || self.children.iter().any(|child| child.has_component(kind))
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
                .map(Self::registered_loop_count)
                .sum::<usize>()
    }

    #[must_use]
    pub fn start(self) -> BoxRuntimeHandle {
        BoxRuntimeHandle(Some(tokio::spawn(Self::run_group(self))))
    }

    #[allow(clippy::too_many_lines)]
    async fn run_group(mut root: Self) -> wasmtime::Result<()> {
        let lifecycle = root.lifecycle_notifier();
        let failure = root
            .mmio
            .as_ref()
            .map(crate::component::vmm::mmio::Router::failure_sink);
        let mut workers = JoinSet::new();
        let result = async {
            let children = std::mem::take(&mut root.children);
            let child_shutdowns = children.iter().map(|child| child.shutdown.clone()).collect::<Vec<_>>();
            for mut child in children {
                let executor = child.filesystem_runtime.as_ref().map_or_else(
                    || Ok(tokio::runtime::Handle::current()),
                    crate::component::fs::FilesystemRuntime::handle,
                )?;
                workers.spawn_on(async move { child.run_until_shutdown(true).await }, &executor);
            }
            let root_result = root.run_until_shutdown(false);
            tokio::pin!(root_result);
            loop {
                tokio::select! {
                    result = &mut root_result => {
                        result?;
                        for shutdown in &child_shutdowns {
                            shutdown.send_replace(true);
                        }
                        return tokio::time::timeout(BOX_SHUTDOWN_TIMEOUT, async {
                            while let Some(result) = workers.join_next().await {
                                result.map_err(|error| wasmtime::Error::msg(format!("box worker task: {error}")))??;
                            }
                            Ok(())
                        }).await.map_err(|_| wasmtime::Error::msg("box runtime shutdown timed out"))?;
                    },
                    result = workers.join_next(), if !workers.is_empty() => {
                        result
                            .ok_or_else(|| wasmtime::Error::msg("box worker task missing"))?
                            .map_err(|error| wasmtime::Error::msg(format!("box worker task: {error}")))??;
                    }
                }
            }
        }
        .await;
        workers.abort_all();
        while workers.join_next().await.is_some() {}
        if let Err(error) = &result {
            if let Some(failure) = &failure {
                crate::component::vmm::mmio::Router::record_failure_in(failure, error);
            }
            if let (Some(failure), Err(recovery)) = (&failure, root.recover_native().await) {
                crate::component::vmm::mmio::Router::record_failure_in(failure, &recovery);
            }
            lifecycle.component_failed();
            lifecycle.complete(crate::component::vmm::lifecycle::Outcome::ComponentFailed);
        }
        result
    }

    #[must_use]
    pub fn lifecycle_notifier(&self) -> crate::component::vmm::lifecycle::LifecycleNotifier {
        self.store.data().lifecycle.notifier()
    }

    async fn recover_native(&mut self) -> wasmtime::Result<()> {
        let machine = self.store.data_mut().platform.take_recovery_reaper()?;
        let (devices, interrupts) = self.store.data_mut().lifecycle.take_shutdowns();
        finish_native_recovery(DropRecovery {
            filesystems: Vec::new(),
            machine,
            devices,
            interrupts,
        })
        .await
    }

    pub fn add_block(&mut self, host: DeviceHost) -> wasmtime::Result<usize> {
        self.add_host(|box_host| &mut box_host.block, host)
    }

    pub fn add_network(&mut self, host: DeviceHost) -> wasmtime::Result<usize> {
        self.add_host(|box_host| &mut box_host.network, host)
    }

    pub fn add_vsock(&mut self, host: DeviceHost) -> wasmtime::Result<usize> {
        self.add_host(|box_host| &mut box_host.vsock, host)
    }

    pub fn add_fs(&mut self, host: FsHost) -> wasmtime::Result<usize> {
        self.add_host(|box_host| &mut box_host.filesystems, host)
    }

    pub fn add_mem(&mut self, host: MemHost) -> wasmtime::Result<usize> {
        self.add_host(|box_host| &mut box_host.memory, host)
    }

    fn add_host<Host>(
        &mut self,
        select: fn(&mut BoxHost) -> &mut Vec<Host>,
        host: Host,
    ) -> wasmtime::Result<usize> {
        if self.component_count() >= MAX_BOX_COMPONENTS {
            return Err(wasmtime::Error::msg("box has too many components"));
        }
        let box_host = self.store.data_mut();
        let hosts = select(box_host);
        let index = hosts.len();
        hosts.push(host);
        Ok(index)
    }

    #[cfg(test)]
    async fn run(&mut self) -> wasmtime::Result<()> {
        self.run_until_shutdown(false).await
    }

    async fn run_until_shutdown(&mut self, wait_for_shutdown: bool) -> wasmtime::Result<()> {
        let mut component_loops = std::mem::take(&mut self.component_loops);
        if let Some(bridge) = self.mmio.as_mut().and_then(|router| router.bridge.take()) {
            component_loops.push(bridge);
        }
        if component_loops.is_empty() {
            return Err(wasmtime::Error::msg("box runtime has no component loops"));
        }
        let mut shutdown = self.shutdown.subscribe();
        let result = self
            .store
            .run_concurrent(async move |accessor| {
                let mut component_loops: Vec<RunningLoop<'_>> = component_loops
                    .into_iter()
                    .map(|component_loop| component_loop(accessor))
                    .collect();
                loop {
                    if wait_for_loop(&mut component_loops).await? {
                        if wait_for_shutdown {
                            while !*shutdown.borrow_and_update() {
                                shutdown.changed().await.map_err(|_| {
                                    wasmtime::Error::msg("box runtime shutdown signal closed")
                                })?;
                            }
                        }
                        return Ok(());
                    }
                }
            })
            .await
            .and_then(|result| result);
        if let Err(error) = &result {
            if let Some(router) = &self.mmio {
                router.record_failure(error);
            }
            self.lifecycle_notifier()
                .complete(crate::component::vmm::lifecycle::Outcome::ComponentFailed);
        }
        result
    }
}

async fn wait_for_loop(component_loops: &mut Vec<RunningLoop<'_>>) -> wasmtime::Result<bool> {
    poll_fn(|context| {
        for (index, component_loop) in component_loops.iter_mut().enumerate() {
            if let Poll::Ready(result) = component_loop.as_mut().poll(context) {
                return Poll::Ready(result.map(|()| index));
            }
        }
        Poll::Pending
    })
    .await
    .map(|index| {
        drop(component_loops.remove(index));
        component_loops.is_empty()
    })
}

#[cfg(test)]
mod tests;
