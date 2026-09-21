//! Bounded component stores for one Terra box.

use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::{sync::watch, task::JoinSet};
use tokio_util::task::AbortOnDropHandle;

use wasmtime::component::Accessor;
use wasmtime::{Engine, Store};

pub mod store;

use store::{BoxHost, BoxMemoryBudget, StoreHost, StoreState, create_store};

pub const BOX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_BOX_COMPONENTS: usize = terra_limits::MAX_DEVICES;
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
        let ticker = spawn_epoch_ticker(engine, EPOCH_TICK_INTERVAL, Arc::clone(&stop))
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

/// Running epoch ticker: bumps the engine clock until `stop` is set so
/// epoch deadlines actually fire. The worker owns one per VM; the
/// harness test proves the mechanism with a short interval.
#[must_use]
fn spawn_epoch_ticker(
    engine: Engine,
    interval: core::time::Duration,
    stop: std::sync::Arc<core::sync::atomic::AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("epoch-tick".to_string())
        .spawn(move || {
            while !stop.load(core::sync::atomic::Ordering::Acquire) {
                std::thread::sleep(interval);
                engine.increment_epoch();
            }
        })
        .ok()
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
        let memory_budget = Arc::clone(host.memory_budget());
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
            store: create_store(&engine, StoreState::with_budget(host, memory_budget)),
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

    pub fn mmio_failure_observation(
        &self,
    ) -> wasmtime::Result<crate::component::vmm::mmio::FailureObservation> {
        self.mmio
            .as_ref()
            .map(crate::component::vmm::mmio::Router::failure_observation)
            .ok_or_else(|| wasmtime::Error::msg("MMIO router missing"))
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
            memory_budget: Arc::clone(self.store.data().memory_budget()),
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
