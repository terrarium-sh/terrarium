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

pub(crate) mod setup;
pub(crate) mod store;

pub use store::{
    BoxHost, ComponentMemoryLimits, DEFAULT_COMPONENT_MEMORY_MIB, RootHost, StoreHost, StoreState,
};

pub(crate) const BOX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const MAX_BOX_COMPONENTS: usize = terra_limits::MAX_DEVICES;
const MAX_BOX_COMPONENT_WORKERS: usize = MAX_BOX_COMPONENTS + 2;
const MAX_BOX_COMPONENT_LOOPS: usize =
    MAX_BOX_COMPONENTS * 3 + terra_limits::MAX_VCPUS as usize + 4;
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
pub(crate) type ComponentLoop<T = BoxHost> = Box<
    dyn for<'a> FnOnce(
            &'a Accessor<T>,
        ) -> Pin<Box<dyn Future<Output = wasmtime::Result<()>> + Send + 'a>>
        + Send,
>;

/// Builds a box's root store and device workers.
pub struct BoxRuntime {
    pub store: Store<BoxHost>,
    pub(crate) vmm: Option<crate::component::vmm::VmmInstance>,
    pub(crate) mmio: Option<crate::component::mmio::MmioInstance>,
    pub(crate) interrupt_controller_configured: bool,
    epoch_clock: Arc<EpochClock>,
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

pub(crate) struct DeviceWorker<H: StoreHost> {
    pub store: Store<StoreState<H>>,
    epoch_clock: Arc<EpochClock>,
    component_loops: Vec<ComponentLoop<StoreState<H>>>,
}

pub(crate) struct WorkerTask {
    run: Pin<Box<dyn Future<Output = wasmtime::Result<()>> + Send>>,
    executor: Option<tokio::runtime::Handle>,
    epoch_clock: Arc<EpochClock>,
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
    #[must_use]
    pub fn lifecycle_notifier(&self) -> crate::component::vmm::lifecycle::LifecycleNotifier {
        self.store.data().lifecycle.notifier()
    }

    #[must_use]
    pub fn native_teardown(&self) -> crate::component::vmm::teardown::NativeTeardown {
        self.store.data().lifecycle.native_teardown()
    }

    pub fn vmm_failure_observation(
        &self,
    ) -> wasmtime::Result<crate::component::vmm::FailureObservation> {
        self.vmm
            .as_ref()
            .map(crate::component::vmm::VmmInstance::failure_observation)
            .ok_or_else(|| wasmtime::Error::msg("VMM missing"))
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
                crate::component::vmm::VmmInstance::record_failure_in(failure, error);
            }
            lifecycle.component_failed();
            lifecycle.publish_outcome(crate::component::vmm::lifecycle::Outcome::ComponentFailed);
            shutdown.send_replace(true);
            if let Err(error) = root.recover_native_until(lifecycle.begin_shutdown()).await {
                log::warn!("native recovery after component failure: {error:#}");
            }
        }
        workers.shutdown().await;
        result
    }

    async fn recover_native_until(&mut self, deadline: std::time::Instant) -> wasmtime::Result<()> {
        self.store
            .data()
            .lifecycle
            .native_teardown()
            .wait_until(deadline)
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
