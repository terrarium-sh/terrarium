//! Bounded component stores for one Terra box.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::{sync::watch, task::JoinSet};
use tokio_util::task::AbortOnDropHandle;

use wasmtime::Store;
use wasmtime::component::Accessor;

pub(crate) mod setup;
pub(crate) mod store;

pub use store::{
    BoxHost, ComponentMemoryLimits, DEFAULT_COMPONENT_MEMORY_MIB, NETWORK_FRONTEND_MEMORY_BYTES,
    RootHost, StoreHost, StoreState,
};

pub(crate) const BOX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const MAX_BOX_COMPONENTS: usize = terra_limits::MAX_DEVICES;
const MAX_BOX_COMPONENT_WORKERS: usize = MAX_BOX_COMPONENTS + 3;
const MAX_BOX_COMPONENT_LOOPS: usize =
    MAX_BOX_COMPONENTS * 3 + terra_limits::MAX_VCPUS as usize + 3;

/// Marks the stores and workers of one box, so a worker cannot join another box.
struct BoxIdentity;

/// A long-running device loop borrowing its component store through an accessor.
pub(crate) type ComponentLoop<T = BoxHost> = Box<
    dyn for<'a> FnOnce(
            &'a Accessor<T>,
        ) -> Pin<Box<dyn Future<Output = wasmtime::Result<()>> + Send + 'a>>
        + Send,
>;

/// One box's device runtime while it is assembled: the root store holding the VMM and MMIO
/// bridge, and one worker store per device. [`Self::prepare`] sets the devices up to run.
pub struct BoxRuntime {
    pub store: Store<BoxHost>,
    pub(crate) vmm: Option<crate::component::vmm::VmmInstance>,
    pub(crate) mmio: Option<crate::component::mmio::MmioInstance>,
    pub(crate) interrupt_controller_configured: bool,
    identity: Arc<BoxIdentity>,
    shutdown: watch::Sender<bool>,
    children: Vec<WorkerTask>,
    component_loops: Vec<ComponentLoop>,
    agent_setup: Option<setup::AgentSetup>,
}

/// A box runtime with its devices set up; [`Self::start`] runs it.
pub struct PreparedBoxRuntime {
    store: Store<BoxHost>,
    shutdown: watch::Sender<bool>,
    children: Vec<WorkerTask>,
    component_loops: Vec<ComponentLoop>,
    failure: Option<Arc<std::sync::Mutex<Option<String>>>>,
}

pub(crate) struct DeviceWorker<H: StoreHost> {
    pub store: Store<StoreState<H>>,
    identity: Arc<BoxIdentity>,
    component_loops: Vec<ComponentLoop<StoreState<H>>>,
}

pub(crate) struct WorkerTask {
    run: Pin<Box<dyn Future<Output = wasmtime::Result<()>> + Send>>,
    executor: Option<tokio::runtime::Handle>,
    identity: Arc<BoxIdentity>,
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
            let teardown = root.native_teardown();
            let deadline = lifecycle.begin_shutdown();
            drop(root);
            if let Err(error) = teardown.wait_until(deadline).await {
                log::warn!("native recovery after component failure: {error:#}");
            }
        }
        workers.shutdown().await;
        result
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
            identity: Arc::clone(&self.identity),
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
