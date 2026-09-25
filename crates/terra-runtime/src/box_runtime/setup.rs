//! Box construction, device registration, and startup sequencing.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::watch;
use wasmtime::Engine;
use wasmtime::component::StreamReader;

#[cfg(test)]
use super::MAX_BOX_COMPONENTS;
use super::store::{BoxHost, StoreHost, StoreState, create_store};
use super::{
    BoxRuntime, ComponentLoop, DeviceWorker, EpochClock, MAX_BOX_COMPONENT_LOOPS,
    MAX_BOX_COMPONENT_WORKERS, PreparedBoxRuntime, WorkerTask,
};
use crate::component::mmio::{self, DevicePlan, Serve, router_error};
use crate::component::mmio::{Reply, Request};
use crate::component::relay;
use crate::component::vmm::boot::BootEntry;
use crate::component::vmm::{self, NativeVcpu, StartedVcpus, VcpuReaper};
use crate::machine::DeviceKind;

pub(crate) const SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) type Setup = Box<
    dyn FnOnce(
            relay::Stream<Request>,
        ) -> Pin<Box<dyn Future<Output = wasmtime::Result<PreparedWorker>> + Send>>
        + Send,
>;

pub(crate) struct PreparedWorker {
    pub worker: WorkerTask,
    pub replies: relay::Stream<Reply>,
}

impl BoxRuntime {
    pub fn new(engine: &Engine, host: BoxHost) -> wasmtime::Result<Self> {
        let epoch_clock = EpochClock::start(engine.clone())?;
        let (shutdown, _) = watch::channel(false);
        Ok(Self {
            store: create_store(engine, host),
            vmm: None,
            mmio: None,
            interrupt_controller_configured: false,
            epoch_clock,
            shutdown,
            children: Vec::new(),
            component_loops: Vec::new(),
        })
    }

    pub(crate) fn new_child<H: StoreHost>(&self, host: H) -> DeviceWorker<H> {
        self.child_factory()(host)
    }

    pub(crate) fn child_factory<H: StoreHost>(
        &self,
    ) -> impl FnOnce(H) -> DeviceWorker<H> + Send + 'static {
        let memory_limits = self.store.data().memory_limits();
        let epoch_clock = Arc::clone(&self.epoch_clock);
        let engine = self.store.engine().clone();
        move |host| DeviceWorker {
            store: create_store(&engine, StoreState::with_limits(host, memory_limits)),
            epoch_clock,
            component_loops: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn attach_child<H: StoreHost>(
        &mut self,
        child: DeviceWorker<H>,
    ) -> wasmtime::Result<()> {
        wasmtime::ensure!(
            self.component_count() < MAX_BOX_COMPONENTS,
            "box has too many components"
        );
        let child = child.prepare(self.shutdown.subscribe());
        self.attach_worker(child)
    }

    pub(crate) fn attach_worker(&mut self, child: WorkerTask) -> wasmtime::Result<()> {
        wasmtime::ensure!(
            Arc::ptr_eq(&self.epoch_clock, &child.epoch_clock),
            "child runtime belongs to another box"
        );
        wasmtime::ensure!(
            self.children.len() < MAX_BOX_COMPONENT_WORKERS,
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
        self.children.len() - usize::from(self.interrupt_controller_configured)
            + self
                .mmio
                .as_ref()
                .map_or(0, |instance| instance.device_plan.len())
    }

    #[must_use]
    pub fn has_component(&self, kind: DeviceKind) -> bool {
        self.mmio
            .as_ref()
            .is_some_and(|instance| instance.has_component(kind))
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
        self.store.data().platform.validate_runtime_start()?;
        self.prepare_devices().await?.finish()
    }

    fn finish(mut self) -> wasmtime::Result<PreparedBoxRuntime> {
        self.store.data().platform.validate_runtime_start()?;
        let failure = if let Some(instance) = self.vmm.take() {
            let crate::component::vmm::VmmInstance {
                lifecycle_loop,
                failure,
                ..
            } = instance;
            if self.store.data().platform.is_machine_running() {
                self.register_loop(lifecycle_loop)?;
            }
            Some(failure)
        } else {
            self.mmio
                .as_ref()
                .map(|instance| Arc::clone(&instance.failure))
        };
        if let Some(mut instance) = self.mmio.take() {
            let mut worker = instance
                .worker
                .take()
                .ok_or_else(|| wasmtime::Error::msg("MMIO worker missing"))?;
            let bridge = instance.bridge;
            let shutdown = self.shutdown.clone();
            worker.register_loop(Box::new(move |accessor| {
                Box::pin(async move {
                    bridge(accessor).await?;
                    shutdown.send_replace(true);
                    Ok(())
                })
            }))?;
            self.attach_worker(worker.prepare(self.shutdown.subscribe()))?;
            if self.component_loops.is_empty() {
                let mut shutdown = self.shutdown.subscribe();
                self.register_loop(Box::new(move |_| {
                    Box::pin(async move {
                        while !*shutdown.borrow_and_update() {
                            shutdown.changed().await?;
                        }
                        Ok(())
                    })
                }))?;
            }
        }
        Ok(PreparedBoxRuntime {
            store: self.store,
            _epoch_clock: self.epoch_clock,
            shutdown: self.shutdown,
            children: self.children,
            component_loops: self.component_loops,
            failure,
        })
    }

    pub async fn prepare_vcpus(
        self,
        start: impl FnOnce(Vec<NativeVcpu>, BootEntry) -> wasmtime::Result<StartedVcpus>
        + Send
        + 'static,
    ) -> wasmtime::Result<(PreparedBoxRuntime, VcpuReaper)> {
        self.store.data().platform.validate_vcpu_start()?;
        let mut runtime = self.prepare_devices().await?;
        runtime.compose_machine().await?;
        let started = runtime
            .store
            .data_mut()
            .platform
            .start_native_vcpus(start)?;
        Ok((runtime.finish()?, started))
    }

    pub(crate) fn grant_device_worker<H: StoreHost>(
        &mut self,
        kind: DeviceKind,
        initialize: impl Future<Output = wasmtime::Result<(DeviceWorker<H>, Serve)>> + Send + 'static,
    ) -> wasmtime::Result<mmio::MmioDevice> {
        self.grant_device_setup(kind, setup(initialize, self.shutdown_receiver()))
    }

    pub(crate) fn grant_device_setup(
        &mut self,
        kind: DeviceKind,
        setup: Setup,
    ) -> wasmtime::Result<mmio::MmioDevice> {
        let device = mmio::MmioDevice::grant_worker(self, kind, setup)?;
        let closing = device.clone();
        if let Err(error) =
            self.add_device_shutdown(vmm::teardown::DeviceShutdown::new(kind, async move {
                closing
                    .close_async()
                    .await
                    .map_err(|error| error.to_string())
            }))
        {
            device.revoke_worker(self)?;
            return Err(error);
        }
        Ok(device)
    }

    pub(crate) fn grant_device_worker_unmanaged<H: StoreHost>(
        &mut self,
        kind: DeviceKind,
        initialize: impl Future<Output = wasmtime::Result<(DeviceWorker<H>, Serve)>> + Send + 'static,
    ) -> wasmtime::Result<mmio::MmioDevice> {
        let setup = setup(initialize, self.shutdown_receiver());
        mmio::MmioDevice::grant_worker(self, kind, setup)
    }

    pub fn grant_interrupt_shutdown(
        &mut self,
        close: impl Future<Output = Result<(), String>> + Send + 'static,
    ) -> wasmtime::Result<()> {
        let teardown = self.store.data().lifecycle.native_teardown();
        teardown.install_interrupts(Box::pin(close))
    }

    pub fn add_device_shutdown(
        &mut self,
        device: vmm::teardown::DeviceShutdown,
    ) -> wasmtime::Result<()> {
        self.store
            .data()
            .lifecycle
            .native_teardown()
            .install_device(device)
    }

    async fn prepare_devices(mut self) -> wasmtime::Result<Self> {
        let Some(instance) = self.mmio.as_mut() else {
            return Ok(self);
        };
        let plans = std::mem::take(&mut instance.device_plan);
        let devices = plans.iter().map(|plan| Arc::clone(&plan.device)).collect();
        for DevicePlan {
            device,
            mapping,
            setup,
        } in plans
        {
            let mapping =
                mapping.ok_or_else(|| wasmtime::Error::msg("worker grant has no mapping"))?;
            let worker = {
                let instance = self
                    .mmio
                    .as_mut()
                    .ok_or_else(|| wasmtime::Error::msg("MMIO router missing"))?;
                let mmio_worker = instance
                    .worker
                    .as_mut()
                    .ok_or_else(|| wasmtime::Error::msg("MMIO worker missing"))?;
                within_setup_timeout(
                    device.slot,
                    prepare_mmio_worker(
                        mmio_worker,
                        &instance.routing,
                        device.slot,
                        mapping,
                        setup,
                    ),
                )
                .await?
            };
            self.attach_worker(worker)?;
        }
        self.mmio
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("MMIO router missing"))?
            .devices
            .set(devices)
            .map_err(|_| wasmtime::Error::msg("device registry already published"))?;
        Ok(self)
    }
}

async fn prepare_mmio_worker(
    mmio_worker: &mut DeviceWorker<mmio::MmioHost>,
    router: &mmio::bindings::router::Guest,
    slot: u32,
    (base, size): (u64, u64),
    setup: Setup,
) -> wasmtime::Result<WorkerTask> {
    wasmtime::ensure!(
        usize::try_from(slot)? < crate::box_runtime::MAX_BOX_COMPONENTS
            && size != 0
            && base.checked_add(size).is_some(),
        "worker grant outside box"
    );
    let (request_reader,) = router
        .func_open_device()
        .call_async(&mut mmio_worker.store, (slot, base, size))
        .await?;
    let request_reader = request_reader.map_err(router_error)?;
    let (sink, request_stream) =
        crate::component::relay::channel(crate::component::relay::MMIO_CAPACITY);
    request_reader.pipe(&mut mmio_worker.store, sink)?;
    let prepared = setup(request_stream).await?;
    let replies = StreamReader::new(&mut mmio_worker.store, prepared.replies)?;
    let (result,) = router
        .func_attach_replies()
        .call_async(&mut mmio_worker.store, (slot, replies))
        .await?;
    result.map_err(router_error)?;
    Ok(prepared.worker)
}

pub(crate) fn setup<H: StoreHost>(
    initialize: impl Future<Output = wasmtime::Result<(DeviceWorker<H>, Serve)>> + Send + 'static,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Setup {
    Box::new(move |requests| {
        Box::pin(async move {
            let (mut worker, serve) = initialize.await?;
            let requests = StreamReader::new(&mut worker.store, requests)?;
            let (reply_reader,) = serve.call_async(&mut worker.store, (requests,)).await?;
            let (sink, replies) = relay::channel(relay::MMIO_CAPACITY);
            reply_reader.pipe(&mut worker.store, sink)?;
            Ok(PreparedWorker {
                worker: worker.prepare(shutdown),
                replies,
            })
        })
    })
}

pub(crate) async fn within_setup_timeout<T>(
    slot: u32,
    operation: impl Future<Output = wasmtime::Result<T>>,
) -> wasmtime::Result<T> {
    tokio::time::timeout(SETUP_TIMEOUT, operation)
        .await
        .map_err(|_| wasmtime::Error::msg(format!("worker {slot} setup timed out")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NotifyDrop(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for NotifyDrop {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test]
    async fn setup_stays_lazy_and_timeout_cancels_preparation() {
        let (dropped, stopped) = tokio::sync::oneshot::channel();
        let (started, mut started_receiver) = tokio::sync::oneshot::channel();
        let setup = setup(
            async move {
                started.send(()).unwrap();
                let _guard = NotifyDrop(Some(dropped));
                std::future::pending::<
                    wasmtime::Result<(
                        DeviceWorker<crate::component::context::DeviceContext>,
                        Serve,
                    )>,
                >()
                .await
            },
            tokio::sync::watch::channel(false).1,
        );
        assert_eq!(
            started_receiver.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        );
        let Err(error) = within_setup_timeout(3, async {
            let (_sink, requests) = relay::channel(relay::MMIO_CAPACITY);
            setup(requests).await
        })
        .await
        else {
            panic!("worker preparation completed");
        };
        assert_eq!(error.to_string(), "worker 3 setup timed out");
        started_receiver.await.unwrap();
        stopped.await.unwrap();
    }
}
