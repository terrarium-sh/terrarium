//! Native setup and request handling for the Wasm MMIO router.

mod bridge;
mod device;

use bridge::{BridgeContext, run_bridge};
pub use device::MmioDevice;

use crate::box_runtime::BoxRuntime;
use crate::box_runtime::store::BoxHost;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use wasmtime::component::{Component, StreamReader, TypedFunc};

#[derive(Clone)]
pub struct FailureObservation {
    failure: Arc<Mutex<Option<String>>>,
}

impl FailureObservation {
    #[must_use]
    pub fn failure(&self) -> Option<String> {
        recorded_failure(&self.failure)
    }
}

use super::bindings::types::{ControlReply, Error, RoutedReply};
pub use super::bindings::types::{DeviceError, Operation, Reply, Request};
use super::bindings::{Vmm, exports, lifecycle_platform};
pub type Serve = TypedFunc<(StreamReader<Request>,), (StreamReader<Reply>,)>;
type Access = TypedFunc<(u64, u8, u64, bool), (Result<RoutedReply, Error>,)>;
type Control = TypedFunc<(u32, Operation), (Result<ControlReply, Error>,)>;
type RunLifecycle = TypedFunc<(), (Result<lifecycle_platform::Event, lifecycle_platform::Error>,)>;
const DEVICE_SPAN: u64 = 0x1000;
const COMMAND_CAPACITY: usize = 64;
const CONTROL_CAPACITY: usize = 64;
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
const RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

enum Command {
    Access(u64, u8, u64, bool),
    Control(u32, Operation),
}
struct Pending {
    command: Command,
    reply: ReplyOwner,
}

#[derive(Default)]
struct DeviceRequestCounts {
    completed: AtomicU64,
    failed: AtomicU64,
}

struct DeviceRegistration {
    kind: crate::component::vmm::bindings::machine::DeviceKind,
    slot: u32,
    base: AtomicU64,
    counts: DeviceRequestCounts,
}

struct DevicePlan {
    device: Arc<DeviceRegistration>,
    mapping: Option<(u64, u64)>,
    setup: crate::box_runtime::setup::Setup,
}

type DeviceRegistry = Arc<OnceLock<Box<[Arc<DeviceRegistration>]>>>;

fn submit(
    sender: &tokio::sync::mpsc::Sender<Pending>,
    admission: &Arc<Mutex<Option<String>>>,
    failure: &Mutex<Option<String>>,
    command: Command,
    control: device::ControlGuard,
) -> wasmtime::Result<RoutedReply> {
    if let Some(failure) = recorded_failure(failure) {
        return Err(wasmtime::Error::msg(failure));
    }
    let (reply, response) = mpsc::sync_channel(1);
    enqueue_reply(
        sender,
        admission,
        command,
        ReplySender::Sync(reply),
        Some(control),
    )?;
    wait_for_reply(failure, &response)
}

fn recorded_failure(failure: &Mutex<Option<String>>) -> Option<String> {
    failure
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn wait_for_reply(
    failure: &Mutex<Option<String>>,
    response: &mpsc::Receiver<wasmtime::Result<RoutedReply>>,
) -> wasmtime::Result<RoutedReply> {
    response
        .recv_timeout(RESPONSE_TIMEOUT)
        .map_err(|error| wasmtime::Error::msg(format!("MMIO response: {error}")))?
        .map_err(|error| recorded_failure(failure).map_or(error, wasmtime::Error::msg))
}

fn enqueue(
    sender: &tokio::sync::mpsc::Sender<Pending>,
    admission: &Arc<Mutex<Option<String>>>,
    command: Command,
) -> wasmtime::Result<mpsc::Receiver<wasmtime::Result<RoutedReply>>> {
    let (reply, response) = mpsc::sync_channel(1);
    enqueue_reply(sender, admission, command, ReplySender::Sync(reply), None)?;
    Ok(response)
}

enum ReplySender {
    Sync(mpsc::SyncSender<wasmtime::Result<RoutedReply>>),
    Async(tokio::sync::oneshot::Sender<wasmtime::Result<RoutedReply>>),
}

struct ReplyOwner {
    sender: Option<ReplySender>,
    control: Option<device::ControlGuard>,
    admission: Arc<Mutex<Option<String>>>,
}

impl ReplyOwner {
    fn send(mut self, result: wasmtime::Result<RoutedReply>) {
        self.complete(result);
    }

    fn complete(&mut self, result: wasmtime::Result<RoutedReply>) {
        if let Some(control) = self.control.take() {
            control.complete(result.is_ok());
        }
        match self.sender.take() {
            Some(ReplySender::Sync(sender)) => {
                let _ = sender.send(result);
            }
            Some(ReplySender::Async(sender)) => {
                let _ = sender.send(result);
            }
            None => {}
        }
    }
}

impl Drop for ReplyOwner {
    fn drop(&mut self) {
        if self.sender.is_some() {
            let reason = recorded_failure(&self.admission)
                .unwrap_or_else(|| "MMIO bridge stopped".to_owned());
            self.complete(Err(wasmtime::Error::msg(reason)));
        }
    }
}

fn enqueue_reply(
    sender: &tokio::sync::mpsc::Sender<Pending>,
    admission: &Arc<Mutex<Option<String>>>,
    command: Command,
    reply: ReplySender,
    control: Option<device::ControlGuard>,
) -> wasmtime::Result<()> {
    let pending = Pending {
        command,
        reply: ReplyOwner {
            sender: Some(reply),
            control,
            admission: Arc::clone(admission),
        },
    };
    let stopped = admission
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if stopped.is_some() {
        drop(stopped);
        return Err(wasmtime::Error::msg("MMIO bridge stopping"));
    }
    let result = sender.try_send(pending);
    drop(stopped);
    result.map_err(|error| wasmtime::Error::msg(format!("MMIO bridge unavailable: {error}")))
}

async fn submit_async(
    sender: &tokio::sync::mpsc::Sender<Pending>,
    admission: &Arc<Mutex<Option<String>>>,
    failure: &Mutex<Option<String>>,
    command: Command,
    control: device::ControlGuard,
) -> wasmtime::Result<RoutedReply> {
    if let Some(failure) = recorded_failure(failure) {
        return Err(wasmtime::Error::msg(failure));
    }
    let (reply, response) = tokio::sync::oneshot::channel();
    enqueue_reply(
        sender,
        admission,
        command,
        ReplySender::Async(reply),
        Some(control),
    )?;
    tokio::time::timeout(RESPONSE_TIMEOUT, response)
        .await
        .map_err(|error| wasmtime::Error::msg(format!("MMIO response: {error}")))?
        .map_err(|error| wasmtime::Error::msg(format!("MMIO response: {error}")))?
        .map_err(|error| recorded_failure(failure).map_or(error, wasmtime::Error::msg))
}

pub(crate) struct Router {
    pub(crate) bridge: crate::box_runtime::ComponentLoop,
    pub(crate) entrypoint: crate::box_runtime::ComponentLoop,
    pub(crate) machine: exports::terra::mmio::machine::Guest,
    pub(crate) interrupts: exports::terra::mmio::interrupts::Guest,
    routing: exports::terra::mmio::router::Guest,
    sender: tokio::sync::mpsc::Sender<Pending>,
    control_sender: tokio::sync::mpsc::Sender<Pending>,
    admission: Arc<Mutex<Option<String>>>,
    devices: DeviceRegistry,
    device_plan: Vec<DevicePlan>,
    pub(crate) failure: Arc<Mutex<Option<String>>>,
}

impl Router {
    #[must_use]
    pub fn failure_observation(&self) -> FailureObservation {
        FailureObservation {
            failure: Arc::clone(&self.failure),
        }
    }
    #[cfg(test)]
    pub(crate) fn failure_sink(&self) -> Arc<Mutex<Option<String>>> {
        Arc::clone(&self.failure)
    }
    pub(crate) fn unprepared_count(&self) -> usize {
        self.device_plan.len()
    }
    pub(crate) fn has_component(
        &self,
        kind: crate::component::vmm::bindings::machine::DeviceKind,
    ) -> bool {
        self.device_plan.iter().any(|plan| plan.device.kind == kind)
    }
    pub(crate) fn record_failure_in(failure: &Mutex<Option<String>>, error: &wasmtime::Error) {
        let mut failure = failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if failure.is_none() {
            *failure = Some(format!("{error:#}"));
        }
    }
}

fn router_error(error: Error) -> wasmtime::Error {
    wasmtime::Error::msg(format!("MMIO router: {error:?}"))
}

fn lifecycle_loop(
    function: RunLifecycle,
    lifecycle: crate::component::vmm::lifecycle::LifecycleNotifier,
) -> crate::box_runtime::ComponentLoop {
    Box::new(move |accessor| {
        Box::pin(async move {
            let (result,) = function.call_concurrent(accessor, ()).await?;
            let outcome = match result {
                Ok(lifecycle_platform::Event::GuestExit(code)) => {
                    crate::component::vmm::lifecycle::Outcome::GuestExit(code)
                }
                Ok(lifecycle_platform::Event::ComponentFailed) => {
                    crate::component::vmm::lifecycle::Outcome::ComponentFailed
                }
                Ok(lifecycle_platform::Event::VcpuFinished) => {
                    crate::component::vmm::lifecycle::Outcome::VcpuFinished
                }
                Ok(lifecycle_platform::Event::Deadline) => {
                    crate::component::vmm::lifecycle::Outcome::Deadline
                }
                Err(error) => {
                    return Err(wasmtime::Error::msg(format!("Wasm lifecycle: {error:?}")));
                }
            };
            lifecycle.publish_outcome(outcome);
            Ok(())
        })
    })
}

impl BoxRuntime {
    pub async fn configure_mmio_vcpus(&mut self, count: u32) -> wasmtime::Result<()> {
        let router = &self
            .mmio
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("MMIO router missing"))?
            .routing;
        let (result,) = router
            .func_configure_vcpus()
            .call_async(&mut self.store, (u8::try_from(count)?,))
            .await?;
        result.map_err(router_error)
    }

    #[allow(clippy::too_many_lines)]
    pub async fn initialize_mmio(&mut self, component: &Component) -> wasmtime::Result<()> {
        if self.mmio.is_some() {
            return Err(wasmtime::Error::msg("MMIO router already initialized"));
        }
        let linker = mmio_component_linker(self.store.engine())?;
        let instance = Vmm::instantiate_async(&mut self.store, component, &linker).await?;
        let router = instance.terra_mmio_router();
        let machine = instance.terra_mmio_machine();
        let interrupts = instance.terra_mmio_interrupts();
        let lifecycle = instance.terra_mmio_lifecycle().clone();
        let (sender, receiver) = tokio::sync::mpsc::channel(COMMAND_CAPACITY);
        let (control_sender, control_receiver) = tokio::sync::mpsc::channel(CONTROL_CAPACITY);
        let admission = Arc::new(Mutex::new(None));
        let failure = Arc::new(Mutex::new(None));
        let devices: DeviceRegistry = Arc::new(OnceLock::new());
        let loop_devices = Arc::clone(&devices);
        let loop_admission = Arc::clone(&admission);
        let bridge_senders = (sender.clone(), control_sender.clone());
        let bridge_router = router.clone();
        let bridge: crate::box_runtime::ComponentLoop = Box::new(move |accessor| {
            Box::pin(async move {
                let _senders = bridge_senders;
                run_bridge(
                    accessor,
                    receiver,
                    control_receiver,
                    BridgeContext {
                        access: bridge_router.func_access(),
                        control: bridge_router.func_control(),
                        devices: loop_devices,
                        admission: loop_admission,
                    },
                )
                .await
            })
        });
        let entrypoint = lifecycle_loop(lifecycle.func_run(), self.lifecycle_notifier());
        let vcpu_devices = Arc::clone(&devices);
        crate::component::vmm::configure_callbacks(
            &mut self.store.data_mut().platform,
            Arc::new(move |slot, failed| {
                let devices = vcpu_devices
                    .get()
                    .ok_or_else(|| wasmtime::Error::msg("device plan is not started"))?;
                let device = devices
                    .get(usize::try_from(slot)?)
                    .ok_or_else(|| wasmtime::Error::msg("vCPU device callback outside box"))?;
                if failed {
                    device.counts.failed.fetch_add(1, Ordering::Relaxed);
                } else {
                    device.counts.completed.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            }),
        );
        self.mmio = Some(Router {
            bridge,
            entrypoint,
            machine: machine.clone(),
            interrupts: interrupts.clone(),
            routing: router.clone(),
            sender,
            control_sender,
            admission,
            devices,
            device_plan: Vec::new(),
            failure,
        });
        Ok(())
    }

    pub async fn initialize_mmio_artifact(
        &mut self,
        artifacts: &crate::TrustedArtifacts,
    ) -> wasmtime::Result<()> {
        let component = artifacts.mmio().deserialize(self.store.engine())?;
        self.initialize_mmio(&component).await
    }
}

pub fn mmio_component_linker(
    engine: &wasmtime::Engine,
) -> wasmtime::Result<wasmtime::component::Linker<BoxHost>> {
    let mut linker = crate::component::context::device_component_linker(engine)?;
    crate::component::vmm::add_to_linker(&mut linker)?;
    Ok(linker)
}

#[cfg(test)]
pub(crate) async fn initialize_test_router(root: &mut BoxRuntime) -> wasmtime::Result<()> {
    let component = Component::new(root.store.engine(), crate::test_fixtures::wasm::VMM)?;
    root.initialize_mmio(&component).await
}

impl BoxRuntime {
    pub(crate) async fn prepare_devices(mut self) -> wasmtime::Result<Self> {
        let Some(router) = self.mmio.as_mut() else {
            return Ok(self);
        };
        let plans = std::mem::take(&mut router.device_plan);
        let devices = plans.iter().map(|plan| Arc::clone(&plan.device)).collect();
        for DevicePlan {
            device,
            mapping,
            setup,
        } in plans
        {
            let mapping =
                mapping.ok_or_else(|| wasmtime::Error::msg("worker grant has no mapping"))?;
            let worker = crate::box_runtime::setup::within_setup_timeout(
                device.slot,
                self.prepare_worker(device.slot, mapping, setup),
            )
            .await?;
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

    async fn prepare_worker(
        &mut self,
        slot: u32,
        (base, size): (u64, u64),
        setup: crate::box_runtime::setup::Setup,
    ) -> wasmtime::Result<crate::box_runtime::WorkerTask> {
        wasmtime::ensure!(
            usize::try_from(slot)? < crate::box_runtime::MAX_BOX_COMPONENTS
                && size != 0
                && base.checked_add(size).is_some(),
            "worker grant outside box"
        );
        let router = &self
            .mmio
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("MMIO router missing"))?
            .routing;
        let (request_reader,) = router
            .func_open_device()
            .call_async(&mut self.store, (slot, base, size))
            .await?;
        let request_reader = request_reader.map_err(router_error)?;
        let (sink, request_stream) =
            crate::component::relay::channel(crate::component::relay::MMIO_CAPACITY);
        request_reader.pipe(&mut self.store, sink)?;
        let worker = setup(request_stream).await?;
        let replies = StreamReader::new(&mut self.store, worker.replies)?;
        let router = &self
            .mmio
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("MMIO router missing"))?
            .routing;
        let (result,) = router
            .func_attach_replies()
            .call_async(&mut self.store, (slot, replies))
            .await?;
        result.map_err(router_error)?;
        Ok(worker.worker)
    }
}
