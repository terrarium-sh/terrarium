//! Native MMIO requests, device handles, and the Wasm routing bridge.

pub(crate) mod bindings;
pub(super) mod bridge;
mod device;

use crate::machine::DeviceKind;
pub use device::MmioDevice;

use crate::box_runtime::store::{StoreHost, StoreState};
use crate::box_runtime::{BoxRuntime, DeviceWorker};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use wasmtime::component::{Component, ResourceTable, StreamReader, TypedFunc};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use bindings::types::{ControlReply, Error, RoutedReply};
pub use bindings::types::{DeviceError, Operation, Reply, Request};
pub type Serve = TypedFunc<(StreamReader<Request>,), (StreamReader<Reply>,)>;
type Access = TypedFunc<(u64, u8, u64, bool), (Result<RoutedReply, Error>,)>;
type Control = TypedFunc<(u32, Operation), (Result<ControlReply, Error>,)>;
const DEVICE_SPAN: u64 = 0x1000;
pub(super) const COMMAND_CAPACITY: usize = 64;
pub(super) const CONTROL_CAPACITY: usize = 64;
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
const RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

enum Command {
    Access(u64, u8, u64, bool),
    Control(u32, Operation),
}

impl Command {
    const fn is_control(&self) -> bool {
        matches!(self, Self::Control(..))
    }
}

#[derive(Clone)]
pub(crate) struct Queue {
    sender: tokio::sync::mpsc::Sender<Pending>,
    data_permits: Arc<tokio::sync::Semaphore>,
    control_permits: Arc<tokio::sync::Semaphore>,
}

impl Queue {
    fn new() -> (Self, tokio::sync::mpsc::Receiver<Pending>) {
        let (sender, receiver) = tokio::sync::mpsc::channel(COMMAND_CAPACITY + CONTROL_CAPACITY);
        (
            Self {
                sender,
                data_permits: Arc::new(tokio::sync::Semaphore::new(COMMAND_CAPACITY)),
                control_permits: Arc::new(tokio::sync::Semaphore::new(CONTROL_CAPACITY)),
            },
            receiver,
        )
    }

    fn try_send(
        &self,
        pending: Pending,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<Pending>> {
        self.sender.try_send(pending)
    }

    fn try_acquire(
        &self,
        command: &Command,
    ) -> wasmtime::Result<tokio::sync::OwnedSemaphorePermit> {
        let permits = if command.is_control() {
            &self.control_permits
        } else {
            &self.data_permits
        };
        permits
            .clone()
            .try_acquire_owned()
            .map_err(|error| wasmtime::Error::msg(format!("MMIO bridge unavailable: {error}")))
    }
}

#[derive(Debug)]
pub(crate) enum QueueError {
    Router(Error),
    Failure(wasmtime::Error),
}

impl QueueError {
    pub(crate) fn into_error(self) -> wasmtime::Error {
        match self {
            Self::Router(error) => router_error(error),
            Self::Failure(error) => error,
        }
    }
}

impl std::fmt::Display for QueueError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Router(error) => write!(formatter, "MMIO router: {error:?}"),
            Self::Failure(error) => error.fmt(formatter),
        }
    }
}

pub(crate) struct Pending {
    command: Command,
    reply: ReplyOwner,
    queue_permit: tokio::sync::OwnedSemaphorePermit,
}

#[derive(Default)]
struct DeviceRequestCounts {
    completed: AtomicU64,
    failed: AtomicU64,
}

pub(crate) struct DeviceRegistration {
    pub(super) kind: DeviceKind,
    pub(crate) slot: u32,
    base: AtomicU64,
    size: AtomicU64,
    closing: AtomicBool,
    closed: AtomicBool,
    counts: DeviceRequestCounts,
}

fn owns_access(device: &DeviceRegistration, address: u64, width: u8) -> bool {
    let base = device.base.load(Ordering::Acquire);
    let Some(end) = base.checked_add(device.size.load(Ordering::Acquire)) else {
        return false;
    };
    address >= base
        && address
            .checked_add(u64::from(width))
            .is_some_and(|access_end| access_end <= end)
}

pub(crate) struct DevicePlan {
    pub(crate) device: Arc<DeviceRegistration>,
    pub(crate) mapping: Option<(u64, u64)>,
    pub(crate) setup: crate::box_runtime::setup::Setup,
}

pub(crate) type DeviceRegistry = Arc<OnceLock<Box<[Arc<DeviceRegistration>]>>>;

pub(crate) struct MmioHost {
    ctx: WasiCtx,
    table: ResourceTable,
}

impl MmioHost {
    fn new() -> Self {
        Self {
            ctx: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
        }
    }
}

impl WasiView for MmioHost {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

impl StoreHost for MmioHost {}

pub(crate) struct MmioInstance {
    pub(crate) worker: Option<DeviceWorker<MmioHost>>,
    pub(crate) bridge: crate::box_runtime::ComponentLoop<StoreState<MmioHost>>,
    pub(crate) routing: bindings::router::Guest,
    pub(crate) sender: Queue,
    pub(crate) admission: Arc<Mutex<Option<String>>>,
    pub(crate) devices: DeviceRegistry,
    pub(crate) device_plan: Vec<DevicePlan>,
    pub(crate) failure: Arc<Mutex<Option<String>>>,
}

impl MmioInstance {
    pub(crate) fn client(&self) -> Client {
        Client {
            sender: self.sender.clone(),
            admission: Arc::clone(&self.admission),
            failure: Arc::clone(&self.failure),
        }
    }
    pub(crate) fn has_component(&self, kind: DeviceKind) -> bool {
        self.device_plan.iter().any(|plan| plan.device.kind == kind)
    }
}

#[derive(Clone)]
pub(crate) struct Client {
    sender: Queue,
    admission: Arc<Mutex<Option<String>>>,
    failure: Arc<Mutex<Option<String>>>,
}

impl Client {
    async fn access(
        &self,
        address: u64,
        width: u8,
        value: u64,
        write: bool,
    ) -> Result<u64, QueueError> {
        submit_async(
            &self.sender,
            &self.admission,
            &self.failure,
            Command::Access(address, width, value, write),
            None,
        )
        .await
        .map(|reply| reply.reply.value)
    }
}

struct VmmMmioClient;

impl wasmtime::component::HasData for VmmMmioClient {
    type Data<'a> = &'a mut Option<Client>;
}

impl crate::component::vmm::bindings::vmm_mmio_client::Host for Option<Client> {}

impl<T: Send + 'static> crate::component::vmm::bindings::vmm_mmio_client::HostWithStore<T>
    for VmmMmioClient
{
    async fn access(
        accessor: &wasmtime::component::Accessor<T, Self>,
        address: u64,
        width: u8,
        value: u64,
        write: bool,
    ) -> wasmtime::Result<Result<u64, Error>> {
        match accessor
            .with(|mut store| store.get().clone())
            .ok_or_else(|| wasmtime::Error::msg("VMM MMIO client is not initialized"))?
            .access(address, width, value, write)
            .await
        {
            Ok(value) => Ok(Ok(value)),
            Err(QueueError::Router(error)) => Ok(Err(error)),
            Err(QueueError::Failure(error)) => Err(error),
        }
    }
}

pub(crate) fn add_vmm_client_to_linker(
    linker: &mut wasmtime::component::Linker<crate::box_runtime::store::BoxHost>,
) -> wasmtime::Result<()> {
    crate::component::vmm::bindings::vmm_mmio_client::add_to_linker::<
        crate::box_runtime::store::BoxHost,
        VmmMmioClient,
    >(linker, |host| &mut host.mmio_client)
}

impl BoxRuntime {
    pub async fn initialize_mmio(&mut self, component: &Component) -> wasmtime::Result<()> {
        wasmtime::ensure!(self.mmio.is_none(), "MMIO already initialized");
        let mut worker = self.new_child(MmioHost::new());
        let linker = wasmtime::component::Linker::new(worker.store.engine());
        let instance = crate::box_runtime::setup::within_setup_timeout(
            0,
            bindings::Mmio::instantiate_async(&mut worker.store, component, &linker),
        )
        .await?;
        let routing = instance.terra_mmio_router();
        let (sender, receiver) = Queue::new();
        let admission = Arc::new(Mutex::new(None));
        let devices: DeviceRegistry = Arc::new(OnceLock::new());
        let bridge = bridge::create_component_loop(
            bridge::BridgeContext {
                access: routing.func_access(),
                control: routing.func_control(),
                devices: Arc::clone(&devices),
                admission: Arc::clone(&admission),
            },
            sender.clone(),
            receiver,
        );
        self.mmio = Some(MmioInstance {
            worker: Some(worker),
            bridge,
            routing: routing.clone(),
            sender,
            admission,
            devices,
            device_plan: Vec::new(),
            failure: Arc::new(Mutex::new(None)),
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

#[cfg(test)]
pub(crate) async fn initialize_test_mmio(root: &mut BoxRuntime) -> wasmtime::Result<()> {
    let component = Component::new(root.store.engine(), crate::test_fixtures::wasm::MMIO)?;
    root.initialize_mmio(&component).await
}

fn submit(
    sender: &Queue,
    admission: &Arc<Mutex<Option<String>>>,
    failure: &Mutex<Option<String>>,
    command: Command,
    control: Option<device::ControlGuard>,
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
        control,
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
    response: &mpsc::Receiver<Result<RoutedReply, QueueError>>,
) -> wasmtime::Result<RoutedReply> {
    response
        .recv_timeout(RESPONSE_TIMEOUT)
        .map_err(|error| wasmtime::Error::msg(format!("MMIO response: {error}")))?
        .map_err(QueueError::into_error)
        .map_err(|error| recorded_failure(failure).map_or(error, wasmtime::Error::msg))
}

fn enqueue(
    sender: &Queue,
    admission: &Arc<Mutex<Option<String>>>,
    command: Command,
) -> wasmtime::Result<mpsc::Receiver<Result<RoutedReply, QueueError>>> {
    let (reply, response) = mpsc::sync_channel(1);
    enqueue_reply(sender, admission, command, ReplySender::Sync(reply), None)?;
    Ok(response)
}

enum ReplySender {
    Sync(mpsc::SyncSender<Result<RoutedReply, QueueError>>),
    Async(tokio::sync::oneshot::Sender<Result<RoutedReply, QueueError>>),
}

struct ReplyOwner {
    sender: Option<ReplySender>,
    control: Option<device::ControlGuard>,
    admission: Arc<Mutex<Option<String>>>,
}

impl ReplyOwner {
    fn send(mut self, result: Result<RoutedReply, QueueError>) {
        self.complete(result);
    }

    fn complete(&mut self, result: Result<RoutedReply, QueueError>) {
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
            self.complete(Err(QueueError::Failure(wasmtime::Error::msg(reason))));
        }
    }
}

fn enqueue_reply(
    sender: &Queue,
    admission: &Arc<Mutex<Option<String>>>,
    command: Command,
    reply: ReplySender,
    control: Option<device::ControlGuard>,
) -> wasmtime::Result<()> {
    let queue_permit = sender.try_acquire(&command)?;
    let pending = Pending {
        command,
        reply: ReplyOwner {
            sender: Some(reply),
            control,
            admission: Arc::clone(admission),
        },
        queue_permit,
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
    sender: &Queue,
    admission: &Arc<Mutex<Option<String>>>,
    failure: &Mutex<Option<String>>,
    command: Command,
    control: Option<device::ControlGuard>,
) -> Result<RoutedReply, QueueError> {
    if let Some(failure) = recorded_failure(failure) {
        return Err(QueueError::Failure(wasmtime::Error::msg(failure)));
    }
    let (reply, response) = tokio::sync::oneshot::channel();
    enqueue_reply(
        sender,
        admission,
        command,
        ReplySender::Async(reply),
        control,
    )
    .map_err(QueueError::Failure)?;
    tokio::time::timeout(RESPONSE_TIMEOUT, response)
        .await
        .map_err(|error| {
            QueueError::Failure(wasmtime::Error::msg(format!("MMIO response: {error}")))
        })?
        .map_err(|error| {
            QueueError::Failure(wasmtime::Error::msg(format!("MMIO response: {error}")))
        })?
        .map_err(|error| match recorded_failure(failure) {
            Some(failure) => QueueError::Failure(wasmtime::Error::msg(failure)),
            None => error,
        })
}

pub(crate) fn router_error(error: Error) -> wasmtime::Error {
    wasmtime::Error::msg(format!("MMIO router: {error:?}"))
}
