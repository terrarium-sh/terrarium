//! Native MMIO requests, device handles, and the Wasm routing bridge.

pub(super) mod bridge;
mod device;

use crate::machine::DeviceKind;
pub use device::MmioDevice;

use crate::box_runtime::BoxRuntime;
use crate::box_runtime::store::BoxHost;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use wasmtime::component::{StreamReader, TypedFunc};

use super::bindings::types::{ControlReply, Error, RoutedReply};
pub use super::bindings::types::{DeviceError, Operation, Reply, Request};
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
pub(super) struct Pending {
    command: Command,
    reply: ReplyOwner,
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
    counts: DeviceRequestCounts,
}

pub(crate) struct DevicePlan {
    pub(crate) device: Arc<DeviceRegistration>,
    pub(crate) mapping: Option<(u64, u64)>,
    pub(crate) setup: crate::box_runtime::setup::Setup,
}

pub(crate) type DeviceRegistry = Arc<OnceLock<Box<[Arc<DeviceRegistration>]>>>;

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

pub(crate) fn router_error(error: Error) -> wasmtime::Error {
    wasmtime::Error::msg(format!("MMIO router: {error:?}"))
}

impl BoxRuntime {
    pub async fn configure_mmio_vcpus(&mut self, count: u32) -> wasmtime::Result<()> {
        let router = &self
            .vmm
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("MMIO router missing"))?
            .routing;
        let (result,) = router
            .func_configure_vcpus()
            .call_async(&mut self.store, (u8::try_from(count)?,))
            .await?;
        result.map_err(router_error)
    }
}

pub(super) fn completion_callback(devices: DeviceRegistry) -> super::Completed {
    Arc::new(move |slot, failed| {
        let devices = devices
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
    })
}
