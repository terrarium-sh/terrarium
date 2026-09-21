//! Native device handles for host-issued MMIO and lifecycle requests.

use super::{
    Arc, AtomicU64, BoxRuntime, Command, DEVICE_SPAN, DevicePlan, DeviceRegistration,
    DeviceRequestCounts, Mutex, Operation, Ordering, Pending, Reply, enqueue, recorded_failure,
    submit, submit_async, wait_for_reply,
};
use crate::machine::{Architecture, DeviceKind};

#[derive(Copy, Clone, Eq, PartialEq)]
enum DeviceState {
    Open,
    Resetting,
    Closing,
    Closed,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum ControlOperation {
    Reset,
    Close,
}

impl From<ControlOperation> for Operation {
    fn from(operation: ControlOperation) -> Self {
        match operation {
            ControlOperation::Reset => Self::Reset,
            ControlOperation::Close => Self::Close,
        }
    }
}

#[derive(Clone)]
pub struct MmioDevice {
    device: Arc<DeviceRegistration>,
    sender: tokio::sync::mpsc::Sender<Pending>,
    control_sender: tokio::sync::mpsc::Sender<Pending>,
    state: Arc<Mutex<DeviceState>>,
    admission: Arc<Mutex<Option<String>>>,
    failure: Arc<Mutex<Option<String>>>,
}

impl MmioDevice {
    pub(crate) fn grant_worker(
        root: &mut BoxRuntime,
        kind: DeviceKind,
        setup: crate::box_runtime::setup::Setup,
    ) -> wasmtime::Result<Self> {
        root.vmm
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("MMIO router missing"))?;
        wasmtime::ensure!(
            root.component_count() < crate::box_runtime::MAX_BOX_COMPONENTS,
            "box has too many components"
        );
        let config = root.store.data().platform.machine_config().cloned();
        let instance = root
            .vmm
            .as_mut()
            .ok_or_else(|| wasmtime::Error::msg("MMIO router missing"))?;
        let slot = u32::try_from(instance.device_plan.len())?;
        let mapping = if let Some(config) = config {
            let ordinal = instance
                .device_plan
                .iter()
                .filter(|plan| plan.device.kind == kind)
                .count();
            config
                .devices()
                .iter()
                .filter(|device| device.kind == kind)
                .nth(ordinal)
                .map(|device| {
                    (
                        device.mmio_base,
                        match config.architecture() {
                            Architecture::X86 => DEVICE_SPAN,
                            Architecture::Arm => 0x200,
                        },
                    )
                })
        } else {
            Some((u64::from(slot) * DEVICE_SPAN, DEVICE_SPAN))
        };
        let device = Arc::new(DeviceRegistration {
            kind,
            slot,
            base: AtomicU64::new(mapping.map_or(u64::from(slot) * DEVICE_SPAN, |(base, _)| base)),
            counts: DeviceRequestCounts::default(),
        });
        let channel = Self {
            device: Arc::clone(&device),
            sender: instance.sender.clone(),
            control_sender: instance.control_sender.clone(),
            state: Arc::new(Mutex::new(DeviceState::Open)),
            admission: Arc::clone(&instance.admission),
            failure: Arc::clone(&instance.failure),
        };
        instance.device_plan.push(DevicePlan {
            device,
            mapping,
            setup,
        });
        Ok(channel)
    }

    pub(crate) fn revoke_worker(&self, root: &mut BoxRuntime) -> wasmtime::Result<()> {
        let instance = root
            .vmm
            .as_mut()
            .ok_or_else(|| wasmtime::Error::msg("MMIO router missing"))?;
        wasmtime::ensure!(
            instance
                .device_plan
                .last()
                .is_some_and(|plan| Arc::ptr_eq(&plan.device, &self.device)),
            "device is not the latest box grant"
        );
        instance.device_plan.pop();
        Ok(())
    }

    pub fn map_mmio(&self, runtime: &mut BoxRuntime, base: u64, size: u64) -> wasmtime::Result<()> {
        wasmtime::ensure!(
            size != 0 && base.checked_add(size).is_some(),
            "invalid MMIO mapping"
        );
        let instance = runtime
            .vmm
            .as_mut()
            .ok_or_else(|| wasmtime::Error::msg("MMIO router missing"))?;
        let plan = instance
            .device_plan
            .get_mut(usize::try_from(self.device.slot)?)
            .filter(|plan| Arc::ptr_eq(&plan.device, &self.device))
            .ok_or_else(|| wasmtime::Error::msg("device belongs to another box"))?;
        plan.mapping = Some((base, size));
        self.device.base.store(base, Ordering::Release);
        Ok(())
    }

    pub fn read(&self, offset: u64, len: usize) -> wasmtime::Result<Vec<u8>> {
        validate_width(len)?;
        let width = u8::try_from(len)?;
        let address = self
            .device
            .base
            .load(Ordering::Acquire)
            .checked_add(offset)
            .ok_or_else(|| wasmtime::Error::msg("MMIO address overflow"))?;
        let reply = self.request(Command::Access(address, width, 0, false))?;
        let bytes = reply.value.to_le_bytes();
        Ok(bytes
            .get(..len)
            .ok_or_else(|| wasmtime::Error::msg("MMIO reply width invalid"))?
            .to_vec())
    }

    pub fn write(&self, offset: u64, bytes: &[u8]) -> wasmtime::Result<()> {
        validate_width(bytes.len())?;
        let mut value = [0; 8];
        value
            .get_mut(..bytes.len())
            .ok_or_else(|| wasmtime::Error::msg("MMIO width too large"))?
            .copy_from_slice(bytes);
        let address = self
            .device
            .base
            .load(Ordering::Acquire)
            .checked_add(offset)
            .ok_or_else(|| wasmtime::Error::msg("MMIO address overflow"))?;
        self.request(Command::Access(
            address,
            u8::try_from(bytes.len())?,
            u64::from_le_bytes(value),
            true,
        ))
        .map(|_| ())
    }

    pub fn reset(&self) -> wasmtime::Result<()> {
        self.control(ControlOperation::Reset)
    }

    fn begin_control(&self, operation: ControlOperation) -> wasmtime::Result<Option<ControlGuard>> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *state {
            DeviceState::Open => {
                *state = match operation {
                    ControlOperation::Reset => DeviceState::Resetting,
                    ControlOperation::Close => DeviceState::Closing,
                }
            }
            DeviceState::Closed if operation == ControlOperation::Close => return Ok(None),
            DeviceState::Closed | DeviceState::Resetting | DeviceState::Closing => {
                return Err(wasmtime::Error::msg("MMIO device unavailable"));
            }
        }
        Ok(Some(ControlGuard {
            state: Arc::clone(&self.state),
            succeeded: false,
        }))
    }

    pub fn close(&self) -> wasmtime::Result<()> {
        self.control(ControlOperation::Close)
    }

    pub async fn close_async(&self) -> wasmtime::Result<()> {
        let Some(control) = self.begin_control(ControlOperation::Close)? else {
            return Ok(());
        };
        submit_async(
            &self.control_sender,
            &self.admission,
            &self.failure,
            Command::Control(self.device.slot, ControlOperation::Close.into()),
            control,
        )
        .await
        .map(|_| ())
    }
    #[must_use]
    pub fn request_counts(&self) -> (u64, u64) {
        (
            self.device.counts.completed.load(Ordering::Relaxed),
            self.device.counts.failed.load(Ordering::Relaxed),
        )
    }
    #[must_use]
    pub fn failure(&self) -> Option<String> {
        self.failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn request(&self, command: Command) -> wasmtime::Result<Reply> {
        if let Some(failure) = recorded_failure(&self.failure) {
            return Err(wasmtime::Error::msg(failure));
        }
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *state != DeviceState::Open {
            return Err(wasmtime::Error::msg("MMIO device unavailable"));
        }
        let response = enqueue(&self.sender, &self.admission, command)?;
        drop(state);
        Ok(wait_for_reply(&self.failure, &response)?.reply)
    }

    fn control(&self, operation: ControlOperation) -> wasmtime::Result<()> {
        let Some(control) = self.begin_control(operation)? else {
            return Ok(());
        };
        submit(
            &self.control_sender,
            &self.admission,
            &self.failure,
            Command::Control(self.device.slot, operation.into()),
            control,
        )
        .map(|_| ())
    }
}

pub(super) struct ControlGuard {
    state: Arc<Mutex<DeviceState>>,
    succeeded: bool,
}

impl ControlGuard {
    pub(super) fn complete(mut self, succeeded: bool) {
        self.succeeded = succeeded;
    }
}

impl Drop for ControlGuard {
    fn drop(&mut self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *state = match *state {
            DeviceState::Resetting if self.succeeded => DeviceState::Open,
            DeviceState::Open
            | DeviceState::Resetting
            | DeviceState::Closing
            | DeviceState::Closed => DeviceState::Closed,
        };
    }
}

fn validate_width(width: usize) -> wasmtime::Result<()> {
    if matches!(width, 1 | 2 | 4 | 8) {
        Ok(())
    } else {
        Err(wasmtime::Error::msg("invalid MMIO width"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_device() -> (MmioDevice, tokio::sync::mpsc::Receiver<Pending>) {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let (control_sender, controls) = tokio::sync::mpsc::channel(1);
        let device = MmioDevice {
            device: Arc::new(DeviceRegistration {
                kind: DeviceKind::Block,
                slot: 0,
                base: AtomicU64::new(0),
                counts: DeviceRequestCounts::default(),
            }),
            sender,
            control_sender,
            state: Arc::new(Mutex::new(DeviceState::Open)),
            admission: Arc::new(Mutex::new(None)),
            failure: Arc::new(Mutex::new(None)),
        };
        (device, controls)
    }

    #[test]
    fn abandoned_sync_waiters_leave_control_completion_to_the_request() {
        use super::super::{ReplySender, RoutedReply, enqueue_reply};

        for operation in [ControlOperation::Reset, ControlOperation::Close] {
            for resolution in [Some(true), Some(false), None] {
                let (device, mut controls) = test_device();
                let control = device.begin_control(operation).unwrap().unwrap();
                let (reply, response) = std::sync::mpsc::sync_channel(1);
                enqueue_reply(
                    &device.control_sender,
                    &device.admission,
                    Command::Control(0, operation.into()),
                    ReplySender::Sync(reply),
                    Some(control),
                )
                .unwrap();
                drop(response);
                assert!(device.reset().is_err());
                assert!(device.close().is_err());
                assert!(device.read(0, 4).is_err());
                let pending = controls.try_recv().unwrap();
                match resolution {
                    Some(true) => pending.reply.send(Ok(RoutedReply {
                        slot: 0,
                        reply: Reply {
                            sequence: 0,
                            value: 0,
                            error: 0,
                            interrupt: false,
                        },
                    })),
                    Some(false) => pending
                        .reply
                        .send(Err(wasmtime::Error::msg("control failed"))),
                    None => drop(pending),
                }
                let expected = if operation == ControlOperation::Reset && resolution == Some(true) {
                    DeviceState::Open
                } else {
                    DeviceState::Closed
                };
                assert!(*device.state.lock().unwrap() == expected);
            }
        }
    }

    #[test]
    fn rejected_controls_close_the_device() {
        for operation in [ControlOperation::Reset, ControlOperation::Close] {
            let (device, _controls) = test_device();
            *device.admission.lock().unwrap() = Some("stopped".to_owned());
            assert!(device.control(operation).is_err());
            assert!(*device.state.lock().unwrap() == DeviceState::Closed);
            device.close().unwrap();
        }
    }

    #[tokio::test]
    async fn cancelled_close_stays_in_flight_until_the_bridge_resolves_it() {
        let (device, mut controls) = test_device();
        let pending = {
            let close = device.close_async();
            tokio::pin!(close);
            tokio::select! {
                result = &mut close => panic!("close completed before reply: {result:?}"),
                pending = controls.recv() => pending.unwrap(),
            }
        };
        assert!(*device.state.lock().unwrap() == DeviceState::Closing);
        assert!(device.close().is_err());
        assert!(device.read(0, 4).is_err());
        drop(pending);
        assert!(*device.state.lock().unwrap() == DeviceState::Closed);
        device.close_async().await.unwrap();
    }

    #[tokio::test]
    async fn failed_or_cancelled_setup_cannot_produce_a_ready_runtime() {
        for cancel in [false, true] {
            let engine = crate::engine::device_engine().unwrap();
            let mut runtime =
                BoxRuntime::new(&engine, crate::box_runtime::store::BoxHost::new()).unwrap();
            crate::component::vmm::initialize_test_vmm(&mut runtime)
                .await
                .unwrap();
            let registry = Arc::downgrade(&runtime.vmm.as_ref().unwrap().devices);
            let cancelled = tokio_util::sync::CancellationToken::new();
            let owner = cancelled.clone().drop_guard();
            let (entered, started) = tokio::sync::oneshot::channel();
            let setup: crate::box_runtime::setup::Setup = Box::new(move |_| {
                Box::pin(async move {
                    let _owner = owner;
                    let _ = entered.send(());
                    if cancel {
                        std::future::pending::<()>().await;
                    }
                    wasmtime::bail!("injected setup failure")
                })
            });
            MmioDevice::grant_worker(&mut runtime, DeviceKind::Block, setup).unwrap();
            {
                let preparation = runtime.prepare();
                tokio::pin!(preparation);
                if cancel {
                    tokio::select! {
                        result = &mut preparation => panic!("setup completed: {}", result.is_ok()),
                        result = tokio::time::timeout(std::time::Duration::from_secs(5), started) => {
                            result.unwrap().unwrap();
                        }
                    }
                } else {
                    assert!(preparation.await.is_err());
                }
            }
            assert!(cancelled.is_cancelled());
            assert!(registry.upgrade().is_none());
        }
    }

    #[tokio::test]
    async fn device_grants_count_manually_attached_workers_towards_box_capacity() {
        let engine = crate::engine::device_engine().unwrap();
        let mut runtime =
            BoxRuntime::new(&engine, crate::box_runtime::store::BoxHost::new()).unwrap();
        crate::component::vmm::initialize_test_vmm(&mut runtime)
            .await
            .unwrap();
        for _ in 0..crate::box_runtime::MAX_BOX_COMPONENTS {
            let worker = runtime.new_child(crate::box_runtime::store::RootHost::new());
            runtime.attach_child(worker).unwrap();
        }
        let setup: crate::box_runtime::setup::Setup =
            Box::new(|_| Box::pin(async { panic!("over-capacity setup must not run") }));
        let error = MmioDevice::grant_worker(&mut runtime, DeviceKind::Block, setup)
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "box has too many components");
    }

    #[test]
    fn accepts_only_virtio_mmio_widths() {
        for width in [1, 2, 4, 8] {
            validate_width(width).expect("valid MMIO width");
        }
        for width in [0, 3, 5, 9] {
            assert!(validate_width(width).is_err());
        }
    }

    #[tokio::test]
    async fn granting_a_worker_requires_an_initialized_router() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut runtime =
            BoxRuntime::new(&engine, crate::box_runtime::store::BoxHost::new()).expect("runtime");
        let setup: crate::box_runtime::setup::Setup =
            Box::new(|_| Box::pin(async { unreachable!() }));

        let error = MmioDevice::grant_worker(&mut runtime, DeviceKind::Block, setup)
            .err()
            .expect("MMIO router is required");

        assert!(error.to_string().contains("MMIO router missing"));
    }
}
