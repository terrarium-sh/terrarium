//! Native device handles for host-issued MMIO and lifecycle requests.

#[cfg(any(test, feature = "test-support"))]
use super::initialize_test_router;
use super::{
    Arc, AtomicU64, BoxRuntime, Command, DEVICE_SPAN, DeviceRequestCounts, Mutex, Operation,
    Ordering, Pending, PendingWorker, Reply, enqueue, recorded_failure, router_error, submit,
    terra, wait_for_reply,
};

#[derive(Copy, Clone, Eq, PartialEq)]
enum DeviceState {
    Open,
    Resetting,
    Closing,
    Closed,
}

#[derive(Clone)]
pub struct MmioDevice {
    slot: u32,
    base: Arc<AtomicU64>,
    sender: tokio::sync::mpsc::Sender<Pending>,
    control_sender: tokio::sync::mpsc::Sender<Pending>,
    state: Arc<Mutex<DeviceState>>,
    admission: Arc<Mutex<bool>>,
    completed: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
    failure: Arc<Mutex<Option<String>>>,
}

impl MmioDevice {
    pub(crate) async fn grant_worker(
        root: &mut BoxRuntime,
        kind: crate::component::vmm::machine::DeviceKind,
        factory: crate::component::vmm::workers::Factory,
    ) -> wasmtime::Result<Self> {
        #[cfg(any(test, feature = "test-support"))]
        initialize_test_router(root).await?;
        let router = root
            .mmio
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("MMIO router missing"))?;
        let slot = u32::try_from(router.slots.load(Ordering::Acquire))?;
        wasmtime::ensure!(
            usize::try_from(slot)? < crate::box_runtime::MAX_BOX_COMPONENTS,
            "box has too many components"
        );
        wasmtime::ensure!(
            root.component_count() < crate::box_runtime::MAX_BOX_COMPONENTS,
            "box has too many components"
        );
        let base = u64::from(slot) * DEVICE_SPAN;
        let channel = Self::register(root, slot, base)?;
        root.pending_workers.push(PendingWorker {
            kind,
            slot,
            base: Arc::clone(&channel.base),
            mapping: (!root.store.data().platform.has_machine()).then_some(
                terra::mmio::workers::Mapping {
                    base,
                    size: DEVICE_SPAN,
                },
            ),
            factory,
        });
        if !root.store.data().platform.has_machine() {
            root.compose_workers().await?;
        }
        Ok(channel)
    }

    fn register(root: &BoxRuntime, slot: u32, base: u64) -> wasmtime::Result<Self> {
        let router = root
            .mmio
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("MMIO router missing"))?;
        let sender = router.sender.clone();
        let control_sender = router.control_sender.clone();
        let admission = Arc::clone(&router.admission);
        let failure = Arc::clone(&router.failure);
        let slots = Arc::clone(&router.slots);
        let callbacks = Arc::clone(&router.callbacks);
        let completed = Arc::new(AtomicU64::new(0));
        let failed = Arc::new(AtomicU64::new(0));
        callbacks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(DeviceRequestCounts {
                completed: Arc::clone(&completed),
                failed: Arc::clone(&failed),
            });
        slots.fetch_add(1, Ordering::Release);
        Ok(Self {
            slot,
            base: Arc::new(AtomicU64::new(base)),
            sender,
            control_sender,
            state: Arc::new(Mutex::new(DeviceState::Open)),
            admission,
            completed,
            failed,
            failure,
        })
    }

    pub async fn map(
        &self,
        runtime: &mut BoxRuntime,
        base: u64,
        size: u64,
    ) -> wasmtime::Result<()> {
        if let Some(worker) = runtime
            .pending_workers
            .iter_mut()
            .find(|worker| worker.slot == self.slot)
        {
            wasmtime::ensure!(
                size != 0 && base.checked_add(size).is_some(),
                "invalid MMIO mapping"
            );
            worker.mapping = Some(terra::mmio::workers::Mapping { base, size });
            self.base.store(base, Ordering::Release);
            return Ok(());
        }
        let remap = runtime
            .mmio
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("MMIO router missing"))?
            .remap;
        let (result,) = remap
            .call_async(&mut runtime.store, (self.slot, base, size))
            .await?;
        result.map_err(router_error)?;
        self.base.store(base, Ordering::Release);
        Ok(())
    }

    pub fn read(&self, offset: u64, len: usize) -> wasmtime::Result<Vec<u8>> {
        validate_width(len)?;
        let width = u8::try_from(len)?;
        let address = self
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
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if *state != DeviceState::Open {
                return Err(wasmtime::Error::msg("MMIO device unavailable"));
            }
            *state = DeviceState::Resetting;
        }
        let result = self.control(Operation::Reset).map(|_| ());
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *state = if result.is_ok() {
            DeviceState::Open
        } else {
            DeviceState::Closed
        };
        result
    }
    pub fn close(&self) -> wasmtime::Result<()> {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match *state {
                DeviceState::Closed => return Ok(()),
                DeviceState::Open => *state = DeviceState::Closing,
                DeviceState::Resetting | DeviceState::Closing => {
                    return Err(wasmtime::Error::msg("MMIO device unavailable"));
                }
            }
        }
        let result = self.control(Operation::Close).map(|_| ());
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = DeviceState::Closed;
        result
    }
    #[must_use]
    pub fn request_counts(&self) -> (u64, u64) {
        (
            self.completed.load(Ordering::Relaxed),
            self.failed.load(Ordering::Relaxed),
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

    fn control(&self, operation: Operation) -> wasmtime::Result<Reply> {
        Ok(submit(
            &self.control_sender,
            &self.admission,
            &self.failure,
            Command::Control(self.slot, operation),
        )?
        .reply)
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
    use super::validate_width;

    #[test]
    fn accepts_only_virtio_mmio_widths() {
        for width in [1, 2, 4, 8] {
            validate_width(width).expect("valid MMIO width");
        }
        for width in [0, 3, 5, 9] {
            assert!(validate_width(width).is_err());
        }
    }
}
