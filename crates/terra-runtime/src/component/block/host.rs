//! Block device capabilities and component bindings.

use super::backing::{BlockBacking, DiskGrant};
use crate::engine::{DeviceContext, DeviceHost, add_device_imports, device_component_linker};
use crate::{MAX_SINGLE_BYTES, SyntheticRam};
use std::sync::{Arc, Mutex};
use wasmtime::Engine;
use wasmtime::component::HasSelf;
use wasmtime_wasi::{WasiCtxView, WasiView};

wasmtime::component::bindgen!({
    world: "block-device",
    path: "../../components/wit/terra",
    exports: { default: async },
    with: {
        "terra:mmio/types@0.1.0": crate::component::vmm::mmio::terra::mmio::types,
    },
});

pub use exports::terra::host::device_api::{Completion, Range};
pub use terra::mmio::types::DeviceError;

pub struct BlockHost {
    pub context: DeviceContext,
    disk: Arc<Mutex<DiskGrant>>,
    disk_capacity: u64,
    disk_slot: Arc<tokio::sync::Semaphore>,
}

impl BlockHost {
    #[must_use]
    pub fn new(ram: SyntheticRam, disk: DiskGrant) -> Self {
        Self {
            context: DeviceContext::with_ram(ram),
            disk_capacity: disk.capacity(),
            disk: Arc::new(Mutex::new(disk)),
            disk_slot: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }
}

impl DeviceHost for BlockHost {
    fn context(&mut self) -> &mut DeviceContext {
        &mut self.context
    }
}
impl WasiView for BlockHost {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        self.context.ctx()
    }
}

impl AsMut<BlockHost> for BlockHost {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl crate::box_runtime::StoreHost for BlockHost {}

fn run_disk_job<T: Send + 'static, F>(
    host: &mut BlockHost,
    offset: u64,
    len: u64,
    max_len: u64,
    operation: F,
) -> impl core::future::Future<Output = Result<T, terra::host::disk::DiskError>> + Send + use<T, F>
where
    F: FnOnce(&mut DiskGrant) -> Result<T, super::backing::BackingError> + Send + 'static,
{
    let disk = Arc::clone(&host.disk);
    let capacity = host.disk_capacity;
    let job = Arc::clone(&host.disk_slot).try_acquire_owned();
    async move {
        use super::backing::BackingError;
        use terra::host::disk::DiskError;
        if len > max_len {
            return Err(DiskError::TooLarge);
        }
        if offset.checked_add(len).is_none_or(|end| end > capacity) {
            return Err(DiskError::OutOfRange);
        }
        let job = job.map_err(|_| DiskError::Busy)?;
        tokio::task::spawn_blocking(move || {
            let _job = job;
            let mut disk = disk.lock().map_err(|_| DiskError::Io)?;
            operation(&mut disk).map_err(|error| match error {
                BackingError::OutOfRange => DiskError::OutOfRange,
                BackingError::ReadOnly => DiskError::Readonly,
                BackingError::Io => DiskError::Io,
            })
        })
        .await
        .map_err(|_| DiskError::Io)?
    }
}

impl<T: Send + 'static> terra::host::disk::HostWithStore<T> for HasSelf<BlockHost> {
    fn read_at(
        host: &wasmtime::component::Accessor<T, Self>,
        offset: u64,
        len: u64,
    ) -> impl core::future::Future<Output = Result<Vec<u8>, terra::host::disk::DiskError>> + Send
    {
        host.with(|mut access| disk_read_at(access.get(), offset, len))
    }
    fn write_at(
        host: &wasmtime::component::Accessor<T, Self>,
        offset: u64,
        data: Vec<u8>,
    ) -> impl core::future::Future<Output = Result<(), terra::host::disk::DiskError>> + Send {
        host.with(|mut access| disk_write_at(access.get(), offset, data))
    }
    fn discard(
        host: &wasmtime::component::Accessor<T, Self>,
        offset: u64,
        len: u64,
    ) -> impl core::future::Future<Output = Result<(), terra::host::disk::DiskError>> + Send {
        host.with(|mut access| disk_discard(access.get(), offset, len))
    }
    fn sync(
        host: &wasmtime::component::Accessor<T, Self>,
    ) -> impl core::future::Future<Output = Result<(), terra::host::disk::DiskError>> + Send {
        host.with(|mut access| disk_sync(access.get()))
    }
}

fn disk_read_at(
    host: &mut BlockHost,
    offset: u64,
    len: u64,
) -> impl core::future::Future<Output = Result<Vec<u8>, terra::host::disk::DiskError>> + Send + use<>
{
    run_disk_job(host, offset, len, MAX_SINGLE_BYTES, move |disk| {
        let len = usize::try_from(len).map_err(|_| super::backing::BackingError::OutOfRange)?;
        let mut bytes = vec![0; len];
        disk.read_at(offset, &mut bytes)?;
        Ok(bytes)
    })
}

fn disk_write_at(
    host: &mut BlockHost,
    offset: u64,
    data: Vec<u8>,
) -> impl core::future::Future<Output = Result<(), terra::host::disk::DiskError>> + Send + use<> {
    run_disk_job(
        host,
        offset,
        data.len() as u64,
        MAX_SINGLE_BYTES,
        move |disk| disk.write_at(offset, &data),
    )
}

fn disk_discard(
    host: &mut BlockHost,
    offset: u64,
    len: u64,
) -> impl core::future::Future<Output = Result<(), terra::host::disk::DiskError>> + Send + use<> {
    run_disk_job(
        host,
        offset,
        len,
        terra_limits::MAX_GUEST_DISCARD_BYTES,
        move |disk| disk.discard(offset, len),
    )
}

fn disk_sync(
    host: &mut BlockHost,
) -> impl core::future::Future<Output = Result<(), terra::host::disk::DiskError>> + Send + use<> {
    run_disk_job(host, 0, 0, MAX_SINGLE_BYTES, |disk| disk.sync())
}

impl terra::host::disk::Host for BlockHost {
    fn capacity(&mut self) -> u64 {
        self.disk_capacity
    }
}

pub fn block_component_linker<T: WasiView + AsMut<BlockHost> + 'static>(
    engine: &Engine,
) -> wasmtime::Result<wasmtime::component::Linker<T>> {
    let mut linker = device_component_linker(engine)?;
    terra::host::disk::add_to_linker::<T, HasSelf<BlockHost>>(&mut linker, AsMut::as_mut)?;
    add_device_imports(&mut linker, |host: &mut T| host.as_mut().context())?;
    Ok(linker)
}

#[cfg(test)]
mod tests {
    use crate::BoundedDisk;
    #[tokio::test]
    async fn disk_imports_enforce_bounds_and_readonly_without_a_guest() {
        use super::terra::host::disk::DiskError;
        use super::{BlockHost, DiskGrant, disk_discard, disk_read_at, disk_sync, disk_write_at};

        let mut host = BlockHost::new(
            crate::SyntheticRam::new(4096).unwrap(),
            DiskGrant::Mem(BoundedDisk::new(4096, false)),
        );
        assert_eq!(disk_write_at(&mut host, 4095, vec![7]).await, Ok(()));
        assert_eq!(disk_read_at(&mut host, 4095, 1).await, Ok(vec![7]));
        assert!(matches!(
            disk_read_at(&mut host, 0, super::MAX_SINGLE_BYTES + 1).await,
            Err(DiskError::TooLarge)
        ));
        assert!(matches!(
            disk_write_at(&mut host, u64::MAX, vec![1]).await,
            Err(DiskError::OutOfRange)
        ));
        assert!(matches!(
            disk_read_at(&mut host, 4096, 1).await,
            Err(DiskError::OutOfRange)
        ));
        assert_eq!(disk_discard(&mut host, 4095, 1).await, Ok(()));
        assert_eq!(disk_read_at(&mut host, 4095, 1).await, Ok(vec![0]));
        assert!(matches!(
            disk_discard(&mut host, 0, terra_limits::MAX_GUEST_DISCARD_BYTES + 1).await,
            Err(DiskError::TooLarge)
        ));
        let mut host = BlockHost::new(
            crate::SyntheticRam::new(4096).unwrap(),
            DiskGrant::Mem(BoundedDisk::new(4096, true)),
        );
        assert!(matches!(
            disk_write_at(&mut host, 0, vec![1]).await,
            Err(DiskError::Readonly)
        ));
        assert!(matches!(
            disk_discard(&mut host, 0, 1).await,
            Err(DiskError::Readonly)
        ));
        assert_eq!(disk_sync(&mut host).await, Ok(()));
    }

    #[tokio::test]
    async fn cancelled_waiter_keeps_its_disk_slot_until_blocking_work_returns() {
        use super::{
            BlockHost, disk_read_at, disk_sync, run_disk_job, terra::host::disk::DiskError,
        };

        let mut host = BlockHost::new(
            crate::SyntheticRam::new(4096).unwrap(),
            crate::component::block::backing::DiskGrant::Mem(crate::BoundedDisk::new(0, false)),
        );
        let mut other = BlockHost::new(
            crate::SyntheticRam::new(4096).unwrap(),
            crate::component::block::backing::DiskGrant::Mem(crate::BoundedDisk::new(0, false)),
        );
        let (started, started_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::sync_channel(0);
        let operation = run_disk_job(&mut host, 0, 0, 0, move |_| {
            started.send(()).expect("work started");
            release_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("work released");
            Ok(())
        });
        assert!(matches!(disk_sync(&mut host).await, Err(DiskError::Busy)));
        assert!(matches!(
            disk_read_at(&mut host, u64::MAX, 1).await,
            Err(DiskError::OutOfRange)
        ));
        let waiter = tokio::spawn(operation);
        started_rx.await.expect("work is running");
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(matches!(disk_sync(&mut host).await, Err(DiskError::Busy)));
        disk_sync(&mut other)
            .await
            .expect("other disk stays available");
        release.send(()).expect("work unblocked");
        let permit =
            tokio::time::timeout(std::time::Duration::from_secs(2), host.disk_slot.acquire())
                .await
                .expect("disk slot released")
                .expect("slot open");
        drop(permit);
        disk_sync(&mut host).await.expect("disk available again");
    }
}
