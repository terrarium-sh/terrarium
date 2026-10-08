//! Host disk capabilities and block component linker.

use super::backing::{BlockBacking, DiskGrant};
use super::bindings::disk;
use crate::MAX_BATCH_BYTES;
use crate::component::context::{DeviceContext, DeviceHost, add_device_imports};
use crate::memory::GuestRam;
use std::sync::{Arc, Mutex};
use wasmtime::Engine;
use wasmtime::component::HasSelf;
use wasmtime_wasi::{WasiCtxView, WasiView};

pub struct BlockHost {
    pub context: DeviceContext,
    disk: Arc<Mutex<DiskGrant>>,
    disk_capacity: u64,
    disk_slot: Arc<tokio::sync::Semaphore>,
}

impl BlockHost {
    #[must_use]
    pub fn new(ram: GuestRam, disk: DiskGrant) -> Self {
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

impl crate::box_runtime::store::StoreHost for BlockHost {}

fn run_disk_job<T: Send + 'static, F>(
    host: &mut BlockHost,
    offset: u64,
    len: u64,
    max_len: u64,
    operation: F,
) -> impl core::future::Future<Output = Result<T, disk::DiskError>> + Send + use<T, F>
where
    F: FnOnce(&mut DiskGrant) -> Result<T, super::backing::BackingError> + Send + 'static,
{
    let disk = Arc::clone(&host.disk);
    let capacity = host.disk_capacity;
    let disk_slot = Arc::clone(&host.disk_slot);
    async move {
        use super::backing::BackingError;
        use disk::DiskError;
        if len > max_len {
            return Err(DiskError::TooLarge);
        }
        if offset.checked_add(len).is_none_or(|end| end > capacity) {
            return Err(DiskError::OutOfRange);
        }
        let job = disk_slot.acquire_owned().await.map_err(|_| DiskError::Io)?;
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

impl<T: Send + 'static> disk::HostWithStore<T> for HasSelf<BlockHost> {
    fn read_at(
        host: &wasmtime::component::Accessor<T, Self>,
        offset: u64,
        len: u64,
    ) -> impl core::future::Future<Output = Result<Vec<u8>, disk::DiskError>> + Send {
        host.with(|mut access| disk_read_at(access.get(), offset, len))
    }
    fn write_at(
        host: &wasmtime::component::Accessor<T, Self>,
        offset: u64,
        data: Vec<u8>,
    ) -> impl core::future::Future<Output = Result<(), disk::DiskError>> + Send {
        host.with(|mut access| disk_write_at(access.get(), offset, data))
    }
    fn discard(
        host: &wasmtime::component::Accessor<T, Self>,
        offset: u64,
        len: u64,
    ) -> impl core::future::Future<Output = Result<(), disk::DiskError>> + Send {
        host.with(|mut access| disk_discard(access.get(), offset, len))
    }
    fn sync(
        host: &wasmtime::component::Accessor<T, Self>,
    ) -> impl core::future::Future<Output = Result<(), disk::DiskError>> + Send {
        host.with(|mut access| disk_sync(access.get()))
    }
}

fn disk_read_at(
    host: &mut BlockHost,
    offset: u64,
    len: u64,
) -> impl core::future::Future<Output = Result<Vec<u8>, disk::DiskError>> + Send + use<> {
    run_disk_job(host, offset, len, MAX_BATCH_BYTES, move |disk| {
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
) -> impl core::future::Future<Output = Result<(), disk::DiskError>> + Send + use<> {
    run_disk_job(
        host,
        offset,
        data.len() as u64,
        MAX_BATCH_BYTES,
        move |disk| disk.write_at(offset, &data),
    )
}

fn disk_discard(
    host: &mut BlockHost,
    offset: u64,
    len: u64,
) -> impl core::future::Future<Output = Result<(), disk::DiskError>> + Send + use<> {
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
) -> impl core::future::Future<Output = Result<(), disk::DiskError>> + Send + use<> {
    run_disk_job(host, 0, 0, MAX_BATCH_BYTES, |disk| disk.sync())
}

impl disk::Host for BlockHost {
    fn capacity(&mut self) -> u64 {
        self.disk_capacity
    }
}

pub fn block_component_linker<T: WasiView + AsMut<BlockHost> + 'static>(
    engine: &Engine,
) -> wasmtime::Result<wasmtime::component::Linker<T>> {
    let mut linker = wasmtime::component::Linker::new(engine);
    disk::add_to_linker::<T, HasSelf<BlockHost>>(&mut linker, AsMut::as_mut)?;
    add_device_imports(&mut linker, |host: &mut T| host.as_mut().context())?;
    Ok(linker)
}

#[cfg(test)]
mod tests {
    use crate::component::block::backing::BoundedDisk;
    #[tokio::test]
    async fn disk_imports_accept_one_bounded_batch() {
        use super::{BlockHost, DiskGrant, MAX_BATCH_BYTES, disk, disk_read_at, disk_write_at};

        let capacity = usize::try_from(MAX_BATCH_BYTES).unwrap();
        let mut host = BlockHost::new(
            crate::memory::GuestRam::new(4096).unwrap(),
            DiskGrant::Mem(BoundedDisk::new(capacity, false)),
        );
        let bytes = vec![0xA5; capacity];
        assert_eq!(disk_write_at(&mut host, 0, bytes.clone()).await, Ok(()));
        assert_eq!(disk_read_at(&mut host, 0, MAX_BATCH_BYTES).await, Ok(bytes));
        assert_eq!(
            disk_write_at(&mut host, 0, vec![0; capacity + 1]).await,
            Err(disk::DiskError::TooLarge)
        );
    }

    #[tokio::test]
    async fn disk_imports_enforce_bounds_and_readonly_without_a_guest() {
        use super::disk::DiskError;
        use super::{BlockHost, DiskGrant, disk_discard, disk_read_at, disk_sync, disk_write_at};

        let mut host = BlockHost::new(
            crate::memory::GuestRam::new(4096).unwrap(),
            DiskGrant::Mem(BoundedDisk::new(4096, false)),
        );
        assert_eq!(disk_write_at(&mut host, 4095, vec![7]).await, Ok(()));
        assert_eq!(disk_read_at(&mut host, 4095, 1).await, Ok(vec![7]));
        assert!(matches!(
            disk_read_at(&mut host, 0, super::MAX_BATCH_BYTES + 1).await,
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
            crate::memory::GuestRam::new(4096).unwrap(),
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
        use super::{BlockHost, disk::DiskError, disk_read_at, disk_sync, run_disk_job};

        let mut host = BlockHost::new(
            crate::memory::GuestRam::new(4096).unwrap(),
            crate::component::block::backing::DiskGrant::Mem(
                crate::component::block::backing::BoundedDisk::new(0, false),
            ),
        );
        let mut other = BlockHost::new(
            crate::memory::GuestRam::new(4096).unwrap(),
            crate::component::block::backing::DiskGrant::Mem(
                crate::component::block::backing::BoundedDisk::new(0, false),
            ),
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
        assert!(matches!(
            disk_read_at(&mut host, u64::MAX, 1).await,
            Err(DiskError::OutOfRange)
        ));
        let waiter = tokio::spawn(operation);
        started_rx.await.expect("work is running");
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        let sync = disk_sync(&mut host);
        tokio::pin!(sync);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut sync)
                .await
                .is_err()
        );
        disk_sync(&mut other)
            .await
            .expect("other disk stays available");
        release.send(()).expect("work unblocked");
        tokio::time::timeout(std::time::Duration::from_secs(2), sync)
            .await
            .expect("queued sync completes after cancelled work")
            .expect("disk synced");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn component_completes_host_io_failures_with_ioerr() {
        use super::{BlockHost, DiskGrant};
        use crate::component::block::component_tests::fixture_with_host;
        use crate::engine::device_engine;
        use terra_platform::memory::MemoryRange;

        let host = BlockHost::new(
            crate::memory::GuestRam::new(256 * 1024).unwrap(),
            DiskGrant::Mem(BoundedDisk::new(4096, false)),
        );
        let disk = std::sync::Arc::clone(&host.disk);
        assert!(
            std::panic::catch_unwind(|| {
                let _guard = disk.lock().unwrap();
                panic!("disk failed");
            })
            .is_err()
        );
        let engine = device_engine().unwrap();
        let component =
            wasmtime::component::Component::new(&engine, crate::test_fixtures::wasm::BLOCK)
                .unwrap();
        let mut fixture = fixture_with_host(&engine, host, &component, false).await;
        for (request_type, ranges) in [
            (
                0,
                vec![MemoryRange {
                    addr: 0x2000,
                    len: 512,
                }],
            ),
            (
                1,
                vec![MemoryRange {
                    addr: 0x2000,
                    len: 512,
                }],
            ),
            (4, vec![]),
        ] {
            fixture.stage_request(request_type, 0, &ranges, 0x3000);
            assert_eq!(fixture.complete_request().await, 1);
            assert_eq!(fixture.read(0x3000, 1).unwrap(), [1]);
        }
    }

    /// A reset while host I/O is suspended fences the old request's guest writes and
    /// used-ring completion, and the worker then accepts a newly negotiated queue.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn component_reset_fences_inflight_host_io() {
        use super::{BlockHost, DiskGrant};
        use crate::component::block::component_tests::fixture_with_host;
        use crate::engine::device_engine;
        use terra_platform::memory::MemoryRange;

        let mut backing = BoundedDisk::new(4096, false);
        super::BlockBacking::write_at(&mut backing, 0, &[0xA5; 512]).unwrap();
        let host = BlockHost::new(
            crate::memory::GuestRam::new(256 * 1024).unwrap(),
            DiskGrant::Mem(backing),
        );
        let disk = std::sync::Arc::clone(&host.disk);
        let disk_slot = std::sync::Arc::clone(&host.disk_slot);
        let engine = device_engine().unwrap();
        let component =
            wasmtime::component::Component::new(&engine, crate::test_fixtures::wasm::BLOCK)
                .unwrap();
        let mut fixture = fixture_with_host(&engine, host, &component, false).await;
        let (locked, locked_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::sync_channel(0);
        let blocker = std::thread::spawn(move || {
            let _guard = disk.lock().unwrap();
            locked.send(()).unwrap();
            release_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        });
        locked_rx.await.unwrap();
        fixture.write(0x2000, &[0xCD; 512]).unwrap();
        fixture.stage_request(
            0,
            0,
            &[MemoryRange {
                addr: 0x2000,
                len: 512,
            }],
            0x3000,
        );
        fixture.device.write(0x050, &0_u32.to_le_bytes()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while disk_slot.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("host read is suspended");
        fixture.device.reset().unwrap();
        release.send(()).unwrap();
        blocker.join().unwrap();
        let permit = tokio::time::timeout(std::time::Duration::from_secs(2), disk_slot.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        fixture.clear_queue();
        assert_eq!(
            fixture
                .submit_request(
                    0,
                    0,
                    &[MemoryRange {
                        addr: 0x4000,
                        len: 512
                    }],
                    0x3100
                )
                .await,
            0
        );
        assert_eq!(fixture.read(0x4000, 512).unwrap(), [0xA5; 512]);
        assert_eq!(fixture.read(0x2000, 512).unwrap(), [0xCD; 512]);
        assert_eq!(fixture.read(0x3000, 1).unwrap(), [0xFF]);
        assert_eq!(fixture.read(0x23002, 2).unwrap(), 1_u16.to_le_bytes());
        fixture.device.close().unwrap();
    }
}
