//! Hostile boundary tests: each fails when the intended check breaks.

use super::*;
use terra_runtime::component::block::backing::{
    DESC_F_INDIRECT, DESC_F_NEXT, DESC_F_WRITE, Descriptor,
};

fn ram_64k() -> SyntheticRam {
    SyntheticRam::new(64 * 1024).expect("64 KiB RAM")
}

#[test]
fn oob_read_fails_closed() {
    let ram = ram_64k();
    let mem = BoundedMemory::new(&ram);
    assert_eq!(mem.read(ram.size(), 1), Err(MemoryError::OutOfRange));
    assert_eq!(mem.read(0, ram.size() + 1), Err(MemoryError::TooLarge));
}

#[test]
fn offset_plus_len_overflow_fails_closed() {
    let ram = ram_64k();
    let mem = BoundedMemory::new(&ram);
    assert_eq!(mem.read(u64::MAX - 4, 16), Err(MemoryError::OutOfRange));
}

#[test]
fn round_trip_through_synthetic_ram() {
    let ram = ram_64k();
    let mem = BoundedMemory::new(&ram);
    mem.write(128, b"virtio").expect("in-range write");
    assert_eq!(mem.read(128, 6).expect("in-range read"), b"virtio");
}

#[test]
fn descriptor_flags_match_bindings() {
    use virtio_bindings::bindings::virtio_ring::{
        VRING_DESC_F_INDIRECT, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE,
    };
    assert_eq!(u32::from(DESC_F_NEXT), VRING_DESC_F_NEXT);
    assert_eq!(u32::from(DESC_F_WRITE), VRING_DESC_F_WRITE);
    assert_eq!(u32::from(DESC_F_INDIRECT), VRING_DESC_F_INDIRECT);
}

#[test]
fn readonly_disk_resists_writes_and_truncation() {
    let mut disk = BoundedDisk::new(4096, true);
    assert_eq!(disk.write(0, b"x"), Err(DiskError::ReadOnly));
    assert!(disk.read(0, 4).is_ok());
    assert_eq!(disk.read(4090, 16), Err(DiskError::OutOfRange));
}

#[test]
fn writable_disk_enforces_capacity() {
    let mut disk = BoundedDisk::new(512, false);
    disk.write(0, &[7u8; 16]).expect("in-capacity write");
    assert_eq!(disk.write(500, &[7u8; 16]), Err(DiskError::OutOfRange));
}

#[test]
fn interrupt_storm_coalesces_and_drops() {
    let mut irq = Interrupt::new();
    for _ in 0..(MAX_SIGNALS_PER_WINDOW + 10) {
        irq.signal();
    }
    assert!(irq.take());
    assert!(!irq.take());
    assert_eq!(irq.delivered(), 1);
    assert_eq!(irq.dropped(), 10);
    irq.end_window();
    irq.signal();
    assert!(irq.take());
}

use super::component::block::backing::{
    BlkError, BlockDevice, ID_BYTES, SECTOR_BYTES, STATUS_FAILED, STATUS_IOERR, STATUS_OK,
    STATUS_UNSUPP, StatusError, device_features, drive_status, negotiate,
};
use virtio_bindings::bindings::{
    virtio_blk as blk, virtio_config as transport, virtio_ring as ring,
};

const BLK_HDR: u64 = 0x1000;
const BLK_DATA: u64 = 0x2000;
const BLK_STATUS: u64 = 0x3000;

fn blk_ram() -> SyntheticRam {
    SyntheticRam::new(256 * 1024).expect("256 KiB RAM")
}

fn write_blk_hdr(mem: &BoundedMemory, request_type: u32, sector: u64) {
    let mut hdr = [0u8; 16];
    hdr[0..4].copy_from_slice(&request_type.to_le_bytes());
    hdr[8..16].copy_from_slice(&sector.to_le_bytes());
    mem.write(BLK_HDR, &hdr).expect("header fits");
}

fn out_chain_1sector() -> Vec<Descriptor> {
    vec![
        Descriptor::readable(BLK_HDR, 16, Some(1)),
        Descriptor::readable(BLK_DATA, 512, Some(2)),
        Descriptor::writable(BLK_STATUS, 1, None),
    ]
}

fn in_chain_1sector() -> Vec<Descriptor> {
    vec![
        Descriptor::readable(BLK_HDR, 16, Some(1)),
        Descriptor::writable(BLK_DATA, 512, Some(2)),
        Descriptor::writable(BLK_STATUS, 1, None),
    ]
}

fn status_byte(mem: &BoundedMemory) -> u8 {
    mem.read(BLK_STATUS, 1).expect("status readable")[0]
}

#[test]
fn block_constants_match_bindings() {
    assert_eq!(u32::from(STATUS_OK), blk::VIRTIO_BLK_S_OK);
    assert_eq!(u32::from(STATUS_IOERR), blk::VIRTIO_BLK_S_IOERR);
    assert_eq!(u32::from(STATUS_UNSUPP), blk::VIRTIO_BLK_S_UNSUPP);
    assert_eq!(
        u32::try_from(ID_BYTES).expect("fits"),
        blk::VIRTIO_BLK_ID_BYTES
    );
    assert_eq!(SECTOR_BYTES, 512);
    assert_eq!(
        STATUS_FAILED,
        u8::try_from(transport::VIRTIO_CONFIG_S_FAILED).expect("fits")
    );
    assert_ne!(
        device_features(false) & (1u64 << blk::VIRTIO_BLK_F_FLUSH),
        0
    );
    assert_eq!(device_features(false) & (1u64 << blk::VIRTIO_BLK_F_RO), 0);
    assert_ne!(device_features(true) & (1u64 << blk::VIRTIO_BLK_F_RO), 0);
}

#[test]
fn block_features_mask_to_implemented() {
    let rw = negotiate(u64::MAX, false);
    assert_eq!(rw, device_features(false));
    assert_eq!(rw & (1u64 << blk::VIRTIO_BLK_F_DISCARD), 0);
    assert_eq!(rw & (1u64 << blk::VIRTIO_BLK_F_WRITE_ZEROES), 0);
    assert_eq!(rw & (1u64 << blk::VIRTIO_BLK_F_MQ), 0);
    assert_eq!(rw & (1u64 << ring::VIRTIO_RING_F_INDIRECT_DESC), 0);
    assert_eq!(rw & (1u64 << ring::VIRTIO_RING_F_EVENT_IDX), 0);
    assert_ne!(rw & (1u64 << transport::VIRTIO_F_VERSION_1), 0);
    assert_ne!(
        negotiate(u64::MAX, true) & (1u64 << blk::VIRTIO_BLK_F_RO),
        0
    );
    assert_eq!(negotiate(0, false), 0);
}

#[test]
fn block_status_sequence_and_reset() {
    assert_eq!(drive_status(0, 1), Ok(1));
    assert_eq!(drive_status(0, 2), Err(StatusError::BadSequence));
    assert_eq!(drive_status(1, 3), Ok(3));
    assert_eq!(drive_status(3, 3), Ok(3));
    assert_eq!(drive_status(3, 15), Err(StatusError::BadSequence));
    assert_eq!(drive_status(3, 11), Ok(11));
    assert_eq!(drive_status(11, 15), Ok(15));
    assert_eq!(drive_status(15, 0), Ok(0));
    assert_eq!(drive_status(0, 0), Ok(0));
    assert_eq!(drive_status(1, 1 | 64), Err(StatusError::BadSequence));
    assert_eq!(drive_status(1, 1 | 128), Ok(1 | 128));
    assert_eq!(drive_status(1 | 128, 3), Err(StatusError::BadSequence));
    assert_eq!(drive_status(1 | 128, 1 | 128), Ok(1 | 128));
    assert_eq!(drive_status(1 | 128, 0), Ok(0));
    assert_eq!(drive_status(1, 2), Err(StatusError::BadSequence));
}

#[test]
fn block_read_write_round_trip() {
    let ram = blk_ram();
    let mem = BoundedMemory::new(&ram);
    let mut dev = BlockDevice::new(8 * 512, false, b"terra-vda");
    mem.write(BLK_DATA, &[0xABu8; 512]).expect("payload fits");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 3);
    let written = dev
        .execute(&mem, &out_chain_1sector(), 0, ram.size(), 0)
        .expect("write completes");
    assert_eq!(written.status, STATUS_OK);
    assert_eq!(written.used_len, 1);
    assert_eq!(status_byte(&mem), STATUS_OK);
    mem.write(BLK_DATA, &[0u8; 512]).expect("clear buffer");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_IN, 3);
    let read = dev
        .execute(&mem, &in_chain_1sector(), 0, ram.size(), 0)
        .expect("read completes");
    assert_eq!(read.status, STATUS_OK);
    assert_eq!(read.used_len, 512 + 1);
    assert_eq!(mem.read(BLK_DATA, 512).expect("read back"), [0xABu8; 512]);
}

#[test]
fn block_readonly_rejects_writes() {
    let ram = blk_ram();
    let mem = BoundedMemory::new(&ram);
    let mut dev = BlockDevice::new(8 * 512, true, b"terra-vda");
    mem.write(BLK_DATA, &[0xABu8; 512]).expect("payload fits");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 0);
    let written = dev
        .execute(&mem, &out_chain_1sector(), 0, ram.size(), 0)
        .expect("well-formed request still completes");
    assert_eq!(written.status, STATUS_IOERR);
    assert_eq!(status_byte(&mem), STATUS_IOERR);
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_IN, 0);
    dev.execute(&mem, &in_chain_1sector(), 0, ram.size(), 0)
        .expect("read completes");
    assert_eq!(mem.read(BLK_DATA, 512).expect("read back"), [0u8; 512]);
}

#[test]
fn block_oob_and_overflow_are_ioerr_not_panic() {
    let ram = blk_ram();
    let mem = BoundedMemory::new(&ram);
    let mut dev = BlockDevice::new(8 * 512, false, b"terra-vda");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_IN, 8);
    let past_end = dev
        .execute(&mem, &in_chain_1sector(), 0, ram.size(), 0)
        .expect("completes with error status");
    assert_eq!(past_end.status, STATUS_IOERR);
    assert_eq!(status_byte(&mem), STATUS_IOERR);
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_IN, u64::MAX);
    let overflow = dev
        .execute(&mem, &in_chain_1sector(), 0, ram.size(), 0)
        .expect("sector overflow completes");
    assert_eq!(overflow.status, STATUS_IOERR);
}

#[test]
fn block_unsupported_types_get_unsupp() {
    let ram = blk_ram();
    let mem = BoundedMemory::new(&ram);
    let mut dev = BlockDevice::new(8 * 512, false, b"terra-vda");
    mem.write(BLK_DATA, &[0x5Au8; 512]).expect("pattern fits");
    for request_type in [
        blk::VIRTIO_BLK_T_SCSI_CMD,
        blk::VIRTIO_BLK_T_DISCARD,
        blk::VIRTIO_BLK_T_WRITE_ZEROES,
        0xFFFF,
    ] {
        write_blk_hdr(&mem, request_type, 0);
        let completion = dev
            .execute(&mem, &out_chain_1sector(), 0, ram.size(), 0)
            .expect("unsupported still completes");
        assert_eq!(completion.status, STATUS_UNSUPP);
        assert_eq!(status_byte(&mem), STATUS_UNSUPP);
    }
    assert_eq!(mem.read(BLK_DATA, 512).expect("untouched"), [0x5Au8; 512]);
}

#[test]
fn block_flush_and_identify() {
    let ram = blk_ram();
    let mem = BoundedMemory::new(&ram);
    let mut dev = BlockDevice::new(8 * 512, false, b"terra-vda-01");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_FLUSH, 0);
    let bare = vec![
        Descriptor::readable(BLK_HDR, 16, Some(1)),
        Descriptor::writable(BLK_STATUS, 1, None),
    ];
    let flushed = dev
        .execute(&mem, &bare, 0, ram.size(), 0)
        .expect("flush completes");
    assert_eq!(flushed.status, STATUS_OK);
    assert_eq!(flushed.used_len, 1);
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_FLUSH, 0);
    assert_eq!(
        dev.execute(&mem, &out_chain_1sector(), 0, ram.size(), 0),
        Err(BlkError::Malformed)
    );
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_GET_ID, 0);
    let identified = dev
        .execute(&mem, &in_chain_1sector(), 0, ram.size(), 0)
        .expect("identify completes");
    assert_eq!(identified.status, STATUS_OK);
    assert_eq!(
        identified.used_len,
        u32::try_from(ID_BYTES).expect("id length fits") + 1
    );
    let mut expected = [0u8; 512];
    expected[..12].copy_from_slice(b"terra-vda-01");
    assert_eq!(mem.read(BLK_DATA, 512).expect("id back"), expected);
}

#[test]
fn block_malformed_chains_write_no_completion() {
    let ram = blk_ram();
    let mem = BoundedMemory::new(&ram);
    let mut dev = BlockDevice::new(8 * 512, false, b"terra-vda");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 0);
    let short_hdr = vec![
        Descriptor::readable(BLK_HDR, 15, Some(1)),
        Descriptor::readable(BLK_DATA, 512, Some(2)),
        Descriptor::writable(BLK_STATUS, 1, None),
    ];
    assert_eq!(
        dev.execute(&mem, &short_hdr, 0, ram.size(), 0),
        Err(BlkError::Malformed)
    );
    let no_status = vec![Descriptor::readable(BLK_HDR, 16, None)];
    assert_eq!(
        dev.execute(&mem, &no_status, 0, ram.size(), 0),
        Err(BlkError::Malformed)
    );
    let mixed = vec![
        Descriptor::readable(BLK_HDR, 16, Some(1)),
        Descriptor::readable(BLK_DATA, 512, Some(2)),
        Descriptor::writable(BLK_DATA + 512, 512, Some(3)),
        Descriptor::writable(BLK_STATUS, 1, None),
    ];
    assert_eq!(
        dev.execute(&mem, &mixed, 0, ram.size(), 0),
        Err(BlkError::Malformed)
    );
    let wrong_dir = vec![
        Descriptor::readable(BLK_HDR, 16, Some(1)),
        Descriptor::readable(BLK_DATA, 512, Some(2)),
        Descriptor::writable(BLK_STATUS, 1, None),
    ];
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_IN, 0);
    assert_eq!(
        dev.execute(&mem, &wrong_dir, 0, ram.size(), 0),
        Err(BlkError::Malformed)
    );
    assert_eq!(status_byte(&mem), 0);
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 0);
    let ragged = vec![
        Descriptor::readable(BLK_HDR, 16, Some(1)),
        Descriptor::readable(BLK_DATA, 100, Some(2)),
        Descriptor::writable(BLK_STATUS, 1, None),
    ];
    let partial = dev
        .execute(&mem, &ragged, 0, ram.size(), 0)
        .expect("ragged length still completes");
    assert_eq!(partial.status, STATUS_IOERR);
    assert_eq!(status_byte(&mem), STATUS_IOERR);
}

#[test]
fn block_oversized_transfers_rejected() {
    let ram = blk_ram();
    let mem = BoundedMemory::new(&ram);
    let mut dev = BlockDevice::new(8 * 512, false, b"terra-vda");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 0);
    let mut flood = vec![Descriptor::readable(BLK_HDR, 16, Some(1))];
    for i in 0..5u16 {
        flood.push(Descriptor::readable(
            BLK_DATA + u64::from(i) * 0x4000,
            16 * 1024,
            Some(2 + i),
        ));
    }
    flood.push(Descriptor::writable(BLK_STATUS, 1, None));
    assert_eq!(
        dev.execute(&mem, &flood, 0, ram.size(), 0),
        Err(BlkError::Malformed)
    );
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 0);
    let wide = vec![
        Descriptor::readable(BLK_HDR, 16, Some(1)),
        Descriptor::readable(BLK_DATA, 32 * 1024, Some(2)),
        Descriptor::writable(BLK_STATUS, 1, None),
    ];
    assert_eq!(
        dev.execute(&mem, &wide, 0, ram.size(), 0),
        Err(BlkError::Malformed)
    );
}

#[test]
fn block_reset_fences_stale_completions() {
    let ram = blk_ram();
    let mem = BoundedMemory::new(&ram);
    let mut dev = BlockDevice::new(8 * 512, false, b"terra-vda");
    mem.write(BLK_DATA, &[0xABu8; 512]).expect("payload fits");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 0);
    dev.execute(&mem, &out_chain_1sector(), 0, ram.size(), 0)
        .expect("write completes");
    dev.reset();
    assert_eq!(dev.epoch(), 1);
    mem.write(BLK_STATUS, &[0u8; 1]).expect("clear status");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 1);
    mem.write(BLK_DATA, &[0xCDu8; 512])
        .expect("new payload fits");
    assert_eq!(
        dev.execute(&mem, &out_chain_1sector(), 0, ram.size(), 0),
        Err(BlkError::Stale)
    );
    assert_eq!(status_byte(&mem), 0);
    dev.execute(&mem, &out_chain_1sector(), 0, ram.size(), 1)
        .expect("current epoch works");
    assert_eq!(status_byte(&mem), STATUS_OK);
    mem.write(BLK_DATA, &[0u8; 512]).expect("clear buffer");
    write_blk_hdr(&mem, blk::VIRTIO_BLK_T_IN, 0);
    dev.execute(&mem, &in_chain_1sector(), 0, ram.size(), 1)
        .expect("read completes");
    assert_eq!(mem.read(BLK_DATA, 512).expect("read back"), [0xABu8; 512]);
}

/// Vertical slice through the real P3 block component: queue-parsed
/// requests drive `execute` through the actual memory/disk imports.
/// Build it first: `make component-block` (nightly `wasm32-wasip3`).
#[cfg(test)]
mod block_component_tests {
    use super::super::component::vmm::mmio::{Operation, Reply, Request};
    use super::super::engine::{
        Completion, DeviceError, DiskGrant, Range, block_component_linker, device_engine,
        device_store, precompile_component,
    };
    use super::super::{BoundedDisk, SyntheticRam};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use wasmtime::StoreContextMut;
    use wasmtime::component::wit_parser::ItemName;
    use wasmtime::component::{
        Component, Instance, Linker, Source, StreamConsumer, StreamReader, StreamResult, TypedFunc,
    };

    const RAM: u64 = 256 * 1024;
    const DATA: u64 = 0x2000;
    const STATUS: u64 = 0x3000;
    const T_IN: u32 = 0;
    const T_OUT: u32 = 1;
    const T_FLUSH: u32 = 4;
    const T_GET_ID: u32 = 8;
    const T_DISCARD: u32 = 11;

    type Execute = TypedFunc<(u32, u64, Vec<Range>, u64, u64), (u8,)>;
    type Configure = TypedFunc<(bool,), (Result<(), super::super::engine::DeviceError>,)>;
    type Serve = TypedFunc<(StreamReader<Request>,), (StreamReader<Reply>,)>;

    fn one(addr: u64, len: u64) -> Vec<Range> {
        vec![Range { addr, len }]
    }

    pub(crate) fn component_bytes() -> Vec<u8> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/block/target/wasm32-wasip3/release/terra_block_component.wasm");
        std::fs::read(&path)
            .expect("block component missing; run `make component-block` with the pinned nightly")
    }

    fn export_name(func: &str) -> ItemName {
        format!("terra:host/device-api.{func}@0.1.0")
            .parse()
            .expect("export name parses")
    }

    struct Fixture {
        store: wasmtime::Store<super::super::engine::DeviceHost>,
        execute: Execute,
        configure: Configure,
        serve: Serve,
    }

    struct ReplySink(Arc<Mutex<Option<Reply>>>);

    impl StreamConsumer<super::super::engine::DeviceHost> for ReplySink {
        type Item = Reply;

        fn poll_consume(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            store: StoreContextMut<super::super::engine::DeviceHost>,
            mut source: Source<'_, Self::Item>,
            finish: bool,
        ) -> Poll<wasmtime::Result<StreamResult>> {
            if finish {
                return Poll::Ready(Ok(StreamResult::Cancelled));
            }
            let mut reply = None;
            source.read(store, &mut reply)?;
            *self.0.lock().expect("reply sink lock") = reply;
            Poll::Ready(Ok(StreamResult::Completed))
        }
    }

    async fn mmio(
        fixture: &mut Fixture,
        operation: Operation,
        offset: u64,
        width: u8,
        value: u64,
    ) -> Reply {
        let requests = StreamReader::new(
            &mut fixture.store,
            vec![Request {
                sequence: 0,
                operation,
                offset,
                width,
                value,
            }],
        )
        .expect("request stream");
        let (replies,) = fixture
            .serve
            .call_async(&mut fixture.store, (requests,))
            .await
            .expect("MMIO server starts");
        let reply = Arc::new(Mutex::new(None));
        replies
            .pipe(&mut fixture.store, ReplySink(Arc::clone(&reply)))
            .expect("reply stream attaches");
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            fixture.store.run_concurrent(async |_| {
                while reply.lock().expect("reply sink lock").is_none() {
                    tokio::task::yield_now().await;
                }
            }),
        )
        .await
        .expect("MMIO reply")
        .expect("MMIO server runs");
        reply
            .lock()
            .expect("reply sink lock")
            .take()
            .expect("MMIO reply")
    }

    async fn fixture(
        capacity_sectors: usize,
        readonly: bool,
    ) -> (Linker<super::super::engine::DeviceHost>, Fixture) {
        let engine = device_engine().expect("engine builds");
        let linker = block_component_linker(&engine).expect("block imports link");
        let mut store = device_store(&engine, RAM).expect("store builds");
        let mut disk = BoundedDisk::new(capacity_sectors * 512, readonly);
        if !readonly {
            disk.write(3 * 512, &[0xABu8; 512]).ok();
        }
        store.data_mut().set_disk(DiskGrant::Mem(disk));
        let component =
            Component::new(&engine, component_bytes()).expect("block component compiles");
        let instance = linker
            .instantiate_async(&mut store, &component)
            .await
            .expect("block imports satisfied");
        let execute = instance
            .get_typed_func::<(u32, u64, Vec<Range>, u64, u64), (u8,)>(
                &mut store,
                export_name("execute"),
            )
            .expect("execute exported");
        let configure = instance
            .get_typed_func(&mut store, export_name("configure"))
            .unwrap();
        let device = component
            .get_export_index(None, "terra:mmio/device@0.1.0")
            .expect("MMIO device exported");
        let serve = instance
            .get_typed_func(
                &mut store,
                component
                    .get_export_index(Some(&device), "serve")
                    .expect("MMIO server exported"),
            )
            .expect("MMIO server type matches");
        (
            linker,
            Fixture {
                store,
                execute,
                configure,
                serve,
            },
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn component_mmio_state_survives_async_calls_and_close_is_terminal() {
        let (_, mut fixture) = fixture(8, false).await;
        assert_eq!(
            fixture
                .configure
                .call_async(&mut fixture.store, (false,))
                .await
                .unwrap(),
            (Ok(()),)
        );
        assert_eq!(
            mmio(&mut fixture, Operation::Read, 0, 4, 0).await.value,
            u64::from(0x7472_6976u32)
        );
        assert_eq!(
            mmio(&mut fixture, Operation::Write, 0x070, 4, 1)
                .await
                .error,
            0
        );
        let interrupt = mmio(&mut fixture, Operation::InterruptLevel, 0, 0, 0).await;
        assert_eq!((interrupt.error, interrupt.value), (0, 0));
        assert_eq!(mmio(&mut fixture, Operation::Close, 0, 0, 0).await.error, 0);
        assert_eq!(
            fixture
                .configure
                .call_async(&mut fixture.store, (false,))
                .await
                .unwrap(),
            (Err(DeviceError::NotReady),)
        );
        assert_eq!(mmio(&mut fixture, Operation::Reset, 0, 0, 0).await.error, 0);
        assert_eq!(
            mmio(&mut fixture, Operation::Write, 0x050, 4, 0)
                .await
                .error,
            4
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn component_advertises_bounded_io_flush_and_discard() {
        let (_, mut fixture) = fixture(256, false).await;
        assert_eq!(
            fixture
                .configure
                .call_async(&mut fixture.store, (false,))
                .await
                .unwrap(),
            (Ok(()),)
        );
        assert_eq!(
            mmio(&mut fixture, Operation::Read, 0x108, 4, 0).await.value,
            u64::from(16 * 1024u32)
        );
        assert_eq!(
            mmio(&mut fixture, Operation::Read, 0x10c, 4, 0).await.value,
            4
        );
        assert_eq!(
            mmio(&mut fixture, Operation::Read, 0x010, 4, 0).await.value,
            u64::from((1u32 << 1) | (1 << 2) | (1 << 9) | (1 << 13))
        );
        assert_eq!(
            mmio(&mut fixture, Operation::Read, 0x124, 4, 0).await.value,
            terra_limits::MAX_GUEST_DISCARD_BYTES / 512
        );
        assert_eq!(
            mmio(&mut fixture, Operation::Read, 0x128, 4, 0).await.value,
            1
        );
        assert_eq!(
            mmio(&mut fixture, Operation::Write, 0x014, 4, 1)
                .await
                .error,
            0
        );
        assert_eq!(
            mmio(&mut fixture, Operation::Read, 0x010, 4, 0).await.value,
            1
        );
    }

    fn status(fixture: &Fixture) -> u8 {
        fixture
            .store
            .data()
            .guest_read(STATUS, 1)
            .expect("status readable")[0]
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn component_read_write_round_trip() {
        let (_linker, mut fixture) = fixture(8, false).await;
        fixture
            .store
            .data_mut()
            .guest_write(DATA, &[0xCDu8; 512])
            .expect("payload staged");
        let (result,) = fixture
            .execute
            .call_async(&mut fixture.store, (T_OUT, 1, one(DATA, 512), STATUS, 0))
            .await
            .expect("write runs");
        assert_eq!(result, 0);
        assert_eq!(status(&fixture), 0);
        assert!(fixture.store.data_mut().drain_signal());
        fixture
            .store
            .data_mut()
            .guest_write(DATA, &[0u8; 512])
            .expect("buffer cleared");
        let (result,) = fixture
            .execute
            .call_async(&mut fixture.store, (T_IN, 1, one(DATA, 512), STATUS, 0))
            .await
            .expect("read runs");
        assert_eq!(result, 0);
        assert_eq!(
            fixture
                .store
                .data()
                .guest_read(DATA, 512)
                .expect("read back"),
            [0xCDu8; 512]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn component_discard_reaches_the_backing_without_changing_neighbors() {
        let (_linker, mut fixture) = fixture(8, false).await;
        fixture
            .store
            .data_mut()
            .guest_write(DATA, &[0x5A; 1536])
            .expect("payload staged");
        let (status,) = fixture
            .execute
            .call_async(&mut fixture.store, (T_OUT, 0, one(DATA, 1536), STATUS, 0))
            .await
            .expect("write runs");
        assert_eq!(status, 0);

        let mut discard = [0; 16];
        discard[..8].copy_from_slice(&1_u64.to_le_bytes());
        discard[8..12].copy_from_slice(&1_u32.to_le_bytes());
        fixture
            .store
            .data_mut()
            .guest_write(DATA, &discard)
            .expect("discard range staged");
        let (status,) = fixture
            .execute
            .call_async(&mut fixture.store, (T_DISCARD, 0, one(DATA, 16), STATUS, 0))
            .await
            .expect("discard runs");
        assert_eq!(status, 0);

        let (status,) = fixture
            .execute
            .call_async(&mut fixture.store, (T_IN, 0, one(DATA, 1536), STATUS, 0))
            .await
            .expect("read runs");
        assert_eq!(status, 0);
        let contents = fixture
            .store
            .data()
            .guest_read(DATA, 1536)
            .expect("read back");
        assert_eq!(&contents[..512], &[0x5A; 512]);
        assert_eq!(&contents[512..1024], &[0; 512]);
        assert_eq!(&contents[1024..], &[0x5A; 512]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn component_scatters_across_ranges_in_order() {
        let (_linker, mut fixture) = fixture(8, false).await;
        fixture
            .store
            .data_mut()
            .guest_write(DATA, &[0x11u8; 512])
            .expect("first half staged");
        fixture
            .store
            .data_mut()
            .guest_write(DATA + 512, &[0x22u8; 512])
            .expect("second half staged");
        let ranges = vec![
            Range {
                addr: DATA,
                len: 512,
            },
            Range {
                addr: DATA + 512,
                len: 512,
            },
        ];
        let (result,) = fixture
            .execute
            .call_async(&mut fixture.store, (T_OUT, 4, ranges, STATUS, 0))
            .await
            .expect("scattered write runs");
        assert_eq!(result, 0);
        fixture
            .store
            .data_mut()
            .guest_write(DATA, &[0u8; 512])
            .expect("buffer cleared");
        fixture
            .store
            .data_mut()
            .guest_write(DATA + 512, &[0u8; 512])
            .expect("buffer cleared");
        let ranges = vec![
            Range {
                addr: DATA,
                len: 512,
            },
            Range {
                addr: DATA + 512,
                len: 512,
            },
        ];
        let (result,) = fixture
            .execute
            .call_async(&mut fixture.store, (T_IN, 4, ranges, STATUS, 0))
            .await
            .expect("scattered read runs");
        assert_eq!(result, 0);
        assert_eq!(
            fixture
                .store
                .data()
                .guest_read(DATA, 512)
                .expect("first back"),
            [0x11u8; 512]
        );
        assert_eq!(
            fixture
                .store
                .data()
                .guest_read(DATA + 512, 512)
                .expect("second back"),
            [0x22u8; 512]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn component_readonly_and_oob_are_ioerr() {
        let (_linker, mut fixture) = fixture(8, true).await;
        fixture
            .store
            .data_mut()
            .guest_write(DATA, &[0xCDu8; 512])
            .expect("payload staged");
        let (result,) = fixture
            .execute
            .call_async(&mut fixture.store, (T_OUT, 0, one(DATA, 512), STATUS, 0))
            .await
            .expect("denial completes");
        assert_eq!(result, 1);
        assert_eq!(status(&fixture), 1);
        let (result,) = fixture
            .execute
            .call_async(&mut fixture.store, (T_IN, 8, one(DATA, 512), STATUS, 0))
            .await
            .expect("past-end completes");
        assert_eq!(result, 1);
        let (result,) = fixture
            .execute
            .call_async(
                &mut fixture.store,
                (T_IN, u64::MAX, one(DATA, 512), STATUS, 0),
            )
            .await
            .expect("overflow completes");
        assert_eq!(result, 1);
        let (result,) = fixture
            .execute
            .call_async(&mut fixture.store, (T_IN, 0, one(DATA, 1 << 20), STATUS, 0))
            .await
            .expect("oversized completes");
        assert_eq!(result, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn component_flush_identify_and_unsupported() {
        let (_linker, mut fixture) = fixture(8, false).await;
        let (result,) = fixture
            .execute
            .call_async(&mut fixture.store, (T_FLUSH, 0, vec![], STATUS, 0))
            .await
            .expect("flush runs");
        assert_eq!(result, 0);
        assert!(fixture.store.data_mut().drain_signal());
        let (result,) = fixture
            .execute
            .call_async(&mut fixture.store, (0xFFFF, 0, one(DATA, 512), STATUS, 0))
            .await
            .expect("unknown type completes");
        assert_eq!(result, 2);
        assert_eq!(status(&fixture), 2);
        assert!(fixture.store.data_mut().drain_signal());
        let (result,) = fixture
            .execute
            .call_async(&mut fixture.store, (T_GET_ID, 0, one(DATA, 512), STATUS, 0))
            .await
            .expect("identify runs");
        assert_eq!(result, 0);
        assert!(fixture.store.data_mut().drain_signal());
        assert_eq!(
            &fixture.store.data().guest_read(DATA, 12).expect("id back")[..],
            b"terra-vda\0\0\0"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn component_reset_fences_stale_epoch() {
        let (_linker, mut fixture) = fixture(8, false).await;
        fixture
            .store
            .data_mut()
            .guest_write(DATA, &[0xCDu8; 512])
            .expect("payload staged");
        let (result,) = fixture
            .execute
            .call_async(&mut fixture.store, (T_OUT, 0, one(DATA, 512), STATUS, 0))
            .await
            .expect("write runs");
        assert_eq!(result, 0);
        assert_eq!(mmio(&mut fixture, Operation::Reset, 0, 0, 0).await.error, 0);
        fixture
            .store
            .data_mut()
            .guest_write(STATUS, &[0xFFu8; 1])
            .expect("status armed");
        let (result,) = fixture
            .execute
            .call_async(&mut fixture.store, (T_OUT, 1, one(DATA, 512), STATUS, 0))
            .await
            .expect("stale completes");
        assert_eq!(result, 1);
        assert_eq!(status(&fixture), 0xFF);
        let (result,) = fixture
            .execute
            .call_async(&mut fixture.store, (T_OUT, 1, one(DATA, 512), STATUS, 1))
            .await
            .expect("current epoch runs");
        assert_eq!(result, 0);
        assert_eq!(status(&fixture), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(unsafe_code)]
    async fn component_aot_deserialize_runs() {
        let engine = device_engine().expect("engine builds");
        let linker = block_component_linker(&engine).expect("block imports link");
        let artifact = precompile_component(&engine, &component_bytes()).expect("precompiles");
        assert!(!artifact.is_empty());
        // SAFETY: artifact was just produced by the trusted build above
        // from the checked-in component source; deserialization performs
        // compatibility checks but not validation of arbitrary bytes.
        let component =
            unsafe { Component::deserialize(&engine, &artifact).expect("deserializes") };
        let mut store = device_store(&engine, RAM).expect("store builds");
        store
            .data_mut()
            .set_disk(DiskGrant::Mem(BoundedDisk::new(8 * 512, false)));
        let instance: Instance = linker
            .instantiate_async(&mut store, &component)
            .await
            .expect("aot imports satisfied");
        let execute = instance
            .get_typed_func::<(u32, u64, Vec<Range>, u64, u64), (u8,)>(
                &mut store,
                export_name("execute"),
            )
            .expect("execute exported");
        let execute_chain = instance
            .get_typed_func::<(u16, u64, u16, u64), (Result<Completion, DeviceError>,)>(
                &mut store,
                export_name("execute-chain"),
            )
            .expect("execute-chain exported");
        let mut header = [0; 16];
        header[..4].copy_from_slice(&T_IN.to_le_bytes());
        store
            .data_mut()
            .guest_write(0x1000, &header)
            .expect("header fits");
        let descriptors = [
            (0x1000u64, 16u32, 1u16, 1u16),
            (DATA, 512, 1 | 2, 2),
            (STATUS, 1, 2, 0),
        ];
        for (index, (addr, len, flags, next)) in descriptors.into_iter().enumerate() {
            let mut descriptor = [0; 16];
            descriptor[..8].copy_from_slice(&addr.to_le_bytes());
            descriptor[8..12].copy_from_slice(&len.to_le_bytes());
            descriptor[12..14].copy_from_slice(&flags.to_le_bytes());
            descriptor[14..].copy_from_slice(&next.to_le_bytes());
            store
                .data_mut()
                .guest_write(
                    0x4000 + u64::try_from(index).expect("index fits") * 16,
                    &descriptor,
                )
                .expect("descriptor fits");
        }
        let (completion,) = execute_chain
            .call_async(&mut store, (0, 0x4000, 8, 0))
            .await
            .expect("aot chain runs");
        assert_eq!(completion.expect("chain completes").used_len, 513);
        let (result,) = execute
            .call_async(&mut store, (T_FLUSH, 0, vec![], STATUS, 0))
            .await
            .expect("aot flush runs");
        assert_eq!(result, 0);
        assert_eq!(
            store.data().guest_read(STATUS, 1).expect("status readable")[0],
            0
        );
    }

    #[test]
    fn synthetic_ram_shapes_match() {
        assert!(SyntheticRam::new(RAM).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn shared_ram_aliases_one_mapping() {
        use super::super::BoundedMemory;
        use std::sync::Arc;
        use vm_memory::{Bytes as _, GuestAddress, GuestMemoryMmap};
        let mem = Arc::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 64 * 1024)]).expect("maps"),
        );
        let first = SyntheticRam::from_shared(Arc::clone(&mem)).expect("aliases");
        let second = SyntheticRam::from_shared(Arc::clone(&mem)).expect("aliases");
        assert_eq!(first.size(), 64 * 1024);
        BoundedMemory::new(&first)
            .write(512, b"shared")
            .expect("writes");
        assert_eq!(
            BoundedMemory::new(&second).read(512, 6).expect("reads"),
            b"shared"
        );
        let mut back = [0u8; 6];
        mem.read_slice(&mut back, GuestAddress(512))
            .expect("mapped");
        assert_eq!(&back, b"shared");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn component_operates_on_shared_machine_ram() {
        use super::super::engine::device_store_with_ram;
        use std::sync::Arc;
        use vm_memory::{Bytes as _, GuestAddress, GuestMemoryMmap};
        let engine = device_engine().expect("engine builds");
        let linker = block_component_linker(&engine).expect("block imports link");
        let mem = Arc::new(
            GuestMemoryMmap::<()>::from_ranges(&[(
                GuestAddress(0),
                usize::try_from(RAM).expect("test RAM fits"),
            )])
            .expect("maps"),
        );
        let ram = SyntheticRam::from_shared(Arc::clone(&mem)).expect("aliases");
        let mut store = device_store_with_ram(&engine, ram);
        let mut disk = BoundedDisk::new(8 * 512, false);
        disk.write(2 * 512, &[0x5Eu8; 512]).expect("pattern in");
        store.data_mut().set_disk(DiskGrant::Mem(disk));
        let component =
            Component::new(&engine, component_bytes()).expect("block component compiles");
        let instance = linker
            .instantiate_async(&mut store, &component)
            .await
            .expect("shared imports satisfied");
        let execute = instance
            .get_typed_func::<(u32, u64, Vec<Range>, u64, u64), (u8,)>(
                &mut store,
                export_name("execute"),
            )
            .expect("execute exported");
        let (result,) = execute
            .call_async(&mut store, (T_IN, 2, one(DATA, 512), STATUS, 0))
            .await
            .expect("read runs");
        assert_eq!(result, 0);
        // The component wrote through the shared mapping, not a copy:
        // the bytes are visible on the other alias with no round trip.
        let mut back = [0u8; 512];
        mem.read_slice(&mut back, GuestAddress(DATA))
            .expect("mapped");
        assert_eq!(back, [0x5Eu8; 512]);
        let mut status = [0u8; 1];
        mem.read_slice(&mut status, GuestAddress(STATUS))
            .expect("mapped");
        assert_eq!(status, [0]);
    }
}

mod file_backend {
    use super::super::component::block::backing::{
        BackingError, BlockBacking, BlockDevice, FileDisk, STATUS_IOERR, STATUS_OK,
    };
    use super::{
        BLK_DATA, BLK_HDR, BLK_STATUS, blk_ram, in_chain_1sector, out_chain_1sector, status_byte,
        write_blk_hdr,
    };
    use super::{BoundedMemory, blk};
    use std::io::Write as _;

    fn backing_file(sectors: u64) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.as_file_mut()
            .set_len(sectors * 512)
            .expect("pre-grown");
        file.as_file_mut().write_all(&[0u8; 512]).expect("zeroed");
        file
    }

    fn file_device(path: &std::path::Path, readonly: bool) -> BlockDevice<FileDisk> {
        BlockDevice::with_backing(
            FileDisk::open(path, readonly).expect("disk opens"),
            b"terra-vda",
        )
    }

    #[test]
    fn file_round_trip_persists_across_reopen() {
        let ram = blk_ram();
        let mem = BoundedMemory::new(&ram);
        let file = backing_file(8);
        mem.write(BLK_DATA, &[0xABu8; 512]).expect("payload fits");
        write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 3);
        {
            let mut dev = file_device(file.path(), false);
            let written = dev
                .execute(&mem, &out_chain_1sector(), 0, ram.size(), 0)
                .expect("write completes");
            assert_eq!(written.status, STATUS_OK);
            assert_eq!(status_byte(&mem), STATUS_OK);
            write_blk_hdr(&mem, blk::VIRTIO_BLK_T_FLUSH, 0);
            let bare = vec![
                super::Descriptor::readable(BLK_HDR, 16, Some(1)),
                super::Descriptor::writable(BLK_STATUS, 1, None),
            ];
            dev.execute(&mem, &bare, 0, ram.size(), 0)
                .expect("flush completes");
        }
        let mut dev = file_device(file.path(), false);
        mem.write(BLK_DATA, &[0u8; 512]).expect("clear buffer");
        write_blk_hdr(&mem, blk::VIRTIO_BLK_T_IN, 3);
        dev.execute(&mem, &in_chain_1sector(), 0, ram.size(), 0)
            .expect("read completes");
        assert_eq!(mem.read(BLK_DATA, 512).expect("read back"), [0xABu8; 512]);
    }

    #[test]
    fn file_capacity_is_fixed_at_open() {
        let ram = blk_ram();
        let mem = BoundedMemory::new(&ram);
        let file = backing_file(4);
        let mut dev = file_device(file.path(), false);
        mem.write(BLK_DATA, &[0xABu8; 512]).expect("payload fits");
        write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 4);
        let past_end = dev
            .execute(&mem, &out_chain_1sector(), 0, ram.size(), 0)
            .expect("completes with error status");
        assert_eq!(past_end.status, STATUS_IOERR);
        assert_eq!(
            std::fs::metadata(file.path()).expect("stat").len(),
            4 * 512,
            "rejected writes never extend the image"
        );
    }

    #[test]
    fn file_readonly_resists_writes() {
        let ram = blk_ram();
        let mem = BoundedMemory::new(&ram);
        let file = backing_file(4);
        let mut dev = file_device(file.path(), true);
        mem.write(BLK_DATA, &[0xABu8; 512]).expect("payload fits");
        write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 0);
        let written = dev
            .execute(&mem, &out_chain_1sector(), 0, ram.size(), 0)
            .expect("well-formed request still completes");
        assert_eq!(written.status, STATUS_IOERR);
        let raw = std::fs::read(file.path()).expect("image readable");
        assert_eq!(&raw[..512], &[0u8; 512]);
        write_blk_hdr(&mem, blk::VIRTIO_BLK_T_IN, 0);
        dev.execute(&mem, &in_chain_1sector(), 0, ram.size(), 0)
            .expect("read completes");
    }

    struct FailDisk;

    impl BlockBacking for FailDisk {
        fn capacity(&self) -> u64 {
            8 * 512
        }

        fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<(), BackingError> {
            buf.fill(0);
            Ok(())
        }

        fn write_at(&mut self, _offset: u64, _buf: &[u8]) -> Result<(), BackingError> {
            Err(BackingError::Io)
        }

        fn discard(&mut self, _offset: u64, _len: u64) -> Result<(), BackingError> {
            Err(BackingError::Io)
        }

        fn sync(&self) -> Result<(), BackingError> {
            Err(BackingError::Io)
        }
    }

    #[test]
    fn host_io_errors_complete_as_ioerr() {
        let ram = blk_ram();
        let mem = BoundedMemory::new(&ram);
        let mut dev = BlockDevice::with_backing(FailDisk, b"terra-vda");
        mem.write(BLK_DATA, &[0xABu8; 512]).expect("payload fits");
        write_blk_hdr(&mem, blk::VIRTIO_BLK_T_OUT, 0);
        let written = dev
            .execute(&mem, &out_chain_1sector(), 0, ram.size(), 0)
            .expect("completes with error status");
        assert_eq!(written.status, STATUS_IOERR);
        write_blk_hdr(&mem, blk::VIRTIO_BLK_T_FLUSH, 0);
        let bare = vec![
            super::Descriptor::readable(BLK_HDR, 16, Some(1)),
            super::Descriptor::writable(BLK_STATUS, 1, None),
        ];
        let flushed = dev
            .execute(&mem, &bare, 0, ram.size(), 0)
            .expect("flush completes");
        assert_eq!(flushed.status, STATUS_IOERR);
    }
}

#[cfg(test)]
mod vsock_tests {
    use super::super::component::vsock::protocol::{
        AGENT_VSOCK_PORT, CONTROL_VSOCK_PORT, GUEST_CID, HOST_CID, MAX_DATA_BYTES,
        MAX_QUEUED_REPLIES, MAX_TX_BYTES, RX_ALLOC, VsockHeader, VsockSwitch,
    };

    fn guest(op: u16, src_port: u32, dst_port: u32, len: u32, fwd: u32) -> VsockHeader {
        VsockHeader {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port,
            dst_port,
            len,
            type_: 1,
            op,
            flags: 0,
            buf_alloc: RX_ALLOC,
            fwd_cnt: fwd,
        }
    }

    #[test]
    fn ports_come_from_the_shared_contract() {
        assert_eq!(AGENT_VSOCK_PORT, 6000);
        assert_eq!(CONTROL_VSOCK_PORT, 6001);
    }

    #[test]
    fn header_pins_kernel_abi_offsets() {
        let header = guest(5, 100, CONTROL_VSOCK_PORT, 3, 7);
        let bytes = header.encode();
        assert_eq!(
            u64::from_le_bytes(bytes[0..8].try_into().expect("fits")),
            GUEST_CID
        );
        assert_eq!(
            u64::from_le_bytes(bytes[8..16].try_into().expect("fits")),
            HOST_CID
        );
        assert_eq!(
            u32::from_le_bytes(bytes[16..20].try_into().expect("fits")),
            100
        );
        assert_eq!(
            u32::from_le_bytes(bytes[24..28].try_into().expect("fits")),
            3
        );
        assert_eq!(
            u16::from_le_bytes(bytes[28..30].try_into().expect("fits")),
            1
        );
        assert_eq!(
            u16::from_le_bytes(bytes[30..32].try_into().expect("fits")),
            5
        );
        assert_eq!(
            u32::from_le_bytes(bytes[40..44].try_into().expect("fits")),
            7
        );
        let (back, rest) = VsockHeader::parse(&bytes).expect("parses");
        assert_eq!(back, header);
        assert!(rest.is_empty());
        assert!(VsockHeader::parse(&bytes[..43]).is_err());
    }

    #[test]
    fn guest_connect_gets_response() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        let replies = switch.take_replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].header.op, 2);
        assert_eq!(replies[0].header.src_cid, HOST_CID);
        assert_eq!(replies[0].header.dst_cid, GUEST_CID);
        assert_eq!(replies[0].header.src_port, CONTROL_VSOCK_PORT);
        assert_eq!(replies[0].header.dst_port, 100);
        assert_eq!(replies[0].header.buf_alloc, RX_ALLOC);
        assert_eq!(switch.connection_count(), 1);
    }

    #[test]
    fn wrong_port_cid_or_type_gets_rst() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(1, 100, AGENT_VSOCK_PORT, 0, 0), &[]);
        switch.rx(&guest(5, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        let mut bad_cid = guest(1, 100, CONTROL_VSOCK_PORT, 0, 0);
        bad_cid.src_cid = 9;
        switch.rx(&bad_cid, &[]);
        let mut bad_type = guest(1, 101, CONTROL_VSOCK_PORT, 0, 0);
        bad_type.type_ = 2;
        switch.rx(&bad_type, &[]);
        let replies = switch.take_replies();
        assert_eq!(replies.len(), 4);
        assert!(replies.iter().all(|reply| reply.header.op == 3));
        assert_eq!(switch.connection_count(), 0);
    }

    #[test]
    fn data_flows_upstream_with_credit() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        switch.take_replies();
        switch.rx(&guest(5, 100, CONTROL_VSOCK_PORT, 5, 0), b"hello");
        assert!(switch.take_replies().is_empty());
        let upstream = switch.take_upstream();
        assert_eq!(upstream.len(), 1);
        assert_eq!(upstream[0].data, b"hello");
        let replies = switch.take_replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].header.op, 6);
        assert_eq!(replies[0].header.fwd_cnt, 5);
        switch.rx(&guest(5, 100, CONTROL_VSOCK_PORT, 5, 0), b"world");
        assert_eq!(switch.take_upstream().len(), 1);
    }

    #[test]
    fn over_credit_gets_rst_and_recycled() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        switch.take_replies();
        let flood = vec![0u8; MAX_DATA_BYTES as usize];
        switch.rx(
            &guest(5, 100, CONTROL_VSOCK_PORT, MAX_DATA_BYTES, 0),
            &flood,
        );
        assert!(switch.take_replies().is_empty());
        switch.rx(&guest(5, 100, CONTROL_VSOCK_PORT, 1, 0), b"x");
        let replies = switch.take_replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].header.op, 3);
        assert_eq!(switch.connection_count(), 0);
    }

    #[test]
    fn stalled_consumer_withholds_credit_until_drained() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        switch.take_replies();
        switch.rx(&guest(5, 100, CONTROL_VSOCK_PORT, 5, 0), b"hello");
        assert!(switch.take_replies().is_empty());
        switch.rx(&guest(5, 100, CONTROL_VSOCK_PORT, 5, 0), b"world");
        assert!(switch.take_replies().is_empty());
        assert_eq!(switch.take_upstream().len(), 2);
        let replies = switch.take_replies();
        assert_eq!(replies.len(), 2);
        assert!(replies.iter().all(|reply| reply.header.op == 6));
        assert_eq!(replies[1].header.fwd_cnt, 10);
    }

    #[test]
    fn repeated_reset_traffic_stays_bounded() {
        let mut switch = VsockSwitch::new();
        for port in 0..200 {
            switch.rx(&guest(5, 9000 + port, CONTROL_VSOCK_PORT, 5, 0), b"hello");
        }
        assert!(switch.take_replies().len() <= MAX_QUEUED_REPLIES);
        assert_eq!(switch.connection_count(), 0);
        switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        switch.take_replies();
        for _ in 0..200 {
            switch.rx(&guest(99, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        }
        assert!(switch.take_replies().len() <= MAX_QUEUED_REPLIES);
        assert_eq!(switch.connection_count(), 1);
    }

    #[test]
    fn forged_credit_ahead_resets_without_freeing() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        switch.take_replies();
        switch
            .deliver(100, CONTROL_VSOCK_PORT, b"hello")
            .expect("fits in window");
        switch.take_replies();
        switch.rx(&guest(6, 100, CONTROL_VSOCK_PORT, 0, 5000), &[]);
        let replies = switch.take_replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].header.op, 3);
        assert_eq!(switch.connection_count(), 0);
    }

    #[test]
    fn credit_wrap_compares_by_distance() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        switch.take_replies();
        switch
            .deliver(100, CONTROL_VSOCK_PORT, &[9u8; 1024])
            .expect("fits");
        switch.take_replies();
        switch.rx(&guest(6, 100, CONTROL_VSOCK_PORT, 0, 1024), &[]);
        assert!(switch.take_replies().is_empty());
        let big = vec![7u8; MAX_TX_BYTES];
        assert!(switch.deliver(100, CONTROL_VSOCK_PORT, &big).is_err());
    }

    #[test]
    fn len_mismatch_and_bad_op_get_rst() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        switch.take_replies();
        switch.rx(&guest(5, 100, CONTROL_VSOCK_PORT, 5, 0), b"abc");
        switch.rx(&guest(99, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        let replies = switch.take_replies();
        assert_eq!(replies.len(), 2);
        assert!(replies.iter().all(|reply| reply.header.op == 3));
        assert_eq!(switch.connection_count(), 1);
    }

    #[test]
    fn duplicate_request_gets_rst() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        switch.take_replies();
        switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        let replies = switch.take_replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].header.op, 3);
        assert_eq!(switch.connection_count(), 1);
    }

    #[test]
    fn rw_on_unknown_gets_rst() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(5, 100, CONTROL_VSOCK_PORT, 5, 0), b"hello");
        let replies = switch.take_replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].header.op, 3);
    }

    #[test]
    fn shutdown_both_directions_recycles() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        switch.take_replies();
        let mut send = guest(4, 100, CONTROL_VSOCK_PORT, 0, 0);
        send.flags = 2;
        switch.rx(&send, &[]);
        assert_eq!(switch.connection_count(), 1);
        let echo = switch.take_replies();
        assert_eq!(echo.len(), 1);
        assert_eq!(echo[0].header.op, 4);
        let mut rcv = guest(4, 100, CONTROL_VSOCK_PORT, 0, 0);
        rcv.flags = 1;
        switch.rx(&rcv, &[]);
        assert_eq!(switch.connection_count(), 0);
        assert!(switch.take_replies().is_empty());
    }

    #[test]
    fn rst_recycles() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        switch.take_replies();
        switch.rx(&guest(3, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        assert_eq!(switch.connection_count(), 0);
        assert!(switch.take_replies().is_empty());
    }

    #[test]
    fn guest_connection_cap_preserves_host_capacity() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(1, 1000, CONTROL_VSOCK_PORT, 0, 0), &[]);
        switch.rx(&guest(1, 1001, CONTROL_VSOCK_PORT, 0, 0), &[]);
        let replies = switch.take_replies();
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0].header.op, 2);
        assert_eq!(replies[1].header.op, 3);
        assert_eq!(switch.connection_count(), 1);
        assert!(switch.connect(AGENT_VSOCK_PORT).is_ok());
        assert_eq!(switch.connection_count(), 2);
    }

    #[test]
    fn host_initiated_connect_completes_on_response() {
        let mut switch = VsockSwitch::new();
        let ephemeral = switch.connect(AGENT_VSOCK_PORT).expect("connects");
        let request = switch.take_replies();
        assert_eq!(request.len(), 1);
        assert_eq!(request[0].header.op, 1);
        assert_eq!(request[0].header.src_port, ephemeral);
        assert_eq!(request[0].header.dst_port, AGENT_VSOCK_PORT);
        assert!(
            switch
                .deliver(AGENT_VSOCK_PORT, ephemeral, b"early")
                .is_err()
        );
        switch.rx(&guest(2, AGENT_VSOCK_PORT, ephemeral, 0, 0), &[]);
        assert_eq!(switch.connection_count(), 1);
        switch
            .deliver(AGENT_VSOCK_PORT, ephemeral, b"hello")
            .expect("delivers");
        let replies = switch.take_replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].header.op, 5);
        assert_eq!(replies[0].payload, b"hello");
        switch.rx(&guest(6, AGENT_VSOCK_PORT, ephemeral, 0, 5), &[]);
        assert!(switch.take_replies().is_empty());
        assert!(switch.connect(6002).is_err());
    }

    #[test]
    fn deliver_honors_peer_window_and_cap() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
        switch.take_replies();
        let big = vec![0u8; RX_ALLOC as usize + 1];
        assert!(switch.deliver(100, CONTROL_VSOCK_PORT, &big).is_err());
        let mut wide = guest(1, 101, CONTROL_VSOCK_PORT, 0, 0);
        wide.buf_alloc = u32::MAX;
        switch.rx(&wide, &[]);
        switch.take_replies();
        let huge = vec![0u8; 257 * 1024];
        assert!(switch.deliver(101, CONTROL_VSOCK_PORT, &huge).is_err());
        assert!(switch.deliver(999, CONTROL_VSOCK_PORT, b"x").is_err());
    }
}

fn kernel_boot_assets() -> (Vec<u8>, Vec<u8>, tempfile::TempPath) {
    use std::io::Read;
    let build = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build");
    let decode = |name| {
        flate2::read::GzDecoder::new(
            std::fs::File::open(build.join(name)).expect("run `make build` first"),
        )
    };
    let mut kernel = Vec::new();
    decode("vmlinux.gz").read_to_end(&mut kernel).unwrap();
    let stage_disk = |name| {
        let mut disk = tempfile::NamedTempFile::new().unwrap();
        std::io::copy(&mut decode(name), &mut disk).unwrap();
        disk.into_temp_path()
    };
    let mut boot_disk = Vec::new();
    decode("boot.img.gz").read_to_end(&mut boot_disk).unwrap();
    (kernel, boot_disk, stage_disk("rootfs.img.gz"))
}

/// Boot plan proving agent readiness end to end: Create mode with one
/// hook asserting every online CPU the machine was given. A hook
/// failure is the agent's nonzero exit report, so SMP rides the same
/// frame as the boot.
fn boot_plan(
    mode: terra_protocol::PlanMode,
    on_create: Vec<String>,
    workload: Vec<String>,
    await_initial_session: bool,
) -> Vec<u8> {
    use std::collections::BTreeMap;
    use terra_protocol::{Net, Plan, encode_frame};
    let plan = Plan {
        mode,
        workdir: None,
        shares: Vec::new(),
        volumes: Vec::new(),
        net: Net {
            guest_ip: std::net::IpAddr::V4(terra_network::GuestNetworkConfig::default().guest_ip),
            prefix: terra_network::GuestNetworkConfig::default().prefix_len,
            gateway: std::net::IpAddr::V4(terra_network::GuestNetworkConfig::default().gateway_ip),
            dns: std::net::IpAddr::V4(terra_network::GuestNetworkConfig::default().dns_server),
        },
        env: BTreeMap::new(),
        root: true,
        sudo: Vec::new(),
        on_create,
        on_start: Vec::new(),
        pre_stop: Vec::new(),
        daemons: Vec::new(),
        workload,
        sandbox_info: String::new(),
        await_initial_session,
        host_tz: None,
        host_time: None,
        host_seed: None,
    };
    encode_frame(&plan).expect("plan encodes")
}

fn boot_probe_plan(vcpus: usize) -> Vec<u8> {
    boot_plan(
        terra_protocol::PlanMode::Create,
        vec![format!("test $(nproc) = {vcpus}")],
        Vec::new(),
        false,
    )
}

fn agent_bridge_plan() -> Vec<u8> {
    boot_plan(
        terra_protocol::PlanMode::Run,
        Vec::new(),
        vec!["sleep".into(), "15".into()],
        false,
    )
}

fn boot_artifacts() -> super::worker::TrustedArtifacts {
    // SAFETY: these build-tree artifacts are trusted AOT output for this binary's Wasmtime.
    #[allow(unsafe_code)]
    unsafe {
        super::worker::TrustedArtifacts::new(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../build/terra-block-component.cwasm"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../build/terra-vsock-component.cwasm"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../build/terra-network-component.cwasm"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../build/terra-fs-component.cwasm"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../build/terra-mem-component.cwasm"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../build/terra-boot-component.cwasm"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../build/terra-vmm-component.cwasm"
            )),
        )
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor and `make test-component-boot`"]
async fn kernel_boots_directory_share() {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use terra_protocol::{Plan, PlanMode, Share, encode_frame, read_frame};
    let directory = tempfile::tempdir().unwrap();
    let mount = std::fs::canonicalize(directory.path()).unwrap();
    std::fs::write(directory.path().join("host-file"), "host-data").unwrap();
    std::fs::write(directory.path().join("large-host"), vec![b'x'; 65_537]).unwrap();
    let executable = directory.path().join("script");
    std::fs::write(&executable, "#!/bin/sh\necho executed\n").unwrap();
    #[cfg(unix)]
    {
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();
    }
    let tag = super::component::fs::host::share_tag(0);
    let encoded = boot_plan(PlanMode::Run, Vec::new(), vec!["/bin/true".into()], false);
    let mut plan: Plan = read_frame(&mut encoded.as_slice()).unwrap().unwrap();
    plan.on_start.push("set -ex; test $(/work/script) = executed; test $(cat /work/host-file) = host-data; printf guest-data >/work/guest-file; ln /work/guest-file /work/hardlink; ln -s guest-file /work/link; test $(cat /work/link) = guest-data; mv /work/guest-file /work/renamed; test $(cat /work/hardlink) = guest-data; cp /work/large-host /work/large-copy; cmp /work/large-host /work/large-copy; test $(wc -c </work/large-copy) = 65537; sync".into());
    let diagnostics = tempfile::NamedTempFile::new().unwrap();
    plan.shares.push(Share {
        tag,
        guest: "/work".into(),
        readonly: false,
    });
    let (kernel, boot_disk, root_disk) = kernel_boot_assets();
    let outcome = super::worker::run(super::worker::WorkerInput {
        component_memory_limits: terra_runtime::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_disk.to_path_buf(),
        volume_disks: Vec::new(),
        shares: vec![super::component::fs::host::ShareGrant::new(&mount, false).unwrap()],
        plan: encode_frame(&plan).unwrap(),
        artifacts: boot_artifacts(),
        network_policy: boot_network_policy(),
        port_mappings: Vec::new(),
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_mins(1)),
        hard_stop: None,
        listener: None,
        control: None,
        diagnostics: Some(diagnostics.reopen().unwrap()),
    })
    .await
    .expect("shared directory worker runs");
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{outcome:?}\n{}",
        std::fs::read_to_string(diagnostics.path()).unwrap()
    );
    assert_eq!(
        std::fs::read(directory.path().join("renamed")).unwrap(),
        b"guest-data"
    );
    assert_eq!(
        std::fs::read(directory.path().join("large-copy")).unwrap(),
        vec![b'x'; 65_537]
    );
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(directory.path().join("renamed"))
            .unwrap()
            .nlink(),
        2
    );
}

struct DenyAllPolicy;

impl terra_network::Policy for DenyAllPolicy {
    fn allows(&self, _: std::net::IpAddr, _: Option<u16>) -> bool {
        false
    }
}

fn boot_network_policy() -> terra_network::PolicyHandle {
    std::sync::Arc::new(DenyAllPolicy)
}

/// 512 MiB of guest RAM for the kernel boot: kernel, Alpine
/// userspace, and page cache with room to spare.
const BOOT_RAM: u64 = 512 << 20;

/// Phase 1B gate: the pinned kernel boots on two vCPUs with both disks
/// behind real block components, the agent dials the control port over
/// the native vsock bridge, reads its plan, proves both CPUs online,
/// and reports success. `TERRA_BOOT_TRACE=1` logs MSR/EOI flow.
#[tokio::test]
#[ignore = "requires a native hypervisor and `make test-component-boot`"]
async fn kernel_boots_to_agent_ready() {
    let vcpus: usize = if std::env::var_os("TERRA_BOOT_ONE_CPU").is_some() {
        1
    } else {
        2
    };
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let outcome = super::worker::run(super::worker::WorkerInput {
        component_memory_limits: terra_runtime::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: boot_probe_plan(vcpus),
        artifacts: boot_artifacts(),
        network_policy: boot_network_policy(),
        port_mappings: Vec::new(),
        hard_stop: None,
        ram_bytes: BOOT_RAM,
        vcpus,
        deadline: Some(std::time::Duration::from_secs(150)),
        listener: None,
        control: None,
        diagnostics: None,
    })
    .await
    .expect("worker runs");
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "agent control outcome: {outcome:?}"
    );
}

#[tokio::test]
#[ignore = "requires a native hypervisor and `make test-component-boot`"]
async fn kernel_reports_free_pages_after_boot() {
    let vcpus: usize = if std::env::var_os("TERRA_BOOT_ONE_CPU").is_some() {
        1
    } else {
        2
    };
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let outcome = super::worker::run(super::worker::WorkerInput {
        component_memory_limits: terra_runtime::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: boot_plan(
            terra_protocol::PlanMode::Run,
            Vec::new(),
            vec!["sleep".into(), "4".into()],
            false,
        ),
        artifacts: boot_artifacts(),
        network_policy: boot_network_policy(),
        port_mappings: Vec::new(),
        hard_stop: None,
        ram_bytes: 2048 << 20,
        vcpus,
        deadline: Some(std::time::Duration::from_secs(150)),
        listener: None,
        control: None,
        diagnostics: None,
    })
    .await
    .expect("worker runs");
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "agent control outcome: {outcome:?}"
    );
}

fn bridge_listener() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    terra_io::local::LocalListener,
) {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().expect("temporary socket directory");
    let path = dir.path().join("agent.sock");
    let listener = terra_io::local::LocalListener::bind(&path).expect("bind agent socket");
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("secure agent socket");
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(&path)
            .expect("agent socket metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    (dir, path, listener)
}

fn connect_agent(path: &std::path::Path) -> std::io::Result<terra_io::local::LocalStream> {
    use std::io::Read as _;
    use terra_protocol::AGENT_HELLO;

    let deadline = std::time::Instant::now() + std::time::Duration::from_mins(2);
    loop {
        let attempt = (|| {
            let mut stream = terra_io::local::LocalStream::connect(path)?;
            stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
            let mut hello = [0; AGENT_HELLO.len()];
            stream.read_exact(&mut hello)?;
            if hello != AGENT_HELLO {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "agent hello mismatch",
                ));
            }
            Ok(stream)
        })();
        match attempt {
            Ok(stream) => return Ok(stream),
            Err(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    }
}

fn assert_agent_control_and_exec(path: &std::path::Path) -> std::io::Result<()> {
    use std::io::Write as _;
    use terra_protocol::{AgentService, ControlReply, ControlRequest, encode_frame, read_frame};

    let mut control = connect_agent(path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("connecting session-control service: {error}"),
        )
    })?;
    control.write_all(&encode_frame(&AgentService::SessionControl)?)?;
    control.write_all(&encode_frame(&ControlRequest::List)?)?;
    let control_reply = read_frame::<ControlReply>(&mut control).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("reading session-control reply: {error}"),
        )
    })?;
    assert_eq!(
        control_reply,
        Some(ControlReply::Done),
        "empty session has no attached clients"
    );

    assert_eq!(
        agent_exec(path, &["printf", "agent-bridge"])?,
        b"agent-bridge"
    );
    Ok(())
}

fn agent_exec(path: &std::path::Path, argv: &[&str]) -> std::io::Result<Vec<u8>> {
    use std::io::Write as _;
    use terra_protocol::{AgentOutput, AgentService, ExecRequest, encode_frame, read_frame};

    let mut exec = connect_agent(path).map_err(|error| {
        std::io::Error::new(error.kind(), format!("connecting exec service: {error}"))
    })?;
    exec.write_all(&encode_frame(&AgentService::Exec)?)?;
    exec.write_all(&encode_frame(&ExecRequest {
        argv: argv.iter().map(ToString::to_string).collect(),
        as_root: true,
        tty: None,
        workdir: None,
        env: std::collections::BTreeMap::new(),
    })?)?;
    let mut output = Vec::new();
    loop {
        match read_frame::<AgentOutput>(&mut exec)? {
            Some(AgentOutput::Out(bytes) | AgentOutput::Err(bytes)) => {
                output.extend_from_slice(&bytes);
            }
            Some(AgentOutput::Exit { code }) => {
                if code != 0 {
                    return Err(std::io::Error::other(format!(
                        "agent exec exits {code}: {}",
                        String::from_utf8_lossy(&output)
                    )));
                }
                break;
            }
            Some(AgentOutput::Detached) => panic!("exec service detached"),
            None => panic!("agent exec closed before its exit frame"),
        }
    }
    Ok(output)
}

fn await_foreground_workload(path: &std::path::Path) -> std::io::Result<(Vec<u8>, i32)> {
    use std::io::Write as _;
    use terra_protocol::{AgentOutput, AgentService, encode_frame, read_frame};

    let mut session = connect_agent(path)?;
    session.write_all(&encode_frame(&AgentService::Session)?)?;
    let mut output = Vec::new();
    loop {
        match read_frame::<AgentOutput>(&mut session)? {
            Some(AgentOutput::Out(bytes) | AgentOutput::Err(bytes)) => {
                output.extend_from_slice(&bytes);
            }
            Some(AgentOutput::Exit { code }) => return Ok((output, code)),
            Some(AgentOutput::Detached) => {
                return Err(std::io::Error::other("foreground session detached"));
            }
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "foreground session closed before its exit frame",
                ));
            }
        }
    }
}

struct LocalHttpPolicy {
    address: std::net::IpAddr,
    port: u16,
}

impl terra_network::Policy for LocalHttpPolicy {
    fn allows(&self, ip: std::net::IpAddr, port: Option<u16>) -> bool {
        ip == self.address && port == Some(self.port)
    }

    fn lookup_name(&self, _: &str) -> terra_network::NameLookup {
        terra_network::NameLookup::Static(vec![self.address])
    }

    fn blocks_direct_dns(&self) -> bool {
        true
    }
}

fn local_http_server(
    address: std::net::Ipv4Addr,
    body: Vec<u8>,
) -> (
    u16,
    std::sync::mpsc::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind((address, 0)).expect("bind local HTTP server");
    listener
        .set_nonblocking(true)
        .expect("make local HTTP server nonblocking");
    let port = listener.local_addr().expect("local HTTP address").port();
    let (stop, stopped) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        loop {
            if stopped.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut request = [0; 1024];
                    let _ = stream.read(&mut request);
                    stream
                        .write_all(
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len())
                                .as_bytes(),
                        )
                        .and_then(|()| stream.write_all(&body))
                        .expect("write local HTTP response");
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("accept local HTTP request: {error}"),
            }
        }
    });
    (port, stop, server)
}

fn local_upload_server(
    address: std::net::Ipv4Addr,
    expected_bytes: usize,
) -> (
    u16,
    std::sync::mpsc::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind((address, 0)).expect("bind local upload server");
    listener
        .set_nonblocking(true)
        .expect("make local upload server nonblocking");
    let port = listener.local_addr().expect("local upload address").port();
    let (stop, stopped) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        loop {
            if stopped.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut data = vec![0; expected_bytes];
                    stream.read_exact(&mut data).expect("read upload");
                    assert!(data.iter().all(|byte| *byte == 0), "upload bytes match");
                    stream
                        .write_all(b"uploaded")
                        .expect("write upload response");
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("accept local upload: {error}"),
            }
        }
    });
    (port, stop, server)
}

/// Phase 1E gate: a Run VM serves agent control and exec over the worker's
/// owner-only Unix listener while the real component-backed machine is running.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, `make component-block-aot component-vsock-aot`, and boot assets"]
async fn kernel_boots_to_agent_bridge() {
    let (_socket_dir, socket_path, listener) = bridge_listener();
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let client_path = socket_path.clone();
    let client = tokio::task::spawn_blocking(move || assert_agent_control_and_exec(&client_path));
    let worker = super::worker::run(super::worker::WorkerInput {
        component_memory_limits: terra_runtime::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: agent_bridge_plan(),
        artifacts: boot_artifacts(),
        network_policy: boot_network_policy(),
        port_mappings: Vec::new(),
        hard_stop: None,
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_secs(150)),
        listener: Some(listener),
        control: None,
        diagnostics: None,
    });
    let (outcome, client) = tokio::join!(worker, client);
    client
        .expect("agent bridge client thread runs")
        .expect("agent bridge serves control and exec");
    let outcome = outcome.expect("worker runs");
    assert_eq!(outcome.exit_code, Some(0), "agent outcome: {outcome:?}");
}

/// Phase 1E gate: the host stop channel reaches a running guest workload and
/// the worker reaps the machine after the agent reports the signal exit.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, component AOT artifacts, and boot assets"]
async fn kernel_boots_and_agent_stop_ends_workload() {
    use std::io::Write as _;

    let (_socket_dir, socket_path, listener) = bridge_listener();
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let (_control_dir, control_path, control_listener) = bridge_listener();
    let mut control_writer = terra_io::local::LocalStream::connect(&control_path).unwrap();
    let (control, _) = control_listener.accept().unwrap();
    let client_path = socket_path.clone();
    let client = tokio::task::spawn_blocking(move || {
        assert_agent_control_and_exec(&client_path)?;
        control_writer.write_all(&[terra_protocol::STOP_SIGNAL])
    });
    let worker = super::worker::run(super::worker::WorkerInput {
        component_memory_limits: terra_runtime::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: boot_plan(
            terra_protocol::PlanMode::Run,
            Vec::new(),
            vec!["sleep".into(), "120".into()],
            false,
        ),
        artifacts: boot_artifacts(),
        network_policy: boot_network_policy(),
        port_mappings: Vec::new(),
        hard_stop: None,
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_secs(150)),
        listener: Some(listener),
        control: Some(control),
        diagnostics: None,
    });
    let (outcome, client) = tokio::join!(worker, client);
    client
        .expect("stop client thread runs")
        .expect("write worker stop signal");
    let outcome = outcome.expect("worker runs");
    assert_eq!(outcome.exit_code, Some(143), "agent outcome: {outcome:?}");
    assert!(
        outcome.vcpu_outcomes.iter().all(Result::is_ok),
        "worker reaps every vCPU: {outcome:?}"
    );
}

/// A foreground Run box waits for its first attached client, then carries the
/// workload's terminal output and exit status through the native agent bridge.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, component AOT artifacts, and boot assets"]
async fn kernel_boots_foreground_session_reports_workload_exit() {
    let (_socket_dir, socket_path, listener) = bridge_listener();
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let client_path = socket_path.clone();
    let client = tokio::task::spawn_blocking(move || await_foreground_workload(&client_path));
    let worker = super::worker::run(super::worker::WorkerInput {
        component_memory_limits: terra_runtime::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: boot_plan(
            terra_protocol::PlanMode::Run,
            Vec::new(),
            vec![
                "sh".into(),
                "-c".into(),
                "printf foreground-lifecycle; exit 7".into(),
            ],
            true,
        ),
        artifacts: boot_artifacts(),
        network_policy: boot_network_policy(),
        port_mappings: Vec::new(),
        hard_stop: None,
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_mins(1)),
        listener: Some(listener),
        control: None,
        diagnostics: None,
    });
    let (outcome, client) = tokio::time::timeout(std::time::Duration::from_secs(75), async {
        tokio::join!(worker, client)
    })
    .await
    .expect("foreground workload finishes within its bound");
    let (output, exit_code) = client
        .expect("foreground client thread runs")
        .expect("foreground session carries output and exit");
    assert!(
        String::from_utf8_lossy(&output).contains("foreground-lifecycle"),
        "foreground output: {}",
        String::from_utf8_lossy(&output)
    );
    assert_eq!(exit_code, 7, "foreground session exit");
    let outcome = outcome.expect("worker runs");
    assert_eq!(outcome.exit_code, Some(7), "worker outcome: {outcome:?}");
    assert!(
        outcome.vcpu_outcomes.iter().all(Result::is_ok),
        "worker reaps every vCPU: {outcome:?}"
    );
}

async fn assert_policy_dns_http(address: std::net::IpAddr, body: &[u8]) {
    let (_socket_dir, socket_path, listener) = bridge_listener();
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let listener_address = std::net::Ipv4Addr::UNSPECIFIED;
    let body = body.to_vec();
    let (port, stop_server, server) = local_http_server(listener_address, body.clone());
    let client_path = socket_path.clone();
    let client = tokio::task::spawn_blocking(move || {
        assert_agent_control_and_exec(&client_path)?;
        let output = agent_exec(
            &client_path,
            &["wget", "-qO-", &format!("http://agent.test:{port}")],
        )?;
        assert_eq!(output, body);
        Ok::<(), std::io::Error>(())
    });
    let worker = super::worker::run(super::worker::WorkerInput {
        component_memory_limits: terra_runtime::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: agent_bridge_plan(),
        artifacts: boot_artifacts(),
        network_policy: std::sync::Arc::new(LocalHttpPolicy { address, port }),
        port_mappings: Vec::new(),
        hard_stop: None,
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_secs(150)),
        listener: Some(listener),
        control: None,
        diagnostics: None,
    });
    let (outcome, client) = tokio::join!(worker, client);
    let _ = stop_server.send(());
    client
        .expect("network client thread runs")
        .expect("agent fetches the policy DNS HTTP server");
    server.join().expect("local HTTP server thread runs");
    let outcome = outcome.expect("worker runs");
    assert_eq!(outcome.exit_code, Some(0), "agent outcome: {outcome:?}");
}

async fn assert_policy_dns_upload(address: std::net::IpAddr, bytes: usize) {
    let (_socket_dir, socket_path, listener) = bridge_listener();
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let listener_address = std::net::Ipv4Addr::UNSPECIFIED;
    let (port, stop_server, server) = local_upload_server(listener_address, bytes);
    let client_path = socket_path.clone();
    let client = tokio::task::spawn_blocking(move || {
        assert_agent_control_and_exec(&client_path)?;
        let command = format!("head -c {bytes} /dev/zero | nc agent.test {port}");
        assert_eq!(
            agent_exec(&client_path, &["sh", "-c", &command])?,
            b"uploaded"
        );
        Ok::<(), std::io::Error>(())
    });
    let worker = super::worker::run(super::worker::WorkerInput {
        component_memory_limits: terra_runtime::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: agent_bridge_plan(),
        artifacts: boot_artifacts(),
        network_policy: std::sync::Arc::new(LocalHttpPolicy { address, port }),
        port_mappings: Vec::new(),
        hard_stop: None,
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_secs(150)),
        listener: Some(listener),
        control: None,
        diagnostics: None,
    });
    let (outcome, client) = tokio::join!(worker, client);
    let _ = stop_server.send(());
    client
        .expect("upload client thread runs")
        .expect("agent uploads through the policy server");
    server.join().expect("local upload server thread runs");
    let outcome = outcome.expect("worker runs");
    assert_eq!(outcome.exit_code, Some(0), "agent outcome: {outcome:?}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, component AOT artifacts, and boot assets"]
async fn kernel_boots_through_standard_wasi_tcp() {
    assert_policy_dns_http(native_ipv4_address(), b"agent-network").await;
}

fn native_ipv4_address() -> std::net::IpAddr {
    let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
        .expect("bind local address probe");
    socket
        .connect((std::net::Ipv4Addr::new(192, 0, 2, 1), 80))
        .expect("select local address");
    socket.local_addr().expect("read local address").ip()
}

fn reserved_loopback_port() -> u16 {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("reserve loopback port");
    listener.local_addr().expect("read reserved port").port()
}

fn published_http_response(port: u16, host_closes_first: bool) -> std::io::Result<Vec<u8>> {
    use std::io::{Read as _, Write as _};

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let attempt = (|| {
            let mut stream = std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))?;
            stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
            stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
            if host_closes_first {
                stream.shutdown(std::net::Shutdown::Write)?;
            }
            let mut response = Vec::new();
            stream.read_to_end(&mut response)?;
            Ok::<Vec<u8>, std::io::Error>(response)
        })();
        match attempt {
            Ok(response) if !response.is_empty() => return Ok(response),
            Ok(_) | Err(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "published listener closed without a response",
                ));
            }
        }
    }
}

/// A guest closing its response sends EOF to a host still holding its write half open.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, component AOT artifacts, and boot assets"]
async fn kernel_boots_published_loopback_http() {
    assert_published_loopback_http(false).await;
}

/// A host finishing its request can still receive the complete guest response and EOF.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, component AOT artifacts, and boot assets"]
async fn kernel_boots_published_loopback_http_after_host_eof() {
    assert_published_loopback_http(true).await;
}

async fn assert_published_loopback_http(host_closes_first: bool) {
    use std::io::Write as _;

    const GUEST_PORT: u16 = 8080;
    const BODY: &[u8] = b"published-body";
    let host_port = reserved_loopback_port();
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let (_control_dir, control_path, control_listener) = bridge_listener();
    let mut control_writer = terra_io::local::LocalStream::connect(&control_path).unwrap();
    let (control, _) = control_listener.accept().unwrap();
    let diagnostics = tempfile::NamedTempFile::new().expect("create diagnostics");
    let client = tokio::task::spawn_blocking(move || {
        let response = published_http_response(host_port, host_closes_first)?;
        control_writer.write_all(&[terra_protocol::STOP_SIGNAL])?;
        Ok::<Vec<u8>, std::io::Error>(response)
    });
    let worker = super::worker::run(super::worker::WorkerInput {
        component_memory_limits: terra_runtime::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: boot_plan(
            terra_protocol::PlanMode::Run,
            Vec::new(),
            vec![
                "sh".into(),
                "-c".into(),
                "while true; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 14\\r\\nConnection: close\\r\\n\\r\\npublished-body' | busybox nc -l -p 8080; done".into(),
            ],
            false,
        ),
        artifacts: boot_artifacts(),
        network_policy: boot_network_policy(),
        port_mappings: vec![terra_network::PortMapping::new(host_port, GUEST_PORT)],
        hard_stop: None,
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_mins(1)),
        listener: None,
        control: Some(control),
        diagnostics: Some(diagnostics.reopen().expect("reopen diagnostics")),
    });
    let (outcome, response) = tokio::time::timeout(std::time::Duration::from_secs(75), async {
        tokio::join!(worker, client)
    })
    .await
    .unwrap_or_else(|error| {
        panic!(
            "published HTTP workload finishes within its bound: {error:?}\n{}",
            std::fs::read_to_string(diagnostics.path()).expect("read diagnostics")
        )
    });
    let response = response
        .expect("published HTTP client thread runs")
        .expect("published port responds");
    assert!(
        response.ends_with(BODY),
        "published HTTP response: {}",
        String::from_utf8_lossy(&response)
    );
    let outcome = outcome.expect("worker runs");
    assert_eq!(outcome.exit_code, Some(143), "worker outcome: {outcome:?}");
    assert!(
        outcome.vcpu_outcomes.iter().all(Result::is_ok),
        "worker reaps every vCPU: {outcome:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, component AOT artifacts, and boot assets"]
async fn kernel_boots_through_standard_wasi_large_tcp() {
    assert_policy_dns_http(native_ipv4_address(), &vec![b's'; 65_537]).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, component AOT artifacts, and boot assets"]
async fn kernel_uploads_through_standard_wasi_tcp() {
    assert_policy_dns_upload(native_ipv4_address(), 65_537).await;
}
#[cfg(unix)]
#[test]
#[allow(unsafe_code)]
fn vsock_header_matches_upstream_packet_layout() {
    use super::component::vsock::protocol::VsockHeader;
    use virtio_vsock::packet::{PKT_HEADER_SIZE, VsockPacket};

    let ours = VsockHeader {
        src_cid: 3,
        dst_cid: 2,
        src_port: 100,
        dst_port: 6001,
        len: 5,
        type_: 1,
        op: 5,
        flags: 0,
        buf_alloc: 65536,
        fwd_cnt: 7,
    };
    let mut raw = [0u8; PKT_HEADER_SIZE];
    // SAFETY: `raw` outlives `packet`, the test is single-threaded, and
    // nothing else touches the buffer while the packet borrows it.
    let mut packet = unsafe { VsockPacket::new(&mut raw, None) }.expect("packet wraps");
    packet
        .set_src_cid(ours.src_cid)
        .set_dst_cid(ours.dst_cid)
        .set_src_port(ours.src_port)
        .set_dst_port(ours.dst_port)
        .set_len(ours.len)
        .set_type(ours.type_)
        .set_op(ours.op)
        .set_flags(ours.flags)
        .set_buf_alloc(ours.buf_alloc)
        .set_fwd_cnt(ours.fwd_cnt);
    let mut upstream = [0u8; PKT_HEADER_SIZE];
    packet.header_slice().copy_to(&mut upstream[..]);
    assert_eq!(upstream, ours.encode());
    let (parsed, rest) = VsockHeader::parse(&upstream).expect("parses");
    assert_eq!(parsed, ours);
    assert!(rest.is_empty());
}

/// Differential oracle against `virtio-blk::Request::parse` at pinned
/// rev `87bf424`. Same hostile corpus through both parsers: `Accept`
/// demands identical fields, `RejectBoth` demands two rejections, and
/// `TerraStricter` marks our policy bounds beyond the spec MUSTs
/// (chain/byte caps, no indirect, uniform direction, exact framing).
/// There is deliberately no fourth arm: anything upstream rejects
/// that we accept is a bug in our walk, and fails loudly.
#[cfg(all(test, unix))]
mod blk_oracle {
    use super::super::component::block::backing::ParsedRequest;
    use virtio_blk::request::{Request, RequestType};

    const RAM: u64 = 128 * 1024;
    const HDR: u64 = 0x4000;
    const STATUS: u64 = 0x8000;
    const RD: u16 = 0;
    const WR: u16 = 2;
    const NEXT: u16 = 1;
    const INDIRECT: u16 = 4;

    const T_IN: u32 = 0;
    const T_OUT: u32 = 1;
    const T_FLUSH: u32 = 4;
    const T_GET_ID: u32 = 8;

    enum Expect {
        Accept,
        RejectBoth,
        TerraStricter,
    }

    struct Case {
        descs: Vec<(u64, u32, u16, u16)>,
        req_type: u32,
        sector: u64,
        expect: Expect,
    }

    fn out_data(n: usize) -> Vec<(u64, u32, u16, u16)> {
        let mut descs = vec![(HDR, 16, RD | NEXT, 1)];
        for i in 0..n {
            descs.push((0x5000 + i as u64 * 0x4000, 512, RD | NEXT, 0));
        }
        descs.push((STATUS, 1, WR, 0));
        for i in 0..descs.len() - 1 {
            descs[i].3 = u16::try_from(i + 1).expect("short chain");
        }
        descs
    }

    fn upstream_type(request_type: RequestType) -> u32 {
        match request_type {
            RequestType::In => T_IN,
            RequestType::Out => T_OUT,
            RequestType::Flush => T_FLUSH,
            RequestType::GetDeviceID => T_GET_ID,
            RequestType::Discard => 11,
            RequestType::WriteZeroes => 13,
            RequestType::Unsupported(t) => t,
        }
    }

    fn corpus() -> Vec<Case> {
        let mut cases = accept_cases();
        cases.extend(reject_cases());
        cases.extend(stricter_cases());
        cases
    }

    fn accept_cases() -> Vec<Case> {
        vec![
            Case {
                descs: out_data(1),
                req_type: T_OUT,
                sector: 3,
                expect: Expect::Accept,
            },
            Case {
                descs: vec![
                    (HDR, 16, RD | NEXT, 1),
                    (0x5000, 512, WR | NEXT, 2),
                    (STATUS, 1, WR, 0),
                ],
                req_type: T_IN,
                sector: 9,
                expect: Expect::Accept,
            },
            Case {
                descs: vec![(HDR, 16, RD | NEXT, 1), (STATUS, 1, WR, 0)],
                req_type: T_FLUSH,
                sector: 0,
                expect: Expect::Accept,
            },
            Case {
                descs: out_data(1),
                req_type: 2,
                sector: 0,
                expect: Expect::Accept,
            },
            Case {
                descs: vec![
                    (HDR, 16, RD | NEXT, 1),
                    (0x5000, 512, WR | NEXT, 2),
                    (STATUS, 1, WR, 0),
                ],
                req_type: T_GET_ID,
                sector: 0,
                expect: Expect::Accept,
            },
        ]
    }

    fn reject_cases() -> Vec<Case> {
        vec![
            Case {
                descs: vec![(HDR, 16, RD | NEXT, 1), (STATUS, 1, WR, 0)],
                req_type: T_FLUSH,
                sector: 7,
                expect: Expect::RejectBoth,
            },
            Case {
                descs: vec![
                    (HDR, 16, WR | NEXT, 1),
                    (0x5000, 512, RD | NEXT, 2),
                    (STATUS, 1, WR, 0),
                ],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::RejectBoth,
            },
            Case {
                descs: vec![
                    (HDR, 16, RD | NEXT, 1),
                    (0x5000, 512, RD | NEXT, 2),
                    (STATUS, 1, RD, 0),
                ],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::RejectBoth,
            },
            Case {
                descs: vec![
                    (HDR, 16, RD | NEXT, 1),
                    (0x5000, 512, RD | NEXT, 2),
                    (STATUS, 0, WR, 0),
                ],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::RejectBoth,
            },
            Case {
                descs: vec![(HDR, 16, RD | NEXT, 1), (0x5000, 512, RD | NEXT, 0)],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::RejectBoth,
            },
            Case {
                descs: vec![
                    (HDR, 16, RD | NEXT, 1),
                    (0x5000, 512, RD | NEXT, 2),
                    (0xFFFF_FFFF, 1, WR, 0),
                ],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::RejectBoth,
            },
            Case {
                descs: vec![(HDR, 16, RD | NEXT, 99)],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::RejectBoth,
            },
            Case {
                descs: vec![(HDR, 16, RD, 0)],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::RejectBoth,
            },
        ]
    }

    fn stricter_cases() -> Vec<Case> {
        let mut wide = out_data(5);
        for desc in wide.iter_mut().skip(1).take(5) {
            desc.1 = 16 * 1024;
        }
        let mut long = vec![(HDR, 16, RD | NEXT, 1)];
        for i in 0..15u16 {
            long.push((0x5000 + u64::from(i) * 0x1000, 512, RD | NEXT, i + 2));
        }
        long.push((STATUS, 1, WR, 0));

        vec![
            Case {
                descs: vec![
                    (HDR, 15, RD | NEXT, 1),
                    (0x5000, 512, RD | NEXT, 2),
                    (STATUS, 1, WR, 0),
                ],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::TerraStricter,
            },
            Case {
                descs: vec![
                    (HDR, 16, RD | NEXT, 1),
                    (0x5000, 512, RD | NEXT, 2),
                    (STATUS, 2, WR, 0),
                ],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::TerraStricter,
            },
            Case {
                descs: long,
                req_type: T_OUT,
                sector: 0,
                expect: Expect::TerraStricter,
            },
            Case {
                descs: wide,
                req_type: T_OUT,
                sector: 0,
                expect: Expect::TerraStricter,
            },
            Case {
                descs: vec![(HDR, 16, RD | NEXT, 1), (0x9000, 32, INDIRECT, 0)],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::TerraStricter,
            },
            Case {
                descs: vec![
                    (HDR, 16, RD | NEXT, 1),
                    (0x5000, 512, RD | NEXT, 2),
                    (0x6000, 512, WR | NEXT, 3),
                    (STATUS, 1, WR, 0),
                ],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::TerraStricter,
            },
            Case {
                descs: vec![
                    (HDR, 16, RD | NEXT, 1),
                    (0xFFFF_FFFF, 512, RD | NEXT, 2),
                    (STATUS, 1, WR, 0),
                ],
                req_type: T_OUT,
                sector: 0,
                expect: Expect::TerraStricter,
            },
        ]
    }
    fn check_case(index: usize, case: &Case) {
        use virtio_queue_git::Queue;
        use virtio_queue_git::QueueOwnedT as _;
        use virtio_queue_git::desc::{RawDescriptor, split::Descriptor as SplitDescriptor};
        use virtio_queue_git::mock::MockSplitQueue;
        use vm_memory::{Bytes as _, GuestAddress, GuestMemoryMmap};

        let ram = usize::try_from(RAM).expect("test RAM fits");
        let mem: GuestMemoryMmap<()> =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), ram)]).expect("test RAM maps");
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&case.req_type.to_le_bytes());
        header[8..16].copy_from_slice(&case.sector.to_le_bytes());
        mem.write_slice(&header, GuestAddress(HDR))
            .expect("header fits");
        if case.descs.iter().any(|desc| desc.2 & INDIRECT != 0) {
            let mut table = [0u8; 32];
            table[0..8].copy_from_slice(&0x5000u64.to_le_bytes());
            table[8..12].copy_from_slice(&512u32.to_le_bytes());
            table[12..14].copy_from_slice(&(RD | NEXT).to_le_bytes());
            table[14..16].copy_from_slice(&1u16.to_le_bytes());
            table[16..24].copy_from_slice(&STATUS.to_le_bytes());
            table[24..28].copy_from_slice(&1u32.to_le_bytes());
            table[28..30].copy_from_slice(&WR.to_le_bytes());
            mem.write_slice(&table, GuestAddress(0x9000))
                .expect("table fits");
        }
        let raws: Vec<RawDescriptor> = case
            .descs
            .iter()
            .map(|desc| RawDescriptor::from(SplitDescriptor::new(desc.0, desc.1, desc.2, desc.3)))
            .collect();
        let queue = MockSplitQueue::new(&mem, 32);
        queue.add_desc_chains(&raws, 0).expect("chains stage");
        let mut device_queue = queue.create_queue::<Queue>().expect("queue params");
        let mut chain = device_queue
            .iter(&mem)
            .expect("avail iterates")
            .next()
            .expect("chain present");
        let upstream = Request::parse(&mut chain);

        let snapshots: Vec<super::Descriptor> = case
            .descs
            .iter()
            .map(|desc| super::Descriptor {
                addr: desc.0,
                len: desc.1,
                flags: desc.2,
                next: desc.3,
            })
            .collect();
        let ours = ParsedRequest::walk(&snapshots, 0, RAM);
        // Mirror `execute`'s sector rule: the walk validates framing
        // only, while upstream folds the flush-sector MUST into
        // parsing. Behavior matches (no completion either way).
        let ours = match (&ours, case.req_type, case.sector) {
            (Ok(_), T_FLUSH, sector) if sector != 0 => None,
            (Ok(parsed), _, _) => Some(parsed.clone()),
            (Err(_), _, _) => None,
        };

        match (&ours, &upstream, &case.expect) {
            (Some(parsed), Ok(request), Expect::Accept) => {
                assert_eq!(upstream_type(request.request_type()), case.req_type);
                assert_eq!(request.sector(), case.sector);
                assert_eq!(request.total_data_len(), parsed.total);
                assert_eq!(request.status_addr().0, parsed.status_addr);
                let up_data: Vec<(u64, u32)> = request
                    .data()
                    .iter()
                    .map(|(addr, len)| (addr.0, *len))
                    .collect();
                let our_data: Vec<(u64, u32)> = parsed.data.clone();
                assert_eq!(up_data, our_data);
            }
            (None, Err(_), Expect::RejectBoth) | (None, Ok(_), Expect::TerraStricter) => {}
            (Some(_), Err(_), _) => {
                panic!("case {index}: upstream rejects what we accept (adopt the rule)");
            }
            _ => panic!("case {index}: wrong expectation annotation"),
        }
    }

    #[test]
    fn parsers_agree_up_to_policy_bounds() {
        for (index, case) in corpus().iter().enumerate() {
            check_case(index, case);
        }
    }
}

#[cfg(unix)]
#[test]
fn memory_hole_is_rejected_before_partial_write() {
    use std::sync::Arc;
    use vm_memory::{GuestAddress, GuestMemoryMmap};
    let mapping = Arc::new(
        GuestMemoryMmap::<()>::from_ranges(&[
            (GuestAddress(0), 0x1000),
            (GuestAddress(0x2000), 0x1000),
        ])
        .unwrap(),
    );
    let ram = SyntheticRam::from_shared(mapping).unwrap();
    let memory = BoundedMemory::new(&ram);
    memory.write(0xff0, &[0x42; 16]).unwrap();
    assert_eq!(memory.write(0xff0, &[0x99; 32]), Err(MemoryError::Unmapped));
    assert_eq!(memory.read(0xff0, 16).unwrap(), vec![0x42; 16]);
}
