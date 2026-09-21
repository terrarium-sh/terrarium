//! Vertical slice through the real P3 block component: queue-parsed
//! requests drive `execute` through the actual memory/disk imports.
//! Build it first: `make component-block` (nightly `wasm32-wasip3`).

use crate::component::block::backing::DiskGrant;
use crate::component::block::host::{BlockHost, Completion, Range, block_component_linker};
use crate::component::vmm::mmio::terra::mmio::types::DeviceError;
use crate::component::vmm::mmio::{Operation, Reply, Request};
use crate::engine::{
    device_engine, precompile_component,
    test_support::{StandaloneHost, device_store},
};
use crate::{BoundedDisk, SyntheticRam};
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
type Configure = TypedFunc<(bool,), (Result<(), DeviceError>,)>;
type Serve = TypedFunc<(StreamReader<Request>,), (StreamReader<Reply>,)>;

fn one(addr: u64, len: u64) -> Vec<Range> {
    vec![Range { addr, len }]
}

pub(crate) fn component_bytes() -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/target/wasm32-wasip3/release/terra_block_component.wasm");
    std::fs::read(&path)
        .expect("block component missing; run `make component-block` with the pinned nightly")
}

fn export_name(func: &str) -> ItemName {
    format!("terra:host/device-api.{func}@0.1.0")
        .parse()
        .expect("export name parses")
}

struct Fixture {
    store: wasmtime::Store<StandaloneHost<BlockHost>>,
    execute: Execute,
    configure: Configure,
    serve: Serve,
}

struct ReplySink(Arc<Mutex<Option<Reply>>>);

impl StreamConsumer<StandaloneHost<BlockHost>> for ReplySink {
    type Item = Reply;

    fn poll_consume(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        store: StoreContextMut<StandaloneHost<BlockHost>>,
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
) -> (Linker<StandaloneHost<BlockHost>>, Fixture) {
    let engine = device_engine().expect("engine builds");
    let linker = block_component_linker(&engine).expect("block imports link");
    let mut disk = BoundedDisk::new(capacity_sectors * 512, readonly);
    if !readonly {
        disk.write(3 * 512, &[0xABu8; 512]).ok();
    }
    let mut store = device_store(
        &engine,
        BlockHost::new(SyntheticRam::new(RAM).unwrap(), DiskGrant::Mem(disk)),
    );
    let component = Component::new(&engine, component_bytes()).expect("block component compiles");
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
        .context
        .guest_read(STATUS, 1)
        .expect("status readable")[0]
}

#[tokio::test(flavor = "multi_thread")]
async fn component_read_write_round_trip() {
    let (_linker, mut fixture) = fixture(8, false).await;
    fixture
        .store
        .data_mut()
        .context
        .guest_write(DATA, &[0xCDu8; 512])
        .expect("payload staged");
    let (result,) = fixture
        .execute
        .call_async(&mut fixture.store, (T_OUT, 1, one(DATA, 512), STATUS, 0))
        .await
        .expect("write runs");
    assert_eq!(result, 0);
    assert_eq!(status(&fixture), 0);
    assert!(fixture.store.data_mut().context.drain_signal());
    fixture
        .store
        .data_mut()
        .context
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
            .context
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
        .context
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
        .context
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
        .context
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
        .context
        .guest_write(DATA, &[0x11u8; 512])
        .expect("first half staged");
    fixture
        .store
        .data_mut()
        .context
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
        .context
        .guest_write(DATA, &[0u8; 512])
        .expect("buffer cleared");
    fixture
        .store
        .data_mut()
        .context
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
            .context
            .guest_read(DATA, 512)
            .expect("first back"),
        [0x11u8; 512]
    );
    assert_eq!(
        fixture
            .store
            .data()
            .context
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
        .context
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
    assert!(fixture.store.data_mut().context.drain_signal());
    let (result,) = fixture
        .execute
        .call_async(&mut fixture.store, (0xFFFF, 0, one(DATA, 512), STATUS, 0))
        .await
        .expect("unknown type completes");
    assert_eq!(result, 2);
    assert_eq!(status(&fixture), 2);
    assert!(fixture.store.data_mut().context.drain_signal());
    let (result,) = fixture
        .execute
        .call_async(&mut fixture.store, (T_GET_ID, 0, one(DATA, 512), STATUS, 0))
        .await
        .expect("identify runs");
    assert_eq!(result, 0);
    assert!(fixture.store.data_mut().context.drain_signal());
    assert_eq!(
        &fixture
            .store
            .data()
            .context
            .guest_read(DATA, 12)
            .expect("id back")[..],
        b"terra-vda\0\0\0"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn component_reset_fences_stale_epoch() {
    let (_linker, mut fixture) = fixture(8, false).await;
    fixture
        .store
        .data_mut()
        .context
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
        .context
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
    let component = unsafe { Component::deserialize(&engine, &artifact).expect("deserializes") };
    let mut store = device_store(
        &engine,
        BlockHost::new(
            crate::SyntheticRam::new(RAM).unwrap(),
            DiskGrant::Mem(BoundedDisk::new(8 * 512, false)),
        ),
    );

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
        .context
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
            .context
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
        store
            .data()
            .context
            .guest_read(STATUS, 1)
            .expect("status readable")[0],
        0
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn component_operates_on_shared_machine_ram() {
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
    let mut disk = BoundedDisk::new(8 * 512, false);
    disk.write(2 * 512, &[0x5Eu8; 512]).expect("pattern in");
    let mut store = device_store(&engine, BlockHost::new(ram, DiskGrant::Mem(disk)));
    let component = Component::new(&engine, component_bytes()).expect("block component compiles");
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
