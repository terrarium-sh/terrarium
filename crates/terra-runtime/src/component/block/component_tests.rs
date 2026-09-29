//! Vertical slice through the real P3 block component: queue-parsed
//! requests drive `execute` through the actual memory/disk imports.
//! Build it first: `make component-block` (nightly `wasm32-unknown-unknown`).

use crate::component::block::backing::BoundedDisk;
use crate::component::block::backing::DiskGrant;
use crate::component::block::bindings::{Completion, Range};
use crate::component::block::{BlockHost, block_component_linker};
use crate::component::mmio::{DeviceError, Operation, Reply, Request};
use crate::engine::{device_engine, precompile_component};
use crate::memory::GuestRam;
use crate::test_support::{StandaloneHost, device_store};
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
type ExecuteChain = TypedFunc<(u16, u64, u16, u64), (Result<Completion, DeviceError>,)>;
type Configure = TypedFunc<(bool,), (Result<(), DeviceError>,)>;
type Serve = TypedFunc<(StreamReader<Request>,), (StreamReader<Reply>,)>;

fn one(addr: u64, len: u64) -> Vec<Range> {
    vec![Range { addr, len }]
}

fn export_name(func: &str) -> ItemName {
    format!("terra:host/device-api.{func}@0.1.0")
        .parse()
        .expect("export name parses")
}

struct Fixture {
    store: wasmtime::Store<StandaloneHost<BlockHost>>,
    execute: Execute,
    execute_chain: ExecuteChain,
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
    let mut disk = BoundedDisk::new(capacity_sectors * 512, readonly);
    if !readonly {
        disk.write(3 * 512, &[0xABu8; 512]).ok();
    }
    let component = Component::new(&engine, crate::test_fixtures::wasm::BLOCK)
        .expect("block component compiles");
    fixture_with_disk(&engine, DiskGrant::Mem(disk), &component).await
}

async fn fixture_with_disk(
    engine: &wasmtime::Engine,
    disk: DiskGrant,
    component: &Component,
) -> (Linker<StandaloneHost<BlockHost>>, Fixture) {
    let linker = block_component_linker(engine).expect("block imports link");
    let mut store = device_store(engine, BlockHost::new(GuestRam::new(RAM).unwrap(), disk));
    let instance = linker
        .instantiate_async(&mut store, component)
        .await
        .expect("block imports satisfied");
    let execute = instance
        .get_typed_func::<(u32, u64, Vec<Range>, u64, u64), (u8,)>(
            &mut store,
            export_name("execute"),
        )
        .expect("execute exported");
    let execute_chain = instance
        .get_typed_func(&mut store, export_name("execute-chain"))
        .expect("execute-chain exported");
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
            execute_chain,
            configure,
            serve,
        },
    )
}

#[cfg(any(unix, windows))]
async fn benchmark_block_io(
    fixture: &mut Fixture,
    disk_path: &std::path::Path,
    version: &str,
    request_type: u32,
    ranges: &[Range],
    pattern: u8,
) {
    const CALLS_PER_SAMPLE: usize = 128;
    const MEASURED_SAMPLES: usize = 7;

    let bytes = ranges.iter().map(|range| range.len).sum::<u64>();
    let mut ns_per_call = Vec::with_capacity(MEASURED_SAMPLES);
    let mut memory_calls_per_operation = (0, 0);
    for sample in 0..=MEASURED_SAMPLES {
        if request_type == T_IN {
            for range in ranges {
                fixture
                    .store
                    .data_mut()
                    .context
                    .guest_write(
                        range.addr,
                        &vec![0; usize::try_from(range.len).expect("range fits usize")],
                    )
                    .expect("read destination cleared");
            }
        }
        let before = fixture.store.data().context.memory_read_import_counts();
        let start = std::time::Instant::now();
        for _ in 0..CALLS_PER_SAMPLE {
            let (result,) = fixture
                .execute
                .call_async(
                    &mut fixture.store,
                    (request_type, 0, ranges.to_vec(), 0x20000, 0),
                )
                .await
                .expect("block operation runs");
            assert_eq!(result, 0);
        }
        let elapsed = start.elapsed();
        let after = fixture.store.data().context.memory_read_import_counts();
        memory_calls_per_operation = (
            (after.0 - before.0) / CALLS_PER_SAMPLE as u64,
            (after.1 - before.1) / CALLS_PER_SAMPLE as u64,
        );
        assert_eq!(
            fixture
                .store
                .data()
                .context
                .guest_read(0x20000, 1)
                .expect("status readable"),
            [0]
        );
        if request_type == T_IN {
            for range in ranges {
                let data = fixture
                    .store
                    .data()
                    .context
                    .guest_read(range.addr, range.len)
                    .expect("read payload readable");
                assert!(data.iter().all(|byte| *byte == pattern));
            }
        } else {
            let data = std::fs::read(disk_path).expect("disk readable");
            assert!(
                data[..usize::try_from(bytes).expect("transfer fits usize")]
                    .iter()
                    .all(|byte| *byte == pattern)
            );
        }
        if sample != 0 {
            ns_per_call.push(
                elapsed.as_nanos() / u128::try_from(CALLS_PER_SAMPLE).expect("count fits u128"),
            );
        }
    }
    ns_per_call.sort_unstable();
    let median_ns = ns_per_call[MEASURED_SAMPLES / 2];
    let p95_ns = ns_per_call[(MEASURED_SAMPLES * 95).div_ceil(100) - 1];
    let bytes_per_second = u128::from(bytes) * 1_000_000_000 / median_ns;
    println!(
        "terra_block_bench version={version} operation={} bytes={bytes} calls_per_sample={CALLS_PER_SAMPLE} samples={MEASURED_SAMPLES} median_ns_per_call={median_ns} p95_ns_per_call={p95_ns} median_bytes_per_second={bytes_per_second} memory_read_calls_per_operation={} memory_read_ranges_calls_per_operation={}",
        if request_type == T_IN {
            "read"
        } else {
            "write"
        },
        memory_calls_per_operation.0,
        memory_calls_per_operation.1,
    );
}

#[cfg(any(unix, windows))]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "AOT file-backed microbenchmark; run with --release --ignored --nocapture"]
#[allow(unsafe_code)]
async fn benchmark_aot_file_backed_block_transfers() {
    use crate::component::block::backing::FileDisk;

    let engine = device_engine().expect("engine builds");
    let current_wasm = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/target/wasm-components/release/terra_block_component.wasm"),
    )
    .expect("current block component");
    let current_aot = precompile_component(&engine, &current_wasm).expect("current block AOT");
    let mut components = Vec::new();
    if let Some(path) = std::env::var_os("TERRA_BASELINE_BLOCK_COMPONENT") {
        let baseline_aot = std::fs::read(path).expect("baseline block AOT");
        components.push((
            "baseline",
            // SAFETY: The benchmark reads the trusted artifact saved from this repository's baseline build.
            unsafe { Component::deserialize(&engine, baseline_aot) }
                .expect("baseline block component"),
        ));
    }
    components.push((
        "candidate",
        // SAFETY: `precompile_component` produced this artifact with the same engine above.
        unsafe { Component::deserialize(&engine, current_aot) }.expect("current block component"),
    ));
    if std::env::var_os("TERRA_BENCH_CANDIDATE_FIRST").is_some() {
        components.reverse();
    }
    for (version, component) in components {
        for (bytes, ranges, pattern) in [
            (4 * 1024, one(0x4000, 4 * 1024), 0x41),
            (
                64 * 1024,
                (0..4)
                    .map(|index| Range {
                        addr: 0x4000 + index * 16 * 1024,
                        len: 16 * 1024,
                    })
                    .collect(),
                0x64,
            ),
        ] {
            let disk = tempfile::NamedTempFile::new().expect("disk file");
            disk.as_file().set_len(128 * 1024).expect("disk capacity");
            let backing = FileDisk::open(disk.path(), false).expect("file-backed disk");
            let (_, mut fixture) =
                fixture_with_disk(&engine, DiskGrant::File(backing), &component).await;
            for range in &ranges {
                fixture
                    .store
                    .data_mut()
                    .context
                    .guest_write(
                        range.addr,
                        &vec![pattern; usize::try_from(range.len).expect("range fits usize")],
                    )
                    .expect("write payload staged");
            }
            assert_eq!(ranges.iter().map(|range| range.len).sum::<u64>(), bytes);
            benchmark_block_io(&mut fixture, disk.path(), version, T_OUT, &ranges, pattern).await;
            benchmark_block_io(&mut fixture, disk.path(), version, T_IN, &ranges, pattern).await;
        }
    }
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
async fn component_transfers_the_full_batch_across_distinct_ranges() {
    let (_, mut fixture) = fixture(256, false).await;
    let ranges: Vec<_> = (0..4u64)
        .map(|index| Range {
            addr: 0x4000 + index * 16 * 1024,
            len: 16 * 1024,
        })
        .collect();
    for (range, pattern) in ranges.iter().zip([0x11, 0x22, 0x33, 0x44]) {
        fixture
            .store
            .data_mut()
            .context
            .guest_write(range.addr, &[pattern; 16 * 1024])
            .expect("batch payload staged");
    }
    let before = fixture.store.data().context.memory_read_import_counts();
    let (write_status,) = fixture
        .execute
        .call_async(&mut fixture.store, (T_OUT, 0, ranges.clone(), STATUS, 0))
        .await
        .expect("full batch write runs");
    assert_eq!(write_status, 0);
    let after = fixture.store.data().context.memory_read_import_counts();
    assert_eq!((after.0 - before.0, after.1 - before.1), (0, 1));
    for range in &ranges {
        fixture
            .store
            .data_mut()
            .context
            .guest_write(range.addr, &[0; 16 * 1024])
            .expect("batch destination cleared");
    }
    let (read_status,) = fixture
        .execute
        .call_async(&mut fixture.store, (T_IN, 0, ranges.clone(), STATUS, 0))
        .await
        .expect("full batch read runs");
    assert_eq!(read_status, 0);
    for (range, pattern) in ranges.iter().zip([0x11, 0x22, 0x33, 0x44]) {
        assert_eq!(
            fixture
                .store
                .data()
                .context
                .guest_read(range.addr, range.len)
                .expect("batch payload readable"),
            [pattern; 16 * 1024]
        );
    }
    let mut over_total = ranges;
    over_total.push(Range {
        addr: 0x14000,
        len: 512,
    });
    let (oversize_status,) = fixture
        .execute
        .call_async(&mut fixture.store, (T_OUT, 0, over_total, STATUS, 0))
        .await
        .expect("oversized batch completes");
    assert_eq!(oversize_status, 1);
    let (oversize_status,) = fixture
        .execute
        .call_async(
            &mut fixture.store,
            (T_OUT, 0, one(0x4000, 16 * 1024 + 1), STATUS, 0),
        )
        .await
        .expect("oversized descriptor completes");
    assert_eq!(oversize_status, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn component_ignores_zero_length_ranges_at_invalid_addresses() {
    let (_, mut fixture) = fixture(8, false).await;
    fixture
        .store
        .data_mut()
        .context
        .guest_write(DATA, &[0xA5; 512])
        .expect("payload staged");
    let ranges = vec![
        Range {
            addr: u64::MAX,
            len: 0,
        },
        Range {
            addr: DATA,
            len: 512,
        },
        Range {
            addr: u64::MAX,
            len: 0,
        },
    ];
    let (write_status,) = fixture
        .execute
        .call_async(&mut fixture.store, (T_OUT, 0, ranges.clone(), STATUS, 0))
        .await
        .expect("write skips empty ranges");
    assert_eq!(write_status, 0);
    fixture
        .store
        .data_mut()
        .context
        .guest_write(DATA, &[0; 512])
        .expect("destination cleared");
    let (read_status,) = fixture
        .execute
        .call_async(&mut fixture.store, (T_IN, 0, ranges, STATUS, 0))
        .await
        .expect("read skips empty ranges");
    assert_eq!(read_status, 0);
    assert_eq!(
        fixture
            .store
            .data()
            .context
            .guest_read(DATA, 512)
            .expect("payload readable"),
        [0xA5; 512]
    );
    let (empty_status,) = fixture
        .execute
        .call_async(&mut fixture.store, (T_IN, 0, one(u64::MAX, 0), STATUS, 0))
        .await
        .expect("empty transfer completes");
    assert_eq!(empty_status, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_later_range_does_not_partially_write_a_batch() {
    let (_, mut fixture) = fixture(8, false).await;
    fixture
        .store
        .data_mut()
        .context
        .guest_write(DATA, &[0xA5; 512])
        .expect("first range staged");
    let (write_status,) = fixture
        .execute
        .call_async(
            &mut fixture.store,
            (
                T_OUT,
                0,
                vec![
                    Range {
                        addr: DATA,
                        len: 512,
                    },
                    Range {
                        addr: u64::MAX,
                        len: 512,
                    },
                ],
                STATUS,
                0,
            ),
        )
        .await
        .expect("invalid batch completes");
    assert_eq!(write_status, 1);
    let (read_status,) = fixture
        .execute
        .call_async(
            &mut fixture.store,
            (T_IN, 0, one(DATA + 1024, 1024), STATUS, 0),
        )
        .await
        .expect("disk contents readable");
    assert_eq!(read_status, 0);
    assert_eq!(
        fixture
            .store
            .data()
            .context
            .guest_read(DATA + 1024, 1024)
            .expect("disk contents copied"),
        [0; 1024]
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
    for (request_type, sector, ranges) in [(T_FLUSH, 7, vec![]), (T_FLUSH, 0, one(DATA, 512))] {
        let (result,) = fixture
            .execute
            .call_async(
                &mut fixture.store,
                (request_type, sector, ranges, STATUS, 0),
            )
            .await
            .unwrap();
        assert_eq!(result, 1);
        assert_eq!(status(&fixture), 1);
    }
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
    let artifact =
        precompile_component(&engine, crate::test_fixtures::wasm::BLOCK).expect("precompiles");
    assert!(!artifact.is_empty());
    // SAFETY: artifact was just produced by the trusted build above
    // from the checked-in component source; deserialization performs
    // compatibility checks but not validation of arbitrary bytes.
    let component = unsafe { Component::deserialize(&engine, &artifact).expect("deserializes") };
    let mut store = device_store(
        &engine,
        BlockHost::new(
            crate::memory::GuestRam::new(RAM).unwrap(),
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

#[tokio::test(flavor = "multi_thread")]
async fn component_operates_on_shared_machine_ram() {
    use terra_platform::memory::GuestMemory;
    let engine = device_engine().expect("engine builds");
    let linker = block_component_linker(&engine).expect("block imports link");
    let mem = GuestMemory::allocate(RAM).expect("maps");
    let ram = GuestRam::from_memory(mem.clone());
    let mut disk = BoundedDisk::new(8 * 512, false);
    disk.write(2 * 512, &[0x5Eu8; 512]).expect("pattern in");
    let mut store = device_store(&engine, BlockHost::new(ram, DiskGrant::Mem(disk)));
    let component = Component::new(&engine, crate::test_fixtures::wasm::BLOCK)
        .expect("block component compiles");
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
    let back = mem.read(DATA, 512).expect("mapped");
    assert_eq!(back, [0x5Eu8; 512]);
    let status = mem.read(STATUS, 1).expect("mapped");
    assert_eq!(status, [0]);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn component_rejects_malformed_chains_without_writing_the_disk() {
    let (_, mut fixture) = fixture(8, false).await;
    let header_addr = 0x1000;
    let table_addr = 0x4000;
    let mut header = [0; 16];
    header[..4].copy_from_slice(&T_OUT.to_le_bytes());
    fixture
        .store
        .data_mut()
        .context
        .guest_write(header_addr, &header)
        .unwrap();
    fixture
        .store
        .data_mut()
        .context
        .guest_write(DATA, &[0xCD; 512])
        .unwrap();
    let header = (header_addr, 16_u32, 1_u16, 1_u16);
    let data = (DATA, 512, 1, 2);
    let tail = (STATUS, 1, 2, 0);
    let mut too_many_ranges = vec![header];
    too_many_ranges.extend((2..=18).map(|next| (DATA, 512, 1, next)));
    too_many_ranges.push(tail);
    let cases = [
        (
            "short header",
            vec![(header_addr, 15, 1, 1), data, tail],
            true,
        ),
        (
            "writable header",
            vec![(header_addr, 16, 3, 1), data, tail],
            true,
        ),
        ("missing status", vec![(header_addr, 16, 0, 0)], false),
        (
            "read-only status",
            vec![header, data, (STATUS, 1, 0, 0)],
            false,
        ),
        ("empty status", vec![header, data, (STATUS, 0, 2, 0)], false),
        ("long status", vec![header, data, (STATUS, 2, 2, 0)], false),
        (
            "status outside RAM",
            vec![header, data, (u64::MAX, 1, 2, 0)],
            false,
        ),
        (
            "wrong direction",
            vec![header, (DATA, 512, 3, 2), tail],
            true,
        ),
        (
            "mixed directions",
            vec![header, data, (DATA + 512, 512, 3, 3), tail],
            true,
        ),
        (
            "oversized buffer",
            vec![header, (DATA, 32 * 1024, 1, 2), tail],
            true,
        ),
        (
            "data outside RAM",
            vec![header, (u64::MAX, 512, 1, 2), tail],
            true,
        ),
        ("indirect descriptor", vec![header, (DATA, 32, 4, 0)], false),
        ("cycle", vec![(header_addr, 16, 1, 0)], false),
        ("invalid next", vec![(header_addr, 16, 1, 99)], false),
        ("too many ranges", too_many_ranges, false),
        (
            "partial sector",
            vec![header, (DATA, 100, 1, 2), tail],
            true,
        ),
    ];
    for (name, descriptors, completes_with_ioerr) in cases {
        fixture
            .store
            .data_mut()
            .context
            .guest_write(STATUS, &[0xFF])
            .unwrap();
        for (index, (addr, len, flags, next)) in descriptors.into_iter().enumerate() {
            let mut bytes = [0; 16];
            bytes[..8].copy_from_slice(&addr.to_le_bytes());
            bytes[8..12].copy_from_slice(&len.to_le_bytes());
            bytes[12..14].copy_from_slice(&flags.to_le_bytes());
            bytes[14..].copy_from_slice(&next.to_le_bytes());
            fixture
                .store
                .data_mut()
                .context
                .guest_write(table_addr + u64::try_from(index).unwrap() * 16, &bytes)
                .unwrap();
        }
        let (completion,) = fixture
            .execute_chain
            .call_async(&mut fixture.store, (0, table_addr, 32, 0))
            .await
            .unwrap();
        if completes_with_ioerr {
            let completion = completion.unwrap_or_else(|error| panic!("{name}: {error:?}"));
            assert_eq!((completion.status, completion.used_len), (1, 1), "{name}");
            assert_eq!(status(&fixture), 1, "{name}");
        } else {
            assert!(completion.is_err(), "{name}");
            assert_eq!(status(&fixture), 0xFF, "{name}");
        }
    }
    let (result,) = fixture
        .execute
        .call_async(&mut fixture.store, (T_IN, 0, one(DATA, 512), STATUS, 0))
        .await
        .unwrap();
    assert_eq!(result, 0);
    assert_eq!(
        fixture
            .store
            .data_mut()
            .context
            .guest_read(DATA, 512)
            .unwrap(),
        [0; 512]
    );
}
