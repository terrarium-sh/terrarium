//! Block regressions through the production MMIO queues, memory, and disk imports.

use crate::component::StandaloneDevice;
use crate::component::block::BlockHost;
use crate::component::block::backing::{BlockBacking, BoundedDisk, DiskGrant};
use crate::engine::{device_engine, precompile_component};
use crate::memory::{BoundedMemory, GuestRam, MemoryError};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use terra_platform::memory::MemoryRange as Range;
use wasmtime::component::Component;

const RAM: u64 = 256 * 1024;
const DATA: u64 = 0x2000;
const STATUS: u64 = 0x3000;
const HEADER: u64 = 0x1000;
const DESCRIPTORS: u64 = 0x21000;
const AVAILABLE: u64 = 0x22000;
const USED: u64 = 0x23000;
const QUEUE_SIZE: u16 = 32;
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;
const T_DISCARD: u32 = 11;

type Descriptor = (u64, u32, u16, u16);

fn one(addr: u64, len: u64) -> Vec<Range> {
    vec![Range { addr, len }]
}

pub(super) struct Fixture {
    pub(super) device: StandaloneDevice,
    ram: GuestRam,
    memory_read_calls: Arc<[AtomicU64; 2]>,
    available: u16,
    used: u16,
    is_queue_ready: bool,
}

impl Fixture {
    pub(super) fn write(&self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        BoundedMemory::new(&self.ram).write(address, bytes)
    }

    pub(super) fn read(&self, address: u64, len: u64) -> Result<Vec<u8>, MemoryError> {
        BoundedMemory::new(&self.ram).read(address, len)
    }

    fn memory_read_import_counts(&self) -> (u64, u64) {
        (
            self.memory_read_calls[0].load(Ordering::Relaxed),
            self.memory_read_calls[1].load(Ordering::Relaxed),
        )
    }

    fn read_register(&self, offset: u64) -> u64 {
        u64::from(u32::from_le_bytes(
            self.device.read(offset, 4).unwrap().try_into().unwrap(),
        ))
    }

    fn drain_interrupt(&self) -> bool {
        let interrupt = self.read_register(0x060);
        self.device.write(0x064, &1_u32.to_le_bytes()).unwrap();
        interrupt != 0
    }

    fn configure_queue(&mut self) {
        for (offset, value) in [
            (0x70, 1_u32),
            (0x70, 3),
            (0x24, 1),
            (0x20, 1),
            (0x70, 11),
            (0x38, u32::from(QUEUE_SIZE)),
            (0x80, u32::try_from(DESCRIPTORS).unwrap()),
            (0x90, u32::try_from(AVAILABLE).unwrap()),
            (0xa0, u32::try_from(USED).unwrap()),
            (0x44, 1),
            (0x70, 15),
        ] {
            self.device.write(offset, &value.to_le_bytes()).unwrap();
        }
        self.is_queue_ready = true;
    }

    pub(super) fn clear_queue(&mut self) {
        self.write(AVAILABLE, &[0; 4]).unwrap();
        self.write(USED, &[0; 4]).unwrap();
        self.available = 0;
        self.used = 0;
        self.is_queue_ready = false;
    }

    fn stage_descriptors(&mut self, descriptors: &[Descriptor]) {
        if !self.is_queue_ready {
            self.configure_queue();
        }
        for (index, (address, len, flags, next)) in descriptors.iter().enumerate() {
            let mut bytes = [0; 16];
            bytes[..8].copy_from_slice(&address.to_le_bytes());
            bytes[8..12].copy_from_slice(&len.to_le_bytes());
            bytes[12..14].copy_from_slice(&flags.to_le_bytes());
            bytes[14..].copy_from_slice(&next.to_le_bytes());
            self.write(DESCRIPTORS + u64::try_from(index).unwrap() * 16, &bytes)
                .unwrap();
        }
        self.write(
            AVAILABLE + 4 + u64::from(self.available % QUEUE_SIZE) * 2,
            &0_u16.to_le_bytes(),
        )
        .unwrap();
        self.available = self.available.wrapping_add(1);
        self.write(AVAILABLE + 2, &self.available.to_le_bytes())
            .unwrap();
    }

    pub(super) fn stage_request(
        &mut self,
        request_type: u32,
        sector: u64,
        ranges: &[Range],
        status_addr: u64,
    ) {
        let mut header = [0; 16];
        header[..4].copy_from_slice(&request_type.to_le_bytes());
        header[8..].copy_from_slice(&sector.to_le_bytes());
        self.write(HEADER, &header).unwrap();
        self.write(status_addr, &[0xFF]).unwrap();
        let mut descriptors = vec![(HEADER, 16, 1, 1)];
        let writable = u16::from(!matches!(request_type, T_OUT | T_DISCARD)) * 2;
        descriptors.extend(ranges.iter().enumerate().map(|(index, range)| {
            (
                range.addr,
                u32::try_from(range.len).unwrap(),
                1 | writable,
                u16::try_from(index + 2).unwrap(),
            )
        }));
        descriptors.push((status_addr, 1, 2, 0));
        self.stage_descriptors(&descriptors);
    }

    pub(super) async fn complete_request(&mut self) -> u32 {
        self.device.write(0x050, &0_u32.to_le_bytes()).unwrap();
        let expected = self.used.wrapping_add(1).to_le_bytes();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while self.read(USED + 2, 2).unwrap() != expected {
                assert!(
                    self.device.failure().is_none(),
                    "{:?}",
                    self.device.failure()
                );
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("queue request completes");
        let entry = USED + 4 + u64::from(self.used % QUEUE_SIZE) * 8;
        assert_eq!(self.read(entry, 4).unwrap(), [0; 4]);
        let used_len = u32::from_le_bytes(self.read(entry + 4, 4).unwrap().try_into().unwrap());
        self.used = self.used.wrapping_add(1);
        used_len
    }

    pub(super) async fn submit_request(
        &mut self,
        request_type: u32,
        sector: u64,
        ranges: &[Range],
        status_addr: u64,
    ) -> u8 {
        self.stage_request(request_type, sector, ranges, status_addr);
        self.complete_request().await;
        self.read(status_addr, 1).unwrap()[0]
    }
}

async fn fixture(capacity_sectors: usize, readonly: bool) -> Fixture {
    let engine = device_engine().expect("engine builds");
    let mut disk = BoundedDisk::new(capacity_sectors * 512, readonly);
    if !readonly {
        disk.write_at(3 * 512, &[0xAB; 512]).ok();
    }
    let component = Component::new(&engine, crate::test_fixtures::wasm::BLOCK)
        .expect("block component compiles");
    fixture_with_host(
        &engine,
        BlockHost::new(GuestRam::new(RAM).unwrap(), DiskGrant::Mem(disk)),
        &component,
        readonly,
    )
    .await
}

async fn fixture_with_disk(
    engine: &wasmtime::Engine,
    disk: DiskGrant,
    component: &Component,
) -> Fixture {
    fixture_with_host(
        engine,
        BlockHost::new(GuestRam::new(RAM).unwrap(), disk),
        component,
        false,
    )
    .await
}

pub(super) async fn fixture_with_host(
    engine: &wasmtime::Engine,
    host: BlockHost,
    component: &Component,
    readonly: bool,
) -> Fixture {
    let ram = host.context.guest_ram().clone();
    let memory_read_calls = host.context.memory_read_import_counters();
    let device = crate::component::block::instantiate(
        engine,
        host,
        component,
        readonly,
        Arc::new(|_| Ok(())),
    )
    .await
    .expect("block worker starts");
    Fixture {
        device,
        ram,
        memory_read_calls,
        available: 0,
        used: 0,
        is_queue_ready: false,
    }
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
                    .write(
                        range.addr,
                        &vec![0; usize::try_from(range.len).expect("range fits usize")],
                    )
                    .expect("read destination cleared");
            }
        }
        let before = fixture.memory_read_import_counts();
        let start = std::time::Instant::now();
        for _ in 0..CALLS_PER_SAMPLE {
            let result = fixture
                .submit_request(request_type, 0, ranges, 0x20000)
                .await;
            assert_eq!(result, 0);
        }
        let elapsed = start.elapsed();
        let after = fixture.memory_read_import_counts();
        memory_calls_per_operation = (
            (after.0 - before.0) / CALLS_PER_SAMPLE as u64,
            (after.1 - before.1) / CALLS_PER_SAMPLE as u64,
        );
        assert_eq!(fixture.read(0x20000, 1).expect("status readable"), [0]);
        if request_type == T_IN {
            for range in ranges {
                let data = fixture
                    .read(range.addr, range.len)
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
        "terra_block_bench path=mmio_queue version={version} operation={} bytes={bytes} calls_per_sample={CALLS_PER_SAMPLE} samples={MEASURED_SAMPLES} median_ns_per_call={median_ns} p95_ns_per_call={p95_ns} median_bytes_per_second={bytes_per_second} memory_read_calls_per_operation={} memory_read_ranges_calls_per_operation={}",
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "AOT file-backed MMIO queue benchmark; run with --release --ignored --nocapture"]
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
            let mut fixture =
                fixture_with_disk(&engine, DiskGrant::File(backing), &component).await;
            for range in &ranges {
                fixture
                    .write(
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn component_mmio_state_survives_async_calls_and_close_is_terminal() {
    let fixture = fixture(8, false).await;
    assert_eq!(
        fixture.device.read(0, 4).unwrap(),
        0x7472_6976_u32.to_le_bytes()
    );
    fixture.device.write(0x070, &1_u32.to_le_bytes()).unwrap();
    assert_eq!(fixture.device.read(0x070, 4).unwrap(), 1_u32.to_le_bytes());
    assert_eq!(fixture.device.read(0x060, 4).unwrap(), [0; 4]);
    fixture.device.close().unwrap();
    assert!(fixture.device.reset().is_err());
    assert!(fixture.device.read(0x044, 4).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn component_advertises_bounded_io_flush_and_discard() {
    let fixture = fixture(256, false).await;
    assert_eq!(fixture.read_register(0x108), u64::from(16 * 1024u32));
    assert_eq!(fixture.read_register(0x10c), 4);
    assert_eq!(
        fixture.read_register(0x010),
        u64::from((1u32 << 1) | (1 << 2) | (1 << 9) | (1 << 13))
    );
    assert_eq!(
        fixture.read_register(0x124),
        terra_limits::MAX_GUEST_DISCARD_BYTES / 512
    );
    assert_eq!(fixture.read_register(0x128), 1);
    fixture.device.write(0x014, &1_u32.to_le_bytes()).unwrap();
    assert_eq!(fixture.read_register(0x010), 1);
}

fn status(fixture: &Fixture) -> u8 {
    fixture.read(STATUS, 1).expect("status readable")[0]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn component_read_write_round_trip() {
    let mut fixture = fixture(8, false).await;
    fixture.write(DATA, &[0xCDu8; 512]).expect("payload staged");
    let result = fixture
        .submit_request(T_OUT, 1, &one(DATA, 512), STATUS)
        .await;
    assert_eq!(result, 0);
    assert_eq!(status(&fixture), 0);
    assert!(fixture.drain_interrupt());
    fixture.write(DATA, &[0u8; 512]).expect("buffer cleared");
    let result = fixture
        .submit_request(T_IN, 1, &one(DATA, 512), STATUS)
        .await;
    assert_eq!(result, 0);
    assert_eq!(fixture.read(DATA, 512).expect("read back"), [0xCDu8; 512]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn component_discard_reaches_the_backing_without_changing_neighbors() {
    let mut fixture = fixture(8, false).await;
    fixture.write(DATA, &[0x5A; 1536]).expect("payload staged");
    let status = fixture
        .submit_request(T_OUT, 0, &one(DATA, 1536), STATUS)
        .await;
    assert_eq!(status, 0);

    let mut discard = [0; 16];
    discard[..8].copy_from_slice(&1_u64.to_le_bytes());
    discard[8..12].copy_from_slice(&1_u32.to_le_bytes());
    fixture.write(DATA, &discard).expect("discard range staged");
    let status = fixture
        .submit_request(T_DISCARD, 0, &one(DATA, 16), STATUS)
        .await;
    assert_eq!(status, 0);

    let status = fixture
        .submit_request(T_IN, 0, &one(DATA, 1536), STATUS)
        .await;
    assert_eq!(status, 0);
    let contents = fixture.read(DATA, 1536).expect("read back");
    assert_eq!(&contents[..512], &[0x5A; 512]);
    assert_eq!(&contents[512..1024], &[0; 512]);
    assert_eq!(&contents[1024..], &[0x5A; 512]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn component_scatters_across_ranges_in_order() {
    let mut fixture = fixture(8, false).await;
    fixture
        .write(DATA, &[0x11u8; 512])
        .expect("first half staged");
    fixture
        .write(DATA + 512, &[0x22u8; 512])
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
    let result = fixture.submit_request(T_OUT, 4, &ranges, STATUS).await;
    assert_eq!(result, 0);
    fixture.write(DATA, &[0u8; 512]).expect("buffer cleared");
    fixture
        .write(DATA + 512, &[0u8; 512])
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
    let result = fixture.submit_request(T_IN, 4, &ranges, STATUS).await;
    assert_eq!(result, 0);
    assert_eq!(fixture.read(DATA, 512).expect("first back"), [0x11u8; 512]);
    assert_eq!(
        fixture.read(DATA + 512, 512).expect("second back"),
        [0x22u8; 512]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn component_transfers_the_full_batch_across_distinct_ranges() {
    let mut fixture = fixture(256, false).await;
    let ranges: Vec<_> = (0..4u64)
        .map(|index| Range {
            addr: 0x4000 + index * 16 * 1024,
            len: 16 * 1024,
        })
        .collect();
    for (range, pattern) in ranges.iter().zip([0x11, 0x22, 0x33, 0x44]) {
        fixture
            .write(range.addr, &[pattern; 16 * 1024])
            .expect("batch payload staged");
    }
    let before = fixture.memory_read_import_counts();
    let write_status = fixture.submit_request(T_OUT, 0, &ranges, STATUS).await;
    assert_eq!(write_status, 0);
    let after = fixture.memory_read_import_counts();
    assert!(after.0 > before.0);
    assert_eq!(after.1 - before.1, 1);
    for range in &ranges {
        fixture
            .write(range.addr, &[0; 16 * 1024])
            .expect("batch destination cleared");
    }
    let read_status = fixture.submit_request(T_IN, 0, &ranges, STATUS).await;
    assert_eq!(read_status, 0);
    for (range, pattern) in ranges.iter().zip([0x11, 0x22, 0x33, 0x44]) {
        assert_eq!(
            fixture
                .read(range.addr, range.len)
                .expect("batch payload readable"),
            [pattern; 16 * 1024]
        );
    }
    let mut over_total = ranges;
    over_total.push(Range {
        addr: 0x14000,
        len: 512,
    });
    let oversize_status = fixture.submit_request(T_OUT, 0, &over_total, STATUS).await;
    assert_eq!(oversize_status, 1);
    let oversize_status = fixture
        .submit_request(T_OUT, 0, &one(0x4000, 16 * 1024 + 1), STATUS)
        .await;
    assert_eq!(oversize_status, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn component_ignores_zero_length_ranges_at_invalid_addresses() {
    let mut fixture = fixture(8, false).await;
    fixture.write(DATA, &[0xA5; 512]).expect("payload staged");
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
    let write_status = fixture.submit_request(T_OUT, 0, &ranges, STATUS).await;
    assert_eq!(write_status, 0);
    fixture.write(DATA, &[0; 512]).expect("destination cleared");
    let read_status = fixture.submit_request(T_IN, 0, &ranges, STATUS).await;
    assert_eq!(read_status, 0);
    assert_eq!(
        fixture.read(DATA, 512).expect("payload readable"),
        [0xA5; 512]
    );
    let empty_status = fixture
        .submit_request(T_IN, 0, &one(u64::MAX, 0), STATUS)
        .await;
    assert_eq!(empty_status, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_later_range_does_not_partially_write_a_batch() {
    let mut fixture = fixture(8, false).await;
    fixture
        .write(DATA, &[0xA5; 512])
        .expect("first range staged");
    let write_status = fixture
        .submit_request(
            T_OUT,
            0,
            &[
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
        )
        .await;
    assert_eq!(write_status, 1);
    let read_status = fixture
        .submit_request(T_IN, 0, &one(DATA + 1024, 1024), STATUS)
        .await;
    assert_eq!(read_status, 0);
    assert_eq!(
        fixture
            .read(DATA + 1024, 1024)
            .expect("disk contents copied"),
        [0; 1024]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn component_readonly_and_oob_are_ioerr() {
    let mut fixture = fixture(8, true).await;
    fixture.write(DATA, &[0xCDu8; 512]).expect("payload staged");
    let result = fixture
        .submit_request(T_OUT, 0, &one(DATA, 512), STATUS)
        .await;
    assert_eq!(result, 1);
    assert_eq!(status(&fixture), 1);
    let result = fixture
        .submit_request(T_IN, 8, &one(DATA, 512), STATUS)
        .await;
    assert_eq!(result, 1);
    let result = fixture
        .submit_request(T_IN, u64::MAX, &one(DATA, 512), STATUS)
        .await;
    assert_eq!(result, 1);
    let result = fixture
        .submit_request(T_IN, 0, &one(DATA, 1 << 20), STATUS)
        .await;
    assert_eq!(result, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn component_flush_identify_and_unsupported() {
    let mut fixture = fixture(8, false).await;
    let result = fixture.submit_request(T_FLUSH, 0, &[], STATUS).await;
    assert_eq!(result, 0);
    assert!(fixture.drain_interrupt());
    for (request_type, sector, ranges) in [(T_FLUSH, 7, vec![]), (T_FLUSH, 0, one(DATA, 512))] {
        let result = fixture
            .submit_request(request_type, sector, &ranges, STATUS)
            .await;
        assert_eq!(result, 1);
        assert_eq!(status(&fixture), 1);
    }
    let result = fixture
        .submit_request(0xFFFF, 0, &one(DATA, 512), STATUS)
        .await;
    assert_eq!(result, 2);
    assert_eq!(status(&fixture), 2);
    assert!(fixture.drain_interrupt());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn component_reset_discards_the_old_queue_until_renegotiated() {
    let mut fixture = fixture(8, false).await;
    fixture.configure_queue();
    fixture.write(DATA, &[0xCD; 512]).unwrap();
    fixture.stage_request(T_OUT, 1, &one(DATA, 512), STATUS);
    fixture.device.reset().unwrap();
    assert_eq!(fixture.read_register(0x044), 0);
    assert_eq!(status(&fixture), 0xFF);
    assert_eq!(fixture.read(USED + 2, 2).unwrap(), [0; 2]);
    fixture.clear_queue();
    assert_eq!(
        fixture
            .submit_request(T_IN, 1, &one(DATA, 512), STATUS)
            .await,
        0
    );
    assert_eq!(fixture.read(DATA, 512).unwrap(), [0; 512]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(unsafe_code)]
async fn component_aot_deserialize_runs() {
    let engine = device_engine().expect("engine builds");
    let artifact =
        precompile_component(&engine, crate::test_fixtures::wasm::BLOCK).expect("precompiles");
    assert!(!artifact.is_empty());
    // SAFETY: The artifact was produced from the trusted component above with the same engine.
    let component = unsafe { Component::deserialize(&engine, &artifact).expect("deserializes") };
    let mut fixture = fixture_with_disk(
        &engine,
        DiskGrant::Mem(BoundedDisk::new(8 * 512, false)),
        &component,
    )
    .await;
    assert_eq!(
        fixture
            .submit_request(T_IN, 0, &one(DATA, 512), STATUS)
            .await,
        0
    );
    assert_eq!(fixture.read(USED + 8, 4).unwrap(), 513_u32.to_le_bytes());
    assert_eq!(fixture.submit_request(T_FLUSH, 0, &[], STATUS).await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn component_operates_on_shared_machine_ram() {
    use terra_platform::memory::GuestMemory;
    let engine = device_engine().expect("engine builds");
    let mem = GuestMemory::allocate(RAM).expect("maps");
    let mut disk = BoundedDisk::new(8 * 512, false);
    disk.write_at(2 * 512, &[0x5E; 512]).expect("pattern in");
    let component =
        Component::new(&engine, crate::test_fixtures::wasm::BLOCK).expect("component compiles");
    let mut fixture = fixture_with_host(
        &engine,
        BlockHost::new(GuestRam::from_memory(mem.clone()), DiskGrant::Mem(disk)),
        &component,
        false,
    )
    .await;
    assert_eq!(
        fixture
            .submit_request(T_IN, 2, &one(DATA, 512), STATUS)
            .await,
        0
    );
    assert_eq!(mem.read(DATA, 512).unwrap(), [0x5E; 512]);
    assert_eq!(mem.read(STATUS, 1).unwrap(), [0]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn component_rejects_malformed_chains_without_writing_the_disk() {
    let mut fixture = fixture(8, false).await;
    let header_addr = 0x1000;
    let mut header = [0; 16];
    header[..4].copy_from_slice(&T_OUT.to_le_bytes());
    fixture.write(header_addr, &header).unwrap();
    fixture.write(DATA, &[0xCD; 512]).unwrap();
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
        fixture.write(STATUS, &[0xFF]).unwrap();
        fixture.stage_descriptors(&descriptors);
        let used_len = fixture.complete_request().await;
        assert_eq!(used_len, u32::from(completes_with_ioerr), "{name}");
        assert_eq!(
            status(&fixture),
            if completes_with_ioerr { 1 } else { 0xFF },
            "{name}"
        );
    }
    let result = fixture
        .submit_request(T_IN, 0, &one(DATA, 512), STATUS)
        .await;
    assert_eq!(result, 0);
    assert_eq!(fixture.read(DATA, 512).unwrap(), [0; 512]);
}
