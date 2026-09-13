use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{LazyLock, Mutex};

use futures::task::AtomicWaker;

use terra_device_transport::{
    INT_USED_BUFFER, MmioError, MmioTransport, QueueEntry, SPLIT_RING_DESC_F_NEXT,
    SPLIT_RING_DESCRIPTOR_BYTES, SplitRingDescriptor, SplitRingError, split_ring_chain,
};

use crate::terra::host::{interrupt, memory};
use crate::terra::mem::host::{self, Range};
use crate::terra::mmio::types::DeviceError;

const INFLATE: usize = 0;
const DEFLATE: usize = 1;
const REPORT: usize = 2;
const QUEUE_COUNT_U16: u16 = 3;
const QUEUE_COUNT: usize = QUEUE_COUNT_U16 as usize;
const QUEUE_SIZE: u16 = 256;
const DESC_BYTES: u64 = SPLIT_RING_DESCRIPTOR_BYTES as u64;
const MAX_CHAIN: usize = 32;
const MAX_REPORT_BYTES: u64 = 128 * 1024 * 1024;
const PAGE_SIZE: u64 = 4096;
const NEXT: u16 = SPLIT_RING_DESC_F_NEXT;
const WRITE: u16 = 2;
const VIRTIO_F_VERSION_1: u64 = 1 << 32;
const VIRTIO_BALLOON_F_PAGE_POISON: u64 = 1 << 4;
const VIRTIO_BALLOON_F_PAGE_REPORTING: u64 = 1 << 5;
const CONFIG_ACTUAL: u64 = 0x104;
const CONFIG_POISON: u64 = 0x10c;

struct State {
    mmio: MmioTransport,
    next: [u16; QUEUE_COUNT],
    config: BalloonConfig,
}

type Descriptor = SplitRingDescriptor;

#[derive(Clone, Copy, Default)]
struct BalloonConfig([u8; 16]);

impl BalloonConfig {
    fn page_contents_are_zeroed(self) -> bool {
        self.0[12..].iter().all(|byte| *byte == 0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GuestRange {
    addr: u64,
    len: u64,
}

static STATE: LazyLock<Mutex<Option<State>>> = LazyLock::new(|| Mutex::new(None));
static CLOSED: AtomicBool = AtomicBool::new(false);
static PENDING_QUEUES: AtomicU32 = AtomicU32::new(0);
static QUEUE_WAKER: AtomicWaker = AtomicWaker::new();

async fn wait_for_queues() -> u32 {
    std::future::poll_fn(|context| {
        let pending = PENDING_QUEUES.swap(0, Ordering::AcqRel);
        if pending != 0 || CLOSED.load(Ordering::Acquire) {
            return std::task::Poll::Ready(pending);
        }
        QUEUE_WAKER.register(context.waker());
        let pending = PENDING_QUEUES.swap(0, Ordering::AcqRel);
        if pending != 0 || CLOSED.load(Ordering::Acquire) {
            std::task::Poll::Ready(pending)
        } else {
            std::task::Poll::Pending
        }
    })
    .await
}

fn publish_interrupt_level(level: bool) {
    if cfg!(target_arch = "wasm32") {
        crate::terra::host::interrupt::set_level(level);
    }
}

fn state<T>(f: impl FnOnce(&mut State) -> Result<T, DeviceError>) -> Result<T, DeviceError> {
    let mut state = STATE.lock().map_err(|_| DeviceError::Io)?;
    let state = state.as_mut().ok_or(DeviceError::NotReady)?;
    let result = f(state);
    if let Some(level) = state.mmio.take_irq() {
        publish_interrupt_level(level);
    }
    result
}

impl From<MmioError> for DeviceError {
    fn from(error: MmioError) -> Self {
        terra_device_transport::device_error!(error, DeviceError)
    }
}

fn read(addr: u64, len: u64) -> Result<Vec<u8>, DeviceError> {
    memory::read(addr, len).map_err(|_| DeviceError::Unmapped)
}

fn write(addr: u64, bytes: &[u8]) -> Result<(), DeviceError> {
    memory::write(addr, bytes).map_err(|_| DeviceError::Unmapped)
}

fn chain(table: &[u8], index: u16, size: u16) -> Result<Vec<Descriptor>, DeviceError> {
    split_ring_chain(table, index, size, MAX_CHAIN, NEXT | WRITE).map_err(|error| match error {
        SplitRingError::BadDescriptor => DeviceError::BadLen,
        SplitRingError::ChainTooLong => DeviceError::TooLarge,
    })
}

fn available(state: &mut State, queue: usize) -> Result<Option<QueueEntry>, DeviceError> {
    if state.mmio.negotiated() & VIRTIO_F_VERSION_1 == 0
        || state.mmio.queue_addrs_for(queue).is_none()
    {
        return Err(DeviceError::NotReady);
    }
    state
        .mmio
        .read_queue_entry(queue, &mut state.next[queue], read)
}

fn complete(state: &mut State, queue: usize, head: u16) -> Result<(), DeviceError> {
    state
        .mmio
        .complete_queue_entry(queue, &mut state.next[queue], head, 0, read, write)?;
    interrupt::signal();
    Ok(())
}

fn overlaps(left: GuestRange, right: GuestRange) -> bool {
    let Some(left_end) = left.addr.checked_add(left.len) else {
        return true;
    };
    let Some(right_end) = right.addr.checked_add(right.len) else {
        return true;
    };
    left.addr < right_end && right.addr < left_end
}

fn report_ranges(
    descriptors: &[Descriptor],
    descriptor_table: GuestRange,
    available_ring: GuestRange,
    used_ring: GuestRange,
) -> Result<Vec<GuestRange>, DeviceError> {
    if descriptors.is_empty() || descriptors.len() > MAX_CHAIN {
        return Err(DeviceError::BadLen);
    }
    let mut bytes = 0_u64;
    let mut ranges = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        if descriptor.flags & WRITE == 0 || descriptor.len == 0 {
            return Err(DeviceError::BadLen);
        }
        let range = GuestRange {
            addr: descriptor.addr,
            len: u64::from(descriptor.len),
        };
        if !range.addr.is_multiple_of(PAGE_SIZE)
            || !range.len.is_multiple_of(PAGE_SIZE)
            || range.addr.checked_add(range.len).is_none()
            || overlaps(range, descriptor_table)
            || overlaps(range, available_ring)
            || overlaps(range, used_ring)
        {
            return Err(DeviceError::BadLen);
        }
        bytes = bytes.checked_add(range.len).ok_or(DeviceError::TooLarge)?;
        if bytes > MAX_REPORT_BYTES {
            return Err(DeviceError::TooLarge);
        }
        ranges.push(range);
    }
    Ok(ranges)
}

fn process_inflate_or_deflate(state: &mut State, queue: usize) -> Result<bool, DeviceError> {
    let Some(ring) = available(state, queue)? else {
        return Ok(false);
    };
    complete(state, queue, ring.head)?;
    Ok(available(state, queue)?.is_some())
}

fn host_features() -> u64 {
    VIRTIO_F_VERSION_1 | VIRTIO_BALLOON_F_PAGE_POISON | VIRTIO_BALLOON_F_PAGE_REPORTING
}

fn config_write(
    config: &mut BalloonConfig,
    addr: u64,
    data: &[u8],
) -> Option<Result<(), DeviceError>> {
    if addr < 0x100 {
        return None;
    }
    let Ok(len) = u64::try_from(data.len()) else {
        return Some(Err(DeviceError::BadLen));
    };
    let Some(end) = addr.checked_add(len) else {
        return Some(Err(DeviceError::BadLen));
    };
    let field = [CONFIG_ACTUAL, CONFIG_POISON]
        .into_iter()
        .find(|field| addr >= *field && end <= *field + 4);
    Some(match field {
        Some(field) if matches!(data.len(), 1 | 2 | 4) => {
            let Ok(relative) = usize::try_from(addr - field) else {
                return Some(Err(DeviceError::BadLen));
            };
            let start = if field == CONFIG_ACTUAL { 4 } else { 12 } + relative;
            let end = start + data.len();
            config.0[start..end].copy_from_slice(data);
            Ok(())
        }
        _ => Err(DeviceError::BadLen),
    })
}

fn config_read(config: BalloonConfig, addr: u64, len: u32) -> Option<Vec<u8>> {
    let len = usize::try_from(len).ok()?;
    let end = addr.checked_add(u64::try_from(len).ok()?)?;
    if addr < 0x100 || end > 0x110 || !matches!(len, 1 | 2 | 4) {
        return None;
    }
    let start = usize::try_from(addr - 0x100).ok()?;
    let end = start.checked_add(len)?;
    Some(config.0.get(start..end)?.to_vec())
}

fn discard_report(state: &State, ring: &QueueEntry) -> Result<(), DeviceError> {
    let table = read(ring.descriptor_table, u64::from(ring.size) * DESC_BYTES)?;
    let descriptors = chain(&table, ring.head, ring.size)?;
    let ranges = report_ranges(
        &descriptors,
        GuestRange {
            addr: ring.descriptor_table,
            len: u64::from(ring.size) * DESC_BYTES,
        },
        GuestRange {
            addr: ring.available_ring,
            len: 4 + u64::from(ring.size) * 2,
        },
        GuestRange {
            addr: ring.used_ring,
            len: 4 + u64::from(ring.size) * 8,
        },
    )?;
    if state.config.page_contents_are_zeroed() {
        let ranges: Vec<Range> = ranges
            .into_iter()
            .map(|range| Range {
                addr: range.addr,
                len: range.len,
            })
            .collect();
        // Reclaim is advisory; unsupported host pages must not stop the balloon worker.
        let _ = host::discard(&ranges);
    }
    Ok(())
}

fn process_report(state: &mut State) -> Result<bool, DeviceError> {
    let Some(ring) = available(state, REPORT)? else {
        return Ok(false);
    };
    if discard_report(state, &ring).is_err() {
        complete(state, REPORT, ring.head)?;
        return Ok(true);
    }
    complete(state, REPORT, ring.head)?;
    Ok(available(state, REPORT)?.is_some())
}

pub fn configure() -> Result<(), DeviceError> {
    CLOSED.store(false, Ordering::Release);
    PENDING_QUEUES.store(0, Ordering::Release);
    publish_interrupt_level(false);
    *STATE.lock().map_err(|_| DeviceError::Io)? = Some(State {
        mmio: MmioTransport::new(
            0,
            0x200,
            memory::ram_bytes(),
            5,
            host_features(),
            QUEUE_SIZE,
            BalloonConfig::default().0.to_vec(),
        )
        .with_queue_count(QUEUE_COUNT_U16),
        next: [0; QUEUE_COUNT],
        config: BalloonConfig::default(),
    });
    Ok(())
}

pub fn mmio_read(addr: u64, len: u32) -> Result<Vec<u8>, DeviceError> {
    state(|state| {
        if let Some(bytes) = config_read(state.config, addr, len) {
            return Ok(bytes);
        }
        state
            .mmio
            .read(addr, usize::try_from(len).map_err(|_| DeviceError::BadLen)?)
            .map_err(DeviceError::from)
    })
}

pub fn mmio_write(addr: u64, data: &[u8]) -> Result<bool, DeviceError> {
    state(|state| {
        if let Some(result) = config_write(&mut state.config, addr, data) {
            return result.map(|()| false);
        }
        let generation = state.mmio.reset_generation();
        let bell = state.mmio.write(addr, data).map_err(DeviceError::from)?;
        if generation != state.mmio.reset_generation() {
            state.next = [0; QUEUE_COUNT];
        }
        if bell.is_some() {
            let queue = u32::from_le_bytes(data.try_into().map_err(|_| DeviceError::BadLen)?);
            if usize::try_from(queue).is_ok_and(|queue| queue < QUEUE_COUNT) {
                PENDING_QUEUES.fetch_or(1 << queue, Ordering::Release);
                QUEUE_WAKER.wake();
            }
        }
        Ok(false)
    })
}

pub fn queue_notify(queue: u32) -> Result<bool, DeviceError> {
    match usize::try_from(queue).map_err(|_| DeviceError::BadQueue)? {
        INFLATE | DEFLATE => state(|state| process_inflate_or_deflate(state, queue as usize)),
        REPORT => state(process_report),
        _ => Err(DeviceError::BadQueue),
    }
}

pub async fn run() -> Result<(), DeviceError> {
    while !CLOSED.load(Ordering::Acquire) {
        let queues = wait_for_queues().await;
        for queue in 0..QUEUE_COUNT {
            if queues & (1 << queue) == 0 {
                continue;
            }
            // An unaddressable ring cannot be completed; wait for reset or another doorbell.
            while queue_notify(u32::try_from(queue).map_err(|_| DeviceError::BadQueue)?)
                .unwrap_or(false)
            {
                wit_bindgen::rt::async_support::yield_async().await;
            }
        }
    }
    Ok(())
}

pub fn interrupt_level() -> bool {
    state(|state| {
        state
            .mmio
            .read(0x60, 4)
            .map(|bytes| {
                u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4])) & INT_USED_BUFFER != 0
            })
            .map_err(DeviceError::from)
    })
    .unwrap_or(false)
}

pub fn reset() {
    if CLOSED.load(Ordering::Acquire) {
        return;
    }
    PENDING_QUEUES.store(0, Ordering::Release);
    let _ = configure();
}

pub fn close() -> Result<(), DeviceError> {
    CLOSED.store(true, Ordering::Release);
    QUEUE_WAKER.wake();
    *STATE.lock().map_err(|_| DeviceError::Io)? = None;
    publish_interrupt_level(false);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_does_not_reopen_a_closed_device() {
        CLOSED.store(true, Ordering::Release);
        *STATE.lock().unwrap() = None;
        reset();
        assert!(STATE.lock().unwrap().is_none());
        CLOSED.store(false, Ordering::Release);
    }

    const TABLE: GuestRange = GuestRange {
        addr: 0x10_000,
        len: 512,
    };
    const AVAIL: GuestRange = GuestRange {
        addr: 0x20_000,
        len: 512,
    };
    const USED: GuestRange = GuestRange {
        addr: 0x30_000,
        len: 1024,
    };

    fn data_descriptor(addr: u64, len: u32, flags: u16) -> Descriptor {
        Descriptor {
            addr,
            len,
            flags,
            next: 0,
        }
    }

    #[test]
    fn report_ranges_accept_page_aligned_writable_pages() {
        let ranges = report_ranges(
            &[data_descriptor(0x40_000, 8192, WRITE)],
            TABLE,
            AVAIL,
            USED,
        )
        .unwrap();
        assert_eq!(
            ranges,
            vec![GuestRange {
                addr: 0x40_000,
                len: 8192
            }]
        );
    }

    #[test]
    fn report_ranges_rejects_hostile_ranges() {
        for descriptor in [
            data_descriptor(0x40_001, 4096, WRITE),
            data_descriptor(0x40_000, 1, WRITE),
            data_descriptor(u64::MAX - 4095, 8192, WRITE),
            data_descriptor(0x40_000, 4096, 0),
            data_descriptor(TABLE.addr, 4096, WRITE),
            data_descriptor(AVAIL.addr, 4096, WRITE),
            data_descriptor(USED.addr, 4096, WRITE),
        ] {
            assert!(report_ranges(&[descriptor], TABLE, AVAIL, USED).is_err());
        }
    }

    #[test]
    fn report_ranges_rejects_unbounded_batches() {
        let descriptors = vec![data_descriptor(0x40_000, 4096, WRITE); MAX_CHAIN + 1];
        assert_eq!(
            report_ranges(&descriptors, TABLE, AVAIL, USED),
            Err(DeviceError::BadLen)
        );
        assert_eq!(
            report_ranges(
                &[data_descriptor(
                    0x40_000,
                    u32::try_from(MAX_REPORT_BYTES + PAGE_SIZE).unwrap(),
                    WRITE
                )],
                TABLE,
                AVAIL,
                USED
            ),
            Err(DeviceError::TooLarge)
        );
    }

    #[test]
    fn chain_rejects_loops_and_invalid_directions() {
        let mut table = vec![0; 32];
        table[12..14].copy_from_slice(&NEXT.to_le_bytes());
        table[14..16].copy_from_slice(&0_u16.to_le_bytes());
        assert_eq!(chain(&table, 0, 2), Err(DeviceError::BadLen));
        table[12..14].copy_from_slice(&4_u16.to_le_bytes());
        assert_eq!(chain(&table, 0, 2), Err(DeviceError::BadLen));
        assert_eq!(chain(&[], 0, 1), Err(DeviceError::BadLen));
    }

    #[test]
    fn page_poison_is_zero_and_reset_forgets_queue_indices() {
        assert_ne!(host_features() & VIRTIO_BALLOON_F_PAGE_POISON, 0);
        assert!(BalloonConfig::default().0.iter().all(|byte| *byte == 0));
        let mut state = State {
            mmio: MmioTransport::new(
                0,
                0x200,
                0,
                5,
                host_features(),
                QUEUE_SIZE,
                BalloonConfig::default().0.to_vec(),
            ),
            next: [1, 2, 3],
            config: BalloonConfig::default(),
        };
        state.next = [0; QUEUE_COUNT];
        assert_eq!(state.next, [0; QUEUE_COUNT]);
    }

    #[test]
    fn config_writes_preserve_partial_poison_values() {
        let mut config = BalloonConfig::default();
        assert_eq!(config_write(&mut config, 0x70, &[0; 4]), None);
        for addr in [CONFIG_ACTUAL, CONFIG_ACTUAL + 1, CONFIG_POISON] {
            assert_eq!(config_write(&mut config, addr, &[0]), Some(Ok(())));
        }
        assert_eq!(
            config_write(&mut config, CONFIG_ACTUAL, &[1, 2, 3, 4]),
            Some(Ok(()))
        );
        assert_eq!(
            config_read(config, CONFIG_ACTUAL, 4),
            Some(vec![1, 2, 3, 4])
        );
        assert_eq!(
            config_write(&mut config, CONFIG_POISON + 1, &[0xaa, 0xbb]),
            Some(Ok(()))
        );
        assert_eq!(
            config_read(config, CONFIG_POISON, 4),
            Some(vec![0, 0xaa, 0xbb, 0])
        );
        assert_eq!(
            config_read(config, CONFIG_POISON - 1, 4),
            Some(vec![0, 0, 0xaa, 0xbb])
        );
        assert!(!config.page_contents_are_zeroed());
        assert_eq!(
            config_write(&mut config, CONFIG_POISON, &[0; 4]),
            Some(Ok(()))
        );
        assert!(config.page_contents_are_zeroed());
        assert_eq!(
            config_write(&mut config, CONFIG_POISON, &[0; 8]),
            Some(Err(DeviceError::BadLen))
        );
        assert_eq!(
            config_write(&mut config, CONFIG_ACTUAL + 3, &[0, 0]),
            Some(Err(DeviceError::BadLen))
        );
        assert_eq!(
            config_write(&mut config, 0x100, &[0; 4]),
            Some(Err(DeviceError::BadLen))
        );
        assert_eq!(
            config_write(&mut config, u64::MAX, &[0, 0]),
            Some(Err(DeviceError::BadLen))
        );
    }
}
