use std::ops::Range as ByteRange;
use std::sync::{LazyLock, Mutex};

use terra_device_transport::{
    Doorbell, INT_USED_BUFFER, MmioTransport, SPLIT_RING_DESC_F_NEXT, SPLIT_RING_DESC_F_WRITE,
    SPLIT_RING_DESCRIPTOR_BYTES, SplitRingDescriptor, WriteOutcome, complete_split_ring_entry,
    publish_interrupt_asserted, read_split_ring_available, split_ring_chain,
};

use crate::terra::host::{interrupt, memory};
use crate::terra::mem::host::{self, Range};
use crate::terra::mmio::types::DeviceError;

#[derive(Debug, PartialEq, Eq)]
struct QueueEntry {
    descriptor_table: u64,
    available_ring: u64,
    used_ring: u64,
    size: u16,
    head: u16,
}

const REPORT: usize = 2;
const QUEUE_COUNT_U16: u16 = 3;
const QUEUE_COUNT: usize = QUEUE_COUNT_U16 as usize;
const QUEUE_SIZE: u16 = 256;
const DESC_BYTES: u64 = SPLIT_RING_DESCRIPTOR_BYTES as u64;
const MAX_CHAIN: usize = 32;
const MAX_REPORT_BYTES: u64 = 128 * 1024 * 1024;
const PAGE_SIZE: u64 = 4096;
const VIRTIO_F_VERSION_1: u64 = 1 << 32;
const VIRTIO_BALLOON_F_PAGE_POISON: u64 = 1 << 4;
const VIRTIO_BALLOON_F_PAGE_REPORTING: u64 = 1 << 5;
const HOST_FEATURES: u64 =
    VIRTIO_F_VERSION_1 | VIRTIO_BALLOON_F_PAGE_POISON | VIRTIO_BALLOON_F_PAGE_REPORTING;
const CONFIG_BASE: u64 = 0x100;
const CONFIG_BYTES: usize = 16;
const CONFIG_ACTUAL: ByteRange<usize> = 4..8;
const CONFIG_POISON: ByteRange<usize> = 12..16;

struct State {
    mmio: MmioTransport,
    next: [u16; QUEUE_COUNT],
}

static STATE: LazyLock<Mutex<Option<State>>> = LazyLock::new(|| Mutex::new(None));
static QUEUES: Doorbell = Doorbell::new();

fn state<T>(f: impl FnOnce(&mut State) -> Result<T, DeviceError>) -> Result<T, DeviceError> {
    let mut state = STATE.lock().map_err(|_| DeviceError::Io)?;
    let state = state.as_mut().ok_or(DeviceError::NotReady)?;
    let result = f(state);
    if let Some(asserted) = state.mmio.take_irq() {
        publish_interrupt_asserted(asserted, interrupt::set_asserted);
    }
    result
}

terra_device_transport::device_error!(DeviceError);

fn read(addr: u64, len: u64) -> Result<Vec<u8>, DeviceError> {
    memory::read(addr, len).map_err(|_| DeviceError::Unmapped)
}

fn write(addr: u64, bytes: &[u8]) -> Result<(), DeviceError> {
    memory::write(addr, bytes).map_err(|_| DeviceError::Unmapped)
}

fn chain(table: &[u8], index: u16, size: u16) -> Result<Vec<SplitRingDescriptor>, DeviceError> {
    split_ring_chain(
        table,
        index,
        size,
        MAX_CHAIN,
        SPLIT_RING_DESC_F_NEXT | SPLIT_RING_DESC_F_WRITE,
    )
    .map_err(DeviceError::from)
}

fn available(state: &mut State, queue: usize) -> Result<Option<QueueEntry>, DeviceError> {
    if state.mmio.negotiated() & VIRTIO_F_VERSION_1 == 0 {
        return Err(DeviceError::NotReady);
    }
    let (descriptor_table, available_ring, used_ring, size) = state
        .mmio
        .queue_addrs_for(queue)
        .ok_or(DeviceError::NotReady)?;
    let (_, head) = read_split_ring_available(available_ring, size, &mut state.next[queue], read)?;
    Ok(head.map(|head| QueueEntry {
        descriptor_table,
        available_ring,
        used_ring,
        size,
        head,
    }))
}

fn complete(state: &mut State, queue: usize, ring: &QueueEntry) -> Result<(), DeviceError> {
    complete_split_ring_entry(ring.used_ring, ring.size, ring.head, 0, read, write)?;
    state.next[queue] = state.next[queue].wrapping_add(1);
    state.mmio.signal(INT_USED_BUFFER);
    Ok(())
}

fn overlaps(left: Range, right: Range) -> bool {
    let Some(left_end) = left.addr.checked_add(left.len) else {
        return true;
    };
    let Some(right_end) = right.addr.checked_add(right.len) else {
        return true;
    };
    left.addr < right_end && right.addr < left_end
}

fn report_ranges(
    descriptors: &[SplitRingDescriptor],
    descriptor_table: Range,
    available_ring: Range,
    used_ring: Range,
) -> Result<Vec<Range>, DeviceError> {
    if descriptors.is_empty() || descriptors.len() > MAX_CHAIN {
        return Err(DeviceError::BadLen);
    }
    let mut bytes = 0_u64;
    let mut ranges = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        if descriptor.flags & SPLIT_RING_DESC_F_WRITE == 0 || descriptor.len == 0 {
            return Err(DeviceError::BadLen);
        }
        let range = Range {
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

/// Writes `num_pages`/`actual` or `poison_val`, the only driver-writable config fields.
fn config_write(config: &mut [u8], offset: u64, data: &[u8]) -> Result<(), DeviceError> {
    let start = usize::try_from(offset).map_err(|_| DeviceError::BadLen)?;
    let field = start..start.checked_add(data.len()).ok_or(DeviceError::BadLen)?;
    let is_writable = [CONFIG_ACTUAL, CONFIG_POISON]
        .iter()
        .any(|writable| writable.start <= field.start && field.end <= writable.end);
    if !is_writable || !matches!(data.len(), 1 | 2 | 4) {
        return Err(DeviceError::BadLen);
    }
    config[field].copy_from_slice(data);
    Ok(())
}

fn poison_is_zero(config: &[u8]) -> bool {
    config
        .get(CONFIG_POISON)
        .is_some_and(|poison| poison.iter().all(|byte| *byte == 0))
}

fn discard_report(state: &State, ring: &QueueEntry) -> Result<(), DeviceError> {
    let table = read(ring.descriptor_table, u64::from(ring.size) * DESC_BYTES)?;
    let descriptors = chain(&table, ring.head, ring.size)?;
    let ranges = report_ranges(
        &descriptors,
        Range {
            addr: ring.descriptor_table,
            len: u64::from(ring.size) * DESC_BYTES,
        },
        Range {
            addr: ring.available_ring,
            len: 4 + u64::from(ring.size) * 2,
        },
        Range {
            addr: ring.used_ring,
            len: 4 + u64::from(ring.size) * 8,
        },
    )?;
    // A nonzero poison value means freed pages must keep it, so discarding would zero them.
    if poison_is_zero(state.mmio.config()) {
        // Reclaim is advisory; unsupported host pages must not stop the balloon worker.
        let _ = host::discard(&ranges);
    }
    Ok(())
}

pub fn configure() -> Result<(), DeviceError> {
    QUEUES.reset();
    publish_interrupt_asserted(false, interrupt::set_asserted);
    *STATE.lock().map_err(|_| DeviceError::Io)? = Some(State {
        mmio: MmioTransport::new(
            memory::address_limit(),
            5,
            HOST_FEATURES,
            QUEUE_SIZE,
            vec![0; CONFIG_BYTES],
        )
        .with_queue_count(QUEUE_COUNT_U16),
        next: [0; QUEUE_COUNT],
    });
    Ok(())
}

pub fn mmio_read(addr: u64, width: u8) -> Result<u64, DeviceError> {
    state(|state| state.mmio.read(addr, width).map_err(DeviceError::from))
}

pub fn mmio_write(addr: u64, width: u8, value: u64) -> Result<(), DeviceError> {
    state(|state| {
        if let Some(offset) = addr.checked_sub(CONFIG_BASE) {
            let bytes = value.to_le_bytes();
            let data = bytes.get(..usize::from(width)).ok_or(DeviceError::BadLen)?;
            return config_write(state.mmio.config_mut(), offset, data);
        }
        match state
            .mmio
            .write(addr, width, value)
            .map_err(DeviceError::from)?
        {
            WriteOutcome::None => {}
            WriteOutcome::Reset => state.next = [0; QUEUE_COUNT],
            WriteOutcome::QueueNotify(queue) => QUEUES.ring(1_u32 << queue),
        }
        Ok(())
    })
}

pub async fn run() -> Result<(), DeviceError> {
    while !QUEUES.is_closed() {
        let queues = QUEUES.wait().await;
        for queue in 0..QUEUE_COUNT {
            if queues & (1 << queue) == 0 {
                continue;
            }
            loop {
                // An unaddressable ring cannot be completed; wait for reset or another doorbell.
                let processed = state(|state| {
                    let Some(ring) = available(state, queue)? else {
                        return Ok(false);
                    };
                    if queue == REPORT {
                        let _ = discard_report(state, &ring);
                    }
                    complete(state, queue, &ring)?;
                    Ok(true)
                })
                .unwrap_or(false);
                if !processed {
                    break;
                }
                wit_bindgen::rt::async_support::yield_async().await;
            }
        }
    }
    Ok(())
}

pub fn interrupt_level() -> bool {
    state(|state| Ok(state.mmio.interrupt_status() & INT_USED_BUFFER != 0)).unwrap_or(false)
}

pub fn reset() {
    if !QUEUES.is_closed() {
        let _ = configure();
    }
}

pub fn close() -> Result<(), DeviceError> {
    QUEUES.close();
    *STATE.lock().map_err(|_| DeviceError::Io)? = None;
    publish_interrupt_asserted(false, interrupt::set_asserted);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_does_not_reopen_a_closed_device() {
        QUEUES.close();
        *STATE.lock().unwrap() = None;
        reset();
        assert!(STATE.lock().unwrap().is_none());
        QUEUES.reset();
    }

    const TABLE: Range = Range {
        addr: 0x10_000,
        len: 512,
    };
    const AVAIL: Range = Range {
        addr: 0x20_000,
        len: 512,
    };
    const USED: Range = Range {
        addr: 0x30_000,
        len: 1024,
    };

    fn data_descriptor(addr: u64, len: u32, flags: u16) -> SplitRingDescriptor {
        SplitRingDescriptor {
            addr,
            len,
            flags,
            next: 0,
        }
    }

    #[test]
    fn report_ranges_accept_page_aligned_writable_pages() {
        let ranges = report_ranges(
            &[data_descriptor(0x40_000, 8192, SPLIT_RING_DESC_F_WRITE)],
            TABLE,
            AVAIL,
            USED,
        )
        .unwrap();
        assert_eq!(
            ranges,
            vec![Range {
                addr: 0x40_000,
                len: 8192
            }]
        );
    }

    #[test]
    fn report_ranges_rejects_hostile_ranges() {
        for descriptor in [
            data_descriptor(0x40_001, 4096, SPLIT_RING_DESC_F_WRITE),
            data_descriptor(0x40_000, 1, SPLIT_RING_DESC_F_WRITE),
            data_descriptor(u64::MAX - 4095, 8192, SPLIT_RING_DESC_F_WRITE),
            data_descriptor(0x40_000, 4096, 0),
            data_descriptor(TABLE.addr, 4096, SPLIT_RING_DESC_F_WRITE),
            data_descriptor(AVAIL.addr, 4096, SPLIT_RING_DESC_F_WRITE),
            data_descriptor(USED.addr, 4096, SPLIT_RING_DESC_F_WRITE),
        ] {
            assert!(report_ranges(&[descriptor], TABLE, AVAIL, USED).is_err());
        }
    }

    #[test]
    fn report_ranges_rejects_unbounded_batches() {
        let descriptors =
            vec![data_descriptor(0x40_000, 4096, SPLIT_RING_DESC_F_WRITE); MAX_CHAIN + 1];
        assert_eq!(
            report_ranges(&descriptors, TABLE, AVAIL, USED),
            Err(DeviceError::BadLen)
        );
        assert_eq!(
            report_ranges(
                &[data_descriptor(
                    0x40_000,
                    u32::try_from(MAX_REPORT_BYTES + PAGE_SIZE).unwrap(),
                    SPLIT_RING_DESC_F_WRITE
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
        table[12..14].copy_from_slice(&SPLIT_RING_DESC_F_NEXT.to_le_bytes());
        table[14..16].copy_from_slice(&0_u16.to_le_bytes());
        assert_eq!(chain(&table, 0, 2), Err(DeviceError::BadLen));
        table[12..14].copy_from_slice(&4_u16.to_le_bytes());
        assert_eq!(chain(&table, 0, 2), Err(DeviceError::BadLen));
        assert_eq!(chain(&[], 0, 1), Err(DeviceError::BadLen));
    }

    #[test]
    fn config_writes_reach_only_driver_fields_and_read_back_through_the_transport() {
        assert_ne!(HOST_FEATURES & VIRTIO_BALLOON_F_PAGE_POISON, 0);
        let mut mmio = MmioTransport::new(0, 5, HOST_FEATURES, QUEUE_SIZE, vec![0; CONFIG_BYTES]);
        assert!(poison_is_zero(mmio.config()));
        let actual = CONFIG_ACTUAL.start as u64;
        let poison = CONFIG_POISON.start as u64;
        for offset in [actual, actual + 1, poison] {
            assert_eq!(config_write(mmio.config_mut(), offset, &[0]), Ok(()));
        }
        assert_eq!(
            config_write(mmio.config_mut(), actual, &[1, 2, 3, 4]),
            Ok(())
        );
        assert_eq!(mmio.read(CONFIG_BASE + actual, 4), Ok(0x0403_0201));
        assert_eq!(
            config_write(mmio.config_mut(), poison + 1, &[0xaa, 0xbb]),
            Ok(())
        );
        assert_eq!(mmio.read(CONFIG_BASE + poison, 4), Ok(0x00bb_aa00));
        assert!(!poison_is_zero(mmio.config()));
        assert_eq!(config_write(mmio.config_mut(), poison, &[0; 4]), Ok(()));
        assert!(poison_is_zero(mmio.config()));
        for (offset, data) in [
            (poison, &[0; 8][..]),
            (actual + 3, &[0, 0][..]),
            (0, &[0; 4][..]),
            (u64::MAX, &[0, 0][..]),
            (poison, &[0; 3][..]),
        ] {
            assert_eq!(
                config_write(mmio.config_mut(), offset, data),
                Err(DeviceError::BadLen),
                "{offset:#x} {data:?}"
            );
        }
    }
}
