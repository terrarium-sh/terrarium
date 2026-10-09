use std::sync::{LazyLock, Mutex};

use terra_device_transport::{
    Doorbell, INT_USED_BUFFER, MmioTransport, QueueEntry, SPLIT_RING_DESC_F_NEXT,
    SPLIT_RING_DESCRIPTOR_BYTES, SplitRingDescriptor, WriteOutcome, complete_split_ring_entry,
    publish_interrupt_asserted, read_split_ring_available, split_ring_chain,
};

use crate::terra::host::{interrupt, memory};
use crate::terra::mem::host::{self, Range};
use crate::terra::mmio::types::DeviceError;

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

fn chain(table: &[u8], index: u16, size: u16) -> Result<Vec<Descriptor>, DeviceError> {
    split_ring_chain(table, index, size, MAX_CHAIN, NEXT | WRITE).map_err(DeviceError::from)
}

fn available(state: &mut State, queue: usize) -> Result<Option<QueueEntry>, DeviceError> {
    if state.mmio.negotiated() & VIRTIO_F_VERSION_1 == 0 {
        return Err(DeviceError::NotReady);
    }
    let (descriptor_table, available_ring, used_ring, size) = state
        .mmio
        .queue_addrs_for(queue)
        .ok_or(DeviceError::NotReady)?;
    let (_, head) = read_split_ring_available(
        available_ring,
        core::num::NonZeroU16::new(size).ok_or(DeviceError::BadQueue)?,
        &mut state.next[queue],
        read,
    )?;
    Ok(head.map(|head| QueueEntry {
        descriptor_table,
        available_ring,
        used_ring,
        size,
        head,
    }))
}

fn complete(state: &mut State, queue: usize, ring: &QueueEntry) -> Result<(), DeviceError> {
    complete_split_ring_entry(
        ring.used_ring,
        core::num::NonZeroU16::new(ring.size).ok_or(DeviceError::BadQueue)?,
        ring.head,
        0,
        read,
        write,
    )?;
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
    descriptors: &[Descriptor],
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
        if descriptor.flags & WRITE == 0 || descriptor.len == 0 {
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

fn config_read(config: BalloonConfig, addr: u64, width: u8) -> Option<u64> {
    let len = usize::from(width);
    let end = addr.checked_add(u64::try_from(len).ok()?)?;
    if addr < 0x100 || end > 0x110 || !matches!(len, 1 | 2 | 4) {
        return None;
    }
    let start = usize::try_from(addr - 0x100).ok()?;
    let end = start.checked_add(len)?;
    let mut value = [0; 8];
    value[..len].copy_from_slice(config.0.get(start..end)?);
    Some(u64::from_le_bytes(value))
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
    if state.config.page_contents_are_zeroed() {
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

pub fn mmio_read(addr: u64, width: u8) -> Result<u64, DeviceError> {
    state(|state| {
        if let Some(value) = config_read(state.config, addr, width) {
            return Ok(value);
        }
        state.mmio.read(addr, width).map_err(DeviceError::from)
    })
}

pub fn mmio_write(addr: u64, width: u8, value: u64) -> Result<(), DeviceError> {
    state(|state| {
        let bytes = value.to_le_bytes();
        let data = bytes.get(..usize::from(width)).ok_or(DeviceError::BadLen)?;
        if let Some(result) = config_write(&mut state.config, addr, data) {
            return result;
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
    if QUEUES.is_closed() {
        return;
    }
    QUEUES.clear();
    let _ = configure();
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
            vec![Range {
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
        assert_eq!(config_read(config, CONFIG_ACTUAL, 4), Some(0x0403_0201));
        assert_eq!(
            config_write(&mut config, CONFIG_POISON + 1, &[0xaa, 0xbb]),
            Some(Ok(()))
        );
        assert_eq!(config_read(config, CONFIG_POISON, 4), Some(0x00bb_aa00));
        assert_eq!(config_read(config, CONFIG_POISON - 1, 4), Some(0xbbaa_0000));
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
