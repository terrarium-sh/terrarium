#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({
        world: "block-device",
        path: "wit",
        generate_all,
    });
}

use bindings::exports::terra::host::device_api::Guest;
use bindings::{exports, terra, wit_stream};
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use terra::mmio::types::DeviceError;
use terra_device_transport::{
    Doorbell, INT_USED_BUFFER, MmioTransport, SPLIT_RING_DESC_F_NEXT, SPLIT_RING_DESC_F_WRITE,
    SPLIT_RING_DESCRIPTOR_BYTES, SplitRingDescriptor, VIRTIO_F_VERSION_1, WriteOutcome,
    complete_split_ring_entry, publish_interrupt_asserted, read_split_ring_available,
    split_ring_chain,
};

mod mmio {
    use super::{Block, DeviceError};

    terra_device_transport::mmio_device!(
        DeviceError,
        Block::mmio_read,
        Block::mmio_write,
        Block::reset,
        Block::close,
        Block::interrupt_level
    );
}

const SECTOR_BYTES: u64 = 512;
const STATUS_OK: u8 = 0;
const STATUS_IOERR: u8 = 1;
const STATUS_UNSUPP: u8 = 2;
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;
const T_DISCARD: u32 = 11;
const VIRTIO_BLK_F_SIZE_MAX: u32 = 1;
const VIRTIO_BLK_F_SEG_MAX: u32 = 2;
const VIRTIO_BLK_F_RO: u32 = 5;
const VIRTIO_BLK_F_FLUSH: u32 = 9;
const VIRTIO_BLK_F_DISCARD: u32 = 13;
const CONFIG_SIZE_MAX: usize = 8;
const CONFIG_SEG_MAX: usize = 12;
const CONFIG_MAX_DISCARD_SECTORS: usize = 36;
const CONFIG_MAX_DISCARD_SEG: usize = 40;
const CONFIG_DISCARD_SECTOR_ALIGNMENT: usize = 44;
const CONFIG_BYTES: usize = 48;
const MAX_SINGLE: u64 = terra_limits::MAX_SINGLE_GUEST_COPY_BYTES;
const MAX_TOTAL: u64 = terra_limits::MAX_BATCH_GUEST_COPY_BYTES;
const MAX_DISCARD: u64 = terra_limits::MAX_GUEST_DISCARD_BYTES;
const MAX_RANGES: usize = 16;
const DISCARD_BYTES: usize = 16;
const DISCARD_SECTOR_ALIGNMENT: u32 = 1;

fn build_block_configuration(capacity: u64, readonly: bool) -> Result<(u64, Vec<u8>), DeviceError> {
    let mut config = vec![0u8; CONFIG_BYTES];
    config[..8].copy_from_slice(&(capacity / SECTOR_BYTES).to_le_bytes());
    config[CONFIG_SIZE_MAX..CONFIG_SIZE_MAX + 4].copy_from_slice(
        &u32::try_from(MAX_SINGLE)
            .map_err(|_| DeviceError::TooLarge)?
            .to_le_bytes(),
    );
    config[CONFIG_SEG_MAX..CONFIG_SEG_MAX + 4].copy_from_slice(
        &u32::try_from(MAX_TOTAL / MAX_SINGLE)
            .map_err(|_| DeviceError::TooLarge)?
            .to_le_bytes(),
    );
    let mut features = (1u64 << VIRTIO_BLK_F_SIZE_MAX)
        | (1u64 << VIRTIO_BLK_F_SEG_MAX)
        | (1u64 << VIRTIO_BLK_F_FLUSH)
        | VIRTIO_F_VERSION_1;
    if readonly {
        features |= 1u64 << VIRTIO_BLK_F_RO;
    } else {
        features |= 1u64 << VIRTIO_BLK_F_DISCARD;
        config[CONFIG_MAX_DISCARD_SECTORS..CONFIG_MAX_DISCARD_SECTORS + 4].copy_from_slice(
            &u32::try_from(MAX_DISCARD / SECTOR_BYTES)
                .map_err(|_| DeviceError::TooLarge)?
                .to_le_bytes(),
        );
        config[CONFIG_MAX_DISCARD_SEG..CONFIG_MAX_DISCARD_SEG + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        config[CONFIG_DISCARD_SECTOR_ALIGNMENT..CONFIG_DISCARD_SECTOR_ALIGNMENT + 4]
            .copy_from_slice(&DISCARD_SECTOR_ALIGNMENT.to_le_bytes());
    }
    Ok((features, config))
}

fn parse_discard_range(bytes: &[u8], capacity: u64) -> Result<(u64, u64), u8> {
    let bytes: &[u8; DISCARD_BYTES] = bytes.try_into().map_err(|_| STATUS_IOERR)?;
    let sector = u64::from_le_bytes(bytes[..8].try_into().map_err(|_| STATUS_IOERR)?);
    let sectors = u64::from(u32::from_le_bytes(
        bytes[8..12].try_into().map_err(|_| STATUS_IOERR)?,
    ));
    let flags = u32::from_le_bytes(bytes[12..].try_into().map_err(|_| STATUS_IOERR)?);
    if flags != 0 {
        return Err(STATUS_UNSUPP);
    }
    if sectors > MAX_DISCARD / SECTOR_BYTES {
        return Err(STATUS_IOERR);
    }
    sector_start(
        sector,
        sectors.checked_mul(SECTOR_BYTES).ok_or(STATUS_IOERR)?,
        capacity,
    )
    .map(|offset| (offset, sectors * SECTOR_BYTES))
    .ok_or(STATUS_IOERR)
}

async fn execute_discard(data: &[Range], capacity: u64) -> Result<(), u8> {
    let [range] = data else {
        return Err(STATUS_IOERR);
    };
    if range.len != DISCARD_BYTES as u64 {
        return Err(STATUS_IOERR);
    }
    let bytes =
        terra::host::memory::read(range.addr, DISCARD_BYTES as u64).map_err(|_| STATUS_IOERR)?;
    let (offset, len) = parse_discard_range(&bytes, capacity)?;
    terra::host::disk::discard(offset, len)
        .await
        .map_err(|_| STATUS_IOERR)
}

static EPOCH: AtomicU64 = AtomicU64::new(0);
static QUEUES: Doorbell = Doorbell::new();

struct TransportState {
    transport: MmioTransport,
    avail: u16,
}

static TRANSPORT: LazyLock<Mutex<Option<TransportState>>> = LazyLock::new(|| Mutex::new(None));

fn transport<T>(
    f: impl FnOnce(&mut TransportState) -> Result<T, DeviceError>,
) -> Result<T, DeviceError> {
    let mut state = TRANSPORT.lock().map_err(|_| DeviceError::Io)?;
    let state = state.as_mut().ok_or(DeviceError::NotReady)?;
    let result = f(state);
    if let Some(asserted) = state.transport.take_irq() {
        publish_interrupt_asserted(asserted, terra::host::interrupt::set_asserted);
    }
    result
}

terra_device_transport::device_error!(DeviceError);
terra_device_transport::guest_memory!(DeviceError);

fn sector_start(sector: u64, total: u64, capacity: u64) -> Option<u64> {
    let start = sector.checked_mul(SECTOR_BYTES)?;
    let end = start.checked_add(total)?;
    if total == 0 || !total.is_multiple_of(SECTOR_BYTES) || end > capacity {
        return None;
    }
    Some(start)
}

fn read_guest_payload(data: &[Range]) -> Result<Vec<u8>, DeviceError> {
    let ranges = data
        .iter()
        .filter(|range| range.len != 0)
        .map(|range| (range.addr, range.len))
        .collect::<Vec<_>>();
    read_guest_memory(&ranges)
}

fn is_current(epoch: u64) -> bool {
    !QUEUES.is_closed() && epoch == EPOCH.load(Ordering::Acquire)
}

fn write_status(status_addr: u64, status: u8, epoch: u64) -> Option<u8> {
    if !is_current(epoch) || terra::host::memory::write(status_addr, &[status]).is_err() {
        return None;
    }
    Some(status)
}

fn write_guest_ranges(ranges: &[Range], mut bytes: &[u8], epoch: u64) -> Result<(), DeviceError> {
    let mut writes = Vec::with_capacity(ranges.len());
    for range in ranges.iter().filter(|range| range.len != 0) {
        let len = usize::try_from(range.len).map_err(|_| DeviceError::TooLarge)?;
        let (chunk, rest) = bytes.split_at_checked(len).ok_or(DeviceError::BadLen)?;
        writes.push((range.addr, chunk));
        bytes = rest;
    }
    if !is_current(epoch) {
        return Err(DeviceError::NotReady);
    }
    write_guest_memory(&writes)
}

fn request_type(header: &SplitRingDescriptor) -> Result<(u32, u64), DeviceError> {
    if header.len < 16 || header.flags & SPLIT_RING_DESC_F_WRITE != 0 {
        return Err(DeviceError::BadLen);
    }
    let bytes = terra::host::memory::read(header.addr, 16).map_err(|_| DeviceError::BadLen)?;
    Ok((
        u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| DeviceError::BadLen)?),
        u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| DeviceError::BadLen)?),
    ))
}

fn ioerr_completion(status_addr: u64, epoch: u64) -> Result<u32, DeviceError> {
    write_status(status_addr, STATUS_IOERR, epoch).ok_or(DeviceError::NotReady)?;
    Ok(1)
}

fn status_tail(chain: &[SplitRingDescriptor]) -> Option<u64> {
    (chain.len() >= 2)
        .then(|| chain.last())
        .flatten()
        .filter(|status| status.len == 1 && status.flags & SPLIT_RING_DESC_F_WRITE != 0)
        .map(|status| status.addr)
}

struct Range {
    addr: u64,
    len: u64,
}

struct Block;

impl exports::terra::mmio::device::Guest for Block {
    async fn serve(
        requests: wit_bindgen::rt::async_support::StreamReader<terra::mmio::types::Request>,
    ) -> wit_bindgen::rt::async_support::StreamReader<terra::mmio::types::Reply> {
        mmio::serve(requests).await
    }
}

impl Guest for Block {
    #[allow(clippy::unused_async_trait_impl)]
    async fn configure(readonly: bool) -> Result<(), DeviceError> {
        if QUEUES.is_closed() {
            return Err(DeviceError::NotReady);
        }
        EPOCH.fetch_add(1, Ordering::AcqRel);
        QUEUES.clear();
        let capacity = terra::host::disk::capacity();
        let (features, config) = build_block_configuration(capacity, readonly)?;
        publish_interrupt_asserted(false, terra::host::interrupt::set_asserted);
        *TRANSPORT.lock().map_err(|_| DeviceError::Io)? = Some(TransportState {
            transport: MmioTransport::new(
                terra::host::memory::address_limit(),
                2,
                features,
                256,
                config,
            ),
            avail: 0,
        });
        Ok(())
    }

    async fn run() -> Result<(), DeviceError> {
        while !QUEUES.is_closed() {
            QUEUES.wait().await;
            if QUEUES.is_closed() {
                break;
            }
            while process_pending().await? {
                wit_bindgen::rt::async_support::yield_async().await;
            }
        }
        Ok(())
    }
}

impl Block {
    async fn execute(
        req_type: u32,
        sector: u64,
        data: Vec<Range>,
        total: u64,
        status_addr: u64,
        epoch: u64,
    ) -> u8 {
        if !is_current(epoch) {
            return STATUS_IOERR;
        }
        let capacity = terra::host::disk::capacity();
        let fail = || write_status(status_addr, STATUS_IOERR, epoch).unwrap_or(STATUS_IOERR);
        match req_type {
            T_IN => {
                let Some(disk_offset) = sector_start(sector, total, capacity) else {
                    return fail();
                };
                let Ok(bytes) = terra::host::disk::read_at(disk_offset, total).await else {
                    return fail();
                };
                if bytes.len() as u64 != total {
                    return fail();
                }
                if write_guest_ranges(&data, &bytes, epoch).is_err() {
                    return fail();
                }
                write_status(status_addr, STATUS_OK, epoch).unwrap_or(STATUS_IOERR)
            }
            T_OUT => {
                let Some(disk_offset) = sector_start(sector, total, capacity) else {
                    return fail();
                };
                let Ok(bytes) = read_guest_payload(&data) else {
                    return fail();
                };
                if !is_current(epoch) {
                    return STATUS_IOERR;
                }
                if terra::host::disk::write_at(disk_offset, bytes)
                    .await
                    .is_err()
                {
                    return fail();
                }
                write_status(status_addr, STATUS_OK, epoch).unwrap_or(STATUS_IOERR)
            }
            T_FLUSH => {
                if sector != 0 || total != 0 {
                    return fail();
                }
                let status = match terra::host::disk::sync().await {
                    Ok(()) => STATUS_OK,
                    Err(_) => STATUS_IOERR,
                };
                write_status(status_addr, status, epoch).unwrap_or(STATUS_IOERR)
            }
            T_DISCARD => {
                let status = execute_discard(&data, capacity)
                    .await
                    .err()
                    .unwrap_or(STATUS_OK);
                write_status(status_addr, status, epoch).unwrap_or(STATUS_IOERR)
            }
            _ => write_status(status_addr, STATUS_UNSUPP, epoch).unwrap_or(STATUS_IOERR),
        }
    }

    async fn execute_chain(
        head: u16,
        desc_table: u64,
        queue_size: u16,
        epoch: u64,
    ) -> Result<u32, DeviceError> {
        if !is_current(epoch) {
            return Err(DeviceError::NotReady);
        }
        if queue_size == 0
            || queue_size > 256
            || !queue_size.is_power_of_two()
            || head >= queue_size
        {
            return Err(DeviceError::BadQueue);
        }
        let table = terra::host::memory::read(
            desc_table,
            u64::from(queue_size) * SPLIT_RING_DESCRIPTOR_BYTES as u64,
        )
        .map_err(|_| DeviceError::BadLen)?;
        let chain = split_ring_chain(
            &table,
            head,
            queue_size,
            MAX_RANGES + 2,
            SPLIT_RING_DESC_F_NEXT | SPLIT_RING_DESC_F_WRITE,
        )
        .map_err(DeviceError::from)?;
        let Some(status_addr) = status_tail(&chain) else {
            return Err(DeviceError::BadLen);
        };
        let Ok((req_type, sector)) = request_type(&chain[0]) else {
            return ioerr_completion(status_addr, epoch);
        };
        let writable_data = !matches!(req_type, T_OUT | T_DISCARD);
        let mut data = Vec::new();
        let mut total = 0u64;
        for desc in &chain[1..chain.len() - 1] {
            if (desc.flags & SPLIT_RING_DESC_F_WRITE != 0) != writable_data
                || u64::from(desc.len) > MAX_SINGLE
            {
                return ioerr_completion(status_addr, epoch);
            }
            total = match total.checked_add(u64::from(desc.len)) {
                Some(total) if total <= MAX_TOTAL => total,
                _ => return ioerr_completion(status_addr, epoch),
            };
            data.push(Range {
                addr: desc.addr,
                len: u64::from(desc.len),
            });
        }
        terra::host::memory::read(status_addr, 1).map_err(|_| DeviceError::BadLen)?;
        let status = Self::execute(req_type, sector, data, total, status_addr, epoch).await;
        if !is_current(epoch) {
            return Err(DeviceError::NotReady);
        }
        let payload = if req_type == T_IN && status == STATUS_OK {
            total
        } else {
            0
        };
        u32::try_from(payload.checked_add(1).ok_or(DeviceError::TooLarge)?)
            .map_err(|_| DeviceError::TooLarge)
    }
}

impl Block {
    fn mmio_read(addr: u64, width: u8) -> Result<u64, DeviceError> {
        transport(|state| state.transport.read(addr, width).map_err(DeviceError::from))
    }

    fn mmio_write(addr: u64, width: u8, value: u64) -> Result<(), DeviceError> {
        let outcome = transport(|state| {
            let outcome = state
                .transport
                .write(addr, width, value)
                .map_err(DeviceError::from)?;
            if outcome == WriteOutcome::Reset {
                state.avail = 0;
            }
            Ok(outcome)
        })?;
        match outcome {
            WriteOutcome::None => {}
            WriteOutcome::QueueNotify(_) => QUEUES.ring(1),
            WriteOutcome::Reset => {
                EPOCH.fetch_add(1, Ordering::AcqRel);
                QUEUES.clear();
            }
        }
        Ok(())
    }

    fn interrupt_level() -> bool {
        transport(|state| Ok(state.transport.interrupt_status() & INT_USED_BUFFER != 0))
            .unwrap_or(false)
    }

    fn reset() {
        EPOCH.fetch_add(1, Ordering::AcqRel);
        QUEUES.clear();
        let _ = transport(|state| {
            state
                .transport
                .write(0x070, 4, 0)
                .map_err(DeviceError::from)?;
            state.avail = 0;
            Ok(())
        });
    }

    async fn close() -> Result<(), DeviceError> {
        QUEUES.close();
        Self::reset();
        terra::host::disk::sync().await.map_err(|_| DeviceError::Io)
    }
}

async fn process_pending() -> Result<bool, DeviceError> {
    if QUEUES.is_closed() {
        return Ok(false);
    }
    let epoch = EPOCH.load(Ordering::Acquire);
    let (desc, avail, used, size, mut next) = match transport(|state| {
        let (desc, avail, used, size) = state
            .transport
            .queue_addrs_for(0)
            .ok_or(DeviceError::NotReady)?;
        Ok((desc, avail, used, size, state.avail))
    }) {
        Ok(state) => state,
        Err(DeviceError::NotReady) => return Ok(false),
        Err(error) => return Err(error),
    };
    let (available, head) = read_split_ring_available(avail, size, &mut next, |address, len| {
        terra::host::memory::read(address, len).map_err(|_| DeviceError::BadLen)
    })?;
    let Some(head) = head else {
        if !is_current(epoch) {
            return Ok(false);
        }
        transport(|state| {
            state.avail = next;
            Ok(())
        })?;
        return Ok(false);
    };
    let used_len = match Block::execute_chain(head, desc, size, epoch).await {
        Ok(used_len) => used_len,
        Err(DeviceError::NotReady) => return Ok(false),
        Err(DeviceError::BadLen | DeviceError::BadQueue | DeviceError::TooLarge) => 0,
        Err(error) => return Err(error),
    };
    if !is_current(epoch) {
        return Ok(false);
    }
    complete_split_ring_entry(
        used,
        size,
        head,
        used_len,
        |address, len| terra::host::memory::read(address, len).map_err(|_| DeviceError::BadLen),
        |address, bytes| {
            terra::host::memory::write(address, bytes).map_err(|_| DeviceError::BadLen)
        },
    )?;
    next = next.wrapping_add(1);
    match transport(|state| {
        if !is_current(epoch) {
            return Err(DeviceError::NotReady);
        }
        state.avail = next;
        state.transport.signal(INT_USED_BUFFER);
        Ok(())
    }) {
        Ok(()) => Ok(next != available),
        Err(DeviceError::NotReady) => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)]
mod component_export {
    use super::{Block, bindings};

    bindings::export!(Block with_types_in bindings);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discard_segment(sector: u64, sectors: u32, flags: u32) -> [u8; DISCARD_BYTES] {
        let mut bytes = [0; DISCARD_BYTES];
        bytes[..8].copy_from_slice(&sector.to_le_bytes());
        bytes[8..12].copy_from_slice(&sectors.to_le_bytes());
        bytes[12..].copy_from_slice(&flags.to_le_bytes());
        bytes
    }

    #[test]
    fn writable_configuration_advertises_one_bounded_discard_segment() {
        let (features, config) = build_block_configuration(16 * 1024, false).unwrap();
        assert_ne!(features & (1 << VIRTIO_BLK_F_DISCARD), 0);
        assert_eq!(
            u32::from_le_bytes(
                config[CONFIG_MAX_DISCARD_SECTORS..CONFIG_MAX_DISCARD_SECTORS + 4]
                    .try_into()
                    .unwrap()
            ),
            u32::try_from(MAX_DISCARD / SECTOR_BYTES).unwrap()
        );
        assert_eq!(
            u32::from_le_bytes(
                config[CONFIG_MAX_DISCARD_SEG..CONFIG_MAX_DISCARD_SEG + 4]
                    .try_into()
                    .unwrap()
            ),
            1
        );
        assert_eq!(
            u32::from_le_bytes(
                config[CONFIG_DISCARD_SECTOR_ALIGNMENT..CONFIG_DISCARD_SECTOR_ALIGNMENT + 4]
                    .try_into()
                    .unwrap()
            ),
            DISCARD_SECTOR_ALIGNMENT
        );
        let (readonly_features, _) = build_block_configuration(16 * 1024, true).unwrap();
        assert_eq!(readonly_features & (1 << VIRTIO_BLK_F_DISCARD), 0);
    }

    #[test]
    fn parse_discard_range_rejects_invalid_segment() {
        assert_eq!(
            parse_discard_range(&discard_segment(2, 4, 0), 16 * 512),
            Ok((1024, 2048))
        );
        assert_eq!(
            parse_discard_range(&discard_segment(0, 0, 0), 16 * 512),
            Err(STATUS_IOERR)
        );
        assert_eq!(
            parse_discard_range(&discard_segment(0, 1, 1), 16 * 512),
            Err(STATUS_UNSUPP)
        );
        assert_eq!(
            parse_discard_range(&discard_segment(u64::MAX, 1, 0), u64::MAX),
            Err(STATUS_IOERR)
        );
        assert_eq!(
            parse_discard_range(
                &discard_segment(0, u32::try_from(MAX_DISCARD / SECTOR_BYTES).unwrap() + 1, 0),
                u64::MAX,
            ),
            Err(STATUS_IOERR)
        );
        assert_eq!(
            parse_discard_range(&discard_segment(15, 2, 0), 16 * 512),
            Err(STATUS_IOERR)
        );
        assert_eq!(parse_discard_range(&[0; 15], 16 * 512), Err(STATUS_IOERR));
    }

    #[test]
    fn malformed_request_retains_a_valid_status_tail() {
        let header = SplitRingDescriptor {
            addr: 0,
            len: 0,
            flags: SPLIT_RING_DESC_F_NEXT,
            next: 1,
        };
        let status = SplitRingDescriptor {
            addr: 0x1000,
            len: 1,
            flags: SPLIT_RING_DESC_F_WRITE,
            next: 0,
        };
        assert_eq!(status_tail(&[header, status]), Some(0x1000));
        assert_eq!(status_tail(&[status]), None);
    }
}
