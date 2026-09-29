use std::sync::{
    LazyLock, Mutex,
    atomic::{AtomicBool, Ordering},
};

use terra_device_transport::{
    INT_USED_BUFFER, MmioError, MmioTransport, SPLIT_RING_DESC_F_NEXT, SPLIT_RING_DESC_F_WRITE,
    SPLIT_RING_DESCRIPTOR_BYTES, SplitRingError, resync_pending_queue_entries, split_ring_chain,
};

use crate::terra::mmio::types::DeviceError;

const RX: usize = 0;
const TX: usize = 1;
const TX_QUEUE: u16 = 1;
const QUEUE_SIZE: u16 = 256;
const MAX_CHAIN: usize = 16;
const MAX_FRAME: usize = 65_536;
const VIRTIO_NET_HDR_BYTES: usize = 12;
const MAX_TRANSFER: usize = MAX_FRAME + VIRTIO_NET_HDR_BYTES;
const MAX_QUEUE_BATCH: usize = super::MAX_WORK_PER_WAKE;
#[allow(clippy::cast_possible_truncation)]
const MAX_MEMORY_IMPORT_BYTES: usize = terra_limits::MAX_SINGLE_GUEST_COPY_BYTES as usize;

struct State {
    mmio: MmioTransport,
    next: [u16; 2],
    pending_tx: bool,
}

struct QueueBatch {
    descriptor_table: u64,
    used_ring: u64,
    size: u16,
    heads: [u16; MAX_QUEUE_BATCH],
    count: usize,
    has_more: bool,
}

static STATE: LazyLock<Mutex<Option<State>>> = LazyLock::new(|| Mutex::new(None));
static CLOSED: AtomicBool = AtomicBool::new(false);

fn publish_interrupt_level(level: bool) {
    if cfg!(target_arch = "wasm32") {
        super::terra::host::interrupt::set_level(level);
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
    if len > MAX_TRANSFER as u64 {
        return Err(DeviceError::TooLarge);
    }
    let capacity = usize::try_from(len).map_err(|_| DeviceError::TooLarge)?;
    let mut bytes = if capacity > MAX_MEMORY_IMPORT_BYTES {
        Vec::with_capacity(capacity)
    } else {
        Vec::new()
    };
    let mut offset = 0_u64;
    while offset < len {
        let chunk = (len - offset).min(MAX_MEMORY_IMPORT_BYTES as u64);
        let address = at(addr, offset)?;
        let chunk_bytes =
            super::terra::host::memory::read(address, chunk).map_err(|_| DeviceError::Unmapped)?;
        if chunk_bytes.len() != usize::try_from(chunk).map_err(|_| DeviceError::TooLarge)? {
            return Err(DeviceError::Io);
        }
        if capacity <= MAX_MEMORY_IMPORT_BYTES {
            bytes = chunk_bytes;
        } else {
            bytes.extend(chunk_bytes);
        }
        offset += chunk;
    }
    Ok(bytes)
}

fn write(addr: u64, bytes: &[u8]) -> Result<(), DeviceError> {
    if bytes.len() > MAX_TRANSFER {
        return Err(DeviceError::TooLarge);
    }
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let end = (offset + MAX_MEMORY_IMPORT_BYTES).min(bytes.len());
        let address = at(
            addr,
            u64::try_from(offset).map_err(|_| DeviceError::TooLarge)?,
        )?;
        super::terra::host::memory::write(address, &bytes[offset..end])
            .map_err(|_| DeviceError::Unmapped)?;
        offset = end;
    }
    Ok(())
}

fn at(base: u64, offset: u64) -> Result<u64, DeviceError> {
    base.checked_add(offset).ok_or(DeviceError::Unmapped)
}

fn chain(
    table: &[u8],
    index: u16,
    size: u16,
) -> Result<Vec<terra_device_transport::SplitRingDescriptor>, DeviceError> {
    split_ring_chain(
        table,
        index,
        size,
        MAX_CHAIN,
        SPLIT_RING_DESC_F_NEXT | SPLIT_RING_DESC_F_WRITE,
    )
    .map_err(|error| match error {
        SplitRingError::BadDescriptor => DeviceError::BadLen,
        SplitRingError::ChainTooLong => DeviceError::TooLarge,
    })
}

fn read_u16(
    address: u64,
    read_memory: impl Fn(u64, u64) -> Result<Vec<u8>, DeviceError>,
) -> Result<u16, DeviceError> {
    let bytes = read_memory(address, 2)?;
    Ok(u16::from_le_bytes(
        bytes.try_into().map_err(|_| DeviceError::BadLen)?,
    ))
}

fn ethernet_frame(mut bytes: Vec<u8>) -> Option<Vec<u8>> {
    if bytes.len() < VIRTIO_NET_HDR_BYTES + 14 {
        return None;
    }
    let header = &bytes[..VIRTIO_NET_HDR_BYTES];
    if header[0] != 0 || header[1] != 0 || header[2..10] != [0; 8] || header[10..12] != [0; 2] {
        return None;
    }
    let length = bytes.len() - VIRTIO_NET_HDR_BYTES;
    bytes.copy_within(VIRTIO_NET_HDR_BYTES.., 0);
    bytes.truncate(length);
    Some(bytes)
}

fn read_tx_frame(head: u16, table: &[u8], size: u16) -> Result<Vec<u8>, DeviceError> {
    let chain = chain(table, head, size)?;
    if chain
        .iter()
        .any(|descriptor| descriptor.flags & SPLIT_RING_DESC_F_WRITE != 0)
    {
        return Err(DeviceError::BadLen);
    }
    let length = chain.iter().try_fold(0usize, |length, descriptor| {
        length.checked_add(descriptor.len as usize)
    });
    let Some(length) =
        length.filter(|length| (VIRTIO_NET_HDR_BYTES + 14..=MAX_TRANSFER).contains(length))
    else {
        return Err(DeviceError::BadLen);
    };
    let frame = if chain.len() == 1 {
        read(chain[0].addr, u64::from(chain[0].len))?
    } else if u64::try_from(length).map_err(|_| DeviceError::TooLarge)?
        > terra_limits::MAX_BATCH_GUEST_COPY_BYTES
    {
        let mut frame = Vec::with_capacity(length);
        for descriptor in &chain {
            frame.extend(read(descriptor.addr, u64::from(descriptor.len))?);
        }
        frame
    } else {
        let mut ranges = Vec::new();
        let max_chunk =
            u32::try_from(MAX_MEMORY_IMPORT_BYTES).map_err(|_| DeviceError::TooLarge)?;
        for descriptor in &chain {
            for offset in (0..descriptor.len).step_by(MAX_MEMORY_IMPORT_BYTES) {
                let len = (descriptor.len - offset).min(max_chunk);
                ranges.push(super::terra::host::memory::ReadRange {
                    offset: at(descriptor.addr, u64::from(offset))?,
                    len: u64::from(len),
                });
            }
        }
        super::terra::host::memory::read_ranges(&ranges).map_err(|_| DeviceError::Unmapped)?
    };
    if frame.len() != length {
        return Err(DeviceError::Io);
    }
    ethernet_frame(frame).ok_or(DeviceError::BadLen)
}

fn capture_heads(
    state: &mut State,
    queue: usize,
    limit: usize,
    read_memory: impl Fn(u64, u64) -> Result<Vec<u8>, DeviceError> + Copy,
) -> Result<Option<QueueBatch>, DeviceError> {
    let limit = limit.min(MAX_QUEUE_BATCH);
    if limit == 0 {
        return Ok(None);
    }
    let Some((descriptor_table, available_ring, used_ring, size)) =
        state.mmio.queue_addrs_for(queue)
    else {
        return Ok(None);
    };
    let available = read_u16(at(available_ring, 2)?, read_memory)?;
    let pending = resync_pending_queue_entries(&mut state.next[queue], available, size);
    if pending == 0 {
        return Ok(None);
    }
    let wanted = usize::from(pending).min(limit);
    let mut heads = [0; MAX_QUEUE_BATCH];
    let mut count = 0;
    while count < wanted {
        let slot = usize::from(
            state.next[queue]
                .wrapping_add(u16::try_from(count).map_err(|_| DeviceError::TooLarge)?)
                % size,
        );
        let segment_count = (wanted - count).min(usize::from(size) - slot);
        let address = at(available_ring, 4 + (slot * 2) as u64)?;
        let bytes = match read_memory(address, (segment_count * 2) as u64) {
            Ok(bytes) if bytes.len() == segment_count * 2 => bytes,
            Ok(_) | Err(_) if count != 0 => break,
            Ok(_) => return Err(DeviceError::BadLen),
            Err(error) => return Err(error),
        };
        for pair in bytes.as_chunks::<2>().0 {
            heads[count] = u16::from_le_bytes(*pair);
            count += 1;
        }
    }
    Ok(Some(QueueBatch {
        descriptor_table,
        used_ring,
        size,
        heads,
        count,
        has_more: usize::from(pending) > count,
    }))
}

fn stage_used(bytes: &mut [u8; MAX_QUEUE_BATCH * 8], count: usize, head: u16, len: u32) {
    let slot = &mut bytes[count * 8..count * 8 + 8];
    slot[..4].copy_from_slice(&u32::from(head).to_le_bytes());
    slot[4..].copy_from_slice(&len.to_le_bytes());
}

fn publish_used(
    state: &mut State,
    queue: usize,
    batch: &QueueBatch,
    bytes: &[u8; MAX_QUEUE_BATCH * 8],
    count: usize,
    read_memory: impl Fn(u64, u64) -> Result<Vec<u8>, DeviceError>,
    write_memory: impl Fn(u64, &[u8]) -> Result<(), DeviceError>,
) -> Result<(), DeviceError> {
    if count == 0 {
        return Ok(());
    }
    let index_address = at(batch.used_ring, 2)?;
    let index = read_u16(index_address, read_memory)?;
    let slot = usize::from(index % batch.size);
    let first_count = count.min(usize::from(batch.size) - slot);
    write_memory(
        at(batch.used_ring, 4 + (slot * 8) as u64)?,
        &bytes[..first_count * 8],
    )?;
    if first_count < count {
        write_memory(at(batch.used_ring, 4)?, &bytes[first_count * 8..count * 8])?;
    }
    let count = u16::try_from(count).map_err(|_| DeviceError::TooLarge)?;
    write_memory(index_address, &index.wrapping_add(count).to_le_bytes())?;
    state.next[queue] = state.next[queue].wrapping_add(count);
    state.mmio.signal(INT_USED_BUFFER);
    Ok(())
}

fn process_tx(state: &mut State, completed: &mut bool) -> Result<bool, DeviceError> {
    let Some(batch) = capture_heads(state, TX, MAX_QUEUE_BATCH, read)? else {
        return Ok(false);
    };
    let table = read(
        batch.descriptor_table,
        u64::from(batch.size) * SPLIT_RING_DESCRIPTOR_BYTES as u64,
    );
    let mut used = [0; MAX_QUEUE_BATCH * 8];
    for (index, head) in batch.heads.into_iter().take(batch.count).enumerate() {
        if let Ok(table) = &table
            && let Ok(frame) = read_tx_frame(head, table, batch.size)
        {
            let _ = super::queue_frame(frame);
        }
        stage_used(&mut used, index, head, 0);
    }
    publish_used(state, TX, &batch, &used, batch.count, read, write)?;
    *completed = true;
    Ok(batch.has_more)
}

fn write_rx_frame(
    chain: &[terra_device_transport::SplitRingDescriptor],
    frame: &[u8],
    mut write_bytes: impl FnMut(u64, &[u8]) -> Result<(), DeviceError>,
) -> Result<(), DeviceError> {
    let packet_len = VIRTIO_NET_HDR_BYTES + frame.len();
    let header = [0; VIRTIO_NET_HDR_BYTES];
    let mut offset = 0;
    for descriptor in chain {
        let amount = (packet_len - offset).min(descriptor.len as usize);
        let header_amount = amount.min(VIRTIO_NET_HDR_BYTES.saturating_sub(offset));
        if header_amount != 0 {
            write_bytes(descriptor.addr, &header[offset..offset + header_amount])?;
        }
        if amount > header_amount {
            let address = at(
                descriptor.addr,
                u64::try_from(header_amount).map_err(|_| DeviceError::TooLarge)?,
            )?;
            write_bytes(
                address,
                &frame[offset + header_amount - VIRTIO_NET_HDR_BYTES
                    ..offset + amount - VIRTIO_NET_HDR_BYTES],
            )?;
        }
        offset += amount;
        if offset == packet_len {
            return Ok(());
        }
    }
    Err(DeviceError::BadLen)
}

fn process_rx(state: &mut State, completed: &mut bool) -> Result<bool, DeviceError> {
    let pending_frames = super::gateway().frames.len();
    let Some(batch) = capture_heads(state, RX, pending_frames, read)? else {
        return Ok(false);
    };
    let table = read(
        batch.descriptor_table,
        u64::from(batch.size) * SPLIT_RING_DESCRIPTOR_BYTES as u64,
    );
    let mut used = [0; MAX_QUEUE_BATCH * 8];
    let mut used_count = 0;
    for head in batch.heads.into_iter().take(batch.count) {
        let chain = table
            .as_ref()
            .ok()
            .and_then(|table| chain(table, head, batch.size).ok());
        let Some(chain) = chain else {
            stage_used(&mut used, used_count, head, 0);
            used_count += 1;
            continue;
        };
        let capacity = chain.iter().try_fold(0usize, |length, descriptor| {
            length.checked_add(descriptor.len as usize)
        });
        if chain
            .iter()
            .any(|descriptor| descriptor.flags & SPLIT_RING_DESC_F_WRITE == 0)
            || capacity.is_none_or(|capacity| {
                !(VIRTIO_NET_HDR_BYTES + 14..=MAX_TRANSFER).contains(&capacity)
            })
        {
            stage_used(&mut used, used_count, head, 0);
            used_count += 1;
            continue;
        }
        let Some(frame) = super::gateway().take_frame(MAX_TRANSFER) else {
            publish_used(state, RX, &batch, &used, used_count, read, write)?;
            *completed |= used_count != 0;
            return Ok(false);
        };
        if !(14..=MAX_FRAME).contains(&frame.len()) {
            publish_used(state, RX, &batch, &used, used_count, read, write)?;
            *completed |= used_count != 0;
            return Err(DeviceError::BadLen);
        }
        let packet_len =
            u32::try_from(VIRTIO_NET_HDR_BYTES + frame.len()).map_err(|_| DeviceError::TooLarge)?;
        let used_len = if write_rx_frame(&chain, &frame, write).is_ok() {
            packet_len
        } else {
            0
        };
        stage_used(&mut used, used_count, head, used_len);
        used_count += 1;
    }
    publish_used(state, RX, &batch, &used, used_count, read, write)?;
    *completed |= used_count != 0;
    if super::gateway().frames.is_empty() {
        Ok(false)
    } else {
        Ok(batch.has_more)
    }
}

pub fn configure() -> Result<(), DeviceError> {
    if CLOSED.load(Ordering::Acquire) {
        return Err(DeviceError::NotReady);
    }
    publish_interrupt_level(false);
    *STATE.lock().map_err(|_| DeviceError::Io)? = Some(State {
        mmio: MmioTransport::new(
            0,
            0x200,
            super::terra::host::memory::address_limit(),
            1,
            1 << 32,
            QUEUE_SIZE,
            0_u64.to_le_bytes().to_vec(),
        )
        .with_queue_count(2),
        next: [0; 2],
        pending_tx: false,
    });
    Ok(())
}

pub fn is_configured() -> bool {
    STATE.lock().is_ok_and(|state| state.is_some())
}

pub fn mmio_read(addr: u64, len: u32) -> Result<Vec<u8>, DeviceError> {
    state(|state| {
        state
            .mmio
            .read(addr, usize::try_from(len).map_err(|_| DeviceError::BadLen)?)
            .map_err(DeviceError::from)
    })
}

pub fn mmio_write(addr: u64, data: &[u8]) -> Result<(), DeviceError> {
    let (bell, reset) = state(|state| {
        let generation = state.mmio.reset_generation();
        let bell = state.mmio.write(addr, data).map_err(DeviceError::from)?;
        let reset = generation != state.mmio.reset_generation();
        if reset {
            state.next = [0; 2];
            state.pending_tx = false;
        }
        if bell == Some(TX_QUEUE) {
            state.pending_tx = true;
        }
        Ok((bell.is_some(), reset))
    })?;
    if reset {
        super::reset_protocol();
    }
    if bell {
        super::tick();
    }
    Ok(())
}

pub fn service_queues() -> Result<bool, DeviceError> {
    if CLOSED.load(Ordering::Acquire) {
        return Err(DeviceError::NotReady);
    }
    let mut completed = false;
    let mut more_tx = false;
    let result = state(|state| {
        more_tx = if state.pending_tx {
            process_tx(state, &mut completed)?
        } else {
            false
        };
        state.pending_tx = more_tx;
        let more_rx = process_rx(state, &mut completed)?;
        Ok(more_tx || more_rx)
    });
    if completed {
        super::terra::host::interrupt::signal();
    }
    if more_tx || result.as_ref().is_ok_and(|more| *more) {
        super::tick();
    }
    result
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
    if !CLOSED.load(Ordering::Acquire) {
        let _ = configure();
    }
}

pub fn close() {
    CLOSED.store(true, Ordering::Release);
    if let Ok(mut state) = STATE.lock() {
        *state = None;
    }
    publish_interrupt_level(false);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use terra_device_transport::SplitRingDescriptor;

    fn armed_rx_queue() -> State {
        let mut mmio = MmioTransport::new(0, 0x200, 64 * 1024, 1, 1 << 32, QUEUE_SIZE, vec![0; 8])
            .with_queue_count(2);
        for status in [1u8, 3, 11, 15] {
            mmio.write(0x70, &[status]).expect("device status");
        }
        mmio.write(0x38, &16u32.to_le_bytes()).expect("queue size");
        for (register, address) in [(0x80, 0x1000u32), (0x90, 0x2000), (0xa0, 0x3000)] {
            mmio.write(register, &address.to_le_bytes())
                .expect("queue address");
        }
        mmio.write(0x44, &1u32.to_le_bytes()).expect("queue ready");
        State {
            mmio,
            next: [0; 2],
            pending_tx: false,
        }
    }

    fn read_ring(
        memory: &RefCell<Vec<u8>>,
        address: u64,
        len: u64,
    ) -> Result<Vec<u8>, DeviceError> {
        let start = usize::try_from(address).map_err(|_| DeviceError::Unmapped)?;
        let length = usize::try_from(len).map_err(|_| DeviceError::TooLarge)?;
        memory
            .borrow()
            .get(start..start + length)
            .map(<[u8]>::to_vec)
            .ok_or(DeviceError::Unmapped)
    }

    fn write_ring(
        memory: &RefCell<Vec<u8>>,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), DeviceError> {
        let start = usize::try_from(address).map_err(|_| DeviceError::Unmapped)?;
        memory
            .borrow_mut()
            .get_mut(start..start + bytes.len())
            .ok_or(DeviceError::Unmapped)?
            .copy_from_slice(bytes);
        Ok(())
    }

    #[test]
    fn modern_virtio_net_header_is_removed_and_restored() {
        let ethernet = vec![0xaa; 14];
        let mut packet = vec![0; VIRTIO_NET_HDR_BYTES];
        packet.extend_from_slice(&ethernet);
        assert_eq!(&packet[..VIRTIO_NET_HDR_BYTES], &[0; VIRTIO_NET_HDR_BYTES]);
        assert_eq!(ethernet_frame(packet), Some(ethernet));
    }

    #[test]
    fn unsupported_offload_header_is_rejected() {
        let mut packet = vec![0; VIRTIO_NET_HDR_BYTES + 14];
        packet[1] = 1;
        assert_eq!(ethernet_frame(packet), None);
    }

    #[test]
    fn rx_header_and_payload_can_cross_descriptors() {
        let descriptors = [
            SplitRingDescriptor {
                addr: 0,
                len: 5,
                flags: SPLIT_RING_DESC_F_WRITE,
                next: 0,
            },
            SplitRingDescriptor {
                addr: 5,
                len: 9,
                flags: SPLIT_RING_DESC_F_WRITE,
                next: 0,
            },
            SplitRingDescriptor {
                addr: 14,
                len: 12,
                flags: SPLIT_RING_DESC_F_WRITE,
                next: 0,
            },
        ];
        let frame = [0xaa; 14];
        let mut memory = [0xff; VIRTIO_NET_HDR_BYTES + 14];
        assert!(
            write_rx_frame(&descriptors, &frame, |address, bytes| {
                let start = usize::try_from(address).expect("test address");
                memory[start..start + bytes.len()].copy_from_slice(bytes);
                Ok(())
            })
            .is_ok()
        );
        assert_eq!(&memory[..VIRTIO_NET_HDR_BYTES], &[0; VIRTIO_NET_HDR_BYTES]);
        assert_eq!(&memory[VIRTIO_NET_HDR_BYTES..], &frame);
    }

    #[test]
    fn capture_limits_heads_without_advancing_consumption_cursor() {
        let mut state = armed_rx_queue();
        let memory = RefCell::new(vec![0; 0x4000]);
        {
            let mut memory = memory.borrow_mut();
            memory[0x2002..0x2004].copy_from_slice(&9u16.to_le_bytes());
            for index in 0..9u16 {
                let slot = 0x2004 + usize::from(index) * 2;
                memory[slot..slot + 2].copy_from_slice(&index.to_le_bytes());
            }
        }
        let reads = Cell::new(0);
        let read = |address, len| {
            reads.set(reads.get() + 1);
            read_ring(&memory, address, len)
        };
        let first = capture_heads(&mut state, RX, MAX_QUEUE_BATCH, read)
            .expect("capture")
            .expect("available entries");
        assert_eq!(first.count, MAX_QUEUE_BATCH);
        assert_eq!(&first.heads[..first.count], &[0, 1, 2, 3, 4, 5, 6, 7]);
        assert!(first.has_more);
        assert_eq!(reads.get(), 2);
        assert_eq!(state.next[RX], 0);

        {
            let mut memory = memory.borrow_mut();
            memory[0x2002..0x2004].copy_from_slice(&10u16.to_le_bytes());
            memory[0x2016..0x2018].copy_from_slice(&9u16.to_le_bytes());
        }
        assert_eq!(&first.heads[..first.count], &[0, 1, 2, 3, 4, 5, 6, 7]);
        state.next[RX] = u16::try_from(first.count).expect("batch size");
        let later = capture_heads(&mut state, RX, MAX_QUEUE_BATCH, read)
            .expect("capture")
            .expect("remaining entries");
        assert_eq!(&later.heads[..later.count], &[8, 9]);
        assert!(!later.has_more);
    }

    #[test]
    fn capture_handles_available_index_wraparound() {
        let mut state = armed_rx_queue();
        state.next[RX] = u16::MAX - 1;
        let memory = RefCell::new(vec![0; 0x4000]);
        {
            let mut memory = memory.borrow_mut();
            memory[0x2002..0x2004].copy_from_slice(&1u16.to_le_bytes());
            for (slot, head) in [(14usize, 14u16), (15, 15), (0, 0)] {
                let start = 0x2004 + slot * 2;
                memory[start..start + 2].copy_from_slice(&head.to_le_bytes());
            }
        }
        let batch = capture_heads(&mut state, RX, MAX_QUEUE_BATCH, |address, len| {
            read_ring(&memory, address, len)
        })
        .expect("capture")
        .expect("wrapped entries");
        assert_eq!(&batch.heads[..batch.count], &[14, 15, 0]);
        assert_eq!(state.next[RX], u16::MAX - 1);
        let partial = capture_heads(&mut state, RX, MAX_QUEUE_BATCH, |address, len| {
            if address == 0x2004 {
                Err(DeviceError::Unmapped)
            } else {
                read_ring(&memory, address, len)
            }
        })
        .expect("partial capture")
        .expect("first span");
        assert_eq!(&partial.heads[..partial.count], &[14, 15]);
        assert!(partial.has_more);
        assert_eq!(state.next[RX], u16::MAX - 1);
    }

    #[test]
    fn used_publication_retries_after_span_or_index_write_failure() {
        let mut used = [0; MAX_QUEUE_BATCH * 8];
        for (index, (head, len)) in [(14, 4), (15, 5), (0, 6)].into_iter().enumerate() {
            stage_used(&mut used, index, head, len);
        }
        let batch = QueueBatch {
            descriptor_table: 0x1000,
            used_ring: 0x3000,
            size: 16,
            heads: [0; MAX_QUEUE_BATCH],
            count: 3,
            has_more: false,
        };
        for failed_address in [0x307c, 0x3004, 0x3002] {
            let mut state = armed_rx_queue();
            state.next[RX] = u16::MAX - 1;
            let memory = RefCell::new(vec![0; 0x4000]);
            write_ring(&memory, 0x3002, &u16::MAX.to_le_bytes()).expect("used index");
            let fail_once = Cell::new(true);
            let read = |address, len| read_ring(&memory, address, len);
            let write = |address, bytes: &[u8]| {
                if address == failed_address && fail_once.replace(false) {
                    Err(DeviceError::Unmapped)
                } else {
                    write_ring(&memory, address, bytes)
                }
            };
            assert_eq!(
                publish_used(&mut state, RX, &batch, &used, 3, read, write),
                Err(DeviceError::Unmapped)
            );
            assert_eq!(read_u16(0x3002, read), Ok(u16::MAX));
            assert_eq!(state.next[RX], u16::MAX - 1);
            assert_eq!(state.mmio.read(0x60, 4), Ok(vec![0; 4]));

            publish_used(&mut state, RX, &batch, &used, 3, read, write).expect("retry publication");
            assert_eq!(read_u16(0x3002, read), Ok(2));
            assert_eq!(state.next[RX], 1);
            assert_eq!(read_ring(&memory, 0x307c, 8), Ok(used[..8].to_vec()));
            assert_eq!(read_ring(&memory, 0x3004, 16), Ok(used[8..24].to_vec()));
            assert_eq!(
                state.mmio.read(0x60, 4),
                Ok(INT_USED_BUFFER.to_le_bytes().to_vec())
            );
        }
    }

    #[test]
    fn unconfigured_queue_defers_work() {
        let mut state = State {
            mmio: MmioTransport::new(0, 0x200, 64 * 1024, 1, 1 << 32, QUEUE_SIZE, vec![0; 8])
                .with_queue_count(2),
            next: [0; 2],
            pending_tx: false,
        };
        assert!(
            capture_heads(&mut state, RX, MAX_QUEUE_BATCH, |_, _| {
                Err(DeviceError::Unmapped)
            })
            .expect("unconfigured queue")
            .is_none()
        );
    }
}
