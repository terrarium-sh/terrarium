use std::sync::{LazyLock, Mutex};

use terra_device_transport::{
    INT_USED_BUFFER, MmioTransport, SPLIT_RING_DESC_F_NEXT, SPLIT_RING_DESC_F_WRITE,
    SPLIT_RING_DESCRIPTOR_BYTES, SplitRingDescriptor, VIRTIO_F_VERSION_1, WriteOutcome,
    resync_pending_queue_entries, split_ring_chain,
};
use terra_vsock_device::{Reply, VSOCK_HEADER_BYTES, VsockHeader};

use crate::terra::host::memory;

use crate::terra::mmio::types::DeviceError;

const RX: usize = 0;
const TX: usize = 1;
const QUEUE_SIZE: u16 = 256;
const DESC_BYTES: u64 = SPLIT_RING_DESCRIPTOR_BYTES as u64;
const MAX_CHAIN: usize = 16;
const MAX_PACKET: usize = VSOCK_HEADER_BYTES + terra_vsock_device::MAX_DATA_BYTES as usize;
const NO_INTERRUPT: u16 = 1;
const NO_NOTIFY: u16 = 1;

struct State {
    mmio: MmioTransport,
    next: [u16; 2],
    pending_rx: Option<Reply>,
    pending: [bool; 2],
}

struct QueueBatch {
    size: u16,
    used_ring: u64,
    used_index: u16,
    snapshot: Vec<u8>,
    descriptor_table_offset: Option<usize>,
    heads: Vec<u16>,
    completions: Vec<(u16, u32)>,
    has_more: bool,
}

impl QueueBatch {
    fn descriptor_table(&self) -> Option<&[u8]> {
        self.descriptor_table_offset.map(|offset| {
            &self.snapshot[offset..offset + usize::from(self.size) * SPLIT_RING_DESCRIPTOR_BYTES]
        })
    }

    fn next_head(&self) -> Option<u16> {
        self.heads.get(self.completions.len()).copied()
    }

    fn has_remaining(&self) -> bool {
        self.next_head().is_some() || self.has_more
    }
}

enum RxStep {
    Completed(u32),
    Retry,
    Idle,
}

fn reset_transport(state: &mut State) {
    state.next = [0; 2];
    state.pending_rx = None;
    state.pending = [false; 2];
    super::switch().reset_connections();
    super::wake_worker();
}

fn new_state() -> State {
    State {
        mmio: MmioTransport::new(
            memory::address_limit(),
            19,
            VIRTIO_F_VERSION_1,
            QUEUE_SIZE,
            terra_vsock_device::GUEST_CID.to_le_bytes().to_vec(),
        )
        .with_queue_count(3),
        next: [0; 2],
        pending_rx: None,
        pending: [false; 2],
    }
}

static STATE: LazyLock<Mutex<Option<State>>> = LazyLock::new(|| Mutex::new(None));

terra_device_transport::device_error!(DeviceError);
terra_device_transport::guest_memory!(DeviceError);

fn publish_interrupt_asserted(asserted: bool) {
    terra_device_transport::publish_interrupt_asserted(
        asserted,
        crate::terra::host::interrupt::set_asserted,
    );
}

fn state<T>(f: impl FnOnce(&mut State) -> Result<T, DeviceError>) -> Result<T, DeviceError> {
    let mut state = STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let state = state.as_mut().ok_or(DeviceError::NotReady)?;
    let result = f(state);
    if let Some(asserted) = state.mmio.take_irq() {
        publish_interrupt_asserted(asserted);
    }
    result
}

fn read(addr: u64, len: u64) -> Result<Vec<u8>, DeviceError> {
    if len > MAX_PACKET as u64 {
        return Err(DeviceError::TooLarge);
    }
    read_guest_memory(&[(addr, len)])
}

fn write(addr: u64, bytes: &[u8]) -> Result<(), DeviceError> {
    if bytes.len() > MAX_PACKET {
        return Err(DeviceError::TooLarge);
    }
    write_guest_memory(&[(addr, bytes)])
}

fn at(base: u64, offset: u64) -> Result<u64, DeviceError> {
    base.checked_add(offset).ok_or(DeviceError::Unmapped)
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

fn capture_queue_batch(
    mmio: &MmioTransport,
    queue: usize,
    next: &mut u16,
    max_steps: usize,
    read_index: impl FnOnce(u64, u64) -> Result<Vec<u8>, DeviceError>,
    mut read_snapshot: impl FnMut(&[memory::ReadRange]) -> Result<Vec<u8>, DeviceError>,
) -> Result<Option<QueueBatch>, DeviceError> {
    let Some((descriptor_table, available_ring, used_ring, size)) = mmio.queue_addrs_for(queue)
    else {
        return Ok(None);
    };
    let available = terra_device_transport::read_ring_index(at(available_ring, 2)?, read_index)?;
    if resync_pending_queue_entries(next, available, size) == 0 {
        return Ok(None);
    }
    let ranges = [
        memory::ReadRange {
            offset: available_ring,
            len: 4 + u64::from(size) * 2,
        },
        memory::ReadRange {
            offset: descriptor_table,
            len: u64::from(size) * DESC_BYTES,
        },
        memory::ReadRange {
            offset: at(used_ring, 2)?,
            len: 2,
        },
    ];
    let (snapshot, has_descriptor_table) = match read_snapshot(&ranges) {
        Ok(snapshot) => (snapshot, true),
        Err(DeviceError::Unmapped) => {
            let mut metadata = read_snapshot(&[
                memory::ReadRange {
                    offset: ranges[0].offset,
                    len: ranges[0].len,
                },
                memory::ReadRange {
                    offset: ranges[2].offset,
                    len: ranges[2].len,
                },
            ])?;
            let available_bytes = 4 + usize::from(size) * 2;
            if metadata.len() != available_bytes + 2 {
                return Err(DeviceError::BadLen);
            }
            let index = [metadata[available_bytes], metadata[available_bytes + 1]];
            metadata.truncate(available_bytes);
            metadata.resize(
                available_bytes + usize::from(size) * SPLIT_RING_DESCRIPTOR_BYTES,
                0,
            );
            metadata.extend_from_slice(&index);
            (metadata, false)
        }
        Err(error) => return Err(error),
    };
    let mut batch = decode_queue_batch(next, available, size, max_steps, used_ring, snapshot)?;
    if !has_descriptor_table {
        batch.descriptor_table_offset = None;
    }
    Ok(Some(batch))
}

fn decode_queue_batch(
    next: &mut u16,
    available: u16,
    size: u16,
    max_steps: usize,
    used_ring: u64,
    snapshot: Vec<u8>,
) -> Result<QueueBatch, DeviceError> {
    let available_bytes = 4 + usize::from(size) * 2;
    let used_offset = available_bytes + usize::from(size) * SPLIT_RING_DESCRIPTOR_BYTES;
    if size == 0
        || size > QUEUE_SIZE
        || !size.is_power_of_two()
        || max_steps == 0
        || snapshot.len() != used_offset + 2
    {
        return Err(DeviceError::BadLen);
    }
    let count = usize::from(resync_pending_queue_entries(next, available, size));
    let head_count = u16::try_from(count.min(max_steps)).map_err(|_| DeviceError::BadLen)?;
    let heads = (0..head_count)
        .map(|offset| {
            let index = next.wrapping_add(offset) % size;
            let offset = 4 + usize::from(index) * 2;
            u16::from_le_bytes([snapshot[offset], snapshot[offset + 1]])
        })
        .collect();
    Ok(QueueBatch {
        size,
        used_ring,
        used_index: u16::from_le_bytes([snapshot[used_offset], snapshot[used_offset + 1]]),
        snapshot,
        descriptor_table_offset: Some(available_bytes),
        heads,
        completions: Vec::with_capacity(usize::from(head_count)),
        has_more: count > usize::from(head_count),
    })
}

fn completion_ranges(
    used_ring: u64,
    size: u16,
    used_index: u16,
    completions: &[(u16, u32)],
) -> Result<Vec<memory::WriteRange>, DeviceError> {
    if size == 0
        || size > QUEUE_SIZE
        || !size.is_power_of_two()
        || completions.len() > usize::from(size)
    {
        return Err(DeviceError::BadLen);
    }
    if completions.is_empty() {
        return Ok(Vec::new());
    }
    let mut ranges = Vec::with_capacity(3);
    let mut index = used_index;
    let mut completions = completions;
    while !completions.is_empty() {
        let slot = index % size;
        let count = completions.len().min(usize::from(size - slot));
        let mut data = Vec::with_capacity(count * 8);
        for (head, len) in &completions[..count] {
            data.extend_from_slice(&u32::from(*head).to_le_bytes());
            data.extend_from_slice(&len.to_le_bytes());
        }
        ranges.push(memory::WriteRange {
            offset: at(used_ring, 4 + u64::from(slot) * 8)?,
            data,
        });
        index = index.wrapping_add(u16::try_from(count).map_err(|_| DeviceError::BadLen)?);
        completions = &completions[count..];
    }
    ranges.push(memory::WriteRange {
        offset: at(used_ring, 2)?,
        data: index.to_le_bytes().to_vec(),
    });
    Ok(ranges)
}

fn publish_batch(
    state: &mut State,
    queue: usize,
    batch: &QueueBatch,
    write_memory: impl FnOnce(&[memory::WriteRange]) -> Result<(), DeviceError>,
    read_flags: impl FnOnce(u64, u64) -> Result<Vec<u8>, DeviceError>,
) -> Result<(), DeviceError> {
    if batch.completions.is_empty() {
        return Ok(());
    }
    let ranges = completion_ranges(
        batch.used_ring,
        batch.size,
        batch.used_index,
        &batch.completions,
    )?;
    write_memory(&ranges)?;
    state.next[queue] = state.next[queue]
        .wrapping_add(u16::try_from(batch.completions.len()).map_err(|_| DeviceError::BadLen)?);
    let flags = state
        .mmio
        .queue_addrs_for(queue)
        .and_then(|(_, available_ring, _, _)| read_flags(available_ring, 2).ok())
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_le_bytes);
    if flags.is_none_or(|flags| flags & NO_INTERRUPT == 0) {
        state.mmio.signal(INT_USED_BUFFER);
    }
    Ok(())
}

fn rx_used_len(capacity: usize, payload: &[u8]) -> Option<u32> {
    (capacity == VSOCK_HEADER_BYTES && !payload.is_empty()).then_some(0)
}

fn read_tx_packet(
    descriptors: &[SplitRingDescriptor],
    mut read_memory: impl FnMut(u64, u64) -> Result<Vec<u8>, DeviceError>,
) -> Result<Option<(VsockHeader, Vec<u8>)>, DeviceError> {
    let Some(first) = descriptors.first().filter(|descriptor| {
        descriptor.flags & SPLIT_RING_DESC_F_WRITE == 0
            && descriptor.len as usize == VSOCK_HEADER_BYTES
    }) else {
        return Ok(None);
    };
    let header_bytes = read_memory(first.addr, u64::from(first.len))?;
    let Some((header, _)) = VsockHeader::parse(&header_bytes) else {
        return Ok(None);
    };
    let payload_len = header.len as usize;
    let data_len = descriptors[1..].iter().try_fold(0usize, |len, descriptor| {
        len.checked_add(descriptor.len as usize)
    });
    if payload_len > terra_vsock_device::MAX_DATA_BYTES as usize
        || data_len != Some(payload_len)
        || descriptors[1..]
            .iter()
            .any(|descriptor| descriptor.flags & SPLIT_RING_DESC_F_WRITE != 0)
    {
        return Ok(None);
    }
    if let [descriptor] = &descriptors[1..] {
        let data = read_memory(descriptor.addr, u64::from(descriptor.len))?;
        if data.len() != descriptor.len as usize {
            return Err(DeviceError::BadLen);
        }
        return Ok(Some((header, data)));
    }
    let mut data = Vec::with_capacity(payload_len);
    for descriptor in &descriptors[1..] {
        let bytes = read_memory(descriptor.addr, u64::from(descriptor.len))?;
        if bytes.len() != descriptor.len as usize {
            return Err(DeviceError::BadLen);
        }
        data.extend(bytes);
    }
    Ok(Some((header, data)))
}

fn process_tx(batch: &QueueBatch, head: u16) {
    if let Some(table) = batch.descriptor_table()
        && let Ok(descriptors) = chain(table, head, batch.size)
        && let Ok(Some((header, data))) = read_tx_packet(&descriptors, read)
    {
        let touched = super::switch().rx(&header, &data);
        if let Some(connection) = touched {
            super::network::notify_connection(connection);
        }
    }
}

fn process_rx(
    state: &mut State,
    batch: &QueueBatch,
    head: u16,
    write_memory: impl FnMut(u64, &[u8]) -> Result<(), DeviceError>,
) -> RxStep {
    let Some(table) = batch.descriptor_table() else {
        return RxStep::Completed(0);
    };
    let Ok(chain) = chain(table, head, batch.size) else {
        return RxStep::Completed(0);
    };
    let capacity = chain
        .iter()
        .try_fold(0usize, |n, d| n.checked_add(d.len as usize));
    let Some(capacity) = capacity else {
        return RxStep::Completed(0);
    };
    if chain.iter().any(|d| d.flags & SPLIT_RING_DESC_F_WRITE == 0) {
        return RxStep::Completed(0);
    }
    if !(VSOCK_HEADER_BYTES..=MAX_PACKET).contains(&capacity) {
        return RxStep::Completed(0);
    }
    if state
        .pending_rx
        .as_ref()
        .is_some_and(|reply| !super::switch().is_reply_current(reply))
    {
        state.pending_rx = None;
    }
    if state.pending_rx.is_none() {
        state.pending_rx = super::switch().take_reply(MAX_PACKET);
        if let Some(reply) = &state.pending_rx {
            let connection =
                super::switch().connection_for(reply.header.dst_port, reply.header.src_port);
            if let Some(connection) = connection {
                super::network::notify_connection(connection);
            }
        }
        if state
            .pending_rx
            .as_ref()
            .is_some_and(|reply| !super::switch().is_reply_current(reply))
        {
            state.pending_rx = None;
            return RxStep::Retry;
        }
    }
    let Some(reply) = state.pending_rx.as_mut() else {
        return RxStep::Idle;
    };
    let Ok(len) = write_rx_packet(reply, &chain, capacity, write_memory) else {
        return RxStep::Completed(0);
    };
    if reply.payload.is_empty() {
        state.pending_rx = None;
    }
    RxStep::Completed(len)
}

fn write_rx_packet(
    reply: &mut Reply,
    descriptors: &[SplitRingDescriptor],
    capacity: usize,
    mut write_memory: impl FnMut(u64, &[u8]) -> Result<(), DeviceError>,
) -> Result<u32, DeviceError> {
    if let Some(len) = rx_used_len(capacity, &reply.payload) {
        return Ok(len);
    }
    let take = (capacity - VSOCK_HEADER_BYTES).min(reply.payload.len());
    let mut header = reply.header;
    header.len = u32::try_from(take).map_err(|_| DeviceError::TooLarge)?;
    let mut packet = Vec::with_capacity(VSOCK_HEADER_BYTES + take);
    packet.extend_from_slice(&header.encode());
    packet.extend_from_slice(&reply.payload[..take]);
    let mut rest = packet.as_slice();
    for descriptor in descriptors {
        let take = rest.len().min(descriptor.len as usize);
        write_memory(descriptor.addr, &rest[..take])?;
        rest = &rest[take..];
        if rest.is_empty() {
            break;
        }
    }
    if !rest.is_empty() {
        return Err(DeviceError::BadLen);
    }
    reply.payload.drain(..take);
    u32::try_from(packet.len()).map_err(|_| DeviceError::TooLarge)
}

pub fn configure() -> Result<(), DeviceError> {
    if super::WORK.is_closed() {
        return Err(DeviceError::NotReady);
    }
    publish_interrupt_asserted(false);
    *STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(new_state());
    Ok(())
}

pub fn mmio_read(addr: u64, width: u8) -> Result<u64, DeviceError> {
    state(|state| state.mmio.read(addr, width).map_err(DeviceError::from))
}

pub fn mmio_write(addr: u64, width: u8, value: u64) -> Result<(), DeviceError> {
    state(|state| write_transport(state, addr, width, value))
}

fn write_transport(state: &mut State, addr: u64, width: u8, value: u64) -> Result<(), DeviceError> {
    match state.mmio.write(addr, width, value)? {
        WriteOutcome::None => {}
        WriteOutcome::QueueNotify(queue) => {
            let queue = usize::from(queue);
            if queue < state.pending.len() {
                state.pending[queue] = true;
            }
            super::wake_worker();
        }
        WriteOutcome::Reset => reset_transport(state),
    }
    Ok(())
}

fn suppress_tx_notifications(
    state: &mut State,
    write_memory: impl FnOnce(u64, &[u8]) -> Result<(), DeviceError>,
) {
    if let Some((_, _, used_ring, _)) = state.mmio.queue_addrs_for(TX)
        && write_memory(used_ring, &NO_NOTIFY.to_le_bytes()).is_ok()
    {
        state.pending[TX] = true;
    }
}

fn rearm_tx_notifications(
    state: &mut State,
    mut read_memory: impl FnMut(u64, u64) -> Result<Vec<u8>, DeviceError>,
    write_memory: impl FnOnce(u64, &[u8]) -> Result<(), DeviceError>,
) -> Result<bool, DeviceError> {
    let Some((_, available_ring, used_ring, size)) = state.mmio.queue_addrs_for(TX) else {
        state.pending[TX] = false;
        return Ok(false);
    };
    if let Err(error) = write_memory(used_ring, &0_u16.to_le_bytes()) {
        let flags = read_memory(used_ring, 2)
            .ok()
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .map(u16::from_le_bytes);
        if flags.is_some_and(|flags| flags & NO_NOTIFY != 0) {
            return Err(error);
        }
    }
    let available = u16::from_le_bytes(
        read_memory(at(available_ring, 2)?, 2)?
            .try_into()
            .map_err(|_| DeviceError::BadLen)?,
    );
    state.pending[TX] = resync_pending_queue_entries(&mut state.next[TX], available, size) != 0;
    Ok(state.pending[TX])
}

pub fn suppress_transmit_notifications() -> Result<(), DeviceError> {
    state(|state| {
        suppress_tx_notifications(state, write);
        Ok(())
    })
}

/// `Ok(true)` means advertised TX heads still need processing.
pub fn rearm_transmit_notifications() -> Result<bool, DeviceError> {
    state(|state| rearm_tx_notifications(state, read, write))
}

fn capture_pending_batches(
    state: &mut State,
    max_steps: usize,
    mut read_index: impl FnMut(u64, u64) -> Result<Vec<u8>, DeviceError>,
    mut read_snapshot: impl FnMut(&[memory::ReadRange]) -> Result<Vec<u8>, DeviceError>,
) -> Result<[Option<QueueBatch>; 2], DeviceError> {
    let mut batches: [Option<QueueBatch>; 2] = [None, None];
    for queue in [TX, RX] {
        if state.pending[queue]
            || (queue == RX
                && batches[TX]
                    .as_ref()
                    .and_then(QueueBatch::next_head)
                    .is_some())
        {
            batches[queue] = capture_queue_batch(
                &state.mmio,
                queue,
                &mut state.next[queue],
                max_steps,
                &mut read_index,
                &mut read_snapshot,
            )?;
        }
    }
    Ok(batches)
}

pub fn process_pending(max_steps: usize) -> Result<bool, DeviceError> {
    state(|state| {
        let mut batches = capture_pending_batches(state, max_steps, read, |ranges| {
            memory::read_ranges(ranges).map_err(|_| DeviceError::Unmapped)
        })?;
        let mut rx_enabled = state.pending[RX]
            || batches[TX]
                .as_ref()
                .and_then(QueueBatch::next_head)
                .is_some();
        let mut progressed = false;
        for _ in 0..max_steps {
            let mut moved = false;
            if let Some(batch) = batches[TX].as_mut()
                && let Some(head) = batch.next_head()
            {
                process_tx(batch, head);
                batch.completions.push((head, 0));
                moved = true;
                rx_enabled = true;
            }
            if rx_enabled
                && let Some(batch) = batches[RX].as_mut()
                && let Some(head) = batch.next_head()
            {
                match process_rx(state, batch, head, write) {
                    RxStep::Completed(len) => {
                        batch.completions.push((head, len));
                        moved = true;
                    }
                    RxStep::Retry => moved = true,
                    RxStep::Idle => rx_enabled = false,
                }
            }
            progressed |= moved;
            if !moved {
                break;
            }
        }
        for queue in [TX, RX] {
            state.pending[queue] = batches[queue]
                .as_ref()
                .is_some_and(|batch| batch.has_remaining() && (queue == TX || rx_enabled));
            if let Some(batch) = batches[queue].as_ref() {
                publish_batch(
                    state,
                    queue,
                    batch,
                    |ranges| memory::write_ranges(ranges).map_err(|_| DeviceError::Unmapped),
                    read,
                )?;
            }
        }
        Ok(progressed)
    })
}

pub fn has_pending_reply_for(connection: terra_vsock_device::ConnectionId) -> bool {
    state(|state| {
        Ok(state.pending_rx.as_ref().is_some_and(|reply| {
            reply.header.src_port == connection.host_port
                && reply.header.dst_port == connection.guest_port
                && super::switch().is_reply_current(reply)
        }))
    })
    .unwrap_or(false)
}

/// Marks the RX queue for service and wakes the worker to fill it.
pub fn schedule_receive_queue() {
    let _ = state(|state| {
        state.pending[RX] = true;
        Ok(())
    });
    super::wake_worker();
}

pub fn reset() {
    if !super::WORK.is_closed() {
        let _ = configure();
        super::switch().reset_connections();
    }
}
pub fn close() {
    super::WORK.close();
    *STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    publish_interrupt_asserted(false);
    super::switch().reset_connections();
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_tx_descriptors(bytes: &[u8], head: u16, queue_size: u16) {
    if let Ok(descriptors) = chain(bytes, head, queue_size) {
        let _ = read_tx_packet(&descriptors, |address, len| {
            let start = usize::try_from(address).map_err(|_| DeviceError::Unmapped)?;
            let len = usize::try_from(len).map_err(|_| DeviceError::TooLarge)?;
            let end = start.checked_add(len).ok_or(DeviceError::Unmapped)?;
            bytes
                .get(start..end)
                .map(<[u8]>::to_vec)
                .ok_or(DeviceError::Unmapped)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use terra_vsock_device::{
        AGENT_RX_ALLOC, AGENT_VSOCK_PORT, GUEST_CID, HOST_CID, MAX_DATA_BYTES,
    };

    fn header(len: u32) -> VsockHeader {
        VsockHeader {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: AGENT_VSOCK_PORT,
            dst_port: AGENT_VSOCK_PORT,
            len,
            type_: 1,
            op: 5,
            flags: 0,
            buf_alloc: AGENT_RX_ALLOC,
            fwd_cnt: 0,
        }
    }

    fn descriptors(len: u32) -> Vec<SplitRingDescriptor> {
        vec![
            SplitRingDescriptor {
                addr: 100,
                len: u32::try_from(VSOCK_HEADER_BYTES).unwrap(),
                flags: SPLIT_RING_DESC_F_NEXT,
                next: 1,
            },
            SplitRingDescriptor {
                addr: 200,
                len,
                flags: 0,
                next: 0,
            },
        ]
    }

    fn queue_snapshot(size: u16, available: u16, used: u16) -> Vec<u8> {
        let available_bytes = 4 + usize::from(size) * 2;
        let used_offset = available_bytes + usize::from(size) * SPLIT_RING_DESCRIPTOR_BYTES;
        let mut bytes = vec![0; used_offset + 2];
        bytes[2..4].copy_from_slice(&available.to_le_bytes());
        bytes[used_offset..].copy_from_slice(&used.to_le_bytes());
        for index in 0..size {
            let offset = 4 + usize::from(index) * 2;
            bytes[offset..offset + 2].copy_from_slice(&index.to_le_bytes());
            let offset = available_bytes + usize::from(index) * SPLIT_RING_DESCRIPTOR_BYTES;
            bytes[offset..offset + 8].copy_from_slice(&(100 + u64::from(index)).to_le_bytes());
            bytes[offset + 8..offset + 12]
                .copy_from_slice(&u32::try_from(VSOCK_HEADER_BYTES).unwrap().to_le_bytes());
            bytes[offset + 12..offset + 14].copy_from_slice(&SPLIT_RING_DESC_F_WRITE.to_le_bytes());
        }
        bytes
    }

    fn queue_mmio(size: u16) -> MmioTransport {
        let mut mmio = MmioTransport::new(65536, 19, VIRTIO_F_VERSION_1, QUEUE_SIZE, Vec::new())
            .with_queue_count(3);
        for (offset, value) in [
            (0x38, u32::from(size)),
            (0x80, 0x1000),
            (0x90, 0x2000),
            (0xa0, 0x3000),
            (0x44, 1),
        ] {
            mmio.write(offset, 4, u64::from(value)).unwrap();
        }
        mmio
    }

    fn notification_state() -> State {
        let mut mmio = queue_mmio(8);
        for (offset, value) in [
            (0x30, 1_u32),
            (0x38, 8),
            (0x80, 0x4000),
            (0x90, 0x5000),
            (0xa0, 0x6000),
            (0x44, 1),
        ] {
            mmio.write(offset, 4, u64::from(value)).unwrap();
        }
        State {
            mmio,
            next: [0; 2],
            pending_rx: None,
            pending: [false; 2],
        }
    }

    fn completed_batch(queue: usize) -> QueueBatch {
        let used_ring = if queue == RX { 0x3000 } else { 0x6000 };
        let mut batch =
            decode_queue_batch(&mut 0, 1, 8, 32, used_ring, queue_snapshot(8, 1, 0)).unwrap();
        batch.completions.push((0, 44));
        batch
    }

    fn used_interrupt_status(state: &mut State) -> bool {
        state.mmio.interrupt_status() & INT_USED_BUFFER != 0
    }

    /// An arrival whose kick was suppressed remains visible when notifications are reenabled.
    #[test]
    fn tx_notification_rearm_checks_availability_after_clearing_the_hint() {
        let mut state = notification_state();
        let flags = std::cell::Cell::new(0_u16);
        let available = std::cell::Cell::new(0_u16);
        let order = std::cell::RefCell::new(Vec::new());
        suppress_tx_notifications(&mut state, |address, bytes| {
            assert_eq!(
                (address, bytes),
                (0x6000, NO_NOTIFY.to_le_bytes().as_slice())
            );
            flags.set(NO_NOTIFY);
            order.borrow_mut().push("suppress");
            Ok(())
        });
        assert!(state.pending[TX]);
        assert!(
            rearm_tx_notifications(
                &mut state,
                |address, len| {
                    assert_eq!((address, len), (0x5002, 2));
                    assert_eq!(flags.get(), 0);
                    order.borrow_mut().push("index");
                    Ok(available.get().to_le_bytes().to_vec())
                },
                |address, bytes| {
                    assert_eq!((address, bytes), (0x6000, 0_u16.to_le_bytes().as_slice()));
                    available.set(1);
                    flags.set(0);
                    order.borrow_mut().push("enable");
                    Ok(())
                }
            )
            .unwrap()
        );
        assert_eq!(*order.borrow(), ["suppress", "enable", "index"]);
        assert!(state.pending[TX]);
        assert_eq!(state.next[TX], 0);
        assert!(!state.pending[RX]);
    }

    /// Active turns poll suppressed TX arrivals, but an empty TX queue does not poll idle RX buffers.
    #[test]
    fn tx_suppression_polls_each_active_turn_without_empty_rx_work() {
        let mut state = notification_state();
        for available in [0, 1] {
            state.pending = [false; 2];
            suppress_tx_notifications(&mut state, |address, bytes| {
                assert_eq!(
                    (address, bytes),
                    (0x6000, NO_NOTIFY.to_le_bytes().as_slice())
                );
                Ok(())
            });
            assert!(state.pending[TX]);
            let mut indices = Vec::new();
            let mut snapshots = Vec::new();
            let batches = capture_pending_batches(
                &mut state,
                32,
                |address, len| {
                    indices.push(address);
                    assert_eq!(len, 2);
                    let index = if address == 0x5002 { available } else { 8_u16 };
                    Ok(index.to_le_bytes().to_vec())
                },
                |ranges| {
                    snapshots.push(ranges[0].offset);
                    Ok(queue_snapshot(
                        8,
                        if ranges[0].offset == 0x5000 {
                            available
                        } else {
                            8
                        },
                        0,
                    ))
                },
            )
            .unwrap();
            if available == 0 {
                assert_eq!(indices, [0x5002]);
                assert_eq!(snapshots, [] as [u64; 0]);
                assert!(batches.iter().all(Option::is_none));
                assert!(
                    !rearm_tx_notifications(
                        &mut state,
                        |address, len| {
                            assert_eq!((address, len), (0x5002, 2));
                            Ok(0_u16.to_le_bytes().to_vec())
                        },
                        |address, bytes| {
                            assert_eq!((address, bytes), (0x6000, 0_u16.to_le_bytes().as_slice()));
                            Ok(())
                        }
                    )
                    .unwrap()
                );
                assert!(!state.pending[TX]);
            } else {
                assert_eq!(indices, [0x5002, 0x2002]);
                assert_eq!(snapshots, [0x5000, 0x2000]);
                assert_eq!(batches[TX].as_ref().unwrap().heads, [0]);
                assert_eq!(batches[RX].as_ref().unwrap().heads.len(), 8);
            }
        }
    }

    #[test]
    fn tx_notification_rearm_handles_wrap_idle_and_impossible_indices() {
        for (next, available, pending, expected_next) in [
            (u16::MAX, 1_u16, true, u16::MAX),
            (4, 4, false, 4),
            (0, 9, false, 9),
        ] {
            let mut state = notification_state();
            state.next[TX] = next;
            state.pending[TX] = true;
            assert_eq!(
                rearm_tx_notifications(
                    &mut state,
                    |address, len| {
                        assert_eq!((address, len), (0x5002, 2));
                        Ok(available.to_le_bytes().to_vec())
                    },
                    |address, bytes| {
                        assert_eq!((address, bytes), (0x6000, 0_u16.to_le_bytes().as_slice()));
                        Ok(())
                    }
                )
                .unwrap(),
                pending
            );
            assert_eq!(state.pending[TX], pending);
            assert_eq!(state.next[TX], expected_next);
        }
    }

    #[test]
    fn tx_notification_helpers_use_current_queue_addresses_and_skip_disabled_or_reset_queues() {
        for reset in [false, true] {
            let mut state = notification_state();
            state.pending[TX] = true;
            state
                .mmio
                .write(if reset { 0x70 } else { 0x44 }, 4, 0)
                .unwrap();
            suppress_tx_notifications(&mut state, |_, _| {
                panic!("inactive TX queue must not write")
            });
            assert!(
                !rearm_tx_notifications(
                    &mut state,
                    |_, _| panic!("inactive TX queue must not read"),
                    |_, _| panic!("inactive TX queue must not write")
                )
                .unwrap()
            );
            assert!(!state.pending[TX]);
            for (offset, value) in [
                (0x30, 1_u32),
                (0x38, 8),
                (0x80, 0x7000),
                (0x90, 0x8000),
                (0xa0, 0x9000),
                (0x44, 1),
            ] {
                state.mmio.write(offset, 4, u64::from(value)).unwrap();
            }
            suppress_tx_notifications(&mut state, |address, _| {
                assert_eq!(address, 0x9000);
                Ok(())
            });
            assert!(state.pending[TX]);
            assert!(
                rearm_tx_notifications(
                    &mut state,
                    |address, len| {
                        assert_eq!((address, len), (0x8002, 2));
                        Ok(1_u16.to_le_bytes().to_vec())
                    },
                    |address, _| {
                        assert_eq!(address, 0x9000);
                        Ok(())
                    }
                )
                .unwrap()
            );
        }
    }

    /// Advisory RAM holes remain recoverable; a readable hint that cannot be cleared prevents sleep.
    #[test]
    fn tx_advisory_write_failures_preserve_progress_without_a_stuck_suppression_hint() {
        let mut state = notification_state();
        suppress_tx_notifications(&mut state, |_, _| Err(DeviceError::Unmapped));
        assert!(!state.pending[TX]);
        for hint in [Err(DeviceError::Unmapped), Ok(0_u16.to_le_bytes().to_vec())] {
            assert!(
                rearm_tx_notifications(
                    &mut state,
                    |address, len| {
                        assert_eq!(len, 2);
                        if address == 0x6000 {
                            hint.clone()
                        } else {
                            assert_eq!(address, 0x5002);
                            Ok(1_u16.to_le_bytes().to_vec())
                        }
                    },
                    |_, _| Err(DeviceError::Unmapped)
                )
                .unwrap()
            );
            assert!(state.pending[TX]);
        }
        assert_eq!(
            rearm_tx_notifications(
                &mut state,
                |address, len| {
                    assert_eq!((address, len), (0x6000, 2));
                    Ok(NO_NOTIFY.to_le_bytes().to_vec())
                },
                |_, _| Err(DeviceError::Unmapped)
            ),
            Err(DeviceError::Unmapped)
        );
        for index in [Err(DeviceError::Unmapped), Ok(vec![0])] {
            assert!(
                rearm_tx_notifications(
                    &mut state,
                    |address, len| {
                        assert_eq!((address, len), (0x5002, 2));
                        index.clone()
                    },
                    |_, _| Ok(())
                )
                .is_err()
            );
        }
    }

    /// Guest callback reenabling must be observed after publishing the final used index.
    #[test]
    fn reenabling_during_publication_requests_an_interrupt_despite_the_old_snapshot() {
        let mut state = notification_state();
        let mut batch = completed_batch(RX);
        batch.snapshot[..2].copy_from_slice(&NO_INTERRUPT.to_le_bytes());
        let flags = std::cell::Cell::new(NO_INTERRUPT);
        let order = std::cell::RefCell::new(Vec::new());
        publish_batch(
            &mut state,
            RX,
            &batch,
            |ranges| {
                assert_eq!(ranges.last().unwrap().offset, 0x3002);
                assert_eq!(ranges.last().unwrap().data, 1_u16.to_le_bytes());
                order.borrow_mut().push("used");
                flags.set(0);
                Ok(())
            },
            |address, len| {
                assert_eq!((address, len), (0x2000, 2));
                order.borrow_mut().push("flags");
                Ok(flags.get().to_le_bytes().to_vec())
            },
        )
        .unwrap();
        assert_eq!(*order.borrow(), ["used", "flags"]);
        assert_eq!(state.next[RX], 1);
        assert!(used_interrupt_status(&mut state));
    }

    #[test]
    fn suppressed_completions_advance_the_queue_and_preserve_sticky_interrupts() {
        for has_prior_interrupt in [false, true] {
            let mut state = notification_state();
            if has_prior_interrupt {
                state.mmio.signal(INT_USED_BUFFER);
            }
            publish_batch(
                &mut state,
                RX,
                &completed_batch(RX),
                |_| Ok(()),
                |_, _| Ok(NO_INTERRUPT.to_le_bytes().to_vec()),
            )
            .unwrap();
            assert_eq!(state.next[RX], 1);
            assert_eq!(used_interrupt_status(&mut state), has_prior_interrupt);
        }
    }

    #[test]
    fn each_queue_reads_its_own_hint_and_either_queue_can_request_notification() {
        let mut state = notification_state();
        for (queue, available_ring, flags) in [(TX, 0x5000, NO_INTERRUPT), (RX, 0x2000, 0)] {
            publish_batch(
                &mut state,
                queue,
                &completed_batch(queue),
                |_| Ok(()),
                |address, len| {
                    assert_eq!((address, len), (available_ring, 2));
                    Ok(flags.to_le_bytes().to_vec())
                },
            )
            .unwrap();
            assert_eq!(used_interrupt_status(&mut state), queue == RX);
        }
        assert_eq!(state.next, [1; 2]);
    }

    #[test]
    fn sticky_completions_do_not_repeat_irq_levels_and_ack_allows_reassertion() {
        let mut state = notification_state();
        for status in [1_u8, 3, 11, 15] {
            state.mmio.write(0x70, 1, u64::from(status)).unwrap();
        }
        for (queue, transition) in [(RX, Some(true)), (TX, None)] {
            publish_batch(
                &mut state,
                queue,
                &completed_batch(queue),
                |_| Ok(()),
                |_, _| Ok(0_u16.to_le_bytes().to_vec()),
            )
            .unwrap();
            assert!(used_interrupt_status(&mut state));
            assert_eq!(state.mmio.take_irq(), transition);
        }
        state.mmio.write(0x64, 4, 3).unwrap();
        assert!(!used_interrupt_status(&mut state));
        assert_eq!(state.mmio.take_irq(), Some(false));
        let mut batch = completed_batch(RX);
        batch.used_index = 1;
        publish_batch(
            &mut state,
            RX,
            &batch,
            |_| Ok(()),
            |_, _| Ok(0_u16.to_le_bytes().to_vec()),
        )
        .unwrap();
        assert!(used_interrupt_status(&mut state));
        assert_eq!(state.mmio.take_irq(), Some(true));
        assert_eq!(state.next, [2, 1]);
    }

    #[test]
    fn unreadable_interrupt_hints_notify_conservatively() {
        for result in [Err(DeviceError::Unmapped), Ok(Vec::new()), Ok(vec![1])] {
            let mut state = notification_state();
            publish_batch(
                &mut state,
                RX,
                &completed_batch(RX),
                |_| Ok(()),
                |_, _| result,
            )
            .unwrap();
            assert!(used_interrupt_status(&mut state));
        }
    }

    #[test]
    fn failed_or_empty_completion_does_not_read_the_interrupt_hint() {
        let mut state = notification_state();
        assert_eq!(
            publish_batch(
                &mut state,
                RX,
                &completed_batch(RX),
                |_| Err(DeviceError::Unmapped),
                |_, _| panic!("failed publication must not read flags"),
            ),
            Err(DeviceError::Unmapped)
        );
        let batch = decode_queue_batch(&mut 0, 0, 8, 32, 0x3000, queue_snapshot(8, 0, 0)).unwrap();
        publish_batch(
            &mut state,
            RX,
            &batch,
            |_| panic!("empty batch must not write"),
            |_, _| panic!("empty batch must not read flags"),
        )
        .unwrap();
        assert_eq!(state.next, [0; 2]);
        assert!(!used_interrupt_status(&mut state));
    }

    /// One index read precedes one snapshot import, and later publication cannot extend that batch.
    #[test]
    fn queue_batch_observes_publication_before_metadata_and_excludes_late_heads() {
        let mut next = 0;
        let order = std::cell::RefCell::new(Vec::new());
        let mut guest = queue_snapshot(8, 4, 7);
        let batch = capture_queue_batch(
            &queue_mmio(8),
            RX,
            &mut next,
            32,
            |address, len| {
                order.borrow_mut().push("index");
                assert_eq!((address, len), (0x2002, 2));
                Ok(2_u16.to_le_bytes().to_vec())
            },
            |ranges| {
                order.borrow_mut().push("snapshot");
                assert_eq!(
                    ranges
                        .iter()
                        .map(|range| (range.offset, range.len))
                        .collect::<Vec<_>>(),
                    [(0x2000, 20), (0x1000, 128), (0x3002, 2)]
                );
                Ok(guest.clone())
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(*order.borrow(), ["index", "snapshot"]);
        assert_eq!(batch.heads, [0, 1]);
        assert!(!batch.has_more);
        assert_eq!(batch.used_index, 7);
        guest[4..6].copy_from_slice(&7_u16.to_le_bytes());
        guest[20..28].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(batch.next_head(), Some(0));
        assert_eq!(
            chain(batch.descriptor_table().unwrap(), 0, 8).unwrap()[0].addr,
            100
        );
    }

    #[test]
    fn queue_batch_wraps_indices_and_keeps_the_step_limit() {
        let mut next = u16::MAX - 1;
        let mut batch =
            decode_queue_batch(&mut next, 2, 8, 3, 0x3000, queue_snapshot(8, 2, 0)).unwrap();
        assert_eq!(batch.heads, [6, 7, 0]);
        assert!(batch.has_more);
        for head in [6, 7, 0] {
            assert_eq!(batch.next_head(), Some(head));
            batch.completions.push((head, 0));
        }
        assert_eq!(batch.next_head(), None);
        assert!(batch.has_remaining());
        assert_eq!(next, u16::MAX - 1);
    }

    #[test]
    fn queue_batch_rejects_invalid_sizes_and_resynchronizes_impossible_publication() {
        for size in [0, 3, QUEUE_SIZE * 2] {
            assert!(
                decode_queue_batch(&mut 0, 1, size, 32, 0, queue_snapshot(size, 1, 0)).is_err()
            );
        }
        assert!(decode_queue_batch(&mut 0, 1, 8, 0, 0, queue_snapshot(8, 1, 0)).is_err());
        assert!(decode_queue_batch(&mut 0, 1, 8, 32, 0, vec![0; 8]).is_err());
        let mut next = 0;
        let batch = decode_queue_batch(&mut next, 9, 8, 32, 0, queue_snapshot(8, 9, 0)).unwrap();
        assert_eq!(next, 9);
        assert_eq!(batch.heads, [] as [u16; 0]);
        assert!(!batch.has_remaining());
        assert!(
            capture_queue_batch(
                &queue_mmio(8),
                RX,
                &mut next,
                32,
                |_, _| Ok(9_u16.to_le_bytes().to_vec()),
                |_| panic!("empty queue must not copy descriptor metadata"),
            )
            .unwrap()
            .is_none()
        );
    }

    /// An unmapped descriptor table completes captured heads with zero bytes and retains replies.
    #[test]
    fn unmapped_descriptor_table_keeps_valid_queue_metadata_recoverable() {
        let mut calls = 0;
        let snapshot = queue_snapshot(8, 2, 6);
        let mut batch = capture_queue_batch(
            &queue_mmio(8),
            RX,
            &mut 0,
            32,
            |_, _| Ok(2_u16.to_le_bytes().to_vec()),
            |ranges| {
                calls += 1;
                if calls == 1 {
                    assert_eq!(ranges.len(), 3);
                    Err(DeviceError::Unmapped)
                } else {
                    assert_eq!(ranges.len(), 2);
                    assert_eq!(ranges[0].offset, 0x2000);
                    assert_eq!(ranges[1].offset, 0x3002);
                    let mut metadata = snapshot[..20].to_vec();
                    metadata.extend_from_slice(&6_u16.to_le_bytes());
                    Ok(metadata)
                }
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(batch.heads, [0, 1]);
        assert_eq!(batch.used_index, 6);
        assert!(batch.descriptor_table().is_none());
        let mut state = State {
            mmio: queue_mmio(8),
            next: [0; 2],
            pending_rx: Some(Reply {
                connection_number: 0,
                header: header(0),
                payload: Vec::new(),
            }),
            pending: [true; 2],
        };
        for head in [0, 1] {
            assert!(matches!(
                process_rx(&mut state, &batch, head, |_, _| panic!(
                    "unmapped table must not write"
                )),
                RxStep::Completed(0)
            ));
            batch.completions.push((head, 0));
        }
        assert!(state.pending_rx.is_some());
        assert!(!batch.has_remaining());
        let ranges = completion_ranges(
            batch.used_ring,
            batch.size,
            batch.used_index,
            &batch.completions,
        )
        .unwrap();
        assert_eq!(ranges.last().unwrap().data, 8_u16.to_le_bytes());
    }

    /// Used entries cross the ring boundary in at most two ranges; the wrapped index is last.
    #[test]
    fn wrapped_completions_publish_entries_before_the_index_within_range_limits() {
        let completions = [(3, 44), (4, 48), (5, 52)];
        let ranges = completion_ranges(0x3000, 8, u16::MAX, &completions).unwrap();
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0].offset, 0x3000 + 4 + 7 * 8);
        assert_eq!(
            ranges[0].data,
            [3_u32.to_le_bytes(), 44_u32.to_le_bytes()].concat()
        );
        assert_eq!(ranges[1].offset, 0x3004);
        assert_eq!(
            ranges[1].data,
            [
                4_u32.to_le_bytes(),
                48_u32.to_le_bytes(),
                5_u32.to_le_bytes(),
                52_u32.to_le_bytes()
            ]
            .concat()
        );
        assert_eq!(ranges[2].offset, 0x3002);
        assert_eq!(ranges[2].data, 2_u16.to_le_bytes());
        let full =
            completion_ranges(0x3000, QUEUE_SIZE, QUEUE_SIZE - 1, &vec![(0, 0); 32]).unwrap();
        assert_eq!(full.len(), 3);
        assert!(full.len() <= terra_limits::MAX_BATCH_GUEST_COPY_RANGES);
        assert_eq!(full.last().unwrap().offset, 0x3002);
        assert_eq!(full.last().unwrap().data, (QUEUE_SIZE + 31).to_le_bytes());
        assert!(completion_ranges(u64::MAX, 8, 0, &completions).is_err());
    }

    #[test]
    fn invalid_batch_heads_and_rx_write_failures_preserve_pending_control() {
        let pending = Reply {
            connection_number: 0,
            header: VsockHeader {
                src_port: u32::MAX,
                dst_port: u32::MAX,
                len: 0,
                op: 3,
                ..header(0)
            },
            payload: Vec::new(),
        };
        let mut state = State {
            mmio: queue_mmio(8),
            next: [0; 2],
            pending_rx: Some(pending.clone()),
            pending: [true; 2],
        };
        let batch = decode_queue_batch(&mut 0, 1, 8, 32, 0x3000, queue_snapshot(8, 1, 0)).unwrap();
        assert!(matches!(
            process_rx(&mut state, &batch, 8, |_, _| panic!(
                "invalid head must not write"
            )),
            RxStep::Completed(0)
        ));
        assert_eq!(state.pending_rx.as_ref().unwrap().header, pending.header);
        assert!(matches!(
            process_rx(&mut state, &batch, 0, |_, _| Err(DeviceError::Unmapped)),
            RxStep::Completed(0)
        ));
        assert_eq!(state.pending_rx.as_ref().unwrap().header, pending.header);
        let mut written = Vec::new();
        assert!(matches!(
            process_rx(&mut state, &batch, 0, |_, bytes| {
                written.extend_from_slice(bytes);
                Ok(())
            }),
            RxStep::Completed(44)
        ));
        assert_eq!(written, pending.header.encode());
        assert!(state.pending_rx.is_none());
    }

    #[test]
    fn partial_rx_packet_drains_only_after_every_write_succeeds() {
        let mut reply = Reply {
            connection_number: 0,
            header: header(5),
            payload: b"abcde".to_vec(),
        };
        let descriptors = [
            SplitRingDescriptor {
                addr: 0,
                len: 44,
                flags: SPLIT_RING_DESC_F_NEXT | SPLIT_RING_DESC_F_WRITE,
                next: 1,
            },
            SplitRingDescriptor {
                addr: 100,
                len: 2,
                flags: SPLIT_RING_DESC_F_WRITE,
                next: 0,
            },
        ];
        assert!(
            write_rx_packet(&mut reply, &descriptors, 46, |address, _| {
                if address == 100 {
                    Err(DeviceError::Unmapped)
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        assert_eq!(reply.payload, b"abcde");
        let mut written = Vec::new();
        assert_eq!(
            write_rx_packet(&mut reply, &descriptors, 46, |_, bytes| {
                written.extend_from_slice(bytes);
                Ok(())
            })
            .unwrap(),
            46
        );
        assert_eq!(VsockHeader::parse(&written).unwrap().0.len, 2);
        assert_eq!(&written[VSOCK_HEADER_BYTES..], b"ab");
        assert_eq!(reply.payload, b"cde");
    }

    #[test]
    fn full_payload_is_distinct_from_header_and_packet_capacity() {
        let descriptors = descriptors(MAX_DATA_BYTES);
        let (parsed, bytes) = read_tx_packet(&descriptors, |address, len| {
            if address == 100 {
                Ok(header(MAX_DATA_BYTES).encode().to_vec())
            } else {
                Ok(vec![0; usize::try_from(len).unwrap()])
            }
        })
        .unwrap()
        .unwrap();
        assert_eq!(parsed.len, MAX_DATA_BYTES);
        assert_eq!(bytes.len() + VSOCK_HEADER_BYTES, MAX_PACKET);
    }

    #[test]
    fn invalid_tx_header_descriptors_are_rejected_before_reading_memory() {
        let mut invalid_chains = vec![Vec::new()];
        let mut short_header = descriptors(5);
        short_header[0].len -= 1;
        invalid_chains.push(short_header);
        let mut writable_header = descriptors(5);
        writable_header[0].flags |= SPLIT_RING_DESC_F_WRITE;
        invalid_chains.push(writable_header);
        for descriptors in invalid_chains {
            assert!(
                read_tx_packet(&descriptors, |_, _| panic!("invalid header descriptor"))
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn malformed_tx_headers_do_not_read_payload() {
        for claimed_len in [0, 4, 6, u32::MAX] {
            let mut reads = 0;
            assert!(
                read_tx_packet(&descriptors(5), |address, _| {
                    reads += 1;
                    assert_eq!(address, 100);
                    Ok(header(claimed_len).encode().to_vec())
                })
                .unwrap()
                .is_none()
            );
            assert_eq!(reads, 1);
        }
        assert!(
            read_tx_packet(&descriptors(5), |address, _| {
                assert_eq!(address, 100);
                Ok(vec![0; VSOCK_HEADER_BYTES - 1])
            })
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn tx_payload_reads_preserve_errors_and_reject_short_reads() {
        for payload in [
            Ok(b"agent".to_vec()),
            Ok(b"abcd".to_vec()),
            Err(DeviceError::Unmapped),
        ] {
            let mut reads = Vec::new();
            let result = read_tx_packet(&descriptors(5), |address, len| {
                reads.push((address, len));
                if address == 100 {
                    Ok(header(5).encode().to_vec())
                } else {
                    payload.clone()
                }
            });
            assert_eq!(reads, [(100, 44), (200, 5)]);
            match payload {
                Ok(payload) => {
                    if payload.len() == 5 {
                        let (parsed, bytes) = result.unwrap().unwrap();
                        assert_eq!(parsed, header(5));
                        assert_eq!(bytes, payload);
                    } else {
                        assert_eq!(result.unwrap_err(), DeviceError::BadLen);
                    }
                }
                Err(error) => assert_eq!(result.unwrap_err(), error),
            }
        }
    }

    #[test]
    fn malformed_descriptor_metadata_is_rejected_before_reading_payload() {
        for (payload_len, flags) in [(MAX_DATA_BYTES + 1, 0), (5, SPLIT_RING_DESC_F_WRITE)] {
            let mut descriptors = descriptors(payload_len);
            descriptors[1].flags = flags;
            let mut reads = 0;
            let result = read_tx_packet(&descriptors, |address, _| {
                reads += 1;
                assert_eq!(address, 100);
                Ok(header(payload_len).encode().to_vec())
            });
            assert!(result.unwrap().is_none());
            assert_eq!(reads, 1);
        }
    }

    #[test]
    fn mutated_guest_header_cannot_change_the_captured_endpoint_or_length() {
        let mut guest_header = header(5);
        let (parsed, bytes) = read_tx_packet(&descriptors(5), |address, len| {
            if address == 100 {
                Ok(guest_header.encode().to_vec())
            } else {
                guest_header.src_port = 6001;
                guest_header.dst_port = 6001;
                guest_header.len = u32::MAX;
                assert_eq!(address, 200);
                assert_eq!(len, 5);
                Ok(b"agent".to_vec())
            }
        })
        .unwrap()
        .unwrap();
        assert_eq!(parsed.src_port, AGENT_VSOCK_PORT);
        assert_eq!(parsed.dst_port, AGENT_VSOCK_PORT);
        assert_eq!(parsed.len, 5);
        assert_eq!(bytes, b"agent");
    }

    #[test]
    fn header_only_rx_keeps_payload_for_a_writable_buffer() {
        assert_eq!(rx_used_len(VSOCK_HEADER_BYTES, b"x"), Some(0));
        assert_eq!(rx_used_len(VSOCK_HEADER_BYTES + 1, b"x"), None);
    }
    #[test]
    fn guest_status_reset_wakes_role_retirement_without_a_queue_bell() {
        use terra_vsock_device::{Role, VsockSwitch};

        for bytes in [vec![0], 0_u32.to_le_bytes().to_vec()] {
            *super::super::switch() = VsockSwitch::new();
            for port in [
                terra_vsock_device::AGENT_VSOCK_PORT,
                terra_vsock_device::CONTROL_VSOCK_PORT,
            ] {
                let request = VsockHeader {
                    op: 1,
                    len: 0,
                    src_port: port,
                    dst_port: port,
                    ..header(0)
                };
                super::super::switch().rx(&request, &[]);
            }
            let mut state = State {
                mmio: MmioTransport::new(
                    4096,
                    19,
                    VIRTIO_F_VERSION_1,
                    QUEUE_SIZE,
                    GUEST_CID.to_le_bytes().to_vec(),
                )
                .with_queue_count(3),
                next: [7, 9],
                pending_rx: None,
                pending: [true, true],
            };
            super::super::WORK.clear();
            write_transport(&mut state, 0x70, u8::try_from(bytes.len()).unwrap(), 0).unwrap();
            assert_ne!(super::super::WORK.take(), 0);
            assert_eq!(state.next, [0, 0]);
            assert_eq!(state.pending, [false, false]);
            assert!(super::super::switch().connection(Role::Agent).is_none());
            assert!(super::super::switch().connection(Role::Control).is_none());
            assert_eq!(super::super::switch().retirements().count(), 2);
        }
    }
}
