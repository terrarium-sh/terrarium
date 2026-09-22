use std::sync::{LazyLock, Mutex};

use terra_device_transport::{
    INT_USED_BUFFER, MmioError, MmioTransport, QueueEntry, SPLIT_RING_DESC_F_NEXT,
    SPLIT_RING_DESC_F_WRITE, SPLIT_RING_DESCRIPTOR_BYTES, SplitRingDescriptor, SplitRingError,
    split_ring_chain,
};
use terra_vsock_device::{Reply, VSOCK_HEADER_BYTES, VsockHeader};

use crate::terra::host::{interrupt, memory};

use crate::terra::mmio::types::DeviceError;

const RX: usize = 0;
const TX: usize = 1;
const QUEUE_SIZE: u16 = 256;
const DESC_BYTES: u64 = SPLIT_RING_DESCRIPTOR_BYTES as u64;
const MAX_CHAIN: usize = 16;
const MAX_PACKET: usize = 64 * 1024;
#[allow(clippy::cast_possible_truncation)]
const MAX_MEMORY_COPY: usize = terra_limits::MAX_SINGLE_GUEST_COPY_BYTES as usize;
const NEXT: u16 = SPLIT_RING_DESC_F_NEXT;
const WRITE: u16 = SPLIT_RING_DESC_F_WRITE;
const DRIVER_OK: u8 = 4;

struct State {
    mmio: MmioTransport,
    next: [u16; 2],
    pending_rx: Option<Reply>,
    pending: [bool; 2],
}

fn reset_transport(state: &mut State) {
    state.next = [0; 2];
    state.pending_rx = None;
    state.pending = [false; 2];
    super::switch().reset_connections();
}

fn new_state() -> State {
    State {
        mmio: MmioTransport::new(
            0,
            0x200,
            memory::address_limit(),
            19,
            1 << 32,
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

impl From<MmioError> for DeviceError {
    fn from(error: MmioError) -> Self {
        terra_device_transport::device_error!(error, DeviceError)
    }
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

fn read(addr: u64, len: u64) -> Result<Vec<u8>, DeviceError> {
    if len > MAX_PACKET as u64 {
        return Err(DeviceError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(len).map_err(|_| DeviceError::TooLarge)?);
    let mut offset = 0_u64;
    while offset < len {
        let chunk = (len - offset).min(MAX_MEMORY_COPY as u64);
        bytes.extend(memory::read(at(addr, offset)?, chunk).map_err(|_| DeviceError::Unmapped)?);
        offset = offset.checked_add(chunk).ok_or(DeviceError::Unmapped)?;
    }
    Ok(bytes)
}

fn write(addr: u64, bytes: &[u8]) -> Result<(), DeviceError> {
    if bytes.len() > MAX_PACKET {
        return Err(DeviceError::TooLarge);
    }
    for (offset, chunk) in bytes.chunks(MAX_MEMORY_COPY).enumerate() {
        let offset = u64::try_from(offset)
            .map_err(|_| DeviceError::TooLarge)?
            .checked_mul(MAX_MEMORY_COPY as u64)
            .ok_or(DeviceError::Unmapped)?;
        memory::write(at(addr, offset)?, chunk).map_err(|_| DeviceError::Unmapped)?;
    }
    Ok(())
}

fn at(base: u64, offset: u64) -> Result<u64, DeviceError> {
    base.checked_add(offset).ok_or(DeviceError::Unmapped)
}

fn chain(table: &[u8], index: u16, size: u16) -> Result<Vec<SplitRingDescriptor>, DeviceError> {
    split_ring_chain(table, index, size, MAX_CHAIN, NEXT | WRITE).map_err(|error| match error {
        SplitRingError::BadDescriptor => DeviceError::BadLen,
        SplitRingError::ChainTooLong => DeviceError::TooLarge,
    })
}

fn available(state: &mut State, queue: usize) -> Result<Option<QueueEntry>, DeviceError> {
    state
        .mmio
        .read_queue_entry(queue, &mut state.next[queue], read)
}

fn complete(state: &mut State, queue: usize, head: u16, len: u32) -> Result<(), DeviceError> {
    state
        .mmio
        .complete_queue_entry(queue, &mut state.next[queue], head, len, read, write)?;
    interrupt::signal();
    Ok(())
}

fn rx_used_len(capacity: usize, payload: &[u8]) -> Option<u32> {
    (capacity == VSOCK_HEADER_BYTES && !payload.is_empty()).then_some(0)
}

fn process_tx(state: &mut State) -> Result<bool, DeviceError> {
    let Some(QueueEntry {
        head,
        descriptor_table: desc,
        size,
        ..
    }) = available(state, TX)?
    else {
        return Ok(false);
    };
    let Ok(table) = read(desc, u64::from(size) * DESC_BYTES) else {
        complete(state, TX, head, 0)?;
        return Ok(true);
    };
    if let Ok(chain) = chain(&table, head, size)
        && let Some(first) = chain
            .first()
            .filter(|d| d.flags & WRITE == 0 && d.len as usize == VSOCK_HEADER_BYTES)
    {
        let Ok(header_bytes) = read(first.addr, u64::from(first.len)) else {
            complete(state, TX, head, 0)?;
            return Ok(true);
        };
        if let Ok((header, _)) = VsockHeader::parse(&header_bytes) {
            let payload_len = header.len as usize;
            let data_len = chain[1..]
                .iter()
                .try_fold(0usize, |n, d| n.checked_add(d.len as usize));
            if payload_len <= MAX_PACKET
                && data_len == Some(payload_len)
                && chain[1..].iter().all(|d| d.flags & WRITE == 0)
            {
                let mut data = Vec::with_capacity(payload_len);
                for descriptor in &chain[1..] {
                    let Ok(bytes) = read(descriptor.addr, u64::from(descriptor.len)) else {
                        complete(state, TX, head, 0)?;
                        return Ok(true);
                    };
                    data.extend(bytes);
                }
                super::switch().rx(&header, &data);
            }
        }
    }
    complete(state, TX, head, 0)?;
    Ok(available(state, TX)?.is_some())
}

fn process_rx(state: &mut State) -> Result<bool, DeviceError> {
    let Some(QueueEntry {
        head,
        descriptor_table: desc,
        size,
        ..
    }) = available(state, RX)?
    else {
        return Ok(false);
    };
    let Ok(table) = read(desc, u64::from(size) * DESC_BYTES) else {
        complete(state, RX, head, 0)?;
        return Ok(true);
    };
    let Ok(chain) = chain(&table, head, size) else {
        complete(state, RX, head, 0)?;
        return Ok(true);
    };
    let capacity = chain
        .iter()
        .try_fold(0usize, |n, d| n.checked_add(d.len as usize));
    let Some(capacity) = capacity else {
        complete(state, RX, head, 0)?;
        return Ok(true);
    };
    if chain.iter().any(|d| d.flags & WRITE == 0) {
        complete(state, RX, head, 0)?;
        return Ok(true);
    }
    if !(VSOCK_HEADER_BYTES..=MAX_PACKET).contains(&capacity) {
        complete(state, RX, head, 0)?;
        return Ok(true);
    }
    if state.pending_rx.is_none() {
        state.pending_rx = super::switch().take_replies_up_to(1, MAX_PACKET).pop();
    }
    let Some(reply) = state.pending_rx.as_ref() else {
        return Ok(false);
    };
    if let Some(len) = rx_used_len(capacity, &reply.payload) {
        complete(state, RX, head, len)?;
        return Ok(true);
    }
    let reply = state.pending_rx.as_mut().ok_or(DeviceError::NotReady)?;
    let take = (capacity - VSOCK_HEADER_BYTES).min(reply.payload.len());
    let mut header = reply.header;
    header.len = u32::try_from(take).map_err(|_| DeviceError::TooLarge)?;
    let mut packet = header.encode().to_vec();
    packet.extend_from_slice(&reply.payload[..take]);
    let mut rest = packet.as_slice();
    for descriptor in &chain {
        let take = rest.len().min(descriptor.len as usize);
        if write(descriptor.addr, &rest[..take]).is_err() {
            complete(state, RX, head, 0)?;
            return Ok(true);
        }
        rest = &rest[take..];
        if rest.is_empty() {
            break;
        }
    }
    if !rest.is_empty() {
        complete(state, RX, head, 0)?;
        return Ok(true);
    }
    reply.payload.drain(..take);
    if reply.payload.is_empty() {
        state.pending_rx = None;
    }
    complete(
        state,
        RX,
        head,
        u32::try_from(packet.len()).map_err(|_| DeviceError::TooLarge)?,
    )?;
    Ok(available(state, RX)?.is_some())
}

pub fn configure() -> Result<(), DeviceError> {
    if super::CLOSED.load(std::sync::atomic::Ordering::Acquire) {
        return Err(DeviceError::NotReady);
    }
    publish_interrupt_level(false);
    *STATE.lock().map_err(|_| DeviceError::Io)? = Some(new_state());
    super::worker::set_transport_ready(false);
    Ok(())
}

pub fn mmio_read(addr: u64, len: u32) -> Result<Vec<u8>, DeviceError> {
    state(|state| {
        state
            .mmio
            .read(addr, usize::try_from(len).map_err(|_| DeviceError::BadLen)?)
            .map_err(DeviceError::from)
    })
}

pub fn mmio_write(addr: u64, data: &[u8]) -> Result<bool, DeviceError> {
    state(|state| write_transport(state, addr, data))
}

fn write_transport(state: &mut State, addr: u64, data: &[u8]) -> Result<bool, DeviceError> {
    let generation = state.mmio.reset_generation();
    let bell = state.mmio.write(addr, data).map_err(DeviceError::from)?;
    if generation != state.mmio.reset_generation() {
        reset_transport(state);
    }
    super::worker::set_transport_ready(state.mmio.status() & DRIVER_OK != 0);
    Ok(bell.is_some())
}

pub fn queue_notify(queue: u32) -> Result<bool, DeviceError> {
    if super::CLOSED.load(std::sync::atomic::Ordering::Acquire) {
        return Err(DeviceError::NotReady);
    }
    let queue = usize::try_from(queue).map_err(|_| DeviceError::BadQueue)?;
    if queue >= 3 {
        return Err(DeviceError::BadQueue);
    }
    state(|state| {
        if queue < state.pending.len() {
            state.pending[queue] = true;
        }
        Ok(false)
    })
}

pub fn process_pending() -> Result<bool, DeviceError> {
    state(|state| {
        let mut more = false;
        let received = state.pending[TX];
        if received {
            state.pending[TX] = process_tx(state)?;
            more |= state.pending[TX];
        }
        if received {
            state.pending[RX] = true;
        }
        if state.pending[RX] {
            state.pending[RX] = process_rx(state)?;
            more |= state.pending[RX];
        }
        Ok(more)
    })
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
    if !super::CLOSED.load(std::sync::atomic::Ordering::Acquire) {
        let _ = configure();
        *super::switch() = terra_vsock_device::VsockSwitch::new();
    }
}
pub fn close() {
    super::CLOSED.store(true, std::sync::atomic::Ordering::Release);
    super::worker::set_transport_ready(false);
    if let Ok(mut state) = STATE.lock() {
        *state = None;
    }
    publish_interrupt_level(false);
    *super::switch() = terra_vsock_device::VsockSwitch::new();
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESPONSE: u16 = 2;
    const RESET: u16 = 3;

    fn request(port: u32, source: u32) -> VsockHeader {
        VsockHeader {
            src_cid: terra_vsock_device::GUEST_CID,
            dst_cid: terra_vsock_device::HOST_CID,
            src_port: source,
            dst_port: port,
            len: 0,
            type_: 1,
            op: 1,
            flags: 0,
            buf_alloc: terra_vsock_device::RX_ALLOC,
            fwd_cnt: 0,
        }
    }

    #[test]
    fn header_only_rx_completes_without_consuming_the_reply() {
        let payload = b"x";
        assert_eq!(rx_used_len(VSOCK_HEADER_BYTES, payload), Some(0));
        assert_eq!(payload, b"x");
        assert_eq!(rx_used_len(VSOCK_HEADER_BYTES + 1, payload), None);
    }

    #[test]
    fn guest_status_reset_keeps_lifecycle_policy() {
        let _guard = crate::SWITCH_TEST_LOCK.lock().unwrap();
        super::super::CLOSED.store(false, std::sync::atomic::Ordering::Release);
        *super::super::switch() = terra_vsock_device::VsockSwitch::new();
        let mut state = State {
            mmio: MmioTransport::new(
                0,
                0x200,
                4096,
                19,
                1 << 32,
                QUEUE_SIZE,
                terra_vsock_device::GUEST_CID.to_le_bytes().to_vec(),
            )
            .with_queue_count(3),
            next: [0; 2],
            pending_rx: None,
            pending: [false; 2],
        };
        write_transport(&mut state, 0x70, &0_u32.to_le_bytes()).unwrap();
        super::super::switch().rx(
            &request(terra_vsock_device::DIAGNOSTIC_VSOCK_PORT, 100),
            &[],
        );
        assert_eq!(super::super::switch().take_replies()[0].header.op, RESPONSE);

        super::super::switch().rx(&request(terra_vsock_device::CONTROL_VSOCK_PORT, 100), &[]);
        super::super::switch().take_replies();
        write_transport(&mut state, 0x70, &0_u32.to_le_bytes()).unwrap();
        for port in [
            terra_vsock_device::CONTROL_VSOCK_PORT,
            terra_vsock_device::DIAGNOSTIC_VSOCK_PORT,
        ] {
            super::super::switch().rx(&request(port, 101), &[]);
        }
        assert!(
            super::super::switch()
                .take_replies()
                .iter()
                .all(|reply| reply.header.op == RESET)
        );
    }
}
