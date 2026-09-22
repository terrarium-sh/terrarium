use std::sync::{
    LazyLock, Mutex,
    atomic::{AtomicBool, Ordering},
};

use terra_device_transport::{
    INT_USED_BUFFER, MmioError, MmioTransport, QueueEntry, SPLIT_RING_DESC_F_NEXT,
    SPLIT_RING_DESC_F_WRITE, SPLIT_RING_DESCRIPTOR_BYTES, SplitRingError, split_ring_chain,
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
#[allow(clippy::cast_possible_truncation)]
const MAX_MEMORY_IMPORT_BYTES: usize = terra_limits::MAX_SINGLE_GUEST_COPY_BYTES as usize;

type TxFrame = Result<Vec<u8>, DeviceError>;

struct State {
    mmio: MmioTransport,
    next: [u16; 2],
    pending_tx: bool,
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
    let mut bytes = Vec::with_capacity(capacity);
    let mut offset = 0_u64;
    while offset < len {
        let chunk = (len - offset).min(MAX_MEMORY_IMPORT_BYTES as u64);
        let address = at(addr, offset)?;
        let chunk_bytes =
            super::terra::host::memory::read(address, chunk).map_err(|_| DeviceError::Unmapped)?;
        if chunk_bytes.len() != usize::try_from(chunk).map_err(|_| DeviceError::TooLarge)? {
            return Err(DeviceError::Io);
        }
        bytes.extend(chunk_bytes);
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

fn available(state: &mut State, queue: usize) -> Result<Option<QueueEntry>, DeviceError> {
    state
        .mmio
        .read_queue_entry(queue, &mut state.next[queue], read)
}

fn complete(state: &mut State, queue: usize, head: u16, len: u32) -> Result<(), DeviceError> {
    state
        .mmio
        .complete_queue_entry(queue, &mut state.next[queue], head, len, read, write)?;
    super::terra::host::interrupt::signal();
    Ok(())
}

fn ethernet_frame(mut bytes: Vec<u8>) -> Option<Vec<u8>> {
    if bytes.len() < VIRTIO_NET_HDR_BYTES + 14 {
        return None;
    }
    let header = &bytes[..VIRTIO_NET_HDR_BYTES];
    if header[0] != 0 || header[1] != 0 || header[2..10] != [0; 8] || header[10..12] != [0; 2] {
        return None;
    }
    Some(bytes.split_off(VIRTIO_NET_HDR_BYTES))
}

fn rx_packet(frame: Vec<u8>) -> Result<Vec<u8>, DeviceError> {
    if !(14..=MAX_FRAME).contains(&frame.len()) {
        return Err(DeviceError::BadLen);
    }
    let mut packet = vec![0; VIRTIO_NET_HDR_BYTES];
    packet.extend(frame);
    Ok(packet)
}

fn read_tx_frame(head: u16, desc: u64, size: u16) -> Result<Vec<u8>, DeviceError> {
    let table = read(desc, u64::from(size) * SPLIT_RING_DESCRIPTOR_BYTES as u64)?;
    let chain = chain(&table, head, size)?;
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
    let mut frame = Vec::with_capacity(length);
    for descriptor in chain {
        frame.extend(read(descriptor.addr, u64::from(descriptor.len))?);
    }
    ethernet_frame(frame).ok_or(DeviceError::BadLen)
}

fn tx_frame(state: &mut State) -> Result<Option<(u16, TxFrame)>, DeviceError> {
    let Some(QueueEntry {
        head,
        descriptor_table: desc,
        size,
        ..
    }) = available(state, TX)?
    else {
        return Ok(None);
    };
    let frame = read_tx_frame(head, desc, size);
    Ok(Some((head, frame)))
}

async fn process_tx() -> Result<bool, DeviceError> {
    let Some((head, frame)) = state(tx_frame)? else {
        return Ok(false);
    };
    if let Ok(frame) = frame {
        let _ = <super::Network as super::Guest>::receive(frame).await;
    }
    state(|state| {
        complete(state, TX, head, 0)?;
        Ok(available(state, TX)?.is_some())
    })
}

fn process_rx() -> Result<bool, DeviceError> {
    state(|state| {
        let Some(QueueEntry {
            head,
            descriptor_table: desc,
            size,
            ..
        }) = available(state, RX)?
        else {
            return Ok(false);
        };
        let Ok(table) = read(desc, u64::from(size) * SPLIT_RING_DESCRIPTOR_BYTES as u64) else {
            complete(state, RX, head, 0)?;
            return Ok(true);
        };
        let Ok(chain) = chain(&table, head, size) else {
            complete(state, RX, head, 0)?;
            return Ok(true);
        };
        if chain
            .iter()
            .any(|descriptor| descriptor.flags & SPLIT_RING_DESC_F_WRITE == 0)
        {
            complete(state, RX, head, 0)?;
            return Ok(true);
        }
        let capacity = chain.iter().try_fold(0usize, |length, descriptor| {
            length.checked_add(descriptor.len as usize)
        });
        let Some(capacity) = capacity.filter(|length| *length <= MAX_TRANSFER) else {
            complete(state, RX, head, 0)?;
            return Ok(true);
        };
        if capacity < VIRTIO_NET_HDR_BYTES + 14 {
            complete(state, RX, head, 0)?;
            return Ok(true);
        }
        let Some(frame) = super::gateway().take_frames(1, MAX_TRANSFER).pop() else {
            return Ok(false);
        };
        let packet = rx_packet(frame)?;
        let mut bytes = packet.as_slice();
        for descriptor in chain {
            let amount = bytes.len().min(descriptor.len as usize);
            if write(descriptor.addr, &bytes[..amount]).is_err() {
                complete(state, RX, head, 0)?;
                return Ok(true);
            }
            bytes = &bytes[amount..];
            if bytes.is_empty() {
                break;
            }
        }
        if !bytes.is_empty() {
            complete(state, RX, head, 0)?;
            return Ok(true);
        }
        complete(
            state,
            RX,
            head,
            u32::try_from(packet.len()).map_err(|_| DeviceError::TooLarge)?,
        )?;
        Ok(available(state, RX)?.is_some())
    })
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

pub async fn service_queues() -> Result<bool, DeviceError> {
    if CLOSED.load(Ordering::Acquire) {
        return Err(DeviceError::NotReady);
    }
    let pending_tx = state(|state| Ok(state.pending_tx))?;
    let more_tx = if pending_tx {
        process_tx().await?
    } else {
        false
    };
    state(|state| {
        state.pending_tx = more_tx;
        Ok(())
    })?;
    let more_rx = process_rx()?;
    if more_tx || more_rx {
        super::tick();
    }
    Ok(more_tx || more_rx)
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

    #[test]
    fn modern_virtio_net_header_is_removed_and_restored() {
        let ethernet = vec![0xaa; 14];
        let packet = rx_packet(ethernet.clone()).expect("RX framing");
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
    fn unconfigured_queue_defers_work() {
        let mut state = State {
            mmio: MmioTransport::new(0, 0x200, 64 * 1024, 1, 1 << 32, QUEUE_SIZE, vec![0; 8])
                .with_queue_count(2),
            next: [0; 2],
            pending_tx: false,
        };
        assert_eq!(available(&mut state, RX), Ok(None));
    }
}
