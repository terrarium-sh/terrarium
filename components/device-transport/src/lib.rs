//! Portable modern virtio-MMIO transport state.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::task::{Context, Poll, Waker};

use futures::task::AtomicWaker;
use terra_limits::{
    MAX_BATCH_GUEST_COPY_BYTES, MAX_BATCH_GUEST_COPY_RANGES, MAX_SINGLE_GUEST_COPY_BYTES,
};

/// Coalesced work bits and closure notification for one waiting task.
#[derive(Default)]
pub struct Doorbell {
    bits: AtomicU32,
    closed: AtomicBool,
    waker: AtomicWaker,
}

impl Doorbell {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bits: AtomicU32::new(0),
            closed: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }

    pub fn ring(&self, bits: u32) {
        self.bits.fetch_or(bits, Ordering::Release);
        self.waker.wake();
    }

    /// Returns whether the doorbell was already closed.
    pub fn close(&self) -> bool {
        let was_closed = self.closed.swap(true, Ordering::AcqRel);
        self.waker.wake();
        was_closed
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn reset(&self) {
        self.clear();
        self.closed.store(false, Ordering::Release);
    }

    pub fn clear(&self) {
        self.bits.store(0, Ordering::Release);
    }

    #[must_use]
    pub fn take(&self) -> u32 {
        self.bits.swap(0, Ordering::AcqRel)
    }

    pub fn register(&self, waker: &Waker) {
        self.waker.register(waker);
    }

    pub fn poll_wait(&self, context: &mut Context<'_>) -> Poll<u32> {
        self.register(context.waker());
        let bits = self.take();
        if bits != 0 || self.is_closed() {
            Poll::Ready(bits)
        } else {
            Poll::Pending
        }
    }

    pub async fn wait(&self) -> u32 {
        std::future::poll_fn(|context| self.poll_wait(context)).await
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryCopyError {
    BadLen,
    Unmapped,
    TooLarge,
}

pub fn read_guest_ranges<E: From<MemoryCopyError>>(
    ranges: &[(u64, u64)],
    read: impl Fn(u64, u64) -> Result<Vec<u8>, E>,
    read_batch: impl Fn(&[(u64, u64)]) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, E> {
    let mut total = 0_u64;
    for &(address, len) in ranges {
        address.checked_add(len).ok_or(MemoryCopyError::Unmapped)?;
        total = total.checked_add(len).ok_or(MemoryCopyError::TooLarge)?;
    }
    let capacity = usize::try_from(total).map_err(|_| MemoryCopyError::TooLarge)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| MemoryCopyError::TooLarge)?;
    let mut batch = Vec::new();
    let mut batch_bytes = 0_u64;
    let mut flush = |batch: &mut Vec<(u64, u64)>, batch_bytes: &mut u64| -> Result<(), E> {
        if batch.is_empty() {
            return Ok(());
        }
        let chunk = if batch.len() == 1 {
            read(batch[0].0, batch[0].1)?
        } else {
            read_batch(batch)?
        };
        if u64::try_from(chunk.len()).map_err(|_| MemoryCopyError::TooLarge)? != *batch_bytes {
            return Err(MemoryCopyError::BadLen.into());
        }
        bytes.extend_from_slice(&chunk);
        batch.clear();
        *batch_bytes = 0;
        Ok(())
    };
    for &(mut address, mut remaining) in ranges {
        while remaining != 0 {
            let len = remaining.min(MAX_SINGLE_GUEST_COPY_BYTES);
            if batch.len() == MAX_BATCH_GUEST_COPY_RANGES
                || batch_bytes + len > MAX_BATCH_GUEST_COPY_BYTES
            {
                flush(&mut batch, &mut batch_bytes)?;
            }
            batch.push((address, len));
            batch_bytes += len;
            address += len;
            remaining -= len;
        }
    }
    flush(&mut batch, &mut batch_bytes)?;
    Ok(bytes)
}

pub fn write_guest_ranges<E: From<MemoryCopyError>>(
    ranges: &[(u64, &[u8])],
    write: impl Fn(u64, &[u8]) -> Result<(), E>,
    write_batch: impl Fn(&[(u64, &[u8])]) -> Result<(), E>,
) -> Result<(), E> {
    for &(address, bytes) in ranges {
        address
            .checked_add(u64::try_from(bytes.len()).map_err(|_| MemoryCopyError::TooLarge)?)
            .ok_or(MemoryCopyError::Unmapped)?;
    }
    let mut batch = Vec::new();
    let mut batch_bytes = 0_u64;
    let flush = |batch: &mut Vec<(u64, &[u8])>, batch_bytes: &mut u64| {
        if batch.len() == 1 {
            write(batch[0].0, batch[0].1)?;
        } else if !batch.is_empty() {
            write_batch(batch)?;
        }
        batch.clear();
        *batch_bytes = 0;
        Ok::<(), E>(())
    };
    let chunk_bytes =
        usize::try_from(MAX_SINGLE_GUEST_COPY_BYTES).map_err(|_| MemoryCopyError::TooLarge)?;
    for &(mut address, bytes) in ranges {
        for chunk in bytes.chunks(chunk_bytes) {
            let len = u64::try_from(chunk.len()).map_err(|_| MemoryCopyError::TooLarge)?;
            if batch.len() == MAX_BATCH_GUEST_COPY_RANGES
                || batch_bytes + len > MAX_BATCH_GUEST_COPY_BYTES
            {
                flush(&mut batch, &mut batch_bytes)?;
            }
            batch.push((address, chunk));
            batch_bytes += len;
            address += len;
        }
    }
    flush(&mut batch, &mut batch_bytes)
}

pub fn publish_interrupt_asserted(asserted: bool, publish: impl FnOnce(bool)) {
    if cfg!(target_arch = "wasm32") {
        publish(asserted);
    }
}

mod status {
    pub const RESET: u8 = 0;
    pub const ACKNOWLEDGE: u8 = 1;
    pub const DRIVER: u8 = 2;
    pub const DRIVER_OK: u8 = 4;
    pub const FEATURES_OK: u8 = 8;
    pub const DEVICE_NEEDS_RESET: u8 = 64;
    pub const FAILED: u8 = 128;
}

pub const MAGIC: u32 = 0x7472_6976;
pub const VERSION: u32 = 2;
pub const VENDOR_ID: u32 = 0x5445_5252;
pub const INT_USED_BUFFER: u32 = 1;
pub const REGION_BYTES: u64 = 0x200;

#[macro_export]
macro_rules! device_error {
    ($output:ident) => {
        impl From<$crate::MmioError> for $output {
            fn from(error: $crate::MmioError) -> Self {
                $crate::device_error!(error, $output)
            }
        }
        impl From<$crate::SplitRingError> for $output {
            fn from(error: $crate::SplitRingError) -> Self {
                match error {
                    $crate::SplitRingError::BadDescriptor => Self::BadLen,
                    $crate::SplitRingError::ChainTooLong => Self::TooLarge,
                }
            }
        }
        impl From<$crate::MemoryCopyError> for $output {
            fn from(error: $crate::MemoryCopyError) -> Self {
                match error {
                    $crate::MemoryCopyError::BadLen => Self::BadLen,
                    $crate::MemoryCopyError::Unmapped => Self::Unmapped,
                    $crate::MemoryCopyError::TooLarge => Self::TooLarge,
                }
            }
        }
    };
    ($error:expr, $output:ident) => {
        match $error {
            $crate::MmioError::Unmapped => $output::Unmapped,
            $crate::MmioError::BadQueue => $output::BadQueue,
            $crate::MmioError::NotReady => $output::NotReady,
            $crate::MmioError::BadLen
            | $crate::MmioError::Unaligned
            | $crate::MmioError::BadFeatures
            | $crate::MmioError::BadStatus
            | $crate::MmioError::ReadOnly => $output::BadLen,
        }
    };
}

/// Defines `read_guest_memory` and `write_guest_memory` over the invoking
/// component's `terra::host::memory` bindings.
// WIT bindings belong to the invoking component.
#[allow(clippy::crate_in_macro_def)]
#[macro_export]
macro_rules! guest_memory {
    ($error:ident) => {
        fn read_guest_memory(ranges: &[(u64, u64)]) -> Result<Vec<u8>, $error> {
            use crate::terra::host::memory;
            $crate::read_guest_ranges(
                ranges,
                |address, len| memory::read(address, len).map_err(|_| $error::Unmapped),
                |ranges| {
                    let ranges = ranges
                        .iter()
                        .map(|&(offset, len)| memory::ReadRange { offset, len })
                        .collect::<Vec<_>>();
                    memory::read_ranges(&ranges).map_err(|_| $error::Unmapped)
                },
            )
        }

        fn write_guest_memory(ranges: &[(u64, &[u8])]) -> Result<(), $error> {
            use crate::terra::host::memory;
            $crate::write_guest_ranges(
                ranges,
                |address, bytes| memory::write(address, bytes).map_err(|_| $error::Unmapped),
                |ranges| {
                    let ranges = ranges
                        .iter()
                        .map(|&(offset, data)| memory::WriteRange {
                            offset,
                            data: data.to_vec(),
                        })
                        .collect::<Vec<_>>();
                    memory::write_ranges(&ranges).map_err(|_| $error::Unmapped)
                },
            )
        }
    };
}

/// Adapts a device's operations to its generated WIT request and reply types.
// WIT bindings and stream constructors belong to the invoking component.
#[allow(clippy::crate_in_macro_def)]
#[macro_export]
macro_rules! mmio_device {
    ($error:ident, $read:path, $write:path, $reset:path, $close:path, $interrupt:path) => {
        use crate::terra::mmio::types::{Operation, Reply, Request};

        async fn handle(request: Request) -> (Reply, bool) {
            let terminal = matches!(request.operation, Operation::Close);
            let result: Result<u64, $error> = match request.operation {
                Operation::Read => $read(request.offset, request.width),
                Operation::Write => {
                    $write(request.offset, request.width, request.value).map(|()| 0)
                }
                Operation::Reset => {
                    $reset();
                    Ok(0)
                }
                Operation::Close => $close().await.map(|_| 0),
                Operation::InterruptLevel => Ok(u64::from($interrupt())),
            };
            let (value, error) = match result {
                Ok(value) => (value, None),
                Err(error) => (0, Some(error)),
            };
            (
                Reply {
                    sequence: request.sequence,
                    value,
                    error,
                    interrupt: $interrupt(),
                },
                terminal,
            )
        }

        pub async fn serve(
            requests: wit_bindgen::StreamReader<Request>,
        ) -> wit_bindgen::StreamReader<Reply> {
            let (mut writer, reader) = crate::wit_stream::new::<Reply>();
            wit_bindgen::spawn_local(async move {
                let mut requests = requests;
                while let Some(request) = requests.next().await {
                    let (reply, terminal) = handle(request).await;
                    if writer.write_one(reply).await.is_some() || terminal {
                        break;
                    }
                }
            });
            reader
        }
    };
}

#[must_use]
fn count_pending_queue_entries(next: u16, available: u16, size: u16) -> Option<u16> {
    let count = available.wrapping_sub(next);
    (size != 0 && count <= size).then_some(count)
}

pub fn resync_pending_queue_entries(next: &mut u16, available: u16, size: u16) -> u16 {
    count_pending_queue_entries(*next, available, size).unwrap_or_else(|| {
        *next = available;
        0
    })
}

/// Returns the published available index and the next descriptor head.
pub fn read_split_ring_available<E: From<MmioError>>(
    available_ring: u64,
    size: core::num::NonZeroU16,
    next: &mut u16,
    read: impl Fn(u64, u64) -> Result<Vec<u8>, E>,
) -> Result<(u16, Option<u16>), E> {
    let available = read_ring_index(ring_address(available_ring, 2)?, &read)?;
    if resync_pending_queue_entries(next, available, size.get()) == 0 {
        return Ok((available, None));
    }
    let offset = 4 + u64::from(*next % size) * 2;
    read_ring_index(ring_address(available_ring, offset)?, &read)
        .map(|head| (available, Some(head)))
}

pub fn complete_split_ring_entry<E: From<MmioError>>(
    used_ring: u64,
    size: core::num::NonZeroU16,
    head: u16,
    len: u32,
    read: impl Fn(u64, u64) -> Result<Vec<u8>, E>,
    write: impl Fn(u64, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let index = read_ring_index(ring_address(used_ring, 2)?, &read)?;
    let slot = ring_address(used_ring, 4 + u64::from(index % size) * 8)?;
    let mut entry = [0; 8];
    entry[..4].copy_from_slice(&u32::from(head).to_le_bytes());
    entry[4..].copy_from_slice(&len.to_le_bytes());
    write(slot, &entry)?;
    write(
        ring_address(used_ring, 2)?,
        &index.wrapping_add(1).to_le_bytes(),
    )
}

fn ring_address(base: u64, offset: u64) -> Result<u64, MmioError> {
    base.checked_add(offset).ok_or(MmioError::Unmapped)
}

pub const SPLIT_RING_DESCRIPTOR_BYTES: usize = 16;
pub const SPLIT_RING_DESC_F_NEXT: u16 = 1;
pub const SPLIT_RING_DESC_F_WRITE: u16 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitRingDescriptor {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplitRingError {
    BadDescriptor,
    ChainTooLong,
}

pub fn split_ring_chain(
    table: &[u8],
    mut index: u16,
    size: u16,
    max_descriptors: usize,
    allowed_flags: u16,
) -> Result<Vec<SplitRingDescriptor>, SplitRingError> {
    if size == 0 || max_descriptors == 0 {
        return Err(SplitRingError::BadDescriptor);
    }
    let mut chain = Vec::with_capacity(max_descriptors);
    let mut visited = vec![false; usize::from(size)];
    for _ in 0..max_descriptors {
        if index >= size || visited[usize::from(index)] {
            return Err(SplitRingError::BadDescriptor);
        }
        visited[usize::from(index)] = true;
        let offset = usize::from(index) * SPLIT_RING_DESCRIPTOR_BYTES;
        let bytes = table
            .get(offset..offset + SPLIT_RING_DESCRIPTOR_BYTES)
            .ok_or(SplitRingError::BadDescriptor)?;
        let flags = u16::from_le_bytes(
            bytes[12..14]
                .try_into()
                .map_err(|_| SplitRingError::BadDescriptor)?,
        );
        if flags & !allowed_flags != 0 {
            return Err(SplitRingError::BadDescriptor);
        }
        let descriptor = SplitRingDescriptor {
            addr: u64::from_le_bytes(
                bytes[..8]
                    .try_into()
                    .map_err(|_| SplitRingError::BadDescriptor)?,
            ),
            len: u32::from_le_bytes(
                bytes[8..12]
                    .try_into()
                    .map_err(|_| SplitRingError::BadDescriptor)?,
            ),
            flags,
            next: u16::from_le_bytes(
                bytes[14..]
                    .try_into()
                    .map_err(|_| SplitRingError::BadDescriptor)?,
            ),
        };
        let has_next = descriptor.flags & SPLIT_RING_DESC_F_NEXT != 0;
        chain.push(descriptor);
        if !has_next {
            return Ok(chain);
        }
        if descriptor.next >= size || visited[usize::from(descriptor.next)] {
            return Err(SplitRingError::BadDescriptor);
        }
        index = descriptor.next;
    }
    Err(SplitRingError::ChainTooLong)
}

const MAGIC_VALUE: u64 = 0x000;
const REG_VERSION: u64 = 0x004;
const DEVICE_ID: u64 = 0x008;
const VENDOR: u64 = 0x00c;
const HOST_FEATURES: u64 = 0x010;
const HOST_FEATURES_SEL: u64 = 0x014;
const GUEST_FEATURES: u64 = 0x020;
const GUEST_FEATURES_SEL: u64 = 0x024;
const QUEUE_SEL: u64 = 0x030;
const QUEUE_NUM_MAX: u64 = 0x034;
const QUEUE_NUM: u64 = 0x038;
const QUEUE_READY: u64 = 0x044;
const QUEUE_NOTIFY: u64 = 0x050;
const INTERRUPT_STATUS: u64 = 0x060;
const INTERRUPT_ACK: u64 = 0x064;
const REG_STATUS: u64 = 0x070;
const QUEUE_DESC_LOW: u64 = 0x080;
const QUEUE_DESC_HIGH: u64 = 0x084;
const QUEUE_AVAIL_LOW: u64 = 0x090;
const QUEUE_AVAIL_HIGH: u64 = 0x094;
const QUEUE_USED_LOW: u64 = 0x0a0;
const QUEUE_USED_HIGH: u64 = 0x0a4;
const CONFIG_GENERATION: u64 = 0x0fc;
const CONFIG_BASE: u64 = 0x100;
const MAX_QUEUE_SIZE: u16 = 32_768;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    None,
    QueueNotify(u16),
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmioError {
    Unmapped,
    BadLen,
    Unaligned,
    BadFeatures,
    BadStatus,
    BadQueue,
    NotReady,
    ReadOnly,
}

#[derive(Clone, Copy, Default)]
struct QueueRegs {
    num: u16,
    ready: bool,
    desc: u64,
    avail: u64,
    used: u64,
}

/// A device's modern virtio-MMIO state.
pub struct MmioTransport {
    ram_size: u64,
    device_id: u32,
    host_features: u64,
    guest_features: u64,
    feature_sel: u32,
    status: u8,
    queue_max: u16,
    selected: usize,
    queues: Vec<QueueRegs>,
    interrupt_status: u32,
    irq_level: bool,
    irq_dirty: bool,
    config: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct QueueEntry {
    pub head: u16,
    pub descriptor_table: u64,
    pub available_ring: u64,
    pub used_ring: u64,
    pub size: u16,
}

pub fn read_ring_index<E: From<MmioError>>(
    address: u64,
    read: impl FnOnce(u64, u64) -> Result<Vec<u8>, E>,
) -> Result<u16, E> {
    Ok(u16::from_le_bytes(
        read(address, 2)?
            .try_into()
            .map_err(|_| MmioError::BadLen)?,
    ))
}

impl MmioTransport {
    #[must_use]
    pub fn new(
        ram_size: u64,
        device_id: u32,
        host_features: u64,
        queue_max: u16,
        config: Vec<u8>,
    ) -> Self {
        Self {
            ram_size,
            device_id,
            host_features,
            guest_features: 0,
            feature_sel: 0,
            status: 0,
            queue_max,
            selected: 0,
            queues: vec![QueueRegs::default()],
            interrupt_status: 0,
            irq_level: false,
            irq_dirty: false,
            config,
        }
    }

    #[must_use]
    pub fn with_queue_count(mut self, count: u16) -> Self {
        self.queues = vec![QueueRegs::default(); usize::from(count.max(1))];
        self
    }
    #[must_use]
    pub fn interrupt_status(&self) -> u32 {
        self.interrupt_status
    }
    #[must_use]
    pub fn negotiated(&self) -> u64 {
        self.guest_features & self.host_features
    }
    #[must_use]
    pub fn queue_addrs_for(&self, queue: usize) -> Option<(u64, u64, u64, u16)> {
        let r = self.queues.get(queue)?;
        r.ready.then_some((r.desc, r.avail, r.used, r.num))
    }
    fn check(offset: u64, width: u8) -> Result<(), MmioError> {
        if !matches!(width, 1 | 2 | 4 | 8) {
            return Err(MmioError::BadLen);
        }
        let end = offset
            .checked_add(u64::from(width))
            .ok_or(MmioError::Unmapped)?;
        if offset >= REGION_BYTES || end > REGION_BYTES {
            return Err(MmioError::Unmapped);
        }
        if !offset.is_multiple_of(4) && offset < CONFIG_BASE {
            return Err(MmioError::Unaligned);
        }
        Ok(())
    }

    pub fn read(&self, offset: u64, width: u8) -> Result<u64, MmioError> {
        Self::check(offset, width)?;
        if offset < CONFIG_BASE && offset != REG_STATUS && width != 4 {
            return Err(MmioError::BadLen);
        }
        let value = match offset {
            MAGIC_VALUE if width == 4 => MAGIC,
            REG_VERSION if width == 4 => VERSION,
            DEVICE_ID if width == 4 => self.device_id,
            VENDOR if width == 4 => VENDOR_ID,
            HOST_FEATURES if width == 4 => self.feature_word(self.host_features)?,
            GUEST_FEATURES if width == 4 => self.feature_word(self.guest_features)?,
            QUEUE_NUM_MAX if width == 4 => u32::from(self.queue_max),
            QUEUE_NUM if width == 4 => u32::from(self.selected_regs().num),
            QUEUE_READY if width == 4 => u32::from(self.selected_regs().ready),
            INTERRUPT_STATUS if width == 4 => self.interrupt_status,
            REG_STATUS if width == 1 || width == 4 => u32::from(self.status),
            CONFIG_GENERATION if width == 4 => 0,
            _ if offset >= CONFIG_BASE => return self.config_read(offset - CONFIG_BASE, width),
            _ => return Err(MmioError::Unmapped),
        };
        Ok(u64::from(value))
    }

    fn feature_word(&self, features: u64) -> Result<u32, MmioError> {
        match self.feature_sel {
            0 => u32::try_from(features & u64::from(u32::MAX)).map_err(|_| MmioError::BadFeatures),
            1 => u32::try_from(features >> 32).map_err(|_| MmioError::BadFeatures),
            _ => Err(MmioError::BadFeatures),
        }
    }
    fn config_read(&self, offset: u64, width: u8) -> Result<u64, MmioError> {
        if !matches!(width, 1 | 2 | 4) {
            return Err(MmioError::BadLen);
        }
        let offset = usize::try_from(offset).map_err(|_| MmioError::Unmapped)?;
        let end = offset
            .checked_add(usize::from(width))
            .ok_or(MmioError::Unmapped)?;
        let bytes = self.config.get(offset..end).ok_or(MmioError::Unmapped)?;
        let mut value = [0; 8];
        value[..bytes.len()].copy_from_slice(bytes);
        Ok(u64::from_le_bytes(value))
    }

    pub fn write(&mut self, offset: u64, width: u8, value: u64) -> Result<WriteOutcome, MmioError> {
        Self::check(offset, width)?;
        let word = u32::try_from(value & u64::from(u32::MAX)).map_err(|_| MmioError::BadLen)?;
        match offset {
            HOST_FEATURES_SEL | GUEST_FEATURES_SEL if width == 4 => {
                let selected = word;
                if selected > 1 {
                    return Err(MmioError::BadFeatures);
                }
                self.feature_sel = selected;
            }
            GUEST_FEATURES if width == 4 => {
                let value = u64::from(word);
                let features = match self.feature_sel {
                    0 => self.guest_features & 0xffff_ffff_0000_0000 | value,
                    1 => self.guest_features & 0xffff_ffff | value << 32,
                    _ => return Err(MmioError::BadFeatures),
                };
                if features & !self.host_features != 0 {
                    return Err(MmioError::BadFeatures);
                }
                self.guest_features = features;
            }
            QUEUE_SEL if width == 4 => {
                let selected = usize::try_from(word).map_err(|_| MmioError::BadQueue)?;
                if selected >= self.queues.len() {
                    return Err(MmioError::BadQueue);
                }
                self.selected = selected;
            }
            QUEUE_NUM if width == 4 => {
                let num = u16::try_from(word).map_err(|_| MmioError::BadQueue)?;
                if self.selected_regs().ready || !valid_queue_size(self.queue_max, num) {
                    return Err(MmioError::BadQueue);
                }
                self.selected_regs_mut()?.num = num;
            }
            QUEUE_READY if width == 4 => match word {
                0 => self.selected_regs_mut()?.ready = false,
                1 => self.arm_queue()?,
                _ => return Err(MmioError::BadQueue),
            },
            QUEUE_NOTIFY if width == 4 => {
                let bell = self.ring_bell(word)?;
                return Ok(WriteOutcome::QueueNotify(bell));
            }
            INTERRUPT_ACK if width == 4 => {
                self.interrupt_status &= !word;
                if self.interrupt_status == 0 {
                    self.set_irq_level(false);
                }
            }
            REG_STATUS if width == 1 || width == 4 => {
                self.status = drive_status(self.status, value.to_le_bytes()[0])?;
                if self.status == 0 || self.status & status::FAILED != 0 {
                    self.reset_device();
                    return Ok(WriteOutcome::Reset);
                }
            }
            QUEUE_DESC_LOW if width == 4 => {
                self.update_addr(|r| &mut r.desc, word, false)?;
            }
            QUEUE_DESC_HIGH if width == 4 => {
                self.update_addr(|r| &mut r.desc, word, true)?;
            }
            QUEUE_AVAIL_LOW if width == 4 => {
                self.update_addr(|r| &mut r.avail, word, false)?;
            }
            QUEUE_AVAIL_HIGH if width == 4 => {
                self.update_addr(|r| &mut r.avail, word, true)?;
            }
            QUEUE_USED_LOW if width == 4 => {
                self.update_addr(|r| &mut r.used, word, false)?;
            }
            QUEUE_USED_HIGH if width == 4 => {
                self.update_addr(|r| &mut r.used, word, true)?;
            }
            _ if offset >= CONFIG_BASE => return Err(MmioError::ReadOnly),
            _ => return Err(MmioError::Unmapped),
        }
        Ok(WriteOutcome::None)
    }

    fn update_addr(
        &mut self,
        field: impl FnOnce(&mut QueueRegs) -> &mut u64,
        value: u32,
        high: bool,
    ) -> Result<(), MmioError> {
        let regs = self.selected_regs_mut()?;
        if regs.ready {
            return Err(MmioError::BadQueue);
        }
        let addr = field(regs);
        *addr = if high {
            *addr & 0xffff_ffff | u64::from(value) << 32
        } else {
            *addr & 0xffff_ffff_0000_0000 | u64::from(value)
        };
        Ok(())
    }
    fn selected_regs(&self) -> QueueRegs {
        self.queues.get(self.selected).copied().unwrap_or_default()
    }
    fn selected_regs_mut(&mut self) -> Result<&mut QueueRegs, MmioError> {
        self.queues
            .get_mut(self.selected)
            .ok_or(MmioError::BadQueue)
    }
    fn ring_bell(&self, value: u32) -> Result<u16, MmioError> {
        let queue = u16::try_from(value).map_err(|_| MmioError::BadQueue)?;
        let regs = self
            .queues
            .get(usize::from(queue))
            .ok_or(MmioError::BadQueue)?;
        if !regs.ready {
            return Err(MmioError::NotReady);
        }
        Ok(queue)
    }
    fn arm_queue(&mut self) -> Result<(), MmioError> {
        let ram_size = self.ram_size;
        let r = self.selected_regs_mut()?;
        let size = u64::from(r.num);
        let rings = [
            (r.desc, size * SPLIT_RING_DESCRIPTOR_BYTES as u64),
            (r.avail, 4 + size * 2),
            (r.used, 4 + size * 8),
        ];
        if r.num == 0
            || rings.into_iter().any(|(addr, len)| {
                addr == 0 || addr.checked_add(len).is_none_or(|end| end > ram_size)
            })
        {
            return Err(MmioError::BadQueue);
        }
        r.ready = true;
        Ok(())
    }
    fn reset_device(&mut self) {
        self.queues.fill(QueueRegs::default());
        self.selected = 0;
        self.guest_features = 0;
        self.interrupt_status = 0;
        self.set_irq_level(false);
    }
    fn set_irq_level(&mut self, level: bool) {
        if self.irq_level != level {
            self.irq_level = level;
            self.irq_dirty = true;
        }
    }
    pub fn signal(&mut self, bit: u32) {
        if self.status & status::FAILED == 0 {
            self.interrupt_status |= bit;
            if self.status & status::DRIVER_OK != 0 {
                self.set_irq_level(true);
            }
        }
    }
    pub fn take_irq(&mut self) -> Option<bool> {
        self.irq_dirty.then(|| {
            self.irq_dirty = false;
            self.irq_level
        })
    }
}

fn valid_queue_size(max: u16, size: u16) -> bool {
    max != 0
        && max <= MAX_QUEUE_SIZE
        && max.is_power_of_two()
        && size != 0
        && size <= max
        && size.is_power_of_two()
}

fn drive_status(current: u8, written: u8) -> Result<u8, MmioError> {
    if written == status::RESET || written == current {
        return Ok(written);
    }
    if current & status::FAILED != 0 || written & status::DEVICE_NEEDS_RESET != 0 {
        return Err(MmioError::BadStatus);
    }
    if written & status::FAILED != 0 {
        return Ok(current | status::FAILED);
    }
    let steps = [
        status::ACKNOWLEDGE,
        status::DRIVER,
        status::FEATURES_OK,
        status::DRIVER_OK,
    ];
    let Some(next) = steps.into_iter().find(|bit| current & bit == 0) else {
        return Err(MmioError::BadStatus);
    };
    (written == current | next)
        .then_some(written)
        .ok_or(MmioError::BadStatus)
}

#[cfg(test)]
mod tests {
    #[test]
    fn corrupt_available_index_resyncs_before_accepting_new_work() {
        let mut next = 4;
        assert_eq!(super::resync_pending_queue_entries(&mut next, 261, 256), 0);
        assert_eq!(next, 261);
        assert_eq!(super::resync_pending_queue_entries(&mut next, 262, 256), 1);
        assert_eq!(next, 261);
        assert_eq!(super::resync_pending_queue_entries(&mut next, 0, 256), 0);
        assert_eq!(next, 0);
    }

    #[test]
    fn split_ring_helpers_advance_available_and_used_entries() {
        let memory = std::cell::RefCell::new(vec![0; 64]);
        let writes = std::cell::RefCell::new(Vec::new());
        memory.borrow_mut()[2..4].copy_from_slice(&1_u16.to_le_bytes());
        memory.borrow_mut()[4..6].copy_from_slice(&7_u16.to_le_bytes());
        let read = |address, len| {
            let address = usize::try_from(address).unwrap();
            let len = usize::try_from(len).unwrap();
            Ok::<_, MmioError>(memory.borrow()[address..address + len].to_vec())
        };
        let mut next = 0;
        let size = core::num::NonZeroU16::new(8).unwrap();
        assert_eq!(
            read_split_ring_available(0, size, &mut next, read),
            Ok((1, Some(7)))
        );
        complete_split_ring_entry(32, size, 7, 12, read, |address, bytes| {
            writes.borrow_mut().push((address, bytes.len()));
            let address = usize::try_from(address).unwrap();
            memory.borrow_mut()[address..address + bytes.len()].copy_from_slice(bytes);
            Ok(())
        })
        .unwrap();
        assert_eq!(*writes.borrow(), [(36, 8), (34, 2)]);
        let memory = memory.borrow();
        assert_eq!(&memory[36..40], &7_u32.to_le_bytes());
        assert_eq!(&memory[40..44], &12_u32.to_le_bytes());
        assert_eq!(&memory[34..36], &1_u16.to_le_bytes());
    }

    #[test]
    fn available_snapshot_handles_wrap_and_resynchronizes_overfull_ring() {
        for (start, available, head, expected_next) in [
            (u16::MAX, 0_u16, Some(7), u16::MAX),
            (0, 9, None, 9),
            (5, 5, None, 5),
        ] {
            let mut next = start;
            let result = read_split_ring_available(
                0,
                core::num::NonZeroU16::new(8).unwrap(),
                &mut next,
                |address, len| {
                    assert_eq!(len, 2);
                    match address {
                        2 => Ok::<_, MmioError>(available.to_le_bytes().to_vec()),
                        18 => Ok(7_u16.to_le_bytes().to_vec()),
                        _ => panic!("unexpected available-ring read"),
                    }
                },
            );
            assert_eq!(result, Ok((available, head)));
            assert_eq!(next, expected_next);
        }
    }

    #[test]
    fn failed_used_entry_write_does_not_publish_completion() {
        for failed_address in [36, 34] {
            let memory = std::cell::RefCell::new(vec![0; 64]);
            let result = complete_split_ring_entry(
                32,
                core::num::NonZeroU16::new(8).unwrap(),
                7,
                12,
                |_, _| Ok(vec![0; 2]),
                |address, bytes| {
                    if address == failed_address {
                        return Err(MmioError::Unmapped);
                    }
                    let address = usize::try_from(address).unwrap();
                    memory.borrow_mut()[address..address + bytes.len()].copy_from_slice(bytes);
                    Ok(())
                },
            );
            assert_eq!(result, Err(MmioError::Unmapped));
            assert_eq!(&memory.borrow()[34..36], &[0; 2]);
        }
        assert_eq!(
            read_ring_index(0, |_, _| Ok::<_, MmioError>(vec![0])),
            Err(MmioError::BadLen)
        );
        assert_eq!(
            read_split_ring_available(
                u64::MAX,
                core::num::NonZeroU16::new(8).unwrap(),
                &mut 0,
                |_, _| panic!("overflow must fail before reading")
            ),
            Err(MmioError::Unmapped)
        );
    }

    #[test]
    fn scalar_mmio_validates_width_and_bounds() {
        let transport = MmioTransport::new(4096, 2, 1, 256, vec![0x11, 0x22, 0x33, 0x44]);
        for (width, value) in [(1, 0x11), (2, 0x2211), (4, 0x4433_2211)] {
            assert_eq!(transport.read(CONFIG_BASE, width), Ok(value));
        }
        for width in [0, 3, 5, 7, 9, 255] {
            assert_eq!(transport.read(0, width), Err(MmioError::BadLen));
        }
        assert_eq!(transport.read(1, 4), Err(MmioError::Unaligned));
        assert_eq!(
            transport.read(REGION_BYTES - 1, 2),
            Err(MmioError::Unmapped)
        );
        assert_eq!(transport.read(u64::MAX, 4), Err(MmioError::Unmapped));
    }

    #[test]
    fn doorbell_coalesces_work_and_wakes_on_ring_and_close() {
        struct WakeCount(std::sync::atomic::AtomicUsize);
        impl std::task::Wake for WakeCount {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let count = std::sync::Arc::new(WakeCount(std::sync::atomic::AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut context = Context::from_waker(&waker);
        let bell = Doorbell::new();
        assert_eq!(bell.poll_wait(&mut context), Poll::Pending);
        bell.ring(1);
        bell.ring(4);
        assert!(count.0.load(Ordering::Relaxed) > 0);
        assert_eq!(bell.poll_wait(&mut context), Poll::Ready(5));
        assert_eq!(bell.poll_wait(&mut context), Poll::Pending);
        let before_close = count.0.load(Ordering::Relaxed);
        assert!(!bell.close());
        assert!(count.0.load(Ordering::Relaxed) > before_close);
        assert_eq!(bell.poll_wait(&mut context), Poll::Ready(0));
        assert!(bell.close());
        bell.reset();
        assert!(!bell.is_closed());
        assert_eq!(bell.poll_wait(&mut context), Poll::Pending);
    }

    #[test]
    fn guest_memory_batches_copies_and_rejects_short_reads() {
        let calls = std::cell::RefCell::new(Vec::new());
        let batch_read = |ranges: &[(u64, u64)]| {
            assert!(ranges.len() <= MAX_BATCH_GUEST_COPY_RANGES);
            let len = ranges.iter().map(|range| range.1).sum::<u64>();
            assert!(len <= MAX_BATCH_GUEST_COPY_BYTES);
            assert!(
                ranges
                    .iter()
                    .all(|range| range.1 <= MAX_SINGLE_GUEST_COPY_BYTES)
            );
            calls.borrow_mut().push(ranges.to_vec());
            Ok::<_, MemoryCopyError>(vec![7; usize::try_from(len).unwrap()])
        };
        let len = MAX_BATCH_GUEST_COPY_BYTES + MAX_SINGLE_GUEST_COPY_BYTES;
        let bytes = read_guest_ranges(
            &[(100, len)],
            |address, len| batch_read(&[(address, len)]),
            batch_read,
        )
        .unwrap();
        assert_eq!(bytes, vec![7; usize::try_from(len).unwrap()]);
        assert_eq!(calls.borrow().len(), 2);
        assert_eq!(
            calls.borrow()[1],
            [(
                100 + MAX_BATCH_GUEST_COPY_BYTES,
                MAX_SINGLE_GUEST_COPY_BYTES
            )]
        );
        for len in [1, MAX_BATCH_GUEST_COPY_BYTES] {
            assert_eq!(
                read_guest_ranges(&[(0, len)], |_, _| Ok(vec![]), |_| Ok(vec![])),
                Err(MemoryCopyError::BadLen)
            );
        }
        assert_eq!(
            read_guest_ranges(
                &[(u64::MAX, 1)],
                |_, _| panic!("overflow must fail before reading"),
                |_| panic!("overflow must fail before reading")
            ),
            Err(MemoryCopyError::Unmapped)
        );
        calls.borrow_mut().clear();
        let ranges = (0..=MAX_BATCH_GUEST_COPY_RANGES)
            .map(|address| (u64::try_from(address).unwrap(), 1))
            .collect::<Vec<_>>();
        read_guest_ranges(
            &ranges,
            |address, len| batch_read(&[(address, len)]),
            batch_read,
        )
        .unwrap();
        assert_eq!(
            calls.borrow().iter().map(Vec::len).collect::<Vec<_>>(),
            [MAX_BATCH_GUEST_COPY_RANGES, 1]
        );
        calls.borrow_mut().clear();
        write_guest_ranges(
            &[(100, &bytes)],
            |address, chunk| {
                calls
                    .borrow_mut()
                    .push(vec![(address, u64::try_from(chunk.len()).unwrap())]);
                Ok::<_, MemoryCopyError>(())
            },
            |ranges| {
                calls.borrow_mut().push(
                    ranges
                        .iter()
                        .map(|&(address, chunk)| (address, u64::try_from(chunk.len()).unwrap()))
                        .collect(),
                );
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls.borrow().len(), 2);
        let failure = write_guest_ranges(
            &[(0, &bytes)],
            |_, _| Err(MemoryCopyError::Unmapped),
            |_| Err(MemoryCopyError::Unmapped),
        );
        assert_eq!(failure, Err(MemoryCopyError::Unmapped));
    }

    #[test]
    fn device_errors_preserve_size_limits() {
        #[derive(Debug, PartialEq, Eq)]
        enum DeviceError {
            Unmapped,
            BadLen,
            BadQueue,
            NotReady,
            TooLarge,
        }
        device_error!(DeviceError);
        assert_eq!(
            DeviceError::from(SplitRingError::BadDescriptor),
            DeviceError::BadLen
        );
        assert_eq!(
            DeviceError::from(SplitRingError::ChainTooLong),
            DeviceError::TooLarge
        );
        assert_eq!(
            DeviceError::from(MemoryCopyError::TooLarge),
            DeviceError::TooLarge
        );
        assert_eq!(
            DeviceError::from(MmioError::NotReady),
            DeviceError::NotReady
        );
    }

    #[test]
    fn pending_entries_handle_wraparound_and_reject_ring_overruns() {
        use super::count_pending_queue_entries;
        assert_eq!(count_pending_queue_entries(4, 4, 256), Some(0));
        assert_eq!(count_pending_queue_entries(4, 260, 256), Some(256));
        assert_eq!(count_pending_queue_entries(u16::MAX - 1, 1, 256), Some(3));
        assert_eq!(count_pending_queue_entries(4, 261, 256), None);
        assert_eq!(count_pending_queue_entries(4, 3, 256), None);
        assert_eq!(count_pending_queue_entries(0, 0, 0), None);
    }

    #[test]
    fn split_ring_chain_rejects_cycles_and_unknown_flags() {
        let mut table = [0_u8; 32];
        table[12..14].copy_from_slice(&SPLIT_RING_DESC_F_NEXT.to_le_bytes());
        table[14..16].copy_from_slice(&1_u16.to_le_bytes());
        table[28..30].copy_from_slice(&SPLIT_RING_DESC_F_NEXT.to_le_bytes());
        assert_eq!(
            split_ring_chain(&table, 0, 2, 2, SPLIT_RING_DESC_F_NEXT),
            Err(SplitRingError::BadDescriptor)
        );
        table[12..14].copy_from_slice(&4_u16.to_le_bytes());
        assert_eq!(
            split_ring_chain(&table, 0, 2, 2, SPLIT_RING_DESC_F_NEXT),
            Err(SplitRingError::BadDescriptor)
        );
    }
    use super::*;

    #[test]
    fn device_status_enforces_sequence_failure_and_reset() {
        for (current, written, expected) in [
            (0, 1, Some(1)),
            (0, 2, None),
            (1, 3, Some(3)),
            (3, 3, Some(3)),
            (3, 15, None),
            (3, 11, Some(11)),
            (11, 15, Some(15)),
            (15, 0, Some(0)),
            (0, 0, Some(0)),
            (1, 65, None),
            (1, 129, Some(129)),
            (129, 3, None),
            (129, 129, Some(129)),
            (129, 0, Some(0)),
            (1, 2, None),
        ] {
            assert_eq!(
                drive_status(current, written).ok(),
                expected,
                "{current} -> {written}"
            );
        }
    }

    #[test]
    fn queue_sizes_match_virtio_queue_rules() {
        for (max, size, valid) in [
            (0, 0, false),
            (3, 1, false),
            (MAX_QUEUE_SIZE + 1, 1, false),
            (256, 0, false),
            (256, 3, false),
            (256, 512, false),
            (256, 1, true),
            (256, 256, true),
            (MAX_QUEUE_SIZE, MAX_QUEUE_SIZE, true),
        ] {
            assert_eq!(valid_queue_size(max, size), valid);
        }
    }

    #[test]
    fn rejected_features_preserve_the_last_valid_selection() {
        let mut transport = MmioTransport::new(4096, 2, 1, 256, vec![]);
        transport
            .write(GUEST_FEATURES, 4, u64::from(1_u32))
            .unwrap();
        assert_eq!(
            transport.write(GUEST_FEATURES, 4, u64::from(2_u32)),
            Err(MmioError::BadFeatures)
        );
        assert_eq!(transport.read(GUEST_FEATURES, 4).unwrap(), 1);
        assert_eq!(
            transport.write(GUEST_FEATURES_SEL, 4, u64::from(2_u32)),
            Err(MmioError::BadFeatures)
        );
        assert_eq!(transport.read(GUEST_FEATURES, 4).unwrap(), 1);
    }

    #[test]
    fn arm_queue_rejects_rings_that_cross_ram_end() {
        let mut transport = MmioTransport::new(10_000, 2, 0, 256, vec![]);
        let size = 128_u16;
        for (desc, avail, used) in [
            (10_000 - u64::from(size) * 16 + 1, 100, 100),
            (100, 10_000 - (4 + u64::from(size) * 2) + 1, 100),
            (100, 100, 10_000 - (4 + u64::from(size) * 8) + 1),
        ] {
            transport.queues[0] = QueueRegs {
                desc,
                avail,
                used,
                num: size,
                ready: false,
            };
            assert_eq!(transport.arm_queue(), Err(MmioError::BadQueue));
        }
    }

    #[test]
    fn arms_notifies_acks_and_resets() {
        let mut transport = MmioTransport::new(0x10_000, 2, 1 << 32, 256, vec![]);
        for status in [1u8, 3, 11, 15] {
            transport.write(0x70, 1, u64::from(status)).unwrap();
        }
        transport.write(0x38, 4, u64::from(128u32)).unwrap();
        for (offset, addr) in [(0x80, 0x1000u32), (0x90, 0x2000), (0xa0, 0x3000)] {
            transport.write(offset, 4, u64::from(addr)).unwrap();
        }
        transport.write(0x44, 4, u64::from(1u32)).unwrap();
        assert_eq!(
            transport.write(0x50, 4, u64::from(0u32)),
            Ok(WriteOutcome::QueueNotify(0))
        );
        transport.signal(INT_USED_BUFFER);
        assert_eq!(transport.take_irq(), Some(true));
        transport
            .write(0x64, 4, u64::from(INT_USED_BUFFER))
            .unwrap();
        assert_eq!(transport.take_irq(), Some(false));
        assert_eq!(transport.write(0x70, 1, 0), Ok(WriteOutcome::Reset));
        assert_eq!(transport.queue_addrs_for(0), None);
    }

    #[test]
    fn write_reports_resets_without_changing_configuration() {
        let config = vec![1, 2, 3, 4];
        for width in [1, 4] {
            let mut transport = MmioTransport::new(0x10_000, 2, 0, 256, config.clone());
            for (status, expected) in [
                (0, Ok(WriteOutcome::Reset)),
                (0, Ok(WriteOutcome::Reset)),
                (1, Ok(WriteOutcome::None)),
                (2, Err(MmioError::BadStatus)),
                (status::FAILED, Ok(WriteOutcome::Reset)),
                (
                    status::ACKNOWLEDGE | status::FAILED,
                    Ok(WriteOutcome::Reset),
                ),
                (3, Err(MmioError::BadStatus)),
                (0, Ok(WriteOutcome::Reset)),
                (1, Ok(WriteOutcome::None)),
            ] {
                assert_eq!(transport.write(0x70, width, u64::from(status)), expected);
                assert_eq!(transport.read(0xfc, 4).unwrap(), 0);
                assert_eq!(transport.read(0x100, 4).unwrap(), 0x0403_0201);
            }
        }
    }

    #[test]
    fn armed_queue_rejects_size_changes() {
        let mut transport = MmioTransport::new(0x10_000, 2, 0, 256, vec![]);
        transport.queues[0] = QueueRegs {
            num: 128,
            desc: 0x1000,
            avail: 0x2000,
            used: 0x3000,
            ready: false,
        };
        transport.arm_queue().unwrap();

        assert_eq!(
            transport.write(QUEUE_NUM, 4, u64::from(256_u32)),
            Err(MmioError::BadQueue)
        );
        assert_eq!(
            transport.queue_addrs_for(0),
            Some((0x1000, 0x2000, 0x3000, 128))
        );
    }

    #[test]
    fn armed_queue_rejects_address_changes() {
        let mut transport = MmioTransport::new(0x10_000, 2, 0, 256, vec![]);
        transport.queues[0] = QueueRegs {
            num: 128,
            desc: 0x1000,
            avail: 0x2000,
            used: 0x3000,
            ready: false,
        };
        transport.arm_queue().unwrap();

        for offset in [
            QUEUE_DESC_LOW,
            QUEUE_DESC_HIGH,
            QUEUE_AVAIL_LOW,
            QUEUE_AVAIL_HIGH,
            QUEUE_USED_LOW,
            QUEUE_USED_HIGH,
        ] {
            assert_eq!(
                transport.write(offset, 4, u64::from(0xffff_ffff_u32)),
                Err(MmioError::BadQueue)
            );
        }
        assert_eq!(
            transport.queue_addrs_for(0),
            Some((0x1000, 0x2000, 0x3000, 128))
        );
    }
}
