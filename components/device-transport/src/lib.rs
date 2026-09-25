//! Portable modern virtio-MMIO transport state.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

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
pub const STATUS_FAILED: u8 = status::FAILED;

#[macro_export]
macro_rules! device_error {
    ($error:expr, $output:ident) => {
        match $error {
            $crate::MmioError::Unmapped => $output::Unmapped,
            $crate::MmioError::BadQueue => $output::BadQueue,
            $crate::MmioError::NotReady => $output::NotReady,
            $crate::MmioError::BadLen
            | $crate::MmioError::Unaligned
            | $crate::MmioError::BadFeatures
            | $crate::MmioError::BadStatus(_)
            | $crate::MmioError::ReadOnly => $output::BadLen,
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

        static SERVER_ACTIVE: ::std::sync::atomic::AtomicBool =
            ::std::sync::atomic::AtomicBool::new(false);

        async fn handle(request: Request) -> (Reply, bool) {
            let terminal = matches!(request.operation, Operation::Close);
            let result = match request.operation {
                Operation::Read => matches!(request.width, 1 | 2 | 4 | 8)
                    .then_some(())
                    .ok_or($error::BadLen)
                    .and_then(|_| $read(request.offset, u32::from(request.width)))
                    .and_then(|bytes| {
                        $crate::decode_mmio_value(&bytes, request.width).ok_or($error::BadLen)
                    }),
                Operation::Write => match $crate::encode_mmio_value(request.value, request.width) {
                    Some(bytes) => $write(request.offset, bytes).await.map(|_| 0),
                    None => Err($error::BadLen),
                },
                Operation::Reset => {
                    $reset();
                    Ok(0)
                }
                Operation::Close => $close().await.map(|_| 0),
                Operation::InterruptLevel => Ok(u64::from($interrupt())),
            };
            let (value, error) = match result {
                Ok(value) => (value, 0),
                Err(error) => (
                    0,
                    match error {
                        $error::Unmapped => 1,
                        $error::BadLen => 2,
                        $error::BadQueue => 3,
                        $error::NotReady => 4,
                        $error::TooLarge => 5,
                        $error::Io => 6,
                    },
                ),
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
            requests: wit_bindgen::rt::async_support::StreamReader<Request>,
        ) -> wit_bindgen::rt::async_support::StreamReader<Reply> {
            let (mut writer, reader) = crate::wit_stream::new::<Reply>();
            if SERVER_ACTIVE
                .compare_exchange(
                    false,
                    true,
                    ::std::sync::atomic::Ordering::AcqRel,
                    ::std::sync::atomic::Ordering::Acquire,
                )
                .is_err()
            {
                wit_bindgen::rt::async_support::spawn_local(async move {
                    let _ = writer
                        .write_one(Reply {
                            sequence: 0,
                            value: 0,
                            error: 4,
                            interrupt: $interrupt(),
                        })
                        .await;
                });
            } else {
                wit_bindgen::rt::async_support::spawn_local(async move {
                    struct Active;

                    impl Drop for Active {
                        fn drop(&mut self) {
                            SERVER_ACTIVE.store(false, ::std::sync::atomic::Ordering::Release);
                        }
                    }

                    let _active = Active;
                    let mut requests = requests;
                    while let Some(request) = requests.next().await {
                        let (reply, terminal) = handle(request).await;
                        if writer.write_one(reply).await.is_some() || terminal {
                            break;
                        }
                    }
                });
            }
            reader
        }
    };
}

#[must_use]
pub fn encode_mmio_value(value: u64, width: u8) -> Option<Vec<u8>> {
    matches!(width, 1 | 2 | 4 | 8).then(|| value.to_le_bytes()[..usize::from(width)].to_vec())
}

#[must_use]
pub fn decode_mmio_value(bytes: &[u8], width: u8) -> Option<u64> {
    if !matches!(width, 1 | 2 | 4 | 8) || bytes.len() != usize::from(width) {
        return None;
    }
    let mut value = [0; 8];
    value[..bytes.len()].copy_from_slice(bytes);
    Some(u64::from_le_bytes(value))
}

#[must_use]
pub fn count_pending_queue_entries(next: u16, available: u16, size: u16) -> Option<u16> {
    let count = available.wrapping_sub(next);
    (size != 0 && count <= size).then_some(count)
}

pub fn resync_pending_queue_entries(next: &mut u16, available: u16, size: u16) -> u16 {
    count_pending_queue_entries(*next, available, size).unwrap_or_else(|| {
        *next = available;
        0
    })
}

pub fn read_split_ring_available_head<E>(
    available_ring: u64,
    size: core::num::NonZeroU16,
    next: &mut u16,
    address: impl Fn(u64, u64) -> Result<u64, E>,
    read_u16: impl Fn(u64) -> Result<u16, E>,
) -> Result<Option<u16>, E> {
    let available = read_u16(address(available_ring, 2)?)?;
    if resync_pending_queue_entries(next, available, size.get()) == 0 {
        return Ok(None);
    }
    let offset = 4 + u64::from(*next % size) * 2;
    read_u16(address(available_ring, offset)?).map(Some)
}

pub fn complete_split_ring_entry<E>(
    used_ring: u64,
    size: core::num::NonZeroU16,
    head: u16,
    len: u32,
    address: impl Fn(u64, u64) -> Result<u64, E>,
    read_u16: impl Fn(u64) -> Result<u16, E>,
    write: impl Fn(u64, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let index = read_u16(address(used_ring, 2)?)?;
    let slot = address(used_ring, 4 + u64::from(index % size) * 8)?;
    write(slot, &u32::from(head).to_le_bytes())?;
    write(address(slot, 4)?, &len.to_le_bytes())?;
    write(address(used_ring, 2)?, &index.wrapping_add(1).to_le_bytes())
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
pub enum StatusError {
    BadSequence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmioError {
    Unmapped,
    BadLen,
    Unaligned,
    BadFeatures,
    BadStatus(StatusError),
    BadQueue,
    NotReady,
    ReadOnly,
}

fn word(bytes: &[u8]) -> Result<u32, MmioError> {
    bytes
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| MmioError::BadLen)
}

#[derive(Clone, Copy, Default)]
struct QueueRegs {
    num: u16,
    ready: bool,
    desc: u64,
    avail: u64,
    used: u64,
}

/// A device's complete modern virtio-MMIO state. It stores no host pointers,
/// file descriptors, or RAM mappings.
pub struct MmioTransport {
    base: u64,
    size: u64,
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
    reset_generation: u64,
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

fn read_ring_index<E: From<MmioError>>(
    address: u64,
    read: &impl Fn(u64, u64) -> Result<Vec<u8>, E>,
) -> Result<u16, E> {
    Ok(u16::from_le_bytes(
        read(address, 2)?
            .try_into()
            .map_err(|_| MmioError::BadLen)?,
    ))
}

impl MmioTransport {
    pub fn read_queue_entry<E: From<MmioError>>(
        &self,
        queue: usize,
        next: &mut u16,
        read: impl Fn(u64, u64) -> Result<Vec<u8>, E>,
    ) -> Result<Option<QueueEntry>, E> {
        let Some((descriptor_table, available_ring, used_ring, size)) = self.queue_addrs_for(queue)
        else {
            return Ok(None);
        };
        let ring_size = core::num::NonZeroU16::new(size).ok_or(MmioError::BadLen)?;
        let head = read_split_ring_available_head(
            available_ring,
            ring_size,
            next,
            |base, offset| {
                base.checked_add(offset)
                    .ok_or_else(|| MmioError::Unmapped.into())
            },
            |address| read_ring_index(address, &read),
        )?;
        Ok(head.map(|head| QueueEntry {
            head,
            descriptor_table,
            available_ring,
            used_ring,
            size,
        }))
    }

    pub fn complete_queue_entry<E: From<MmioError>>(
        &mut self,
        queue: usize,
        next: &mut u16,
        head: u16,
        len: u32,
        read: impl Fn(u64, u64) -> Result<Vec<u8>, E>,
        write: impl Fn(u64, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let (_, _, used, size) = self.queue_addrs_for(queue).ok_or(MmioError::NotReady)?;
        complete_split_ring_entry(
            used,
            core::num::NonZeroU16::new(size).ok_or(MmioError::BadLen)?,
            head,
            len,
            |base, offset| {
                base.checked_add(offset)
                    .ok_or_else(|| MmioError::Unmapped.into())
            },
            |address| read_ring_index(address, &read),
            write,
        )?;
        *next = next.wrapping_add(1);
        self.signal(INT_USED_BUFFER);
        Ok(())
    }

    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base: u64,
        size: u64,
        ram_size: u64,
        device_id: u32,
        host_features: u64,
        queue_max: u16,
        config: Vec<u8>,
    ) -> Self {
        Self {
            base,
            size,
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
            reset_generation: 0,
            config,
        }
    }

    #[must_use]
    pub fn with_queue_count(mut self, count: u16) -> Self {
        self.queues = vec![QueueRegs::default(); usize::from(count.max(1))];
        self
    }
    #[must_use]
    pub fn status(&self) -> u8 {
        self.status
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
    #[must_use]
    pub fn reset_generation(&self) -> u64 {
        self.reset_generation
    }

    fn check(&self, addr: u64, len: usize) -> Result<u64, MmioError> {
        let len = u64::try_from(len).map_err(|_| MmioError::BadLen)?;
        let end = addr.checked_add(len).ok_or(MmioError::Unmapped)?;
        let limit = self
            .base
            .checked_add(self.size)
            .ok_or(MmioError::Unmapped)?;
        if addr < self.base || addr >= limit || end > limit {
            return Err(MmioError::Unmapped);
        }
        let offset = addr - self.base;
        if !offset.is_multiple_of(4) && offset < CONFIG_BASE {
            return Err(MmioError::Unaligned);
        }
        Ok(offset)
    }

    pub fn read(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, MmioError> {
        let offset = self.check(addr, len)?;
        if offset < CONFIG_BASE && offset != REG_STATUS && len != 4 {
            return Err(MmioError::BadLen);
        }
        let value = match offset {
            MAGIC_VALUE if len == 4 => MAGIC,
            REG_VERSION if len == 4 => VERSION,
            DEVICE_ID if len == 4 => self.device_id,
            VENDOR if len == 4 => VENDOR_ID,
            HOST_FEATURES if len == 4 => self.feature_word(self.host_features)?,
            GUEST_FEATURES if len == 4 => self.feature_word(self.guest_features)?,
            QUEUE_NUM_MAX if len == 4 => u32::from(self.queue_max),
            QUEUE_NUM if len == 4 => u32::from(self.selected_regs().num),
            QUEUE_READY if len == 4 => u32::from(self.selected_regs().ready),
            INTERRUPT_STATUS if len == 4 => self.interrupt_status,
            REG_STATUS if len == 1 || len == 4 => u32::from(self.status),
            CONFIG_GENERATION if len == 4 => 0,
            _ if offset >= CONFIG_BASE => return self.config_read(offset - CONFIG_BASE, len),
            _ => return Err(MmioError::Unmapped),
        };
        Ok(value.to_le_bytes()[..len].to_vec())
    }

    fn feature_word(&self, features: u64) -> Result<u32, MmioError> {
        match self.feature_sel {
            0 => u32::try_from(features & u64::from(u32::MAX)).map_err(|_| MmioError::BadFeatures),
            1 => u32::try_from(features >> 32).map_err(|_| MmioError::BadFeatures),
            _ => Err(MmioError::BadFeatures),
        }
    }
    fn config_read(&self, offset: u64, len: usize) -> Result<Vec<u8>, MmioError> {
        if !matches!(len, 1 | 2 | 4) {
            return Err(MmioError::BadLen);
        }
        let offset = usize::try_from(offset).map_err(|_| MmioError::Unmapped)?;
        let end = offset.checked_add(len).ok_or(MmioError::Unmapped)?;
        self.config
            .get(offset..end)
            .map(<[u8]>::to_vec)
            .ok_or(MmioError::Unmapped)
    }

    pub fn write(&mut self, addr: u64, data: &[u8]) -> Result<Option<u16>, MmioError> {
        let offset = self.check(addr, data.len())?;
        match offset {
            HOST_FEATURES_SEL | GUEST_FEATURES_SEL if data.len() == 4 => {
                let selected = word(data)?;
                if selected > 1 {
                    return Err(MmioError::BadFeatures);
                }
                self.feature_sel = selected;
            }
            GUEST_FEATURES if data.len() == 4 => {
                let value = u64::from(word(data)?);
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
            QUEUE_SEL if data.len() == 4 => {
                let selected = usize::try_from(word(data)?).map_err(|_| MmioError::BadQueue)?;
                if selected >= self.queues.len() {
                    return Err(MmioError::BadQueue);
                }
                self.selected = selected;
            }
            QUEUE_NUM if data.len() == 4 => {
                let num = u16::try_from(word(data)?).map_err(|_| MmioError::BadQueue)?;
                if self.selected_regs().ready || !valid_queue_size(self.queue_max, num) {
                    return Err(MmioError::BadQueue);
                }
                self.selected_regs_mut()?.num = num;
            }
            QUEUE_READY if data.len() == 4 => match word(data)? {
                0 => self.selected_regs_mut()?.ready = false,
                1 => self.arm_queue()?,
                _ => return Err(MmioError::BadQueue),
            },
            QUEUE_NOTIFY if data.len() == 4 => {
                let bell = self.ring_bell(data)?;
                return Ok(Some(bell));
            }
            INTERRUPT_ACK if data.len() == 4 => {
                self.interrupt_status &= !word(data)?;
                if self.interrupt_status == 0 {
                    self.set_irq_level(false);
                }
            }
            REG_STATUS if data.len() == 1 || data.len() == 4 => {
                self.status = drive_status(self.status, data[0])?;
                if self.status == 0 || self.status & status::FAILED != 0 {
                    self.reset_device();
                }
            }
            QUEUE_DESC_LOW if data.len() == 4 => {
                self.update_addr(|r| &mut r.desc, word(data)?, false)?;
            }
            QUEUE_DESC_HIGH if data.len() == 4 => {
                self.update_addr(|r| &mut r.desc, word(data)?, true)?;
            }
            QUEUE_AVAIL_LOW if data.len() == 4 => {
                self.update_addr(|r| &mut r.avail, word(data)?, false)?;
            }
            QUEUE_AVAIL_HIGH if data.len() == 4 => {
                self.update_addr(|r| &mut r.avail, word(data)?, true)?;
            }
            QUEUE_USED_LOW if data.len() == 4 => {
                self.update_addr(|r| &mut r.used, word(data)?, false)?;
            }
            QUEUE_USED_HIGH if data.len() == 4 => {
                self.update_addr(|r| &mut r.used, word(data)?, true)?;
            }
            _ if offset >= CONFIG_BASE => return Err(MmioError::ReadOnly),
            _ => return Err(MmioError::Unmapped),
        }
        Ok(None)
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
    fn ring_bell(&self, data: &[u8]) -> Result<u16, MmioError> {
        let queue = u16::try_from(word(data)?).map_err(|_| MmioError::BadQueue)?;
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
        self.reset_generation = self.reset_generation.wrapping_add(1);
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

pub fn drive_status(current: u8, written: u8) -> Result<u8, MmioError> {
    if written == status::RESET || written == current {
        return Ok(written);
    }
    if current & status::FAILED != 0 || written & status::DEVICE_NEEDS_RESET != 0 {
        return Err(MmioError::BadStatus(StatusError::BadSequence));
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
        return Err(MmioError::BadStatus(StatusError::BadSequence));
    };
    (written == current | next)
        .then_some(written)
        .ok_or(MmioError::BadStatus(StatusError::BadSequence))
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
        memory.borrow_mut()[2..4].copy_from_slice(&1_u16.to_le_bytes());
        memory.borrow_mut()[4..6].copy_from_slice(&7_u16.to_le_bytes());
        let read_u16 = |address| {
            let address = usize::try_from(address).unwrap();
            let memory = memory.borrow();
            Ok::<_, ()>(u16::from_le_bytes(
                memory[address..address + 2].try_into().unwrap(),
            ))
        };
        let mut next = 0;
        assert_eq!(
            super::read_split_ring_available_head(
                0,
                core::num::NonZeroU16::new(8).unwrap(),
                &mut next,
                |base, offset| Ok(base + offset),
                read_u16,
            ),
            Ok(Some(7))
        );
        super::complete_split_ring_entry(
            32,
            core::num::NonZeroU16::new(8).unwrap(),
            7,
            12,
            |base, offset| Ok(base + offset),
            |address| {
                let address = usize::try_from(address).unwrap();
                let memory = memory.borrow();
                Ok::<_, ()>(u16::from_le_bytes(
                    memory[address..address + 2].try_into().unwrap(),
                ))
            },
            |address, bytes| {
                let address = usize::try_from(address).unwrap();
                memory.borrow_mut()[address..address + bytes.len()].copy_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
        let memory = memory.borrow();
        assert_eq!(&memory[36..40], &7_u32.to_le_bytes());
        assert_eq!(&memory[40..44], &12_u32.to_le_bytes());
        assert_eq!(&memory[34..36], &1_u16.to_le_bytes());
    }

    #[test]
    fn mmio_values_validate_width_and_exact_reply_length() {
        let value = 0x8877_6655_4433_2211;
        for (width, bytes) in [
            (1, vec![0x11]),
            (2, vec![0x11, 0x22]),
            (4, vec![0x11, 0x22, 0x33, 0x44]),
            (8, vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
        ] {
            assert_eq!(super::encode_mmio_value(value, width), Some(bytes.clone()));
            let mut expected = [0; 8];
            expected[..bytes.len()].copy_from_slice(&bytes);
            assert_eq!(
                super::decode_mmio_value(&bytes, width),
                Some(u64::from_le_bytes(expected))
            );
            assert_eq!(
                super::decode_mmio_value(&bytes[..bytes.len() - 1], width),
                None
            );
        }
        for width in [0, 3, 5, 7, 9, 255] {
            assert_eq!(super::encode_mmio_value(value, width), None);
            assert_eq!(
                super::decode_mmio_value(&vec![0; usize::from(width)], width),
                None
            );
        }
        assert_eq!(super::decode_mmio_value(&[0; 9], 8), None);
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
        let mut transport = MmioTransport::new(0, 0x200, 4096, 2, 1, 256, vec![]);
        transport
            .write(GUEST_FEATURES, &1_u32.to_le_bytes())
            .unwrap();
        assert_eq!(
            transport.write(GUEST_FEATURES, &2_u32.to_le_bytes()),
            Err(MmioError::BadFeatures)
        );
        assert_eq!(
            transport.read(GUEST_FEATURES, 4).unwrap(),
            1_u32.to_le_bytes()
        );
        assert_eq!(
            transport.write(GUEST_FEATURES_SEL, &2_u32.to_le_bytes()),
            Err(MmioError::BadFeatures)
        );
        assert_eq!(
            transport.read(GUEST_FEATURES, 4).unwrap(),
            1_u32.to_le_bytes()
        );
    }

    #[test]
    fn arm_queue_rejects_rings_that_cross_ram_end() {
        let mut transport = MmioTransport::new(0, 0x200, 10_000, 2, 0, 256, vec![]);
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
        let mut transport = MmioTransport::new(0x1000, 0x200, 0x10_000, 2, 1 << 32, 256, vec![]);
        for status in [1u8, 3, 11, 15] {
            transport.write(0x1070, &[status]).unwrap();
        }
        transport.write(0x1038, &128u32.to_le_bytes()).unwrap();
        for (offset, addr) in [(0x1080, 0x1000u32), (0x1090, 0x2000), (0x10a0, 0x3000)] {
            transport.write(offset, &addr.to_le_bytes()).unwrap();
        }
        transport.write(0x1044, &1u32.to_le_bytes()).unwrap();
        assert_eq!(transport.write(0x1050, &0u32.to_le_bytes()), Ok(Some(0)));
        transport.signal(INT_USED_BUFFER);
        assert_eq!(transport.take_irq(), Some(true));
        transport
            .write(0x1064, &INT_USED_BUFFER.to_le_bytes())
            .unwrap();
        assert_eq!(transport.take_irq(), Some(false));
        transport.write(0x1070, &[0]).unwrap();
        assert_eq!(transport.queue_addrs_for(0), None);
    }

    #[test]
    fn armed_queue_rejects_size_changes() {
        let mut transport = MmioTransport::new(0, 0x200, 0x10_000, 2, 0, 256, vec![]);
        transport.queues[0] = QueueRegs {
            num: 128,
            desc: 0x1000,
            avail: 0x2000,
            used: 0x3000,
            ready: false,
        };
        transport.arm_queue().unwrap();

        assert_eq!(
            transport.write(QUEUE_NUM, &256_u32.to_le_bytes()),
            Err(MmioError::BadQueue)
        );
        assert_eq!(
            transport.queue_addrs_for(0),
            Some((0x1000, 0x2000, 0x3000, 128))
        );
    }

    #[test]
    fn armed_queue_rejects_address_changes() {
        let mut transport = MmioTransport::new(0, 0x200, 0x10_000, 2, 0, 256, vec![]);
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
                transport.write(offset, &0xffff_ffff_u32.to_le_bytes()),
                Err(MmioError::BadQueue)
            );
        }
        assert_eq!(
            transport.queue_addrs_for(0),
            Some((0x1000, 0x2000, 0x3000, 128))
        );
    }
}
