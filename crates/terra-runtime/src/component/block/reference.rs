//! Test-only virtio-blk reference implementation.

use super::{BlockBacking, STATUS_OK};

use crate::component::block::backing::BoundedDisk;
use crate::memory::BoundedMemory;
use crate::{MAX_BATCH_BYTES, MAX_SINGLE_BYTES};
use virtio_bindings::bindings::{virtio_blk as blk, virtio_config as transport};

pub const SECTOR_BYTES: u64 = 512;
pub const ID_BYTES: usize = 20;
pub const STATUS_IOERR: u8 = 1;
pub const STATUS_UNSUPP: u8 = 2;
pub const STATUS_FAILED: u8 = 128;

const OUT_HDR_BYTES: u64 = 16;
const STATUS_BYTES: u64 = 1;
const STATUS_KNOWN: u8 = 1 | 2 | 4 | 8;
const STATUS_ORDER: [u8; 4] = [1, 2, 8, 4];

#[must_use]
pub fn device_features(readonly: bool) -> u64 {
    let mut features = (1u64 << transport::VIRTIO_F_VERSION_1) | (1u64 << blk::VIRTIO_BLK_F_FLUSH);
    if readonly {
        features |= 1u64 << blk::VIRTIO_BLK_F_RO;
    }
    features
}

#[must_use]
pub fn negotiate(driver_features: u64, readonly: bool) -> u64 {
    driver_features & device_features(readonly)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusError {
    BadSequence,
}

pub fn drive_status(current: u8, written: u8) -> Result<u8, StatusError> {
    if written == 0 {
        return Ok(0);
    }
    if written == current {
        return Ok(current);
    }
    if (current & STATUS_FAILED) != 0 {
        return Err(StatusError::BadSequence);
    }
    if (written & STATUS_FAILED) != 0 {
        return Ok(current | STATUS_FAILED);
    }
    if (written & !STATUS_KNOWN) != 0 {
        return Err(StatusError::BadSequence);
    }
    let Some(next) = STATUS_ORDER.iter().find(|bit| (current & *bit) == 0) else {
        return Err(StatusError::BadSequence);
    };
    if written == (current | *next) {
        Ok(written)
    } else {
        Err(StatusError::BadSequence)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkError {
    Malformed,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    pub status: u8,
    pub used_len: u32,
}

#[derive(Debug, Clone)]
pub struct ParsedRequest {
    pub header_addr: u64,
    pub data: Vec<(u64, u32)>,
    pub data_writable: Option<bool>,
    pub total: u64,
    pub status_addr: u64,
}

impl ParsedRequest {
    pub fn walk(chain: &[Descriptor], head: usize, ram_size: u64) -> Result<Self, BlkError> {
        if chain.is_empty() || head >= chain.len() {
            return Err(BlkError::Malformed);
        }
        let mut descriptors = Vec::new();
        let mut index = head;
        let mut complete = false;
        for _ in 0..MAX_CHAIN_DESCRIPTORS {
            let descriptor = *chain.get(index).ok_or(BlkError::Malformed)?;
            if (descriptor.flags & DESC_F_INDIRECT) != 0 {
                return Err(BlkError::Malformed);
            }
            if descriptor
                .addr
                .checked_add(u64::from(descriptor.len))
                .ok_or(BlkError::Malformed)?
                > ram_size
            {
                return Err(BlkError::Malformed);
            }
            let last = (descriptor.flags & DESC_F_NEXT) == 0;
            descriptors.push(descriptor);
            if last {
                complete = true;
                break;
            }
            index = usize::from(descriptor.next);
        }
        if !complete || descriptors.len() < 2 {
            return Err(BlkError::Malformed);
        }
        let header = descriptors[0];
        let status = descriptors[descriptors.len() - 1];
        if (header.flags & DESC_F_WRITE) != 0 || u64::from(header.len) != OUT_HDR_BYTES {
            return Err(BlkError::Malformed);
        }
        if (status.flags & DESC_F_WRITE) == 0 || u64::from(status.len) != STATUS_BYTES {
            return Err(BlkError::Malformed);
        }
        let mut data = Vec::with_capacity(descriptors.len() - 2);
        let mut data_writable = None;
        let mut total: u64 = 0;
        for descriptor in &descriptors[1..descriptors.len() - 1] {
            let writable = (descriptor.flags & DESC_F_WRITE) != 0;
            match data_writable {
                None => data_writable = Some(writable),
                Some(seen) if seen == writable => {}
                Some(_) => return Err(BlkError::Malformed),
            }
            if u64::from(descriptor.len) > MAX_SINGLE_BYTES {
                return Err(BlkError::Malformed);
            }
            total = total
                .checked_add(u64::from(descriptor.len))
                .ok_or(BlkError::Malformed)?;
            data.push((descriptor.addr, descriptor.len));
        }
        if total > MAX_BATCH_BYTES {
            return Err(BlkError::Malformed);
        }
        Ok(Self {
            header_addr: header.addr,
            data,
            data_writable,
            total,
            status_addr: status.addr,
        })
    }
}

pub struct BlockDevice<B = BoundedDisk> {
    backing: B,
    epoch: u64,
    id: [u8; ID_BYTES],
}

impl BlockDevice<BoundedDisk> {
    #[must_use]
    pub fn new(capacity: usize, readonly: bool, id: &[u8]) -> Self {
        Self::with_backing(BoundedDisk::new(capacity, readonly), id)
    }
}

impl<B: BlockBacking> BlockDevice<B> {
    #[must_use]
    pub fn with_backing(backing: B, id: &[u8]) -> Self {
        let mut tag = [0; ID_BYTES];
        let len = id.len().min(ID_BYTES);
        tag[..len].copy_from_slice(&id[..len]);
        Self {
            backing,
            epoch: 0,
            id: tag,
        }
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn reset(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
    }

    pub fn execute(
        &mut self,
        mem: &BoundedMemory<'_>,
        chain: &[Descriptor],
        head: usize,
        ram_size: u64,
        epoch: u64,
    ) -> Result<Completion, BlkError> {
        if epoch != self.epoch {
            return Err(BlkError::Stale);
        }
        let request = ParsedRequest::walk(chain, head, ram_size)?;
        let header = mem
            .read(request.header_addr, OUT_HDR_BYTES)
            .map_err(|_| BlkError::Malformed)?;
        let header: [u8; 16] = header
            .as_slice()
            .try_into()
            .map_err(|_| BlkError::Malformed)?;
        let request_type =
            u32::from_le_bytes(header[0..4].try_into().map_err(|_| BlkError::Malformed)?);
        let sector = u64::from_le_bytes(header[8..16].try_into().map_err(|_| BlkError::Malformed)?);
        let status = match request_type {
            blk::VIRTIO_BLK_T_IN if request.data_writable == Some(true) => {
                self.read_sectors(mem, &request, sector)
            }
            blk::VIRTIO_BLK_T_OUT if request.data_writable == Some(false) => {
                self.write_sectors(mem, &request, sector)
            }
            blk::VIRTIO_BLK_T_FLUSH if request.total == 0 && sector == 0 => self
                .backing
                .sync()
                .map_or(Ok(STATUS_IOERR), |()| Ok(STATUS_OK)),
            blk::VIRTIO_BLK_T_GET_ID
                if request.data_writable == Some(true) && request.total > 0 =>
            {
                self.identify(mem, &request)
            }
            blk::VIRTIO_BLK_T_IN
            | blk::VIRTIO_BLK_T_OUT
            | blk::VIRTIO_BLK_T_FLUSH
            | blk::VIRTIO_BLK_T_GET_ID => return Err(BlkError::Malformed),
            _ => Ok(STATUS_UNSUPP),
        }?;
        mem.write(request.status_addr, &[status])
            .map_err(|_| BlkError::Malformed)?;
        let payload = match request_type {
            blk::VIRTIO_BLK_T_IN if status == STATUS_OK => request.total,
            blk::VIRTIO_BLK_T_GET_ID if status == STATUS_OK => request.total.min(ID_BYTES as u64),
            _ => 0,
        };
        let used_len = u32::try_from(payload + STATUS_BYTES).map_err(|_| BlkError::Malformed)?;
        Ok(Completion { status, used_len })
    }

    fn sector_range(&self, sector: u64, total: u64) -> Option<(u64, u64)> {
        let start = sector.checked_mul(SECTOR_BYTES)?;
        let end = start.checked_add(total)?;
        (total != 0 && total.is_multiple_of(SECTOR_BYTES) && end <= self.backing.capacity())
            .then_some((start, total))
    }

    fn read_sectors(
        &self,
        mem: &BoundedMemory<'_>,
        request: &ParsedRequest,
        sector: u64,
    ) -> Result<u8, BlkError> {
        let Some((mut offset, _)) = self.sector_range(sector, request.total) else {
            return Ok(STATUS_IOERR);
        };
        for &(address, len) in &request.data {
            let len = usize::try_from(len).map_err(|_| BlkError::Malformed)?;
            let mut bytes = vec![0; len];
            if self.backing.read_at(offset, &mut bytes).is_err() {
                return Ok(STATUS_IOERR);
            }
            mem.write(address, &bytes)
                .map_err(|_| BlkError::Malformed)?;
            offset = offset
                .checked_add(u64::try_from(len).map_err(|_| BlkError::Malformed)?)
                .ok_or(BlkError::Malformed)?;
        }
        Ok(STATUS_OK)
    }

    fn write_sectors(
        &mut self,
        mem: &BoundedMemory<'_>,
        request: &ParsedRequest,
        sector: u64,
    ) -> Result<u8, BlkError> {
        let Some((offset, _)) = self.sector_range(sector, request.total) else {
            return Ok(STATUS_IOERR);
        };
        let mut bytes = Vec::new();
        for &(address, len) in &request.data {
            bytes.extend_from_slice(
                &mem.read(address, u64::from(len))
                    .map_err(|_| BlkError::Malformed)?,
            );
        }
        Ok(if self.backing.write_at(offset, &bytes).is_ok() {
            STATUS_OK
        } else {
            STATUS_IOERR
        })
    }

    fn identify(&self, mem: &BoundedMemory<'_>, request: &ParsedRequest) -> Result<u8, BlkError> {
        let mut copied = 0;
        for &(address, len) in &request.data {
            let remaining = ID_BYTES.saturating_sub(copied);
            if remaining == 0 {
                break;
            }
            let len = remaining.min(usize::try_from(len).map_err(|_| BlkError::Malformed)?);
            mem.write(address, &self.id[copied..copied + len])
                .map_err(|_| BlkError::Malformed)?;
            copied += len;
        }
        Ok(STATUS_OK)
    }
}

pub const MAX_CHAIN_DESCRIPTORS: usize = 16;

/// One descriptor in a chain under validation.
#[derive(Debug, Clone, Copy)]
pub struct Descriptor {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

pub const DESC_F_NEXT: u16 = 1;
pub const DESC_F_WRITE: u16 = 2;
pub const DESC_F_INDIRECT: u16 = 4;

impl Descriptor {
    #[must_use]
    pub fn readable(addr: u64, len: u32, next: Option<u16>) -> Self {
        Self {
            addr,
            len,
            flags: next.map_or(0, |_| DESC_F_NEXT),
            next: next.unwrap_or(0),
        }
    }

    #[must_use]
    pub fn writable(addr: u64, len: u32, next: Option<u16>) -> Self {
        Self {
            addr,
            len,
            flags: DESC_F_WRITE | next.map_or(0, |_| DESC_F_NEXT),
            next: next.unwrap_or(0),
        }
    }
}

#[cfg(test)]
#[path = "reference/tests.rs"]
mod tests;
