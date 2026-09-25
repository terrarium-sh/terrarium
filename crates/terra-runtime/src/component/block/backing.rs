//! Host disk capabilities for the Wasm block device.

use crate::MAX_BATCH_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskError {
    OutOfRange,
    ReadOnly,
    TooLarge,
}

/// One disk grant: fixed capacity with the real read-only mode enforced
/// on every mutation path, mirroring the native WASI wrapper.
pub struct BoundedDisk {
    data: Vec<u8>,
    readonly: bool,
}

impl BoundedDisk {
    #[must_use]
    pub fn new(capacity: usize, readonly: bool) -> Self {
        Self {
            data: vec![0u8; capacity],
            readonly,
        }
    }

    #[must_use]
    pub fn from_readonly_bytes(data: Vec<u8>) -> Self {
        Self {
            data,
            readonly: true,
        }
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    pub fn read(&self, offset: usize, len: usize) -> Result<&[u8], DiskError> {
        let end = offset.checked_add(len).ok_or(DiskError::OutOfRange)?;
        let len_u64 = u64::try_from(len).map_err(|_| DiskError::OutOfRange)?;
        if end > self.data.len() || len_u64 > MAX_BATCH_BYTES {
            return Err(DiskError::OutOfRange);
        }
        Ok(&self.data[offset..end])
    }

    pub fn write(&mut self, offset: usize, buf: &[u8]) -> Result<(), DiskError> {
        if self.readonly {
            return Err(DiskError::ReadOnly);
        }
        let len_u64 = u64::try_from(buf.len()).map_err(|_| DiskError::TooLarge)?;
        if len_u64 > MAX_BATCH_BYTES {
            return Err(DiskError::TooLarge);
        }
        let end = offset.checked_add(buf.len()).ok_or(DiskError::OutOfRange)?;
        if end > self.data.len() {
            return Err(DiskError::OutOfRange);
        }
        self.data[offset..end].copy_from_slice(buf);
        Ok(())
    }
}

/// Host storage operations exposed to the block component.
pub trait BlockBacking {
    fn capacity(&self) -> u64;
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BackingError>;
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), BackingError>;
    fn discard(&mut self, offset: u64, len: u64) -> Result<(), BackingError>;
    fn sync(&self) -> Result<(), BackingError>;
}

/// The one disk grant bound to a component instance. Capacity and
/// read-only enforcement live in these native methods on every path;
/// a check inside the component never constrains it after compromise.
pub enum DiskGrant {
    Mem(BoundedDisk),
    #[cfg(any(unix, windows))]
    File(FileDisk),
}

impl BlockBacking for DiskGrant {
    fn capacity(&self) -> u64 {
        match self {
            Self::Mem(disk) => BlockBacking::capacity(disk),
            #[cfg(any(unix, windows))]
            Self::File(disk) => BlockBacking::capacity(disk),
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BackingError> {
        match self {
            Self::Mem(disk) => BlockBacking::read_at(disk, offset, buf),
            #[cfg(any(unix, windows))]
            Self::File(disk) => BlockBacking::read_at(disk, offset, buf),
        }
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), BackingError> {
        match self {
            Self::Mem(disk) => BlockBacking::write_at(disk, offset, buf),
            #[cfg(any(unix, windows))]
            Self::File(disk) => BlockBacking::write_at(disk, offset, buf),
        }
    }

    fn discard(&mut self, offset: u64, len: u64) -> Result<(), BackingError> {
        match self {
            Self::Mem(disk) => BlockBacking::discard(disk, offset, len),
            #[cfg(any(unix, windows))]
            Self::File(disk) => BlockBacking::discard(disk, offset, len),
        }
    }

    fn sync(&self) -> Result<(), BackingError> {
        match self {
            Self::Mem(disk) => BlockBacking::sync(disk),
            #[cfg(any(unix, windows))]
            Self::File(disk) => BlockBacking::sync(disk),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackingError {
    OutOfRange,
    ReadOnly,
    Io,
}

impl BlockBacking for BoundedDisk {
    fn capacity(&self) -> u64 {
        u64::try_from(self.capacity()).unwrap_or(u64::MAX)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BackingError> {
        let offset = usize::try_from(offset).map_err(|_| BackingError::OutOfRange)?;
        let chunk = self
            .read(offset, buf.len())
            .map_err(|_| BackingError::OutOfRange)?;
        buf.copy_from_slice(chunk);
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), BackingError> {
        let offset = usize::try_from(offset).map_err(|_| BackingError::OutOfRange)?;
        self.write(offset, buf).map_err(|error| match error {
            DiskError::ReadOnly => BackingError::ReadOnly,
            DiskError::OutOfRange | DiskError::TooLarge => BackingError::OutOfRange,
        })
    }

    fn discard(&mut self, offset: u64, len: u64) -> Result<(), BackingError> {
        if self.readonly {
            return Err(BackingError::ReadOnly);
        }
        let offset = usize::try_from(offset).map_err(|_| BackingError::OutOfRange)?;
        let len = usize::try_from(len).map_err(|_| BackingError::OutOfRange)?;
        let end = offset.checked_add(len).ok_or(BackingError::OutOfRange)?;
        self.data
            .get_mut(offset..end)
            .ok_or(BackingError::OutOfRange)?
            .fill(0);
        Ok(())
    }

    fn sync(&self) -> Result<(), BackingError> {
        Ok(())
    }
}

/// File-backed grant: the image opened with its real read-only or
/// read-write mode, capacity fixed at the pre-grown length. There is
/// no resize or truncate path, so a compromised component cannot grow
/// the image through this handle; writes are positional loops that
/// either complete fully or report `Io`.
#[cfg(any(unix, windows))]
pub struct FileDisk {
    file: std::fs::File,
    capacity: u64,
    readonly: bool,
}

#[cfg(any(unix, windows))]
impl FileDisk {
    pub fn open(path: &std::path::Path, readonly: bool) -> std::io::Result<Self> {
        let file = terra_platform::filesystem::open_disk(path, readonly)?;
        let capacity = file.metadata()?.len();
        Ok(Self {
            file,
            capacity,
            readonly,
        })
    }
}

#[cfg(any(unix, windows))]
impl BlockBacking for FileDisk {
    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BackingError> {
        self.check_range(offset, buf.len())?;
        terra_platform::filesystem::read_exact_at(&self.file, offset, buf)
            .map_err(|_| BackingError::Io)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), BackingError> {
        if self.readonly {
            return Err(BackingError::ReadOnly);
        }
        self.check_range(offset, buf.len())?;
        terra_platform::filesystem::write_all_at(&self.file, offset, buf)
            .map_err(|_| BackingError::Io)
    }

    fn discard(&mut self, offset: u64, len: u64) -> Result<(), BackingError> {
        if self.readonly {
            return Err(BackingError::ReadOnly);
        }
        self.check_range_len(offset, len)?;
        terra_platform::filesystem::discard(&self.file, offset, len).map_err(|_| BackingError::Io)
    }

    fn sync(&self) -> Result<(), BackingError> {
        self.file.sync_all().map_err(|_| BackingError::Io)
    }
}

#[cfg(any(unix, windows))]
impl FileDisk {
    fn check_range(&self, offset: u64, len: usize) -> Result<(), BackingError> {
        let len = u64::try_from(len).map_err(|_| BackingError::OutOfRange)?;
        self.check_range_len(offset, len)
    }

    fn check_range_len(&self, offset: u64, len: u64) -> Result<(), BackingError> {
        let end = offset.checked_add(len).ok_or(BackingError::OutOfRange)?;
        if end > self.capacity {
            return Err(BackingError::OutOfRange);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_disk_preserves_bytes_and_refuses_mutation() {
        let mut disk = DiskGrant::Mem(BoundedDisk::from_readonly_bytes(vec![1, 2, 3, 4]));
        let mut bytes = [0; 4];
        assert_eq!(disk.capacity(), 4);
        assert_eq!(disk.read_at(0, &mut bytes), Ok(()));
        assert_eq!(bytes, [1, 2, 3, 4]);
        assert_eq!(disk.write_at(0, &[9]), Err(BackingError::ReadOnly));
        assert_eq!(disk.discard(0, 4), Err(BackingError::ReadOnly));
        assert_eq!(disk.read_at(1, &mut bytes), Err(BackingError::OutOfRange));
        assert_eq!(disk.read_at(0, &mut bytes), Ok(()));
        assert_eq!(bytes, [1, 2, 3, 4]);
    }
}

#[cfg(all(test, any(unix, windows)))]
mod file_tests {
    use super::{BackingError, BlockBacking, FileDisk};

    fn backing_file() -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(4096).unwrap();
        file
    }

    #[test]
    fn file_round_trip_persists_across_reopen() {
        let file = backing_file();
        {
            let mut disk = FileDisk::open(file.path(), false).unwrap();
            disk.write_at(1536, &[0xAB; 512]).unwrap();
            disk.sync().unwrap();
        }
        let disk = FileDisk::open(file.path(), true).unwrap();
        let mut bytes = [0; 512];
        disk.read_at(1536, &mut bytes).unwrap();
        assert_eq!(bytes, [0xAB; 512]);
    }

    #[test]
    fn file_bounds_reject_past_end_and_overflow_without_extending_the_image() {
        let file = backing_file();
        let mut disk = FileDisk::open(file.path(), false).unwrap();
        assert_eq!(disk.capacity(), 4096);
        for offset in [4096, u64::MAX] {
            assert_eq!(
                disk.read_at(offset, &mut [0]),
                Err(BackingError::OutOfRange)
            );
            assert_eq!(disk.write_at(offset, &[1]), Err(BackingError::OutOfRange));
            assert_eq!(disk.discard(offset, 1), Err(BackingError::OutOfRange));
        }
        assert_eq!(file.as_file().metadata().unwrap().len(), 4096);
        file.as_file().set_len(8192).unwrap();
        assert_eq!(disk.capacity(), 4096);
        assert_eq!(disk.write_at(4096, &[1]), Err(BackingError::OutOfRange));
    }

    #[test]
    fn file_readonly_rejects_writes_and_discard() {
        let file = backing_file();
        let mut disk = FileDisk::open(file.path(), true).unwrap();
        assert_eq!(disk.write_at(0, &[1]), Err(BackingError::ReadOnly));
        assert_eq!(disk.discard(0, 512), Err(BackingError::ReadOnly));
        let mut bytes = [1; 512];
        disk.read_at(0, &mut bytes).unwrap();
        assert_eq!(bytes, [0; 512]);
    }
}
