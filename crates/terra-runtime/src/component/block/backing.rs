//! Host disk capabilities for the Wasm block device.

use crate::BoundedDisk;
pub const STATUS_OK: u8 = 0;
#[cfg(feature = "test-support")]
#[path = "reference.rs"]
mod reference;
#[cfg(feature = "test-support")]
pub use reference::*;

/// Host storage operations exposed to the block component.
pub trait BlockBacking {
    fn capacity(&self) -> u64;
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BackingError>;
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), BackingError>;
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
            crate::DiskError::ReadOnly => BackingError::ReadOnly,
            _ => BackingError::OutOfRange,
        })
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
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(!readonly)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(std::io::Error::other(
                "block backing must be a regular file",
            ));
        }
        let capacity = metadata.len();
        Ok(Self {
            file,
            capacity,
            readonly,
        })
    }
}

#[cfg(unix)]
impl BlockBacking for FileDisk {
    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BackingError> {
        use std::os::unix::fs::FileExt as _;
        self.check_range(offset, buf.len())?;
        self.file
            .read_exact_at(buf, offset)
            .map_err(|_| BackingError::Io)?;
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), BackingError> {
        use std::os::unix::fs::FileExt as _;
        if self.readonly {
            return Err(BackingError::ReadOnly);
        }
        self.check_range(offset, buf.len())?;
        self.file
            .write_all_at(buf, offset)
            .map_err(|_| BackingError::Io)
    }

    fn sync(&self) -> Result<(), BackingError> {
        self.file.sync_all().map_err(|_| BackingError::Io)?;
        Ok(())
    }
}

#[cfg(windows)]
impl BlockBacking for FileDisk {
    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BackingError> {
        use std::os::windows::fs::FileExt as _;
        self.check_range(offset, buf.len())?;
        let mut done = 0;
        while done < buf.len() {
            let at = offset
                .checked_add(u64::try_from(done).map_err(|_| BackingError::Io)?)
                .ok_or(BackingError::Io)?;
            match self.file.seek_read(&mut buf[done..], at) {
                Ok(0) => return Err(BackingError::Io),
                Ok(len) => done += len,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(BackingError::Io),
            }
        }
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), BackingError> {
        use std::os::windows::fs::FileExt as _;
        if self.readonly {
            return Err(BackingError::ReadOnly);
        }
        self.check_range(offset, buf.len())?;
        let mut done = 0;
        while done < buf.len() {
            let at = offset
                .checked_add(u64::try_from(done).map_err(|_| BackingError::Io)?)
                .ok_or(BackingError::Io)?;
            match self.file.seek_write(&buf[done..], at) {
                Ok(0) => return Err(BackingError::Io),
                Ok(len) => done += len,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(BackingError::Io),
            }
        }
        Ok(())
    }

    fn sync(&self) -> Result<(), BackingError> {
        self.file.sync_all().map_err(|_| BackingError::Io)
    }
}

#[cfg(any(unix, windows))]
impl FileDisk {
    fn check_range(&self, offset: u64, len: usize) -> Result<(), BackingError> {
        let len = u64::try_from(len).map_err(|_| BackingError::OutOfRange)?;
        let end = offset.checked_add(len).ok_or(BackingError::OutOfRange)?;
        if end > self.capacity {
            return Err(BackingError::OutOfRange);
        }
        Ok(())
    }
}
