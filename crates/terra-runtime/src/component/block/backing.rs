//! Host disk capabilities for the Wasm block device.

use crate::BoundedDisk;
pub const STATUS_OK: u8 = 0;
#[cfg(any(test, feature = "test-support"))]
#[path = "reference.rs"]
mod reference;
#[cfg(any(test, feature = "test-support"))]
pub use reference::*;

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
            crate::DiskError::ReadOnly => BackingError::ReadOnly,
            _ => BackingError::OutOfRange,
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

#[cfg(any(unix, windows))]
impl BlockBacking for FileDisk {
    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BackingError> {
        self.check_range(offset, buf.len())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt as _;
            self.file
                .read_exact_at(buf, offset)
                .map_err(|_| BackingError::Io)?;
            Ok(())
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt as _;
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
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), BackingError> {
        if self.readonly {
            return Err(BackingError::ReadOnly);
        }
        self.check_range(offset, buf.len())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt as _;
            self.file
                .write_all_at(buf, offset)
                .map_err(|_| BackingError::Io)
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt as _;
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
    }

    fn discard(&mut self, offset: u64, len: u64) -> Result<(), BackingError> {
        if self.readonly {
            return Err(BackingError::ReadOnly);
        }
        self.check_range_len(offset, len)?;
        if len == 0 {
            return Ok(());
        }
        discard_file(&self.file, offset, len).map_err(|_| BackingError::Io)
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

#[cfg(target_os = "linux")]
fn discard_file(file: &std::fs::File, offset: u64, len: u64) -> std::io::Result<()> {
    use rustix::fs::{FallocateFlags, fallocate};

    fallocate(
        file,
        FallocateFlags::PUNCH_HOLE | FallocateFlags::KEEP_SIZE,
        offset,
        len,
    )
    .map_err(std::io::Error::from)
    .or_else(ignore_unsupported)
}

#[cfg(target_os = "macos")]
fn discard_file(file: &std::fs::File, offset: u64, len: u64) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    let block = rustix::fs::fstatvfs(file)
        .map_err(std::io::Error::from)?
        .f_frsize;
    if block == 0 {
        return Err(std::io::Error::other("zero filesystem block size"));
    }
    let end = offset
        .checked_add(len)
        .ok_or_else(|| std::io::Error::other("discard range overflow"))?;
    let offset = offset
        .div_ceil(block)
        .checked_mul(block)
        .ok_or_else(|| std::io::Error::other("discard range overflow"))?;
    let end = end / block * block;
    if end <= offset {
        return Ok(());
    }
    let len = end - offset;
    let offset = libc::off_t::try_from(offset).map_err(std::io::Error::other)?;
    let len = libc::off_t::try_from(len).map_err(std::io::Error::other)?;
    let range = libc::fpunchhole_t {
        fp_flags: 0,
        reserved: 0,
        fp_offset: offset,
        fp_length: len,
    };
    #[allow(unsafe_code)]
    let result = unsafe {
        // SAFETY: `file` owns the descriptor and `range` remains valid for this call.
        libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &range)
    };
    if result == 0 {
        Ok(())
    } else {
        ignore_unsupported(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn discard_file(file: &std::fs::File, offset: u64, len: u64) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{
        FILE_ZERO_DATA_INFORMATION, FSCTL_SET_SPARSE, FSCTL_SET_ZERO_DATA,
    };

    let offset = i64::try_from(offset).map_err(std::io::Error::other)?;
    let end = offset
        .checked_add(i64::try_from(len).map_err(std::io::Error::other)?)
        .ok_or_else(|| std::io::Error::other("discard range overflow"))?;
    let mut returned = 0;
    #[allow(unsafe_code)]
    let sparse = unsafe {
        // SAFETY: `file` owns the handle and FSCTL_SET_SPARSE has no input or output buffer.
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_SPARSE,
            core::ptr::null(),
            0,
            core::ptr::null_mut(),
            0,
            &raw mut returned,
            core::ptr::null_mut(),
        )
    };
    if sparse == 0 {
        return ignore_unsupported(std::io::Error::last_os_error());
    }
    let range = FILE_ZERO_DATA_INFORMATION {
        FileOffset: offset,
        BeyondFinalZero: end,
    };
    #[allow(unsafe_code)]
    let zeroed = unsafe {
        // SAFETY: `file` owns the handle and `range` is a valid input buffer of the stated size.
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_ZERO_DATA,
            (&raw const range).cast(),
            u32::try_from(core::mem::size_of_val(&range)).map_err(std::io::Error::other)?,
            core::ptr::null_mut(),
            0,
            &raw mut returned,
            core::ptr::null_mut(),
        )
    };
    if zeroed == 0 {
        ignore_unsupported(std::io::Error::last_os_error())?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn discard_file(_file: &std::fs::File, _offset: u64, _len: u64) -> std::io::Result<()> {
    Ok(())
}

fn ignore_unsupported(error: std::io::Error) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED};
        if error.raw_os_error().is_some_and(|code| {
            matches!(
                code.cast_unsigned(),
                ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED
            )
        }) {
            return Ok(());
        }
    }
    (error.kind() == std::io::ErrorKind::Unsupported)
        .then_some(())
        .ok_or(error)
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
