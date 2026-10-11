//! Positional reads, writes, and hole punching on block backing files.

use std::{fs::File, io, path::Path};

pub fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt as _;
        file.read_exact_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt as _;
        let mut done = 0;
        while done < buf.len() {
            let at = offset
                .checked_add(u64::try_from(done).map_err(io::Error::other)?)
                .ok_or_else(|| io::Error::other("file offset overflow"))?;
            match file.seek_read(&mut buf[done..], at) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(len) => done += len,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

pub fn write_all_at(file: &File, offset: u64, buf: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt as _;
        file.write_all_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt as _;
        let mut done = 0;
        while done < buf.len() {
            let at = offset
                .checked_add(u64::try_from(done).map_err(io::Error::other)?)
                .ok_or_else(|| io::Error::other("file offset overflow"))?;
            match file.seek_write(&buf[done..], at) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "zero-length positional write",
                    ));
                }
                Ok(len) => done += len,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

pub fn discard(file: &File, offset: u64, len: u64) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    discard_file(file, offset, len)
}

pub fn open_disk(path: &Path, readonly: bool) -> io::Result<File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(!readonly)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("block backing must be a regular file"));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn discard_file(file: &File, offset: u64, len: u64) -> io::Result<()> {
    rustix::fs::fallocate(
        file,
        rustix::fs::FallocateFlags::PUNCH_HOLE | rustix::fs::FallocateFlags::KEEP_SIZE,
        offset,
        len,
    )
    .map_err(io::Error::from)
    .or_else(ignore_unsupported)
}

#[cfg(target_os = "macos")]
fn discard_file(file: &File, offset: u64, len: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;
    let block = rustix::fs::fstatvfs(file)
        .map_err(io::Error::from)?
        .f_frsize;
    if block == 0 {
        return Err(io::Error::other("zero filesystem block size"));
    }
    let end = offset
        .checked_add(len)
        .ok_or_else(|| io::Error::other("discard range overflow"))?;
    let offset = offset
        .div_ceil(block)
        .checked_mul(block)
        .ok_or_else(|| io::Error::other("discard range overflow"))?;
    let end = end / block * block;
    if end <= offset {
        return Ok(());
    }
    let range = libc::fpunchhole_t {
        fp_flags: 0,
        reserved: 0,
        fp_offset: libc::off_t::try_from(offset).map_err(io::Error::other)?,
        fp_length: libc::off_t::try_from(end - offset).map_err(io::Error::other)?,
    };
    #[allow(unsafe_code)]
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &range) };
    if result == 0 {
        Ok(())
    } else {
        ignore_unsupported(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn discard_file(file: &File, offset: u64, len: u64) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{
        FILE_ZERO_DATA_INFORMATION, FSCTL_SET_SPARSE, FSCTL_SET_ZERO_DATA,
    };
    let start = i64::try_from(offset).map_err(io::Error::other)?;
    let end = start
        .checked_add(i64::try_from(len).map_err(io::Error::other)?)
        .ok_or_else(|| io::Error::other("discard range overflow"))?;
    let mut returned = 0;
    #[allow(unsafe_code)]
    let sparse = unsafe {
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
        return zero_file_range(file, offset, len);
    }
    let range = FILE_ZERO_DATA_INFORMATION {
        FileOffset: start,
        BeyondFinalZero: end,
    };
    #[allow(unsafe_code)]
    let zeroed = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_ZERO_DATA,
            (&raw const range).cast(),
            u32::try_from(core::mem::size_of_val(&range)).map_err(io::Error::other)?,
            core::ptr::null_mut(),
            0,
            &raw mut returned,
            core::ptr::null_mut(),
        )
    };
    if zeroed == 0 {
        return zero_file_range(file, offset, len);
    }
    Ok(())
}

#[cfg(windows)]
fn zero_file_range(file: &File, mut offset: u64, mut len: u64) -> io::Result<()> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| io::Error::other("discard range overflow"))?;
    if end > file.metadata()?.len() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let zeroes = vec![0; 64 * 1024];
    while len > 0 {
        let chunk = usize::try_from(len.min(zeroes.len() as u64)).map_err(io::Error::other)?;
        write_all_at(file, offset, &zeroes[..chunk])?;
        offset += chunk as u64;
        len -= chunk as u64;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn ignore_unsupported(error: io::Error) -> io::Result<()> {
    (error.kind() == io::ErrorKind::Unsupported).ok_or(error)
}

#[cfg(all(test, windows))]
mod windows_discard_tests {
    use super::*;

    #[test]
    fn zero_fill_fallback_preserves_neighbors_and_file_length() {
        let file = tempfile::tempfile().unwrap();
        file.set_len(200_000).unwrap();
        write_all_at(&file, 0, &vec![0xa5; 200_000]).unwrap();
        zero_file_range(&file, 500, 131_000).unwrap();
        let mut contents = vec![0; 200_000];
        read_exact_at(&file, 0, &mut contents).unwrap();
        assert!(contents[..500].iter().all(|byte| *byte == 0xa5));
        assert!(contents[500..131_500].iter().all(|byte| *byte == 0));
        assert!(contents[131_500..].iter().all(|byte| *byte == 0xa5));
        assert!(zero_file_range(&file, 199_999, 2).is_err());
        assert_eq!(file.metadata().unwrap().len(), 200_000);
    }
}
