//! Native file metadata, permissions, and capped appends.

use std::{
    fs::File,
    io::{self, Write as _},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Access,
    Unsupported,
    Io,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilesystemStat {
    pub blocks: u64,
    pub blocks_free: u64,
    pub blocks_available: u64,
    pub files: u64,
    pub files_free: u64,
    pub block_size: u32,
    pub name_max: u32,
}

#[must_use]
pub fn open_file_limit() -> Option<u64> {
    #[cfg(unix)]
    {
        rustix::process::getrlimit(rustix::process::Resource::Nofile).current
    }
    #[cfg(not(unix))]
    {
        None
    }
}

pub fn mode(file: &File, is_directory: bool) -> Result<Option<u32>, Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let _ = is_directory;
        file.metadata()
            .map(|metadata| Some(metadata.mode()))
            .map_err(|_| Error::Io)
    }
    #[cfg(windows)]
    {
        if is_directory {
            Ok(Some(0o040_755))
        } else {
            file.metadata()
                .map(|metadata| {
                    Some(if metadata.permissions().readonly() {
                        0o100_555
                    } else {
                        0o100_755
                    })
                })
                .map_err(|_| Error::Io)
        }
    }
}

pub fn set_mode(file: &File, is_directory: bool, mode: u32) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = is_directory;
        let permissions = std::fs::Permissions::from_mode(mode & 0o777);
        let result = file.set_permissions(permissions.clone());
        #[cfg(target_os = "linux")]
        if result
            .as_ref()
            .is_err_and(|error| error.raw_os_error() == Some(libc::EBADF))
        {
            use std::os::fd::AsRawFd as _;
            match rustix::fs::chmodat(
                file,
                "",
                rustix::fs::Mode::from_raw_mode(mode & 0o777),
                rustix::fs::AtFlags::EMPTY_PATH,
            ) {
                Ok(()) => return Ok(()),
                Err(
                    rustix::io::Errno::NOSYS
                    | rustix::io::Errno::INVAL
                    | rustix::io::Errno::OPNOTSUPP,
                ) => {}
                Err(_) => return Err(Error::Io),
            }
            return std::fs::set_permissions(
                format!("/proc/self/fd/{}", file.as_raw_fd()),
                permissions,
            )
            .map_err(|_| Error::Io);
        }
        result.map_err(|_| Error::Io)
    }
    #[cfg(windows)]
    {
        if is_directory {
            (mode & 0o777 == 0o755).ok_or(Error::Unsupported)
        } else {
            windows::set_readonly(file, mode & 0o222 == 0)
        }
    }
}

pub fn stat(file: &File) -> Result<FilesystemStat, Error> {
    #[cfg(unix)]
    {
        let stat = rustix::fs::fstatvfs(file).map_err(|_| Error::Io)?;
        let block_size = if stat.f_frsize == 0 {
            stat.f_bsize
        } else {
            stat.f_frsize
        };
        if block_size == 0 {
            return Err(Error::Io);
        }
        Ok(FilesystemStat {
            blocks: stat.f_blocks,
            blocks_free: stat.f_bfree,
            blocks_available: stat.f_bavail,
            files: stat.f_files,
            files_free: stat.f_ffree,
            block_size: u32::try_from(block_size).map_err(|_| Error::Io)?,
            name_max: u32::try_from(stat.f_namemax).map_err(|_| Error::Io)?,
        })
    }
    #[cfg(windows)]
    {
        windows::stat(file)
    }
}

pub fn open_regular_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits().cast_signed());
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("expected a regular file"));
    }
    Ok(file)
}

/// Restrict an existing path to its owner: `0700` for a directory, `0600` for a
/// file.
#[cfg(unix)]
pub fn set_owner_only(path: &std::path::Path, dir: bool) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if dir { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(windows)]
pub use windows::set_owner_only;

#[cfg(windows)]
mod windows;

pub mod disk;
pub mod share;

/// Drops bytes beyond the cap; concurrent writers must use independently opened append handles.
pub fn append_capped(file: &mut File, bytes: &[u8], max_bytes: u64) -> io::Result<()> {
    file.lock()?;
    let result = (|| {
        let remaining = max_bytes.saturating_sub(file.metadata()?.len());
        let count = bytes
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        file.write_all(&bytes[..count])
    })();
    let unlocked = file.unlock();
    result.and(unlocked)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_LOG_FILE_BYTES: u64 = 32;

    #[test]
    fn cap_drops_excess_bytes_without_truncating_existing_contents() {
        use std::io::{Read as _, Seek as _};
        let mut file = tempfile::tempfile().unwrap();
        append_capped(&mut file, b"abc", 3).unwrap();
        append_capped(&mut file, b"ignored", 3).unwrap();
        append_capped(&mut file, b"ignored", 0).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 3);
        append_capped(&mut file, b"def", 5).unwrap();
        file.rewind().unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abcde");
    }

    #[test]
    fn independent_append_handles_share_one_file_cap() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("log");
        File::create(&path)
            .unwrap()
            .set_len(MAX_LOG_FILE_BYTES - 3)
            .unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let mut file = File::options().read(true).append(true).open(&path).unwrap();
                scope.spawn(move || {
                    append_capped(&mut file, b"123456", MAX_LOG_FILE_BYTES).unwrap();
                });
            }
        });
        assert_eq!(std::fs::metadata(path).unwrap().len(), MAX_LOG_FILE_BYTES);
    }
}
