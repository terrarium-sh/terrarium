//! Native filesystem and positional file operations.

use std::{fs::File, io, path::Path};

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

pub fn open_share_root(root: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, openat};
        use std::path::Component;

        if !root.is_absolute() {
            return Err(io::Error::other("mount source is not an absolute path"));
        }
        let mut directory = File::open("/")?;
        for component in root.components() {
            let Component::Normal(name) = component else {
                if component != Component::RootDir {
                    return Err(io::Error::other("mount source is not an absolute path"));
                }
                continue;
            };
            directory = openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io::Error::from)?
            .into();
        }
        Ok(directory)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

        let directory = File::options()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(root)?;
        if !directory.metadata()?.is_dir() {
            return Err(io::Error::other("mount source must be a directory"));
        }
        if windows::read_final_path(&directory)? != root {
            return Err(io::Error::other("mount source changed while opening it"));
        }
        Ok(directory)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = root;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported host",
        ))
    }
}

#[cfg(target_os = "macos")]
pub fn open_metadata_file(_directory: &File, name: &str) -> Result<File, Error> {
    validate_child_name(name)?;
    Err(Error::Unsupported)
}

#[cfg(not(target_os = "macos"))]
pub fn open_metadata_file(directory: &File, name: &str) -> Result<File, Error> {
    validate_child_name(name)?;
    let file = {
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, openat};
            #[cfg(target_os = "linux")]
            let flags = OFlags::PATH;
            File::from(
                openat(
                    directory,
                    name,
                    flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| Error::Access)?,
            )
        }
        #[cfg(windows)]
        {
            windows::open_metadata_file(directory, name)?
        }
    };
    let metadata = file.metadata().map_err(|_| Error::Io)?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(Error::Access);
    }
    Ok(file)
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

pub fn mode_at(directory: &File, name: &str) -> Result<Option<u32>, Error> {
    validate_child_name(name)?;
    #[cfg(unix)]
    {
        let metadata = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| Error::Access)?;
        #[allow(clippy::useless_conversion)]
        Ok(Some(u32::from(metadata.st_mode)))
    }
    #[cfg(windows)]
    {
        let _ = directory;
        Ok(None)
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
            (mode & 0o777 == 0o755)
                .then_some(())
                .ok_or(Error::Unsupported)
        } else {
            windows::set_readonly(file, mode & 0o222 == 0)
        }
    }
}

pub fn set_mode_at(directory: &File, name: &str, mode: u32) -> Result<(), Error> {
    validate_child_name(name)?;
    #[cfg(target_os = "linux")]
    {
        let file = open_metadata_file(directory, name)?;
        set_mode(
            &file,
            file.metadata().map_err(|_| Error::Io)?.is_dir(),
            mode,
        )
    }
    #[cfg(target_os = "macos")]
    {
        let metadata = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| Error::Access)?;
        if !matches!(
            rustix::fs::FileType::from_raw_mode(metadata.st_mode),
            rustix::fs::FileType::RegularFile | rustix::fs::FileType::Directory
        ) {
            return Err(Error::Access);
        }
        let mode = u16::try_from(mode & 0o777).map_err(|_| Error::Access)?;
        rustix::fs::chmodat(
            directory,
            name,
            rustix::fs::Mode::from_raw_mode(mode),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| Error::Access)
    }
    #[cfg(windows)]
    {
        let _ = (directory, mode);
        Err(Error::Unsupported)
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

fn validate_child_name(name: &str) -> Result<(), Error> {
    if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\0']) {
        return Err(Error::Access);
    }
    #[cfg(windows)]
    if name.contains(['\\', ':']) {
        return Err(Error::Access);
    }
    Ok(())
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
    let offset = i64::try_from(offset).map_err(io::Error::other)?;
    let end = offset
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
        return ignore_unsupported(io::Error::last_os_error());
    }
    let range = FILE_ZERO_DATA_INFORMATION {
        FileOffset: offset,
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
        ignore_unsupported(io::Error::last_os_error())?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn discard_file(_file: &File, _offset: u64, _len: u64) -> io::Result<()> {
    Ok(())
}

fn ignore_unsupported(error: io::Error) -> io::Result<()> {
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
    (error.kind() == io::ErrorKind::Unsupported)
        .then_some(())
        .ok_or(error)
}

#[cfg(windows)]
#[path = "filesystem/windows.rs"]
mod windows;

#[cfg(all(test, unix, not(target_os = "macos")))]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    #[test]
    fn share_root_and_metadata_handles_reject_symlinks_and_retain_inodes() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = tempfile::tempdir().expect("root");
        let root_path = root.path().canonicalize().expect("canonical root");
        let original = root_path.join("original");
        std::fs::write(&original, b"original").expect("write original");
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o000))
            .expect("remove permissions");
        let directory = open_share_root(&root_path).expect("open root");
        let mut metadata = open_metadata_file(&directory, "original").expect("open metadata");
        assert_eq!(metadata.metadata().expect("metadata").len(), 8);
        assert!(metadata.read(&mut [0; 1]).is_err());
        let moved = root_path.join("moved");
        std::fs::rename(&original, &moved).expect("rename original");
        std::fs::write(&original, b"replacement").expect("replace original");
        set_mode(&metadata, false, 0o600).expect("set mode");
        assert!(metadata.read(&mut [0; 1]).is_err());
        assert!(metadata.write(b"changed").is_err());
        assert_eq!(std::fs::read(&moved).expect("read moved"), b"original");
        assert_eq!(
            std::fs::read(&original).expect("read replacement"),
            b"replacement"
        );
        for name in ["", ".", "..", "../original", "original/child", "original\0"] {
            assert!(matches!(
                open_metadata_file(&directory, name),
                Err(Error::Access)
            ));
        }
        symlink(&original, root_path.join("link")).expect("symlink");
        assert!(matches!(
            open_metadata_file(&directory, "link"),
            Err(Error::Access)
        ));
    }

    #[test]
    fn share_root_rejects_symlinked_ancestors() {
        let root = tempfile::tempdir().expect("root");
        let base = root.path().canonicalize().expect("canonical root");
        let expected_parent = base.join("expected");
        let private_parent = base.join("private");
        std::fs::create_dir_all(expected_parent.join("share")).expect("expected share");
        std::fs::create_dir_all(private_parent.join("share")).expect("private share");
        let expected = expected_parent.join("share");
        std::fs::rename(&expected_parent, base.join("moved")).expect("move expected");
        std::os::unix::fs::symlink(&private_parent, &expected_parent).expect("symlink parent");
        assert!(open_share_root(&expected).is_err());
    }
}
