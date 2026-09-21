use wasmtime_wasi::filesystem::Descriptor;

use super::host::terra;

#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
pub(super) fn open_metadata_file(
    _directory: &std::fs::File,
    _name: &str,
) -> Result<std::fs::File, terra::fs::host::Error> {
    Err(terra::fs::host::Error::Unsupported)
}

fn validate_child_name(name: &str) -> Result<(), terra::fs::host::Error> {
    use terra::fs::host::Error;
    // Separators and stream syntax could escape the granted directory.
    if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\0']) {
        return Err(Error::Access);
    }
    #[cfg(windows)]
    if name.contains(['\\', ':']) {
        return Err(Error::Access);
    }
    Ok(())
}

pub(super) fn get_mode_at(
    parent: &Descriptor,
    name: &str,
) -> Result<Option<u32>, terra::fs::host::Error> {
    use terra::fs::host::Error;
    validate_child_name(name)?;
    let Descriptor::Dir(directory) = parent else {
        return Err(Error::Access);
    };
    #[cfg(unix)]
    {
        let metadata =
            rustix::fs::statat(&directory.dir, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
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

pub(super) fn set_mode_at(
    parent: &Descriptor,
    name: &str,
    mode: u32,
) -> Result<(), terra::fs::host::Error> {
    use terra::fs::host::Error;
    validate_child_name(name)?;
    let Descriptor::Dir(directory) = parent else {
        return Err(Error::Access);
    };
    if directory.perms.write_not_permitted() {
        return Err(Error::Access);
    }
    #[cfg(target_os = "linux")]
    {
        let file = open_metadata_file(&directory.dir, name)?;
        set_mode(
            &Descriptor::File(wasmtime_wasi::filesystem::File::new(
                file,
                directory.perms,
                wasmtime_wasi::filesystem::OpenMode::empty(),
                false,
            )),
            mode,
        )
    }
    #[cfg(target_os = "macos")]
    {
        let metadata =
            rustix::fs::statat(&directory.dir, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| Error::Access)?;
        if !matches!(
            rustix::fs::FileType::from_raw_mode(metadata.st_mode),
            rustix::fs::FileType::RegularFile | rustix::fs::FileType::Directory
        ) {
            return Err(Error::Access);
        }
        let permissions = u16::try_from(mode & 0o777).map_err(|_| Error::Access)?;
        rustix::fs::chmodat(
            &directory.dir,
            name,
            rustix::fs::Mode::from_raw_mode(permissions),
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

#[cfg(not(target_os = "macos"))]
pub(super) fn open_metadata_file(
    directory: &std::fs::File,
    name: &str,
) -> Result<std::fs::File, terra::fs::host::Error> {
    use terra::fs::host::Error;
    validate_child_name(name)?;
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags, openat};
        #[cfg(target_os = "linux")]
        let flags = OFlags::PATH;
        std::fs::File::from(
            openat(
                directory,
                name,
                flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Error::Access)?,
        )
    };
    #[cfg(windows)]
    let file = windows::open_metadata_file(directory, name)?;
    let metadata = file.metadata().map_err(|_| Error::Io)?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(Error::Access);
    }
    Ok(file)
}

pub(super) fn statfs(
    descriptor: &Descriptor,
) -> Result<terra::fs::host::FilesystemStat, terra::fs::host::Error> {
    #[cfg(unix)]
    {
        let stat = match descriptor {
            Descriptor::File(file) => rustix::fs::fstatvfs(&file.file),
            Descriptor::Dir(directory) => rustix::fs::fstatvfs(&directory.dir),
        }
        .map_err(|_| terra::fs::host::Error::Io)?;
        let block_size = if stat.f_frsize == 0 {
            stat.f_bsize
        } else {
            stat.f_frsize
        };
        if block_size == 0 {
            return Err(terra::fs::host::Error::Io);
        }
        Ok(terra::fs::host::FilesystemStat {
            blocks: stat.f_blocks,
            blocks_free: stat.f_bfree,
            blocks_available: stat.f_bavail,
            files: stat.f_files,
            files_free: stat.f_ffree,
            block_size: u32::try_from(block_size).map_err(|_| terra::fs::host::Error::Io)?,
            name_max: u32::try_from(stat.f_namemax).map_err(|_| terra::fs::host::Error::Io)?,
        })
    }
    #[cfg(windows)]
    {
        let file = match descriptor {
            Descriptor::File(file) => &file.file,
            Descriptor::Dir(directory) => &directory.dir,
        };
        windows::statfs(file)
    }
}

pub(super) fn get_mode(descriptor: &Descriptor) -> Result<Option<u32>, terra::fs::host::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let file = match descriptor {
            Descriptor::File(file) => &file.file,
            Descriptor::Dir(directory) => &directory.dir,
        };
        file.metadata()
            .map(|metadata| Some(metadata.mode()))
            .map_err(|_| terra::fs::host::Error::Io)
    }
    #[cfg(windows)]
    {
        match descriptor {
            Descriptor::Dir(_) => Ok(Some(0o040_755)),
            Descriptor::File(file) => file
                .file
                .metadata()
                .map(|metadata| {
                    Some(if metadata.permissions().readonly() {
                        0o100_555
                    } else {
                        0o100_755
                    })
                })
                .map_err(|_| terra::fs::host::Error::Io),
        }
    }
}

pub(super) fn set_mode(descriptor: &Descriptor, mode: u32) -> Result<(), terra::fs::host::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let file = match descriptor {
            Descriptor::File(file) => &file.file,
            Descriptor::Dir(directory) => &directory.dir,
        };
        let permissions = std::fs::Permissions::from_mode(mode & 0o0777);
        let result = file.set_permissions(permissions.clone());
        #[cfg(target_os = "linux")]
        if result
            .as_ref()
            .is_err_and(|error| error.raw_os_error() == Some(libc::EBADF))
        {
            use std::os::fd::AsRawFd;
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
                Err(_) => return Err(terra::fs::host::Error::Io),
            }
            // Older Linux kernels need procfs to chmod the retained O_PATH inode, including after unlink.
            return std::fs::set_permissions(
                format!("/proc/self/fd/{}", file.as_raw_fd()),
                permissions,
            )
            .map_err(|_| terra::fs::host::Error::Io);
        }
        result.map_err(|_| terra::fs::host::Error::Io)
    }
    #[cfg(windows)]
    {
        match descriptor {
            Descriptor::File(file) => windows::set_readonly(&file.file, mode & 0o222 == 0),
            Descriptor::Dir(_) if mode & 0o777 == 0o755 => Ok(()),
            Descriptor::Dir(_) => Err(terra::fs::host::Error::Unsupported),
        }
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;
    use crate::component::fs::ShareGrant;
    use std::io::{Read, Write};
    use wasmtime_wasi::filesystem::{FsPerms, OpenMode};

    #[test]
    fn metadata_handle_keeps_the_inode_without_granting_content_access() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        std::fs::write(&original, b"original").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        let grant = ShareGrant::new(&root.path().canonicalize().unwrap(), false).unwrap();
        let mut metadata = open_metadata_file(&grant.directory.dir, "original").unwrap();
        assert_eq!(metadata.metadata().unwrap().len(), 8);
        assert!(metadata.read(&mut [0; 1]).is_err());
        let moved = root.path().join("moved");
        std::fs::rename(&original, &moved).unwrap();
        std::fs::write(&original, b"replacement").unwrap();
        let descriptor = Descriptor::File(wasmtime_wasi::filesystem::File::new(
            metadata.try_clone().unwrap(),
            FsPerms::ReadWrite,
            OpenMode::empty(),
            false,
        ));
        set_mode(&descriptor, 0o600).unwrap();
        assert!(metadata.read(&mut [0; 1]).is_err());
        assert!(metadata.write(b"changed").is_err());
        assert_eq!(std::fs::read(&moved).unwrap(), b"original");
        assert_eq!(std::fs::read(&original).unwrap(), b"replacement");
        for name in ["", ".", "..", "../original", "original/child", "original\0"] {
            assert!(open_metadata_file(&grant.directory.dir, name).is_err());
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&original, root.path().join("link")).unwrap();
            assert!(open_metadata_file(&grant.directory.dir, "link").is_err());
        }
        #[cfg(windows)]
        for name in ["..\\original", "original:stream"] {
            assert!(open_metadata_file(&grant.directory.dir, name).is_err());
        }
    }
}

#[cfg(all(test, unix))]
mod path_metadata_tests {
    use super::*;
    use crate::component::fs::ShareGrant;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn repairs_inaccessible_children_without_following_symlinks_or_escaping() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let outside_mode = outside.as_file().metadata().unwrap().permissions().mode();
        let grant = ShareGrant::new(&root.path().canonicalize().unwrap(), false).unwrap();
        let parent = Descriptor::Dir(grant.directory);
        for name in ["file", "directory"] {
            let path = root.path().join(name);
            if name == "directory" {
                std::fs::create_dir(&path).unwrap();
            } else {
                std::fs::write(&path, b"contents").unwrap();
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
            assert_eq!(get_mode_at(&parent, name).unwrap().unwrap() & 0o777, 0);
            set_mode_at(&parent, name, 0o700).unwrap();
            assert_eq!(get_mode_at(&parent, name).unwrap().unwrap() & 0o777, 0o700);
        }
        symlink(outside.path(), root.path().join("link")).unwrap();
        assert!(set_mode_at(&parent, "link", 0o777).is_err());
        assert_eq!(
            outside.as_file().metadata().unwrap().permissions().mode(),
            outside_mode
        );
        for name in ["", ".", "..", "../file", "directory/file", "file\0"] {
            assert!(get_mode_at(&parent, name).is_err());
            assert!(set_mode_at(&parent, name, 0o777).is_err());
        }
        let readonly = ShareGrant::new(&root.path().canonicalize().unwrap(), true).unwrap();
        assert!(set_mode_at(&Descriptor::Dir(readonly.directory), "file", 0o777).is_err());
    }
}
