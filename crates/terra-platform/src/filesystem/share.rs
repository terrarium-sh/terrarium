//! Share-root opening and handle-relative operations for the file-sharing device.

use std::{fs::File, io, path::Path};

use super::Error;

pub fn open_share_root(root: &Path) -> io::Result<File> {
    #[cfg(unix)]
    if !root.is_absolute()
        || root.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(io::Error::other("mount source is not an absolute path"));
    }
    #[cfg(target_os = "macos")]
    {
        use rustix::fs::{Mode, OFlags, open};

        Ok(open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW_ANY | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .into())
    }
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{Mode, OFlags, openat};
        use std::path::Component;

        let mut directory = File::open("/")?;
        for component in root.components() {
            let Component::Normal(name) = component else {
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
        if !windows::matches_canonical_root(&directory, root)? {
            return Err(io::Error::other("mount source changed while opening it"));
        }
        Ok(directory)
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub volume_serial: u64,
    pub file_id: [u8; 16],
}

#[cfg(windows)]
impl std::fmt::Display for FileIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}:{}",
            self.volume_serial,
            u128::from_le_bytes(self.file_id)
        )
    }
}

#[cfg(windows)]
impl std::str::FromStr for FileIdentity {
    type Err = io::Error;

    fn from_str(value: &str) -> io::Result<Self> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid share file identity");
        let (serial, file_id) = value.split_once(':').ok_or_else(invalid)?;
        Ok(Self {
            volume_serial: serial.parse().map_err(|_| invalid())?,
            file_id: file_id
                .parse::<u128>()
                .map_err(|_| invalid())?
                .to_le_bytes(),
        })
    }
}

#[cfg(windows)]
pub fn file_identity(file: &File) -> io::Result<FileIdentity> {
    windows::file_identity(file)
}

#[cfg(windows)]
pub fn open_granted_share_root(root: &Path, expected: FileIdentity) -> io::Result<File> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let directory = File::options()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(root)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other(
            "granted share root must be a regular directory",
        ));
    }
    if file_identity(&directory)? != expected {
        return Err(io::Error::other(
            "granted share root changed while opening it",
        ));
    }
    Ok(directory)
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

pub fn set_mode_at(directory: &File, name: &str, mode: u32) -> Result<(), Error> {
    validate_child_name(name)?;
    #[cfg(target_os = "linux")]
    {
        let file = open_metadata_file(directory, name)?;
        super::set_mode(
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

#[cfg(windows)]
pub mod windows;

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn share_root_and_metadata_handles_reject_symlinks_and_retain_inodes() {
        use std::assert_matches;
        use std::io::{Read as _, Write as _};
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
        crate::filesystem::set_mode(&metadata, false, 0o600).expect("set mode");
        assert!(metadata.read(&mut [0; 1]).is_err());
        assert!(metadata.write(b"changed").is_err());
        assert_eq!(std::fs::read(&moved).expect("read moved"), b"original");
        assert_eq!(
            std::fs::read(&original).expect("read replacement"),
            b"replacement"
        );
        for name in ["", ".", "..", "../original", "original/child", "original\0"] {
            assert_matches!(open_metadata_file(&directory, name), Err(Error::Access));
        }
        symlink(&original, root_path.join("link")).expect("symlink");
        assert_matches!(open_metadata_file(&directory, "link"), Err(Error::Access));
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

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    #[test]
    fn granted_root_rejects_a_different_directory_identity() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        let share = base.join("share");
        std::fs::create_dir_all(&share).unwrap();
        let pinned = super::open_share_root(&share).unwrap();
        let identity = file_identity(&pinned).unwrap();
        assert_eq!(
            identity.to_string().parse::<super::FileIdentity>().unwrap(),
            identity
        );
        assert!(super::open_granted_share_root(&share, identity).is_ok());

        let other = base.join("other");
        std::fs::create_dir(&other).unwrap();
        assert!(super::open_granted_share_root(&other, identity).is_err());
    }

    #[test]
    fn share_root_rejects_a_redirected_ancestor() {
        use std::os::windows::process::CommandExt as _;
        use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        let expected_parent = base.join("expected");
        let private_parent = base.join("private");
        std::fs::create_dir_all(expected_parent.join("share")).unwrap();
        std::fs::create_dir_all(private_parent.join("share")).unwrap();
        let expected = expected_parent.join("share");
        assert!(super::open_share_root(&expected).is_ok());
        std::fs::rename(&expected_parent, base.join("moved")).unwrap();
        let output = std::process::Command::new("cmd")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&expected_parent)
            .arg(&private_parent)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "creating test junction: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(super::open_share_root(&expected).is_err());
    }

    #[test]
    fn metadata_handles_retain_the_opened_file() {
        let root = tempfile::tempdir().expect("root");
        let root_path = root.path().canonicalize().expect("canonical root");
        let original = root_path.join("original");
        std::fs::write(&original, b"original").expect("write original");
        let directory = super::open_share_root(&root_path).expect("open root");
        let mut file = open_metadata_file(&directory, "original").expect("open metadata");
        assert!(file.read(&mut [0]).is_err());
        assert!(file.write(b"changed").is_err());
        let moved = root_path.join("moved");
        std::fs::rename(&original, &moved).expect("rename original");
        std::fs::write(&original, b"replacement").expect("replace original");
        crate::filesystem::windows::set_readonly(&file, true).expect("set readonly");
        assert!(
            moved
                .metadata()
                .expect("moved metadata")
                .permissions()
                .readonly()
        );
        assert!(
            !original
                .metadata()
                .expect("replacement metadata")
                .permissions()
                .readonly()
        );
        assert_eq!(file.metadata().expect("retained metadata").len(), 8);
        crate::filesystem::windows::set_readonly(&file, false).expect("clear readonly");
        let filesystem = crate::filesystem::stat(&directory).expect("filesystem statistics");
        assert!(filesystem.block_size > 0);
        assert!(filesystem.name_max > 0);
        assert!(filesystem.blocks_free <= filesystem.blocks);
    }
}
