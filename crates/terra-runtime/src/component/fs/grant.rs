#[cfg(unix)]
use std::path::Component;
use std::{io, path::Path};

use wasmtime_wasi::filesystem::{Dir, FsPerms, OpenMode};

#[derive(Clone)]
pub struct ShareGrant {
    pub readonly: bool,
    pub(crate) root: std::path::PathBuf,
    pub(super) directory: Dir,
    pub(super) watch_budget: std::sync::Arc<tokio::sync::Semaphore>,
    pub(super) event_budget: std::sync::Arc<tokio::sync::Semaphore>,
    #[cfg(test)]
    pub(super) watch_registration: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

impl ShareGrant {
    pub fn new(root: &Path, readonly: bool) -> io::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self::from_directory(
                open_directory_without_symlinks(root)?,
                readonly,
                root,
            ))
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS);
            let directory = options.open(root)?;
            if !directory.metadata()?.is_dir() {
                return Err(io::Error::other("mount source must be a directory"));
            }
            if read_final_path(&directory)? != root {
                return Err(io::Error::other("mount source changed while opening it"));
            }
            Ok(Self::from_directory(directory, readonly, root))
        }
    }

    fn from_directory(directory: std::fs::File, readonly: bool, root: &Path) -> Self {
        let directory = Dir::new(
            directory,
            if readonly {
                FsPerms::ReadOnly
            } else {
                FsPerms::ReadWrite
            },
            if readonly {
                OpenMode::READ
            } else {
                OpenMode::READ | OpenMode::WRITE
            },
            false,
        );
        Self {
            readonly,
            root: root.to_path_buf(),
            watch_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(
                super::file_events::MAX_NATIVE_WATCHES,
            )),
            event_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(
                super::file_events::MAX_PENDING_FILE_EVENTS - 2,
            )),
            directory,
            #[cfg(test)]
            watch_registration: None,
        }
    }
}

pub fn share_notification_budgets(shares: &mut [ShareGrant]) {
    // Reserve the stream transfer and worker slots for each share.
    let queued =
        super::file_events::MAX_PENDING_FILE_EVENTS.saturating_sub(shares.len().saturating_mul(2));
    let budget = std::sync::Arc::new(tokio::sync::Semaphore::new(queued));
    let watches = std::sync::Arc::new(tokio::sync::Semaphore::new(
        super::file_events::MAX_NATIVE_WATCHES,
    ));
    for share in shares {
        share.watch_budget = watches.clone();
        share.event_budget = budget.clone();
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn read_final_path(file: &std::fs::File) -> io::Result<std::path::PathBuf> {
    use std::os::{windows::ffi::OsStringExt as _, windows::io::AsRawHandle as _};
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;

    const PATH_CAPACITY: u32 = 32_768;
    let mut path = vec![0; PATH_CAPACITY as usize];
    // SAFETY: `path` is writable for its stated length and `file` stays open.
    let len = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle().cast(),
            path.as_mut_ptr(),
            PATH_CAPACITY,
            0,
        )
    };
    if len == 0 || len >= PATH_CAPACITY {
        return Err(io::Error::last_os_error());
    }
    Ok(std::ffi::OsString::from_wide(&path[..len as usize]).into())
}

#[cfg(unix)]
fn open_directory_without_symlinks(root: &Path) -> io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags, openat};

    if !root.is_absolute() {
        return Err(io::Error::other("mount source is not an absolute path"));
    }
    let mut directory = std::fs::File::open("/")?;
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

#[must_use]
pub fn share_tag(index: usize) -> String {
    format!("terra-share-{index}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::symlink as symlink_dir;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_dir;

    #[test]
    fn mount_source_requires_a_directory_without_a_leaf_symlink() {
        let root = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(root.path()).unwrap();
        let directory = base.join("directory");
        std::fs::create_dir(&directory).unwrap();
        let link = base.join("link");
        symlink_dir(&directory, &link).unwrap();
        assert!(ShareGrant::new(&directory, true).is_ok());
        assert!(ShareGrant::new(&link, true).is_err());
        let file = base.join("file");
        std::fs::write(&file, b"file").unwrap();
        assert!(ShareGrant::new(&file, false).is_err());
    }

    #[test]
    fn mount_source_rejects_a_symlinked_ancestor() {
        let root = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(root.path()).unwrap();
        let expected_parent = base.join("expected");
        let private_parent = base.join("private");
        std::fs::create_dir_all(expected_parent.join("share")).unwrap();
        std::fs::create_dir_all(private_parent.join("share")).unwrap();
        let expected = expected_parent.join("share");
        std::fs::rename(&expected_parent, base.join("moved")).unwrap();
        symlink_dir(&private_parent, &expected_parent).unwrap();
        assert!(ShareGrant::new(&expected, false).is_err());
    }
}
