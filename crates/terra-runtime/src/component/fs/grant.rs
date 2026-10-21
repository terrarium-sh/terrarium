use std::{io, path::Path};

use wasmtime_wasi::filesystem::{Dir, FsPerms, OpenMode};

use crate::component::AccessMode;

#[derive(Clone)]
pub struct ShareGrant {
    pub access: AccessMode,
    pub(crate) root: std::path::PathBuf,
    pub(super) directory: Dir,
    pub(super) watch_budget: std::sync::Arc<tokio::sync::Semaphore>,
    pub(super) event_budget: std::sync::Arc<tokio::sync::Semaphore>,
    #[cfg(test)]
    pub(super) watch_registration: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

impl ShareGrant {
    pub fn new(root: &Path, access: AccessMode) -> io::Result<Self> {
        Ok(Self::from_directory(
            terra_platform::filesystem::share::open_share_root(root)?,
            access,
            root,
        ))
    }

    #[cfg(windows)]
    pub fn new_host_granted(
        root: &Path,
        access: AccessMode,
        expected: terra_platform::filesystem::share::FileIdentity,
    ) -> io::Result<Self> {
        Ok(Self::from_directory(
            terra_platform::filesystem::share::open_granted_share_root(root, expected)?,
            access,
            root,
        ))
    }

    fn from_directory(directory: std::fs::File, access: AccessMode, root: &Path) -> Self {
        let (permissions, open_mode) = match access {
            AccessMode::ReadOnly => (FsPerms::ReadOnly, OpenMode::READ),
            AccessMode::ReadWrite => (FsPerms::ReadWrite, OpenMode::READ | OpenMode::WRITE),
        };
        let directory = Dir::new(directory, permissions, open_mode, false);
        Self {
            access,
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
        assert!(ShareGrant::new(&directory, AccessMode::ReadOnly).is_ok());
        assert!(ShareGrant::new(&link, AccessMode::ReadOnly).is_err());
        let file = base.join("file");
        std::fs::write(&file, b"file").unwrap();
        assert!(ShareGrant::new(&file, AccessMode::ReadWrite).is_err());
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
        assert!(ShareGrant::new(&expected, AccessMode::ReadWrite).is_err());
    }

    /// A share under a parent the user can only pass through (mode 0711 on a multi-user host)
    /// opens on macOS and Windows, so Linux must not need read permission on its ancestors.
    #[cfg(unix)]
    #[test]
    fn mount_source_needs_only_search_permission_on_ancestors() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let parent = std::fs::canonicalize(root.path())
            .unwrap()
            .join("search-only");
        std::fs::create_dir_all(parent.join("share")).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o311)).unwrap();
        let grant = ShareGrant::new(&parent.join("share"), AccessMode::ReadOnly);
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        grant.unwrap();
    }
}
