use std::os::unix::fs::{MetadataExt as _, symlink};

use wasmtime::component::Resource;
use wasmtime_wasi::{
    WasiView,
    filesystem::{Descriptor, FsPerms, WasiFilesystem, WasiFilesystemView},
    p3::bindings::filesystem::{
        preopens::Host as _,
        types::{DescriptorFlags, ErrorCode, HostDescriptorWithStore, OpenFlags, PathFlags},
    },
};

use crate::{
    component::fs::host::{FsHost, ShareGrant},
    engine::DeviceHost,
};

fn host(grant: ShareGrant) -> FsHost {
    FsHost::new(DeviceHost::new(4096).unwrap(), grant)
}

#[test]
fn mount_source_requires_a_directory_without_a_leaf_symlink() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("directory");
    std::fs::create_dir(&directory).unwrap();
    let link = root.path().join("link");
    symlink(&directory, &link).unwrap();
    assert!(ShareGrant::new(&directory, true).is_ok());
    assert!(ShareGrant::new(&link, true).is_err());
    let file = root.path().join("file");
    std::fs::write(&file, b"file").unwrap();
    assert!(ShareGrant::new(&file, false).is_err());
}

#[test]
fn mount_source_rejects_a_symlinked_ancestor() {
    let root = tempfile::tempdir().unwrap();
    let expected_parent = root.path().join("expected");
    let private_parent = root.path().join("private");
    std::fs::create_dir_all(expected_parent.join("share")).unwrap();
    std::fs::create_dir_all(private_parent.join("share")).unwrap();
    let expected = expected_parent.join("share");
    std::fs::rename(&expected_parent, root.path().join("moved")).unwrap();
    symlink(&private_parent, &expected_parent).unwrap();
    assert!(ShareGrant::new(&expected, false).is_err());
}

#[test]
fn preopen_retains_its_directory_and_rights_without_ambient_resources() {
    let root = tempfile::tempdir().unwrap();
    let original = root.path().join("grant");
    std::fs::create_dir(&original).unwrap();
    let inode = std::fs::metadata(&original).unwrap().ino();
    let grant = ShareGrant::new(&original, true).unwrap();
    std::fs::rename(&original, root.path().join("moved")).unwrap();
    std::fs::create_dir(&original).unwrap();
    let mut fs = host(grant);
    let directories = fs.get_directories().unwrap();
    assert_eq!(directories.len(), 1);
    assert_eq!(directories[0].1, "/");
    let view = fs.ctx();
    let Descriptor::Dir(directory) = view.table.get(&directories[0].0).unwrap() else {
        panic!("preopen must be a directory")
    };
    assert_eq!(directory.dir.metadata().unwrap().ino(), inode);
    assert_eq!(directory.perms, FsPerms::ReadOnly);
    view.table.set_max_capacity(1);
    assert!(fs.get_directories().is_err());
    fs.ctx()
        .table
        .delete(directories.into_iter().next().unwrap().0)
        .unwrap();
    assert_eq!(fs.get_directories().unwrap().len(), 1);
    let mut empty = DeviceHost::new(4096).unwrap();
    assert!(empty.filesystem().get_directories().unwrap().is_empty());
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn wasi_itself_denies_escape_and_readonly_mutation() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("secret"), b"outside").unwrap();
    let mounted = root.path().join("mounted");
    std::fs::create_dir(&mounted).unwrap();
    std::fs::write(mounted.join("file"), b"original").unwrap();
    symlink("../secret", mounted.join("escape")).unwrap();
    let engine = crate::engine::device_engine().unwrap();
    for readonly in [false, true] {
        let mut fs = host(ShareGrant::new(&mounted, readonly).unwrap());
        let root_fd = fs.get_directories().unwrap().remove(0).0;
        let mut store = wasmtime::Store::new(&engine, fs);
        store
            .run_concurrent(async |accessor| {
                let access = accessor.with_getter::<WasiFilesystem>(WasiFilesystemView::filesystem);
                WasiFilesystem::sync(&access, Resource::new_borrow(root_fd.rep()))
                    .await
                    .unwrap();
                let open = async |path: &str, flags, mode| {
                    WasiFilesystem::open_at(
                        &access,
                        Resource::new_borrow(root_fd.rep()),
                        PathFlags::SYMLINK_FOLLOW,
                        path.to_owned(),
                        flags,
                        mode,
                    )
                    .await
                };
                assert!(
                    open("file", OpenFlags::empty(), DescriptorFlags::READ)
                        .await
                        .is_ok()
                );
                for path in ["../secret", "/etc/passwd", "escape"] {
                    assert!(
                        open(path, OpenFlags::empty(), DescriptorFlags::READ)
                            .await
                            .is_err(),
                        "{path}"
                    );
                }
                assert!(
                    WasiFilesystem::open_at(
                        &access,
                        Resource::new_borrow(u32::MAX),
                        PathFlags::empty(),
                        "file".into(),
                        OpenFlags::empty(),
                        DescriptorFlags::READ,
                    )
                    .await
                    .is_err()
                );
                assert_eq!(
                    open("file", OpenFlags::empty(), DescriptorFlags::WRITE)
                        .await
                        .is_ok(),
                    !readonly
                );
                if !readonly {
                    WasiFilesystem::create_directory_at(
                        &access,
                        Resource::new_borrow(root_fd.rep()),
                        "created-directory".into(),
                    )
                    .await
                    .unwrap();
                    WasiFilesystem::symlink_at(
                        &access,
                        Resource::new_borrow(root_fd.rep()),
                        "file".into(),
                        "created-symlink".into(),
                    )
                    .await
                    .unwrap();
                    let error = WasiFilesystem::symlink_at(
                        &access,
                        Resource::new_borrow(root_fd.rep()),
                        "/guest-absolute-target".into(),
                        "absolute-symlink".into(),
                    )
                    .await
                    .unwrap_err()
                    .downcast()
                    .unwrap();
                    assert!(matches!(error, ErrorCode::NotPermitted));
                    let created = open(
                        "created",
                        OpenFlags::CREATE | OpenFlags::TRUNCATE,
                        DescriptorFlags::WRITE,
                    )
                    .await
                    .unwrap();
                    HostDescriptorWithStore::sync_data(
                        &access,
                        Resource::new_borrow(created.rep()),
                    )
                    .await
                    .unwrap();
                }
                if readonly {
                    for (path, flags) in [("new", OpenFlags::CREATE), ("file", OpenFlags::TRUNCATE)]
                    {
                        assert!(open(path, flags, DescriptorFlags::WRITE).await.is_err());
                    }
                    assert!(
                        WasiFilesystem::unlink_file_at(
                            &access,
                            Resource::new_borrow(root_fd.rep()),
                            "file".into()
                        )
                        .await
                        .is_err()
                    );
                    assert!(
                        WasiFilesystem::create_directory_at(
                            &access,
                            Resource::new_borrow(root_fd.rep()),
                            "new-dir".into()
                        )
                        .await
                        .is_err()
                    );
                }
            })
            .await
            .unwrap();
    }
    assert_eq!(std::fs::read(mounted.join("file")).unwrap(), b"original");
    assert!(!mounted.join("new").exists());
}

#[tokio::test]
async fn mode_capability_changes_writable_files_and_rejects_readonly_files() {
    let root = tempfile::tempdir().unwrap();
    let mounted = root.path().join("mounted");
    std::fs::create_dir(&mounted).unwrap();
    std::fs::write(mounted.join("file"), b"file").unwrap();
    let engine = crate::engine::device_engine().unwrap();

    for readonly in [false, true] {
        let mut fs = host(ShareGrant::new(&mounted, readonly).unwrap());
        let root_fd = fs.get_directories().unwrap().remove(0).0;
        let mut store = wasmtime::Store::new(&engine, fs);
        let descriptor = store
            .run_concurrent(async |accessor| {
                let access = accessor.with_getter::<WasiFilesystem>(WasiFilesystemView::filesystem);
                WasiFilesystem::open_at(
                    &access,
                    Resource::new_borrow(root_fd.rep()),
                    PathFlags::empty(),
                    "file".into(),
                    OpenFlags::empty(),
                    DescriptorFlags::READ,
                )
                .await
                .unwrap()
                .rep()
            })
            .await
            .unwrap();
        let result = store
            .data_mut()
            .set_mode_for_descriptor(Resource::new_borrow(descriptor), 0o7600);
        assert_eq!(result.is_ok(), !readonly);
        if !readonly {
            assert_eq!(
                store
                    .data_mut()
                    .mode_for_descriptor(Resource::new_borrow(descriptor))
                    .unwrap(),
                Some(0o100_600)
            );
        }
    }
}
