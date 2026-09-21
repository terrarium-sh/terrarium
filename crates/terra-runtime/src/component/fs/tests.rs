#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, symlink as symlink_file};
#[cfg(windows)]
use std::os::windows::fs::symlink_file;

use wasmtime::component::Resource;
use wasmtime_wasi::{
    WasiView,
    filesystem::{Descriptor, FsPerms, WasiFilesystem, WasiFilesystemView},
    p3::bindings::filesystem::{
        preopens::Host as _,
        types::{DescriptorFlags, ErrorCode, HostDescriptorWithStore, OpenFlags, PathFlags},
    },
};

use crate::component::context::DeviceContext;
use crate::component::fs::{FsHost, ShareGrant};

fn host(grant: ShareGrant) -> FsHost {
    FsHost::new(DeviceContext::new(4096).unwrap(), grant)
}

#[tokio::test]
async fn preopen_retains_its_directory_and_rights_without_ambient_resources() {
    let root = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(root.path()).unwrap();
    let original = base.join("grant");
    std::fs::create_dir(&original).unwrap();
    std::fs::write(original.join("retained"), b"original").unwrap();
    #[cfg(unix)]
    let inode = std::fs::metadata(&original).unwrap().ino();
    let grant = ShareGrant::new(&original, true).unwrap();
    std::fs::rename(&original, base.join("moved")).unwrap();
    std::fs::create_dir(&original).unwrap();
    let mut fs = host(grant);
    let directories = fs.get_directories().unwrap();
    assert_eq!(directories.len(), 1);
    assert_eq!(directories[0].1, "/");
    let view = fs.ctx();
    let Descriptor::Dir(directory) = view.table.get(&directories[0].0).unwrap() else {
        panic!("preopen must be a directory")
    };
    #[cfg(unix)]
    assert_eq!(directory.dir.metadata().unwrap().ino(), inode);
    assert_eq!(directory.perms, FsPerms::ReadOnly);
    fs.ctx().table.set_max_capacity(1);
    assert!(fs.get_directories().is_err());
    fs.ctx()
        .table
        .delete(directories.into_iter().next().unwrap().0)
        .unwrap();
    let directories = fs.get_directories().unwrap();
    assert_eq!(directories.len(), 1);
    let mut empty = DeviceContext::new(4096).unwrap();
    assert!(empty.filesystem().get_directories().unwrap().is_empty());
    fs.ctx().table.set_max_capacity(2);
    let engine = crate::engine::device_engine().unwrap();
    let mut store = wasmtime::Store::new(&engine, fs);
    let opened = store
        .run_concurrent(async |accessor| {
            let access = accessor.with_getter::<WasiFilesystem>(WasiFilesystemView::filesystem);
            WasiFilesystem::open_at(
                &access,
                Resource::new_borrow(directories[0].0.rep()),
                PathFlags::empty(),
                "retained".into(),
                OpenFlags::empty(),
                DescriptorFlags::READ,
            )
            .await
            .unwrap()
            .rep()
        })
        .await
        .unwrap();
    let mut fs = store.into_data();
    fs.ctx()
        .table
        .delete(Resource::<Descriptor>::new_own(opened))
        .unwrap();
}

/// Windows denies syncing WASI's read-only directory handle; escape and
/// readonly-mutation checks still run on every host.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn wasi_itself_denies_escape_and_readonly_mutation() {
    let root = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(root.path()).unwrap();
    std::fs::write(base.join("secret"), b"outside").unwrap();
    let mounted = base.join("mounted");
    std::fs::create_dir(&mounted).unwrap();
    std::fs::write(mounted.join("file"), b"original").unwrap();
    symlink_file("../secret", mounted.join("escape")).unwrap();
    let engine = crate::engine::device_engine().unwrap();
    for readonly in [false, true] {
        let mut fs = host(ShareGrant::new(&mounted, readonly).unwrap());
        let root_fd = fs.get_directories().unwrap().remove(0).0;
        let mut store = wasmtime::Store::new(&engine, fs);
        store
            .run_concurrent(async |accessor| {
                let access = accessor.with_getter::<WasiFilesystem>(WasiFilesystemView::filesystem);
                let synced =
                    WasiFilesystem::sync(&access, Resource::new_borrow(root_fd.rep())).await;
                #[cfg(unix)]
                synced.unwrap();
                #[cfg(windows)]
                assert!(matches!(
                    synced.unwrap_err().downcast().unwrap(),
                    ErrorCode::Access
                ));
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
    let base = std::fs::canonicalize(root.path()).unwrap();
    let mounted = base.join("mounted");
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
            .set_mode_for_descriptor(&Resource::new_borrow(descriptor), 0o7600);
        assert_eq!(result.is_ok(), !readonly);
        #[cfg(windows)]
        {
            assert_eq!(
                store
                    .data_mut()
                    .mode_for_descriptor(&Resource::new_borrow(descriptor))
                    .unwrap(),
                Some(0o100_755)
            );
            if !readonly {
                store
                    .data_mut()
                    .set_mode_for_descriptor(&Resource::new_borrow(descriptor), 0o444)
                    .unwrap();
                assert_eq!(
                    store
                        .data_mut()
                        .mode_for_descriptor(&Resource::new_borrow(descriptor))
                        .unwrap(),
                    Some(0o100_555)
                );
                store
                    .data_mut()
                    .set_mode_for_descriptor(&Resource::new_borrow(descriptor), 0o644)
                    .unwrap();
                assert_eq!(
                    store
                        .data_mut()
                        .mode_for_descriptor(&Resource::new_borrow(descriptor))
                        .unwrap(),
                    Some(0o100_755)
                );
            }
        }
        if !readonly && cfg!(unix) {
            assert_eq!(
                store
                    .data_mut()
                    .mode_for_descriptor(&Resource::new_borrow(descriptor))
                    .unwrap(),
                Some(0o100_600)
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn filesystem_actor_alone_publishes_interrupt_levels() {
    use crate::component::context::DeviceContext;
    use crate::component::fs::{FsHost, ShareGrant};
    use crate::engine::device_engine;

    let directory = tempfile::tempdir().unwrap();
    let mount = std::fs::canonicalize(directory.path()).unwrap();
    let engine = device_engine().unwrap();
    let component =
        wasmtime::component::Component::new(&engine, crate::test_fixtures::wasm::FS).unwrap();
    let host = FsHost::new(
        DeviceContext::new(64 * 1024).unwrap(),
        ShareGrant::new(&mount, false).unwrap(),
    );
    let channel = crate::component::fs::instantiate(
        &engine,
        host,
        &component,
        "test",
        8192,
        std::sync::Arc::new(|_| Ok(())),
    )
    .await
    .unwrap();
    let device = channel;
    assert_eq!(device.read(0, 4).unwrap(), 0x7472_6976_u32.to_le_bytes());
    device.write(0x70, &0_u32.to_le_bytes()).unwrap();
    device.close().unwrap();
}
