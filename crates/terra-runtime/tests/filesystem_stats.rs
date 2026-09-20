#![allow(clippy::expect_used)]

use terra_runtime::{
    component::fs::host::{FsHost, ShareGrant},
    engine::DeviceContext,
};
use wasmtime::component::Resource;
use wasmtime_wasi::p3::bindings::filesystem::preopens::Host as _;

fn host(root: &std::path::Path, readonly: bool) -> FsHost {
    FsHost::new(
        DeviceContext::new(4096).expect("guest RAM"),
        ShareGrant::new(&root.canonicalize().expect("canonical path"), readonly)
            .expect("share grant"),
    )
}

#[test]
fn shares_report_filesystem_statistics() {
    let root = tempfile::tempdir().expect("tempdir");
    for readonly in [false, true] {
        let mut fs = host(root.path(), readonly);
        let descriptor = fs.get_directories().expect("preopen").remove(0).0;
        let stat = fs
            .statfs_for_descriptor(&Resource::new_borrow(descriptor.rep()))
            .expect("filesystem statistics");
        assert_ne!(stat.blocks, 0);
        assert_ne!(stat.block_size, 0);
        assert_ne!(stat.name_max, 0);
    }
}

#[test]
fn filesystem_statistics_reject_unknown_descriptors() {
    let root = tempfile::tempdir().expect("tempdir");
    let mut fs = host(root.path(), true);
    assert!(
        fs.statfs_for_descriptor(&Resource::new_borrow(u32::MAX))
            .is_err()
    );
}
