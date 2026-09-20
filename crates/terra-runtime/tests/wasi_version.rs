#![allow(clippy::expect_used)]

use terra_runtime::component::fs::host::fs_component_linker;
use terra_runtime::engine::device_engine;
use wasmtime::component::Component;

const FILESYSTEM_TYPES_031: &[u8] = b"wasi:filesystem/types@0.3.1";

#[test]
fn filesystem_descriptor_methods_link_at_wasi_031() {
    let engine = device_engine().expect("device engine");
    let linker = fs_component_linker::<terra_runtime::component::fs::host::FsHost>(&engine)
        .expect("filesystem linker");
    let component = include_bytes!(
        "../../../components/fs/target/wasm32-wasip3/release/terra_fs_component.wasm"
    );

    assert!(
        component
            .windows(FILESYSTEM_TYPES_031.len())
            .any(|bytes| bytes == FILESYSTEM_TYPES_031),
        "filesystem component imports wasi:filesystem/types@0.3.1"
    );

    let component = Component::new(&engine, component).expect("filesystem component compiles");
    assert!(
        linker.instantiate_pre(&component).is_ok(),
        "Wasmtime 48 links the standard 0.3.1 filesystem descriptor methods"
    );
}
