//! Shared host interfaces and block component bindings.

wasmtime::component::bindgen!({
    world: "block-device",
    path: "../../components/wit/terra",
    exports: { default: async },
    with: {
        "terra:mmio/types@0.1.0": crate::component::vmm::bindings::types,
    },
});

pub use exports::terra::host::device_api::{Completion, Range};
pub use terra::host::{diagnostics, disk, interrupt, memory};
