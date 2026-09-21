//! Block component bindings.

wasmtime::component::bindgen!({
    world: "block-device",
    path: "../../components/wit/terra",
    exports: { default: async },
    with: {
        "terra:host/memory@0.1.0": crate::component::bindings::memory,
        "terra:host/interrupt@0.1.0": crate::component::bindings::interrupt,
        "terra:host/diagnostics@0.1.0": crate::component::bindings::diagnostics,
        "terra:mmio/types@0.1.0": crate::component::vmm::bindings::types,
    },
});

#[cfg(test)]
pub(crate) use exports::terra::host::device_api::{Completion, Range};
pub(crate) use terra::host::disk;
