//! Block component bindings.

wasmtime::component::bindgen!({
    world: "block-device",
    path: "../../components/wit/terra",
    exports: { default: async },
    with: {
        "terra:host/memory@0.1.0": crate::component::bindings::memory,
        "terra:host/interrupt@0.1.0": crate::component::bindings::interrupt,
        "terra:mmio/types@0.1.0": crate::component::mmio::bindings::canonical::types,
    },
});

pub(crate) use terra::host::disk;
