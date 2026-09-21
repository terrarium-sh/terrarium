//! Memory component bindings.

wasmtime::component::bindgen!({
    world: "device",
    path: "../../components/mem/wit",
    debug: false,
    exports: { default: async },
    with: {
        "terra:host/memory@0.1.0": crate::component::bindings::memory,
        "terra:host/interrupt@0.1.0": crate::component::bindings::interrupt,
        "terra:mmio/types@0.1.0": crate::component::vmm::bindings::types,
    },
});

pub(crate) use Device as MemComponent;
pub(crate) use terra as wit;
pub(crate) use terra::mmio::types::DeviceError as MemDeviceError;
