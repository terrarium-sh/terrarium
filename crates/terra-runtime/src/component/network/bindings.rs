//! Network component bindings.

wasmtime::component::bindgen!({
    world: "device",
    path: "../../components/network/wit",
    exports: { default: async },
    with: {
        "terra:mmio/types@0.1.0": crate::component::vmm::bindings::types,
    },
});

pub(crate) use Device as NetworkComponent;
pub(crate) use exports::terra::network::api::{
    Config as NetworkConfig, Error as NetworkError, PublishedPort,
};
pub(crate) use terra::mmio::types::DeviceError;
