//! Vsock component bindings.

wasmtime::component::bindgen!({
    world: "device",
    path: "../../components/vsock/wit",
    exports: { default: async },
    imports: {
        default: trappable,
        "terra:vsock/host-service.[method]client.input": store | trappable,
        "terra:vsock/host-service.listener": store | trappable,
        "terra:vsock/host-service.plan": store | trappable,
        "terra:vsock/host-service.stop": store | trappable,
    },
    with: {
        "terra:mmio/types@0.1.0": crate::component::mmio::bindings::canonical::types,
    },
});

pub(crate) use Device as VsockBindings;
pub use exports::terra::vsock::api::{Error as VsockError, Event as VsockEvent};
pub(crate) use terra as wit;
