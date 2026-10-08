//! Broker interface bindings.

wasmtime::component::bindgen!({
    world: "broker-host",
    path: "../../components/wit/network",
});

pub(crate) use crate::component::vsock::bindings::terra::network::types::{
    Config as NetworkConfig, PublishedPort, Transport,
};
