//! Shared device host interfaces.

wasmtime::component::bindgen!({
    world: "host-interfaces",
    path: "../../components/wit/terra",
});

pub use terra::host::{diagnostics, interrupt, memory};
