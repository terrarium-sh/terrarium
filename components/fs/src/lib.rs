#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({ world: "device", path: "wit", generate_all });
}
use bindings::{exports, terra, wasi, wit_stream};

mod host;
mod mmio;
mod transport;
pub mod wire;

struct Fs;

impl exports::terra::mmio::device::Guest for Fs {
    async fn serve(
        requests: wit_bindgen::rt::async_support::StreamReader<terra::mmio::types::Request>,
    ) -> wit_bindgen::rt::async_support::StreamReader<terra::mmio::types::Reply> {
        mmio::serve(requests).await
    }
}

impl exports::terra::fs::transport::Guest for Fs {
    async fn configure(tag: String, max_nodes: u32) -> Result<(), terra::mmio::types::DeviceError> {
        transport::configure(&tag, max_nodes).await
    }

    async fn run() -> Result<(), terra::mmio::types::DeviceError> {
        transport::run().await
    }
}

#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)]
mod component_exports {
    use super::{Fs, bindings};
    bindings::export!(Fs with_types_in bindings);
}
