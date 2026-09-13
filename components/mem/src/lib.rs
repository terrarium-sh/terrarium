#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({ world: "device", path: "wit", generate_all });
}
use bindings::{exports, terra, wit_stream};

mod mmio;
mod transport;

use exports::terra::mem::transport::Guest;
use terra::mmio::types::DeviceError;

struct Mem;

impl exports::terra::mmio::device::Guest for Mem {
    async fn serve(
        requests: wit_bindgen::rt::async_support::StreamReader<terra::mmio::types::Request>,
    ) -> wit_bindgen::rt::async_support::StreamReader<terra::mmio::types::Reply> {
        mmio::serve(requests).await
    }
}

impl Guest for Mem {
    fn configure() -> Result<(), DeviceError> {
        transport::configure()
    }

    async fn run() -> Result<(), DeviceError> {
        transport::run().await
    }
}

#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)]
mod component_exports {
    use super::{Mem, bindings};
    bindings::export!(Mem with_types_in bindings);
}
