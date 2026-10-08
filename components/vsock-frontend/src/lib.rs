#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({ world: "device", path: "wit", generate_all });
}

use bindings::{exports, terra, wit_stream};
use std::sync::{
    LazyLock, Mutex,
    atomic::{AtomicBool, Ordering},
};
use terra_vsock_device::VsockSwitch;

mod agent;
mod mmio;
mod network;
mod transport;
mod worker;

static SWITCH: LazyLock<Mutex<VsockSwitch>> = LazyLock::new(|| Mutex::new(VsockSwitch::new()));
static CONFIGURED: AtomicBool = AtomicBool::new(false);
static WORK: terra_device_transport::Doorbell = terra_device_transport::Doorbell::new();

fn switch() -> std::sync::MutexGuard<'static, VsockSwitch> {
    SWITCH
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn wake_worker() {
    WORK.ring(1);
}

async fn wait_for_work() {
    WORK.wait().await;
}

struct Frontend;

impl exports::terra::mmio::device::Guest for Frontend {
    async fn serve(
        requests: wit_bindgen::StreamReader<terra::mmio::types::Request>,
    ) -> wit_bindgen::StreamReader<terra::mmio::types::Reply> {
        mmio::serve(requests).await
    }
}

impl exports::terra::vsock_frontend::api::Guest for Frontend {
    fn configure_device(
        network: Option<terra::network::types::Config>,
    ) -> Result<(), terra::mmio::types::DeviceError> {
        if WORK.is_closed() || CONFIGURED.load(Ordering::Acquire) {
            return Err(terra::mmio::types::DeviceError::NotReady);
        }
        let capacity = network
            .as_ref()
            .map_or(0, |config| config.flow_capacity as usize);
        let is_network_enabled = network.is_some();
        if let Some(config) = network {
            network::configure(config).map_err(|error| match error {
                terra::network::types::Error::Malformed => terra::mmio::types::DeviceError::BadLen,
                terra::network::types::Error::Backpressure => {
                    terra::mmio::types::DeviceError::TooLarge
                }
                terra::network::types::Error::NotReady => terra::mmio::types::DeviceError::NotReady,
            })?;
        }
        CONFIGURED.store(true, Ordering::Release);
        *switch() = VsockSwitch::with_network_socket_capacity(is_network_enabled, capacity);
        transport::configure()
    }

    async fn run() -> Result<(), terra::mmio::types::DeviceError> {
        worker::run().await
    }

    async fn close() {
        WORK.close();
        network::close();
        transport::close();
        wake_worker();
        worker::finish().await;
    }
}

fn reset_device() {
    network::reset();
    transport::reset();
    wake_worker();
}

#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)]
mod component_exports {
    use super::{Frontend, bindings};
    bindings::export!(Frontend with_types_in bindings);
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_tx_descriptors(bytes: &[u8], head: u16, queue_size: u16) {
    transport::fuzz_tx_descriptors(bytes, head, queue_size);
}
