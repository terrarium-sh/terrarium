//! Restricted broker authority and network policy for the device frontend.

mod bindings;
mod broker_linker;
mod config;
mod host;

pub(crate) use broker_linker::add as add_broker_to_linker;
pub use config::{HostServiceAddresses, PortMapping};
pub use host::{NetworkBackend, NetworkHost};

#[cfg(any(test, feature = "test-support"))]
pub fn start_test_broker(
    config: terra_network::config::Config,
) -> wasmtime::Result<NetworkBackend> {
    let broker = terra_network::Broker::bind(&config)?;
    let ready = broker.ready();
    let (worker, endpoint) =
        tokio::io::duplex(terra_protocol::network::MAX_NETWORK_FRAME_BYTES * 2);
    tokio::spawn(broker.serve(endpoint));
    Ok(NetworkBackend {
        client: terra_network::Client::new(worker),
        ready,
        listeners: config.listeners,
    })
}
