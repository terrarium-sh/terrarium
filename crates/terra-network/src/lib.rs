//! Bounded network broker and client, with no VM runtime dependency.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod client;
pub mod config;
mod frames;
mod mux;
mod server;

pub use client::{Client, TcpDownload, TcpFlow, TcpUpload, UdpFlow};
pub use server::Broker;

pub use terra_protocol::network::{Error, ListenerGrant, ResourceKind};

pub const MAX_RESOURCES: usize = 2 * terra_protocol::vsock::MAX_NETWORK_SOCKETS;
pub const MAX_DNS_REQUESTS: usize = 16;
pub const MAX_LISTENERS: usize = 2 * terra_protocol::MAX_PUBLISHED_PORTS;
pub const MAX_RESOLVERS: usize = 8;
pub const MAX_UDP_PEERS: usize = terra_protocol::network::MAX_UDP_PEERS;
pub const MAX_SOCKET_BUFFER_BYTES: u32 = 256 << 10;
const MAX_STREAMS: usize = MAX_RESOURCES + MAX_LISTENERS + MAX_DNS_REQUESTS + 16;
const _: () = assert!(
    terra_protocol::network::MAX_NETWORK_READ_BYTES <= terra_limits::NETWORK_TCP_READ_BUFFER_BYTES
);
const _: () =
    assert!(terra_policy::MAX_RESOLVED_ADDRESSES <= terra_protocol::network::MAX_NETWORK_ADDRESSES);

#[allow(clippy::needless_pass_by_value)]
fn map_io_error(error: std::io::Error) -> Error {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => Error::AccessDenied,
        std::io::ErrorKind::ConnectionRefused => Error::ConnectionRefused,
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => {
            Error::ConnectionReset
        }
        std::io::ErrorKind::TimedOut => Error::TimedOut,
        std::io::ErrorKind::InvalidInput => Error::InvalidArgument,
        _ => Error::Io,
    }
}
