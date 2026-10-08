//! Bounded network broker and client, with no VM runtime dependency.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod client;
pub mod config;
mod server;
mod writer;

pub use client::{Client, WriteAdmission};
pub use server::Broker;

pub use terra_protocol::network::{Error, Handle, ListenerGrant, Operation, Reply, ResourceKind};

pub const MAX_RESOURCES: usize = 2 * terra_protocol::vsock::MAX_NETWORK_SOCKETS;
pub const MAX_QUEUED_REQUESTS: usize = 512;
pub const MAX_DNS_REQUESTS: usize = 16;
pub const MAX_NON_DNS_REQUESTS: usize = MAX_QUEUED_REQUESTS / 2 - MAX_DNS_REQUESTS;
pub const MAX_SOCKET_WAIT_REQUESTS: usize = 2 * MAX_RESOURCES + MAX_LISTENERS;
pub const MAX_PENDING_REQUESTS: usize =
    2 * (MAX_SOCKET_WAIT_REQUESTS + MAX_NON_DNS_REQUESTS + MAX_DNS_REQUESTS) + MAX_RESOURCES;
pub const MAX_TCP_WRITE_REQUESTS: usize = 4;
pub const MAX_LISTENERS: usize = 2 * terra_protocol::MAX_PUBLISHED_PORTS;
pub const MAX_RESOLVERS: usize = 8;
pub const MAX_UDP_PEERS: usize = terra_protocol::network::MAX_UDP_PEERS;
pub const MAX_BUFFERED_BYTES: usize = 64 << 20;
pub const MAX_SOCKET_BUFFER_BYTES: u32 = 256 << 10;
const IPC_READ_BUFFER_BYTES: usize =
    writer::MAX_WRITE_BATCH_FRAMES * (terra_protocol::network::MAX_NETWORK_FRAME_BYTES + 4);
const _: () = assert!(
    terra_protocol::network::MAX_NETWORK_READ_BYTES <= terra_limits::NETWORK_TCP_READ_BUFFER_BYTES
);

#[derive(Clone, Copy, PartialEq, Eq)]
enum RequestAdmission {
    SocketWait,
    Active,
    Dns,
}

impl RequestAdmission {
    const fn limit(self) -> usize {
        match self {
            Self::SocketWait => MAX_SOCKET_WAIT_REQUESTS,
            Self::Active => MAX_NON_DNS_REQUESTS,
            Self::Dns => MAX_DNS_REQUESTS,
        }
    }
}

impl From<&Operation> for RequestAdmission {
    fn from(operation: &Operation) -> Self {
        match operation {
            Operation::Accept(_)
            | Operation::Read { .. }
            | Operation::ReceiveDatagram(_)
            | Operation::WaitError(_) => Self::SocketWait,
            Operation::Resolve(_) => Self::Dns,
            Operation::OpenTcp { .. }
            | Operation::OpenUdp
            | Operation::OpenPublishedUdp(_)
            | Operation::WriteAll { .. }
            | Operation::SendDatagrams { .. }
            | Operation::ShutdownWrite(_)
            | Operation::Cancel(_)
            | Operation::Close(_) => Self::Active,
        }
    }
}

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
