use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
pub use terra_policy::config::{Network, NetworkMode, StaticDnsRecord};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedListener {
    pub grant: crate::ListenerGrant,
    pub address: SocketAddr,
    pub transport: crate::ResourceKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub policy: terra_policy::config::Network,
    pub listeners: Vec<PublishedListener>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ready {
    pub host_service_ports: Vec<Option<u16>>,
}

pub const GATEWAY_ADDRESSES: [IpAddr; 2] = [
    IpAddr::V4(terra_protocol::socket::HOST_SERVICE_IPV4),
    IpAddr::V6(terra_protocol::socket::HOST_SERVICE_IPV6),
];

/// 48 bytes covers one JSON-quoted IPv6 address and its separator.
pub const MAX_STARTUP_BYTES: usize =
    terra_policy::MAX_CONFIG_BYTES + terra_policy::MAX_HOST_ADDRESSES * 48 + 64 * 1024;
pub const MAX_READY_BYTES: usize = 32 * 1024;
