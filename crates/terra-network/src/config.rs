use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
pub use terra_policy::config::{Network, NetworkMode, StaticDnsRecord};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub resources: usize,
    pub pending_requests: usize,
    pub buffered_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            resources: crate::MAX_RESOURCES,
            pending_requests: crate::MAX_PENDING_REQUESTS,
            buffered_bytes: crate::MAX_BUFFERED_BYTES,
        }
    }
}

impl Limits {
    pub fn validate(&self) -> std::io::Result<()> {
        if self.resources == 0
            || self.resources > crate::MAX_RESOURCES
            || self.pending_requests == 0
            || self.pending_requests > crate::MAX_PENDING_REQUESTS
            || self.buffered_bytes > crate::MAX_BUFFERED_BYTES
            || (self.pending_requests.min(crate::MAX_NON_DNS_REQUESTS)
                + self.pending_requests.min(crate::MAX_QUEUED_REQUESTS)
                + 6
                + crate::writer::MAX_WRITE_BATCH_FRAMES)
                * terra_protocol::network::MAX_NETWORK_FRAME_BYTES
                + crate::IPC_READ_BUFFER_BYTES
                > self.buffered_bytes
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid broker resource, request, or buffer budget",
            ));
        }
        Ok(())
    }
}

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
    pub gateways: [IpAddr; 2],
    pub listeners: Vec<PublishedListener>,
    pub limits: Limits,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ready {
    pub version: u32,
    pub host_service_ports: Vec<Option<u16>>,
    pub blocks_direct_dns: bool,
}

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_STARTUP_BYTES: usize = terra_policy::MAX_CONFIG_BYTES + 64 * 1024;
pub const MAX_READY_BYTES: usize = 32 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_budget_counts_writer_held_frames_while_reply_queue_refills() {
        for pending_requests in [1, crate::MAX_PENDING_REQUESTS] {
            let mut limits = Limits {
                pending_requests,
                buffered_bytes: (pending_requests.min(crate::MAX_NON_DNS_REQUESTS)
                    + pending_requests.min(crate::MAX_QUEUED_REQUESTS)
                    + 6)
                    * terra_protocol::network::MAX_NETWORK_FRAME_BYTES
                    + crate::IPC_READ_BUFFER_BYTES,
                ..Limits::default()
            };
            assert!(limits.validate().is_err());
            limits.buffered_bytes += crate::writer::MAX_WRITE_BATCH_FRAMES
                * terra_protocol::network::MAX_NETWORK_FRAME_BYTES;
            assert!(limits.validate().is_ok());
            limits.buffered_bytes -= 1;
            assert!(limits.validate().is_err());
        }
    }
}
