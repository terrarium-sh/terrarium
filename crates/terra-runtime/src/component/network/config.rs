//! Synthetic host-service addresses and trusted publication grants.

use std::net::{Ipv4Addr, Ipv6Addr};
use terra_protocol::network::ResourceKind;

use super::bindings::{NetworkConfig, PublishedPort, Transport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortMapping {
    pub host: u16,
    pub guest: u16,
    pub transport: ResourceKind,
}

impl PortMapping {
    #[must_use]
    pub const fn new(host: u16, guest: u16) -> Self {
        Self {
            host,
            guest,
            transport: ResourceKind::Tcp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostServiceAddresses {
    pub gateway_ip: Ipv4Addr,
    pub gateway_ip6: Ipv6Addr,
}

impl HostServiceAddresses {
    #[must_use]
    pub const fn default() -> Self {
        Self {
            gateway_ip: terra_protocol::socket::HOST_SERVICE_IPV4,
            gateway_ip6: terra_protocol::socket::HOST_SERVICE_IPV6,
        }
    }

    pub(crate) fn build_component_config(
        host_service_ports: Vec<Option<u16>>,
        port_mappings: Vec<PortMapping>,
        memory_limit: usize,
    ) -> NetworkConfig {
        NetworkConfig {
            host_service_ports,
            published_ports: port_mappings
                .into_iter()
                .map(|mapping| PublishedPort {
                    host_port: mapping.host,
                    guest_port: mapping.guest,
                    transport: match mapping.transport {
                        ResourceKind::Tcp => Transport::Tcp,
                        ResourceKind::Udp => Transport::Udp,
                    },
                })
                .collect(),
            flow_capacity: flow_capacity(memory_limit),
        }
    }
}

fn flow_capacity(memory_limit: usize) -> u32 {
    u32::try_from(
        (memory_limit.saturating_sub(terra_limits::NETWORK_SHARED_MEMORY_BYTES)
            / terra_limits::NETWORK_FLOW_MEMORY_BYTES)
            .min(terra_protocol::vsock::MAX_NETWORK_SOCKETS),
    )
    .unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_capacity_reserves_shared_memory_and_scales_with_buffer_cost() {
        for (memory_mib, expected) in [
            (0, 0),
            (8, 0),
            (16, 42),
            (32, 128),
            (200, 1024),
            (400, 1024),
        ] {
            assert_eq!(flow_capacity(memory_mib << 20), expected);
        }
    }

    #[test]
    fn component_config_preserves_grants_and_memory_capacity() {
        let config = HostServiceAddresses::build_component_config(
            vec![Some(5432)],
            vec![
                PortMapping::new(8080, 80),
                PortMapping {
                    host: 8080,
                    guest: 53,
                    transport: ResourceKind::Udp,
                },
            ],
            crate::box_runtime::NETWORK_FRONTEND_MEMORY_BYTES,
        );
        assert_eq!(config.flow_capacity, 1024);
        assert_eq!(config.host_service_ports, [Some(5432)]);
        assert_eq!(config.published_ports[0].host_port, 8080);
        assert_eq!(config.published_ports[0].guest_port, 80);
        assert_eq!(config.published_ports[0].transport, Transport::Tcp);
        assert_eq!(config.published_ports[1].transport, Transport::Udp);
        assert_eq!(config.published_ports[1].guest_port, 53);
    }
}
