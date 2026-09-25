//! Guest network layout and published ports.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::bindings::{NetworkConfig, PublishedPort};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortMapping {
    pub host: u16,
    pub guest: u16,
}

impl PortMapping {
    #[must_use]
    pub const fn new(host: u16, guest: u16) -> Self {
        Self { host, guest }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestNetworkConfig {
    pub guest_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway_ip6: Ipv6Addr,
    pub gateway_mac: [u8; 6],
    pub dns_server: Ipv4Addr,
}

impl GuestNetworkConfig {
    #[must_use]
    pub const fn default() -> Self {
        Self {
            guest_ip: Ipv4Addr::new(100, 96, 0, 2),
            gateway_ip: Ipv4Addr::new(100, 96, 0, 1),
            prefix_len: 30,
            gateway_ip6: Ipv6Addr::new(0xfd53, 0x4d00, 0, 0, 0, 0, 0, 1),
            gateway_mac: [0x02, 0x53, 0x4d, 0x00, 0x00, 0x01],
            dns_server: Ipv4Addr::new(100, 96, 0, 1),
        }
    }

    pub(super) fn into_component_config(
        self,
        host_service_ports: Vec<Option<u16>>,
        port_mappings: Vec<PortMapping>,
    ) -> NetworkConfig {
        NetworkConfig {
            gateway_mac: self.gateway_mac.to_vec(),
            gateway_ip: self.gateway_ip.octets().to_vec(),
            gateway_ip6: self.gateway_ip6.octets().to_vec(),
            host_service_ports,
            published_ports: port_mappings
                .into_iter()
                .map(|mapping| PublishedPort {
                    host_port: mapping.host,
                    guest_port: mapping.guest,
                })
                .collect(),
            mtu: 1500,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_config_uses_the_guest_layout() {
        let layout = GuestNetworkConfig::default();
        let config =
            layout.into_component_config(vec![Some(5432)], vec![PortMapping::new(8080, 80)]);
        assert_eq!(config.gateway_ip, layout.gateway_ip.octets());
        assert_eq!(config.gateway_ip6, layout.gateway_ip6.octets());
        assert_eq!(config.gateway_mac, layout.gateway_mac);
        assert_eq!(config.host_service_ports, [Some(5432)]);
        assert_eq!(config.published_ports[0].host_port, 8080);
        assert_eq!(config.published_ports[0].guest_port, 80);
    }
}
