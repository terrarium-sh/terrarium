//! Portable network configuration and address primitives.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

    #[must_use]
    pub const fn gateway_addresses(self) -> [IpAddr; 2] {
        [IpAddr::V4(self.gateway_ip), IpAddr::V6(self.gateway_ip6)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_layout_and_port_mapping_need_no_runtime() {
        let layout = GuestNetworkConfig::default();
        assert_eq!(layout.gateway_ip, Ipv4Addr::new(100, 96, 0, 1));
        assert_eq!(
            layout.gateway_addresses(),
            [
                IpAddr::V4(layout.gateway_ip),
                IpAddr::V6(layout.gateway_ip6),
            ]
        );
        assert_eq!(PortMapping::new(8080, 80).guest, 80);
    }
}
