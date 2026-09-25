//! IP ranges and the default egress floor.

use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Copy, Debug)]
pub enum Cidr {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl Cidr {
    #[must_use]
    pub fn parse(spec: &str) -> Option<Self> {
        let (addr, prefix) = match spec.trim().split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix.parse::<u8>().ok()?)),
            None => (spec.trim(), None),
        };
        let address = addr.parse::<IpAddr>().ok()?;
        let prefix = match (address, prefix) {
            (IpAddr::V6(ip), Some(prefix)) if ip.to_ipv4_mapped().is_some() => {
                Some(prefix.checked_sub(96)?)
            }
            (_, prefix) => prefix,
        };
        match address.to_canonical() {
            IpAddr::V4(ip) => {
                let prefix = prefix.unwrap_or(32);
                if prefix > 32 {
                    return None;
                }
                let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
                Some(Self::V4 {
                    network: u32::from(ip) & mask,
                    mask,
                })
            }
            IpAddr::V6(ip) => {
                let prefix = prefix.unwrap_or(128);
                if prefix > 128 {
                    return None;
                }
                let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
                Some(Self::V6 {
                    network: u128::from(ip) & mask,
                    mask,
                })
            }
        }
    }

    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { network, mask }, IpAddr::V4(ip)) => (u32::from(ip) & mask) == *network,
            (Self::V6 { network, mask }, IpAddr::V6(ip)) => (u128::from(ip) & mask) == *network,
            _ => false,
        }
    }
}

#[must_use]
pub fn is_floored(ip: IpAddr) -> bool {
    if let Some(ip) = embedded_ipv4(ip) {
        return !is_global_v4(ip);
    }
    match ip.to_canonical() {
        IpAddr::V4(ip) => !is_global_v4(ip),
        IpAddr::V6(ip) => !is_global_v6(ip),
    }
}

fn embedded_ipv4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(ip) => ip.to_ipv4().or_else(|| {
            matches!(ip.segments(), [0, 0, 0, 0, 0xffff, 0, ..]).then(|| {
                let octets = ip.octets();
                Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15])
            })
        }),
    }
}

fn is_global_v4(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    !(a == 0
        || ip.is_private()
        || (a == 100 && (64..128).contains(&b))
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || (a == 192 && b == 0 && c == 0 && d != 9 && d != 10)
        || matches!([a, b, c], [192, 0, 2] | [198, 51, 100] | [203, 0, 113])
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (18..20).contains(&b))
        || a >= 240
        || ip.is_broadcast())
}

fn is_global_v6(ip: std::net::Ipv6Addr) -> bool {
    if let Some(ip) = nat64_well_known_v4(ip) {
        return is_global_v4(ip);
    }
    let [a, b, c, ..] = ip.segments();
    !((a & 0xe000) != 0x2000
        || (a == 0x2001
            && b < 0x200
            && !matches!(ip.segments(), [0x2001, 1, 0, 0, 0, 0, 0, 1..=3])
            && !matches!([b, c], [3, _] | [4, 0x112])
            && !(0x20..=0x3f).contains(&b))
        || a == 0x2002
        || (a == 0x2001 && b == 0xdb8)
        || (a == 0x3fff && b < 0x1000))
}

#[must_use]
pub fn nat64_well_known_v4(ip: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let segments = ip.segments();
    matches!(segments, [0x64, 0xff9b, 0, 0, 0, 0, ..]).then(|| {
        let octets = ip.octets();
        std::net::Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Registry classifications from IANA's IPv4 and IPv6 special-purpose registries
    /// (2025-10-09) and IPv6 address-space registry (2025-10-23).
    /// Reserved, deprecated, and conditionally reachable ranges remain floored;
    /// mapped/translated IPv4 destinations inherit the embedded IPv4 classification.
    #[test]
    fn floor_matches_registry_range_boundaries() {
        for (prefix, floored) in [
            ("0.0.0.0/8", true),
            ("10.0.0.0/8", true),
            ("100.64.0.0/10", true),
            ("127.0.0.0/8", true),
            ("169.254.0.0/16", true),
            ("172.16.0.0/12", true),
            ("192.0.0.0/24", true),
            ("192.0.0.9/32", false),
            ("192.0.0.10/32", false),
            ("192.0.2.0/24", true),
            ("192.31.196.0/24", false),
            ("192.52.193.0/24", false),
            ("192.88.99.0/24", true),
            ("192.88.99.2/32", true),
            ("192.168.0.0/16", true),
            ("192.175.48.0/24", false),
            ("198.18.0.0/15", true),
            ("198.51.100.0/24", true),
            ("203.0.113.0/24", true),
            ("224.0.0.0/4", true),
            ("240.0.0.0/4", true),
            ("::/8", true),
            ("::1/128", true),
            ("64:ff9b:1::/48", true),
            ("100::/64", true),
            ("100:0:0:1::/64", true),
            ("100::/8", true),
            ("200::/7", true),
            ("400::/6", true),
            ("800::/5", true),
            ("1000::/4", true),
            ("2000::/3", false),
            ("2001::/23", true),
            ("2001::/32", true),
            ("2001:1::1/128", false),
            ("2001:1::2/128", false),
            ("2001:1::3/128", false),
            ("2001:2::/48", true),
            ("2001:3::/32", false),
            ("2001:4:112::/48", false),
            ("2001:10::/28", true),
            ("2001:20::/28", false),
            ("2001:30::/28", false),
            ("2001:db8::/32", true),
            ("2002::/16", true),
            ("2620:4f:8000::/48", false),
            ("3fff::/20", true),
            ("4000::/3", true),
            ("5f00::/16", true),
            ("6000::/3", true),
            ("8000::/3", true),
            ("a000::/3", true),
            ("c000::/3", true),
            ("e000::/4", true),
            ("f000::/5", true),
            ("f800::/6", true),
            ("fc00::/7", true),
            ("fe00::/9", true),
            ("fe80::/10", true),
            ("fec0::/10", true),
            ("ff00::/8", true),
        ] {
            match Cidr::parse(prefix).expect("CIDR parses") {
                Cidr::V4 { network, mask } => {
                    for bits in [network, network | !mask] {
                        let ip = Ipv4Addr::from(bits);
                        for address in [
                            ip.to_string(),
                            format!("::ffff:{ip}"),
                            format!("::ffff:0:{ip}"),
                            format!("::{ip}"),
                            format!("64:ff9b::{ip}"),
                        ] {
                            assert_eq!(
                                is_floored(address.parse().expect("IP parses")),
                                floored,
                                "{prefix}: {address}"
                            );
                        }
                    }
                }
                Cidr::V6 { network, mask } => {
                    for bits in [network, network | !mask] {
                        let ip = IpAddr::V6(bits.into());
                        assert_eq!(is_floored(ip), floored, "{prefix}: {ip}");
                    }
                }
            }
        }
    }

    #[test]
    fn ipv6_floor_preserves_only_the_global_protocol_exceptions() {
        for (address, floored) in [
            ("2001:1::", true),
            ("2001:1::4", true),
            ("2001:1::1:3", true),
            ("2001:2:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:4::", true),
            ("2001:4:111:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:4:113::", true),
            ("2001:20:1000::", false),
            ("2001:21::", false),
            ("2001:31::", false),
            ("2001:40::", true),
            ("2001:200::", false),
            ("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:db9::", false),
            ("2003::", false),
            ("3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("3fff:1000::", false),
            ("64:ff9b::1.1.1.1", false),
            ("64:ff9a:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("64:ff9b::1:0:0", true),
        ] {
            assert_eq!(
                is_floored(address.parse().expect("IP parses")),
                floored,
                "{address}"
            );
        }
    }

    #[test]
    fn cidr_and_strict_floor_are_portable() {
        let cidr = Cidr::parse("203.0.113.0/24").expect("CIDR parses");
        assert!(cidr.contains("203.0.113.1".parse().expect("IP parses")));
        assert!(is_floored("169.254.169.254".parse().expect("IP parses")));
    }

    #[test]
    fn floor_canonicalizes_and_excludes_non_global_ranges() {
        for address in [
            "::ffff:127.0.0.1",
            "::127.0.0.1",
            "::ffff:0:127.0.0.1",
            "0.0.0.1",
            "192.0.0.1",
            "198.18.0.1",
            "192.88.99.0",
            "192.88.99.255",
            "::ffff:192.88.99.1",
            "64:ff9b::192.88.99.1",
            "fec0::",
            "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:2::1",
            "203.0.113.1",
            "240.0.0.1",
            "2001:db8::1",
            "64:ff9b::10.0.0.1",
            "64:ff9b::169.254.169.254",
        ] {
            assert!(is_floored(address.parse().expect("IP parses")), "{address}");
        }
        for address in ["1.1.1.1", "192.88.98.255", "192.88.100.0", "2001:20::1"] {
            assert!(
                !is_floored(address.parse().expect("IP parses")),
                "{address}"
            );
        }
        assert!(!is_floored("64:ff9b::1.1.1.1".parse().expect("IP parses")));

        let cidr = Cidr::parse("::ffff:1.1.1.1").expect("CIDR parses");
        assert!(cidr.contains("1.1.1.1".parse().expect("IP parses")));
        let cidr = Cidr::parse("::ffff:1.1.1.0/120").expect("CIDR parses");
        assert!(cidr.contains("1.1.1.1".parse().expect("IP parses")));
    }
}
