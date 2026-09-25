#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use terra::BoxPolicy;
use terra::config::{Network, NetworkMode, StaticDnsRecord};
use terra_runtime::component::network::{GuestNetworkConfig, NameLookup, Policy};

#[allow(dead_code)]
#[path = "../../components/policy/src/address.rs"]
mod address;
#[path = "../../components/policy/src/hostname.rs"]
mod hostname;
use address::is_floored;

#[derive(Arbitrary, Debug)]
enum Address {
    V4([u8; 4]),
    V6([u8; 16]),
    Mapped([u8; 4]),
    Special(u8),
}

impl Address {
    fn ip(&self) -> IpAddr {
        match *self {
            Self::V4(bytes) => Ipv4Addr::from(bytes).into(),
            Self::V6(bytes) => Ipv6Addr::from(bytes).into(),
            Self::Mapped(bytes) => Ipv4Addr::from(bytes).to_ipv6_mapped().into(),
            Self::Special(index) => {
                let layout = GuestNetworkConfig::default();
                let choices = [
                    layout.gateway_ip.into(),
                    layout.gateway_ip6.into(),
                    Ipv4Addr::LOCALHOST.into(),
                    Ipv6Addr::LOCALHOST.into(),
                    Ipv4Addr::new(169, 254, 169, 254).into(),
                    Ipv4Addr::new(10, 0, 0, 1).into(),
                    Ipv4Addr::new(192, 0, 2, 1).into(),
                    Ipv4Addr::new(224, 0, 0, 1).into(),
                    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(),
                    Ipv4Addr::new(1, 1, 1, 1).into(),
                    layout.gateway_ip.to_ipv6_mapped().into(),
                ];
                choices[usize::from(index) % choices.len()]
            }
        }
    }
}

#[derive(Arbitrary, Debug)]
enum Step {
    Resolve(u8, Vec<Address>),
    Check(Address, Option<u16>),
    Lookup(String),
}

fn check_host(policy: &BoxPolicy) {
    let layout = GuestNetworkConfig::default();
    for address in [
        IpAddr::V4(layout.gateway_ip),
        IpAddr::V6(layout.gateway_ip6),
        IpAddr::V6(layout.gateway_ip.to_ipv6_mapped()),
    ] {
        for port in [None, Some(0), Some(22), Some(443), Some(u16::MAX)] {
            assert!(!policy.allows(address, port));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Exercise recipe parsing separately so rejected syntax cannot starve the state machine.
    if let Ok(network) = serde_json::from_slice::<Network>(data)
        && let Ok(policy) = BoxPolicy::new(&network)
    {
        check_host(&policy);
    }
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(policy) = BoxPolicy::new(&Network {
            allow: text.lines().take(16).map(str::to_owned).collect(),
            ..Network::default()
        })
    {
        check_host(&policy);
    }
    let mut input = Unstructured::new(data);
    let Ok((open, port, grant_host)) = input.arbitrary::<(bool, u16, bool)>() else {
        return;
    };
    let port = port.max(1);
    let mut network = Network {
        mode: if open {
            NetworkMode::UnrestrictedPublic
        } else {
            NetworkMode::Allowlist
        },
        allow: if open {
            vec![]
        } else {
            vec![format!("api.test:{port}"), "*.svc.test".into()]
        },
        hosts: vec![StaticDnsRecord {
            name: "static.test".into(),
            addr: "10.0.0.5".into(),
        }],
        ..Network::default()
    };
    if grant_host {
        network.allow.push("HOST_LOOPBACK:443".into());
    }
    let Ok(policy) = BoxPolicy::new(&network) else {
        return;
    };
    let Ok(isolated) = BoxPolicy::new(&Network::default()) else {
        return;
    };
    let mut learned = HashSet::new();
    check_host(&policy);
    let Ok(steps) = input.arbitrary_iter::<Step>() else {
        return;
    };
    for step in steps.take(64) {
        match step {
            Ok(Step::Resolve(selector, addresses)) => {
                let (name, grant) = match selector % 4 {
                    0 => ("API.TEST.", Some(Some(port))),
                    1 => ("child.svc.test", Some(None)),
                    2 => ("evil.test", None),
                    _ => ("svc.test", None),
                };
                let addresses: Vec<_> = addresses.iter().take(16).map(Address::ip).collect();
                let mut expected = Vec::new();
                for ip in addresses.iter().map(IpAddr::to_canonical) {
                    if (open || grant.is_some()) && !is_floored(ip) && !expected.contains(&ip) {
                        expected.push(ip);
                        if let Some(grant) = grant {
                            learned.insert((ip, grant));
                        }
                    }
                }
                assert_eq!(policy.accept_resolved(name, &addresses), expected);
                for ip in expected {
                    assert!(!isolated.allows(ip, Some(port)));
                    assert!(policy.allows(ip, Some(port)));
                }
            }
            Ok(Step::Check(address, query_port)) => {
                let ip = address.ip();
                let canonical = ip.to_canonical();
                let layout = GuestNetworkConfig::default();
                let host = canonical == IpAddr::V4(layout.gateway_ip)
                    || canonical == IpAddr::V6(layout.gateway_ip6);
                let expected = if host {
                    false
                } else {
                    !is_floored(canonical)
                        && (open
                            || learned.contains(&(canonical, None))
                            || learned.contains(&(canonical, query_port)))
                };
                assert_eq!(policy.allows(ip, query_port), expected);
                assert_eq!(
                    policy.allows(ip, query_port),
                    policy.allows(canonical, query_port)
                );
            }
            Ok(Step::Lookup(name)) => {
                let lookup = policy.lookup_name(&name);
                let Some(normalized) = hostname::normalize_hostname(&name) else {
                    assert!(matches!(lookup, NameLookup::Denied));
                    continue;
                };
                let allowed = normalized == "api.test"
                    || normalized
                        .strip_suffix(".svc.test")
                        .is_some_and(|prefix| !prefix.is_empty());
                match lookup {
                    NameLookup::Static(addresses) => {
                        assert_eq!(normalized, "static.test");
                        assert_eq!(addresses, [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))]);
                    }
                    NameLookup::Resolve(resolved_name) => {
                        assert_eq!(resolved_name, normalized);
                        assert!(open || allowed);
                    }
                    NameLookup::Denied => {
                        assert!(!open && !allowed && normalized != "static.test");
                    }
                }
            }
            Err(_) => break,
        }
    }
});
