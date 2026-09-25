//! Egress grants and bounded DNS learning.

use crate::address::{Cidr, is_floored, nat64_well_known_v4};
use crate::config::{Network, NetworkMode};
use crate::hostname::normalize_hostname;
use lru::LruCache;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use super::rules::{
    HOST_LOOPBACK_SYMBOL, Port, Rule, is_single_address, name_covers, parse_allow, parse_dns_record,
};

type Result<T> = std::result::Result<T, String>;

pub const LEARNED_ADDRESSES_CAPACITY: usize = 4096;
const LEARNED_DNS_TTL_SECS: u64 = 60;

pub(crate) enum NameLookup {
    Static(Vec<IpAddr>),
    Resolve(String),
    Denied,
}

#[derive(Debug)]
pub struct BoxPolicy {
    mode: NetworkMode,
    address_rules: Vec<(Cidr, Port)>,
    name_rules: Vec<(String, Port)>,
    pub(crate) learned_dns: Mutex<LruCache<(IpAddr, Port), u64>>,
    static_dns: BTreeMap<String, Vec<IpAddr>>,
    host_grants: Vec<Port>,
    host_addresses: Vec<IpAddr>,
    gateway_addresses: [IpAddr; 2],
}

impl BoxPolicy {
    pub fn new(net: &Network, gateway_addresses: [IpAddr; 2]) -> Result<Self> {
        let host_addresses = net
            .host_addresses
            .iter()
            .map(|address| {
                address
                    .parse::<IpAddr>()
                    .map(|address| address.to_canonical())
                    .map_err(|_| "invalid host address".to_owned())
            })
            .collect::<Result<Vec<_>>>()?;
        let static_dns = Self::parse_static_dns(net, &gateway_addresses)?;
        let (address_rules, name_rules, host_grants) =
            Self::parse_allow_rules(net, &static_dns, &gateway_addresses)?;
        Ok(Self {
            mode: net.mode,
            address_rules,
            name_rules,
            learned_dns: Mutex::new(LruCache::new(
                #[allow(clippy::unwrap_used)]
                const {
                    NonZeroUsize::new(LEARNED_ADDRESSES_CAPACITY).unwrap()
                },
            )),
            static_dns,
            host_grants,
            host_addresses,
            gateway_addresses,
        })
    }

    fn parse_static_dns(
        net: &Network,
        gateway_addrs: &[IpAddr; 2],
    ) -> Result<BTreeMap<String, Vec<IpAddr>>> {
        let mut static_dns: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
        for rule in &net.hosts {
            let (key, addrs) = parse_dns_record(rule, gateway_addrs)?;
            if static_dns.insert(key, addrs).is_some() {
                return Err(format!(
                    "duplicate hosts record for '{}': it names the same record as an earlier \
                     rule (a name is matched without case and without a trailing dot)",
                    rule.name
                ));
            }
        }
        Ok(static_dns)
    }

    #[allow(clippy::type_complexity)]
    fn parse_allow_rules(
        net: &Network,
        static_dns: &BTreeMap<String, Vec<IpAddr>>,
        gateway_addrs: &[IpAddr; 2],
    ) -> Result<(Vec<(Cidr, Port)>, Vec<(String, Port)>, Vec<Port>)> {
        let mut address_rules = Vec::new();
        let mut name_rules = Vec::new();
        let mut host_grants = Vec::new();
        for entry in &net.allow {
            match parse_allow(entry)? {
                Rule::Host(port) => host_grants.push(port),
                Rule::Addr(cidr, port) => {
                    if let Some(gw) = gateway_addrs.iter().find(|a| is_single_address(cidr, **a)) {
                        return Err(format!(
                            "allow rule '{entry}': {gw} is the machine terra is running on, \
                             which no address rule opens - write '{HOST_LOOPBACK_SYMBOL}' (with the \
                             same ':PORT', if any) to open the host"
                        ));
                    }
                    address_rules.push((cidr, port));
                }
                Rule::Name(name, port) => {
                    let resolved: Vec<IpAddr> = static_dns
                        .iter()
                        .filter(|(r, _)| name_covers(&name, r))
                        .flat_map(|(_, a)| a)
                        .copied()
                        .collect();
                    if resolved.is_empty() && net.mode == NetworkMode::UnrestrictedPublic {
                        return Err(format!(
                            "allow rule '{entry}' opens nothing under \
                             'mode: unrestricted-public': every public address is already \
                             reachable, and a name resolved upstream cannot open the LAN or \
                             any other floored range (that is what stops a hostile answer \
                             from pointing it there).\n\
                             Write the address itself - 'allow: [10.0.0.5:445]' - or publish \
                             the name with a 'hosts:' record and keep this rule, or switch \
                             to 'mode: allowlist' where a name rule gates public egress."
                        ));
                    }
                    for addr in resolved {
                        if gateway_addrs.contains(&addr) {
                            host_grants.push(port);
                        } else if let Some(cidr) = Cidr::parse(&addr.to_string()) {
                            address_rules.push((cidr, port));
                        }
                    }
                    name_rules.push((name, port));
                }
            }
        }
        Ok((address_rules, name_rules, host_grants))
    }

    #[must_use]
    pub(crate) fn grants_for(&self, name: &str) -> Vec<Port> {
        let Some(name) = normalize_hostname(name) else {
            return Vec::new();
        };
        self.name_rules
            .iter()
            .filter(|(rule, _)| name_covers(rule, &name))
            .map(|(_, grant)| *grant)
            .collect()
    }

    pub(crate) fn static_answer(&self, name: &str) -> Option<&[IpAddr]> {
        self.static_dns
            .get(&normalize_hostname(name)?)
            .map(Vec::as_slice)
    }

    pub(crate) fn accept_resolved(&self, name: &str, addresses: &[IpAddr]) -> Vec<IpAddr> {
        let grants = self.grants_for(name);
        if self.mode == NetworkMode::Allowlist && grants.is_empty() {
            return Vec::new();
        }
        if self.mode == NetworkMode::UnrestrictedPublic {
            return addresses
                .iter()
                .map(IpAddr::to_canonical)
                .filter(|ip| {
                    !is_floored(*ip)
                        && !self.gateway_addresses.contains(ip)
                        && !self.is_host_address(*ip)
                })
                .fold(Vec::new(), |mut accepted, ip| {
                    if !accepted.contains(&ip) {
                        accepted.push(ip);
                    }
                    accepted
                });
        }
        let Ok(mut learned) = self.learned_dns.lock() else {
            return Vec::new();
        };
        let now = crate::monotonic_now();
        let host = self.gateway_addresses;
        let mut accepted = Vec::new();
        for ip in addresses.iter().map(IpAddr::to_canonical) {
            if is_floored(ip) || host.contains(&ip) || self.is_host_address(ip) {
                continue;
            }
            let expires_at = now.saturating_add(LEARNED_DNS_TTL_SECS * 1_000_000_000);
            for grant in &grants {
                let key = (ip, *grant);
                if let Some(previous) = learned.get_mut(&key) {
                    *previous = (*previous).max(expires_at);
                } else {
                    learned.put(key, expires_at);
                }
            }
            if !accepted.contains(&ip) {
                accepted.push(ip);
            }
        }
        accepted
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn forwards(&self, name: &str) -> bool {
        matches!(self.lookup_name(name), NameLookup::Resolve(_))
    }

    #[cfg(test)]
    pub(crate) fn learn_named(&self, name: &str, records: &[(IpAddr, u32)]) {
        let addresses = records
            .iter()
            .map(|(address, _)| *address)
            .collect::<Vec<_>>();
        self.accept_resolved(name, &addresses);
    }

    #[must_use]
    pub(crate) fn lookup_name(&self, name: &str) -> NameLookup {
        let Some(name) = normalize_hostname(name) else {
            return NameLookup::Denied;
        };
        if let Some(ips) = self.static_answer(&name) {
            return NameLookup::Static(ips.to_vec());
        }
        match self.mode {
            NetworkMode::Allowlist if self.grants_for(&name).is_empty() => NameLookup::Denied,
            NetworkMode::UnrestrictedPublic | NetworkMode::Allowlist => NameLookup::Resolve(name),
        }
    }

    fn is_host_address(&self, ip: IpAddr) -> bool {
        self.host_addresses.contains(&ip)
            || matches!(ip, IpAddr::V6(ip) if nat64_well_known_v4(ip).is_some_and(|ip| self.host_addresses.contains(&IpAddr::V4(ip))))
    }

    pub(crate) fn allows(&self, ip: IpAddr, port: Option<u16>) -> bool {
        let ip = ip.to_canonical();
        if self.gateway_addresses.contains(&ip) {
            return false;
        }
        if self
            .address_rules
            .iter()
            .any(|(cidr, grant)| cidr.contains(ip) && (grant.is_none() || *grant == port))
        {
            return true;
        }
        if self.is_host_address(ip) {
            return false;
        }
        if is_floored(ip) {
            return false;
        }
        match self.mode {
            NetworkMode::UnrestrictedPublic => true,
            NetworkMode::Allowlist => self.learned_dns.lock().is_ok_and(|mut learned| {
                let now = crate::monotonic_now();
                [None, port].into_iter().any(|grant| {
                    let key = (ip, grant);
                    if learned
                        .get(&key)
                        .is_some_and(|expires_at| *expires_at > now)
                    {
                        true
                    } else {
                        learned.pop(&key);
                        false
                    }
                })
            }),
        }
    }

    pub(crate) fn host_service_ports(&self) -> &[Option<u16>] {
        &self.host_grants
    }

    pub(crate) fn blocks_direct_dns(&self) -> bool {
        self.mode == NetworkMode::Allowlist || !self.static_dns.is_empty()
    }
}
