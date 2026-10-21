//! Egress grants and bounded DNS learning.

use crate::address::{Cidr, is_floored, nat64_well_known_v4};
use crate::config::{Network, NetworkMode, StaticDnsRecord};
use crate::hostname::normalize_hostname;
use lru::LruCache;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Mutex;

use super::rules::{
    HOST_LOOPBACK_SYMBOL, Port, Rule, is_host_loopback, name_covers, parse_allow, parse_dns_record,
};

type Result<T> = std::result::Result<T, String>;

pub(crate) const LEARNED_ADDRESSES_CAPACITY: usize = 4096;
pub const LEARNED_DNS_TTL_SECS: u64 = 60;

#[derive(Debug)]
pub enum NameLookup<'a> {
    Static(&'a [IpAddr]),
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
    clock: fn() -> u64,
}

impl BoxPolicy {
    pub fn new(net: &Network, gateway_addresses: [IpAddr; 2]) -> Result<Self> {
        Self::with_clock(net, gateway_addresses, monotonic_now)
    }

    pub fn with_clock(
        net: &Network,
        gateway_addresses: [IpAddr; 2],
        clock: fn() -> u64,
    ) -> Result<Self> {
        net.validate_limits()?;
        let mut policy = Self {
            mode: net.mode,
            address_rules: Vec::new(),
            name_rules: Vec::new(),
            learned_dns: Mutex::new(LruCache::new(
                #[allow(clippy::unwrap_used)]
                const {
                    NonZeroUsize::new(LEARNED_ADDRESSES_CAPACITY).unwrap()
                },
            )),
            static_dns: BTreeMap::new(),
            host_grants: Vec::new(),
            host_addresses: net
                .host_addresses
                .iter()
                .map(IpAddr::to_canonical)
                .collect(),
            gateway_addresses,
            clock,
        };
        for record in &net.hosts {
            policy.add_dns_record(record)?;
        }
        for entry in &net.allow {
            policy.add_allow_rule(entry)?;
            if policy.address_rules.len() + policy.host_grants.len() > crate::MAX_EXPANDED_RULES {
                return Err(format!(
                    "network configuration exceeds {} expanded grants",
                    crate::MAX_EXPANDED_RULES
                ));
            }
        }
        Ok(policy)
    }

    fn add_dns_record(&mut self, record: &StaticDnsRecord) -> Result<()> {
        let (key, addrs) = parse_dns_record(record, &self.gateway_addresses)?;
        if self.static_dns.insert(key, addrs).is_some() {
            return Err(format!(
                "duplicate hosts record for '{}': it names the same record as an earlier \
                 rule (a name is matched without case and without a trailing dot)",
                record.name
            ));
        }
        Ok(())
    }

    fn add_allow_rule(&mut self, entry: &str) -> Result<()> {
        let rule = parse_allow(entry)?;
        if matches!(
            rule,
            Rule::Host(Some(53)) | Rule::Addr(_, Some(53)) | Rule::Name(_, Some(53))
        ) && self.blocks_direct_dns()
        {
            return Err(format!(
                "allow rule '{entry}' can never open port 53: with 'mode: allowlist' or \
                 'hosts:' records, all guest DNS goes to terra's built-in resolver, which \
                 answers A and AAAA queries only.\n\
                 Drop the rule, or use 'mode: unrestricted-public' without 'hosts:' \
                 records to query other DNS servers directly."
            ));
        }
        match rule {
            Rule::Host(port) => self.host_grants.push(port),
            Rule::Addr(cidr, port) => {
                if let Some(gateway) = self
                    .gateway_addresses
                    .iter()
                    .find(|gateway| Cidr::from(**gateway) == cidr)
                {
                    return Err(format!(
                        "allow rule '{entry}': {gateway} is the machine terra is running on, \
                         which no address rule opens - write '{HOST_LOOPBACK_SYMBOL}' (with the \
                         same ':PORT', if any) to open the host"
                    ));
                }
                self.address_rules.push((cidr, port));
            }
            Rule::Name(name, port) => {
                let resolved: Vec<IpAddr> = self
                    .static_dns
                    .iter()
                    .filter(|(record, _)| name_covers(&name, record))
                    .flat_map(|(_, addrs)| addrs)
                    .copied()
                    .collect();
                if resolved.is_empty() && self.mode == NetworkMode::UnrestrictedPublic {
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
                    if self.gateway_addresses.contains(&addr) {
                        self.host_grants.push(port);
                    } else {
                        self.address_rules.push((addr.into(), port));
                    }
                }
                self.name_rules.push((name, port));
            }
        }
        Ok(())
    }

    pub(crate) fn grants_for(&self, normalized_name: &str) -> Vec<Port> {
        self.name_rules
            .iter()
            .filter(|(rule, _)| name_covers(rule, normalized_name))
            .map(|(_, grant)| *grant)
            .collect()
    }

    pub(crate) fn static_answer(&self, normalized_name: &str) -> Option<&[IpAddr]> {
        self.static_dns.get(normalized_name).map(Vec::as_slice)
    }

    pub fn accept_resolved(&self, name: &str, addresses: &[IpAddr]) -> Vec<IpAddr> {
        let Some(name) = normalize_hostname(name) else {
            return Vec::new();
        };
        let grants = self.grants_for(&name);
        if self.mode == NetworkMode::Allowlist && grants.is_empty() {
            return Vec::new();
        }
        let mut accepted = Vec::new();
        for ip in addresses
            .iter()
            .take(crate::MAX_RESOLVED_ADDRESSES)
            .map(IpAddr::to_canonical)
        {
            if !is_floored(ip)
                && !self.gateway_addresses.contains(&ip)
                && !self.is_host_address(ip)
                && !accepted.contains(&ip)
            {
                accepted.push(ip);
            }
        }
        match self.mode {
            NetworkMode::UnrestrictedPublic => accepted,
            NetworkMode::Allowlist => {
                let Ok(mut learned) = self.learned_dns.lock() else {
                    return Vec::new();
                };
                let expires_at = self
                    .now()
                    .saturating_add(LEARNED_DNS_TTL_SECS * 1_000_000_000);
                for key in accepted
                    .iter()
                    .flat_map(|ip| grants.iter().map(|grant| (*ip, *grant)))
                {
                    if let Some(previous) = learned.get_mut(&key) {
                        *previous = (*previous).max(expires_at);
                    } else {
                        learned.put(key, expires_at);
                    }
                }
                accepted
            }
        }
    }

    #[must_use]
    pub fn lookup_name(&self, name: &str) -> NameLookup<'_> {
        let Some(name) = normalize_hostname(name) else {
            return NameLookup::Denied;
        };
        if let Some(ips) = self.static_answer(&name) {
            return NameLookup::Static(ips);
        }
        match self.mode {
            NetworkMode::Allowlist if self.grants_for(&name).is_empty() => NameLookup::Denied,
            NetworkMode::UnrestrictedPublic | NetworkMode::Allowlist => NameLookup::Resolve(name),
        }
    }

    fn is_host_address(&self, ip: IpAddr) -> bool {
        let nat64_target = match ip {
            IpAddr::V6(ip) => nat64_well_known_v4(ip).map(IpAddr::V4),
            IpAddr::V4(_) => None,
        };
        self.host_addresses.contains(&ip)
            || nat64_target.is_some_and(|target| self.host_addresses.contains(&target))
    }

    pub fn now(&self) -> u64 {
        (self.clock)()
    }

    pub fn authorizes(&self, peer: SocketAddr) -> bool {
        self.authorized_until(peer).is_some()
    }

    /// `None` denies `peer`; `Some(t)` allows it until [`Self::now`] reaches `t`.
    pub fn authorized_until(&self, peer: SocketAddr) -> Option<u64> {
        if peer.port() == 53 && self.blocks_direct_dns() {
            return None;
        }
        if is_host_loopback(peer.ip())
            && self
                .host_grants
                .iter()
                .any(|grant| grant.is_none_or(|port| port == peer.port()))
        {
            return Some(u64::MAX);
        }
        self.allowed_until(peer.ip(), Some(peer.port()))
    }

    pub fn allows(&self, ip: IpAddr, port: Port) -> bool {
        self.allowed_until(ip, port).is_some()
    }

    fn allowed_until(&self, ip: IpAddr, port: Port) -> Option<u64> {
        let ip = ip.to_canonical();
        if self.gateway_addresses.contains(&ip) {
            return None;
        }
        if self
            .address_rules
            .iter()
            .any(|(cidr, grant)| cidr.contains(ip) && (grant.is_none() || *grant == port))
        {
            return Some(u64::MAX);
        }
        if self.is_host_address(ip) || is_floored(ip) {
            return None;
        }
        match self.mode {
            NetworkMode::UnrestrictedPublic => Some(u64::MAX),
            NetworkMode::Allowlist => {
                let mut learned = self.learned_dns.lock().ok()?;
                let now = self.now();
                [None, port]
                    .into_iter()
                    .filter_map(|grant| {
                        let key = (ip, grant);
                        match learned.get(&key) {
                            Some(expires_at) if *expires_at > now => Some(*expires_at),
                            Some(_) | None => {
                                learned.pop(&key);
                                None
                            }
                        }
                    })
                    .max()
            }
        }
    }

    pub fn host_service_ports(&self) -> &[Port] {
        &self.host_grants
    }

    fn blocks_direct_dns(&self) -> bool {
        self.mode == NetworkMode::Allowlist || !self.static_dns.is_empty()
    }
}

pub(crate) fn monotonic_now() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;

    static STARTED: OnceLock<Instant> = OnceLock::new();
    u64::try_from(STARTED.get_or_init(Instant::now).elapsed().as_nanos()).unwrap_or(u64::MAX)
}
