use crate::config::{Network, NetworkMode};
use anyhow::{Result, bail};
use lru::LruCache;
use smolvm_network::{Cidr, DnsDecision, FloorMode, Policy, dns, is_floored};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::rules::{
    HOST_LOOPBACK_SYMBOL, Port, Rule, is_single_address, name_covers, parse_allow, parse_dns_record,
};

/// The full multi-tenant floor - not the metadata-only one that leaves the
/// LAN reachable: the host's LAN, every private and CGNAT range, link-local
/// (cloud metadata) and multicast, all denied unless a rule opens them. So
/// the widest posture nobody wrote down is public egress rather than
/// "whatever this machine can reach".
const EGRESS_FLOOR: FloorMode = FloorMode::Strict;

/// Short, so a guest that caches an answer does not hold it past a
/// reconfiguration.
const STATIC_TTL: u32 = 60;

const MIN_LEARNED_TTL: u64 = 60;
const MAX_LEARNED_TTL: u64 = 3600;

/// Ceiling on learned addresses: a workload that controls the DNS for a name a
/// rule covers can mint an entry per answer, and the map lives in the host
/// process, which `hw.mem_mib` does not cap.
pub const LEARNED_ADDRESSES_CAPACITY: usize = 4096;

pub fn describe(net: &Network) -> &'static str {
    match net.mode {
        NetworkMode::UnrestrictedPublic if net.allow.is_empty() => {
            "unrestricted-public (public egress only)"
        }
        NetworkMode::UnrestrictedPublic => "unrestricted-public (public egress + listed rules)",
        NetworkMode::Allowlist if net.allow.is_empty() && net.hosts.is_empty() => {
            "none (allowlist with no rules - nothing gets out, not even DNS)"
        }
        NetworkMode::Allowlist if net.allow.is_empty() => {
            "none (allowlist with no allow rules - the hosts: records resolve, \
             and nothing is reachable)"
        }
        NetworkMode::Allowlist => "allowlist active (deny by default)",
    }
}

/// What a box's recipe grants, as the `smolvm_network::Policy` the gateway
/// consults.
#[derive(Debug)]
pub struct BoxPolicy {
    mode: NetworkMode,
    address_rules: Vec<(Cidr, Port)>,
    name_rules: Vec<(String, Port)>,
    pub(crate) learned_dns: Mutex<LruCache<(IpAddr, Port), Instant>>,
    static_dns: HashMap<String, Vec<IpAddr>>,
    host_grants: Vec<Port>,
}

impl BoxPolicy {
    pub fn new(net: &Network) -> Result<Self> {
        let addrs = HOST_ADDRS;
        let static_dns = Self::parse_static_dns(net, &addrs)?;
        let (address_rules, name_rules, host_grants) =
            Self::parse_allow_rules(net, &static_dns, &addrs)?;
        Ok(Self {
            mode: net.mode,
            address_rules,
            name_rules,
            learned_dns: Mutex::new(LruCache::new(
                #[allow(clippy::unwrap_used)]
                NonZeroUsize::new(LEARNED_ADDRESSES_CAPACITY).unwrap(),
            )),
            static_dns,
            host_grants,
        })
    }

    fn parse_static_dns(
        net: &Network,
        gateway_addrs: &[IpAddr; 2],
    ) -> Result<HashMap<String, Vec<IpAddr>>> {
        let mut static_dns: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for rule in &net.hosts {
            let (key, addrs) = parse_dns_record(rule, gateway_addrs)?;
            if static_dns.insert(key, addrs).is_some() {
                bail!(
                    "duplicate hosts record for '{}': it names the same record as an earlier \
                     rule (a name is matched without case and without a trailing dot)",
                    rule.name
                );
            }
        }
        Ok(static_dns)
    }

    #[allow(clippy::type_complexity)]
    fn parse_allow_rules(
        net: &Network,
        static_dns: &HashMap<String, Vec<IpAddr>>,
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
                        bail!(
                            "allow rule '{entry}': {gw} is the machine terra is running on, \
                             which no address rule opens - write '{HOST_LOOPBACK_SYMBOL}' (with the \
                             same ':PORT', if any) to open the host"
                        );
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
                        bail!(
                            "allow rule '{entry}' opens nothing under \
                             'mode: unrestricted-public': every public address is already \
                             reachable, and a name resolved upstream cannot open the LAN or \
                             any other floored range (that is what stops a hostile answer \
                             from pointing it there).\n\
                             Write the address itself - 'allow: [10.0.0.5:445]' - or publish \
                             the name with a 'hosts:' record and keep this rule, or switch \
                             to 'mode: allowlist' where a name rule gates public egress."
                        );
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
        let Some(name) = dns::normalize_hostname(name) else {
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
            .get(&dns::normalize_hostname(name)?)
            .map(Vec::as_slice)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn forwards(&self, name: &str) -> bool {
        matches!(self.dns_for(name), DnsVerdict::Forward { .. })
    }

    pub(crate) fn learn_named(&self, name: &str, records: &[(IpAddr, u32)]) {
        let grants = self.grants_for(name);
        if grants.is_empty() {
            return;
        }
        let Ok(mut learned) = self.learned_dns.lock() else {
            return;
        };
        let now = Instant::now();
        let host = HOST_ADDRS;
        for (ip, ttl) in records {
            // A learned address is only a resolver's word, and that is where
            // DNS rebinding aims, so the floor and the host stay closed to it.
            if is_floored(*ip, EGRESS_FLOOR) || host.contains(ip) {
                continue;
            }
            let expires_at =
                now + Duration::from_secs(u64::from(*ttl).clamp(MIN_LEARNED_TTL, MAX_LEARNED_TTL));
            for grant in &grants {
                let key = (*ip, *grant);
                if let Some(prev) = learned.get(&key) {
                    let max = (*prev).max(expires_at);
                    learned.put(key, max);
                } else {
                    learned.put(key, expires_at);
                }
            }
        }
    }

    #[must_use]
    pub(crate) fn dns_for(&self, name: &str) -> DnsVerdict {
        if let Some(ips) = self.static_answer(name) {
            return DnsVerdict::Answer(ips.to_vec());
        }
        match self.mode {
            // Nothing filtered, nothing learned: every public address is
            // already reachable, and a learned one cannot cross the floor
            // (see [`Self::learn_named`]).
            NetworkMode::UnrestrictedPublic => DnsVerdict::Forward { learn: false },
            NetworkMode::Allowlist if self.grants_for(name).is_empty() => DnsVerdict::Refuse,
            NetworkMode::Allowlist => DnsVerdict::Forward { learn: true },
        }
    }
}

/// The gateway's v4 and ULA endpoints, what `HOST_LOOPBACK` grants.
pub(crate) const HOST_ADDRS: [IpAddr; 2] = {
    let layout = smolvm_network::GuestNetworkConfig::default();
    [
        IpAddr::V4(layout.gateway_ip),
        IpAddr::V6(layout.gateway_ip6),
    ]
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DnsVerdict {
    Answer(Vec<IpAddr>),
    Forward { learn: bool },
    Refuse,
}

impl BoxPolicy {
    pub(crate) fn is_granted(&self, ip: IpAddr, port: Option<u16>) -> bool {
        if HOST_ADDRS.contains(&ip) {
            return self.host_grants.iter().any(|g| g.is_none() || *g == port);
        }
        if self
            .address_rules
            .iter()
            .any(|(cidr, grant)| cidr.contains(ip) && (grant.is_none() || *grant == port))
        {
            return true;
        }
        if is_floored(ip, EGRESS_FLOOR) {
            return false;
        }
        match self.mode {
            NetworkMode::UnrestrictedPublic => true,
            // A poisoned lock denies rather than propagates - the safe half.
            NetworkMode::Allowlist => self.learned_dns.lock().is_ok_and(|learned| {
                let now = Instant::now();
                [None, port].into_iter().any(|grant| {
                    learned
                        .peek(&(ip, grant))
                        .is_some_and(|expires_at| *expires_at > now)
                })
            }),
        }
    }
}

impl Policy for BoxPolicy {
    fn allows(&self, ip: IpAddr, port: Option<u16>) -> bool {
        if self.is_granted(ip, port) {
            log::trace!(
                "terra: egress: allowed {ip}{}",
                port.map_or_else(String::new, |port| format!(":{port}"))
            );
            return true;
        }
        log::warn!(
            "terra: egress: blocked {ip}{} - no rule names it",
            port.map_or_else(String::new, |port| format!(":{port}"))
        );
        false
    }

    fn rewrite(&self, ip: IpAddr) -> Option<IpAddr> {
        HOST_ADDRS.contains(&ip).then_some(match ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        })
    }

    fn dns(&self, query: &[u8]) -> DnsDecision {
        let Some(name) = dns::question_name(query) else {
            return DnsDecision::Immediate(dns::error_response(query, dns::DNS_RCODE_SERVFAIL));
        };
        match self.dns_for(&name) {
            DnsVerdict::Answer(ips) => {
                DnsDecision::Immediate(dns::build_ip_response(query, &ips, STATIC_TTL))
            }
            DnsVerdict::Forward { learn } => DnsDecision::Forward { learn },
            DnsVerdict::Refuse => {
                // Answered, not forwarded: without this the box would see an
                // unresolvable name and no reason why.
                log::warn!("terra: egress: no allow rule names '{name}' - answered NXDOMAIN");
                DnsDecision::Immediate(dns::error_response(query, dns::DNS_RCODE_NXDOMAIN))
            }
        }
    }

    fn learn(&self, answer: &[u8]) {
        // The response echoes its question; the echoed name only selects
        // among rules that already exist.
        let Some(name) = dns::question_name(answer) else {
            return;
        };
        self.learn_named(&name, &dns::answer_ip_records(answer));
    }

    fn intercepts_dns(&self) -> bool {
        // Every allowlist box: TCP/53 to an allowed resolver could carry names
        // the rules refuse - the query itself is the leak. And any box
        // answering names itself, or the guest's own resolver would win.
        self.mode == NetworkMode::Allowlist || !self.static_dns.is_empty()
    }
}
