//! The recipe's `network:` section, as the gateway's [`Policy`]: what a box may
//! resolve, and what it may reach.

use crate::config::{Network, NetworkMode, StaticDnsRecord};
use anyhow::{Result, bail};
use smolvm_network::{
    Cidr, DnsDecision, FloorMode, GuestNetworkConfig, Policy, PortMapping, dns, is_floored,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The full multi-tenant floor - not the metadata-only one that leaves the
/// LAN reachable: the host's LAN, every private and CGNAT range, link-local
/// (cloud metadata) and multicast, all denied unless a rule opens them. So
/// the widest posture nobody wrote down is public egress rather than
/// "whatever this machine can reach".
const EGRESS_FLOOR: FloorMode = FloorMode::Strict;

/// The underscore keeps it outside the hostname grammar (RFC 1123), so no
/// real name can collide with it.
const HOST_LOOPBACK_SYMBOL: &str = "HOST_LOOPBACK";

/// The addresses that are the machine terra runs on - the v4/v6 pair plus
/// the EUI-64 link-local `smolvm_network::stack` derives from the same MAC.
#[must_use]
const fn gateway_self_addrs(net: &GuestNetworkConfig) -> [IpAddr; 3] {
    let mac = net.gateway_mac;
    [
        IpAddr::V4(net.gateway_ip),
        IpAddr::V6(net.gateway_ip6),
        IpAddr::V6(Ipv6Addr::new(
            0xfe80,
            0,
            0,
            0,
            u16::from_be_bytes([mac[0] ^ 0x02, mac[1]]),
            u16::from_be_bytes([mac[2], 0xff]),
            u16::from_be_bytes([0xfe, mac[3]]),
            u16::from_be_bytes([mac[4], mac[5]]),
        )),
    ]
}

/// Short, so a guest that caches an answer does not hold it past a
/// reconfiguration.
const STATIC_TTL: u32 = 60;

/// Learned-IP TTL clamp, matching the gateway's own DNS filter.
const MIN_LEARNED_TTL: u64 = 60;
const MAX_LEARNED_TTL: u64 = 3600;

/// Ceiling on learned addresses: a workload that controls the DNS for a name a
/// rule covers can mint an entry per answer, and the map lives in the host
/// process, which `hw.mem_mib` does not cap.
const LEARNED_ADDRESSES_CAPACITY: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Port {
    Any,
    Only(u16),
}

impl Port {
    #[must_use]
    fn covers(self, port: Option<u16>) -> bool {
        match (self, port) {
            (Port::Any, _) => true,
            (Port::Only(granted), Some(dialed)) => granted == dialed,
            (Port::Only(_), None) => false,
        }
    }
}

/// Parse `network.ports` - `"HOST[:GUEST]"`, bare = same on both. The host
/// side always binds `127.0.0.1`.
pub fn parse_port_mappings(ports: &[String]) -> Result<Vec<PortMapping>> {
    let mut mappings: Vec<PortMapping> = Vec::new();
    for spec in ports {
        let (host_port, guest_port) = spec.split_once(':').unwrap_or((spec, spec));
        let parse_port = |text, side| {
            parse_port_number(text).ok_or_else(|| {
                anyhow::anyhow!("invalid published port '{spec}': {side} port must be 1-65535")
            })
        };
        let mapping = PortMapping::new(
            parse_port(host_port, "host")?,
            parse_port(guest_port, "guest")?,
        );
        if let Some(earlier) = mappings.iter().find(|m| m.host == mapping.host) {
            bail!(
                "published port '{spec}': host port {} already carries guest port {}",
                mapping.host,
                earlier.guest
            );
        }
        mappings.push(mapping);
    }
    Ok(mappings)
}

/// 1-65535; no 0, which would read as "every port" somewhere down the line.
fn parse_port_number(text: &str) -> Option<u16> {
    text.trim().parse::<u16>().ok().filter(|port| *port != 0)
}

/// Refuse a `network:` section the gateway could not be built from - at
/// recipe time, the only place anyone is listening: the gateway is built
/// mid-boot, after `terra setup` pinned the recipe and the `y` was given.
/// This builds exactly what a boot would and throws it away.
pub fn validate(net: &Network) -> Result<()> {
    BoxPolicy::new(net, &GuestNetworkConfig::default()).map(drop)
}

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
    learned_dns: Mutex<HashMap<(IpAddr, Port), Instant>>,
    static_dns: HashMap<String, Vec<IpAddr>>,
    host_grants: Vec<Port>,
    host: [IpAddr; 3],
}

impl BoxPolicy {
    pub fn new(net: &Network, guest_net: &GuestNetworkConfig) -> Result<Self> {
        let gateway_addrs = gateway_self_addrs(guest_net);
        let mut static_dns: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for rule in &net.hosts {
            let (key, addrs) = parse_dns_record(rule, &gateway_addrs)?;
            if static_dns.insert(key, addrs).is_some() {
                bail!(
                    "duplicate hosts record for '{}': it names the same record as an earlier \
                     rule (a name is matched without case and without a trailing dot)",
                    rule.name
                );
            }
        }

        let mut address_rules = Vec::new();
        let mut name_rules = Vec::new();
        let mut host_grants = Vec::new();
        for entry in &net.allow {
            match parse_allow(entry)? {
                Rule::Host(port) => host_grants.push(port),
                Rule::Addr(cidr, port) => {
                    match gateway_addrs
                        .iter()
                        .find(|host_addr| is_single_address(cidr, **host_addr))
                    {
                        Some(gw) => bail!(
                            "allow rule '{entry}': {gw} is the machine terra is running on, \
                             which no address rule opens - write '{HOST_LOOPBACK_SYMBOL}' (with the \
                             same ':PORT', if any) to open the host"
                        ),
                        None => address_rules.push((cidr, port)),
                    }
                }
                Rule::Name(name, port) => {
                    let resolved_addrs: Vec<IpAddr> = static_dns
                        .iter()
                        .filter(|(record, _)| name_covers(&name, record))
                        .flat_map(|(_, addrs)| addrs)
                        .copied()
                        .collect();
                    if resolved_addrs.is_empty() && net.mode == NetworkMode::UnrestrictedPublic {
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
                    for addr in resolved_addrs {
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

        Ok(Self {
            mode: net.mode,
            address_rules,
            name_rules,
            learned_dns: Mutex::new(HashMap::new()),
            static_dns,
            host_grants,
            host: gateway_addrs,
        })
    }

    #[must_use]
    fn grants_for(&self, name: &str) -> Vec<Port> {
        let Some(name) = dns::normalize_hostname(name) else {
            return Vec::new();
        };
        self.name_rules
            .iter()
            .filter(|(rule, _)| name_covers(rule, &name))
            .map(|(_, grant)| *grant)
            .collect()
    }

    #[must_use]
    fn is_restricted(&self) -> bool {
        self.mode == NetworkMode::Allowlist
    }

    fn static_answer(&self, name: &str) -> Option<&[IpAddr]> {
        self.static_dns
            .get(&dns::normalize_hostname(name)?)
            .map(Vec::as_slice)
    }

    #[cfg(test)]
    #[must_use]
    fn forwards(&self, name: &str) -> bool {
        matches!(self.dns_for(name), DnsVerdict::Forward { .. })
    }

    fn learn_named(&self, name: &str, records: &[(IpAddr, u32)]) {
        let grants = self.grants_for(name);
        if grants.is_empty() {
            return;
        }
        let Ok(mut learned) = self.learned_dns.lock() else {
            return;
        };
        let now = Instant::now();
        learned.retain(|_, expires_at| *expires_at > now);
        for (ip, ttl) in records {
            // A learned address is only a resolver's word, and that is where
            // DNS rebinding aims, so the floor and the host stay closed to it.
            if is_floored(*ip, EGRESS_FLOOR) || self.host.contains(ip) {
                continue;
            }
            let expires_at =
                now + Duration::from_secs(u64::from(*ttl).clamp(MIN_LEARNED_TTL, MAX_LEARNED_TTL));
            for grant in &grants {
                // ponytail: O(n) scan, only once the cap is reached - a heap
                // keyed by expiry would pay for itself only at a far larger cap.
                if learned.len() >= LEARNED_ADDRESSES_CAPACITY
                    && !learned.contains_key(&(*ip, *grant))
                    && let Some(soonest) =
                        learned.iter().min_by_key(|(_, at)| **at).map(|(k, _)| *k)
                {
                    learned.remove(&soonest);
                }
                learned
                    .entry((*ip, *grant))
                    .and_modify(|at| *at = (*at).max(expires_at))
                    .or_insert(expires_at);
            }
        }
    }

    #[must_use]
    fn dns_for(&self, name: &str) -> DnsVerdict {
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

#[derive(Debug, PartialEq, Eq)]
enum DnsVerdict {
    Answer(Vec<IpAddr>),
    Forward { learn: bool },
    Refuse,
}

impl BoxPolicy {
    fn is_granted(&self, ip: IpAddr, port: Option<u16>) -> bool {
        if self.host.contains(&ip) {
            return self.host_grants.iter().any(|g| g.covers(port));
        }
        if self
            .address_rules
            .iter()
            .any(|(cidr, grant)| cidr.contains(ip) && grant.covers(port))
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
                [Some(Port::Any), port.map(Port::Only)]
                    .into_iter()
                    .flatten()
                    .any(|grant| {
                        learned
                            .get(&(ip, grant))
                            .is_some_and(|expires_at| *expires_at > now)
                    })
            }),
        }
    }
}

impl Policy for BoxPolicy {
    fn allows(&self, ip: IpAddr, port: Option<u16>) -> bool {
        if self.is_granted(ip, port) {
            log::trace!("terra: egress: allowed {}{}", ip, port_suffix(port));
            return true;
        }
        log::warn!(
            "terra: egress: blocked {}{} - no rule names it",
            ip,
            port_suffix(port)
        );
        false
    }

    fn rewrite(&self, ip: IpAddr) -> Option<IpAddr> {
        self.host.contains(&ip).then_some(match ip {
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
        self.is_restricted() || !self.static_dns.is_empty()
    }
}

#[must_use]
fn port_suffix(port: Option<u16>) -> String {
    port.map_or(String::new(), |p| format!(":{p}"))
}

/// Only a full-length prefix counts: a range containing the gateway is a
/// rule like any other, the exact spelling reads as a grant and is not.
#[must_use]
fn is_single_address(cidr: Cidr, ip: IpAddr) -> bool {
    let full_length = match cidr {
        Cidr::V4 { mask, .. } => mask == u32::MAX,
        Cidr::V6 { mask, .. } => mask == u128::MAX,
    };
    full_length && cidr.contains(ip)
}

#[must_use]
fn name_covers(rule: &str, name: &str) -> bool {
    let Some(parent) = rule.strip_prefix("*.") else {
        return rule == name;
    };
    name.strip_suffix(parent)
        .is_some_and(|sub| sub.ends_with('.') && sub.len() > 1)
}

#[derive(Debug)]
enum Rule {
    Host(Port),
    Addr(Cidr, Port),
    Name(String, Port),
}

/// Parse one `allow:` entry: `HOST[:PORT]`, or `[V6]:PORT`. Everything an
/// entry can be wrong about fails the recipe here rather than leaving a rule
/// that quietly opens more (a dropped port) or nothing at all.
fn parse_allow(entry: &str) -> Result<Rule> {
    let entry = entry.trim();
    let after_wildcard = entry.strip_prefix("*.").unwrap_or(entry);
    if after_wildcard.contains('*') || after_wildcard.is_empty() {
        bail!(
            "allow rule '{entry}': the only wildcard is a leading '*.', which covers \
             the subdomains of what follows - write '*.example.com' for those, or \
             'example.com' for that name exactly, or both to get both"
        );
    }
    let (host, port) = split_host_port(entry)?;
    classify(entry, host, port)
}

fn split_host_port(entry: &str) -> Result<(&str, Port)> {
    let parse_port = |text: &str| {
        parse_port_number(text).map(Port::Only).ok_or_else(|| {
            anyhow::anyhow!("allow rule '{entry}': '{text}' is not a port (1-65535)")
        })
    };
    if let Some(rest) = entry.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .ok_or_else(|| anyhow::anyhow!("allow rule '{entry}': unclosed '['"))?;
        return match suffix.strip_prefix(':') {
            Some(port_text) => Ok((host, parse_port(port_text)?)),
            None if suffix.is_empty() => Ok((host, Port::Any)),
            None => bail!("allow rule '{entry}': trailing '{suffix}' after ']'"),
        };
    }
    match entry.rsplit_once(':') {
        Some((host, port_text)) if !host.is_empty() && !host.contains(':') => {
            Ok((host, parse_port(port_text)?))
        }
        Some((host, port_text))
            if host.parse::<Ipv6Addr>().is_ok() && parse_port_number(port_text).is_some() =>
        {
            bail!(
                "allow rule '{entry}': an un-bracketed IPv6 address ending in ':{port_text}' \
                 could be that address or a ':PORT' suffix - write '[{entry}]' for the \
                 address on every port, or '[{host}]:{port_text}' for port {port_text}"
            )
        }
        _ => Ok((entry, Port::Any)),
    }
}

fn classify(entry: &str, host: &str, port: Port) -> Result<Rule> {
    if host.eq_ignore_ascii_case(HOST_LOOPBACK_SYMBOL) {
        return Ok(Rule::Host(port));
    }
    if host
        .split_once('/')
        .map_or(host, |(addr, _)| addr)
        .parse::<IpAddr>()
        .is_ok()
    {
        let cidr = Cidr::parse(host).ok_or_else(|| {
            anyhow::anyhow!("allow rule '{entry}': prefix length is out of range")
        })?;
        return Ok(Rule::Addr(cidr, port));
    }
    // Normalize the name only; the `*.` rides over it, or the rule would key
    // differently to the query.
    let (wildcard, name_without_wildcard) = match host.strip_prefix("*.") {
        Some(parent) => ("*.", parent),
        None => ("", host),
    };
    let name = dns::normalize_hostname(name_without_wildcard)
        .map(|normalized| format!("{wildcard}{normalized}"))
        .ok_or_else(|| anyhow::anyhow!("allow rule '{entry}': not a name the gateway can match"))?;
    Ok(Rule::Name(name, port))
}

fn parse_dns_record(
    rule: &StaticDnsRecord,
    gateway_addrs: &[IpAddr; 3],
) -> Result<(String, Vec<IpAddr>)> {
    if rule.name.trim().is_empty() {
        bail!("hosts record has an empty 'name'");
    }
    if rule.name.contains('*') {
        bail!(
            "hosts record '{}' cannot use '*': it is answered as a DNS record, so it \
             names one host exactly",
            rule.name
        );
    }
    // A name the gateway cannot key is a record it silently never publishes -
    // fail closed, but say so.
    let key = dns::normalize_hostname(&rule.name).ok_or_else(|| {
        anyhow::anyhow!(
            "hosts record '{}' is not a name the gateway can answer",
            rule.name
        )
    })?;
    let addrs = match rule.addr.trim() {
        addr if addr.eq_ignore_ascii_case(HOST_LOOPBACK_SYMBOL) => gateway_addrs.to_vec(),
        addr => vec![addr.parse().map_err(|_| {
            anyhow::anyhow!(
                "hosts record '{}': '{}' is neither an IP address nor '{HOST_LOOPBACK_SYMBOL}' (the \
                 machine terra is running on)",
                rule.name,
                rule.addr
            )
        })?],
    };
    Ok((key, addrs))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the gateway terra starts is configured with - every address it
    /// answers on itself included - and so what `HOST_LOOPBACK` resolves to
    /// in these tests.
    const HOST_ADDRS: [IpAddr; 3] = gateway_self_addrs(&GuestNetworkConfig::default());

    fn net(mode: NetworkMode, allow: &[&str]) -> Network {
        Network {
            mode,
            allow: allow.iter().map(ToString::to_string).collect(),
            hosts: vec![],
            ports: vec![],
        }
    }

    fn build(network: &Network) -> Result<BoxPolicy> {
        BoxPolicy::new(network, &GuestNetworkConfig::default())
    }

    fn policy(mode: NetworkMode, allow: &[&str]) -> BoxPolicy {
        build(&net(mode, allow)).expect("test policy")
    }

    /// One `hosts:` record. `addr` is an address or the host token.
    fn record(name: &str, addr: &str) -> StaticDnsRecord {
        StaticDnsRecord {
            name: name.into(),
            addr: addr.into(),
        }
    }

    /// A policy with both halves: records, and the rules that open them.
    fn published(mode: NetworkMode, hosts: &[StaticDnsRecord], allow: &[&str]) -> BoxPolicy {
        let mut network = net(mode, allow);
        network.hosts = hosts.to_vec();
        build(&network).expect("test policy")
    }

    fn err_of(network: &Network) -> String {
        build(network)
            .expect_err("this network section must not build")
            .to_string()
    }

    /// A minimal query for `name`, enough for the policy to read the question.
    fn query(name: &str, qtype: u8) -> Vec<u8> {
        let mut bytes = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            bytes.push(u8::try_from(label.len()).expect("test label fits a DNS label"));
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.extend_from_slice(&[0, 0, qtype, 0, 1]); // root, QTYPE, QCLASS=IN
        bytes
    }

    /// An A query for `name`.
    fn query_for(name: &str) -> Vec<u8> {
        query(name, 1)
    }

    #[test]
    fn parse_port_mappings_parse() {
        let mappings = parse_port_mappings(&["8080".into(), "3000:80".into()]).unwrap();
        assert_eq!(mappings[0].host, 8080);
        assert_eq!(mappings[0].guest, 8080);
        assert_eq!(mappings[1].host, 3000);
        assert_eq!(mappings[1].guest, 80);
        assert!(parse_port_mappings(&["0:80".into()]).is_err()); // port 0 rejected
        assert!(parse_port_mappings(&["nope".into()]).is_err());

        // Two rules on one host port: the second bind fails mid-boot, long
        // after the recipe was approved, so the recipe is refused instead.
        let err = parse_port_mappings(&["8080".into(), "8080:90".into()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("already carries"), "{err}");
        assert!(parse_port_mappings(&["8080:80".into(), "8081:80".into()]).is_ok());

        let refused = crate::config::parse_recipe(
            "network:\n  ports: [\"8080\", \"8080:90\"]\n",
            std::path::Path::new("/proj"),
            std::path::Path::new("/proj/r.yaml"),
        )
        .unwrap_err()
        .to_string();
        assert!(refused.contains("already carries"), "{refused}");
    }

    /// An `allow:` rule is respected whatever the floor thinks - that is the
    /// point of writing one. The floor is for what *nobody* wrote down.
    #[test]
    fn an_allow_rule_outranks_the_floor() {
        for mode in [NetworkMode::Allowlist, NetworkMode::UnrestrictedPublic] {
            // A single address, on the port it named and nothing else nearby.
            let one = policy(mode, &["10.0.0.5:5432"]);
            assert!(
                one.allows("10.0.0.5".parse().unwrap(), Some(5432)),
                "{mode:?}"
            );
            assert!(
                !one.allows("10.0.0.5".parse().unwrap(), Some(22)),
                "{mode:?}"
            );
            assert!(
                !one.allows("10.0.0.6".parse().unwrap(), Some(5432)),
                "{mode:?}"
            );
            for held in ["127.0.0.1", "169.254.169.254", "224.0.0.251"] {
                assert!(
                    !one.allows(held.parse().unwrap(), Some(5432)),
                    "{mode:?} {held}"
                );
            }

            // A range is a rule too: the LAN, the loopback and even multicast
            // are reachable when the recipe says so.
            let lan = policy(mode, &["10.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4"]);
            assert!(
                lan.allows("10.0.0.6".parse().unwrap(), Some(22)),
                "{mode:?}"
            );
            assert!(
                lan.allows("127.0.0.1".parse().unwrap(), Some(5432)),
                "{mode:?}"
            );
            assert!(
                lan.allows("224.0.0.251".parse().unwrap(), Some(1900)),
                "{mode:?}"
            );
            assert!(
                !lan.allows("169.254.169.254".parse().unwrap(), Some(80)),
                "{mode:?}"
            );
        }
    }

    /// With nothing written down, the widest mode is *public* egress: the floor
    /// is what makes that claim true.
    #[test]
    fn nothing_unwritten_crosses_the_floor() {
        let open = policy(NetworkMode::UnrestrictedPublic, &[]);
        for held in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.5",
            "192.168.1.1",
            "100.96.0.1",
            "239.255.255.250",
            "ff02::1",
            // …including the IPv4-mapped multicast spelling, which
            // `Ipv6Addr::is_multicast` answers `false` for on its own.
            "::ffff:239.255.255.250",
        ] {
            assert!(
                !open.allows(held.parse().unwrap(), Some(443)),
                "{held} must be floored"
            );
        }
        assert!(open.allows("1.1.1.1".parse().unwrap(), Some(443)));

        // The allowlist reaches nothing at all without a rule - not even DNS.
        let closed = build(&Network::default()).unwrap();
        assert!(closed.is_restricted());
        assert!(closed.intercepts_dns());
        assert!(!closed.allows("1.1.1.1".parse().unwrap(), Some(443)));
        assert!(!closed.forwards("example.com"));
    }

    /// The banner tells the truth about the posture - including that records
    /// grant nothing, so an allowlist with only `hosts:` still lets nothing out.
    #[test]
    fn describe_names_the_posture() {
        let mut open = net(NetworkMode::UnrestrictedPublic, &[]);
        assert_eq!(describe(&open), "unrestricted-public (public egress only)");
        open.allow = vec!["10.0.0.5:5432".into()];
        assert_eq!(
            describe(&open),
            "unrestricted-public (public egress + listed rules)"
        );

        let mut closed = net(NetworkMode::Allowlist, &[]);
        assert!(describe(&closed).contains("not even DNS"));
        // …but a box with records has a resolver, and answering them is the
        // whole point of writing them - only what is *reachable* is nothing.
        closed.hosts = vec![record("db.local", HOST_LOOPBACK_SYMBOL)];
        let with_records = describe(&closed);
        assert!(
            !with_records.contains("not even DNS"),
            "the records are answered: {with_records}"
        );
        assert!(
            with_records.contains("nothing is reachable"),
            "{with_records}"
        );
        closed.allow = vec!["db.local:5432".into()];
        assert_eq!(describe(&closed), "allowlist active (deny by default)");
    }

    /// One allowlist box driven only through the [`Policy`] trait, as the
    /// gateway drives it: resolve, learn from the answer bytes, connect,
    /// rewrite.
    #[test]
    fn allowlist_mode_end_to_end() {
        let p = published(
            NetworkMode::Allowlist,
            &[
                record("db.local", HOST_LOOPBACK_SYMBOL),
                record("nas.local", "10.0.0.5"),
            ],
            &["api.test:443", "db.local:5432", "nas.local:445"],
        );
        assert!(p.intercepts_dns());

        let DnsDecision::Immediate(answer) = p.dns(&query_for("db.local")) else {
            panic!("record not answered")
        };
        assert_eq!(dns::answer_ip_records(&answer)[0].0, HOST_ADDRS[0]);
        let DnsDecision::Immediate(aaaa) = p.dns(&query("db.local", 28)) else {
            panic!("record not answered")
        };
        assert_eq!(dns::answer_ip_records(&aaaa)[0].0, HOST_ADDRS[1]);

        // A listed public name forwards; its answer, fed back through `learn`,
        // opens the address it carried on the rule's port.
        let api_query = query_for("api.test");
        assert!(matches!(
            p.dns(&api_query),
            DnsDecision::Forward { learn: true }
        ));
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        p.learn(&dns::build_ip_response(&api_query, &[ip], 300));
        assert!(p.allows(ip, Some(443)));
        assert!(!p.allows(ip, Some(80)));

        // The same answer under a name nobody listed teaches nothing.
        let other: IpAddr = "5.5.5.5".parse().unwrap();
        p.learn(&dns::build_ip_response(
            &query_for("evil.test"),
            &[other],
            300,
        ));
        assert!(!p.allows(other, Some(443)));
        p.learn(&[0, 1, 2]);

        // The records' grants: the host on 5432 dialed at the loopback, the
        // NAS on 445 dialed as itself.
        assert!(p.allows(HOST_ADDRS[0], Some(5432)));
        assert!(!p.allows(HOST_ADDRS[0], Some(22)));
        assert!(p.rewrite(HOST_ADDRS[0]).is_some_and(|ip| ip.is_loopback()));
        let nas: IpAddr = "10.0.0.5".parse().unwrap();
        assert!(p.allows(nas, Some(445)));
        assert_eq!(p.rewrite(nas), None);

        // Everything unlisted: no resolution, no connection.
        assert!(matches!(
            p.dns(&query_for("exfil.example")),
            DnsDecision::Immediate(_)
        ));
        assert!(!p.allows("1.1.1.1".parse().unwrap(), Some(443)));
    }

    /// The same lifecycle under `unrestricted-public`: public egress needs no
    /// rules; the floor and the host still do.
    #[test]
    fn unrestricted_public_mode_end_to_end() {
        let p = published(
            NetworkMode::UnrestrictedPublic,
            &[record("db.local", HOST_LOOPBACK_SYMBOL)],
            &["db.local:5432", "10.0.0.5:445"],
        );
        // Records are answered here, so DNS is still intercepted…
        assert!(p.intercepts_dns());
        assert!(matches!(
            p.dns(&query_for("db.local")),
            DnsDecision::Immediate(_)
        ));
        // …while every other name forwards, unlearned.
        assert!(matches!(
            p.dns(&query_for("anything.test")),
            DnsDecision::Forward { learn: false }
        ));

        // Public is open by default; the floor and the host are not.
        assert!(p.allows("1.1.1.1".parse().unwrap(), Some(443)));
        assert!(!p.allows("192.168.1.1".parse().unwrap(), Some(443)));
        assert!(!p.allows(HOST_ADDRS[0], Some(22)));

        // The rules still mean what they say: the record's port on the host,
        // the written address across the floor.
        assert!(p.allows(HOST_ADDRS[0], Some(5432)));
        assert!(p.rewrite(HOST_ADDRS[0]).is_some_and(|ip| ip.is_loopback()));
        assert!(p.allows("10.0.0.5".parse().unwrap(), Some(445)));
    }

    /// The four routes a query can take - each a decision about whether a name,
    /// and so the data in it, leaves the box.
    #[test]
    fn a_query_is_answered_forwarded_or_refused() {
        let mut network = net(NetworkMode::Allowlist, &["api.test:443"]);
        network.hosts = vec![record("db.local", HOST_LOOPBACK_SYMBOL)];
        let p = build(&network).unwrap();

        // Answered here: the record's own address, never sent upstream.
        let DnsDecision::Immediate(answer) = p.dns(&query_for("db.local")) else {
            panic!("a hosts record must be answered by the gateway")
        };
        assert_eq!(
            dns::answer_ip_records(&answer)
                .iter()
                .map(|(ip, _)| *ip)
                .collect::<Vec<_>>(),
            vec![HOST_ADDRS[0]],
            "an A query gets the v4 answer only"
        );

        // A listed name goes upstream, and its answer is learned - but not its
        // subdomains: a name is exact unless the rule says `*.`.
        assert!(matches!(
            p.dns(&query_for("api.test")),
            DnsDecision::Forward { learn: true }
        ));
        assert!(matches!(
            p.dns(&query_for("v2.api.test")),
            DnsDecision::Immediate(_)
        ));

        // Nothing else resolves at all: NXDOMAIN, not a forwarded query. This is
        // the exfiltration channel - the query itself carries the payload.
        for refused in ["payload.db.local", "exfil.example"] {
            assert!(
                matches!(p.dns(&query_for(refused)), DnsDecision::Immediate(_)),
                "{refused}"
            );
        }
        assert!(matches!(p.dns(&[0, 1, 2]), DnsDecision::Immediate(_)));

        // The wide mode filters nothing and learns nothing: it has no allow-list
        // to be exclusive against.
        let open = policy(NetworkMode::UnrestrictedPublic, &[]);
        assert!(matches!(
            open.dns(&query_for("anything.test")),
            DnsDecision::Forward { learn: false }
        ));
        assert!(!open.intercepts_dns());

        // An address rule does not turn that gate exclusive - it is read there,
        // it simply has nothing to say about resolution.
        assert!(policy(NetworkMode::UnrestrictedPublic, &["10.0.0.5:5432"]).forwards("any.test"));
        // Nor does a name rule that a `hosts:` record gave something to open;
        // a name rule with no record behind it is refused outright (see
        // [`a_name_rule_that_could_not_grant_anything_is_refused_not_ignored`]).
        assert!(
            published(
                NetworkMode::UnrestrictedPublic,
                &[record("nas.local", "10.0.0.5")],
                &["nas.local:445"],
            )
            .forwards("any.test")
        );
    }

    /// A name rule under `unrestricted-public` can only ever open what it
    /// resolves at construction: public addresses are already reachable, and a
    /// *learned* address cannot cross the floor. So `allow: [nas.local:445]`
    /// used to sit in a recipe granting nothing while the banner read "public
    /// egress + listed rules"; it is refused now, with the spellings that work.
    #[test]
    fn a_name_rule_that_could_not_grant_anything_is_refused_not_ignored() {
        let nas: IpAddr = "10.0.0.5".parse().unwrap();

        let err = err_of(&net(NetworkMode::UnrestrictedPublic, &["nas.local:445"]));
        assert!(err.contains("opens nothing"), "{err}");
        // The message has to carry the way out, or it is just a wall.
        assert!(err.contains("hosts:"), "{err}");
        assert!(err.contains("allowlist"), "{err}");

        // The two spellings it names both work, in that same mode.
        let by_addr = policy(NetworkMode::UnrestrictedPublic, &["10.0.0.5:445"]);
        assert!(by_addr.allows(nas, Some(445)));
        assert!(!by_addr.allows(nas, Some(22)));

        let by_record = published(
            NetworkMode::UnrestrictedPublic,
            &[record("nas.local", "10.0.0.5")],
            &["nas.local:445"],
        );
        assert!(by_record.allows(nas, Some(445)));
        assert!(!by_record.allows(nas, Some(22)));

        // …and the same rule keeps its ordinary meaning under an allowlist,
        // where it gates public egress rather than opening the floor.
        let gated = policy(NetworkMode::Allowlist, &["api.test:443"]);
        let public: IpAddr = "93.184.216.34".parse().unwrap();
        gated.learn_named("api.test", &[(public, 300)]);
        assert!(gated.allows(public, Some(443)));
        // Even there, a name cannot reach the floor by resolving into it.
        gated.learn_named("api.test", &[(nas, 300)]);
        assert!(!gated.allows(nas, Some(443)));
    }

    /// The port written against a *name* binds whatever that name resolves to -
    /// which is the only way a name rule can be port-scoped at all.
    #[test]
    fn a_learned_address_carries_its_name_s_port() {
        let p = policy(NetworkMode::Allowlist, &["api.test:443", "open.test"]);
        let resolved: IpAddr = "93.184.216.34".parse().unwrap();

        assert!(!p.allows(resolved, Some(443)), "nothing is learned yet");
        p.learn_named("api.test", &[(resolved, 300)]);
        assert!(p.allows(resolved, Some(443)));
        assert!(!p.allows(resolved, Some(80)));
        assert!(
            !p.allows(resolved, None),
            "portless flows need an any-port rule"
        );

        // The same address under a second name keeps both grants.
        p.learn_named("open.test", &[(resolved, 300)]);
        assert!(p.allows(resolved, Some(80)));

        // A name no rule covers learns nothing, however the answer arrives.
        let other: IpAddr = "5.5.5.5".parse().unwrap();
        p.learn_named("evil.test", &[(other, 300)]);
        assert!(!p.allows(other, Some(443)));
    }

    /// The learned set is the one thing here a guest can grow: it owns the DNS
    /// for any name its own rules cover, and every answer is an entry that
    /// outlives the query by up to an hour. The box's memory is capped by the
    /// recipe; the host process holding this map is not.
    #[test]
    fn what_a_guest_can_teach_this_policy_is_bounded() {
        let p = policy(NetworkMode::Allowlist, &["*.attacker.test"]);
        for i in 0..(LEARNED_ADDRESSES_CAPACITY * 2) {
            let ip: IpAddr = format!("203.0.{}.{}", (i / 256) % 256, i % 256)
                .parse()
                .unwrap();
            p.learn_named(&format!("n{i}.attacker.test"), &[(ip, 3600)]);
        }
        let held = p.learned_dns.lock().unwrap().len();
        assert!(
            held <= LEARNED_ADDRESSES_CAPACITY,
            "{held} learned entries, cap {LEARNED_ADDRESSES_CAPACITY}"
        );

        // Eviction is by soonest expiry, not wholesale: an address learned with
        // a long TTL is still reachable after the flood.
        let keeper: IpAddr = "198.51.100.7".parse().unwrap();
        p.learn_named("keep.attacker.test", &[(keeper, 3600)]);
        assert!(p.allows(keeper, Some(443)));
    }

    /// DNS rebinding: the answer is attacker-controlled, so it is the one place
    /// a floored address could be smuggled in behind a name that was
    /// legitimately allowed. An answer is not a rule, so the floor holds.
    #[test]
    fn an_answer_cannot_smuggle_in_a_floored_address_or_a_published_addr() {
        let p = published(
            NetworkMode::Allowlist,
            &[record("db.local", HOST_LOOPBACK_SYMBOL)],
            &["api.test", "db.local:5432"],
        );

        for hostile in ["10.0.0.5", "127.0.0.1", "169.254.169.254", "100.96.0.1"] {
            let ip: IpAddr = hostile.parse().unwrap();
            p.learn_named("api.test", &[(ip, 300)]);
            assert!(!p.allows(ip, Some(443)), "rebound onto {hostile}");
            assert!(!p.allows(ip, Some(22)), "rebound onto {hostile}");
        }
        // …and the host rule's own grant is untouched by the attempt.
        assert!(p.allows(HOST_ADDRS[0], Some(5432)));
    }

    /// The machine terra runs on is out of the allow-list's namespace: only
    /// `HOST_LOOPBACK` - or a name resolving there - reaches it, in either
    /// mode, and no range does however wide.
    #[test]
    fn only_a_host_rule_reaches_the_host() {
        for mode in [NetworkMode::Allowlist, NetworkMode::UnrestrictedPublic] {
            for host in HOST_ADDRS.iter().copied() {
                for entry in [&[][..], &["0.0.0.0/0", "::/0"]] {
                    let p = policy(mode, entry);
                    assert!(!p.allows(host, Some(22)), "{mode:?} {host} {entry:?}");
                    assert!(!p.allows(host, None), "{mode:?} {host} {entry:?}");
                }

                // The token, on the port it names.
                let scoped = policy(mode, &["HOST_LOOPBACK:5432"]);
                assert!(scoped.allows(host, Some(5432)), "{mode:?} {host}");
                assert!(!scoped.allows(host, Some(22)), "{mode:?} {host}");

                // …and portless, which is every port on the host.
                let open = policy(mode, &["host_loopback"]);
                assert!(open.allows(host, Some(22)), "{mode:?} {host}");

                // Whatever opened it, the connection is dialed at the loopback.
                assert!(scoped.rewrite(host).is_some_and(|ip| ip.is_loopback()));
            }

            // A record resolving to the host answers with it and grants
            // nothing by itself.
            let dns_only = published(mode, &[record("db.local", HOST_LOOPBACK_SYMBOL)], &[]);
            assert_eq!(
                dns_only.static_answer("db.local"),
                Some(HOST_ADDRS.as_slice()),
                "{mode:?}"
            );
            assert!(!dns_only.allows(HOST_ADDRS[0], Some(5432)), "{mode:?}");
        }
    }

    /// An `allow:` rule spelling out the gateway's own address would parse as
    /// an address rule and then open nothing - [`Policy::allows`] answers the
    /// host from `HOST_LOOPBACK` grants alone. Refused with the spelling that
    /// works; a *range* containing the gateway keeps its meaning.
    #[test]
    fn an_address_rule_naming_the_gateway_is_refused_not_left_inert() {
        for mode in [NetworkMode::Allowlist, NetworkMode::UnrestrictedPublic] {
            for gw in HOST_ADDRS {
                // An un-bracketed v6 ending in `:port` reads as ambiguous and
                // is refused before the rule ever classifies.
                let bare = match gw {
                    IpAddr::V6(_) => format!("[{gw}]"),
                    IpAddr::V4(_) => gw.to_string(),
                };
                let err = err_of(&net(mode, &[bare.as_str()]));
                assert!(err.contains(HOST_LOOPBACK_SYMBOL), "{mode:?} {gw}: {err}");

                let ported = format!("[{gw}]:80");
                let err = err_of(&net(mode, &[ported.as_str()]));
                assert!(err.contains(HOST_LOOPBACK_SYMBOL), "{mode:?} {gw}: {err}");
            }

            // The gateway's own /24, as a range: accepted, and still closed at
            // the gateway itself.
            let subnet = format!("{}/24", HOST_ADDRS[0]);
            let p = policy(mode, &[subnet.as_str()]);
            assert!(!p.allows(HOST_ADDRS[0], Some(80)), "{mode:?}");
        }
    }

    /// A record pointing at a real address is answered with it, grants nothing
    /// by itself, and is opened by a rule naming it either way.
    #[test]
    fn a_record_can_point_at_the_lan() {
        let nas: IpAddr = "10.0.0.5".parse().unwrap();
        for mode in [NetworkMode::Allowlist, NetworkMode::UnrestrictedPublic] {
            let records = [record("nas.local", "10.0.0.5")];

            let dns_only = published(mode, &records, &[]);
            assert_eq!(
                dns_only.static_answer("nas.local"),
                Some([nas].as_slice()),
                "{mode:?}"
            );
            // Under the floor until something opens it, record or no record.
            assert!(!dns_only.allows(nas, Some(445)), "{mode:?}");

            // The name rule and the address rule open the same thing.
            for rule in ["nas.local:445", "10.0.0.5:445"] {
                let p = published(mode, &records, &[rule]);
                assert!(p.allows(nas, Some(445)), "{mode:?} {rule}");
                assert!(!p.allows(nas, Some(22)), "{mode:?} {rule}");
            }
        }
    }

    /// Records sharing an address share what is opened there - one name's rule
    /// reaches the other's service, as anywhere else in DNS.
    #[test]
    fn records_sharing_an_address_share_its_grants() {
        let p = published(
            NetworkMode::Allowlist,
            &[
                record("db.local", HOST_LOOPBACK_SYMBOL),
                record("cache.local", HOST_LOOPBACK_SYMBOL),
            ],
            &["db.local:5432", "cache.local:6379"],
        );
        assert_eq!(p.static_answer("db.local"), p.static_answer("cache.local"));
        // Both ports are open on the one address both names resolve to.
        assert!(p.allows(HOST_ADDRS[0], Some(5432)));
        assert!(p.allows(HOST_ADDRS[0], Some(6379)));
        assert!(!p.allows(HOST_ADDRS[0], Some(22)));
    }

    /// A record is answered by the gateway, never forwarded, so nothing under
    /// its name resolves either: `<base32-payload>.api.mycorp.dev` used to be
    /// an outbound channel out of a box with no egress.
    #[test]
    fn a_record_does_not_open_dns_forwarding_for_its_subdomains() {
        let p = published(
            NetworkMode::Allowlist,
            &[record("api.mycorp.dev", HOST_LOOPBACK_SYMBOL)],
            &["api.mycorp.dev:8080"],
        );
        for under in [
            "payload.api.mycorp.dev",
            "a.b.api.mycorp.dev",
            "mycorp.dev",
            "anything.test",
        ] {
            assert!(!p.forwards(under), "{under} must not resolve");
        }
        assert!(!p.forwards("api.mycorp.dev"));

        // A `*.` rule covering a record opens the record *and* keeps its usual
        // meaning for the rest of the subtree, which still goes upstream.
        let sub = published(
            NetworkMode::Allowlist,
            &[record("api.example.com", HOST_LOOPBACK_SYMBOL)],
            &["*.example.com:8080"],
        );
        assert!(sub.allows(HOST_ADDRS[0], Some(8080)));
        assert!(sub.forwards("www.example.com"));
        assert!(!sub.forwards("api.example.com"), "answered here");
    }

    /// A name is exactly that name; the subtree is opted into with `*.`.
    /// The old behaviour handed a recipe the whole subtree whether it wanted
    /// one or not, which left "only this host" unwriteable.
    #[test]
    fn a_name_is_exact_and_the_subtree_is_opted_into() {
        let exact = policy(NetworkMode::Allowlist, &["example.com"]);
        assert!(exact.forwards("example.com"));
        for denied in ["www.example.com", "a.b.example.com", "notexample.com"] {
            assert!(!exact.forwards(denied), "{denied} is not example.com");
        }

        let sub = policy(NetworkMode::Allowlist, &["*.example.com"]);
        for allowed in ["www.example.com", "a.b.example.com"] {
            assert!(sub.forwards(allowed), "{allowed}");
        }
        for denied in ["example.com", "notexample.com", "example.com.evil.com"] {
            assert!(!sub.forwards(denied), "{denied}");
        }
        // The matcher itself, where a suffix test would open `notexample.com`
        // to a rule meaning `example.com`.
        assert!(!name_covers("*.example.com", ".example.com"), "empty label");
        assert!(!name_covers("*.example.com", "com"));

        // Both, if a recipe wants both.
        let both = policy(NetworkMode::Allowlist, &["example.com", "*.example.com"]);
        assert!(both.forwards("example.com"));
        assert!(both.forwards("www.example.com"));

        // A leading `*.` is the only wildcard there is.
        for bad in ["*", "*.", "api.*.com", "*example.com", "*.*.example.com"] {
            let err = parse_allow(bad).unwrap_err().to_string();
            assert!(err.contains("only wildcard"), "{bad}: {err}");
        }
        // …and it survives the port suffix and the normalization the rule is
        // matched by, which the query has already been through too.
        let name_of = |e: &str| match parse_allow(e).unwrap() {
            Rule::Name(name, _) => name,
            other => panic!("{e} should be a name rule: {other:?}"),
        };
        assert_eq!(name_of("*.API.test:443"), "*.api.test");
        assert!(policy(NetworkMode::Allowlist, &["*.api.test:443"]).forwards("v2.api.test"));
        assert_eq!(name_of(" example.com "), "example.com");
    }

    /// A `:PORT` suffix narrows the rule to that port, whatever it names.
    #[test]
    fn port_scope_is_enforced() {
        let ip: IpAddr = "8.8.8.3".parse().unwrap();
        let scoped = policy(NetworkMode::Allowlist, &["8.8.8.0/24:443"]);
        assert!(scoped.allows(ip, Some(443)));
        assert!(!scoped.allows(ip, Some(80)));
        // A portless rule permits any port, and only it matches a portless flow.
        let any = policy(NetworkMode::Allowlist, &["8.8.8.0/24"]);
        assert!(any.allows(ip, Some(80)));
        assert!(any.allows(ip, None));
        assert!(!scoped.allows(ip, None));
        assert!(!any.allows("1.1.1.1".parse().unwrap(), Some(80)));
    }

    /// Where an entry's host ends decides what it grants, so the ambiguous
    /// spellings are pinned here.
    #[test]
    fn an_entry_is_split_on_the_socketaddr_convention() {
        let split = |e: &str| {
            let (host, port) = split_host_port(e).unwrap();
            (host.to_string(), port)
        };
        assert_eq!(split("[db.local]"), ("db.local".into(), Port::Any));
        assert_eq!(
            split("[db.local]:5432"),
            ("db.local".into(), Port::Only(5432))
        );
        assert_eq!(
            split("db.local:5432"),
            ("db.local".into(), Port::Only(5432))
        );
        assert_eq!(split("db.local"), ("db.local".into(), Port::Any));
        // A v6 literal is not a host:port pair, whatever `rsplit_once` thinks.
        assert_eq!(split("::1"), ("::1".into(), Port::Any));
        assert_eq!(
            split("[2001:db8::1]:443"),
            ("2001:db8::1".into(), Port::Only(443))
        );
        // The prefix length is part of what an entry covers, so it survives:
        // dropping it would turn `0.0.0.0/0` into the single host `0.0.0.0`.
        assert_eq!(
            split("8.8.8.0/24:443"),
            ("8.8.8.0/24".into(), Port::Only(443))
        );
        assert_eq!(split("0.0.0.0/0"), ("0.0.0.0/0".into(), Port::Any));

        // An address rule is told apart from a name rule by the host alone.
        for addr in [
            "8.8.8.8",
            "8.8.8.0/24",
            "8.8.8.0/24:443",
            "[::1]:443",
            "::1",
        ] {
            let rule = parse_allow(addr).unwrap();
            assert!(
                matches!(rule, Rule::Addr(..)),
                "{addr} is an address: {rule:?}"
            );
        }
        for name in ["example.com", "api.openai.com:443", "vma.terra"] {
            let rule = parse_allow(name).unwrap();
            assert!(matches!(rule, Rule::Name(..)), "{name} is a name: {rule:?}");
        }
        // …and the one word for the machine terra runs on is neither, in any case.
        for host in [HOST_LOOPBACK_SYMBOL, "host_loopback", "HOST_LOOPBACK:22"] {
            let rule = parse_allow(host).unwrap();
            assert!(
                matches!(rule, Rule::Host(_)),
                "{host} is the host: {rule:?}"
            );
        }

        // An un-bracketed v6 address whose last group also reads as a port is
        // two rules in one spelling, and taking it as the address silently
        // opens every port. Refused, with both spellings named.
        for ambiguous in ["fe80::1:2", "2001:db8::1:443"] {
            let err = parse_allow(ambiguous).unwrap_err().to_string();
            assert!(err.contains("un-bracketed"), "{ambiguous}: {err}");
            assert!(err.contains(&format!("[{ambiguous}]")), "{err}");
        }
        // Both of the spellings it names mean exactly one thing.
        assert_eq!(split("[fe80::1:2]"), ("fe80::1:2".into(), Port::Any));
        assert_eq!(split("[fe80::1]:2"), ("fe80::1".into(), Port::Only(2)));
        // A v6 literal that could not be read as host:port is left alone -
        // `::1` splits into an empty head, and a hex group is not a port.
        for plain in ["::1", "2001:db8::443", "fe80::abcd"] {
            assert_eq!(split(plain), (plain.into(), Port::Any), "{plain}");
        }
        // …and a prefix length keeps a CIDR out of the ambiguity entirely.
        assert_eq!(split("fe80::1:2/64"), ("fe80::1:2/64".into(), Port::Any));

        // A present-but-unusable port fails the recipe rather than widening the
        // rule to every port - which is what dropping it would quietly do.
        for bad in ["1.1.1.1:", "1.1.1.1:0", "api.test:99999", "[::1]:x"] {
            assert!(parse_allow(bad).is_err(), "{bad} should be refused");
        }
        // …as do the malformed spellings around brackets and the empty entry.
        for bad in ["", "  ", "[db.local", "[db.local]x"] {
            assert!(parse_allow(bad).is_err(), "{bad:?} should be refused");
        }
        // A name rule that normalizes to nothing is refused, not left inert.
        let err = err_of(&net(NetworkMode::Allowlist, &["."]));
        assert!(err.contains("not a name"), "{err}");
        // …and a prefix length past the address width is refused, not dropped.
        let err = err_of(&net(NetworkMode::Allowlist, &["10.0.0.0/33"]));
        assert!(err.contains("prefix length"), "{err}");

        // The bracketed spelling still matches a record, brackets stripped.
        let bracketed = published(
            NetworkMode::Allowlist,
            &[record("db.local", HOST_LOOPBACK_SYMBOL)],
            &["[db.local]:5432"],
        );
        assert!(bracketed.allows(HOST_ADDRS[0], Some(5432)));
    }

    /// A `hosts:` rule is one record: one name, one address. The spellings
    /// that would silently collapse into one - or into none - are refused.
    #[test]
    fn a_hosts_rule_names_exactly_one_answerable_record() {
        let mut network = net(NetworkMode::Allowlist, &[]);

        network.hosts = vec![record("*.local", HOST_LOOPBACK_SYMBOL)];
        assert!(err_of(&network).contains("cannot use '*'"));

        // A name that normalizes to nothing is refused rather than left as a
        // record the gateway silently drops.
        network.hosts = vec![record(".", HOST_LOOPBACK_SYMBOL)];
        assert!(err_of(&network).contains("can answer"));

        // Duplicates - including a pair differing only in case or by a trailing
        // dot, which the gateway strips. One record would silently own the name.
        for pair in [
            [
                record("a.test", HOST_LOOPBACK_SYMBOL),
                record("a.test", "10.0.0.5"),
            ],
            [
                record("a.test", HOST_LOOPBACK_SYMBOL),
                record("A.TEST", "10.0.0.5"),
            ],
            [
                record("db.local", HOST_LOOPBACK_SYMBOL),
                record("db.local.", "10.0.0.5"),
            ],
        ] {
            network.hosts = pair.to_vec();
            assert!(
                err_of(&network).contains("duplicate"),
                "{:?}",
                network.hosts
            );
        }

        // A record's addr is an address, or the one word for the host - any case.
        for bad in ["", "db.other.local", "10.0.0.5:5432", "10.0.0.0/8", "HOST"] {
            network.hosts = vec![record("db.local", bad)];
            assert!(err_of(&network).contains("neither an IP address"), "{bad}");
        }
        network.hosts = vec![record("db.local", "host_loopback")];
        assert!(build(&network).is_ok(), "the token is case-insensitive");

        // Distinct names are still distinct.
        network.hosts = vec![
            record("a.test", HOST_LOOPBACK_SYMBOL),
            record("b.test", HOST_LOOPBACK_SYMBOL),
        ];
        assert!(build(&network).is_ok());
    }
}
