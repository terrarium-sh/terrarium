use crate::config::StaticDnsRecord;
use anyhow::{Result, bail};
use smolvm_network::{Cidr, PortMapping, dns};
use std::net::{IpAddr, Ipv6Addr};

/// The underscore keeps it outside the hostname grammar (RFC 1123), so no
/// real name can collide with it.
pub const HOST_LOOPBACK_SYMBOL: &str = "HOST_LOOPBACK";

pub type Port = Option<u16>;

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

/// Only a full-length prefix counts: a range containing the gateway is a
/// rule like any other, the exact spelling reads as a grant and is not.
#[must_use]
pub(crate) fn is_single_address(cidr: Cidr, ip: IpAddr) -> bool {
    let full_length = match cidr {
        Cidr::V4 { mask, .. } => mask == u32::MAX,
        Cidr::V6 { mask, .. } => mask == u128::MAX,
    };
    full_length && cidr.contains(ip)
}

#[must_use]
pub(crate) fn name_covers(rule: &str, name: &str) -> bool {
    let Some(parent) = rule.strip_prefix("*.") else {
        return rule == name;
    };
    name.strip_suffix(parent)
        .is_some_and(|sub| sub.ends_with('.') && sub.len() > 1)
}

#[derive(Debug)]
pub(crate) enum Rule {
    Host(Port),
    Addr(Cidr, Port),
    Name(String, Port),
}

/// Parse one `allow:` entry: `HOST[:PORT]`, or `[V6]:PORT`. Everything an
/// entry can be wrong about fails the recipe here rather than leaving a rule
/// that quietly opens more (a dropped port) or nothing at all.
pub(crate) fn parse_allow(entry: &str) -> Result<Rule> {
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

pub(crate) fn split_host_port(entry: &str) -> Result<(&str, Port)> {
    let parse_port = |text: &str| {
        parse_port_number(text).ok_or_else(|| {
            anyhow::anyhow!("allow rule '{entry}': '{text}' is not a port (1-65535)")
        })
    };
    if let Some(rest) = entry.strip_prefix('[') {
        if let Some(host) = rest.strip_suffix(']') {
            return Ok((host, None));
        }
        let (host, port_text) = rest
            .split_once("]:")
            .ok_or_else(|| anyhow::anyhow!("allow rule '{entry}': unclosed '['"))?;
        return Ok((host, Some(parse_port(port_text)?)));
    }
    match entry.rsplit_once(':') {
        Some((host, port_text)) if !host.is_empty() && !host.contains(':') => {
            Ok((host, Some(parse_port(port_text)?)))
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
        None | Some((_, _)) => Ok((entry, None)),
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

pub(crate) fn parse_dns_record(
    rule: &StaticDnsRecord,
    gateway_addrs: &[IpAddr; 2],
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
