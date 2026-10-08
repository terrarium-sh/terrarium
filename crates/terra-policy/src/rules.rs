//! Recipe allow rules and static DNS records.

use crate::address::Cidr;
use crate::config::StaticDnsRecord;
use crate::hostname::normalize_hostname;
use std::net::{IpAddr, Ipv6Addr};

type Result<T> = std::result::Result<T, String>;

/// The underscore keeps it outside the hostname grammar (RFC 1123), so no
/// real name can collide with it.
pub const HOST_LOOPBACK_SYMBOL: &str = "HOST_LOOPBACK";

pub type Port = Option<u16>;

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

pub(crate) fn parse_allow(entry: &str) -> Result<Rule> {
    let entry = entry.trim();
    let after_wildcard = entry.strip_prefix("*.").unwrap_or(entry);
    if after_wildcard.contains('*') || after_wildcard.is_empty() {
        return Err(format!(
            "allow rule '{entry}': the only wildcard is a leading '*.', which covers \
             the subdomains of what follows - write '*.example.com' for those, or \
             'example.com' for that name exactly, or both to get both"
        ));
    }
    let (host, port) = split_host_port(entry)?;
    classify(entry, host, port)
}

pub(crate) fn split_host_port(entry: &str) -> Result<(&str, Port)> {
    let parse_rule_port = |text: &str| {
        parse_port(text)
            .ok_or_else(|| format!("allow rule '{entry}': '{text}' is not a port (1-65535)"))
    };
    if let Some(rest) = entry.strip_prefix('[') {
        if let Some(host) = rest.strip_suffix(']') {
            return Ok((host, None));
        }
        let (host, port_text) = rest
            .split_once("]:")
            .ok_or_else(|| format!("allow rule '{entry}': unclosed '['"))?;
        return Ok((host, Some(parse_rule_port(port_text)?)));
    }
    match entry.rsplit_once(':') {
        Some((host, port_text)) if !host.is_empty() && !host.contains(':') => {
            Ok((host, Some(parse_rule_port(port_text)?)))
        }
        Some((host, port_text))
            if host.parse::<Ipv6Addr>().is_ok() && parse_port(port_text).is_some() =>
        {
            Err(format!(
                "allow rule '{entry}': an un-bracketed IPv6 address ending in ':{port_text}' \
                 could be that address or a ':PORT' suffix - write '[{entry}]' for the \
                 address on every port, or '[{host}]:{port_text}' for port {port_text}"
            ))
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
        let cidr = Cidr::parse(host)
            .ok_or_else(|| format!("allow rule '{entry}': prefix length is out of range"))?;
        return Ok(Rule::Addr(cidr, port));
    }
    let (wildcard, name_without_wildcard) = match host.strip_prefix("*.") {
        Some(parent) => ("*.", parent),
        None => ("", host),
    };
    if !wildcard.is_empty() && name_without_wildcard.parse::<IpAddr>().is_ok() {
        return Err(format!(
            "allow rule '{entry}': a wildcard must name a hostname"
        ));
    }
    let name = normalize_hostname(name_without_wildcard)
        .map(|normalized| format!("{wildcard}{normalized}"))
        .ok_or_else(|| format!("allow rule '{entry}': not a name the gateway can match"))?;
    Ok(Rule::Name(name, port))
}

pub(crate) fn parse_dns_record(
    rule: &StaticDnsRecord,
    gateway_addrs: &[IpAddr; 2],
) -> Result<(String, Vec<IpAddr>)> {
    if rule.name.trim().is_empty() {
        return Err("hosts record has an empty 'name'".into());
    }
    if rule.name.contains('*') {
        return Err(format!(
            "hosts record '{}' cannot use '*': it is answered as a DNS record, so it \
             names one host exactly",
            rule.name
        ));
    }
    let key = normalize_hostname(&rule.name).ok_or_else(|| {
        format!(
            "hosts record '{}' is not a name the gateway can answer",
            rule.name
        )
    })?;
    let addrs = match rule.addr.trim() {
        addr if addr.eq_ignore_ascii_case(HOST_LOOPBACK_SYMBOL) => gateway_addrs.to_vec(),
        addr => vec![addr
            .parse::<IpAddr>()
            .map(|ip| ip.to_canonical())
            .map_err(|_| {
            format!(
                "hosts record '{}': '{}' is neither an IP address nor '{HOST_LOOPBACK_SYMBOL}' (the \
                 machine terra is running on)",
                rule.name,
                rule.addr
            )
            })?],
    };
    Ok((key, addrs))
}

fn parse_port(text: &str) -> Option<u16> {
    let text = text.trim();
    text.parse::<u16>()
        .ok()
        .filter(|port| *port != 0 && !text.starts_with('+'))
}
