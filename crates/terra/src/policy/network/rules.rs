use anyhow::{Result, bail};
use terra_protocol::network::ResourceKind;
use terra_runtime::component::network::PortMapping;

pub fn parse_port_mappings(ports: &[String]) -> Result<Vec<PortMapping>> {
    anyhow::ensure!(
        ports.len() <= terra_protocol::MAX_PUBLISHED_PORTS,
        "network.ports has {} mappings; at most {} can be published; remove excess mappings",
        ports.len(),
        terra_protocol::MAX_PUBLISHED_PORTS
    );
    let mut mappings: Vec<PortMapping> = Vec::new();
    for spec in ports {
        let (ports, transport) = match spec.rsplit_once('/') {
            Some((ports, "tcp")) => (ports, ResourceKind::Tcp),
            Some((ports, "udp")) => (ports, ResourceKind::Udp),
            Some(_) => bail!("invalid published port '{spec}': use HOST[:GUEST][/tcp|/udp]"),
            None => (spec.as_str(), ResourceKind::Tcp),
        };
        let (host_port, guest_port) = ports.split_once(':').unwrap_or((ports, ports));
        let parse_mapping_port = |text, side| {
            parse_port(text).ok_or_else(|| {
                anyhow::anyhow!("invalid published port '{spec}': {side} port must be 1-65535")
            })
        };
        let mapping = PortMapping {
            host: parse_mapping_port(host_port, "host")?,
            guest: parse_mapping_port(guest_port, "guest")?,
            transport,
        };
        if let Some(earlier) = mappings
            .iter()
            .find(|m| m.host == mapping.host && m.transport == transport)
        {
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

fn parse_port(text: &str) -> Option<u16> {
    let text = text.trim();
    text.parse::<u16>()
        .ok()
        .filter(|port| *port != 0 && !text.starts_with('+'))
}
