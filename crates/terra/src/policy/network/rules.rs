use anyhow::{Result, bail};
use terra_network::{PortMapping, parse_port};

/// Parse `network.ports` - `"HOST[:GUEST]"`, bare = same on both. The host
/// side always binds `127.0.0.1`.
pub fn parse_port_mappings(ports: &[String]) -> Result<Vec<PortMapping>> {
    let mut mappings: Vec<PortMapping> = Vec::new();
    for spec in ports {
        let (host_port, guest_port) = spec.split_once(':').unwrap_or((spec, spec));
        let parse_mapping_port = |text, side| {
            parse_port(text).ok_or_else(|| {
                anyhow::anyhow!("invalid published port '{spec}': {side} port must be 1-65535")
            })
        };
        let mapping = PortMapping::new(
            parse_mapping_port(host_port, "host")?,
            parse_mapping_port(guest_port, "guest")?,
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
