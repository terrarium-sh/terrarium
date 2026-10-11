use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Allows public destinations except addresses collected from host interfaces at VM startup.
    /// Explicit `allow` rules can grant access to those addresses and private ranges.
    #[serde(rename = "unrestricted-public")]
    UnrestrictedPublic,
    /// Nothing without a rule; an empty allowlist reaches nothing.
    #[default]
    Allowlist,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticDnsRecord {
    pub name: String,
    /// An IP address, or `HOST_LOOPBACK` for the machine terra is running on.
    pub addr: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    pub mode: NetworkMode,
    pub allow: Vec<String>,
    pub hosts: Vec<StaticDnsRecord>,
    pub host_addresses: Vec<IpAddr>,
}

impl Network {
    pub(crate) fn validate_limits(&self) -> Result<(), String> {
        if self.allow.len() > crate::MAX_RULES || self.hosts.len() > crate::MAX_RULES {
            return Err(format!(
                "network configuration exceeds {} rules or records",
                crate::MAX_RULES
            ));
        }
        if self.host_addresses.len() > crate::MAX_HOST_ADDRESSES {
            return Err(format!(
                "host has more than {} interface addresses",
                crate::MAX_HOST_ADDRESSES
            ));
        }
        let strings = self.allow.iter().map(String::as_str).chain(
            self.hosts
                .iter()
                .flat_map(|record| [record.name.as_str(), record.addr.as_str()]),
        );
        let mut bytes = 0_usize;
        for text in strings {
            if text.len() > crate::MAX_RULE_BYTES {
                return Err(format!(
                    "network configuration entry exceeds {} bytes",
                    crate::MAX_RULE_BYTES
                ));
            }
            bytes = bytes.saturating_add(text.len());
        }
        if bytes > crate::MAX_CONFIG_BYTES {
            return Err(format!(
                "network configuration exceeds {} KiB",
                crate::MAX_CONFIG_BYTES >> 10
            ));
        }
        Ok(())
    }
}
