use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    #[default]
    Allowlist,
    UnrestrictedPublic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticDnsRecord {
    pub name: String,
    pub addr: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    pub mode: NetworkMode,
    pub allow: Vec<String>,
    pub hosts: Vec<StaticDnsRecord>,
    pub host_addresses: Vec<String>,
}

impl Network {
    pub fn validate_limits(&self) -> Result<(), String> {
        if self.allow.len() > crate::MAX_RULES
            || self.hosts.len() > crate::MAX_RULES
            || self.host_addresses.len() > crate::MAX_RULES
        {
            return Err(
                "network configuration exceeds 4096 rules, records, or host addresses".into(),
            );
        }
        let strings = self
            .allow
            .iter()
            .map(String::as_str)
            .chain(
                self.hosts
                    .iter()
                    .flat_map(|record| [record.name.as_str(), record.addr.as_str()]),
            )
            .chain(self.host_addresses.iter().map(String::as_str));
        let mut bytes = 0_usize;
        for text in strings {
            if text.len() > crate::MAX_RULE_BYTES {
                return Err("network configuration entry exceeds 512 bytes".into());
            }
            bytes = bytes.saturating_add(text.len());
        }
        if bytes > crate::MAX_CONFIG_BYTES {
            return Err("network configuration exceeds 64 KiB".into());
        }
        Ok(())
    }
}
