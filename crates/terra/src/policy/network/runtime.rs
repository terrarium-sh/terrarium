use crate::config::{Network, NetworkMode};
use anyhow::Result;
use std::net::IpAddr;
use std::sync::OnceLock;
use terra_network::{NameLookup, Policy, dns::normalize_hostname};
use terra_runtime::component::policy::{ComponentPolicy, Config, HostRecord, Mode, PolicyFactory};

pub struct BoxPolicy(ComponentPolicy);

impl BoxPolicy {
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn new(network: &Network) -> Result<Self> {
        Self::with_memory_limit(network, 16 << 20)
    }

    #[allow(unsafe_code)]
    pub fn with_memory_limit(network: &Network, memory_bytes: usize) -> Result<Self> {
        static FACTORY: OnceLock<Result<PolicyFactory, String>> = OnceLock::new();
        let factory = FACTORY
            .get_or_init(|| {
                // SAFETY: Make produces this embedded artifact for the pinned Wasmtime build.
                unsafe {
                    PolicyFactory::from_build_artifact(include_bytes!(env!("TERRA_POLICY_AOT")))
                }
                .map_err(|error| error.to_string())
            })
            .as_ref()
            .map_err(|error| anyhow::anyhow!("network policy component: {error}"))?;
        let config = Config {
            mode: match network.mode {
                NetworkMode::UnrestrictedPublic => Mode::UnrestrictedPublic,
                NetworkMode::Allowlist => Mode::Allowlist,
            },
            allow: network.allow.clone(),
            hosts: network
                .hosts
                .iter()
                .map(|record| HostRecord {
                    name: record.name.clone(),
                    addr: record.addr.clone(),
                })
                .collect(),
            host_addresses: crate::sys::host_addresses()?
                .into_iter()
                .map(|address| address.to_string())
                .collect(),
        };
        Ok(Self(factory.instantiate(&config, memory_bytes).map_err(
            |error| anyhow::anyhow!("network policy component: {error:#}"),
        )?))
    }
}

impl Policy for BoxPolicy {
    fn is_available(&self) -> bool {
        self.0.is_available()
    }

    fn allows(&self, address: IpAddr, port: Option<u16>) -> bool {
        let allowed = self.0.allows(address, port);
        let suffix = port.map_or_else(String::new, |port| format!(":{port}"));
        if allowed {
            log::trace!("terra: egress: allowed {address}{suffix}");
        } else {
            log::warn!("terra: egress: blocked {address}{suffix} - policy denied access");
        }
        allowed
    }
    fn host_service_ports(&self) -> &[Option<u16>] {
        self.0.host_service_ports()
    }
    fn lookup_name(&self, name: &str) -> NameLookup {
        let Some(name) = normalize_hostname(name) else {
            log::warn!("terra: egress: blocked name lookup - invalid hostname");
            return NameLookup::Denied;
        };
        let lookup = self.0.lookup_name(&name);
        if matches!(lookup, NameLookup::Denied) {
            log::warn!("terra: egress: blocked {name} - policy denied name lookup");
        }
        lookup
    }
    fn accept_resolved(&self, name: &str, addresses: &[IpAddr]) -> Vec<IpAddr> {
        self.0.accept_resolved(name, addresses)
    }
    fn blocks_direct_dns(&self) -> bool {
        self.0.blocks_direct_dns()
    }
}
