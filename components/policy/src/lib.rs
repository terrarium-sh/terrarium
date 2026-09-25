#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({ world: "policy", path: "wit", generate_all });
}
use bindings::exports;
#[cfg(target_arch = "wasm32")]
use bindings::wasi;

mod address;
mod hostname;
mod rules;
mod runtime;
#[cfg(test)]
mod tests;

mod config {
    pub use crate::bindings::exports::terra::policy::decisions::{
        Config as Network, HostRecord as StaticDnsRecord, Mode as NetworkMode,
    };

    #[cfg(test)]
    impl Default for Network {
        fn default() -> Self {
            Self {
                mode: NetworkMode::Allowlist,
                allow: Vec::new(),
                hosts: Vec::new(),
                host_addresses: Vec::new(),
            }
        }
    }
}

use exports::terra::policy::decisions::{Config, Grants, Guest, Lookup};
use runtime::NameLookup;
use std::sync::Mutex;

static POLICY: Mutex<Option<runtime::BoxPolicy>> = Mutex::new(None);

fn monotonic_now() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        wasi::clocks::monotonic_clock::now()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::sync::OnceLock;
        use std::time::Instant;

        static STARTED: OnceLock<Instant> = OnceLock::new();
        u64::try_from(STARTED.get_or_init(Instant::now).elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}
struct Component;

impl Guest for Component {
    fn configure(
        config: Config,
        gateway_ip: String,
        gateway_ip6: String,
    ) -> Result<Grants, String> {
        let mut state = POLICY.lock().map_err(|_| "policy unavailable")?;
        if state.is_some() {
            return Err("policy already configured".into());
        }
        let gateways = [
            std::net::IpAddr::V4(gateway_ip.parse().map_err(|_| "invalid IPv4 gateway")?),
            std::net::IpAddr::V6(gateway_ip6.parse().map_err(|_| "invalid IPv6 gateway")?),
        ];
        let policy = runtime::BoxPolicy::new(&config, gateways)?;
        let grants = Grants {
            host_ports: policy.host_service_ports().to_vec(),
            blocks_direct_dns: policy.blocks_direct_dns(),
        };
        *state = Some(policy);
        Ok(grants)
    }

    fn allows(address: String, port: Option<u16>) -> bool {
        POLICY
            .lock()
            .ok()
            .and_then(|policy| Some(policy.as_ref()?.allows(address.parse().ok()?, port)))
            .unwrap_or(false)
    }

    fn lookup_name(name: String) -> Lookup {
        let Ok(policy) = POLICY.lock() else {
            return Lookup::Denied;
        };
        let Some(policy) = policy.as_ref() else {
            return Lookup::Denied;
        };
        match policy.lookup_name(&name) {
            NameLookup::Denied => Lookup::Denied,
            NameLookup::Resolve(name) => Lookup::Resolve(name),
            NameLookup::Static(addresses) => {
                Lookup::Static(addresses.iter().map(ToString::to_string).collect())
            }
        }
    }

    fn accept_resolved(name: String, addresses: Vec<String>) -> Vec<String> {
        let Ok(policy) = POLICY.lock() else {
            return Vec::new();
        };
        let Some(policy) = policy.as_ref() else {
            return Vec::new();
        };
        let Ok(addresses) = addresses
            .iter()
            .map(|address| address.parse())
            .collect::<Result<Vec<_>, _>>()
        else {
            return Vec::new();
        };
        policy
            .accept_resolved(&name, &addresses)
            .iter()
            .map(ToString::to_string)
            .collect()
    }
}

#[allow(unsafe_code)]
mod component_exports {
    use super::{Component, bindings};
    bindings::export!(Component with_types_in bindings);
}
