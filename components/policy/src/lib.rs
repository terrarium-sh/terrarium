#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({ world: "policy", path: "wit" });
}
use bindings::exports;

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
use std::sync::Mutex;
use terra_network::{NameLookup, Policy};

static POLICY: Mutex<Option<runtime::BoxPolicy>> = Mutex::new(None);
struct Component;

impl Guest for Component {
    fn configure(config: Config) -> Result<Grants, String> {
        let mut state = POLICY.lock().map_err(|_| "policy unavailable")?;
        if state.is_some() {
            return Err("policy already configured".into());
        }
        let policy = runtime::BoxPolicy::new(&config)?;
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
            NameLookup::Resolve => Lookup::Resolve,
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
