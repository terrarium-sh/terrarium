//! The recipe's `network:` section, as the gateway's policy: what a box may
//! resolve, and what it may reach.

pub mod rules;
pub mod runtime;

#[cfg(test)]
mod tests;

use crate::config::{Network, NetworkMode};

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
