//! Portable network protocol, DNS wire helpers, and policy contracts.

#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::expect_used,
        clippy::unwrap_used
    )
)]

pub mod address;
pub mod config;
pub mod dns;
pub mod policy;

pub use address::{Cidr, is_floored, nat64_well_known_v4};
pub use config::{GuestNetworkConfig, PortMapping};
pub use policy::{NameLookup, Policy, PolicyHandle};

pub const LEARNED_DNS_TTL_SECS: u32 = 60;

#[must_use]
pub fn parse_port(text: &str) -> Option<u16> {
    let text = text.trim();
    (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
        .filter(|port| *port != 0)
}
