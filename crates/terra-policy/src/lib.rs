//! Shared egress policy and bounded DNS learning.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod address;
pub mod config;
mod hostname;
mod rules;
mod runtime;
#[cfg(test)]
mod tests;

pub use hostname::normalize_hostname;
pub use rules::{HOST_LOOPBACK_SYMBOL, is_host_loopback, parse_port};
pub use runtime::{BoxPolicy, LEARNED_DNS_TTL_SECS, NameLookup};

pub const MAX_CONFIG_BYTES: usize = 64 << 10;
pub(crate) const MAX_RULES: usize = 4096;
pub const MAX_EXPANDED_RULES: usize = 4096;
pub(crate) const MAX_RULE_BYTES: usize = 512;
pub const MAX_HOST_ADDRESSES: usize = 1024;
pub(crate) const MAX_NAME_BYTES: usize = 256;
pub const MAX_RESOLVED_ADDRESSES: usize = 32;
