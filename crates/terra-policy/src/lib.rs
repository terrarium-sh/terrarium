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
pub use rules::HOST_LOOPBACK_SYMBOL;
pub use runtime::{BoxPolicy, LEARNED_ADDRESSES_CAPACITY, LEARNED_DNS_TTL_SECS, NameLookup};

pub const MAX_CONFIG_BYTES: usize = 64 << 10;
pub const MAX_RULES: usize = 4096;
pub const MAX_EXPANDED_RULES: usize = 4096;
pub const MAX_RULE_BYTES: usize = 512;
pub const MAX_NAME_BYTES: usize = 256;
pub const MAX_RESOLVED_ADDRESSES: usize = 32;

fn monotonic_now() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;

    static STARTED: OnceLock<Instant> = OnceLock::new();
    u64::try_from(STARTED.get_or_init(Instant::now).elapsed().as_nanos()).unwrap_or(u64::MAX)
}
