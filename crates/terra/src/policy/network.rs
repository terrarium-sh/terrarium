//! The recipe's `network:` section, as the gateway's policy: what a box may
//! resolve, and what it may reach.

pub mod rules;
pub mod runtime;

#[cfg(test)]
mod tests;

pub use rules::parse_port_mappings;
pub use runtime::{BoxPolicy, describe, validate};
