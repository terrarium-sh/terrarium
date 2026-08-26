//! The whole shared surface between host and guest: the wire contract
//! ([`contract`]) and the one filesystem primitive they share ([`no_symlinks`]).

// unwrap/expect/panic are denied workspace-wide via Cargo.toml; tests opt back in.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod contract;
#[cfg(target_os = "linux")]
pub mod no_symlinks;

pub use contract::*;
