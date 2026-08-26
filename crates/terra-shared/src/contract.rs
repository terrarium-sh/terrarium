//! The host/guest wire contract: the boot plan, the protocol constants, and
//! the framed terminal protocol.

// unwrap/expect/panic are denied workspace-wide via Cargo.toml; tests opt back in.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod frames;
pub mod plan;

pub use frames::*;
pub use plan::*;
