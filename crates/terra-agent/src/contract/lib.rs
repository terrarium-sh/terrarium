//! The host/guest contract: the boot plan, the protocol constants, and the
//! framed terminal protocol, plus the shared no-symlink open. Everything here
//! builds for the host as well as the guest; the agent's own machinery is
//! `guest/`.

// unwrap/expect/panic are denied workspace-wide via Cargo.toml; tests opt back in.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod frames;
#[cfg(target_os = "linux")]
pub mod nofollow;
pub mod plan;

pub use frames::*;
pub use plan::*;
