//! Host/guest messages, launch plans, and control-channel wire types.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod control;
mod frames;
mod plan;

pub use frames::*;
pub use plan::*;
