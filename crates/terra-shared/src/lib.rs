//! The shared surface between host and guest.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod contract {
    mod frames;
    mod plan;

    pub use frames::*;
    pub use plan::*;
}
pub mod no_symlinks;
