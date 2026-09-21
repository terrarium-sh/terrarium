//! Native hosting and scoped capabilities for Terra's WASI worlds.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod artifacts;
pub use artifacts::{TrustedArtifact, TrustedArtifacts};
pub mod box_runtime;
pub mod component;
pub mod engine;

pub mod machine;
pub mod memory;
pub mod orchestration;

pub(crate) use terra_limits::MAX_BATCH_GUEST_COPY_BYTES as MAX_BATCH_BYTES;
pub(crate) use terra_limits::MAX_SINGLE_GUEST_COPY_BYTES as MAX_SINGLE_BYTES;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[cfg(test)]
#[allow(dead_code)]
mod test_fixtures;

#[cfg(test)]
mod boot_tests;
