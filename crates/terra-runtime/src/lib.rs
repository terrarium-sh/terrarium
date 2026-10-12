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
pub mod self_test;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[cfg(test)]
#[allow(dead_code)]
mod test_fixtures;

#[cfg(test)]
mod boot_tests;
