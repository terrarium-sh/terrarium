//! Build-script logic for the terra and terra-sandbox crates.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub const EMBEDDED_ARTIFACT_SECTION: &str = ".terra_artifacts";

pub mod bwrap;
pub mod seccomp;
pub mod seccomp_policy;
pub mod version;
