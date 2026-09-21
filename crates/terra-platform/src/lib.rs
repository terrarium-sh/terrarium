//! Virtual-machine execution backends for Terra's portable VMM devices.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod aarch64;
#[cfg(target_arch = "x86_64")]
pub mod amd64;
pub mod worker;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_arch = "x86_64")]
pub use amd64::machine;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use linux::kvm::amd64::{arch, kvm};
#[cfg(target_os = "linux")]
pub(crate) use linux::runner;

#[cfg(test)]
mod boot_tests;
