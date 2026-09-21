//! Virtual-machine execution backends for Terra's portable VMM devices.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "windows")
))]
mod amd64;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(all(
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "windows")
))]
pub(crate) use amd64::machine;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) use linux::kvm::amd64::{arch, kvm};
#[cfg(target_os = "linux")]
pub(crate) use linux::runner;

pub mod filesystem;
pub mod io;
pub mod memory;
pub mod vm;
