//! Native VM, memory, filesystem, local-I/O, and child-process operations.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!("terra runs VMs only on Linux (KVM), macOS (HVF), and Windows (WHP)");

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

pub mod filesystem;
pub mod io;
pub mod memory;
pub mod process;
pub mod psci;
pub mod vm;
