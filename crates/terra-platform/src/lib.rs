//! Native VM, memory, filesystem, and local-I/O operations.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

pub mod filesystem;
pub mod io;
pub mod memory;
pub mod vm;
