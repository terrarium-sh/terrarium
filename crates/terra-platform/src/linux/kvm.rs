//! Linux Kernel Virtual Machine backends.

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "x86_64")]
pub mod amd64;
