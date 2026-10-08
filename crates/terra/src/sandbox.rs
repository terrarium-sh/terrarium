//! Sandbox launcher configuration and Linux seccomp policy generation.

pub(crate) mod config;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod generation;
pub(crate) mod policy;
