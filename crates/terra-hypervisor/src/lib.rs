//! Native VMs and guest memory over KVM, Hypervisor.framework, and WHP.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "macos", target_arch = "aarch64"),
    all(windows, any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
compile_error!(
    "terra runs VMs only on Linux x86_64/aarch64 (KVM), macOS aarch64 (HVF), and Windows x86_64/aarch64 (WHP)"
);

#[cfg(any(all(target_arch = "aarch64", not(target_os = "linux")), test))]
mod arm;
#[cfg(target_os = "macos")]
mod hvf;
#[cfg(target_os = "linux")]
mod kvm;
pub mod memory;
mod vcpus;
pub mod vm;
#[cfg(windows)]
mod whp;
#[cfg(target_arch = "x86_64")]
mod x86;
