//! Apple Silicon Hypervisor.framework backend.

mod aarch64;

pub(crate) use aarch64::{Machine, Vm, map_guest_ram, unmap_guest_ram};
