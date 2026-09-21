//! Native x86 VM constants.

#[cfg(target_os = "linux")]
pub const IRQ_BASE: u32 = 11;
pub const MAX_VCPUS: usize = terra_limits::X86_MAX_VCPUS as usize;
