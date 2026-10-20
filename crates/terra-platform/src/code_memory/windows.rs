#![allow(unsafe_code)]

use std::io;
use windows_sys::Win32::System::Memory::{
    PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READONLY, VirtualProtect,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

fn system_info() -> SYSTEM_INFO {
    // SAFETY: GetSystemInfo fills every field of the out parameter.
    unsafe {
        let mut info = std::mem::zeroed();
        GetSystemInfo(&raw mut info);
        info
    }
}

#[must_use]
pub fn page_size() -> usize {
    system_info().dwPageSize as usize
}

/// # Safety
///
/// `ptr..ptr + len` must be page-aligned committed memory that nothing writes
/// while it is executable.
pub unsafe fn protect_executable(ptr: *const u8, len: usize) -> io::Result<()> {
    // SAFETY: the caller upholds the alignment and no-writer contract.
    unsafe { protect(ptr, len, PAGE_EXECUTE_READ) }
}

/// # Safety
///
/// `ptr..ptr + len` must be page-aligned committed memory from which no code runs.
pub unsafe fn protect_read_only(ptr: *const u8, len: usize) -> io::Result<()> {
    // SAFETY: the caller guarantees nothing executes from the range.
    unsafe { protect(ptr, len, PAGE_READONLY) }
}

unsafe fn protect(ptr: *const u8, len: usize, protection: PAGE_PROTECTION_FLAGS) -> io::Result<()> {
    let mut previous = 0;
    // SAFETY: the callers' contracts make the range a valid VirtualProtect target.
    if unsafe { VirtualProtect(ptr.cast(), len, protection, &raw mut previous) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
