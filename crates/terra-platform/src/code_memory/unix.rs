#![allow(unsafe_code)]

use std::io;

#[must_use]
pub fn page_size() -> usize {
    rustix::param::page_size()
}

/// # Safety
///
/// `ptr..ptr + len` must be page-aligned mapped memory that nothing writes
/// while it is executable.
pub unsafe fn protect_executable(ptr: *const u8, len: usize) -> io::Result<()> {
    // SAFETY: the caller upholds the alignment and no-writer contract.
    unsafe { protect(ptr, len, libc::PROT_READ | libc::PROT_EXEC) }
}

/// # Safety
///
/// `ptr..ptr + len` must be page-aligned mapped memory from which no code runs.
pub unsafe fn protect_read_only(ptr: *const u8, len: usize) -> io::Result<()> {
    // SAFETY: the caller guarantees nothing executes from the range.
    unsafe { protect(ptr, len, libc::PROT_READ) }
}

unsafe fn protect(ptr: *const u8, len: usize, protection: libc::c_int) -> io::Result<()> {
    // SAFETY: the callers' contracts make the range a valid mprotect target.
    if unsafe { libc::mprotect(ptr.cast_mut().cast(), len, protection) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
