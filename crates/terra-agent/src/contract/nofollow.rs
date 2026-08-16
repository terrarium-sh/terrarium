//! `openat2(RESOLVE_NO_SYMLINKS)`: the one no-symlink open primitive, shared
//! by the host's and the guest's symlink defenses.
#![allow(unsafe_code)]

use std::fs::File;
use std::path::Path;

/// Create or truncate `path` for writing, owner-only, refusing a symlink at
/// any component. `openat2` resolves atomically, so a concurrent attacker
/// gets no check-to-use window.
pub fn create_no_symlinks_raw(path: &Path) -> std::io::Result<File> {
    open_no_symlinks_raw(path, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o600)
}

pub fn open_no_symlinks_raw(
    path: &Path,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<File> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // `open_how` is `#[non_exhaustive]` (the kernel may grow it), so it is
    // built zeroed rather than with a struct literal.
    // SAFETY: an all-zero `open_how` is the documented "no extra options" value,
    // and every field it currently has is set below.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = u64::try_from(flags | libc::O_CLOEXEC).unwrap_or_default();
    how.mode = u64::from(mode);
    how.resolve = libc::RESOLVE_NO_SYMLINKS;
    // SAFETY: `c_path` outlives the call, `how` is the size the kernel is told it
    // is, and the returned descriptor is handed straight to `File`.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            c_path.as_ptr(),
            std::ptr::from_ref(&how),
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[allow(clippy::cast_possible_truncation)] // a descriptor is an int
    // SAFETY: a fresh descriptor this process now owns.
    Ok(unsafe { File::from_raw_fd(fd as std::os::fd::RawFd) })
}
