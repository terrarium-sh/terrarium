//! Page protection for code that runs from memory Wasmtime does not own.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::{page_size, protect_executable, protect_read_only};
#[cfg(windows)]
pub use windows::{page_size, protect_executable, protect_read_only};

/// Places a value on pages of its own: aligned, and padded to whole pages by
/// its size, so its code can be made executable in place without exposing
/// neighbouring data. COFF sections cannot align beyond 8 KiB.
#[cfg_attr(windows, repr(C, align(4096)))]
#[cfg_attr(not(windows), repr(C, align(65536)))]
pub struct PageAligned<T: ?Sized>(pub T);
