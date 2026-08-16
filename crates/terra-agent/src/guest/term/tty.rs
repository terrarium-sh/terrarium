//! Terminal glue: raw mode and window size for the TTY/PTY pair.

use std::os::fd::RawFd;

/// Put a TTY into raw mode (no-op if `fd` is not one). Never restored: on a
/// `--foreground` boot the guest console owns the terminal until the VM stops.
pub fn set_raw(fd: RawFd) {
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::isatty(fd) != 1 || libc::tcgetattr(fd, std::ptr::addr_of_mut!(t)) != 0 {
            return;
        }
        libc::cfmakeraw(std::ptr::addr_of_mut!(t));
        libc::tcsetattr(fd, libc::TCSANOW, std::ptr::addr_of!(t));
    }
}

/// The window size of `fd`, if it is a TTY.
#[must_use]
pub fn winsize(fd: RawFd) -> Option<(u16, u16)> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, std::ptr::addr_of_mut!(ws)) } == 0
        && ws.ws_row > 0
        && ws.ws_col > 0
    {
        Some((ws.ws_row, ws.ws_col))
    } else {
        None
    }
}

/// Set a PTY master's window size.
pub fn set_winsize(fd: RawFd, rows: u16, cols: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::ioctl(fd, libc::TIOCSWINSZ, std::ptr::addr_of!(ws));
    }
}
