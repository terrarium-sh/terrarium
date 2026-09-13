//! Terminal window sizing.

use rustix::fd::BorrowedFd;
use rustix::termios::{Winsize, tcsetwinsize};

pub fn set_winsize(fd: BorrowedFd<'_>, rows: u16, cols: u16) {
    let ws = Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let _ = tcsetwinsize(fd, ws);
}
