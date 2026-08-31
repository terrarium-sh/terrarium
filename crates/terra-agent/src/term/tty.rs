//! Terminal glue: raw mode and window size for the TTY/PTY pair.

use rustix::fd::BorrowedFd;
use rustix::termios::{OptionalActions, Winsize, tcgetattr, tcgetwinsize, tcsetattr, tcsetwinsize};

#[allow(unsafe_code)]
/// Puts `fd` in raw mode (no-op if not a TTY). Never restored as the guest console owns the terminal until shutdown.
pub fn set_raw(fd: BorrowedFd<'_>) {
    if let Ok(mut t) = tcgetattr(fd) {
        t.make_raw();
        let _ = tcsetattr(fd, OptionalActions::Now, &t);
    }
}

#[must_use]
pub fn get_winsize(fd: BorrowedFd<'_>) -> Option<(u16, u16)> {
    match tcgetwinsize(fd) {
        Ok(ws) if ws.ws_row > 0 && ws.ws_col > 0 => Some((ws.ws_row, ws.ws_col)),
        _ => None,
    }
}

pub fn set_winsize(fd: BorrowedFd<'_>, rows: u16, cols: u16) {
    let ws = Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let _ = tcsetwinsize(fd, ws);
}
