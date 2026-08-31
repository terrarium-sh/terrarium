//! The muxed terminal: the workload's PTY session and the console attached to
//! it. The workload is spawned by [`crate::init`], which also serves the agent
//! port ([`crate::vsock::serve_agent_port`]); this module multiplexes.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::similar_names,
    clippy::struct_field_names
)]

use crate::term::session::{ConsoleSink, Session, Sink};
use crate::term::tty::{set_raw, set_winsize, winsize};
use crate::vsock::VsockListener;
use anyhow::Result;
use pty_process::blocking::Pty;
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CONSOLE_REATTACH_POLL: Duration = Duration::from_millis(500);

/// How long the workload's last output is given to cross the PTY after the
/// process itself has gone - see the drain in [`Terminal::wait`]. Bounded
/// because EOF may never come: a backgrounded grandchild can hold the slave
/// open for as long as it likes, and the box still has to stop.
const OUTPUT_DRAIN_GRACE: Duration = Duration::from_secs(2);

/// The workload's terminal: its PTY session, the output pump, and the clients
/// attached to it. The child was spawned by [`crate::init`] on a fresh PTY;
/// this multiplexes it until [`Terminal::wait`] reaps it.
pub struct Terminal {
    child: Child,
    session: Arc<Session>,
    /// `true` once [`Terminal::wait`] has reaped the workload - the handle
    /// the graceful stop watcher polls.
    exited: Arc<AtomicBool>,
    drained: std::sync::mpsc::Receiver<()>,
}

impl Terminal {
    /// Multiplex `child`'s PTY: split the master into separate read/write
    /// fds, pump its output into the session, and attach the console and the
    /// agent port.
    ///
    /// The console is attached *before* the pump below: a one-shot printing
    /// more than a screenful into an empty session would have the overflow
    /// replaced by the repaint [`Session::attach`] sends.
    pub fn start(
        pty: Pty,
        child: Child,
        on_console: bool,
        port: VsockListener,
        as_root: bool,
    ) -> Result<Terminal> {
        let master: OwnedFd = pty.into();
        let reader = master.try_clone()?;
        let input_file = std::fs::File::from(master);
        // A raw fd for TIOCSWINSZ; valid while `input_file` (held by the
        // session) lives. Any fd on the pty master works for the ioctl.
        let master_fd = input_file.as_raw_fd();
        let input: Sink = Arc::new(Mutex::new(input_file));

        let session = Session::new(input);
        if on_console {
            attach_console(&session, master_fd);
        }

        // Never joined - a join can hang (see [`OUTPUT_DRAIN_GRACE`]). `drained`
        // is the bounded stand-in: the sender lives in the pump thread, so the
        // channel disconnects the moment the pump ends.
        let (drained_tx, drained) = std::sync::mpsc::channel::<()>();
        let out_session = session.clone();
        std::thread::spawn(move || {
            let _drained_tx = drained_tx;
            let mut reader = std::fs::File::from(reader);
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => out_session.feed_output(&buf[..n]),
                }
            }
        });

        crate::vsock::serve_agent_port(&session, port, master_fd, as_root);

        Ok(Terminal {
            child,
            session,
            exited: Arc::new(AtomicBool::new(false)),
            drained,
        })
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The handle the graceful stop watcher polls: `true` once [`Terminal::wait`]
    /// has reaped the workload.
    pub fn exited(&self) -> Arc<AtomicBool> {
        self.exited.clone()
    }

    /// The session clients are attached to; the box broadcasts its exit
    /// status over it.
    pub fn session(&self) -> Arc<Session> {
        self.session.clone()
    }

    /// Reap the workload, hand back its status, and wait its last output
    /// through the pump.
    ///
    /// PID 1's own exit tells the host nothing - libkrun reports every clean
    /// shutdown the same way - so the status is carried out deliberately, over
    /// the control connection (see [`terra_shared::send_exit_status`]).
    ///
    /// The workload's last bytes are commonly still in the PTY when it is
    /// reaped, and the pump that carries them into the session runs on a
    /// thread of its own. [`Session::broadcast_exit`] takes every client away
    /// moments after this returns, so without this wait a one-shot fast enough
    /// to finish before its own output was pumped (`echo x; exit 7`) left
    /// `terra logs` with a boot banner and no output at all.
    pub fn wait(&mut self) -> i32 {
        let code = crate::exec::exit_code(&mut self.child);
        self.exited.store(true, Ordering::SeqCst);
        let _ = self.drained.recv_timeout(OUTPUT_DRAIN_GRACE);
        code
    }
}

/// Attach fd 0/1 as a client: broadcast output to stdout, forward stdin keys.
fn attach_console(session: &Arc<Session>, master_fd: RawFd) {
    set_raw(0);
    let id = session.attach(ConsoleSink(std::io::stdout()));
    // hvc0 on an interactive host reports a real size; a headless console
    // reports none.
    if let Some((rows, cols)) = winsize(0)
        && let Some((r, c)) = session.set_client_size(id, rows, cols)
    {
        set_winsize(master_fd, r, c);
    }

    // Watch for a console dropped for a full outbox and re-attach it.
    let watcher = session.clone();
    std::thread::spawn(move || {
        let mut id = id;
        loop {
            std::thread::sleep(CONSOLE_REATTACH_POLL);
            if !watcher.list_clients().iter().any(|(live, _)| *live == id) {
                id = watcher.attach(ConsoleSink(std::io::stdout()));
                if let Some((rows, cols)) = winsize(0)
                    && let Some((r, c)) = watcher.set_client_size(id, rows, cols)
                {
                    set_winsize(master_fd, r, c);
                }
            }
        }
    });

    let session = session.clone();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 8192];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if session.send_input(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });
}
