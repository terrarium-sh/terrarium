//! Terminal-multiplexer core: broadcast output to all attached clients,
//! forward client input to the workload.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SCROLLBACK: usize = 1000;

/// The PTY size with no sized client attached.
pub(crate) const DEFAULT_ROWS: u16 = 24;
pub(crate) const DEFAULT_COLS: u16 = 80;

/// How many output chunks may be queued for one client before it is dropped:
/// the PTY pump reads 8 KiB at a time, so this bounds a stalled client at
/// around half a megabyte of guest memory. Dropping is safe - a `terra attach`
/// reconnects, and [`Session::attach`] repaints it from the screen model.
const OUTBOX: usize = 64;

pub(crate) const MIN_ROWS: u16 = 5;
pub(crate) const MIN_COLS: u16 = 20;

/// Ceilings on wire-reported sizes: `set_size` allocates a scrollback grid per
/// cell, so an unclamped `u16::MAX` report would exhaust PID 1's memory.
pub(crate) const MAX_ROWS: u16 = 512;
pub(crate) const MAX_COLS: u16 = 1024;

pub type Sink = Arc<Mutex<dyn Write + Send>>;

/// One attached client's downstream: output, and the status the workload
/// ended with.
pub trait ClientSink: Send {
    fn out(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    fn exit(&mut self, code: i32) -> std::io::Result<()>;
    fn detached(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The guest console, attached as a client by a `--foreground` boot alone: raw
/// bytes, and no channel for a status - what the box ended with reaches the
/// host over the control connection instead.
pub(crate) struct ConsoleSink(pub std::io::Stdout);

impl ClientSink for ConsoleSink {
    fn out(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.0.write_all(bytes).and_then(|()| self.0.flush())
    }
    fn exit(&mut self, _code: i32) -> std::io::Result<()> {
        Ok(())
    }
}

/// What one client's writer thread is handed.
enum Chunk {
    Out(Arc<[u8]>),
    Exit(i32),
    Detached,
}

pub struct Session {
    inner: Mutex<Inner>,
    input: Sink,
}

struct Inner {
    parser: vt100::Parser,
    clients: Vec<Client>,
    next_id: u64,
}

struct Client {
    id: u64,
    /// This client's outbox.
    out: std::sync::mpsc::SyncSender<Chunk>,
    /// The terminal size this client reported, floored; `None` puts no
    /// constraint on the session.
    size: Option<(u16, u16)>,
    /// Set by the writer thread when it has drained its outbox and finished.
    finished: Arc<AtomicBool>,
}

impl Session {
    pub fn new(input: Sink) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                parser: vt100::Parser::new(DEFAULT_ROWS, DEFAULT_COLS, SCROLLBACK),
                clients: Vec::new(),
                next_id: 0,
            }),
            input,
        })
    }

    /// Feed workload output: update the screen model and broadcast. Never
    /// blocks: a client that has stopped reading is dropped, not allowed to
    /// hold up the workload (see [`OUTBOX`]).
    ///
    /// ponytail: closes the *guest* side of that, and only that. End to end a
    /// stalled client still freezes the VM - libkrun's vsock muxer blocks on the
    /// host end of the proxied socket, which stops the console and `terra exec`
    /// too, and recovers when the client is killed. Upgrade path is upstream in
    /// the vendored fork: a bounded outbox per proxied connection, this same shape
    /// one layer down. Worth fixing here anyway - the two blocks are independent,
    /// and this one is ours.
    pub fn feed_output(&self, bytes: &[u8]) {
        let mut inner = lock(&self.inner);
        inner.parser.process(bytes);
        let chunk: Arc<[u8]> = Arc::from(bytes);
        inner
            .clients
            .retain(|c| c.out.try_send(Chunk::Out(chunk.clone())).is_ok());
    }

    /// Tell every attached client the status the workload ended with, and wait
    /// up to `grace` for those writes to land.
    pub fn broadcast_exit(&self, code: i32, grace: Duration) {
        let clients = std::mem::take(&mut lock(&self.inner).clients);
        let finished: Vec<Arc<AtomicBool>> = clients.iter().map(|c| c.finished.clone()).collect();
        for c in &clients {
            let _ = c.out.try_send(Chunk::Exit(code));
        }
        // The senders go with them, which is what ends each writer thread.
        drop(clients);
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline && !finished.iter().all(|f| f.load(Ordering::SeqCst)) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Attach a client, repainting it with the current screen. Returns an id
    /// for [`Session::detach_client`].
    ///
    /// The sink is written to only from a thread of its own, which taking it
    /// by value guarantees by construction.
    #[must_use]
    pub fn attach(&self, sink: impl ClientSink + 'static) -> u64 {
        let mut inner = lock(&self.inner);
        let (out, rx) = std::sync::mpsc::sync_channel::<Chunk>(OUTBOX);
        let finished = Arc::new(AtomicBool::new(false));
        let done = finished.clone();
        std::thread::spawn(move || {
            let mut sink = sink;
            // Ends when the session drops this client and the sender goes with
            // it, which closes the sink and lets the far end see EOF.
            for chunk in rx {
                let wrote = match chunk {
                    Chunk::Out(bytes) => sink.out(&bytes),
                    Chunk::Exit(code) => sink.exit(code),
                    Chunk::Detached => sink.detached(),
                };
                if wrote.is_err() {
                    break;
                }
            }
            done.store(true, Ordering::SeqCst);
        });
        // Best-effort initial paint, into an outbox nothing has used yet.
        let _ = out.try_send(Chunk::Out(Arc::from(
            inner.parser.screen().contents_formatted(),
        )));
        let id = inner.next_id;
        inner.next_id += 1;
        inner.clients.push(Client {
            id,
            out,
            size: None,
            finished,
        });
        id
    }

    pub fn detach_client(&self, id: u64) -> Option<(u16, u16)> {
        let mut inner = lock(&self.inner);
        if let Some(c) = inner.clients.iter().find(|c| c.id == id) {
            let _ = c.out.try_send(Chunk::Detached);
        }
        inner.clients.retain(|c| c.id != id);
        inner.shared_size()
    }

    pub fn detach_all_clients(&self) -> Option<(u16, u16)> {
        let mut inner = lock(&self.inner);
        for c in &inner.clients {
            let _ = c.out.try_send(Chunk::Detached);
        }
        inner.clients.clear();
        inner.shared_size()
    }

    /// The attached clients as `(id, size)` pairs, `size` `None` when the
    /// client reported none - what `terra <box> sessions` shows.
    pub fn list_clients(&self) -> Vec<(u64, Option<(u16, u16)>)> {
        lock(&self.inner)
            .clients
            .iter()
            .map(|c| (c.id, c.size))
            .collect()
    }

    /// Record a client's terminal size; returns the new shared size if it
    /// changed. tmux semantics: everyone sees what the tightest screen can
    /// show.
    pub fn set_client_size(&self, id: u64, rows: u16, cols: u16) -> Option<(u16, u16)> {
        let mut inner = lock(&self.inner);
        if let Some(c) = inner.clients.iter_mut().find(|c| c.id == id) {
            c.size = Some((
                rows.clamp(MIN_ROWS, MAX_ROWS),
                cols.clamp(MIN_COLS, MAX_COLS),
            ));
        }
        inner.shared_size()
    }

    /// Forward client keystrokes to the workload.
    pub fn send_input(&self, bytes: &[u8]) -> std::io::Result<()> {
        let mut g = self
            .input
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.write_all(bytes)?;
        g.flush()
    }

    #[cfg(test)]
    #[must_use]
    fn client_count(&self) -> usize {
        lock(&self.inner).clients.len()
    }
}

impl Inner {
    /// The size every client can show - the per-dimension minimum over
    /// reported sizes, or the default when nobody reports one - applied to
    /// the screen model; `None` when nothing changed.
    fn shared_size(&mut self) -> Option<(u16, u16)> {
        let (mut rows, mut cols) = (u16::MAX, u16::MAX);
        for (r, c) in self.clients.iter().filter_map(|c| c.size) {
            rows = rows.min(r);
            cols = cols.min(c);
        }
        if rows == u16::MAX {
            (rows, cols) = (DEFAULT_ROWS, DEFAULT_COLS);
        }
        if self.parser.screen().size() == (rows, cols) {
            return None;
        }
        self.parser.screen_mut().set_size(rows, cols);
        Some((rows, cols))
    }
}

/// One panicking client thread must not take the console down with it: recover
/// the lock instead of cascading the poison into every later broadcast.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A sink that was told it was detached: what the far end of a
    /// `terra <box> detach` reads, instead of a bare EOF that would read as
    /// the box dying.
    #[derive(Clone)]
    struct DetachRecorder {
        seen: Arc<Mutex<Vec<u8>>>,
        detached: Arc<Mutex<bool>>,
    }

    impl DetachRecorder {
        fn new() -> Self {
            Self {
                seen: Arc::new(Mutex::new(Vec::new())),
                detached: Arc::new(Mutex::new(false)),
            }
        }
        fn was_detached(&self) -> bool {
            *lock(&self.detached)
        }
    }

    impl ClientSink for DetachRecorder {
        fn out(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            lock(&self.seen).extend_from_slice(bytes);
            Ok(())
        }
        fn exit(&mut self, _code: i32) -> std::io::Result<()> {
            Ok(())
        }
        fn detached(&mut self) -> std::io::Result<()> {
            *lock(&self.detached) = true;
            Ok(())
        }
    }

    /// A dropped client is owed the news that it was dropped, queued behind
    /// whatever output it is still owed - the frame is what turns the socket's
    /// close into a detach on the far end. `detach_client` and `detach_all_clients` both say
    /// it, and the detach key's own drop does too, which is the one path that
    /// never reads the frame (that end already knows).
    #[test]
    fn a_dropped_client_is_told_it_was_dropped() {
        let (input, _) = input_sink();
        let session = Session::new(input);
        let one = DetachRecorder::new();
        let two = DetachRecorder::new();
        let _ = session.attach(one.clone());
        let _ = session.attach(two.clone());

        session.detach_client(0);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !one.was_detached() {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(one.was_detached(), "the detached client was never told");
        assert!(!two.was_detached(), "the surviving client was told too");

        session.detach_all_clients();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !two.was_detached() {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            two.was_detached(),
            "detach_all_clients never told the client"
        );
    }

    /// The PTY-side sink, which is still shared: one resource, several client
    /// reader threads writing keystrokes to it, and no fan-out to stall on.
    fn input_sink() -> (Sink, Arc<Mutex<Vec<u8>>>) {
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        (shared.clone(), shared)
    }

    /// A client sink the test can read back - output and the status separately,
    /// as a real client receives them. Cloned so the test keeps a handle after
    /// the session has taken one by value.
    #[derive(Clone)]
    struct Recorder {
        seen: Arc<Mutex<Vec<u8>>>,
        exited: Arc<Mutex<Option<i32>>>,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                seen: Arc::new(Mutex::new(Vec::new())),
                exited: Arc::new(Mutex::new(None)),
            }
        }

        /// Wait for `pred` to hold of what has been written so far.
        ///
        /// Needed because a broadcast now only queues: the write lands on the
        /// client's own thread, so reading straight after `feed_output` races it.
        /// That asynchrony is the point of the change, not an artefact of it.
        fn wait_for(&self, pred: impl Fn(&[u8]) -> bool) -> Vec<u8> {
            for _ in 0..500 {
                let got = lock(&self.seen).clone();
                if pred(&got) {
                    return got;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("timed out; the client received {:?}", lock(&self.seen));
        }

        fn exit_status(&self) -> Option<i32> {
            *lock(&self.exited)
        }
    }

    impl ClientSink for Recorder {
        fn out(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            lock(&self.seen).extend_from_slice(bytes);
            Ok(())
        }
        fn exit(&mut self, code: i32) -> std::io::Result<()> {
            *lock(&self.exited) = Some(code);
            Ok(())
        }
    }

    #[test]
    fn output_broadcasts_to_all_clients_and_reaches_the_process() {
        let (input, proc_in) = input_sink();
        let session = Session::new(input);

        let (a, b) = (Recorder::new(), Recorder::new());
        let _ = session.attach(a.clone());
        let _ = session.attach(b.clone());
        assert_eq!(session.client_count(), 2);

        session.feed_output(b"hello");
        a.wait_for(|got| got.ends_with(b"hello"));
        b.wait_for(|got| got.ends_with(b"hello"));

        session.send_input(b"q").unwrap();
        assert_eq!(&*lock(&proc_in), b"q");
    }

    #[test]
    fn late_client_gets_a_screen_repaint_not_missed_history() {
        let (input, _) = input_sink();
        let session = Session::new(input);
        session.feed_output(b"important TUI state");

        let late = Recorder::new();
        let _ = session.attach(late.clone());
        late.wait_for(|got| {
            got.windows(b"important TUI state".len())
                .any(|w| w == b"important TUI state")
        });
    }

    #[test]
    fn smallest_attached_terminal_wins() {
        let (input, _) = input_sink();
        let session = Session::new(input);
        let ida = session.attach(Recorder::new());
        let idb = session.attach(Recorder::new());

        assert_eq!(session.set_client_size(ida, 50, 200), Some((50, 200)));
        // A smaller client shrinks the session to fit it…
        assert_eq!(session.set_client_size(idb, 30, 100), Some((30, 100)));
        // …per dimension: short-but-wide meets tall-but-narrow.
        assert_eq!(session.set_client_size(ida, 20, 300), Some((20, 100)));
        // Same report again: nothing changed, nothing to apply.
        assert_eq!(session.set_client_size(ida, 20, 300), None);
        // The constraint leaves with the client.
        assert_eq!(session.detach_client(ida), Some((30, 100)));
        // The floor holds against an absurd report.
        assert_eq!(
            session.set_client_size(idb, 1, 1),
            Some((MIN_ROWS, MIN_COLS))
        );
        // So does the ceiling: the screen model allocates a cell per row×col,
        // and the size arrives from the wire.
        assert_eq!(
            session.set_client_size(idb, u16::MAX, u16::MAX),
            Some((MAX_ROWS, MAX_COLS))
        );
        // The last sized client leaving reverts the session to the default -
        // a departed terminal's size must not outlive it.
        assert_eq!(
            session.detach_client(idb),
            Some((DEFAULT_ROWS, DEFAULT_COLS))
        );
    }

    /// `terra <box> sessions` shows the client list as it is: ids in attach order,
    /// the size each client reported, and `None` for one that reported none -
    /// the shape a stale-size cleanup reads before choosing a victim.
    #[test]
    fn list_clients_names_every_client_with_its_size() {
        let (input, _) = input_sink();
        let session = Session::new(input);
        assert_eq!(session.list_clients(), vec![]);

        let sized = session.attach(Recorder::new());
        let plain = session.attach(Recorder::new());
        session.set_client_size(sized, 30, 100);

        assert_eq!(
            session.list_clients(),
            vec![(sized, Some((30, 100))), (plain, None)]
        );

        session.detach_client(sized);
        assert_eq!(session.list_clients(), vec![(plain, None)]);
    }

    /// `detach --all` takes every client at once, and the size reverts with
    /// them - the same shared-size answer `detach` gives, so the caller applies
    /// one mechanism to both. An empty session has nothing to change and says
    /// so.
    #[test]
    fn detach_all_clears_the_clients_and_returns_the_default_size() {
        let (input, _) = input_sink();
        let session = Session::new(input);
        let a = session.attach(Recorder::new());
        let _b = session.attach(Recorder::new());
        session.set_client_size(a, 30, 100);

        assert_eq!(
            session.detach_all_clients(),
            Some((DEFAULT_ROWS, DEFAULT_COLS))
        );
        assert_eq!(session.client_count(), 0);
        assert_eq!(session.list_clients(), vec![]);
        // One more is a no-op, not an error: the box was already bare.
        assert_eq!(session.detach_all_clients(), None);
    }

    /// Every attached client is owed the status the workload ended with - that
    /// is what lets whoever *joined* a box tell a workload that finished from a
    /// VM that was killed, which a bare EOF cannot say. It arrives after the
    /// output it belongs to, because the two share one queue.
    #[test]
    fn the_workloads_status_reaches_every_attached_client_after_its_output() {
        let (input, _) = input_sink();
        let session = Session::new(input);
        let (a, b) = (Recorder::new(), Recorder::new());
        let _ = session.attach(a.clone());
        let _ = session.attach(b.clone());

        session.feed_output(b"the last line\n");
        assert_eq!(a.exit_status(), None, "nothing has ended yet");

        session.broadcast_exit(42, Duration::from_secs(5));

        for (who, client) in [("a", &a), ("b", &b)] {
            assert_eq!(client.exit_status(), Some(42), "client {who}");
            // Panics naming what it did receive if the output never landed.
            client.wait_for(|got| got.ends_with(b"the last line\n"));
        }
        // The clients are gone with it: the session has nothing left to serve,
        // and each socket closes behind the status it just carried.
        assert_eq!(session.client_count(), 0);
    }

    /// A client that has stopped reading must not hold up the box's shutdown:
    /// the guest is on its way out, and the host takes the VM down the moment
    /// the status crosses the control connection.
    #[test]
    fn a_stalled_client_cannot_hold_the_shutdown_past_the_grace() {
        struct NeverReturns;
        impl ClientSink for NeverReturns {
            fn out(&mut self, _: &[u8]) -> std::io::Result<()> {
                std::thread::sleep(Duration::from_secs(30));
                Ok(())
            }
            fn exit(&mut self, _: i32) -> std::io::Result<()> {
                Ok(())
            }
        }

        let (input, _) = input_sink();
        let session = Session::new(input);
        let _ = session.attach(NeverReturns);
        session.feed_output(b"parks the writer thread");

        let start = Instant::now();
        session.broadcast_exit(0, Duration::from_millis(200));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "a stalled client held the shutdown for {:?}",
            start.elapsed()
        );
    }

    /// A sink that refuses everything: its writer thread ends on the first
    /// chunk, so the next broadcast finds the outbox gone and drops the client.
    struct Broken;
    impl ClientSink for Broken {
        fn out(&mut self, _: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn exit(&mut self, _: i32) -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn dead_clients_are_dropped_on_broadcast() {
        let (input, _) = input_sink();
        let session = Session::new(input);
        let _ = session.attach(Broken);
        assert_eq!(session.client_count(), 1);
        // One broadcast more than before: the write fails on the client's own
        // thread now, so the session learns about it from the closed outbox.
        for _ in 0..500 {
            session.feed_output(b"x");
            if session.client_count() == 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("a client that cannot be written to was never dropped");
    }

    /// The reason every client has a thread. A broadcast used to write to each
    /// sink under the session lock, so one client that stopped draining froze the
    /// PTY pump, the console, and every other client. Now it fills its own outbox
    /// and is dropped alone.
    ///
    /// In-process only: end to end a stalled client still freezes the VM, on
    /// libkrun's side of the socket. That is why this is a unit test and not a
    /// boot-suite one - the box-level symptom is dominated by something this
    /// cannot reach.
    #[test]
    fn a_stalled_client_does_not_hold_up_the_others() {
        struct Stalled;
        impl ClientSink for Stalled {
            fn out(&mut self, _: &[u8]) -> std::io::Result<()> {
                // Long enough to stay stalled for the whole loop below, short
                // enough that a regression reports in seconds rather than
                // waiting this out: under the old blocking broadcast the loop
                // cannot finish until this returns.
                std::thread::sleep(Duration::from_secs(20));
                Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
            }
            fn exit(&mut self, _: i32) -> std::io::Result<()> {
                Ok(())
            }
        }

        let (input, _) = input_sink();
        let session = Session::new(input);
        let _ = session.attach(Stalled);
        let healthy = Recorder::new();
        let _ = session.attach(healthy.clone());

        // Well past the stalled client's outbox, so the old code would be parked
        // in its `write_all` with the session lock held.
        let start = std::time::Instant::now();
        let ticks = OUTBOX * 4;
        for _ in 0..ticks {
            session.feed_output(b"tick ");
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "a stalled client blocked the broadcast for {:?}",
            start.elapsed()
        );
        // Every tick must land - a healthy client dropped mid-loop would
        // still pass an ends-with check, and the count below would fail
        // without naming why.
        healthy.wait_for(|got| {
            got.windows(b"tick ".len())
                .filter(|w| *w == b"tick ")
                .count()
                == ticks
        });
        assert_eq!(
            session.client_count(),
            1,
            "the stalled client should have been dropped, and only it"
        );
    }
}
