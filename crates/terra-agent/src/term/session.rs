//! Terminal-multiplexer core: broadcast output to all attached clients,
//! forward client input to the workload.

use crate::mutex::lock_recover;
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};
use terra_shared::contract::{AgentOutput, encode_frame};

pub(crate) const DEFAULT_ROWS: u16 = 24;
pub(crate) const DEFAULT_COLS: u16 = 80;

pub(crate) const MIN_ROWS: u16 = 5;
pub(crate) const MIN_COLS: u16 = 20;

/// Ceilings on wire-reported sizes to prevent memory exhaustion from large grid allocations.
pub(crate) const MAX_ROWS: u16 = 512;
pub(crate) const MAX_COLS: u16 = 1024;

pub type Sink = Arc<Mutex<dyn Write + Send>>;
const INPUT_QUEUE_CAPACITY: usize = 64;

/// Downstream sink for an attached vsock client or the guest console.
#[derive(Clone)]
pub(crate) struct ClientConn(Arc<Mutex<ClientConnKind>>);

enum ClientConnKind {
    Vsock(File),
    Console(std::io::Stdout),
}

impl ClientConn {
    pub(crate) fn from_vsock(conn: File) -> Self {
        Self(Arc::new(Mutex::new(ClientConnKind::Vsock(conn))))
    }

    pub(crate) fn from_console(stdout: std::io::Stdout) -> Self {
        Self(Arc::new(Mutex::new(ClientConnKind::Console(stdout))))
    }

    fn write(&self, msg: &AgentOutput) -> std::io::Result<()> {
        match &mut *lock_recover(&self.0) {
            ClientConnKind::Vsock(conn) => {
                let bytes = encode_frame(msg)?;
                conn.write_all(&bytes).and_then(|()| conn.flush())
            }
            ClientConnKind::Console(stdout) => match msg {
                AgentOutput::Out(bytes) => stdout.write_all(bytes).and_then(|()| stdout.flush()),
                AgentOutput::Err(_) | AgentOutput::Exit { .. } | AgentOutput::Detached => Ok(()),
            },
        }
    }
}

impl Drop for ClientConnKind {
    fn drop(&mut self) {
        if let ClientConnKind::Vsock(conn) = self {
            // Shut down socket so the host reader receives EOF despite cloned streams.
            let _ = rustix::net::shutdown(conn, rustix::net::Shutdown::Both);
        }
    }
}

pub struct Session {
    inner: Mutex<Inner>,
    input: std::sync::mpsc::SyncSender<Vec<u8>>,
}

struct Inner {
    parser: vt100::Parser,
    clients: Vec<Client>,
    next_id: u64,
    closed: bool,
    exit_code: i32,
}

struct Client {
    id: u64,
    conn: ClientConn,
    size: Option<(u16, u16)>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DetachOutcome {
    Missing,
    Detached { size: Option<(u16, u16)> },
}

impl Session {
    pub fn new(input: Sink) -> Arc<Self> {
        let (input_sender, input_receiver) =
            std::sync::mpsc::sync_channel::<Vec<u8>>(INPUT_QUEUE_CAPACITY);
        std::thread::spawn(move || {
            while let Ok(bytes) = input_receiver.recv() {
                let mut input = lock_recover(&input);
                if input
                    .write_all(&bytes)
                    .and_then(|()| input.flush())
                    .is_err()
                {
                    break;
                }
            }
        });
        Arc::new(Self {
            inner: Mutex::new(Inner {
                parser: vt100::Parser::new(DEFAULT_ROWS, DEFAULT_COLS, 0),
                clients: Vec::new(),
                next_id: 0,
                closed: false,
                exit_code: 0,
            }),
            input: input_sender,
        })
    }

    /// Broadcasts output to all attached clients, dropping any whose writes fail.
    pub fn feed_output(&self, bytes: &[u8]) {
        let clients = {
            let mut inner = lock_recover(&self.inner);
            inner.parser.process(bytes);
            inner
                .clients
                .iter()
                .map(|c| (c.id, c.conn.clone()))
                .collect::<Vec<_>>()
        };
        let frame = AgentOutput::Out(bytes.to_vec());
        let failed = clients
            .into_iter()
            .filter_map(|(id, conn)| conn.write(&frame).err().map(|_| id))
            .collect::<Vec<_>>();
        if !failed.is_empty() {
            lock_recover(&self.inner)
                .clients
                .retain(|client| !failed.contains(&client.id));
        }
    }

    /// Broadcasts the workload exit code to all clients and closes connections.
    pub fn broadcast_exit(&self, code: i32) {
        let clients = {
            let mut inner = lock_recover(&self.inner);
            inner.exit_code = code;
            inner.closed = true;
            std::mem::take(&mut inner.clients)
        };
        for client in clients {
            let _ = client.conn.write(&AgentOutput::Exit { code });
        }
    }

    /// Attaches a client and repaints the current screen, returning its client ID.
    #[must_use]
    pub fn attach_client(&self, conn: &ClientConn) -> u64 {
        let (id, output) = {
            let mut inner = lock_recover(&self.inner);
            let id = inner.next_id;
            inner.next_id += 1;
            let output = if inner.closed {
                AgentOutput::Exit {
                    code: inner.exit_code,
                }
            } else {
                inner.clients.push(Client {
                    id,
                    conn: conn.clone(),
                    size: None,
                });
                AgentOutput::Out(inner.parser.screen().contents_formatted())
            };
            (id, output)
        };
        let _ = conn.write(&output);
        id
    }

    pub fn detach_client(&self, id: u64) -> DetachOutcome {
        let (client, size) = {
            let mut inner = lock_recover(&self.inner);
            let Some(index) = inner.clients.iter().position(|client| client.id == id) else {
                return DetachOutcome::Missing;
            };
            let client = inner.clients.remove(index);
            (client, inner.update_shared_size())
        };
        let _ = client.conn.write(&AgentOutput::Detached);
        DetachOutcome::Detached { size }
    }

    pub fn detach_all_clients(&self) -> (Vec<u64>, Option<(u16, u16)>) {
        let (clients, size) = {
            let mut inner = lock_recover(&self.inner);
            let clients = std::mem::take(&mut inner.clients);
            let size = inner.update_shared_size();
            (clients, size)
        };
        for client in &clients {
            let _ = client.conn.write(&AgentOutput::Detached);
        }
        (clients.into_iter().map(|client| client.id).collect(), size)
    }

    pub fn list_clients(&self) -> Vec<(u64, Option<(u16, u16)>)> {
        lock_recover(&self.inner)
            .clients
            .iter()
            .map(|c| (c.id, c.size))
            .collect()
    }

    /// Records a client's terminal size, returning the new shared size if changed.
    pub fn set_client_size(&self, id: u64, rows: u16, cols: u16) -> Option<(u16, u16)> {
        let mut inner = lock_recover(&self.inner);
        let c = inner.clients.iter_mut().find(|c| c.id == id)?;
        c.size = Some((
            rows.clamp(MIN_ROWS, MAX_ROWS),
            cols.clamp(MIN_COLS, MAX_COLS),
        ));
        inner.update_shared_size()
    }

    pub fn send_input(&self, bytes: &[u8]) -> std::io::Result<()> {
        self.input
            .try_send(bytes.to_vec())
            .map_err(|error| match error {
                std::sync::mpsc::TrySendError::Full(_) => {
                    std::io::Error::from(std::io::ErrorKind::WouldBlock)
                }
                std::sync::mpsc::TrySendError::Disconnected(_) => {
                    std::io::Error::from(std::io::ErrorKind::BrokenPipe)
                }
            })
    }

    #[cfg(test)]
    #[must_use]
    fn count_clients(&self) -> usize {
        lock_recover(&self.inner).clients.len()
    }
}

impl Inner {
    fn update_shared_size(&mut self) -> Option<(u16, u16)> {
        let (rows, cols) = self
            .clients
            .iter()
            .filter_map(|c| c.size)
            .reduce(|(rows, cols), (r, c)| (rows.min(r), cols.min(c)))
            .unwrap_or((DEFAULT_ROWS, DEFAULT_COLS));
        if self.parser.screen().size() == (rows, cols) {
            return None;
        }
        self.parser.screen_mut().set_size(rows, cols);
        Some((rows, cols))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;
    use terra_shared::contract::read_frame;

    fn create_client_pair() -> (ClientConn, UnixStream) {
        let (client, server) = UnixStream::pair().unwrap();
        (
            ClientConn::from_vsock(File::from(std::os::fd::OwnedFd::from(server))),
            client,
        )
    }

    fn drain_repaint(stream: &mut UnixStream) {
        match read_frame::<AgentOutput>(stream).unwrap() {
            Some(AgentOutput::Out(_)) => {}
            other => panic!("expected a repaint frame, got {other:?}"),
        }
    }

    fn create_input_sink() -> (Sink, Arc<Mutex<Vec<u8>>>) {
        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        (shared.clone(), shared)
    }

    /// `terra <box> detach` ends with the client told it was detached - the
    /// frame is what turns the socket's close into a detach on the far end
    /// instead of a bare EOF that would read as the box dying.
    #[test]
    fn a_dropped_client_is_told_it_was_dropped() {
        let (input, _) = create_input_sink();
        let session = Session::new(input);
        let (one, mut a) = create_client_pair();
        let (two, mut b) = create_client_pair();
        let _ = session.attach_client(&one);
        let _ = session.attach_client(&two);
        drain_repaint(&mut a);
        drain_repaint(&mut b);

        session.detach_client(0);
        assert_eq!(
            read_frame::<AgentOutput>(&mut a).unwrap(),
            Some(AgentOutput::Detached)
        );
        b.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        assert!(
            read_frame::<AgentOutput>(&mut b).is_err(),
            "the surviving client was told too"
        );

        let _ = session.detach_all_clients();
        assert_eq!(
            read_frame::<AgentOutput>(&mut b).unwrap(),
            Some(AgentOutput::Detached)
        );
    }

    #[test]
    fn output_broadcasts_to_all_clients_and_reaches_the_process() {
        let (input, proc_in) = create_input_sink();
        let session = Session::new(input);

        let (a, mut a_stream) = create_client_pair();
        let (b, mut b_stream) = create_client_pair();
        let _ = session.attach_client(&a);
        let _ = session.attach_client(&b);
        assert_eq!(session.count_clients(), 2);
        drain_repaint(&mut a_stream);
        drain_repaint(&mut b_stream);

        session.feed_output(b"hello");
        assert_eq!(
            read_frame::<AgentOutput>(&mut a_stream).unwrap(),
            Some(AgentOutput::Out(b"hello".to_vec()))
        );
        assert_eq!(
            read_frame::<AgentOutput>(&mut b_stream).unwrap(),
            Some(AgentOutput::Out(b"hello".to_vec()))
        );

        session.send_input(b"q").unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while lock_recover(&proc_in).as_slice() != b"q" && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(&*lock_recover(&proc_in), b"q");
    }

    #[test]
    fn input_enqueue_does_not_wait_for_the_writer() {
        let (input, proc_in) = create_input_sink();
        let session = Session::new(input);
        let _writer = lock_recover(&proc_in);
        let start = std::time::Instant::now();
        session.send_input(b"q").unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn late_client_gets_a_screen_repaint_not_missed_history() {
        let (input, _) = create_input_sink();
        let session = Session::new(input);
        session.feed_output(b"important TUI state");

        let (late, mut stream) = create_client_pair();
        let _ = session.attach_client(&late);
        let Some(AgentOutput::Out(repaint)) = read_frame::<AgentOutput>(&mut stream).unwrap()
        else {
            panic!("a fresh client got no repaint");
        };
        assert!(
            repaint
                .windows(b"important TUI state".len())
                .any(|w| { w == b"important TUI state" })
        );
    }

    #[test]
    fn smallest_attached_terminal_wins() {
        let (input, _) = create_input_sink();
        let session = Session::new(input);
        let ida = session.attach_client(&create_client_pair().0);
        let idb = session.attach_client(&create_client_pair().0);

        assert_eq!(session.set_client_size(ida, 50, 200), Some((50, 200)));
        assert_eq!(session.set_client_size(idb, 30, 100), Some((30, 100)));
        assert_eq!(session.set_client_size(ida, 20, 300), Some((20, 100)));
        assert_eq!(session.set_client_size(ida, 20, 300), None);
        assert_eq!(
            session.detach_client(ida),
            DetachOutcome::Detached {
                size: Some((30, 100))
            }
        );
        assert_eq!(
            session.set_client_size(idb, 1, 1),
            Some((MIN_ROWS, MIN_COLS))
        );
        assert_eq!(
            session.set_client_size(idb, u16::MAX, u16::MAX),
            Some((MAX_ROWS, MAX_COLS))
        );
        assert_eq!(
            session.detach_client(idb),
            DetachOutcome::Detached {
                size: Some((DEFAULT_ROWS, DEFAULT_COLS))
            }
        );
    }

    /// `terra <box> sessions` shows the client list as it is: ids in attach order,
    /// the size each client reported, and `None` for one that reported none -
    /// the shape a stale-size cleanup reads before choosing a victim.
    #[test]
    fn list_clients_names_every_client_with_its_size() {
        let (input, _) = create_input_sink();
        let session = Session::new(input);
        assert_eq!(session.list_clients(), vec![]);

        let sized = session.attach_client(&create_client_pair().0);
        let plain = session.attach_client(&create_client_pair().0);
        session.set_client_size(sized, 30, 100);

        assert_eq!(
            session.list_clients(),
            vec![(sized, Some((30, 100))), (plain, None)]
        );

        assert_eq!(
            session.detach_client(sized),
            DetachOutcome::Detached {
                size: Some((DEFAULT_ROWS, DEFAULT_COLS))
            }
        );
        assert_eq!(session.list_clients(), vec![(plain, None)]);
        assert_eq!(
            session.detach_client(plain),
            DetachOutcome::Detached { size: None }
        );
        assert_eq!(session.detach_client(plain), DetachOutcome::Missing);
    }

    /// `detach --all` takes every client at once, and the size reverts with
    /// them - the same shared-size answer `detach` gives, so the caller applies
    /// one mechanism to both. An empty session has nothing to change and says
    /// so.
    #[test]
    fn detach_all_clears_the_clients_and_returns_the_default_size() {
        let (input, _) = create_input_sink();
        let session = Session::new(input);
        let a = session.attach_client(&create_client_pair().0);
        let _b = session.attach_client(&create_client_pair().0);
        session.set_client_size(a, 30, 100);

        assert_eq!(
            session.detach_all_clients().1,
            Some((DEFAULT_ROWS, DEFAULT_COLS))
        );
        assert_eq!(session.count_clients(), 0);
        assert_eq!(session.list_clients(), vec![]);
        assert_eq!(session.detach_all_clients().1, None);
    }

    /// Every attached client is owed the status the workload ended with - that
    /// is what lets whoever *joined* a box tell a workload that finished from a
    /// VM that was killed, which a bare EOF cannot say. It arrives after the
    /// output it belongs to, because the two share one connection, and the
    /// socket closes behind it.
    #[test]
    fn the_workloads_status_reaches_every_attached_client_after_its_output() {
        let (input, _) = create_input_sink();
        let session = Session::new(input);
        let (a, mut a_stream) = create_client_pair();
        let (b, mut b_stream) = create_client_pair();
        let _ = session.attach_client(&a);
        let _ = session.attach_client(&b);
        drain_repaint(&mut a_stream);
        drain_repaint(&mut b_stream);

        session.feed_output(b"the last line\n");
        session.broadcast_exit(42);
        drop(a);
        drop(b);

        for (stream, label) in [(&mut a_stream, "a"), (&mut b_stream, "b")] {
            assert_eq!(
                read_frame::<AgentOutput>(stream).unwrap(),
                Some(AgentOutput::Out(b"the last line\n".to_vec())),
                "client {label}"
            );
            assert_eq!(
                read_frame::<AgentOutput>(stream).unwrap(),
                Some(AgentOutput::Exit { code: 42 }),
                "client {label}"
            );
            assert_eq!(
                read_frame::<AgentOutput>(stream).unwrap(),
                None,
                "client {label}"
            );
        }
        assert_eq!(session.count_clients(), 0);
    }

    #[test]
    fn a_client_attaching_after_exit_gets_the_exit_status() {
        let (input, _) = create_input_sink();
        let session = Session::new(input);
        session.broadcast_exit(42);

        let (conn, mut stream) = create_client_pair();
        let _ = session.attach_client(&conn);

        assert_eq!(
            read_frame::<AgentOutput>(&mut stream).unwrap(),
            Some(AgentOutput::Exit { code: 42 })
        );
        assert_eq!(session.count_clients(), 0);
    }

    /// A client whose socket is gone is dropped on the next broadcast: the
    /// write fails and the session stops trying, so a dead far end cannot pile
    /// up frames in a vec it will never drain.
    #[test]
    fn dead_clients_are_dropped_on_broadcast() {
        let (input, _) = create_input_sink();
        let session = Session::new(input);
        let (conn, a) = create_client_pair();
        let _ = session.attach_client(&conn);
        // `shutdown`, not a bare drop: a concurrent test's fork inherits the
        // peer fd between fork and exec, and the inherited copy keeps the
        // socket alive - only the socket-level shutdown survives it.
        a.shutdown(std::net::Shutdown::Both).unwrap();
        drop(a);

        assert_eq!(session.count_clients(), 1);
        session.feed_output(b"x");
        assert_eq!(session.count_clients(), 0);
    }

    #[test]
    fn an_unknown_client_cannot_change_the_shared_size() {
        let (input, _) = create_input_sink();
        let session = Session::new(input);

        assert_eq!(session.set_client_size(42, 30, 100), None);
    }
}
