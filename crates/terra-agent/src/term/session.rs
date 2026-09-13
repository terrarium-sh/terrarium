//! Terminal-multiplexer core: broadcast output to all attached clients,
//! forward client input to the workload.

use crate::mutex::lock_or_abort;
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use terra_protocol::{AgentOutput, encode_frame};

pub(crate) const DEFAULT_ROWS: u16 = 24;
pub(crate) const DEFAULT_COLS: u16 = 80;

pub(crate) const MIN_ROWS: u16 = 5;
pub(crate) const MIN_COLS: u16 = 20;

/// Ceilings on wire-reported sizes to prevent memory exhaustion from large grid allocations.
pub(crate) const MAX_ROWS: u16 = 512;
pub(crate) const MAX_COLS: u16 = 1024;

pub type Sink = Arc<Mutex<dyn Write + Send>>;
const INPUT_QUEUE_CAPACITY: usize = 1;
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

/// Downstream sink for an attached vsock client.
#[derive(Clone)]
pub(crate) struct ClientConn(Arc<Mutex<ClientConnKind>>);

enum ClientConnKind {
    Vsock(File),
    #[cfg(test)]
    Test(Box<dyn Write + Send>),
}

impl ClientConn {
    pub(crate) fn from_vsock(conn: File) -> std::io::Result<Self> {
        rustix::net::sockopt::set_socket_timeout(
            &conn,
            rustix::net::sockopt::Timeout::Send,
            Some(CLIENT_WRITE_TIMEOUT),
        )?;
        Ok(Self(Arc::new(Mutex::new(ClientConnKind::Vsock(conn)))))
    }

    #[cfg(test)]
    fn from_test_sink(writer: impl Write + Send + 'static) -> Self {
        Self(Arc::new(Mutex::new(ClientConnKind::Test(Box::new(writer)))))
    }

    fn write(&self, msg: &AgentOutput) -> std::io::Result<()> {
        self.write_by(msg, Instant::now() + CLIENT_WRITE_TIMEOUT)
    }

    fn write_by(&self, msg: &AgentOutput, deadline: Instant) -> std::io::Result<()> {
        match &mut *lock_or_abort(&self.0) {
            ClientConnKind::Vsock(conn) => {
                let bytes = encode_frame(msg)?;
                write_until(conn, &bytes, deadline, |conn, timeout| {
                    Ok(rustix::net::sockopt::set_socket_timeout(
                        conn,
                        rustix::net::sockopt::Timeout::Send,
                        Some(timeout),
                    )?)
                })
            }
            #[cfg(test)]
            ClientConnKind::Test(writer) => {
                let bytes = encode_frame(msg)?;
                write_until(writer, &bytes, deadline, |_, _| Ok(()))
            }
        }
    }
}

fn write_until<W: Write>(
    writer: &mut W,
    mut bytes: &[u8],
    deadline: Instant,
    mut prepare_write: impl FnMut(&mut W, Duration) -> std::io::Result<()>,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .filter(|timeout| !timeout.is_zero())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::TimedOut))?;
        prepare_write(writer, prepare_socket_timeout(timeout))?;
        match writer.write(bytes) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero)),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    writer.flush()
}

fn prepare_socket_timeout(timeout: Duration) -> Duration {
    // rustix rounds fractional microseconds up without carrying into tv_sec.
    timeout
        .saturating_sub(Duration::from_nanos(u64::from(
            timeout.subsec_nanos() % 1_000,
        )))
        .max(Duration::from_micros(1))
}

impl Drop for ClientConnKind {
    fn drop(&mut self) {
        match self {
            Self::Vsock(conn) => {
                let _ = rustix::net::shutdown(conn, rustix::net::Shutdown::Both);
            }
            #[cfg(test)]
            Self::Test(_) => {}
        }
    }
}

pub struct Session {
    inner: Mutex<Inner>,
    delivery: Mutex<()>,
    _input_sink: Sink,
    input: std::sync::mpsc::SyncSender<Vec<u8>>,
}

struct Inner {
    parser: vt100::Parser,
    clients: Vec<Client>,
    next_id: u64,
    closed: bool,
    exit_code: i32,
    saw_output: bool,
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
        let input_sink = input.clone();
        std::thread::spawn(move || {
            while let Ok(bytes) = input_receiver.recv() {
                let mut input = lock_or_abort(&input);
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
                saw_output: false,
            }),
            delivery: Mutex::new(()),
            _input_sink: input_sink,
            input: input_sender,
        })
    }

    /// Broadcasts output, dropping clients that cannot be reached within one write budget.
    pub fn feed_output(&self, bytes: &[u8]) {
        let _delivery = lock_or_abort(&self.delivery);
        let frame = AgentOutput::Out(bytes.to_vec());
        let clients = {
            let mut inner = lock_or_abort(&self.inner);
            if inner.closed {
                return;
            }
            inner.parser.process(bytes);
            inner.saw_output = true;
            inner
                .clients
                .iter()
                .map(|client| (client.id, client.conn.clone()))
                .collect::<Vec<_>>()
        };
        let mut failed = Vec::new();
        for (id, conn) in clients {
            if conn
                .write_by(&frame, Instant::now() + CLIENT_WRITE_TIMEOUT)
                .is_err()
            {
                failed.push(id);
            }
        }
        if !failed.is_empty() {
            lock_or_abort(&self.inner)
                .clients
                .retain(|client| !failed.contains(&client.id));
        }
    }

    /// Broadcasts the workload exit code to all clients and closes connections.
    pub fn broadcast_exit(&self, code: i32) {
        let _delivery = lock_or_abort(&self.delivery);
        let clients = {
            let mut inner = lock_or_abort(&self.inner);
            inner.exit_code = code;
            inner.closed = true;
            std::mem::take(&mut inner.clients)
        };
        for client in clients {
            let _ = client.conn.write_by(
                &AgentOutput::Exit { code },
                Instant::now() + CLIENT_WRITE_TIMEOUT,
            );
        }
    }

    /// Attaches a client and repaints the current screen, returning its client ID on success.
    #[must_use]
    pub fn attach_client(&self, conn: &ClientConn) -> Option<u64> {
        let _delivery = lock_or_abort(&self.delivery);
        let (id, output, exit) = {
            let mut inner = lock_or_abort(&self.inner);
            let id = inner.next_id;
            inner.next_id += 1;
            let (output, exit) = if inner.closed {
                let output = inner
                    .saw_output
                    .then(|| AgentOutput::Out(inner.parser.screen().contents_formatted()));
                (output, Some(inner.exit_code))
            } else {
                inner.clients.push(Client {
                    id,
                    conn: conn.clone(),
                    size: None,
                });
                (
                    Some(AgentOutput::Out(inner.parser.screen().contents_formatted())),
                    None,
                )
            };
            (id, output, exit)
        };
        if let Some(output) = output
            && conn.write(&output).is_err()
        {
            lock_or_abort(&self.inner)
                .clients
                .retain(|client| client.id != id);
            return None;
        }
        if let Some(code) = exit
            && conn.write(&AgentOutput::Exit { code }).is_err()
        {
            return None;
        }
        Some(id)
    }

    pub fn detach_client(&self, id: u64) -> DetachOutcome {
        let _delivery = lock_or_abort(&self.delivery);
        let (client, size) = {
            let mut inner = lock_or_abort(&self.inner);
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
        let _delivery = lock_or_abort(&self.delivery);
        let (clients, size) = {
            let mut inner = lock_or_abort(&self.inner);
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
        lock_or_abort(&self.inner)
            .clients
            .iter()
            .map(|c| (c.id, c.size))
            .collect()
    }

    /// Records a client's terminal size, returning the new shared size if changed.
    pub fn set_client_size(&self, id: u64, rows: u16, cols: u16) -> Option<(u16, u16)> {
        let mut inner = lock_or_abort(&self.inner);
        let c = inner.clients.iter_mut().find(|c| c.id == id)?;
        c.size = Some((
            rows.clamp(MIN_ROWS, MAX_ROWS),
            cols.clamp(MIN_COLS, MAX_COLS),
        ));
        inner.update_shared_size()
    }

    pub fn send_input(&self, bytes: &[u8]) -> std::io::Result<()> {
        let deadline = Instant::now() + CLIENT_WRITE_TIMEOUT;
        let mut bytes = bytes.to_vec();
        loop {
            match self.input.try_send(bytes) {
                Ok(()) => return Ok(()),
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    return Err(std::io::ErrorKind::BrokenPipe.into());
                }
                Err(std::sync::mpsc::TrySendError::Full(pending)) => bytes = pending,
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            std::thread::sleep(remaining.min(Duration::from_millis(10)));
        }
    }

    #[cfg(test)]
    #[must_use]
    fn count_clients(&self) -> usize {
        lock_or_abort(&self.inner).clients.len()
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
    use std::sync::mpsc;
    use std::time::Duration;
    use terra_protocol::read_frame;

    fn create_client_pair() -> (ClientConn, UnixStream) {
        let (client, server) = UnixStream::pair().unwrap();
        (
            ClientConn::from_vsock(File::from(std::os::fd::OwnedFd::from(server))).unwrap(),
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

    struct StalledWriter {
        writes: usize,
        started: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }

    struct SlowWriter {
        writes: usize,
        started: Option<mpsc::Sender<()>>,
    }

    impl Write for SlowWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            if self.writes > 1 {
                if let Some(started) = self.started.take() {
                    let _ = started.send(());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct TrickleWriter;

    struct FailingWriter(mpsc::Sender<()>);

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            let _ = self.0.send(());
            Err(std::io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Write for TrickleWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            std::thread::sleep(Duration::from_millis(100));
            Ok(usize::from(!bytes.is_empty()))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_trickling_frame_cannot_extend_its_write_deadline() {
        let start = Instant::now();
        assert_eq!(
            write_until(
                &mut TrickleWriter,
                b"abcdefghij",
                start + Duration::from_millis(250),
                |_, _| Ok(())
            )
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::TimedOut
        );
        assert!(start.elapsed() < Duration::from_millis(400));
    }

    #[test]
    fn socket_timeout_does_not_round_into_an_invalid_timeval() {
        assert_eq!(
            prepare_socket_timeout(Duration::new(0, 999_999_999)),
            Duration::from_micros(999_999)
        );
        assert_eq!(
            prepare_socket_timeout(Duration::from_nanos(1)),
            Duration::from_micros(1)
        );
    }

    impl Write for StalledWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            if self.writes > 1 {
                let _ = self.started.send(());
                let _ = self.release.recv();
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn stalled_output_does_not_hold_session_state_lock() {
        let (input, _) = create_input_sink();
        let session = Session::new(input);
        let (started, started_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let client = ClientConn::from_test_sink(StalledWriter {
            writes: 0,
            started,
            release: release_rx,
        });
        let _ = session.attach_client(&client);

        let output_session = session.clone();
        let output = std::thread::spawn(move || output_session.feed_output(b"blocked"));
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let start = std::time::Instant::now();
        assert_eq!(session.list_clients().len(), 1);
        assert!(start.elapsed() < Duration::from_millis(100));
        release.send(()).unwrap();
        output.join().unwrap();
    }

    #[test]
    fn slow_clients_delay_an_attach_only_while_they_are_written() {
        let (input, _) = create_input_sink();
        let session = Session::new(input);
        let (started, started_rx) = mpsc::channel();
        for client_number in 0..4 {
            let client = ClientConn::from_test_sink(SlowWriter {
                writes: 0,
                started: (client_number == 0).then_some(started.clone()),
            });
            let _ = session.attach_client(&client);
        }
        let output_session = session.clone();
        let output = std::thread::spawn(move || output_session.feed_output(b"blocked"));
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let attach_session = session.clone();
        let attach = std::thread::spawn(move || {
            let client = ClientConn::from_test_sink(Vec::new());
            let _ = attach_session.attach_client(&client);
        });
        let start = std::time::Instant::now();
        attach.join().unwrap();
        assert!(start.elapsed() < Duration::from_millis(600));
        output.join().unwrap();
    }

    #[test]
    fn a_slow_client_does_not_skip_a_healthy_clients_output() {
        let (input, _) = create_input_sink();
        let session = Session::new(input);
        for _ in 0..11 {
            let _ = session.attach_client(&ClientConn::from_test_sink(SlowWriter {
                writes: 0,
                started: None,
            }));
        }
        let (healthy, mut stream) = create_client_pair();
        let _ = session.attach_client(&healthy);
        drain_repaint(&mut stream);
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        session.feed_output(b"still here");

        assert_eq!(
            read_frame::<AgentOutput>(&mut stream).unwrap(),
            Some(AgentOutput::Out(b"still here".to_vec()))
        );
    }

    #[test]
    fn a_client_whose_repaint_fails_is_not_attached() {
        let (input, _) = create_input_sink();
        let session = Session::new(input);
        let (failed, _) = mpsc::channel();

        assert_eq!(
            session.attach_client(&ClientConn::from_test_sink(FailingWriter(failed))),
            None
        );
        assert_eq!(session.count_clients(), 0);
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
        let mut fds = [rustix::event::PollFd::new(&b, rustix::event::PollFlags::IN)];
        rustix::event::poll(&mut fds, Some(&rustix::event::Timespec::default())).unwrap();
        assert!(
            fds[0].revents().is_empty(),
            "the surviving client was told too"
        );

        let _ = session.detach_all_clients();
        rustix::event::poll(
            &mut fds,
            Some(&rustix::event::Timespec::try_from(CLIENT_WRITE_TIMEOUT).unwrap()),
        )
        .unwrap();
        assert!(
            !fds[0].revents().is_empty(),
            "the survivor was not told it was dropped"
        );
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
        while lock_or_abort(&proc_in).as_slice() != b"q" && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(&*lock_or_abort(&proc_in), b"q");
    }

    #[test]
    fn input_enqueue_does_not_wait_for_the_writer() {
        let (input, proc_in) = create_input_sink();
        let session = Session::new(input);
        let _writer = lock_or_abort(&proc_in);
        let start = std::time::Instant::now();
        session.send_input(b"q").unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn failed_input_write_keeps_the_sink_alive_for_terminal_resizes() {
        let (failed, failed_rx) = mpsc::channel();
        let input: Sink = Arc::new(Mutex::new(FailingWriter(failed)));
        let session = Session::new(input.clone());
        session.send_input(b"q").unwrap();
        failed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while Arc::strong_count(&input) > 2 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert_eq!(Arc::strong_count(&input), 2);
    }

    #[test]
    fn full_input_queue_applies_backpressure_until_the_workload_reads() {
        let (started, started_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let input: Sink = Arc::new(Mutex::new(StalledWriter {
            writes: 1,
            started,
            release: release_rx,
        }));
        let session = Session::new(input);
        session.send_input(b"q").unwrap();
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        for _ in 0..INPUT_QUEUE_CAPACITY {
            session.send_input(b"q").unwrap();
        }
        assert_eq!(
            session.send_input(b"timeout").unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        let (sent, received) = mpsc::channel();
        let sender = std::thread::spawn(move || {
            session.send_input(b"last").unwrap();
            sent.send(()).unwrap();
        });
        assert!(received.recv_timeout(Duration::from_millis(50)).is_err());
        release.send(()).unwrap();
        received.recv_timeout(Duration::from_secs(1)).unwrap();
        sender.join().unwrap();
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
        let ida = session.attach_client(&create_client_pair().0).unwrap();
        let idb = session.attach_client(&create_client_pair().0).unwrap();

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

        let sized = session.attach_client(&create_client_pair().0).unwrap();
        let plain = session.attach_client(&create_client_pair().0).unwrap();
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
        let a = session.attach_client(&create_client_pair().0).unwrap();
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

    #[test]
    fn a_client_attaching_after_output_and_exit_receives_the_screen_then_status() {
        let (input, _) = create_input_sink();
        let session = Session::new(input);
        session.feed_output(b"one-shot\n");
        session.broadcast_exit(0);

        let (conn, mut stream) = create_client_pair();
        let _ = session.attach_client(&conn);

        let Some(AgentOutput::Out(output)) = read_frame(&mut stream).unwrap() else {
            panic!("late client did not receive output");
        };
        assert!(String::from_utf8_lossy(&output).contains("one-shot"));
        assert_eq!(
            read_frame::<AgentOutput>(&mut stream).unwrap(),
            Some(AgentOutput::Exit { code: 0 })
        );
    }

    #[test]
    fn output_after_exit_does_not_change_a_late_clients_repaint() {
        let (input, _) = create_input_sink();
        let session = Session::new(input);
        session.feed_output(b"before exit\n");
        session.broadcast_exit(0);
        session.feed_output(b"after exit\n");

        let (conn, mut stream) = create_client_pair();
        let _ = session.attach_client(&conn);
        let Some(AgentOutput::Out(output)) = read_frame(&mut stream).unwrap() else {
            panic!("late client did not receive output");
        };
        assert!(String::from_utf8_lossy(&output).contains("before exit"));
        assert!(!String::from_utf8_lossy(&output).contains("after exit"));
        assert_eq!(
            read_frame::<AgentOutput>(&mut stream).unwrap(),
            Some(AgentOutput::Exit { code: 0 })
        );
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
