//! Terminal-multiplexer core: broadcast output to attached clients and forward input.

use crate::AsyncFile;
#[cfg(test)]
use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{Arc, Weak};
use std::time::Duration;
use terra_protocol::AgentOutput;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{Mutex, mpsc};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub(crate) const DEFAULT_ROWS: u16 = 24;
pub(crate) const DEFAULT_COLS: u16 = 80;
pub(crate) const MIN_ROWS: u16 = 5;
pub(crate) const MIN_COLS: u16 = 20;
pub(crate) const MAX_ROWS: u16 = 512;
pub(crate) const MAX_COLS: u16 = 1024;

const INPUT_QUEUE_CAPACITY: usize = 1;
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const REPAINT_CHUNK_BYTES: usize = 64 << 10;

/// Downstream connection for an attached vsock client.
#[derive(Clone)]
pub(crate) struct ClientConn(Arc<ClientConnInner>);

struct ClientConnInner {
    file: Mutex<AsyncFile>,
    shutdown: OwnedFd,
}

impl ClientConn {
    #[cfg(test)]
    pub(crate) fn from_vsock(conn: File) -> std::io::Result<Self> {
        Self::from_async(crate::into_async_file(conn)?)
    }

    pub(crate) fn from_async(conn: AsyncFile) -> std::io::Result<Self> {
        let shutdown = conn.get_ref().as_fd().try_clone_to_owned()?;
        Ok(Self(Arc::new(ClientConnInner {
            file: Mutex::new(conn),
            shutdown,
        })))
    }

    async fn write(&self, message: &AgentOutput) -> std::io::Result<()> {
        tokio::time::timeout(CLIENT_WRITE_TIMEOUT, async {
            terra_protocol::write_frame_async(&mut *self.0.file.lock().await, message).await
        })
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
    }

    async fn write_out_chunks(&self, bytes: &[u8]) -> std::io::Result<()> {
        for chunk in bytes.chunks(REPAINT_CHUNK_BYTES) {
            self.write(&AgentOutput::Out(chunk.to_vec())).await?;
        }
        Ok(())
    }

    fn close(&self) {
        let _ = rustix::net::shutdown(&self.0.shutdown, rustix::net::Shutdown::Both);
    }
}

impl Drop for ClientConnInner {
    fn drop(&mut self) {
        let _ = rustix::net::shutdown(
            self.file.get_mut().get_ref().as_fd(),
            rustix::net::Shutdown::Both,
        );
    }
}

pub struct Session {
    inner: Mutex<Inner>,
    delivery: Mutex<()>,
    input_fd: OwnedFd,
    input: mpsc::Sender<Vec<u8>>,
    cancellation: CancellationToken,
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
    pub fn new(
        input: AsyncFile,
        cancellation: &CancellationToken,
        tasks: &TaskTracker,
    ) -> std::io::Result<Arc<Self>> {
        let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(INPUT_QUEUE_CAPACITY);
        let input_fd = input.get_ref().as_fd().try_clone_to_owned()?;
        let cancellation = cancellation.clone();
        let session = Arc::new(Self {
            inner: Mutex::new(Inner {
                parser: vt100::Parser::new(DEFAULT_ROWS, DEFAULT_COLS, 0),
                clients: Vec::new(),
                next_id: 0,
                closed: false,
                exit_code: 0,
                saw_output: false,
            }),
            delivery: Mutex::new(()),
            input_fd,
            input: sender,
            cancellation: cancellation.clone(),
        });
        tasks.spawn(cancellation.clone().run_until_cancelled_owned(async move {
            let mut writer = input;
            while let Some(bytes) = receiver.recv().await {
                if writer.write_all(&bytes).await.is_err() || writer.flush().await.is_err() {
                    break;
                }
            }
        }));
        let session_weak = Arc::downgrade(&session);
        tasks.spawn(close_on_cancellation(session_weak, cancellation));
        Ok(session)
    }

    pub(crate) fn input_fd(&self) -> BorrowedFd<'_> {
        self.input_fd.as_fd()
    }

    /// Broadcasts output, dropping clients that do not finish a frame within one second.
    pub(crate) async fn feed_output(&self, bytes: &[u8]) {
        let _delivery = self.delivery.lock().await;
        let clients = {
            let mut inner = self.inner.lock().await;
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
        let output = AgentOutput::Out(bytes.to_vec());
        let mut failed = Vec::new();
        for (id, conn) in clients {
            if conn.write(&output).await.is_err() {
                conn.close();
                failed.push(id);
            }
        }
        if !failed.is_empty() {
            self.inner
                .lock()
                .await
                .clients
                .retain(|client| !failed.contains(&client.id));
        }
    }

    /// Broadcasts the workload exit code and closes attached connections.
    pub(crate) async fn broadcast_exit(&self, code: i32) {
        let _delivery = self.delivery.lock().await;
        let clients = {
            let mut inner = self.inner.lock().await;
            inner.exit_code = code;
            inner.closed = true;
            std::mem::take(&mut inner.clients)
        };
        for client in clients {
            let _ = client.conn.write(&AgentOutput::Exit { code }).await;
            client.conn.close();
        }
    }

    /// Attaches a client and repaints the current screen.
    pub(crate) async fn attach_client(&self, conn: &ClientConn) -> Option<u64> {
        let _delivery = self.delivery.lock().await;
        let (id, output, exit) = {
            let mut inner = self.inner.lock().await;
            let id = inner.next_id;
            inner.next_id += 1;
            if inner.closed {
                let output = inner
                    .saw_output
                    .then(|| inner.parser.screen().contents_formatted());
                (id, output, Some(inner.exit_code))
            } else {
                let output = inner.parser.screen().contents_formatted();
                inner.clients.push(Client {
                    id,
                    conn: conn.clone(),
                    size: None,
                });
                (id, Some(output), None)
            }
        };
        if let Some(output) = output
            && conn.write_out_chunks(&output).await.is_err()
        {
            self.inner
                .lock()
                .await
                .clients
                .retain(|client| client.id != id);
            return None;
        }
        if let Some(code) = exit
            && conn.write(&AgentOutput::Exit { code }).await.is_err()
        {
            return None;
        }
        if exit.is_some() {
            conn.close();
        }
        Some(id)
    }

    pub(crate) async fn detach_client(&self, id: u64) -> DetachOutcome {
        let _delivery = self.delivery.lock().await;
        let (client, size) = {
            let mut inner = self.inner.lock().await;
            let Some(index) = inner.clients.iter().position(|client| client.id == id) else {
                return DetachOutcome::Missing;
            };
            let client = inner.clients.remove(index);
            let size = inner.update_shared_size();
            (client, size)
        };
        let _ = client.conn.write(&AgentOutput::Detached).await;
        client.conn.close();
        DetachOutcome::Detached { size }
    }

    pub(crate) async fn detach_all_clients(&self) -> (Vec<u64>, Option<(u16, u16)>) {
        let _delivery = self.delivery.lock().await;
        let (clients, size) = {
            let mut inner = self.inner.lock().await;
            let clients = std::mem::take(&mut inner.clients);
            let size = inner.update_shared_size();
            (clients, size)
        };
        for client in &clients {
            let _ = client.conn.write(&AgentOutput::Detached).await;
            client.conn.close();
        }
        (clients.into_iter().map(|client| client.id).collect(), size)
    }

    pub(crate) async fn list_clients(&self) -> Vec<(u64, Option<(u16, u16)>)> {
        self.inner
            .lock()
            .await
            .clients
            .iter()
            .map(|client| (client.id, client.size))
            .collect()
    }

    /// Records a client terminal size, returning the changed shared size.
    pub(crate) async fn set_client_size(
        &self,
        id: u64,
        rows: u16,
        cols: u16,
    ) -> Option<(u16, u16)> {
        let mut inner = self.inner.lock().await;
        let client = inner.clients.iter_mut().find(|client| client.id == id)?;
        client.size = Some((
            rows.clamp(MIN_ROWS, MAX_ROWS),
            cols.clamp(MIN_COLS, MAX_COLS),
        ));
        inner.update_shared_size()
    }

    pub(crate) async fn send_input(&self, bytes: &[u8]) -> std::io::Result<()> {
        tokio::select! {
            () = self.cancellation.cancelled() => Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
            result = tokio::time::timeout(CLIENT_WRITE_TIMEOUT, self.input.send(bytes.to_vec())) => {
                result
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
        }
    }

    async fn close_clients(&self) {
        let clients = {
            let mut inner = self.inner.lock().await;
            inner.closed = true;
            std::mem::take(&mut inner.clients)
        };
        for client in clients {
            client.conn.close();
        }
    }
}

async fn close_on_cancellation(session: Weak<Session>, cancellation: CancellationToken) {
    cancellation.cancelled().await;
    if let Some(session) = session.upgrade() {
        session.close_clients().await;
    }
}

impl Inner {
    fn update_shared_size(&mut self) -> Option<(u16, u16)> {
        let (rows, cols) = self
            .clients
            .iter()
            .filter_map(|client| client.size)
            .reduce(|(rows, cols), (other_rows, other_cols)| {
                (rows.min(other_rows), cols.min(other_cols))
            })
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
    use tokio::io::AsyncReadExt as _;

    fn session() -> (Arc<Session>, AsyncFile) {
        let (input, sink) = std::os::unix::net::UnixStream::pair().unwrap();
        let cancellation = CancellationToken::new();
        let tasks = TaskTracker::new();
        (
            Session::new(
                crate::into_async_file(input).unwrap(),
                &cancellation,
                &tasks,
            )
            .unwrap(),
            crate::into_async_file(sink).unwrap(),
        )
    }

    fn client() -> (ClientConn, AsyncFile) {
        let (client, agent) = std::os::unix::net::UnixStream::pair().unwrap();
        (
            ClientConn::from_vsock(File::from(std::os::fd::OwnedFd::from(agent))).unwrap(),
            crate::into_async_file(client).unwrap(),
        )
    }

    async fn frame(reader: &mut AsyncFile) -> AgentOutput {
        tokio::time::timeout(
            Duration::from_secs(2),
            terra_protocol::read_frame_async(reader),
        )
        .await
        .expect("timed out waiting for a frame")
        .unwrap()
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn output_reaches_clients_before_exit() {
        let (session, _) = session();
        let (first, mut first_reader) = client();
        let (second, mut second_reader) = client();
        session.attach_client(&first).await.unwrap();
        session.attach_client(&second).await.unwrap();
        let _ = frame(&mut first_reader).await;
        let _ = frame(&mut second_reader).await;

        session.feed_output(b"last line\n").await;
        session.broadcast_exit(42).await;

        for reader in [&mut first_reader, &mut second_reader] {
            assert_eq!(
                frame(reader).await,
                AgentOutput::Out(b"last line\n".to_vec())
            );
            assert_eq!(frame(reader).await, AgentOutput::Exit { code: 42 });
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn input_reaches_the_pty() {
        let (session, mut input) = session();
        session.send_input(b"q").await.unwrap();
        let mut received = [0];
        tokio::time::timeout(Duration::from_secs(1), input.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, b"q");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn smallest_terminal_controls_the_shared_size() {
        let (session, _) = session();
        let (first, _first_reader) = client();
        let (second, _second_reader) = client();
        let first = session.attach_client(&first).await.unwrap();
        let second = session.attach_client(&second).await.unwrap();

        assert_eq!(
            session.set_client_size(first, 50, 200).await,
            Some((50, 200))
        );
        assert_eq!(
            session.set_client_size(second, 30, 100).await,
            Some((30, 100))
        );
        assert_eq!(
            session.detach_client(second).await,
            DetachOutcome::Detached {
                size: Some((50, 200))
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn late_client_gets_the_screen_then_exit() {
        let (session, _) = session();
        session.feed_output(b"one-shot\n").await;
        session.broadcast_exit(0).await;
        let (client, mut reader) = client();
        session.attach_client(&client).await.unwrap();

        let AgentOutput::Out(output) = frame(&mut reader).await else {
            panic!("late client did not receive a repaint");
        };
        assert!(String::from_utf8_lossy(&output).contains("one-shot"));
        assert_eq!(frame(&mut reader).await, AgentOutput::Exit { code: 0 });
    }

    /// A supported 512×1024 attributed screen repaints to more than the 8 MiB
    /// frame limit, so the repaint goes out as consecutive frames no larger
    /// than `REPAINT_CHUNK_BYTES` - as one frame the protocol refused it and
    /// the attaching client received nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_repaint_above_the_frame_limit_is_chunked() {
        let (session, _) = session();
        session
            .inner
            .lock()
            .await
            .parser
            .screen_mut()
            .set_size(MAX_ROWS, MAX_COLS);
        let cells = usize::from(MAX_ROWS) * usize::from(MAX_COLS);
        let bytes = "\x1b[38;2;0;0;0mX\x1b[38;2;255;255;255mX".repeat(cells / 2);
        session.feed_output(bytes.as_bytes()).await;
        let expected = session
            .inner
            .lock()
            .await
            .parser
            .screen()
            .contents_formatted();
        assert!(
            expected.len() > (8 << 20),
            "the screen must overflow the frame limit: {}",
            expected.len()
        );
        session.broadcast_exit(0).await;

        let (client, mut reader) = client();
        let attach = tokio::spawn({
            let session = session.clone();
            let client = client.clone();
            async move { session.attach_client(&client).await }
        });
        let mut painted = Vec::new();
        loop {
            match frame(&mut reader).await {
                AgentOutput::Out(chunk) => {
                    assert!(chunk.len() <= REPAINT_CHUNK_BYTES, "{}", chunk.len());
                    painted.extend_from_slice(&chunk);
                }
                AgentOutput::Exit { code: 0 } => break,
                other => panic!("unexpected frame: {other:?}"),
            }
        }
        assert_eq!(attach.await.unwrap().unwrap(), 0);
        assert_eq!(painted, expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_output_waits_for_all_repaint_chunks() {
        let (session, _) = session();
        session
            .inner
            .lock()
            .await
            .parser
            .screen_mut()
            .set_size(100, 200);
        let bytes = "\x1b[38;2;0;0;0mX\x1b[38;2;255;255;255mX".repeat(10_000);
        session.feed_output(bytes.as_bytes()).await;
        let expected = session
            .inner
            .lock()
            .await
            .parser
            .screen()
            .contents_formatted();
        assert!(expected.len() > REPAINT_CHUNK_BYTES);
        let (client, mut reader) = client();
        let attach = tokio::spawn({
            let session = session.clone();
            async move { session.attach_client(&client).await }
        });
        let AgentOutput::Out(mut painted) = frame(&mut reader).await else {
            panic!("expected repaint");
        };
        let output = tokio::spawn({
            let session = session.clone();
            async move {
                session.feed_output(b"live output").await;
                session.broadcast_exit(0).await;
            }
        });
        while painted.len() < expected.len() {
            let AgentOutput::Out(chunk) = frame(&mut reader).await else {
                panic!("repaint interrupted");
            };
            assert!(chunk.len() <= REPAINT_CHUNK_BYTES);
            painted.extend_from_slice(&chunk);
        }
        assert_eq!(painted, expected);
        assert_eq!(
            frame(&mut reader).await,
            AgentOutput::Out(b"live output".to_vec())
        );
        assert_eq!(frame(&mut reader).await, AgentOutput::Exit { code: 0 });
        assert!(attach.await.unwrap().is_some());
        output.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detached_clients_receive_their_status_then_eof() {
        let (session, _) = session();
        let (client, mut reader) = client();
        let id = session.attach_client(&client).await.unwrap();
        let _ = frame(&mut reader).await;

        assert_eq!(
            session.detach_client(id).await,
            DetachOutcome::Detached { size: None }
        );
        assert_eq!(frame(&mut reader).await, AgentOutput::Detached);
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(2),
                terra_protocol::read_frame_async::<AgentOutput>(&mut reader)
            )
            .await
            .expect("timed out waiting for EOF")
            .unwrap(),
            None
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detaching_all_removes_every_client() {
        let (session, _) = session();
        let (first, _first_reader) = client();
        let (second, _second_reader) = client();
        let first = session.attach_client(&first).await.unwrap();
        let second = session.attach_client(&second).await.unwrap();

        assert_eq!(session.detach_all_clients().await.0, vec![first, second]);
        assert!(session.list_clients().await.is_empty());
        assert_eq!(session.detach_client(99).await, DetachOutcome::Missing);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dead_clients_are_removed_on_the_next_broadcast() {
        let (session, _) = session();
        let (client, reader) = client();
        session.attach_client(&client).await.unwrap();
        drop(reader);

        session.feed_output(b"x").await;
        assert!(session.list_clients().await.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn output_after_exit_does_not_change_the_late_repaint() {
        let (session, _) = session();
        session.feed_output(b"before exit\n").await;
        session.broadcast_exit(0).await;
        session.feed_output(b"after exit\n").await;
        let (client, mut reader) = client();
        session.attach_client(&client).await.unwrap();

        let AgentOutput::Out(output) = frame(&mut reader).await else {
            panic!("late client did not receive a repaint");
        };
        assert!(String::from_utf8_lossy(&output).contains("before exit"));
        assert!(!String::from_utf8_lossy(&output).contains("after exit"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unknown_clients_cannot_change_the_shared_size() {
        let (session, _) = session();
        assert_eq!(session.set_client_size(42, 30, 100).await, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_input_write_keeps_the_pty_open_for_resizes() {
        let (input, sink) = std::os::unix::net::UnixStream::pair().unwrap();
        let cancellation = CancellationToken::new();
        let tasks = TaskTracker::new();
        let session = Session::new(
            crate::into_async_file(input).unwrap(),
            &cancellation,
            &tasks,
        )
        .unwrap();
        drop(sink);
        loop {
            match session.send_input(b"q").await {
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => break,
                Ok(()) => {}
                Err(error) => panic!("unexpected input error: {error}"),
            }
        }
        assert!(rustix::fs::fcntl_getfl(session.input_fd()).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_input_queue_times_out() {
        let (sink, input) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let cancellation = CancellationToken::new();
        let tasks = TaskTracker::new();
        let session = Session::new(
            crate::into_async_file(input).unwrap(),
            &cancellation,
            &tasks,
        )
        .unwrap();
        let bytes = vec![0; 64 << 10];
        loop {
            match session.send_input(&bytes).await {
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => break,
                Ok(()) => {}
                Err(error) => panic!("unexpected input error: {error}"),
            }
        }
        drop(sink);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_stops_input_and_closes_clients() {
        let (_sink, input) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let cancellation = CancellationToken::new();
        let tasks = TaskTracker::new();
        let session = Session::new(
            crate::into_async_file(input).unwrap(),
            &cancellation,
            &tasks,
        )
        .unwrap();
        let (client, mut reader) = client();
        session.attach_client(&client).await.unwrap();
        let _ = frame(&mut reader).await;
        session.send_input(&vec![0; 1 << 20]).await.unwrap();

        cancellation.cancel();
        tasks.close();
        tokio::time::timeout(Duration::from_secs(1), tasks.wait())
            .await
            .expect("cancellation did not stop session workers");
        assert_eq!(
            session.send_input(b"q").await.unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            terra_protocol::read_frame_async::<AgentOutput>(&mut reader)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_output_does_not_hold_the_session_state_lock() {
        let (session, _) = session();
        let (stalled, _reader) = client();
        session.attach_client(&stalled).await.unwrap();
        let output_session = session.clone();
        let output = tokio::spawn(async move {
            output_session.feed_output(&vec![b'x'; 1 << 20]).await;
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if session.delivery.try_lock().is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("broadcast did not start");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), session.list_clients())
                .await
                .is_ok()
        );
        output.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stalled_client_does_not_skip_healthy_output() {
        let (session, _) = session();
        let (stalled, _stalled_reader) = client();
        let (healthy, mut healthy_reader) = client();
        session.attach_client(&stalled).await.unwrap();
        session.attach_client(&healthy).await.unwrap();
        let _ = frame(&mut healthy_reader).await;

        let bytes = vec![b'x'; 1 << 20];
        let reading = tokio::spawn(async move { frame(&mut healthy_reader).await });
        session.feed_output(&bytes).await;
        assert_eq!(reading.await.unwrap(), AgentOutput::Out(bytes));
    }
}
