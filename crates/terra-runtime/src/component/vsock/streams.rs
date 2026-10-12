use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use tokio::sync::watch;
use wasmtime::AsContextMut;
use wasmtime::component::{Access, Accessor, Linker, StreamReader};

use crate::component::relay::{DirectBuffer, DirectSink, DirectSource, TryRead, TryWrite};

mod bindings {
    wasmtime::component::bindgen!({
        world: "stream-hosts",
        path: "../../components/wit/vsock",
        imports: {
            default: trappable,
            "terra:vsock/frontend-stream.connect": store | trappable,
        },
    });
}

pub use bindings::terra::vsock::{frontend_stream, role_stream, stream_types};
use stream_types::StreamError;

pub const STREAM_BUFFER_BYTES: usize = 64 * 1024;

struct Pipe {
    connection_number: Option<u64>,
    retired_connection_number: u64,
    is_retired: bool,
    write_open: [bool; 2],
    frontend_ends: u8,
    queues: [VecDeque<u8>; 2],
    changes: watch::Sender<()>,
}

impl Pipe {
    fn notify(&self) {
        self.changes.send_replace(());
    }

    fn is_current(&self, connection_number: u64) -> bool {
        self.connection_number == Some(connection_number)
    }

    fn end_connection(&mut self) {
        self.connection_number = None;
        self.write_open = [false; 2];
        for queue in &mut self.queues {
            queue.clear();
        }
    }
}

#[derive(Clone)]
pub struct StreamEndpoint {
    pipe: Arc<Mutex<Pipe>>,
    changes: watch::Receiver<()>,
    side: usize,
}

impl StreamEndpoint {
    #[must_use]
    pub fn new() -> Self {
        Self::pair().1
    }

    #[must_use]
    pub fn pair() -> (Self, Self) {
        let (changes, observed) = watch::channel(());
        let pipe = Arc::new(Mutex::new(Pipe {
            connection_number: None,
            retired_connection_number: 0,
            is_retired: false,
            write_open: [false; 2],
            frontend_ends: 0,
            queues: std::array::from_fn(|_| VecDeque::new()),
            changes,
        }));
        let frontend = Self {
            pipe,
            changes: observed,
            side: 0,
        };
        let mut role = frontend.clone();
        role.side = 1;
        (frontend, role)
    }

    fn lock(&self) -> MutexGuard<'_, Pipe> {
        self.pipe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn connect(&mut self, connection_number: u64) -> Result<(), StreamError> {
        let mut pipe = self.lock();
        if pipe.is_retired {
            return Err(StreamError::Closed);
        }
        if connection_number == 0
            || connection_number <= pipe.retired_connection_number
            || pipe.connection_number.is_some()
        {
            return Err(StreamError::Stale);
        }
        pipe.connection_number = Some(connection_number);
        pipe.retired_connection_number = connection_number;
        pipe.write_open = [true; 2];
        pipe.frontend_ends = 2;
        for queue in &mut pipe.queues {
            queue.clear();
        }
        pipe.notify();
        Ok(())
    }

    #[must_use]
    pub fn current(&self) -> Option<u64> {
        self.lock().connection_number
    }

    /// Copies bytes the peer wrote into `buffer` and returns how many; 0 when none are queued yet.
    pub fn read_into(
        &mut self,
        connection_number: u64,
        buffer: &mut [u8],
    ) -> Result<usize, StreamError> {
        let mut pipe = self.lock();
        if !pipe.is_current(connection_number) {
            return Err(StreamError::Stale);
        }
        let peer = 1 - self.side;
        if pipe.queues[peer].is_empty() && !pipe.write_open[peer] {
            return Err(StreamError::Closed);
        }
        let count = buffer.len().min(pipe.queues[peer].len());
        let (front, back) = pipe.queues[peer].as_slices();
        let from_front = count.min(front.len());
        buffer[..from_front].copy_from_slice(&front[..from_front]);
        buffer[from_front..count].copy_from_slice(&back[..count - from_front]);
        pipe.queues[peer].drain(..count);
        if count != 0 {
            pipe.notify();
        }
        Ok(count)
    }

    /// Takes up to `max` bytes the peer wrote; empty when none are queued yet.
    pub fn try_read(&mut self, connection_number: u64, max: usize) -> Result<Vec<u8>, StreamError> {
        let mut bytes = vec![0; max.min(STREAM_BUFFER_BYTES)];
        let count = self.read_into(connection_number, &mut bytes)?;
        bytes.truncate(count);
        Ok(bytes)
    }

    /// Queues what fits in the peer's buffer and returns how many bytes that was.
    pub fn try_write(
        &mut self,
        connection_number: u64,
        bytes: &[u8],
    ) -> Result<usize, StreamError> {
        let mut pipe = self.lock();
        if !pipe.is_current(connection_number) {
            return Err(StreamError::Stale);
        }
        if !pipe.write_open[self.side] {
            return Err(StreamError::Closed);
        }
        let queue = &mut pipe.queues[self.side];
        let count = bytes.len().min(STREAM_BUFFER_BYTES - queue.len());
        queue.extend(&bytes[..count]);
        if count != 0 {
            pipe.notify();
        }
        Ok(count)
    }

    pub fn close(&mut self, connection_number: u64) {
        let mut pipe = self.lock();
        if pipe.is_current(connection_number) {
            pipe.write_open[self.side] = false;
            pipe.notify();
        }
    }

    pub fn disconnect(&mut self, connection_number: u64) {
        let mut pipe = self.lock();
        if pipe.is_current(connection_number) {
            pipe.end_connection();
            pipe.notify();
        }
    }

    fn release_frontend_end(&mut self, connection_number: u64) {
        if self.side != 0 {
            return;
        }
        let mut pipe = self.lock();
        if !pipe.is_current(connection_number) {
            return;
        }
        pipe.frontend_ends -= 1;
        if pipe.frontend_ends == 0 {
            pipe.end_connection();
        }
        pipe.notify();
    }

    fn is_retired(&self) -> bool {
        self.lock().is_retired
    }

    pub(crate) fn retire(&mut self) {
        let mut pipe = self.lock();
        pipe.is_retired = true;
        pipe.end_connection();
        pipe.notify();
    }

    fn stop_input(&mut self, connection_number: u64) {
        let mut pipe = self.lock();
        if pipe.is_current(connection_number) {
            let peer = 1 - self.side;
            pipe.write_open[peer] = false;
            pipe.queues[peer].clear();
            pipe.notify();
        }
    }

    /// Returns once the pipe changed since this endpoint last waited, so a check-then-wait loop misses no change.
    pub async fn wait(&mut self) {
        let _ = self.changes.changed().await;
    }

    /// Resolves after the pipe's next change, counted from now.
    fn changed(&self) -> BoxFuture<'static, ()> {
        let mut changes = self.changes.clone();
        changes.borrow_and_update();
        async move {
            let _ = changes.changed().await;
        }
        .boxed()
    }

    /// Waits for at least one byte; `Err(Closed)` once the peer closed and every byte was read.
    pub async fn read(
        &mut self,
        connection_number: u64,
        max: usize,
    ) -> Result<Vec<u8>, StreamError> {
        loop {
            let bytes = self.try_read(connection_number, max)?;
            if !bytes.is_empty() || max == 0 {
                return Ok(bytes);
            }
            self.wait().await;
        }
    }

    pub async fn write_all(
        &mut self,
        connection_number: u64,
        mut bytes: &[u8],
    ) -> Result<(), StreamError> {
        while !bytes.is_empty() {
            let count = self.try_write(connection_number, bytes)?;
            if count == 0 {
                self.wait().await;
            }
            bytes = &bytes[count..];
        }
        Ok(())
    }
}

impl Default for StreamEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

pub struct FrontendStreams {
    agent: StreamEndpoint,
}

impl FrontendStreams {
    #[must_use]
    pub fn new() -> (Self, StreamEndpoint) {
        let (agent_frontend, agent) = StreamEndpoint::pair();
        (
            Self {
                agent: agent_frontend,
            },
            agent,
        )
    }

    pub(crate) fn retire(&mut self) {
        self.agent.retire();
    }
}

impl role_stream::Host for StreamEndpoint {}

impl<T: Send + 'static> role_stream::HostWithStore<T>
    for wasmtime::component::HasSelf<StreamEndpoint>
{
    async fn accept(
        host: &Accessor<T, Self>,
        mut output: StreamReader<u8>,
    ) -> wasmtime::Result<Option<StreamReader<u8>>> {
        let mut endpoint = host.with(|mut access| access.get().clone());
        let connection_number = loop {
            if endpoint.is_retired() {
                host.with(|mut access| output.close(&mut access))?;
                return Ok(None);
            }
            if let Some(connection_number) = endpoint.current() {
                break connection_number;
            }
            endpoint.wait().await;
        };
        host.with(|mut access| attach(&mut access, endpoint, connection_number, output).map(Some))
    }
}

/// Stops the peer's writes and releases the frontend's claim when the component drops its input.
struct InputEnd {
    endpoint: StreamEndpoint,
    connection_number: u64,
}

impl Drop for InputEnd {
    fn drop(&mut self) {
        self.endpoint.stop_input(self.connection_number);
        self.endpoint.release_frontend_end(self.connection_number);
    }
}

/// Half-closes the component's direction and releases the frontend's claim once its output ends.
struct OutputEnd {
    endpoint: StreamEndpoint,
    connection_number: u64,
}

impl Drop for OutputEnd {
    fn drop(&mut self) {
        self.endpoint.close(self.connection_number);
        self.endpoint.release_frontend_end(self.connection_number);
    }
}

/// Wires one connection to a component: its `output` fills the pipe, and the returned stream drains the peer.
fn attach<A: AsContextMut>(
    mut store: A,
    endpoint: StreamEndpoint,
    connection_number: u64,
    output: StreamReader<u8>,
) -> wasmtime::Result<StreamReader<u8>> {
    let output_end = OutputEnd {
        endpoint: endpoint.clone(),
        connection_number,
    };
    output.pipe(&mut store, DirectSink::new(output_end))?;
    let input_end = InputEnd {
        endpoint,
        connection_number,
    };
    StreamReader::new(store, DirectSource::new(input_end, STREAM_BUFFER_BYTES))
}

impl DirectBuffer for InputEnd {
    fn changed(&mut self) -> BoxFuture<'static, ()> {
        self.endpoint.changed()
    }
}

impl TryRead for InputEnd {
    fn try_read(&mut self, buffer: &mut [u8]) -> Option<usize> {
        self.endpoint.read_into(self.connection_number, buffer).ok()
    }
}

impl DirectBuffer for OutputEnd {
    fn changed(&mut self) -> BoxFuture<'static, ()> {
        self.endpoint.changed()
    }
}

impl TryWrite for OutputEnd {
    fn try_write(&mut self, bytes: &[u8]) -> Option<usize> {
        self.endpoint.try_write(self.connection_number, bytes).ok()
    }
}

impl frontend_stream::Host for FrontendStreams {}

impl<T: Send + 'static> frontend_stream::HostWithStore<T>
    for wasmtime::component::HasSelf<FrontendStreams>
{
    fn connect(
        mut access: Access<'_, T, Self>,
        connection_number: u64,
        mut input: StreamReader<u8>,
    ) -> wasmtime::Result<Result<StreamReader<u8>, StreamError>> {
        let endpoint = &mut access.get().agent;
        if let Err(error) = endpoint.connect(connection_number) {
            input.close(&mut access)?;
            return Ok(Err(error));
        }
        let endpoint = endpoint.clone();
        attach(&mut access, endpoint, connection_number, input).map(Ok)
    }
}

pub fn add_role_stream_to_linker<T: Send + 'static>(
    linker: &mut Linker<T>,
    get: fn(&mut T) -> &mut StreamEndpoint,
) -> wasmtime::Result<()> {
    role_stream::add_to_linker::<T, wasmtime::component::HasSelf<StreamEndpoint>>(linker, get)
}

pub fn add_frontend_stream_to_linker<T: Send + 'static>(
    linker: &mut Linker<T>,
    get: fn(&mut T) -> &mut FrontendStreams,
) -> wasmtime::Result<()> {
    frontend_stream::add_to_linker::<T, wasmtime::component::HasSelf<FrontendStreams>>(linker, get)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn bounded_streams_preserve_partial_io_half_close_and_connection_numbers() {
        let (mut frontend, mut role) = StreamEndpoint::pair();
        frontend.connect(1).unwrap();
        assert!(frontend.connect(2).is_err());
        assert_eq!(
            role.try_write(1, &vec![9; STREAM_BUFFER_BYTES]).unwrap(),
            65536
        );
        assert_eq!(role.try_write(1, &[1]).unwrap(), 0);
        role.close(1);
        assert_eq!(frontend.try_read(1, 17).unwrap(), vec![9; 17]);
        assert_eq!(
            frontend.try_read(1, 65536).unwrap().len(),
            STREAM_BUFFER_BYTES - 17
        );
        assert_matches!(frontend.try_read(1, 1), Err(StreamError::Closed));
        frontend.try_write(1, &[4]).unwrap();
        assert_eq!(role.try_read(1, 1).unwrap(), [4]);
        frontend.disconnect(1);
        frontend.connect(2).unwrap();
        assert_matches!(role.try_write(1, &[5]), Err(StreamError::Stale));
        role.close(1);
        assert_eq!(role.try_write(2, &[6]).unwrap(), 1);
    }

    /// The frontend stream pair transfers bounded chunks, drains before EOF, and retires on drop.
    #[tokio::test]
    async fn frontend_stream_pair_preserves_backpressure_eof_and_retirement() {
        let engine = crate::engine::device_engine().unwrap();
        let (streams, mut role) = FrontendStreams::new();
        let mut store = wasmtime::Store::new(&engine, streams);
        let payload = vec![37; STREAM_BUFFER_BYTES * 2];
        let input = StreamReader::new(&mut store, payload.clone()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), store.run_concurrent(async |accessor| {
            let mut output = accessor.with(|access| {
                <wasmtime::component::HasSelf<FrontendStreams> as frontend_stream::HostWithStore<FrontendStreams>>::connect(
                    access, 1, input,
                )
            }).unwrap().unwrap();
            let mut received = Vec::new();
            loop {
                match role.try_read(1, 8192) {
                    Ok(bytes) if bytes.is_empty() => role.wait().await,
                    Ok(bytes) => received.extend(bytes),
                    Err(StreamError::Closed) => break,
                    Err(StreamError::Stale | StreamError::Io) => panic!("stream connection number remains live"),
                }
            }
            assert_eq!(received, payload);
            assert_eq!(role.current(), Some(1));
            assert_eq!(role.try_write(1, &[8]).unwrap(), 1);
            accessor.with(|mut access| output.close(&mut access)).unwrap();
            while role.current().is_some() {
                role.wait().await;
            }
        })).await.unwrap().unwrap();
    }

    /// Closing either frontend stream preserves the other direction; both retire the connection number.
    #[test]
    fn frontend_stream_drops_half_close_and_retire_without_affecting_replacements() {
        let (mut frontend, mut role) = StreamEndpoint::pair();
        frontend.connect(1).unwrap();
        let input = OutputEnd {
            endpoint: frontend.clone(),
            connection_number: 1,
        };
        let output = InputEnd {
            endpoint: frontend.clone(),
            connection_number: 1,
        };
        frontend.try_write(1, &[7]).unwrap();
        drop(input);
        assert_eq!(role.try_read(1, 1).unwrap(), [7]);
        assert_matches!(role.try_read(1, 1), Err(StreamError::Closed));
        assert_eq!(role.try_write(1, &[8]).unwrap(), 1);
        assert_eq!(frontend.current(), Some(1));
        drop(output);
        assert_eq!(frontend.current(), None);
        frontend.connect(2).unwrap();
        let input = OutputEnd {
            endpoint: frontend.clone(),
            connection_number: 2,
        };
        let output = InputEnd {
            endpoint: frontend.clone(),
            connection_number: 2,
        };
        drop(output);
        assert_matches!(role.try_write(2, &[8]), Err(StreamError::Closed));
        assert_eq!(frontend.try_write(2, &[9]).unwrap(), 1);
        assert_eq!(role.try_read(2, 1).unwrap(), [9]);
        frontend.disconnect(2);
        frontend.connect(3).unwrap();
        drop(input);
        assert_eq!(frontend.current(), Some(3));
        assert_eq!(frontend.try_write(3, &[10]).unwrap(), 1);
    }

    /// Dropping a role reader closes only that direction.
    #[test]
    fn dropping_role_input_stops_frontend_input_but_preserves_output() {
        let (mut frontend, mut role) = StreamEndpoint::pair();
        frontend.connect(1).unwrap();
        frontend.try_write(1, &[7]).unwrap();
        drop(InputEnd {
            endpoint: role.clone(),
            connection_number: 1,
        });
        assert_matches!(frontend.try_write(1, &[8]), Err(StreamError::Closed));
        assert_eq!(role.try_write(1, &[9]).unwrap(), 1);
        assert_eq!(frontend.try_read(1, 1).unwrap(), [9]);
        assert_eq!(frontend.current(), Some(1));
    }

    #[tokio::test]
    async fn notification_between_blocked_io_and_wait_is_retained() {
        let (mut frontend, mut role) = StreamEndpoint::pair();
        frontend.connect(1).unwrap();
        role.wait().await;
        assert_eq!(role.try_read(1, 1).unwrap(), [] as [u8; 0]);
        frontend.try_write(1, &[8]).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), role.wait())
            .await
            .unwrap();
        assert_eq!(role.try_read(1, 1).unwrap(), [8]);
    }

    #[test]
    fn retiring_the_agent_rejects_reconnection() {
        let (mut streams, mut agent) = FrontendStreams::new();
        streams.agent.connect(1).unwrap();
        streams.retire();
        assert_matches!(agent.try_read(1, 1), Err(StreamError::Stale));
        assert_matches!(streams.agent.connect(2), Err(StreamError::Closed));
    }
}
