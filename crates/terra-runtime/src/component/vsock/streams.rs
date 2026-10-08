use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use wasmtime::StoreContextMut;
use wasmtime::component::{
    Access, Accessor, Destination, Linker, Source, StreamConsumer, StreamProducer, StreamReader,
    StreamResult, VecBuffer,
};

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
use stream_types::{Connection, StreamError};

pub const STREAM_BUFFER_BYTES: usize = 64 * 1024;

struct Pipe {
    generation: Option<u64>,
    retired_generation: u64,
    is_retired: bool,
    write_open: [bool; 2],
    frontend_ends: u8,
    queues: [VecDeque<u8>; 2],
    revision: u64,
    input_waiters: [Option<Waker>; 2],
    output_waiters: [Option<Waker>; 2],
    native_waiters: [Option<Waker>; 2],
}

#[derive(Clone)]
pub struct StreamEndpoint {
    pipe: Arc<Mutex<Pipe>>,
    observed_revision: u64,
    side: usize,
}

impl StreamEndpoint {
    #[must_use]
    pub fn new() -> Self {
        Self::pair().1
    }

    #[must_use]
    pub fn pair() -> (Self, Self) {
        let pipe = Arc::new(Mutex::new(Pipe {
            generation: None,
            retired_generation: 0,
            is_retired: false,
            write_open: [false; 2],
            frontend_ends: 0,
            queues: std::array::from_fn(|_| VecDeque::new()),
            revision: 0,
            input_waiters: [None, None],
            output_waiters: [None, None],
            native_waiters: [None, None],
        }));
        let frontend = Self {
            pipe,
            observed_revision: 0,
            side: 0,
        };
        let mut role = frontend.clone();
        role.side = 1;
        (frontend, role)
    }

    fn notify(&self) {
        let mut pipe = self
            .pipe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pipe.revision = pipe.revision.wrapping_add(1);
        let waiters = [
            std::mem::take(&mut pipe.input_waiters),
            std::mem::take(&mut pipe.output_waiters),
            std::mem::take(&mut pipe.native_waiters),
        ];
        drop(pipe);
        waiters
            .into_iter()
            .flatten()
            .flatten()
            .for_each(Waker::wake);
    }

    pub fn connect(&mut self, generation: u64) -> Result<(), StreamError> {
        let mut pipe = self
            .pipe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pipe.is_retired {
            return Err(StreamError::Closed);
        }
        if generation == 0 || generation <= pipe.retired_generation || pipe.generation.is_some() {
            return Err(StreamError::Stale);
        }
        pipe.generation = Some(generation);
        pipe.retired_generation = generation;
        pipe.write_open = [true; 2];
        pipe.frontend_ends = 2;
        for queue in &mut pipe.queues {
            queue.clear();
        }
        drop(pipe);
        self.notify();
        Ok(())
    }

    #[must_use]
    pub fn current(&self) -> Option<u64> {
        self.pipe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .generation
    }

    pub fn try_read(&mut self, generation: u64, max: u32) -> Result<Vec<u8>, StreamError> {
        let max = usize::try_from(max).map_err(|_| StreamError::Io)?;
        if max > STREAM_BUFFER_BYTES {
            return Err(StreamError::Io);
        }
        let mut pipe = self
            .pipe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pipe.generation != Some(generation) {
            return Err(StreamError::Stale);
        }
        let peer = 1 - self.side;
        let count = max.min(pipe.queues[peer].len());
        if pipe.queues[peer].is_empty() && !pipe.write_open[peer] {
            return Err(StreamError::Closed);
        }
        let bytes = pipe.queues[peer].drain(..count).collect();
        drop(pipe);
        if count != 0 {
            self.notify();
        }
        Ok(bytes)
    }

    pub fn try_write(&mut self, generation: u64, bytes: &[u8]) -> Result<u32, StreamError> {
        if bytes.len() > STREAM_BUFFER_BYTES {
            return Err(StreamError::Io);
        }
        let mut pipe = self
            .pipe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pipe.generation != Some(generation) {
            return Err(StreamError::Stale);
        }
        if !pipe.write_open[self.side] {
            return Err(StreamError::Closed);
        }
        let queue = &mut pipe.queues[self.side];
        let count = bytes.len().min(STREAM_BUFFER_BYTES - queue.len());
        queue.extend(&bytes[..count]);
        drop(pipe);
        if count != 0 {
            self.notify();
        }
        u32::try_from(count).map_err(|_| StreamError::Io)
    }

    pub fn close(&mut self, generation: u64) {
        let mut pipe = self
            .pipe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pipe.generation != Some(generation) {
            return;
        }
        pipe.write_open[self.side] = false;
        drop(pipe);
        self.notify();
    }

    pub fn disconnect(&mut self, generation: u64) {
        let mut pipe = self
            .pipe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pipe.generation != Some(generation) {
            return;
        }
        pipe.generation = None;
        pipe.write_open = [false; 2];
        for queue in &mut pipe.queues {
            queue.clear();
        }
        drop(pipe);
        self.notify();
    }

    fn release_frontend_end(&mut self, generation: u64) {
        if self.side != 0 {
            return;
        }
        let mut pipe = self
            .pipe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pipe.generation != Some(generation) {
            return;
        }
        pipe.frontend_ends -= 1;
        if pipe.frontend_ends == 0 {
            pipe.generation = None;
            pipe.write_open = [false; 2];
            for queue in &mut pipe.queues {
                queue.clear();
            }
        }
        drop(pipe);
        self.notify();
    }

    fn is_retired(&self) -> bool {
        self.pipe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_retired
    }

    pub(crate) fn retire(&mut self) {
        let mut pipe = self
            .pipe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pipe.is_retired = true;
        pipe.generation = None;
        pipe.write_open = [false; 2];
        for queue in &mut pipe.queues {
            queue.clear();
        }
        drop(pipe);
        self.notify();
    }

    fn stop_input(&mut self, generation: u64) -> Result<(), StreamError> {
        let mut pipe = self
            .pipe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pipe.generation != Some(generation) {
            return Err(StreamError::Stale);
        }
        let peer = 1 - self.side;
        pipe.write_open[peer] = false;
        pipe.queues[peer].clear();
        drop(pipe);
        self.notify();
        Ok(())
    }

    pub async fn wait(&mut self) {
        std::future::poll_fn(|context| {
            let mut pipe = self
                .pipe
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if pipe.revision == self.observed_revision {
                pipe.native_waiters[self.side] = Some(context.waker().clone());
                Poll::Pending
            } else {
                self.observed_revision = pipe.revision;
                Poll::Ready(())
            }
        })
        .await;
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
        let generation = loop {
            if endpoint.is_retired() {
                host.with(|mut access| output.close(&mut access))?;
                return Ok(None);
            }
            if let Some(generation) = endpoint.current() {
                break generation;
            }
            endpoint.wait().await;
        };
        host.with(|mut access| {
            output.pipe(
                &mut access,
                PipeOutput {
                    endpoint: endpoint.clone(),
                    generation,
                },
            )?;
            StreamReader::new(
                &mut access,
                PipeInput {
                    endpoint,
                    generation,
                },
            )
            .map(Some)
        })
    }
}

struct PipeInput {
    endpoint: StreamEndpoint,
    generation: u64,
}

impl Drop for PipeInput {
    fn drop(&mut self) {
        let _ = self.endpoint.stop_input(self.generation);
        self.endpoint.release_frontend_end(self.generation);
    }
}

impl<T: 'static> StreamProducer<T> for PipeInput {
    type Item = u8;
    type Buffer = VecBuffer<u8>;

    fn poll_produce<'a>(
        self: core::pin::Pin<&mut Self>,
        context: &mut Context<'_>,
        mut store: StoreContextMut<'a, T>,
        destination: Destination<'a, u8, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        let mut pipe = self
            .endpoint
            .pipe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pipe.generation != Some(self.generation) {
            return Poll::Ready(Ok(StreamResult::Dropped));
        }
        let peer = 1 - self.endpoint.side;
        if pipe.queues[peer].is_empty() {
            if !pipe.write_open[peer] {
                return Poll::Ready(Ok(StreamResult::Dropped));
            }
            if finish {
                return Poll::Ready(Ok(StreamResult::Cancelled));
            }
            pipe.input_waiters[self.endpoint.side] = Some(context.waker().clone());
            return Poll::Pending;
        }
        if destination.remaining(&mut store) == Some(0) {
            return Poll::Ready(Ok(StreamResult::Completed));
        }
        let mut destination = destination.as_direct(store, STREAM_BUFFER_BYTES);
        let bytes = destination.remaining();
        let count = bytes.len().min(pipe.queues[peer].len());
        for (slot, byte) in bytes.iter_mut().zip(pipe.queues[peer].drain(..count)) {
            *slot = byte;
        }
        destination.mark_written(count);
        drop(pipe);
        self.endpoint.notify();
        Poll::Ready(Ok(StreamResult::Completed))
    }
}

struct PipeOutput {
    endpoint: StreamEndpoint,
    generation: u64,
}

impl Drop for PipeOutput {
    fn drop(&mut self) {
        self.endpoint.close(self.generation);
        self.endpoint.release_frontend_end(self.generation);
    }
}

impl<T: 'static> StreamConsumer<T> for PipeOutput {
    type Item = u8;

    fn poll_consume(
        self: core::pin::Pin<&mut Self>,
        context: &mut Context<'_>,
        store: StoreContextMut<T>,
        source: Source<'_, u8>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        let mut pipe = self
            .endpoint
            .pipe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let side = self.endpoint.side;
        if pipe.generation != Some(self.generation) || !pipe.write_open[side] {
            return Poll::Ready(Ok(StreamResult::Dropped));
        }
        let capacity = STREAM_BUFFER_BYTES - pipe.queues[side].len();
        if capacity == 0 {
            if finish {
                return Poll::Ready(Ok(StreamResult::Cancelled));
            }
            pipe.output_waiters[side] = Some(context.waker().clone());
            return Poll::Pending;
        }
        let mut source = source.as_direct(store);
        let bytes = source.remaining();
        let count = bytes.len().min(capacity);
        pipe.queues[side].extend(&bytes[..count]);
        source.mark_read(count);
        drop(pipe);
        if count != 0 {
            self.endpoint.notify();
        }
        Poll::Ready(Ok(StreamResult::Completed))
    }
}

impl frontend_stream::Host for FrontendStreams {}

impl<T: Send + 'static> frontend_stream::HostWithStore<T>
    for wasmtime::component::HasSelf<FrontendStreams>
{
    fn connect(
        mut access: Access<'_, T, Self>,
        connection: Connection,
        mut input: StreamReader<u8>,
    ) -> wasmtime::Result<Result<StreamReader<u8>, StreamError>> {
        let endpoint = &mut access.get().agent;
        if let Err(error) = endpoint.connect(connection.generation) {
            input.close(&mut access)?;
            return Ok(Err(error));
        }
        let endpoint = endpoint.clone();
        input.pipe(
            &mut access,
            PipeOutput {
                endpoint: endpoint.clone(),
                generation: connection.generation,
            },
        )?;
        StreamReader::new(
            &mut access,
            PipeInput {
                endpoint,
                generation: connection.generation,
            },
        )
        .map(Ok)
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

    #[test]
    fn bounded_streams_preserve_partial_io_half_close_and_generations() {
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
        assert!(matches!(frontend.try_read(1, 1), Err(StreamError::Closed)));
        frontend.try_write(1, &[4]).unwrap();
        assert_eq!(role.try_read(1, 1).unwrap(), [4]);
        frontend.disconnect(1);
        frontend.connect(2).unwrap();
        assert!(matches!(role.try_write(1, &[5]), Err(StreamError::Stale)));
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
                    access, Connection { generation: 1 }, input,
                )
            }).unwrap().unwrap();
            let mut received = Vec::new();
            loop {
                match role.try_read(1, 8192) {
                    Ok(bytes) if bytes.is_empty() => role.wait().await,
                    Ok(bytes) => received.extend(bytes),
                    Err(StreamError::Closed) => break,
                    Err(StreamError::Stale | StreamError::Io) => panic!("stream generation remains live"),
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

    /// Closing either frontend stream preserves the other direction; both retire the generation.
    #[test]
    fn frontend_stream_drops_half_close_and_retire_without_affecting_replacements() {
        let (mut frontend, mut role) = StreamEndpoint::pair();
        frontend.connect(1).unwrap();
        let input = PipeOutput {
            endpoint: frontend.clone(),
            generation: 1,
        };
        let output = PipeInput {
            endpoint: frontend.clone(),
            generation: 1,
        };
        frontend.try_write(1, &[7]).unwrap();
        drop(input);
        assert_eq!(role.try_read(1, 1).unwrap(), [7]);
        assert!(matches!(role.try_read(1, 1), Err(StreamError::Closed)));
        assert_eq!(role.try_write(1, &[8]).unwrap(), 1);
        assert_eq!(frontend.current(), Some(1));
        drop(output);
        assert_eq!(frontend.current(), None);
        frontend.connect(2).unwrap();
        let input = PipeOutput {
            endpoint: frontend.clone(),
            generation: 2,
        };
        let output = PipeInput {
            endpoint: frontend.clone(),
            generation: 2,
        };
        drop(output);
        assert!(matches!(role.try_write(2, &[8]), Err(StreamError::Closed)));
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
        drop(PipeInput {
            endpoint: role.clone(),
            generation: 1,
        });
        assert!(matches!(
            frontend.try_write(1, &[8]),
            Err(StreamError::Closed)
        ));
        assert_eq!(role.try_write(1, &[9]).unwrap(), 1);
        assert_eq!(frontend.try_read(1, 1).unwrap(), [9]);
        assert_eq!(frontend.current(), Some(1));
    }

    #[tokio::test]
    async fn notification_between_blocked_io_and_wait_is_retained() {
        let (mut frontend, mut role) = StreamEndpoint::pair();
        frontend.connect(1).unwrap();
        role.wait().await;
        assert!(role.try_read(1, 1).unwrap().is_empty());
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
        assert!(matches!(agent.try_read(1, 1), Err(StreamError::Stale)));
        assert!(matches!(streams.agent.connect(2), Err(StreamError::Closed)));
    }
}
