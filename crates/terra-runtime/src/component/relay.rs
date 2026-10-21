//! Component stream ends backed by bounded channels, host async streams, or host memory buffers,
//! so host code stays async.

use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Bytes, BytesMut};
use futures_util::future::BoxFuture;
use futures_util::stream::{self, BoxStream, Peekable, StreamExt};
use tokio::sync::mpsc;
use tokio_util::sync::{CancellationToken, PollSender};
use wasmtime::StoreContextMut;
use wasmtime::component::{
    Destination, Lift, Lower, Resource, Source, StreamConsumer, StreamProducer, StreamResult,
    VecBuffer,
};

/// Bytes a [`ByteSink`] buffers ahead of the host task draining it, whatever its chunk size.
pub const BYTE_QUEUE_BYTES: usize = 128 * 1024;

/// Takes the component's items into a channel; a cancelled write leaves the channel open.
pub struct Sink<T> {
    sender: PollSender<T>,
}

/// Hands the component each item of a host stream; the host stream's end ends the component stream.
pub struct Stream<T> {
    items: Peekable<BoxStream<'static, T>>,
}

#[must_use]
pub fn channel<T: Send + 'static>(capacity: NonZeroUsize) -> (Sink<T>, Stream<T>) {
    let (sender, receiver) = mpsc::channel(capacity.get());
    (
        Sink {
            sender: PollSender::new(sender),
        },
        Stream::new(receive_all(receiver)),
    )
}

fn receive_all<T: Send + 'static>(
    receiver: mpsc::Receiver<T>,
) -> impl futures_util::Stream<Item = T> {
    stream::unfold(receiver, |mut receiver| async move {
        let item = receiver.recv().await?;
        Some((item, receiver))
    })
}

impl<T: Send> Sink<T> {
    pub(crate) async fn send(&mut self, item: T) -> wasmtime::Result<()> {
        let closed = || wasmtime::Error::msg("device request stream closed");
        let sender = self.sender.get_ref().ok_or_else(closed)?;
        sender.reserve().await.map_err(|_| closed())?.send(item);
        Ok(())
    }
}

impl<T: Send + 'static> Stream<T> {
    pub fn new(items: impl futures_util::Stream<Item = T> + Send + 'static) -> Self {
        Self {
            items: items.boxed().peekable(),
        }
    }

    pub async fn next(&mut self) -> Option<T> {
        self.items.next().await
    }
}

/// An empty stream: the component sees it end at once.
impl<T: Send + 'static> Default for Stream<T> {
    fn default() -> Self {
        Self::new(stream::empty())
    }
}

impl<D, T: Lift + Lower + Send + Sync + 'static> StreamConsumer<D> for Sink<T> {
    type Item = T;

    fn poll_consume(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        store: StoreContextMut<D>,
        mut source: Source<'_, T>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            self.sender.abort_send();
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        if ready!(self.sender.poll_reserve(context)).is_err() {
            return Poll::Ready(Ok(StreamResult::Dropped));
        }
        let mut item = None;
        if let Err(error) = source.read(store, &mut item) {
            self.sender.abort_send();
            return Poll::Ready(Err(error));
        }
        if let Some(item) = item {
            match self.sender.send_item(item) {
                Ok(()) => Poll::Ready(Ok(StreamResult::Completed)),
                Err(_) => Poll::Ready(Ok(StreamResult::Dropped)),
            }
        } else {
            self.sender.abort_send();
            Poll::Ready(Ok(StreamResult::Completed))
        }
    }
}

impl<D, T: Lift + Lower + Send + Sync + 'static> StreamProducer<D> for Stream<T> {
    type Item = T;
    // P3 device streams require VecBuffer; Option<T> stalls the cross-store bridge.
    type Buffer = VecBuffer<T>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        store: StoreContextMut<'a, D>,
        destination: Destination<'a, T, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        produce(
            &mut self.items,
            context,
            store,
            destination,
            finish,
            |_, item| Ok(Some(vec![item].into())),
        )
    }
}

/// Takes the component's bytes into a channel in chunks of at most `max_chunk` bytes.
pub struct ByteSink {
    sender: PollSender<Bytes>,
    max_chunk: usize,
    cancelled: CancellationToken,
}

/// The host end of a [`ByteSink`].
pub struct ByteReceiver {
    receiver: mpsc::Receiver<Bytes>,
    cancelled: CancellationToken,
    max_chunk: usize,
    carried: Option<Bytes>,
}

/// The component cancelled a write, which it only does when it abandons the stream, so bytes may be missing.
#[derive(Debug, PartialEq, Eq)]
pub struct WriteCancelled;

/// # Panics
///
/// If `max_chunk` is 0, which would leave every write taking nothing.
#[must_use]
pub fn byte_channel(max_chunk: usize) -> (ByteSink, ByteReceiver) {
    assert!(
        max_chunk > 0,
        "a byte channel chunk holds at least one byte"
    );
    let queued_chunks = (BYTE_QUEUE_BYTES / max_chunk).max(1);
    let (sender, receiver) = mpsc::channel(queued_chunks);
    let cancelled = CancellationToken::new();
    let sink = ByteSink {
        sender: PollSender::new(sender),
        max_chunk,
        cancelled: cancelled.clone(),
    };
    (
        sink,
        ByteReceiver {
            receiver,
            cancelled,
            max_chunk,
            carried: None,
        },
    )
}

impl ByteReceiver {
    /// Cancelled once the component cancels a write, so a task blocked elsewhere can stop too.
    #[must_use]
    pub fn cancellation(&self) -> CancellationToken {
        self.cancelled.clone()
    }

    /// `None` is a clean end: the component dropped the stream with every write complete.
    pub async fn next(&mut self) -> Option<Result<Bytes, WriteCancelled>> {
        let first = if let Some(chunk) = self.carried.take() {
            chunk
        } else {
            tokio::select! {
                biased;
                () = self.cancelled.cancelled() => return Some(Err(WriteCancelled)),
                chunk = self.receiver.recv() => chunk?,
            }
        };
        Some(Ok(self.merge_queued(first)))
    }

    /// Appends the chunks already queued while they fit in `max_chunk`, so a consumer that fell
    /// behind catches up in fewer writes; the first chunk that does not fit waits for the next call.
    fn merge_queued(&mut self, first: Bytes) -> Bytes {
        let mut merged: Option<BytesMut> = None;
        while let Ok(chunk) = self.receiver.try_recv() {
            let length = merged.as_ref().map_or(first.len(), BytesMut::len);
            if length + chunk.len() > self.max_chunk {
                self.carried = Some(chunk);
                break;
            }
            merged
                .get_or_insert_with(|| BytesMut::from(&first[..]))
                .extend_from_slice(&chunk);
        }
        merged.map_or(first, BytesMut::freeze)
    }
}

impl<D> StreamConsumer<D> for ByteSink {
    type Item = u8;

    fn poll_consume(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        store: StoreContextMut<D>,
        source: Source<'_, u8>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            self.sender.abort_send();
            self.cancelled.cancel();
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        if ready!(self.sender.poll_reserve(context)).is_err() {
            return Poll::Ready(Ok(StreamResult::Dropped));
        }
        let mut source = source.as_direct(store);
        let count = source.remaining().len().min(self.max_chunk);
        if count == 0 {
            self.sender.abort_send();
            return Poll::Ready(Ok(StreamResult::Completed));
        }
        let chunk = Bytes::copy_from_slice(&source.remaining()[..count]);
        source.mark_read(count);
        Poll::Ready(Ok(if self.sender.send_item(chunk).is_ok() {
            StreamResult::Completed
        } else {
            StreamResult::Dropped
        }))
    }
}

/// Hands the component each chunk of a host byte stream; the host stream's end ends the component stream.
pub struct ByteStream {
    chunks: Peekable<BoxStream<'static, Bytes>>,
}

impl ByteStream {
    pub fn new(chunks: impl futures_util::Stream<Item = Bytes> + Send + 'static) -> Self {
        Self {
            chunks: chunks.boxed().peekable(),
        }
    }
}

/// An empty stream: the component sees it end at once.
impl Default for ByteStream {
    fn default() -> Self {
        Self::new(stream::empty())
    }
}

impl<D> StreamProducer<D> for ByteStream {
    type Item = u8;
    type Buffer = Bytes;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        store: StoreContextMut<'a, D>,
        destination: Destination<'a, u8, Bytes>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        produce(
            &mut self.chunks,
            context,
            store,
            destination,
            finish,
            |_, chunk| Ok(Some(chunk)),
        )
    }
}

/// Hands the component a resource for each host value, which `push` moves into the store's table.
/// `push` returning `Ok(None)` ends the stream.
pub struct ResourceStream<V, F, R> {
    values: Peekable<BoxStream<'static, V>>,
    push: F,
    resource: PhantomData<fn() -> R>,
}

impl<V: Send + 'static, F, R> ResourceStream<V, F, R> {
    pub fn new(values: impl futures_util::Stream<Item = V> + Send + 'static, push: F) -> Self {
        Self {
            values: values.boxed().peekable(),
            push,
            resource: PhantomData,
        }
    }
}

impl<D, V, F, R> StreamProducer<D> for ResourceStream<V, F, R>
where
    V: Send + 'static,
    F: FnMut(&mut D, V) -> wasmtime::Result<Option<Resource<R>>> + Send + Unpin + 'static,
    R: 'static,
{
    type Item = Resource<R>;
    type Buffer = VecBuffer<Resource<R>>;

    fn poll_produce<'a>(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        store: StoreContextMut<'a, D>,
        destination: Destination<'a, Resource<R>, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        let this = self.get_mut();
        produce(
            &mut this.values,
            context,
            store,
            destination,
            finish,
            |store, value| {
                let resource = (this.push)(store.data_mut(), value)?;
                Ok(resource.map(|resource| vec![resource].into()))
            },
        )
    }
}

/// A byte buffer in host memory, or a non-blocking socket, that the component reads or writes
/// directly, with no task or copy in between. A writer that does more than a non-blocking write,
/// such as framing, uses [`byte_channel`] instead, so that work runs beside the store.
pub trait DirectBuffer: Send + Unpin + 'static {
    /// Resolves after the buffer next changes, so an attempt that moved nothing can retry.
    fn changed(&mut self) -> BoxFuture<'static, ()>;
}

/// Bytes the component reads straight out of host memory or a non-blocking socket.
pub trait TryRead: DirectBuffer {
    /// Copies what is queued into the non-empty `buffer` and returns how much; `Some(0)` means
    /// nothing is queued yet, and `None` ends the stream.
    fn try_read(&mut self, buffer: &mut [u8]) -> Option<usize>;
}

/// Bytes the component writes straight into host memory or a non-blocking socket.
pub trait TryWrite: DirectBuffer {
    /// Takes what fits of the non-empty `bytes` and returns how much; `Some(0)` means the buffer
    /// is full, and `None` ends the stream.
    fn try_write(&mut self, bytes: &[u8]) -> Option<usize>;
}

/// Hands the component bytes straight from a [`TryRead`] buffer into its memory.
pub struct DirectSource<R> {
    buffer: R,
    max_read: usize,
    retry: Retry,
}

impl<R> DirectSource<R> {
    /// `max_read` bounds a read by another host stream, which has no guest buffer to fill.
    pub fn new(buffer: R, max_read: usize) -> Self {
        Self {
            buffer,
            max_read,
            retry: Retry::default(),
        }
    }
}

impl<D, R: TryRead> StreamProducer<D> for DirectSource<R> {
    type Item = u8;
    type Buffer = VecBuffer<u8>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        store: StoreContextMut<'a, D>,
        destination: Destination<'a, u8, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        let this = &mut *self;
        let mut destination = destination.as_direct(store, this.max_read);
        if destination.remaining().is_empty() {
            return Poll::Ready(Ok(StreamResult::Completed));
        }
        loop {
            let Some(count) = this.buffer.try_read(destination.remaining()) else {
                return Poll::Ready(Ok(StreamResult::Dropped));
            };
            if count != 0 {
                destination.mark_written(count);
                return Poll::Ready(Ok(this.retry.done(StreamResult::Completed)));
            }
            if finish {
                return Poll::Ready(Ok(this.retry.done(StreamResult::Cancelled)));
            }
            ready!(this.retry.poll(context, &mut this.buffer));
        }
    }
}

/// Takes the component's bytes straight from its memory into a [`TryWrite`] buffer.
pub struct DirectSink<W> {
    buffer: W,
    retry: Retry,
}

impl<W> DirectSink<W> {
    pub fn new(buffer: W) -> Self {
        Self {
            buffer,
            retry: Retry::default(),
        }
    }
}

impl<D, W: TryWrite> StreamConsumer<D> for DirectSink<W> {
    type Item = u8;

    fn poll_consume(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        store: StoreContextMut<D>,
        source: Source<'_, u8>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        let this = &mut *self;
        let mut source = source.as_direct(store);
        if source.remaining().is_empty() {
            return Poll::Ready(Ok(StreamResult::Completed));
        }
        loop {
            let Some(count) = this.buffer.try_write(source.remaining()) else {
                return Poll::Ready(Ok(StreamResult::Dropped));
            };
            if count != 0 {
                source.mark_read(count);
                return Poll::Ready(Ok(this.retry.done(StreamResult::Completed)));
            }
            if finish {
                return Poll::Ready(Ok(this.retry.done(StreamResult::Cancelled)));
            }
            ready!(this.retry.poll(context, &mut this.buffer));
        }
    }
}

/// The wait between direct attempts that moved nothing.
#[derive(Default)]
struct Retry(Option<BoxFuture<'static, ()>>);

impl Retry {
    /// Ready when the attempt should run again. Arming returns at once, so a change between the
    /// empty attempt and the arming still counts.
    fn poll(&mut self, context: &mut Context<'_>, buffer: &mut impl DirectBuffer) -> Poll<()> {
        match &mut self.0 {
            None => self.0 = Some(buffer.changed()),
            Some(changed) => {
                ready!(changed.as_mut().poll(context));
                self.0 = None;
            }
        }
        Poll::Ready(())
    }

    fn done(&mut self, result: StreamResult) -> StreamResult {
        self.0 = None;
        result
    }
}

enum Next<T> {
    Item(T),
    /// An item is ready but stays queued; the answer to a zero-length read.
    Ready,
    Ended,
    Cancelled,
}

/// Answers one read from `items`; `lower` turns an item a non-zero read took into the buffer the
/// component receives, or `None` to end the stream.
fn produce<'a, D, I, T, B>(
    items: &mut Peekable<BoxStream<'static, I>>,
    context: &mut Context<'_>,
    mut store: StoreContextMut<'a, D>,
    mut destination: Destination<'a, T, B>,
    finish: bool,
    lower: impl FnOnce(&mut StoreContextMut<'a, D>, I) -> wasmtime::Result<Option<B>>,
) -> Poll<wasmtime::Result<StreamResult>> {
    let is_readiness_probe = destination.remaining(&mut store) == Some(0);
    Poll::Ready(Ok(
        match ready!(poll_next(items, context, is_readiness_probe, finish)) {
            Next::Item(item) => match lower(&mut store, item)? {
                Some(buffer) => {
                    destination.set_buffer(buffer);
                    StreamResult::Completed
                }
                None => StreamResult::Dropped,
            },
            Next::Ready => StreamResult::Completed,
            Next::Ended => StreamResult::Dropped,
            Next::Cancelled => StreamResult::Cancelled,
        },
    ))
}

fn poll_next<T>(
    items: &mut Peekable<BoxStream<'static, T>>,
    context: &mut Context<'_>,
    is_readiness_probe: bool,
    finish: bool,
) -> Poll<Next<T>> {
    let next = if is_readiness_probe {
        Pin::new(items).poll_peek(context).map(|item| {
            if item.is_some() {
                Next::Ready
            } else {
                Next::Ended
            }
        })
    } else {
        items
            .poll_next_unpin(context)
            .map(|item| item.map_or(Next::Ended, Next::Item))
    };
    match next {
        Poll::Pending if finish => Poll::Ready(Next::Cancelled),
        next => next,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use wasmtime::component::{Source, StreamConsumer, StreamReader};

    struct TrackedSink {
        sink: Sink<crate::component::mmio::Request>,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for TrackedSink {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    impl StreamConsumer<()> for TrackedSink {
        type Item = crate::component::mmio::Request;

        fn poll_consume(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            store: StoreContextMut<()>,
            source: Source<'_, Self::Item>,
            finish: bool,
        ) -> Poll<wasmtime::Result<StreamResult>> {
            Pin::new(&mut self.sink).poll_consume(context, store, source, finish)
        }
    }

    fn request(sequence: u64) -> crate::component::mmio::Request {
        crate::component::mmio::Request {
            sequence,
            operation: crate::component::mmio::Operation::Read,
            offset: 0,
            width: 4,
            value: 0,
        }
    }

    #[tokio::test]
    async fn sink_reserves_capacity_before_lowering_and_preserves_order() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut store = crate::engine::device_store(&engine, ());
        let (sink, mut stream) =
            channel::<crate::component::mmio::Request>(NonZeroUsize::new(2).expect("capacity"));
        let input =
            StreamReader::new(&mut store, vec![request(1), request(2), request(3)]).expect("input");
        input.pipe(&mut store, sink).expect("attach sink");
        store
            .run_concurrent(async |_| {
                for _ in 0..16 {
                    tokio::task::yield_now().await;
                }
                assert_eq!(stream.next().await.expect("first").sequence, 1);
                assert_eq!(stream.next().await.expect("second").sequence, 2);
                assert_eq!(stream.next().await.expect("third").sequence, 3);
            })
            .await
            .expect("run relay");
    }

    #[tokio::test]
    async fn stream_moves_records_between_independent_stores_in_order() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut root = crate::engine::device_store(&engine, ());
        let mut child = crate::engine::device_store(&engine, ());
        let (sink, stream) =
            channel::<crate::component::mmio::Request>(NonZeroUsize::new(2).expect("capacity"));
        let input =
            StreamReader::new(&mut root, vec![request(1), request(2), request(3)]).expect("input");
        input.pipe(&mut root, sink).expect("attach root sink");
        let child_input = StreamReader::new(&mut child, stream).expect("child source");
        let (child_sink, mut received) =
            channel::<crate::component::mmio::Request>(NonZeroUsize::new(2).expect("capacity"));
        child_input
            .pipe(&mut child, child_sink)
            .expect("attach child sink");
        let (finished, root_done) = tokio::sync::oneshot::channel();
        let (root_result, child_result) = tokio::join!(
            root.run_concurrent(async |_| root_done.await),
            child.run_concurrent(async |_| {
                let mut sequences = Vec::new();
                while sequences.len() != 3 {
                    sequences.push(received.next().await.expect("relayed record").sequence);
                }
                finished.send(()).expect("root waits");
                sequences
            })
        );
        root_result.expect("root relay").expect("root finished");
        assert_eq!(child_result.expect("child relay"), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn closed_receiver_drops_the_source_stream() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut store = crate::engine::device_store(&engine, ());
        let (sink, stream) = channel::<crate::component::mmio::Reply>(NonZeroUsize::MIN);
        drop(stream);
        let input = StreamReader::new(
            &mut store,
            vec![crate::component::mmio::Reply {
                sequence: 1,
                value: 0,
                error: None,
            }],
        )
        .expect("input");
        input.pipe(&mut store, sink).expect("attach sink");
        store
            .run_concurrent(async |_| tokio::task::yield_now().await)
            .await
            .expect("closed receiver");
    }

    #[tokio::test]
    async fn dropping_the_other_store_cancels_a_blocked_relay() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut store = crate::engine::device_store(&engine, ());
        let (sink, mut stream) =
            channel::<crate::component::mmio::Request>(NonZeroUsize::new(1).expect("capacity"));
        let dropped = Arc::new(AtomicBool::new(false));
        let input =
            StreamReader::new(&mut store, vec![request(1), request(2), request(3)]).expect("input");
        input
            .pipe(
                &mut store,
                TrackedSink {
                    sink,
                    dropped: Arc::clone(&dropped),
                },
            )
            .expect("attach sink");
        store
            .run_concurrent(async |_| {
                let _ = stream.next().await.expect("first");
                for _ in 0..16 {
                    tokio::task::yield_now().await;
                }
                drop(stream);
                while !dropped.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("cancellation");
    }

    #[tokio::test]
    async fn queued_chunks_merge_in_order_up_to_the_chunk_limit() {
        let (sink, mut chunks) = byte_channel(4);
        for chunk in [&b"ab"[..], b"cd", b"e"] {
            let sender = sink.sender.get_ref().unwrap();
            sender.send(Bytes::copy_from_slice(chunk)).await.unwrap();
        }
        drop(sink);
        assert_eq!(chunks.next().await, Some(Ok(Bytes::from_static(b"abcd"))));
        assert_eq!(chunks.next().await, Some(Ok(Bytes::from_static(b"e"))));
        assert_eq!(chunks.next().await, None);
    }

    #[tokio::test]
    async fn bytes_cross_the_component_boundary_in_bounded_chunks_and_end_cleanly() {
        let engine = crate::engine::device_engine().unwrap();
        let mut store = crate::engine::device_store(&engine, ());
        let source = ByteStream::new(stream::iter([
            Bytes::from_static(b"abcde"),
            Bytes::from_static(b"f"),
        ]));
        let (sink, mut chunks) = byte_channel(2);
        StreamReader::new(&mut store, source)
            .unwrap()
            .pipe(&mut store, sink)
            .unwrap();
        let received = store
            .run_concurrent(async |_| {
                let mut received = Vec::new();
                while let Some(chunk) = chunks.next().await {
                    received.push(chunk.unwrap());
                }
                received
            })
            .await
            .unwrap();
        assert!(received.iter().all(|chunk| chunk.len() <= 2));
        assert_eq!(received.concat(), b"abcdef");
    }

    /// A zero-length read reports readiness without taking the item, so the next read still gets it.
    #[test]
    fn readiness_probe_leaves_the_item_queued() {
        let mut items = stream::iter([1, 2]).boxed().peekable();
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            poll_next(&mut items, &mut context, true, false),
            Poll::Ready(Next::Ready)
        ));
        assert!(matches!(
            poll_next(&mut items, &mut context, false, false),
            Poll::Ready(Next::Item(1))
        ));
        assert!(matches!(
            poll_next(&mut items, &mut context, false, false),
            Poll::Ready(Next::Item(2))
        ));
        assert!(matches!(
            poll_next(&mut items, &mut context, true, false),
            Poll::Ready(Next::Ended)
        ));
    }

    #[test]
    fn cancelling_a_blocked_read_takes_nothing() {
        let mut items = stream::pending::<u8>().boxed().peekable();
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(poll_next(&mut items, &mut context, false, false).is_pending());
        assert!(matches!(
            poll_next(&mut items, &mut context, false, true),
            Poll::Ready(Next::Cancelled)
        ));
    }

    /// A cancelled write must not look like a clean end, or a truncated stream would pass as complete.
    #[tokio::test]
    async fn cancelled_write_is_reported_instead_of_a_clean_end() {
        let (sink, mut chunks) = byte_channel(2);
        sink.cancelled.cancel();
        drop(sink);
        assert_eq!(chunks.next().await, Some(Err(WriteCancelled)));
    }
}
