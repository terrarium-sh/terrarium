//! Bounded owned-value streams between component stores.

use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use wasmtime::StoreContextMut;
use wasmtime::component::{
    Destination, Lift, Lower, Source, StreamConsumer, StreamProducer, StreamResult, VecBuffer,
};

pub const MMIO_CAPACITY: NonZeroUsize = NonZeroUsize::new(64).expect("nonzero relay capacity");

pub struct Sink<T> {
    sender: PollSender<T>,
}

pub struct Stream<T> {
    receiver: mpsc::Receiver<T>,
}

#[must_use]
pub fn channel<T: Lift + Lower + Send + Sync + 'static>(
    capacity: NonZeroUsize,
) -> (Sink<T>, Stream<T>) {
    let (sender, receiver) = mpsc::channel(capacity.get());
    (
        Sink {
            sender: PollSender::new(sender),
        },
        Stream { receiver },
    )
}

impl<D: 'static, T: Lift + Lower + Send + Sync + 'static> StreamConsumer<D> for Sink<T> {
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
        if std::task::ready!(self.sender.poll_reserve(context)).is_err() {
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

impl<D: 'static, T: Lift + Lower + Send + Sync + 'static> StreamProducer<D> for Stream<T> {
    type Item = T;
    // P3 device streams require VecBuffer; Option<T> stalls the cross-store bridge.
    type Buffer = VecBuffer<T>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        _: StoreContextMut<'a, D>,
        mut destination: Destination<'a, T, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        match std::task::ready!(self.receiver.poll_recv(context)) {
            Some(item) => {
                destination.set_buffer(vec![item].into());
                Poll::Ready(Ok(StreamResult::Completed))
            }
            None => Poll::Ready(Ok(StreamResult::Dropped)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use wasmtime::Store;
    use wasmtime::component::{Source, StreamConsumer, StreamReader};

    struct TrackedSink {
        sink: Sink<crate::component::vmm::mmio::Request>,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for TrackedSink {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    impl StreamConsumer<()> for TrackedSink {
        type Item = crate::component::vmm::mmio::Request;

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

    struct CollectSink(Arc<std::sync::Mutex<Vec<u64>>>);

    impl StreamConsumer<()> for CollectSink {
        type Item = crate::component::vmm::mmio::Request;

        fn poll_consume(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            store: StoreContextMut<()>,
            mut source: Source<'_, Self::Item>,
            finish: bool,
        ) -> Poll<wasmtime::Result<StreamResult>> {
            if finish {
                return Poll::Ready(Ok(StreamResult::Cancelled));
            }
            let mut item = None;
            source.read(store, &mut item)?;
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend(item.into_iter().map(|request| request.sequence));
            Poll::Ready(Ok(StreamResult::Completed))
        }
    }

    fn request(sequence: u64) -> crate::component::vmm::mmio::Request {
        crate::component::vmm::mmio::Request {
            sequence,
            operation: crate::component::vmm::mmio::Operation::Read,
            offset: 0,
            width: 4,
            value: 0,
        }
    }

    #[tokio::test]
    async fn sink_reserves_capacity_before_lowering_and_preserves_order() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut store = Store::new(&engine, ());
        let (sink, mut stream) = channel::<crate::component::vmm::mmio::Request>(
            NonZeroUsize::new(2).expect("capacity"),
        );
        let input =
            StreamReader::new(&mut store, vec![request(1), request(2), request(3)]).expect("input");
        input.pipe(&mut store, sink).expect("attach sink");
        store
            .run_concurrent(async |_| {
                while stream.receiver.len() != 2 {
                    tokio::task::yield_now().await;
                }
                assert_eq!(stream.receiver.recv().await.expect("first").sequence, 1);
                assert_eq!(stream.receiver.recv().await.expect("second").sequence, 2);
                assert_eq!(stream.receiver.recv().await.expect("third").sequence, 3);
            })
            .await
            .expect("run relay");
    }

    #[tokio::test]
    async fn stream_moves_records_between_independent_stores_in_order() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut root = Store::new(&engine, ());
        let mut child = Store::new(&engine, ());
        let (sink, stream) = channel::<crate::component::vmm::mmio::Request>(
            NonZeroUsize::new(2).expect("capacity"),
        );
        let input =
            StreamReader::new(&mut root, vec![request(1), request(2), request(3)]).expect("input");
        input.pipe(&mut root, sink).expect("attach root sink");
        let child_input = StreamReader::new(&mut child, stream).expect("child source");
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        child_input
            .pipe(&mut child, CollectSink(Arc::clone(&received)))
            .expect("attach child sink");
        let root_received = Arc::clone(&received);
        let child_received = Arc::clone(&received);
        let (root_result, child_result) = tokio::join!(
            root.run_concurrent(async |_| {
                while root_received
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len()
                    != 3
                {
                    tokio::task::yield_now().await;
                }
            }),
            child.run_concurrent(async |_| {
                while child_received
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len()
                    != 3
                {
                    tokio::task::yield_now().await;
                }
            })
        );
        root_result.expect("root relay");
        child_result.expect("child relay");
        assert_eq!(
            *received
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            vec![1, 2, 3]
        );
    }

    #[tokio::test]
    async fn closed_receiver_drops_the_source_stream() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut store = Store::new(&engine, ());
        let (sink, stream) = channel::<crate::component::vmm::mmio::Reply>(MMIO_CAPACITY);
        drop(stream);
        let input = StreamReader::new(
            &mut store,
            vec![crate::component::vmm::mmio::Reply {
                sequence: 1,
                value: 0,
                error: 0,
                interrupt: false,
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
        let mut store = Store::new(&engine, ());
        let (sink, mut stream) = channel::<crate::component::vmm::mmio::Request>(
            NonZeroUsize::new(1).expect("capacity"),
        );
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
                while stream.receiver.len() != 1 {
                    tokio::task::yield_now().await;
                }
                let _ = stream.receiver.recv().await.expect("first");
                while stream.receiver.len() != 1 {
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
}
