#![allow(clippy::expect_used)]

#[path = "support/stream_relay.rs"]
mod relay;

use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

use relay::{ByteSink, CHUNK_BYTES, QUEUED_CHUNKS, create_byte_channel};
use wasmtime::component::{Source, StreamConsumer, StreamReader, StreamResult};
use wasmtime::{Store, StoreContextMut};

struct TrackedSink {
    sink: ByteSink,
    dropped: Arc<AtomicBool>,
}

impl Drop for TrackedSink {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

impl StreamConsumer<()> for TrackedSink {
    type Item = u8;

    fn poll_consume(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        store: StoreContextMut<()>,
        source: Source<'_, u8>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        Pin::new(&mut self.sink).poll_consume(context, store, source, finish)
    }
}

#[tokio::test]
async fn bounded_relay_releases_a_blocked_cross_store_writer() {
    let engine = terra_runtime::engine::device_engine().expect("engine");
    let mut store = Store::new(&engine, ());
    let (sink, mut source) = create_byte_channel();
    let dropped = Arc::new(AtomicBool::new(false));
    let input = StreamReader::new(&mut store, vec![7_u8; CHUNK_BYTES * (QUEUED_CHUNKS + 2)])
        .expect("input stream");
    input
        .pipe(
            &mut store,
            TrackedSink {
                sink,
                dropped: Arc::clone(&dropped),
            },
        )
        .expect("attach relay");

    tokio::time::timeout(
        Duration::from_secs(2),
        store.run_concurrent(async |_| {
            while source.receiver.len() != QUEUED_CHUNKS {
                tokio::task::yield_now().await;
            }
            assert!(!dropped.load(Ordering::Acquire));
            assert_eq!(
                source.receiver.try_recv().expect("queued chunk"),
                vec![7; CHUNK_BYTES]
            );
            while source.receiver.len() != QUEUED_CHUNKS {
                tokio::task::yield_now().await;
            }
            drop(source);
            while !dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        }),
    )
    .await
    .expect("relay deadline")
    .expect("relay execution");
}
