use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

use crate::support::stream_relay::DropFlag;
use terra_runtime::component::relay::{BYTE_QUEUE_BYTES, ByteSink, byte_channel};
use wasmtime::StoreContextMut;
use wasmtime::component::{Source, StreamConsumer, StreamReader, StreamResult};

const CHUNK_BYTES: usize = 16 * 1024;

/// Observes when wasmtime drops the sink; it forwards every call unchanged.
struct TrackedSink {
    sink: ByteSink,
    _dropped: DropFlag,
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
    let mut store = terra_runtime::engine::device_store(&engine, ());
    let (sink, mut chunks) = byte_channel(CHUNK_BYTES);
    let dropped = Arc::new(AtomicBool::new(false));
    let input = StreamReader::new(&mut store, vec![7_u8; BYTE_QUEUE_BYTES + CHUNK_BYTES * 4])
        .expect("input stream");
    input
        .pipe(
            &mut store,
            TrackedSink {
                sink,
                _dropped: DropFlag(Arc::clone(&dropped)),
            },
        )
        .expect("attach relay");

    tokio::time::timeout(
        Duration::from_secs(2),
        store.run_concurrent(async |_| {
            let first = chunks
                .next()
                .await
                .expect("queued chunk")
                .expect("complete write");
            assert_eq!(first, vec![7; CHUNK_BYTES]);
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
            assert!(!dropped.load(Ordering::Acquire));
            drop(chunks);
            while !dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        }),
    )
    .await
    .expect("relay deadline")
    .expect("relay execution");
}
