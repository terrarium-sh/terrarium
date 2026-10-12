use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use bytes::Bytes;
use futures_util::stream;
use terra_runtime::component::relay::ByteStream;

/// Sets its flag when dropped, so a test sees when a stream released its source.
pub struct DropFlag(pub Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Yields the bytes once `receiver` delivers them, then ends; `dropped` is set when the stream is dropped.
pub fn delayed_bytes(
    receiver: tokio::sync::oneshot::Receiver<Vec<u8>>,
    dropped: Arc<AtomicBool>,
) -> ByteStream {
    let state = (Some(receiver), DropFlag(dropped));
    ByteStream::new(stream::unfold(state, |(receiver, flag)| async move {
        let bytes = receiver?.await.ok()?;
        Some((Bytes::from(bytes), (None, flag)))
    }))
}
