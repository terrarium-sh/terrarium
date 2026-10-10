//! Length-prefixed frames on yamux streams, bounded by the network frame limit.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io;
use terra_protocol::network::MAX_NETWORK_FRAME_BYTES;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// `None` means the stream ended at a frame boundary.
pub(crate) async fn read_frame<T: DeserializeOwned>(
    read: &mut (impl AsyncRead + Unpin),
) -> io::Result<Option<T>> {
    terra_protocol::read_frame_async_with_limit(read, MAX_NETWORK_FRAME_BYTES).await
}

pub(crate) async fn write_frame<T: Serialize>(
    write: &mut (impl AsyncWrite + Unpin),
    value: &T,
) -> io::Result<()> {
    let frame = terra_protocol::encode_frame_with_limit(value, MAX_NETWORK_FRAME_BYTES)?;
    write.write_all(&frame).await
}
