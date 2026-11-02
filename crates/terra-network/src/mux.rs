//! The yamux connection both ends of the broker channel share.

use tokio::io::{AsyncRead, AsyncWrite, BufStream};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use yamux::{Connection, Mode};

const CHANNEL_READ_BUFFER_BYTES: usize = 256 << 10;
const CHANNEL_WRITE_BUFFER_BYTES: usize = 64 << 10;

pub(crate) type Channel<T> = Compat<BufStream<T>>;

#[must_use]
pub fn broker_yamux_config() -> yamux::Config {
    terra_protocol::mux::yamux_config(
        crate::MAX_STREAMS,
        terra_protocol::network::MAX_NETWORK_PAYLOAD_BYTES,
    )
}

/// yamux reads and writes each frame's header and body separately, so the channel is buffered: one
/// syscall carries many frames, and yamux flushes whenever its send queue drains.
pub(crate) fn connect<T: AsyncRead + AsyncWrite + Unpin>(
    channel: T,
    mode: Mode,
) -> Connection<Channel<T>> {
    Connection::new(
        BufStream::with_capacity(
            CHANNEL_READ_BUFFER_BYTES,
            CHANNEL_WRITE_BUFFER_BYTES,
            channel,
        )
        .compat(),
        broker_yamux_config(),
        mode,
    )
}
