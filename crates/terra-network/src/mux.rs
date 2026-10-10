//! The yamux connection both ends of the broker channel share.

use tokio::io::{AsyncRead, AsyncWrite, BufStream};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use yamux::{Config, Connection, Mode};

const YAMUX_STREAM_WINDOW_BYTES: usize = 256 << 10;
const CHANNEL_READ_BUFFER_BYTES: usize = 256 << 10;
const CHANNEL_WRITE_BUFFER_BYTES: usize = 64 << 10;

pub(crate) type Channel<T> = Compat<BufStream<T>>;

pub(crate) fn yamux_config() -> Config {
    let mut config = Config::default();
    config
        .set_max_num_streams(crate::MAX_STREAMS)
        .set_max_connection_receive_window(Some(crate::MAX_STREAMS * YAMUX_STREAM_WINDOW_BYTES))
        .set_split_send_size(terra_protocol::network::MAX_NETWORK_FRAME_BYTES)
        .set_read_after_close(false);
    config
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
        yamux_config(),
        mode,
    )
}
