//! Shared limits for the agent's Yamux carrier.

pub const RESERVED_STREAMS: usize = 2;
pub const CONTROL_STREAM_ID: u32 = 1;
pub const DIAGNOSTIC_STREAM_ID: u32 = 3;
pub const MAX_CLIENT_STREAMS: usize = 64;
pub const MAX_STREAM_WINDOW_BYTES: usize = 256 << 10;
pub const MAX_CONNECTION_WINDOW_BYTES: usize =
    (RESERVED_STREAMS + MAX_CLIENT_STREAMS) * MAX_STREAM_WINDOW_BYTES;
pub const MAX_STREAM_FRAME_BYTES: usize = 16 << 10;

#[cfg(feature = "mux")]
#[must_use]
pub fn yamux_config() -> yamux::Config {
    let mut config = yamux::Config::default();
    config
        .set_max_num_streams(RESERVED_STREAMS + MAX_CLIENT_STREAMS)
        .set_max_connection_receive_window(Some(MAX_CONNECTION_WINDOW_BYTES))
        .set_split_send_size(MAX_STREAM_FRAME_BYTES)
        .set_read_after_close(false);
    config
}
