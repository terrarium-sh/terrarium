//! Shared limits and configuration for terra's Yamux carriers.

pub const CONTROL_STREAM_ID: u32 = 1;
pub const DIAGNOSTIC_STREAM_ID: u32 = 3;
/// The streams the guest opens first, in order; Yamux numbers client-opened streams 1, 3, ….
pub const RESERVED_STREAM_IDS: [u32; 2] = [CONTROL_STREAM_ID, DIAGNOSTIC_STREAM_ID];
pub const MAX_CLIENT_STREAMS: usize = 64;
/// Every stream's receive window: Yamux opens each stream with this credit, and
/// [`yamux_config`] leaves no connection window for auto-tuning to grow one past it.
pub const MAX_STREAM_WINDOW_BYTES: usize = yamux::DEFAULT_CREDIT as usize;
pub const MAX_STREAM_FRAME_BYTES: usize = 16 << 10;

/// The agent carrier's configuration: the reserved streams plus the client streams.
#[must_use]
pub fn agent_yamux_config() -> yamux::Config {
    yamux_config(
        RESERVED_STREAM_IDS.len() + MAX_CLIENT_STREAMS,
        MAX_STREAM_FRAME_BYTES,
    )
}

/// Caps every stream at [`MAX_STREAM_WINDOW_BYTES`] and splits sends into `max_frame_bytes`.
#[must_use]
pub fn yamux_config(max_streams: usize, max_frame_bytes: usize) -> yamux::Config {
    let mut config = yamux::Config::default();
    config
        .set_max_num_streams(max_streams)
        .set_max_connection_receive_window(Some(max_streams * MAX_STREAM_WINDOW_BYTES))
        .set_split_send_size(max_frame_bytes)
        .set_read_after_close(false);
    config
}
