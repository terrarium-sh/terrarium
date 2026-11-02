//! Hand-built Yamux frames, so agent fixtures pin the wire format instead of reusing the yamux crate.

use terra_protocol::mux::MAX_STREAM_FRAME_BYTES;

const HEADER_BYTES: usize = 12;
pub const DATA: u8 = 0;
pub const WINDOW_UPDATE: u8 = 1;
pub const PING: u8 = 2;
pub const GO_AWAY: u8 = 3;
pub const SYN: u16 = 1;
pub const ACK: u16 = 2;
pub const RST: u16 = 8;
/// Yamux numbers host-opened streams 2, 4, …, so the host's first client stream is 2.
pub const FIRST_CLIENT_STREAM_ID: u32 = 2;

pub struct Frame {
    pub kind: u8,
    pub flags: u16,
    pub stream: u32,
    pub value: u32,
    pub payload: Vec<u8>,
}

/// One frame; a data frame's `value` is its payload length.
#[must_use]
pub fn encode(kind: u8, flags: u16, stream: u32, value: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, kind];
    bytes.extend(flags.to_be_bytes());
    bytes.extend(stream.to_be_bytes());
    bytes.extend(value.to_be_bytes());
    bytes.extend(payload);
    bytes
}

pub fn data(flags: u16, stream: u32, payload: &[u8]) -> wasmtime::Result<Vec<u8>> {
    Ok(encode(
        DATA,
        flags,
        stream,
        u32::try_from(payload.len())?,
        payload,
    ))
}

/// Removes the first whole frame from `bytes`; `Ok(None)` until one has arrived.
pub fn take_frame(bytes: &mut Vec<u8>) -> wasmtime::Result<Option<Frame>> {
    let Some(header) = bytes.first_chunk::<HEADER_BYTES>() else {
        return Ok(None);
    };
    let [_, kind, f0, f1, s0, s1, s2, s3, v0, v1, v2, v3] = *header;
    let value = u32::from_be_bytes([v0, v1, v2, v3]);
    let length = if kind == DATA {
        usize::try_from(value)?
    } else {
        0
    };
    wasmtime::ensure!(
        length <= MAX_STREAM_FRAME_BYTES,
        "Yamux frame over the agent frame limit"
    );
    let Some(payload) = bytes.get(HEADER_BYTES..HEADER_BYTES + length) else {
        return Ok(None);
    };
    let frame = Frame {
        kind,
        flags: u16::from_be_bytes([f0, f1]),
        stream: u32::from_be_bytes([s0, s1, s2, s3]),
        value,
        payload: payload.to_vec(),
    };
    bytes.drain(..HEADER_BYTES + length);
    Ok(Some(frame))
}
