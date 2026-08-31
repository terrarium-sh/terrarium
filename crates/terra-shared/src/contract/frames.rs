//! The framed wire protocol spoken across host/guest channels.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TermSize {
    pub rows: u16,
    pub cols: u16,
}

/// Ceiling on a frame's payload; the reader refuses a peer's length past it
/// before allocating.
const MAX_FRAME_BYTES: usize = 8 << 20;

/// Read a `u32`-LE length prefix; see [`MAX_FRAME_BYTES`]. Returns `None` on a
/// clean EOF at a frame boundary.
fn read_len(reader: &mut impl Read) -> io::Result<Option<usize>> {
    let mut bytes = [0u8; 4];
    match reader.read_exact(&mut bytes[..1]) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    reader.read_exact(&mut bytes[1..])?;
    let len = u32::from_le_bytes(bytes) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(make_oversized_error(len));
    }
    Ok(Some(len))
}

fn make_oversized_error(len: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("framed message of {len} bytes exceeds the {MAX_FRAME_BYTES}-byte limit"),
    )
}

struct FramePayload(Vec<u8>);

impl Write for FramePayload {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let len = self.0.len().saturating_add(bytes.len());
        if len > MAX_FRAME_BYTES {
            return Err(make_oversized_error(len));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Encode any message as the one wire shape every terra channel uses: a
/// `u32` LE length prefix plus JSON.
#[allow(clippy::cast_possible_truncation)]
pub fn encode_frame<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let mut payload = FramePayload(Vec::new());
    serde_json::to_writer(&mut payload, value).map_err(io::Error::other)?;
    let mut frame = Vec::with_capacity(4 + payload.0.len());
    frame.extend_from_slice(&(payload.0.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload.0);
    Ok(frame)
}

/// Read one frame; `None` on a clean EOF at a frame boundary.
pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> io::Result<Option<T>> {
    let Some(len) = read_len(reader)? else {
        return Ok(None);
    };
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientInput {
    Keys(Vec<u8>),
    Resize(TermSize),
    Eof,
}

/// A framed message from the agent to one client - down a `terra exec` and
/// down an attached session alike.
///
/// Framed rather than raw because the status the command or the workload
/// ended with has to come back, and the vsock proxy carries no half-close to
/// mark the end with.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentOutput {
    Out(Vec<u8>),
    Err(Vec<u8>),
    /// The last frame either connection sends: an exec's command status, or the
    /// status the box's workload ended with.
    Exit {
        code: i32,
    },
    /// The session dropped this client - `terra <box> detach` - so the bare
    /// EOF that follows does not read as the box dying.
    Detached,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlRequest {
    List,
    Detach { id: u64 },
    DetachAll,
}

/// The agent's answer to one [`ControlRequest`]: a `List` gets a `Client`
/// frame per attached client, then a `Done`. A `Detach` gets `Detached` or
/// `Missing`; a `DetachAll`, one `Detached` per client dropped, then `Done`.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlReply {
    Client { id: u64, size: Option<TermSize> },
    Done,
    Detached { id: u64 },
    Missing { id: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_client_input_frames() {
        for msg in [
            ClientInput::Keys(b"ls -la\n".to_vec()),
            ClientInput::Keys(vec![]),
            ClientInput::Resize(TermSize {
                rows: 40,
                cols: 120,
            }),
            ClientInput::Eof,
        ] {
            let encoded = encode_frame(&msg).unwrap();
            let mut cur = std::io::Cursor::new(encoded);
            assert_eq!(read_frame(&mut cur).unwrap(), Some(msg));
        }
        let mut empty = std::io::Cursor::new(Vec::new());
        assert_eq!(read_frame::<ClientInput>(&mut empty).unwrap(), None);
    }

    #[test]
    fn refuse_oversized_frame() {
        let big = vec![b'x'; MAX_FRAME_BYTES + 1];
        let err = encode_frame(&ClientInput::Keys(big)).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    /// The reader runs as guest init, on a length its peer chose.
    #[test]
    fn refuse_absurd_client_frame_before_allocating() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&u32::MAX.to_le_bytes());
        let err = read_frame::<ClientInput>(&mut std::io::Cursor::new(wire)).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    /// An exec's output and its exit status share one stream, so the status has
    /// to survive whatever the command printed - a `\x01` in the output must not
    /// be read as an exit frame, and a negative code must round-trip.
    #[test]
    fn round_trip_exec_output_and_exit_status() {
        for msg in [
            AgentOutput::Out(b"\x00\x01\x02 arbitrary \xff bytes\n".to_vec()),
            AgentOutput::Out(vec![]),
            AgentOutput::Err(b"warning: \x01\x02\n".to_vec()),
            AgentOutput::Exit { code: 0 },
            AgentOutput::Exit { code: 127 },
            AgentOutput::Exit { code: -1 },
            AgentOutput::Detached,
        ] {
            let mut cur = std::io::Cursor::new(encode_frame(&msg).unwrap());
            assert_eq!(read_frame(&mut cur).unwrap(), Some(msg));
        }
        let mut empty = std::io::Cursor::new(Vec::new());
        assert_eq!(read_frame::<AgentOutput>(&mut empty).unwrap(), None);
    }

    #[test]
    fn round_trip_control_requests() {
        for msg in [
            ControlRequest::List,
            ControlRequest::Detach { id: 0 },
            ControlRequest::Detach { id: u64::MAX },
            ControlRequest::DetachAll,
        ] {
            let encoded = encode_frame(&msg).unwrap();
            let mut cur = std::io::Cursor::new(encoded);
            assert_eq!(read_frame(&mut cur).unwrap(), Some(msg));
        }
        let mut empty = std::io::Cursor::new(Vec::new());
        assert_eq!(read_frame::<ControlRequest>(&mut empty).unwrap(), None);
    }

    #[test]
    fn round_trip_control_replies() {
        for msg in [
            ControlReply::Client {
                id: 7,
                size: Some(TermSize {
                    rows: 40,
                    cols: 120,
                }),
            },
            ControlReply::Client { id: 3, size: None },
            ControlReply::Done,
            ControlReply::Detached { id: 2 },
            ControlReply::Missing { id: 9 },
        ] {
            let encoded = encode_frame(&msg).unwrap();
            let mut cur = std::io::Cursor::new(encoded);
            assert_eq!(read_frame(&mut cur).unwrap(), Some(msg));
        }
    }

    #[test]
    fn refuse_bad_control_frame() {
        let mut bad = Vec::new();
        bad.extend_from_slice(&4u32.to_le_bytes());
        bad.extend_from_slice(b"nope");
        let err = read_frame::<ControlReply>(&mut std::io::Cursor::new(bad)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
