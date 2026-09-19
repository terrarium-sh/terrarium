//! The framed wire protocol spoken across host/guest channels.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TermSize {
    pub rows: u16,
    pub cols: u16,
}

/// Ceiling on a frame's payload; the reader refuses a peer's length past it
/// before allocating.
const MAX_FRAME_BYTES: usize = 8 << 20;

pub const MAX_PLAN_BYTES: usize = 1 << 20;
pub const MAX_PLAN_HOST_STATE_BYTES: usize = 1024;

/// Read a `u32`-LE length prefix; see [`MAX_FRAME_BYTES`]. Returns `None` on a
/// clean EOF at a frame boundary.
fn read_len(reader: &mut impl Read, max_bytes: usize) -> io::Result<Option<usize>> {
    let mut bytes = [0u8; 4];
    match reader.read_exact(&mut bytes[..1]) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    reader.read_exact(&mut bytes[1..])?;
    checked_len(bytes, max_bytes).map(Some)
}

fn checked_len(bytes: [u8; 4], max_bytes: usize) -> io::Result<usize> {
    let len = u32::from_le_bytes(bytes) as usize;
    if len > max_bytes {
        return Err(make_oversized_error(len, max_bytes));
    }
    Ok(len)
}

fn make_oversized_error(len: usize, max_bytes: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("framed message of {len} bytes exceeds the {max_bytes}-byte limit"),
    )
}

struct FramePayload {
    bytes: Vec<u8>,
    max_bytes: usize,
}

impl Write for FramePayload {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let len = self.bytes.len().saturating_add(bytes.len());
        if len > self.max_bytes {
            return Err(make_oversized_error(len, self.max_bytes));
        }
        self.bytes.extend_from_slice(bytes);
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
    encode_frame_with_limit(value, MAX_FRAME_BYTES)
}

/// Encode one frame with a payload limit.
#[allow(clippy::cast_possible_truncation)]
pub fn encode_frame_with_limit<T: Serialize>(value: &T, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut payload = FramePayload {
        bytes: Vec::new(),
        max_bytes: max_bytes.min(MAX_FRAME_BYTES),
    };
    serde_json::to_writer(&mut payload, value).map_err(io::Error::other)?;
    let mut frame = Vec::with_capacity(4 + payload.bytes.len());
    frame.extend_from_slice(&(payload.bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload.bytes);
    Ok(frame)
}

/// Read one frame; `None` on a clean EOF at a frame boundary.
pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> io::Result<Option<T>> {
    read_frame_with_limit(reader, MAX_FRAME_BYTES)
}

/// Read one frame asynchronously; `None` on a clean EOF at a frame boundary.
#[cfg(feature = "tokio")]
pub async fn read_frame_async<T: DeserializeOwned>(
    reader: &mut (impl AsyncRead + Unpin),
) -> io::Result<Option<T>> {
    read_frame_async_with_limit(reader, MAX_FRAME_BYTES).await
}

/// Read an async frame with a tighter payload limit; `None` means EOF at a frame boundary.
#[cfg(feature = "tokio")]
pub async fn read_frame_async_with_limit<T: DeserializeOwned>(
    reader: &mut (impl AsyncRead + Unpin),
    max_bytes: usize,
) -> io::Result<Option<T>> {
    let mut bytes = [0u8; 4];
    match reader.read_exact(&mut bytes[..1]).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    reader.read_exact(&mut bytes[1..]).await?;
    let mut payload = vec![0u8; checked_len(bytes, max_bytes.min(MAX_FRAME_BYTES))?];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Encode and write one frame asynchronously.
#[cfg(feature = "tokio")]
pub async fn write_frame_async<T: Serialize>(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &T,
) -> io::Result<()> {
    writer.write_all(&encode_frame(value)?).await
}

/// Read one frame with a tighter payload limit; `None` means EOF at a frame boundary.
pub fn read_frame_with_limit<T: DeserializeOwned>(
    reader: &mut impl Read,
    max_bytes: usize,
) -> io::Result<Option<T>> {
    let Some(len) = read_len(reader, max_bytes.min(MAX_FRAME_BYTES))? else {
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

/// A framed response from the agent to a client.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentOutput {
    Out(Vec<u8>),
    Err(Vec<u8>),
    Exit {
        code: i32,
    },
    /// Distinguishes a requested detach from a workload exit.
    Detached,
}

pub use crate::control::LifecycleEvent;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlRequest {
    List,
    Detach { id: u64 },
    DetachAll,
}

/// The agent's answer to a [`ControlRequest`].
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

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn async_frames_share_the_sync_wire_format() {
        let value = ControlReply::Detached { id: 7 };
        let (mut sync_writer, mut async_reader) = tokio::io::duplex(128);
        sync_writer
            .write_all(&encode_frame(&value).unwrap())
            .await
            .unwrap();
        sync_writer.shutdown().await.unwrap();
        assert_eq!(
            read_frame_async(&mut async_reader).await.unwrap(),
            Some(value)
        );

        let (mut async_writer, mut sync_reader) = tokio::io::duplex(128);
        write_frame_async(&mut async_writer, &ControlReply::Done)
            .await
            .unwrap();
        async_writer.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        sync_reader.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(
            read_frame::<ControlReply>(&mut bytes.as_slice()).unwrap(),
            Some(ControlReply::Done)
        );
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn async_frames_enforce_the_callers_limit_before_reading_the_payload() {
        for (length, limit) in [
            (65_u32, 64),
            (u32::try_from(MAX_FRAME_BYTES + 1).unwrap(), usize::MAX),
        ] {
            let (mut writer, mut reader) = tokio::io::duplex(4);
            writer.write_all(&length.to_le_bytes()).await.unwrap();
            let error = read_frame_async_with_limit::<ControlReply>(&mut reader, limit)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn async_frames_reject_truncated_and_oversized_input() {
        let frame = encode_frame(&ControlReply::Done).unwrap();
        let (mut writer, mut reader) = tokio::io::duplex(128);
        writer.write_all(&frame[..frame.len() - 1]).await.unwrap();
        writer.shutdown().await.unwrap();
        assert_eq!(
            read_frame_async::<ControlReply>(&mut reader)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );

        let (mut writer, mut reader) = tokio::io::duplex(128);
        writer.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        writer.shutdown().await.unwrap();
        assert_eq!(
            read_frame_async::<ControlReply>(&mut reader)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn frame_limits_reject_the_prefix_before_reading_payload() {
        for (limit, claimed) in [(32, 33_u32), (usize::MAX, u32::MAX)] {
            let mut reader = std::io::Cursor::new(claimed.to_le_bytes());
            let error = read_frame_with_limit::<ControlReply>(&mut reader, limit).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(reader.position(), 4);
        }
        let frame = encode_frame(&ControlReply::Done).unwrap();
        let limit = frame.len() - 4;
        assert_eq!(
            read_frame_with_limit::<ControlReply>(&mut frame.as_slice(), limit).unwrap(),
            Some(ControlReply::Done)
        );
        assert_eq!(
            read_frame_with_limit::<ControlReply>(&mut [].as_slice(), limit).unwrap(),
            None
        );
    }

    #[test]
    fn plan_limit_rejects_an_oversized_plan_before_allocating() {
        let over_limit = u32::try_from(MAX_PLAN_BYTES + 1).unwrap();
        let mut reader = std::io::Cursor::new(over_limit.to_le_bytes());
        let error = read_frame_with_limit::<crate::Plan>(&mut reader, MAX_PLAN_BYTES).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(reader.position(), 4);
    }

    #[test]
    fn encoding_with_a_limit_rejects_the_payload() {
        let value = ClientInput::Keys(b"input".to_vec());
        let payload_bytes = encode_frame(&value).unwrap().len() - 4;
        let error = encode_frame_with_limit(&value, payload_bytes - 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

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
    fn round_trip_lifecycle_events() {
        for event in [
            LifecycleEvent::Diagnostic {
                bytes: b"hook output".to_vec(),
            },
            LifecycleEvent::Exit { code: 23 },
        ] {
            let mut cur = std::io::Cursor::new(encode_frame(&event).unwrap());
            assert_eq!(read_frame(&mut cur).unwrap(), Some(event));
        }
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
