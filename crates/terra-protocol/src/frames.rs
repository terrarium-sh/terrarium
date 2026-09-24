//! The framed wire protocol spoken across host/guest channels.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io::{self, Read, Write};
#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Ceiling on a frame's payload; the reader refuses a peer's length past it
/// before allocating.
const MAX_FRAME_BYTES: usize = 8 << 20;

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

struct FrameWriter {
    bytes: Vec<u8>,
    max_bytes: usize,
}

impl Write for FrameWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let len = (self.bytes.len() - 4).saturating_add(bytes.len());
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
/// `u32` LE length prefix plus Postcard.
#[allow(clippy::cast_possible_truncation)]
pub fn encode_frame<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    encode_frame_with_limit(value, MAX_FRAME_BYTES)
}

/// Encode one frame with a payload limit.
#[allow(clippy::cast_possible_truncation)]
pub fn encode_frame_with_limit<T: Serialize>(value: &T, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut frame = FrameWriter {
        bytes: vec![0; 4],
        max_bytes: max_bytes.min(MAX_FRAME_BYTES),
    };
    postcard::to_io(value, &mut frame).map_err(io::Error::other)?;
    let len = (frame.bytes.len() - 4) as u32;
    frame.bytes[..4].copy_from_slice(&len.to_le_bytes());
    Ok(frame.bytes)
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
    decode_frame_payload(&payload).map(Some)
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
    decode_frame_payload(&payload).map(Some)
}

/// Decode a complete Postcard payload, rejecting trailing bytes.
pub fn decode_frame_payload<T: DeserializeOwned>(payload: &[u8]) -> io::Result<T> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(make_oversized_error(payload.len(), MAX_FRAME_BYTES));
    }
    let (value, remaining) = postcard::take_from_bytes(payload)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if !remaining.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing frame bytes",
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn async_frames_share_the_sync_wire_format() {
        let value = 7_u8;
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
        write_frame_async(&mut async_writer, &9_u8).await.unwrap();
        async_writer.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        sync_reader.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(read_frame::<u8>(&mut bytes.as_slice()).unwrap(), Some(9));
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
            let error = read_frame_async_with_limit::<u8>(&mut reader, limit)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn async_frames_reject_truncated_and_oversized_input() {
        let frame = encode_frame(&7_u8).unwrap();
        let (mut writer, mut reader) = tokio::io::duplex(128);
        writer.write_all(&frame[..frame.len() - 1]).await.unwrap();
        writer.shutdown().await.unwrap();
        assert_eq!(
            read_frame_async::<u8>(&mut reader)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );

        let (mut writer, mut reader) = tokio::io::duplex(128);
        writer.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        writer.shutdown().await.unwrap();
        assert_eq!(
            read_frame_async::<u8>(&mut reader)
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
            let error = read_frame_with_limit::<u8>(&mut reader, limit).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(reader.position(), 4);
        }
        let frame = encode_frame(&7_u8).unwrap();
        let limit = frame.len() - 4;
        assert_eq!(
            read_frame_with_limit::<u8>(&mut frame.as_slice(), limit).unwrap(),
            Some(7)
        );
        assert_eq!(
            read_frame_with_limit::<u8>(&mut [].as_slice(), limit).unwrap(),
            None
        );
    }

    #[test]
    fn binary_frames_reject_trailing_and_malformed_payloads() {
        for payload in [&[7, 0][..], &[0x80][..]] {
            let mut frame = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
            frame.extend_from_slice(payload);
            let error = read_frame::<u64>(&mut frame.as_slice()).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn terminal_bytes_have_constant_small_overhead() {
        let bytes: Vec<u8> = (0..=255).cycle().take(65536).collect();
        let message = crate::AgentOutput::Out(bytes.clone());
        let frame = encode_frame(&message).unwrap();
        assert_eq!(frame.len(), bytes.len() + 8);
        assert_eq!(&frame[8..], bytes);
        assert_eq!(read_frame(&mut frame.as_slice()).unwrap(), Some(message));
    }

    #[test]
    fn encoding_with_a_limit_rejects_the_payload() {
        let value = "input";
        let frame = encode_frame(&value).unwrap();
        let payload_bytes = frame.len() - 4;
        assert_eq!(
            encode_frame_with_limit(&value, payload_bytes).unwrap(),
            frame
        );
        let error = encode_frame_with_limit(&value, payload_bytes - 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn refuse_oversized_frame() {
        let big = "x".repeat(MAX_FRAME_BYTES + 1);
        let err = encode_frame(&big).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    /// The reader runs as guest init, on a length its peer chose.
    #[test]
    fn refuse_absurd_client_frame_before_allocating() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&u32::MAX.to_le_bytes());
        let err = read_frame::<u8>(&mut std::io::Cursor::new(wire)).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }
}
