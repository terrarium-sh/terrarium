//! The framed wire protocol spoken across host/guest channels.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io::{self, Read};
#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A message framed on a terra channel, with the payload limit both ends enforce.
pub trait Message: Serialize + DeserializeOwned {
    /// The reader refuses a peer's length past this before allocating.
    const MAX_PAYLOAD_BYTES: usize;
}

/// A byte-string variant's tag and length varint, for strings under 2 MiB.
pub(crate) const BYTE_VARIANT_OVERHEAD_BYTES: usize = 4;

fn check_len<T: Message>(len: usize) -> io::Result<usize> {
    if len > T::MAX_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "framed message of {len} bytes exceeds the {}-byte limit",
                T::MAX_PAYLOAD_BYTES
            ),
        ));
    }
    Ok(len)
}

/// The payload length a frame's `u32` LE prefix declares, refused past `T`'s limit.
pub fn frame_payload_len<T: Message>(prefix: [u8; 4]) -> io::Result<usize> {
    check_len::<T>(u32::from_le_bytes(prefix) as usize)
}

/// Encode a message as the one wire shape every terra channel uses: a `u32` LE
/// length prefix plus Postcard.
pub fn encode_frame<T: Message>(value: &T) -> io::Result<Vec<u8>> {
    let mut frame = postcard::to_extend(value, vec![0; 4]).map_err(io::Error::other)?;
    let len = u32::try_from(check_len::<T>(frame.len() - 4)?).map_err(io::Error::other)?;
    frame[..4].copy_from_slice(&len.to_le_bytes());
    Ok(frame)
}

/// The one frame-reading body behind every reader; `await` is passed for async readers.
macro_rules! read_frame_body {
    ($T:ty, $reader:ident $(, $await:tt)?) => {{
        let mut bytes = [0u8; 4];
        match $reader.read_exact(&mut bytes[..1])$(.$await)? {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error),
        }
        $reader.read_exact(&mut bytes[1..])$(.$await)??;
        let len = frame_payload_len::<$T>(bytes)?;
        let mut payload = Vec::with_capacity(len);
        if $reader.take(len as u64).read_to_end(&mut payload)$(.$await)?? != len {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        decode_frame_payload(&payload).map(Some)
    }};
}

/// Read one frame; `None` on a clean EOF at a frame boundary.
pub fn read_frame<T: Message>(reader: &mut impl Read) -> io::Result<Option<T>> {
    read_frame_body!(T, reader)
}

/// Read one frame from a tokio reader; `None` on a clean EOF at a frame boundary.
#[cfg(feature = "tokio")]
pub async fn read_frame_async<T: Message>(
    reader: &mut (impl AsyncRead + Unpin),
) -> io::Result<Option<T>> {
    read_frame_body!(T, reader, await)
}

/// Read one frame from a `futures` reader; `None` on a clean EOF at a frame boundary.
#[cfg(feature = "futures-io")]
pub async fn read_frame_futures<T: Message>(
    reader: &mut (impl futures_util::io::AsyncRead + Unpin),
) -> io::Result<Option<T>> {
    use futures_util::io::AsyncReadExt as _;
    read_frame_body!(T, reader, await)
}

/// Encode and write one frame asynchronously.
#[cfg(feature = "tokio")]
pub async fn write_frame_async<T: Message>(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &T,
) -> io::Result<()> {
    writer.write_all(&encode_frame(value)?).await
}

/// Decode a complete Postcard payload, rejecting trailing bytes.
pub fn decode_frame_payload<T: Message>(payload: &[u8]) -> io::Result<T> {
    check_len::<T>(payload.len())?;
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

/// Frames any serializable value, for tests that craft malformed or foreign payloads.
#[cfg(test)]
pub(crate) fn frame_bytes(value: &impl Serialize) -> Vec<u8> {
    let payload = postcard::to_allocvec(value).unwrap();
    let mut frame = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
    frame.extend(payload);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Message for u8 {
        const MAX_PAYLOAD_BYTES: usize = 1;
    }

    impl Message for u64 {
        const MAX_PAYLOAD_BYTES: usize = 10;
    }

    /// Fits a 31-byte string after its one-byte length.
    #[derive(Debug, PartialEq, Serialize, serde::Deserialize)]
    struct Word(String);

    impl Message for Word {
        const MAX_PAYLOAD_BYTES: usize = 32;
    }

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
    async fn async_frames_enforce_the_message_limit_before_reading_the_payload() {
        for claimed in [33_u32, u32::MAX] {
            let (mut writer, mut reader) = tokio::io::duplex(4);
            writer.write_all(&claimed.to_le_bytes()).await.unwrap();
            let error = read_frame_async::<Word>(&mut reader).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn async_frames_reject_truncated_input() {
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
    }

    /// The reader runs as guest init, on a length its peer chose.
    #[test]
    fn frame_limits_reject_the_prefix_before_reading_payload() {
        for claimed in [33_u32, u32::MAX] {
            let mut reader = std::io::Cursor::new(claimed.to_le_bytes());
            let error = read_frame::<Word>(&mut reader).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(reader.position(), 4);
        }
        let word = Word("w".repeat(31));
        let frame = encode_frame(&word).unwrap();
        assert_eq!(frame.len(), 4 + Word::MAX_PAYLOAD_BYTES);
        assert_eq!(read_frame(&mut frame.as_slice()).unwrap(), Some(word));
        assert_eq!(read_frame::<Word>(&mut [].as_slice()).unwrap(), None);
    }

    /// Only an EOF before a frame's first byte is a clean end of stream.
    #[test]
    fn truncated_prefixes_and_payloads_are_unexpected_eof() {
        let frame = encode_frame(&7_u8).unwrap();
        for truncated in [&frame[..2], &frame[..frame.len() - 1]] {
            let error = read_frame::<u8>(&mut &truncated[..]).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        }
    }

    #[cfg(feature = "futures-io")]
    #[test]
    fn futures_frames_share_the_sync_wire_format_and_limits() {
        use futures_util::FutureExt as _;
        let read = |bytes: &[u8]| {
            read_frame_futures::<Word>(&mut &bytes[..])
                .now_or_never()
                .unwrap()
        };
        let word = Word("w".repeat(31));
        let frame = encode_frame(&word).unwrap();
        assert_eq!(read(&frame).unwrap(), Some(word));
        assert_eq!(read(&[]).unwrap(), None);
        for (bytes, kind) in [
            (&frame[..2], io::ErrorKind::UnexpectedEof),
            (&frame[..frame.len() - 1], io::ErrorKind::UnexpectedEof),
            (&33_u32.to_le_bytes()[..], io::ErrorKind::InvalidData),
        ] {
            assert_eq!(read(bytes).unwrap_err().kind(), kind);
        }
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
    fn encoding_enforces_the_message_limit() {
        let error = encode_frame(&Word("w".repeat(32))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds"), "{error}");
    }
}
