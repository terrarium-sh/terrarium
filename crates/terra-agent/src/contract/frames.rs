//! The framed wire protocol spoken in both directions of a terminal
//! connection.

use crate::plan;
use std::io::Read;

/// Encode a payload as one or more `[tag:u8][len:u32-le][payload]` frames.
fn tagged(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    let mut frame = |chunk: &[u8]| {
        out.push(tag);
        // Chunked to MAX_FRAME, far below what the header carries.
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        out.extend_from_slice(chunk);
    };
    if payload.is_empty() {
        frame(&[]);
    } else {
        payload.chunks(plan::MAX_FRAME).for_each(frame);
    }
    out
}

/// Read one tagged frame; `None` on a clean EOF at a frame boundary.
fn read_tagged<R: Read>(r: &mut R) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; 5];
    match r.read_exact(&mut head) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if len > plan::MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "frame of {len} bytes exceeds the {}-byte limit",
                plan::MAX_FRAME
            ),
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some((head[0], payload)))
}

/// A framed message from a client.
#[derive(Debug, PartialEq, Eq)]
pub enum ClientInput {
    Keys(Vec<u8>),
    Resize {
        rows: u16,
        cols: u16,
    },
    /// This client's stdin has ended.
    Eof,
}

const TAG_KEYS: u8 = 0;
const TAG_RESIZE: u8 = 1;
const TAG_EOF: u8 = 2;

impl ClientInput {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            ClientInput::Keys(b) => tagged(TAG_KEYS, b),
            ClientInput::Resize { rows, cols } => {
                let mut p = Vec::with_capacity(4);
                p.extend_from_slice(&rows.to_le_bytes());
                p.extend_from_slice(&cols.to_le_bytes());
                tagged(TAG_RESIZE, &p)
            }
            ClientInput::Eof => tagged(TAG_EOF, &[]),
        }
    }

    /// Read one frame. Returns `None` on clean EOF at a frame boundary.
    pub fn read<R: Read>(r: &mut R) -> std::io::Result<Option<Self>> {
        let Some((tag, payload)) = read_tagged(r)? else {
            return Ok(None);
        };
        match tag {
            TAG_KEYS => Ok(Some(ClientInput::Keys(payload))),
            TAG_RESIZE if payload.len() == 4 => Ok(Some(ClientInput::Resize {
                rows: u16::from_le_bytes([payload[0], payload[1]]),
                cols: u16::from_le_bytes([payload[2], payload[3]]),
            })),
            TAG_EOF => Ok(Some(ClientInput::Eof)),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad client frame",
            )),
        }
    }
}

/// A framed message from the agent to one client - down a `terra exec` and
/// down an attached session alike.
///
/// Framed rather than raw because the status the command or the workload
/// ended with has to come back, and the vsock proxy carries no half-close to
/// mark the end with.
#[derive(Debug, PartialEq, Eq)]
pub enum AgentOutput {
    Out(Vec<u8>),
    Err(Vec<u8>),
    /// The last frame either connection sends: an exec's command status, or the
    /// status the box's workload ended with.
    Exit(i32),
}

const TAG_OUT: u8 = 0;
const TAG_EXIT: u8 = 1;
const TAG_ERR: u8 = 2;

impl AgentOutput {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            AgentOutput::Out(b) => tagged(TAG_OUT, b),
            AgentOutput::Err(b) => tagged(TAG_ERR, b),
            AgentOutput::Exit(code) => tagged(TAG_EXIT, &code.to_le_bytes()),
        }
    }

    /// Read one frame. Returns `None` on clean EOF at a frame boundary.
    pub fn read<R: Read>(r: &mut R) -> std::io::Result<Option<Self>> {
        let Some((tag, payload)) = read_tagged(r)? else {
            return Ok(None);
        };
        match tag {
            TAG_OUT => Ok(Some(AgentOutput::Out(payload))),
            TAG_ERR => Ok(Some(AgentOutput::Err(payload))),
            TAG_EXIT if payload.len() == 4 => Ok(Some(AgentOutput::Exit(i32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ])))),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad agent frame",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_input_frames_round_trip() {
        for msg in [
            ClientInput::Keys(b"ls -la\n".to_vec()),
            ClientInput::Keys(vec![]),
            ClientInput::Resize {
                rows: 40,
                cols: 120,
            },
            ClientInput::Eof,
        ] {
            let encoded = msg.encode();
            let mut cur = std::io::Cursor::new(encoded);
            assert_eq!(ClientInput::read(&mut cur).unwrap(), Some(msg));
        }
        // Clean EOF at a boundary -> None.
        let mut empty = std::io::Cursor::new(Vec::new());
        assert_eq!(ClientInput::read(&mut empty).unwrap(), None);
    }

    /// A stream payload past the frame ceiling is split into several valid
    /// frames - the encoder must never write a length its header cannot carry
    /// or its reader would refuse.
    #[test]
    fn an_oversized_stream_payload_is_split_not_lied_about() {
        let big = vec![b'x'; plan::MAX_FRAME + 3];
        let mut cur = std::io::Cursor::new(ClientInput::Keys(big.clone()).encode());
        let mut got = Vec::new();
        while let Some(msg) = ClientInput::read(&mut cur).unwrap() {
            let ClientInput::Keys(k) = msg else {
                panic!("a split frame changed its tag: {msg:?}")
            };
            got.extend_from_slice(&k);
        }
        assert_eq!(got, big);
    }

    /// The reader runs as guest init, on a length its peer chose.
    #[test]
    fn an_absurd_client_frame_is_refused_before_allocating() {
        let mut wire = vec![TAG_KEYS];
        wire.extend_from_slice(&u32::MAX.to_le_bytes());
        let err = ClientInput::read(&mut std::io::Cursor::new(wire)).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    /// An exec's output and its exit status share one stream, so the status has
    /// to survive whatever the command printed - a `\x01` in the output must not
    /// be read as an exit frame, and a negative code must round-trip.
    #[test]
    fn exec_frames_round_trip_output_and_exit_status() {
        for msg in [
            AgentOutput::Out(b"\x00\x01\x02 arbitrary \xff bytes\n".to_vec()),
            AgentOutput::Out(vec![]),
            AgentOutput::Err(b"warning: \x01\x02\n".to_vec()),
            AgentOutput::Exit(0),
            AgentOutput::Exit(127),
            AgentOutput::Exit(-1),
        ] {
            let mut cur = std::io::Cursor::new(msg.encode());
            assert_eq!(AgentOutput::read(&mut cur).unwrap(), Some(msg));
        }
        // The two enums number their tags independently - the direction decides
        // the type, so nothing ever tells them apart from the bytes alone.
        assert_eq!(AgentOutput::Err(vec![]).encode(), ClientInput::Eof.encode());
        // A stream that stops without an exit frame is the box going away, not a
        // command that succeeded.
        let mut empty = std::io::Cursor::new(Vec::new());
        assert_eq!(AgentOutput::read(&mut empty).unwrap(), None);
    }
}
