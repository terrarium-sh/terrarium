//! The framed wire protocol spoken in both directions of a terminal
//! connection.

use crate::plan;
use std::io::Read;

/// Encode a payload as one or more `[tag:u8][len:u32-le][payload]` frames.
#[must_use]
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

fn new_invalid_data_error(what: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, what)
}

fn le_u64_of_first_8_bytes(payload: &[u8]) -> Option<u64> {
    payload.get(..8)?.try_into().ok().map(u64::from_le_bytes)
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

const TAG_CLIENT_KEYS: u8 = 0;
const TAG_CLIENT_RESIZE: u8 = 1;
const TAG_CLIENT_EOF: u8 = 2;

impl ClientInput {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            ClientInput::Keys(b) => tagged(TAG_CLIENT_KEYS, b),
            ClientInput::Resize { rows, cols } => {
                let mut p = Vec::with_capacity(4);
                p.extend_from_slice(&rows.to_le_bytes());
                p.extend_from_slice(&cols.to_le_bytes());
                tagged(TAG_CLIENT_RESIZE, &p)
            }
            ClientInput::Eof => tagged(TAG_CLIENT_EOF, &[]),
        }
    }

    /// Read one frame. Returns `None` on clean EOF at a frame boundary.
    pub fn read<R: Read>(r: &mut R) -> std::io::Result<Option<Self>> {
        let Some((tag, payload)) = read_tagged(r)? else {
            return Ok(None);
        };
        match tag {
            TAG_CLIENT_KEYS => Ok(Some(ClientInput::Keys(payload))),
            TAG_CLIENT_RESIZE if payload.len() == 4 => Ok(Some(ClientInput::Resize {
                rows: u16::from_le_bytes([payload[0], payload[1]]),
                cols: u16::from_le_bytes([payload[2], payload[3]]),
            })),
            TAG_CLIENT_EOF => Ok(Some(ClientInput::Eof)),
            _ => Err(new_invalid_data_error("bad client frame")),
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
    /// The session dropped this client - `terra <box> detach` - so the bare
    /// EOF that follows does not read as the box dying.
    Detached,
}

const TAG_AGENT_OUT: u8 = 0;
const TAG_AGENT_EXIT: u8 = 1;
const TAG_AGENT_ERR: u8 = 2;
const TAG_AGENT_DETACHED: u8 = 3;

impl AgentOutput {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            AgentOutput::Out(b) => tagged(TAG_AGENT_OUT, b),
            AgentOutput::Err(b) => tagged(TAG_AGENT_ERR, b),
            AgentOutput::Exit(code) => tagged(TAG_AGENT_EXIT, &code.to_le_bytes()),
            AgentOutput::Detached => tagged(TAG_AGENT_DETACHED, &[]),
        }
    }

    /// Read one frame. Returns `None` on clean EOF at a frame boundary.
    pub fn read<R: Read>(r: &mut R) -> std::io::Result<Option<Self>> {
        let Some((tag, payload)) = read_tagged(r)? else {
            return Ok(None);
        };
        match tag {
            TAG_AGENT_OUT => Ok(Some(AgentOutput::Out(payload))),
            TAG_AGENT_ERR => Ok(Some(AgentOutput::Err(payload))),
            TAG_AGENT_EXIT if payload.len() == 4 => {
                Ok(Some(AgentOutput::Exit(i32::from_le_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ]))))
            }
            TAG_AGENT_DETACHED => Ok(Some(AgentOutput::Detached)),
            _ => Err(new_invalid_data_error("bad agent frame")),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ControlRequest {
    List,
    Detach { id: u64 },
    DetachAll,
}

const TAG_SESSION_LIST: u8 = 0;
const TAG_SESSION_DETACH: u8 = 1;
const TAG_SESSION_DETACH_ALL: u8 = 2;

impl ControlRequest {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            ControlRequest::List => tagged(TAG_SESSION_LIST, &[]),
            ControlRequest::Detach { id } => tagged(TAG_SESSION_DETACH, &id.to_le_bytes()),
            ControlRequest::DetachAll => tagged(TAG_SESSION_DETACH_ALL, &[]),
        }
    }

    pub fn read<R: Read>(r: &mut R) -> std::io::Result<Option<Self>> {
        let Some((tag, payload)) = read_tagged(r)? else {
            return Ok(None);
        };
        match tag {
            TAG_SESSION_LIST => Ok(Some(ControlRequest::List)),
            TAG_SESSION_DETACH => le_u64_of_first_8_bytes(&payload)
                .ok_or_else(|| new_invalid_data_error("bad control frame"))
                .map(|id| Some(ControlRequest::Detach { id })),
            TAG_SESSION_DETACH_ALL => Ok(Some(ControlRequest::DetachAll)),
            _ => Err(new_invalid_data_error("bad control frame")),
        }
    }
}

/// The agent's answer to one [`ControlRequest`]. A `List` gets a `Client` frame
/// per attached client - `rows`/`cols` are 0 when the client reported no size -
/// and then a `Done`. A `Detach` gets `Detached` or `Missing`, and a
/// `DetachAll` one `Detached` per client dropped, then `Done`.
#[derive(Debug, PartialEq, Eq)]
pub enum ControlReply {
    Client { id: u64, rows: u16, cols: u16 },
    Done,
    Detached { id: u64 },
    Missing { id: u64 },
}

const TAG_SESSION_CLIENT: u8 = 0;
const TAG_SESSION_DONE: u8 = 1;
const TAG_SESSION_DETACHED: u8 = 2;
const TAG_SESSION_MISSING: u8 = 3;

impl ControlReply {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let payload = |id: u64, rows: u16, cols: u16| {
            let mut p = Vec::with_capacity(12);
            p.extend_from_slice(&id.to_le_bytes());
            p.extend_from_slice(&rows.to_le_bytes());
            p.extend_from_slice(&cols.to_le_bytes());
            p
        };
        match self {
            ControlReply::Client { id, rows, cols } => {
                tagged(TAG_SESSION_CLIENT, &payload(*id, *rows, *cols))
            }
            ControlReply::Done => tagged(TAG_SESSION_DONE, &[]),
            ControlReply::Detached { id } => tagged(TAG_SESSION_DETACHED, &id.to_le_bytes()),
            ControlReply::Missing { id } => tagged(TAG_SESSION_MISSING, &id.to_le_bytes()),
        }
    }

    /// Read one frame. Returns `None` on clean EOF at a frame boundary.
    pub fn read<R: Read>(r: &mut R) -> std::io::Result<Option<Self>> {
        let Some((tag, payload)) = read_tagged(r)? else {
            return Ok(None);
        };
        match tag {
            TAG_SESSION_CLIENT if payload.len() == 12 => {
                let id = le_u64_of_first_8_bytes(&payload[..8])
                    .ok_or_else(|| new_invalid_data_error("bad control frame"))?;
                Ok(Some(ControlReply::Client {
                    id,
                    rows: u16::from_le_bytes([payload[8], payload[9]]),
                    cols: u16::from_le_bytes([payload[10], payload[11]]),
                }))
            }
            TAG_SESSION_DONE => Ok(Some(ControlReply::Done)),
            TAG_SESSION_DETACHED => le_u64_of_first_8_bytes(&payload)
                .ok_or_else(|| new_invalid_data_error("bad control frame"))
                .map(|id| Some(ControlReply::Detached { id })),
            TAG_SESSION_MISSING => le_u64_of_first_8_bytes(&payload)
                .ok_or_else(|| new_invalid_data_error("bad control frame"))
                .map(|id| Some(ControlReply::Missing { id })),
            _ => Err(new_invalid_data_error("bad control frame")),
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
        let mut wire = vec![TAG_CLIENT_KEYS];
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
            AgentOutput::Detached,
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

    #[test]
    fn control_requests_round_trip() {
        for msg in [
            ControlRequest::List,
            ControlRequest::Detach { id: 0 },
            ControlRequest::Detach { id: u64::MAX },
            ControlRequest::DetachAll,
        ] {
            let encoded = msg.encode();
            let mut cur = std::io::Cursor::new(encoded);
            assert_eq!(ControlRequest::read(&mut cur).unwrap(), Some(msg));
        }
        let mut empty = std::io::Cursor::new(Vec::new());
        assert_eq!(ControlRequest::read(&mut empty).unwrap(), None);
    }

    #[test]
    fn control_replies_round_trip() {
        for msg in [
            ControlReply::Client {
                id: 7,
                rows: 40,
                cols: 120,
            },
            // 0x0 is the no-size spelling a client that reported none gets.
            ControlReply::Client {
                id: 3,
                rows: 0,
                cols: 0,
            },
            ControlReply::Done,
            ControlReply::Detached { id: 2 },
            ControlReply::Missing { id: 9 },
        ] {
            let encoded = msg.encode();
            let mut cur = std::io::Cursor::new(encoded);
            assert_eq!(ControlReply::read(&mut cur).unwrap(), Some(msg));
        }
    }

    /// A reply the agent never sends must not be read as one it does: the two
    /// detach answers share a shape, so a payload of the wrong length would
    /// otherwise silently decode as the other side of the pair.
    #[test]
    fn a_bad_control_frame_is_refused() {
        for wire in [
            vec![TAG_SESSION_CLIENT, 0, 0, 0, 0],  // Client with no payload
            vec![TAG_SESSION_MISSING, 0, 0, 0, 0], // Missing with no id
            vec![TAG_SESSION_DETACHED, 4, 0, 0, 0, 0, 0, 0, 0], // id of the wrong length
        ] {
            let err = ControlReply::read(&mut std::io::Cursor::new(wire.clone())).unwrap_err();
            assert!(
                err.to_string().contains("bad control frame"),
                "{wire:?}: {err}"
            );
        }
    }
}
