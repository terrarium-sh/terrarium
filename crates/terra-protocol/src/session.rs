//! Terminal, exec, and session-management messages.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;

/// Terminal bytes one [`ClientInput::Keys`], [`AgentOutput::Out`] or [`AgentOutput::Err`] carries at most.
pub const MAX_TERMINAL_CHUNK_BYTES: usize = 64 << 10;
/// Clients one [`SessionControlReply::Clients`] lists at most.
const MAX_SESSION_CLIENTS: usize = 1024;
/// A [`SessionClient`] at its largest: a ten-byte id, the option tag and two three-byte sizes.
const MAX_SESSION_CLIENT_BYTES: usize = 17;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TermSize {
    pub rows: u16,
    pub cols: u16,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientInput {
    Keys(#[serde(with = "serde_bytes")] Vec<u8>),
    Resize(TermSize),
    Eof,
}

impl crate::Message for ClientInput {
    const MAX_PAYLOAD_BYTES: usize =
        MAX_TERMINAL_CHUNK_BYTES + crate::frames::BYTE_VARIANT_OVERHEAD_BYTES;
}

/// A framed response from the agent to a terminal or exec client.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentOutput {
    Out(#[serde(with = "serde_bytes")] Vec<u8>),
    Err(#[serde(with = "serde_bytes")] Vec<u8>),
    Exit {
        code: i32,
    },
    /// Distinguishes a requested detach from a workload exit.
    Detached,
}

impl crate::Message for AgentOutput {
    const MAX_PAYLOAD_BYTES: usize =
        MAX_TERMINAL_CHUNK_BYTES + crate::frames::BYTE_VARIANT_OVERHEAD_BYTES;
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionControlRequest {
    List,
    Detach { id: u64 },
    DetachAll,
}

impl crate::Message for SessionControlRequest {
    const MAX_PAYLOAD_BYTES: usize = 16;
}

/// One attached client in the answer to [`SessionControlRequest::List`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionClient {
    pub id: u64,
    pub reported_size: Option<TermSize>,
}

/// How a [`SessionControlRequest::Detach`] went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetachOutcome {
    Detached,
    /// No client with that id was attached.
    Missing,
}

/// The agent's answer to a [`SessionControlRequest`]. The variant tag keeps one request's
/// reply from decoding as another's, as an empty listing and a detach would untagged.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionControlReply {
    /// The answer to [`SessionControlRequest::List`].
    Clients(
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_SESSION_CLIENTS>")]
        Vec<SessionClient>,
    ),
    /// The answer to [`SessionControlRequest::Detach`].
    Detach(DetachOutcome),
    /// The answer to [`SessionControlRequest::DetachAll`]: how many clients it detached.
    DetachedAll(u64),
}

impl crate::Message for SessionControlReply {
    /// The variant tag, the list's two-byte length varint, then every client at its largest.
    const MAX_PAYLOAD_BYTES: usize = 1 + 2 + MAX_SESSION_CLIENTS * MAX_SESSION_CLIENT_BYTES;
}

/// `as_root` is the `--root` flag, and the agent resolves the command identity.
/// `tty: Some(size)` asks for a PTY at that size; `None` uses pipes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecRequest {
    #[serde(deserialize_with = "deserialize_argv")]
    pub argv: Vec<String>,
    pub as_root: bool,
    pub tty: Option<TermSize>,
    pub workdir: Option<String>,
    pub env: BTreeMap<String, String>,
}

impl crate::Message for ExecRequest {
    /// The same budget a boot plan gives the workload's command and environment.
    const MAX_PAYLOAD_BYTES: usize = crate::MAX_PLAN_BYTES;
}

fn deserialize_argv<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let argv = Vec::<String>::deserialize(deserializer)?;
    if argv.is_empty() {
        return Err(D::Error::custom("exec request has no command"));
    }
    if argv.iter().any(|arg| arg.contains('\0')) {
        return Err(D::Error::custom(
            "exec request arguments cannot contain NUL bytes",
        ));
    }
    Ok(argv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode_frame, read_frame};

    #[test]
    fn terminal_and_session_messages_retain_their_wire_format() {
        assert_eq!(&encode_frame(&ClientInput::Eof).unwrap()[4..], &[2]);
        assert_eq!(
            &encode_frame(&AgentOutput::Exit { code: -1 }).unwrap()[4..],
            &[2, 1]
        );
        assert_eq!(
            &encode_frame(&SessionControlRequest::Detach { id: 7 }).unwrap()[4..],
            &[1, 7]
        );
        assert_eq!(
            &encode_frame(&SessionControlReply::Clients(vec![SessionClient {
                id: 7,
                reported_size: Some(TermSize {
                    rows: 40,
                    cols: 120
                }),
            }]))
            .unwrap()[4..],
            &[0, 1, 7, 1, 40, 120]
        );
        assert_eq!(
            &encode_frame(&SessionControlReply::Detach(DetachOutcome::Missing)).unwrap()[4..],
            &[1, 1]
        );
        assert_eq!(
            &encode_frame(&SessionControlReply::DetachedAll(5)).unwrap()[4..],
            &[2, 5]
        );
    }

    #[test]
    fn exec_requests_round_trip_optional_fields() {
        for workdir in [None, Some("/work".into())] {
            for env in [
                BTreeMap::new(),
                BTreeMap::from([("KEY".into(), "value".into())]),
            ] {
                let request = ExecRequest {
                    argv: vec!["echo".into(), "ok".into()],
                    as_root: false,
                    tty: None,
                    workdir: workdir.clone(),
                    env,
                };
                let frame = encode_frame(&request).unwrap();
                assert_eq!(read_frame(&mut frame.as_slice()).unwrap(), Some(request));
            }
        }
    }

    #[test]
    fn reject_invalid_exec_requests() {
        for argv in [vec![], vec!["/bin/sh".into(), "bad\0arg".into()]] {
            let request = ExecRequest {
                argv,
                as_root: false,
                tty: None,
                workdir: None,
                env: BTreeMap::new(),
            };
            let frame = encode_frame(&request).unwrap();
            assert!(read_frame::<ExecRequest>(&mut frame.as_slice()).is_err());
        }
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

    /// Arbitrary binary output and negative exit codes retain their distinct framed messages.
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
            SessionControlRequest::List,
            SessionControlRequest::Detach { id: 0 },
            SessionControlRequest::Detach { id: u64::MAX },
            SessionControlRequest::DetachAll,
        ] {
            let encoded = encode_frame(&msg).unwrap();
            let mut cur = std::io::Cursor::new(encoded);
            assert_eq!(read_frame(&mut cur).unwrap(), Some(msg));
        }
        let mut empty = std::io::Cursor::new(Vec::new());
        assert_eq!(
            read_frame::<SessionControlRequest>(&mut empty).unwrap(),
            None
        );
    }

    /// Every control reply round-trips at its largest, and a listing past the client limit is
    /// refused.
    #[test]
    fn control_replies_round_trip_at_their_limits() {
        let largest = SessionClient {
            id: u64::MAX,
            reported_size: Some(TermSize {
                rows: u16::MAX,
                cols: u16::MAX,
            }),
        };
        let full = SessionControlReply::Clients(vec![largest; MAX_SESSION_CLIENTS]);
        let frame = encode_frame(&full).unwrap();
        assert_eq!(
            frame.len() - 4,
            <SessionControlReply as crate::Message>::MAX_PAYLOAD_BYTES
        );
        assert_eq!(read_frame(&mut frame.as_slice()).unwrap(), Some(full));
        let over = crate::frames::frame_bytes(&SessionControlReply::Clients(vec![
            SessionClient {
                id: 0,
                reported_size: None,
            };
            MAX_SESSION_CLIENTS
                + 1
        ]));
        assert!(read_frame::<SessionControlReply>(&mut over.as_slice()).is_err());
        for reply in [
            SessionControlReply::Clients(Vec::new()),
            SessionControlReply::Detach(DetachOutcome::Detached),
            SessionControlReply::Detach(DetachOutcome::Missing),
            SessionControlReply::DetachedAll(0),
            SessionControlReply::DetachedAll(u64::MAX),
        ] {
            let frame = encode_frame(&reply).unwrap();
            assert_eq!(read_frame(&mut frame.as_slice()).unwrap(), Some(reply));
        }
    }

    /// An empty listing, a detach and a zero detach count encode differently, so a reply to the
    /// wrong request never reads as this one's.
    #[test]
    fn replies_to_different_requests_never_share_bytes() {
        let replies = [
            SessionControlReply::Clients(Vec::new()),
            SessionControlReply::Detach(DetachOutcome::Detached),
            SessionControlReply::Detach(DetachOutcome::Missing),
            SessionControlReply::DetachedAll(0),
        ];
        let frames: std::collections::BTreeSet<_> = replies
            .iter()
            .map(|reply| encode_frame(reply).unwrap())
            .collect();
        assert_eq!(frames.len(), replies.len());
    }

    #[test]
    fn refuse_bad_control_frame() {
        let mut bad = Vec::new();
        bad.extend_from_slice(&4u32.to_le_bytes());
        bad.extend_from_slice(b"nope");
        let err = read_frame::<SessionControlReply>(&mut std::io::Cursor::new(bad)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
