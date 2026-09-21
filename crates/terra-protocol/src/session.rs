//! Terminal, exec, and session-management messages.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TermSize {
    pub rows: u16,
    pub cols: u16,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientInput {
    Keys(Vec<u8>),
    Resize(TermSize),
    Eof,
}

/// A framed response from the agent to a terminal or exec client.
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

/// `as_root` is the `--root` flag, and the agent resolves the command identity.
/// `tty: Some(size)` asks for a PTY at that size; `None` uses pipes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecRequest {
    #[serde(deserialize_with = "deserialize_argv")]
    pub argv: Vec<String>,
    pub as_root: bool,
    pub tty: Option<TermSize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
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
        assert_eq!(serde_json::to_string(&ClientInput::Eof).unwrap(), "\"Eof\"");
        assert_eq!(
            serde_json::to_string(&AgentOutput::Exit { code: -1 }).unwrap(),
            "{\"Exit\":{\"code\":-1}}"
        );
        assert_eq!(
            serde_json::to_string(&ControlRequest::Detach { id: 7 }).unwrap(),
            "{\"Detach\":{\"id\":7}}"
        );
        assert_eq!(
            serde_json::to_string(&ControlReply::Client {
                id: 7,
                size: Some(TermSize {
                    rows: 40,
                    cols: 120
                }),
            })
            .unwrap(),
            "{\"Client\":{\"id\":7,\"size\":{\"rows\":40,\"cols\":120}}}"
        );
        assert_eq!(
            serde_json::to_string(&ExecRequest {
                argv: vec!["echo".into(), "ok".into()],
                as_root: false,
                tty: None,
                workdir: None,
                env: BTreeMap::new(),
            })
            .unwrap(),
            "{\"argv\":[\"echo\",\"ok\"],\"as_root\":false,\"tty\":null}"
        );
    }

    #[test]
    fn reject_invalid_exec_requests() {
        for argv in [
            serde_json::json!([]),
            serde_json::json!(["/bin/sh", "bad\0arg"]),
        ] {
            assert!(
                serde_json::from_value::<ExecRequest>(serde_json::json!({
                    "argv": argv,
                    "as_root": false,
                    "tty": null
                }))
                .is_err()
            );
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
