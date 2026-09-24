//! Agent connection control, lifecycle events, and clock updates.

use serde::{Deserialize, Serialize};

/// The service selected by the first host frame on an agent connection.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentService {
    Session,
    Sync,
    Exec,
    SessionControl,
}

pub const MAX_SERVICE_FRAME_BYTES: usize = 64;

pub const STOP_SIGNAL: u8 = b'S';

pub const DEFAULT_STOP_GRACE_SECS: u64 = 30;

/// Bump when a host and a running guest agent cannot safely communicate.
pub const AGENT_PROTOCOL_VERSION: u8 = 3;

pub const AGENT_READY_NOTIFICATION: u8 = b'R';

/// The first bytes the agent writes on each accepted connection.
/// `V` cannot be an escape byte because a session repaints immediately after the hello.
pub const AGENT_HELLO: [u8; 2] = [b'V', AGENT_PROTOCOL_VERSION];

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleEvent {
    AgentReady,
    Diagnostic {
        #[serde(deserialize_with = "deserialize_diagnostic")]
        bytes: Vec<u8>,
    },
    Exit {
        code: i32,
    },
}

pub const MAX_DIAGNOSTIC_EVENT_BYTES: usize = 64 << 10;
pub const MAX_DIAGNOSTIC_FRAME_BYTES: usize = MAX_DIAGNOSTIC_EVENT_BYTES + 4;

fn deserialize_diagnostic<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    use serde::{Deserialize as _, de::Error as _};
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    if bytes.len() > MAX_DIAGNOSTIC_EVENT_BYTES {
        return Err(D::Error::custom("diagnostic exceeds the 65536-byte limit"));
    }
    Ok(bytes)
}

pub const CLOCK_SYNC: u8 = b'T';
pub const CLOCK_SYNC_BYTES: usize = 13;

#[must_use]
pub fn encode_clock_sync(seconds: i64, nanoseconds: u32) -> [u8; CLOCK_SYNC_BYTES] {
    let mut bytes = [0; CLOCK_SYNC_BYTES];
    bytes[0] = CLOCK_SYNC;
    bytes[1..9].copy_from_slice(&seconds.to_le_bytes());
    bytes[9..13].copy_from_slice(&nanoseconds.to_le_bytes());
    bytes
}

#[must_use]
pub fn decode_clock_sync(bytes: &[u8]) -> Option<(i64, u32)> {
    if bytes.len() != CLOCK_SYNC_BYTES || bytes[0] != CLOCK_SYNC {
        return None;
    }
    let seconds = i64::from_le_bytes(bytes[1..9].try_into().ok()?);
    let nanoseconds = u32::from_le_bytes(bytes[9..13].try_into().ok()?);
    (nanoseconds < 1_000_000_000).then_some((seconds, nanoseconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_limit_is_enforced_when_decoding() {
        for size in [MAX_DIAGNOSTIC_EVENT_BYTES, MAX_DIAGNOSTIC_EVENT_BYTES + 1] {
            let event = LifecycleEvent::Diagnostic {
                bytes: vec![0; size],
            };
            let encoded = crate::encode_frame(&event).unwrap();
            let decoded = crate::read_frame::<LifecycleEvent>(&mut encoded.as_slice());
            assert_eq!(decoded.is_ok(), size == MAX_DIAGNOSTIC_EVENT_BYTES);
        }
    }

    #[test]
    fn clock_update_is_fixed_size_and_rejects_invalid_nanoseconds() {
        let update = encode_clock_sync(-1, 999_999_999);
        assert_eq!(decode_clock_sync(&update), Some((-1, 999_999_999)));
        let mut invalid = update;
        invalid[9..13].copy_from_slice(&1_000_000_000_u32.to_le_bytes());
        assert_eq!(decode_clock_sync(&invalid), None);
    }

    #[test]
    fn service_selection_retains_its_wire_format() {
        for (service, wire) in [
            (AgentService::Session, "\"session\""),
            (AgentService::Sync, "\"sync\""),
            (AgentService::Exec, "\"exec\""),
            (AgentService::SessionControl, "\"session_control\""),
        ] {
            let frame = crate::encode_frame(&service).unwrap();
            assert_eq!(&frame[4..], wire.as_bytes());
            assert_eq!(
                crate::read_frame_with_limit::<AgentService>(
                    &mut frame.as_slice(),
                    MAX_SERVICE_FRAME_BYTES,
                )
                .unwrap(),
                Some(service),
            );
        }
        assert_eq!(AGENT_HELLO, [b'V', AGENT_PROTOCOL_VERSION]);
    }

    #[test]
    fn service_selection_rejects_unknown_and_oversized_frames() {
        let unknown = crate::encode_frame(&"unknown_service").unwrap();
        let oversized = u32::try_from(MAX_SERVICE_FRAME_BYTES + 1)
            .unwrap()
            .to_le_bytes();
        for mut bytes in [unknown.as_slice(), oversized.as_slice()] {
            let error =
                crate::read_frame_with_limit::<AgentService>(&mut bytes, MAX_SERVICE_FRAME_BYTES)
                    .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn lifecycle_events_retain_their_wire_format() {
        assert_eq!(
            serde_json::to_string(&LifecycleEvent::Exit { code: 23 }).unwrap(),
            "{\"Exit\":{\"code\":23}}"
        );
    }
    #[test]
    fn round_trip_lifecycle_events() {
        for event in [
            LifecycleEvent::AgentReady,
            LifecycleEvent::Diagnostic {
                bytes: b"hook output".to_vec(),
            },
            LifecycleEvent::Exit { code: 23 },
        ] {
            let mut cur = std::io::Cursor::new(crate::encode_frame(&event).unwrap());
            assert_eq!(crate::read_frame(&mut cur).unwrap(), Some(event));
        }
    }
}
