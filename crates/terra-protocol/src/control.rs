//! Agent connection control, lifecycle events, and the host's clock and entropy.

use serde::{Deserialize, Serialize};

/// The service selected by the first host frame on an agent connection.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentService {
    Session,
    Sync,
    Exec,
    SessionControl,
}

impl crate::Message for AgentService {
    const MAX_PAYLOAD_BYTES: usize = 64;
}

/// The byte written to a running box's stop socket; the guest receives [`AgentCommand::Stop`].
pub const STOP_SIGNAL: u8 = b'S';

pub const DEFAULT_STOP_GRACE_SECS: u64 = 30;

/// Bump when a host and a running guest agent cannot safely communicate.
pub const AGENT_PROTOCOL_VERSION: u8 = 2;

/// The first bytes the agent writes on each accepted connection.
/// `V` cannot be an escape byte because a session repaints immediately after the hello.
pub const AGENT_HELLO: [u8; 2] = [b'V', AGENT_PROTOCOL_VERSION];

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleEvent {
    AgentReady,
    Diagnostic {
        #[serde(
            serialize_with = "serde_bytes::serialize",
            deserialize_with = "crate::bounded::bytes::<_, MAX_DIAGNOSTIC_EVENT_BYTES>"
        )]
        bytes: Vec<u8>,
    },
    Exit {
        code: i32,
    },
}

impl crate::Message for LifecycleEvent {
    const MAX_PAYLOAD_BYTES: usize =
        MAX_DIAGNOSTIC_EVENT_BYTES + crate::frames::BYTE_VARIANT_OVERHEAD_BYTES;
}

pub const MAX_DIAGNOSTIC_EVENT_BYTES: usize = 64 << 10;

/// What the host sends the agent on its control stream after the boot plan and [`HostState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentCommand {
    Stop,
    /// The host's wall clock, for an agent whose clock has drifted.
    SyncClock(HostTime),
}

impl crate::Message for AgentCommand {
    const MAX_PAYLOAD_BYTES: usize = 32;
}

/// Time since the Unix epoch.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostTime {
    pub seconds: i64,
    pub nanoseconds: u32,
}

/// The host's clock and entropy for the guest, sampled when the box's agent service starts:
/// the frame after the [`crate::Plan`] on the agent control stream.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostState {
    pub time: HostTime,
    pub seed: [u8; 32],
}

impl crate::Message for HostState {
    const MAX_PAYLOAD_BYTES: usize = 64;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The extreme clock sample with any seed fits its frame.
    #[test]
    fn host_state_round_trips_at_its_extremes() {
        for seconds in [i64::MIN, i64::MAX] {
            let state = HostState {
                time: HostTime {
                    seconds,
                    nanoseconds: 999_999_999,
                },
                seed: [u8::MAX; 32],
            };
            let frame = crate::encode_frame(&state).unwrap();
            assert_eq!(
                crate::read_frame::<HostState>(&mut frame.as_slice()).unwrap(),
                Some(state)
            );
        }
    }

    #[test]
    fn diagnostic_limit_is_enforced_when_decoding() {
        for size in [MAX_DIAGNOSTIC_EVENT_BYTES, MAX_DIAGNOSTIC_EVENT_BYTES + 1] {
            let event = LifecycleEvent::Diagnostic {
                bytes: vec![0; size],
            };
            let encoded = crate::frames::frame_bytes(&event);
            let decoded = crate::read_frame::<LifecycleEvent>(&mut encoded.as_slice());
            assert_eq!(decoded.is_ok(), size == MAX_DIAGNOSTIC_EVENT_BYTES);
        }
    }

    #[test]
    fn agent_commands_round_trip_within_their_limit() {
        for command in [
            AgentCommand::Stop,
            AgentCommand::SyncClock(HostTime {
                seconds: i64::MIN,
                nanoseconds: u32::MAX,
            }),
        ] {
            let frame = crate::encode_frame(&command).unwrap();
            assert_eq!(
                crate::read_frame::<AgentCommand>(&mut frame.as_slice()).unwrap(),
                Some(command)
            );
        }
    }

    #[test]
    fn service_selection_retains_its_wire_format() {
        for (service, wire) in [
            (AgentService::Session, 0),
            (AgentService::Sync, 1),
            (AgentService::Exec, 2),
            (AgentService::SessionControl, 3),
        ] {
            let frame = crate::encode_frame(&service).unwrap();
            assert_eq!(&frame[4..], &[wire]);
            assert_eq!(
                crate::read_frame::<AgentService>(&mut frame.as_slice()).unwrap(),
                Some(service),
            );
        }
    }

    #[test]
    fn service_selection_rejects_unknown_and_oversized_frames() {
        let unknown = crate::frames::frame_bytes(&"unknown_service");
        let oversized = u32::try_from(<AgentService as crate::Message>::MAX_PAYLOAD_BYTES + 1)
            .unwrap()
            .to_le_bytes();
        for mut bytes in [unknown.as_slice(), oversized.as_slice()] {
            let error = crate::read_frame::<AgentService>(&mut bytes).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn lifecycle_events_retain_their_wire_format() {
        assert_eq!(
            &crate::encode_frame(&LifecycleEvent::Exit { code: 23 }).unwrap()[4..],
            &[2, 46]
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
