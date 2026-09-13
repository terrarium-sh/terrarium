//! Agent channel identifiers, lifecycle events, and clock updates.

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LifecycleEvent {
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

pub const AGENT_VSOCK_PORT: u32 = 6000;
pub const CONTROL_VSOCK_PORT: u32 = 6001;
pub const DIAGNOSTIC_VSOCK_PORT: u32 = 6002;
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
}
