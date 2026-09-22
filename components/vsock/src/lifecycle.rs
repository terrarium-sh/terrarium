use crate::exports::terra::vsock::api::{ControlResult, DiagnosticResult, Error};
use serde::de::DeserializeOwned;
use terra_protocol::control::LifecycleEvent;

const MAX_CONTROL_BYTES: usize = 1 << 20;
const MAX_DIAGNOSTIC_BYTES: usize = 65536;
const MAX_MESSAGES: usize = 16;

fn decode_frame<T: DeserializeOwned>(
    bytes: &[u8],
    max: usize,
) -> Result<Option<(T, usize)>, Error> {
    let Some(prefix) = bytes.get(..4) else {
        return Ok(None);
    };
    let length = u32::from_le_bytes(prefix.try_into().map_err(|_| Error::Malformed)?) as usize;
    if length > max {
        return Err(Error::Malformed);
    }
    let Some(payload) = bytes.get(4..4 + length) else {
        return Ok(None);
    };
    serde_json::from_slice(payload)
        .map(|value| Some((value, length + 4)))
        .map_err(|_| Error::Malformed)
}

pub fn decode_control(bytes: &[u8]) -> Result<ControlResult, Error> {
    if bytes.len() > MAX_CONTROL_BYTES {
        return Err(Error::Malformed);
    }
    let mut result = ControlResult {
        consumed: 0,
        exit_code: None,
        agent_ready: false,
    };
    for _ in 0..MAX_MESSAGES {
        let unread = &bytes[result.consumed as usize..];
        let Some((event, consumed)) =
            decode_frame::<LifecycleEvent>(unread, MAX_CONTROL_BYTES - 4)?
        else {
            break;
        };
        result.consumed += u32::try_from(consumed).map_err(|_| Error::Malformed)?;
        match event {
            LifecycleEvent::Exit { code } => {
                result.exit_code = Some(code);
                return Ok(result);
            }
            LifecycleEvent::AgentReady => result.agent_ready = true,
            LifecycleEvent::Diagnostic { .. } => {}
        }
    }
    Ok(result)
}

pub fn decode_diagnostics(bytes: &[u8]) -> Result<DiagnosticResult, Error> {
    if bytes.len() > MAX_DIAGNOSTIC_BYTES + 4 {
        return Err(Error::Malformed);
    }
    let mut result = DiagnosticResult {
        consumed: 0,
        output: Vec::new(),
    };
    for _ in 0..MAX_MESSAGES {
        let Some((event, consumed)) = decode_frame::<LifecycleEvent>(
            &bytes[result.consumed as usize..],
            MAX_DIAGNOSTIC_BYTES,
        )?
        else {
            break;
        };
        match event {
            LifecycleEvent::Diagnostic { bytes } => result.output.extend_from_slice(&bytes),
            LifecycleEvent::Exit { .. } | LifecycleEvent::AgentReady => {
                return Err(Error::Malformed);
            }
        }
        result.consumed += u32::try_from(consumed).map_err(|_| Error::Malformed)?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_survives_fragmentation_and_precedes_exit() {
        let ready = frame(&LifecycleEvent::AgentReady);
        for end in 0..ready.len() {
            let partial = decode_control(&ready[..end]).unwrap();
            assert!(!partial.agent_ready);
            assert_eq!(partial.consumed, 0);
        }
        let mut bytes = ready;
        bytes.extend_from_slice(&frame(&LifecycleEvent::Exit { code: 7 }));
        let result = decode_control(&bytes).unwrap();
        assert!(result.agent_ready);
        assert_eq!(result.exit_code, Some(7));
        assert_eq!(result.consumed as usize, bytes.len());
        assert!(decode_diagnostics(&frame(&LifecycleEvent::AgentReady)).is_err());
    }

    fn frame(event: &impl serde::Serialize) -> Vec<u8> {
        let payload = serde_json::to_vec(event).unwrap();
        let mut bytes = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
        bytes.extend_from_slice(&payload);
        bytes
    }

    #[test]
    fn fragmented_lifecycle_frames_preserve_the_cursor() {
        let bytes = frame(&LifecycleEvent::Exit { code: -7 });
        for end in 0..bytes.len() {
            let result = decode_control(&bytes[..end]).unwrap();
            assert_eq!(result.consumed, 0);
            assert_eq!(result.exit_code, None);
        }
        let result = decode_control(&bytes).unwrap();
        assert_eq!(result.consumed as usize, bytes.len());
        assert_eq!(result.exit_code, Some(-7));
        assert!(decode_control(&frame(&-7)).is_err());
    }

    #[test]
    fn diagnostic_batches_preserve_partial_tail_and_reject_exit_events() {
        let first = frame(&LifecycleEvent::Diagnostic {
            bytes: b"hook output".to_vec(),
        });
        let mut bytes = first.clone();
        bytes.extend_from_slice(&first[..first.len() - 1]);
        let result = decode_diagnostics(&bytes).unwrap();
        assert_eq!(result.consumed as usize, first.len());
        assert_eq!(result.output, b"hook output");
        assert!(decode_diagnostics(&frame(&LifecycleEvent::Exit { code: 0 })).is_err());
        assert!(decode_diagnostics(&u32::MAX.to_le_bytes()).is_err());
        assert!(decode_control(&u32::MAX.to_le_bytes()).is_err());
        assert!(decode_control(&[1, 0, 0, 0, b'{']).is_err());
    }
}
