//! Readers for the guest's lifecycle and diagnostic mux streams.

use crate::exports::terra::agent::api::Event;
use futures_channel::{mpsc::Sender, oneshot};
use futures_io::AsyncRead;
use futures_util::{SinkExt as _, io::AsyncReadExt as _};
use terra_protocol::control::{LifecycleEvent, MAX_DIAGNOSTIC_FRAME_BYTES};

const MAX_CONTROL_PAYLOAD_BYTES: usize = (1 << 20) - 4;
pub(crate) const MAX_DIAGNOSTIC_PAYLOAD_BYTES: usize = MAX_DIAGNOSTIC_FRAME_BYTES - 4;

pub(crate) struct Diagnostic {
    pub bytes: Vec<u8>,
    /// Signalled once the host has accepted the event.
    pub delivered: Option<oneshot::Sender<()>>,
}

/// Reads one length-prefixed frame; `None` ends the stream, on EOF and on malformed input alike.
pub(crate) async fn read_event(
    stream: &mut (impl AsyncRead + Unpin),
    max_payload_bytes: usize,
) -> Option<LifecycleEvent> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).await.ok()?;
    let length = usize::try_from(u32::from_le_bytes(length))
        .ok()
        .filter(|length| *length <= max_payload_bytes)?;
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await.ok()?;
    terra_protocol::decode_frame_payload(&payload).ok()
}

pub(crate) async fn read_lifecycle(mut stream: impl AsyncRead + Unpin, mut sender: Sender<Event>) {
    while let Some(event) = read_event(&mut stream, MAX_CONTROL_PAYLOAD_BYTES).await {
        let event = match event {
            LifecycleEvent::AgentReady => Event::AgentReady,
            LifecycleEvent::Exit { code } => Event::Exit(code),
            LifecycleEvent::Diagnostic { .. } => return,
        };
        if sender.send(event).await.is_err() {
            return;
        }
    }
}

pub(crate) async fn read_diagnostics(
    mut stream: impl AsyncRead + Unpin,
    mut sender: Sender<Diagnostic>,
) {
    while let Some(LifecycleEvent::Diagnostic { bytes }) =
        read_event(&mut stream, MAX_DIAGNOSTIC_PAYLOAD_BYTES).await
    {
        if !bytes.is_empty()
            && sender
                .send(Diagnostic {
                    bytes,
                    delivered: None,
                })
                .await
                .is_err()
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_channel::mpsc;
    use futures_util::FutureExt as _;
    use std::assert_matches;

    fn frame(event: &impl serde::Serialize) -> Vec<u8> {
        terra_protocol::encode_frame(event).unwrap()
    }

    fn lifecycle_events(bytes: &[u8]) -> Vec<Event> {
        let (sender, mut receiver) = mpsc::channel(8);
        read_lifecycle(bytes, sender).now_or_never().unwrap();
        std::iter::from_fn(|| receiver.try_recv().ok()).collect()
    }

    /// Readiness and exit reach the host in wire order, and a diagnostic on the
    /// control stream ends it before any later frame is trusted.
    #[test]
    fn control_events_keep_wire_order_and_reject_diagnostics() {
        let mut bytes = frame(&LifecycleEvent::AgentReady);
        bytes.extend_from_slice(&frame(&LifecycleEvent::Exit { code: -7 }));
        let events = lifecycle_events(&bytes);
        assert_matches!(events.as_slice(), [Event::AgentReady, Event::Exit(-7)]);
        let mut bytes = frame(&LifecycleEvent::Diagnostic { bytes: vec![1] });
        bytes.extend_from_slice(&frame(&LifecycleEvent::Exit { code: 0 }));
        assert!(lifecycle_events(&bytes).is_empty());
    }

    /// The diagnostic stream forwards diagnostic frames and stops at any other kind.
    #[test]
    fn diagnostics_forward_output_and_reject_lifecycle_events() {
        let mut bytes = frame(&LifecycleEvent::Diagnostic {
            bytes: b"hook output".to_vec(),
        });
        bytes.extend_from_slice(&frame(&LifecycleEvent::Exit { code: 0 }));
        bytes.extend_from_slice(&frame(&LifecycleEvent::Diagnostic {
            bytes: b"after exit".to_vec(),
        }));
        let (sender, mut receiver) = mpsc::channel(8);
        read_diagnostics(bytes.as_slice(), sender)
            .now_or_never()
            .unwrap();
        let output: Vec<_> = std::iter::from_fn(|| receiver.try_recv().ok())
            .map(|diagnostic| diagnostic.bytes)
            .collect();
        assert_eq!(output, [b"hook output".to_vec()]);
    }

    #[test]
    fn maximum_diagnostic_fits_the_frame_budget() {
        let bytes = vec![255; terra_protocol::MAX_DIAGNOSTIC_EVENT_BYTES];
        let frame = frame(&LifecycleEvent::Diagnostic {
            bytes: bytes.clone(),
        });
        assert_eq!(frame.len(), MAX_DIAGNOSTIC_FRAME_BYTES);
        assert_eq!(
            read_event(&mut frame.as_slice(), MAX_DIAGNOSTIC_PAYLOAD_BYTES)
                .now_or_never()
                .unwrap(),
            Some(LifecycleEvent::Diagnostic { bytes })
        );
    }

    /// A guest-claimed length past the cap ends the stream before the payload is allocated.
    #[test]
    fn oversized_truncated_and_malformed_frames_end_the_stream() {
        for bytes in [
            u32::MAX.to_le_bytes().to_vec(),
            u32::try_from(MAX_CONTROL_PAYLOAD_BYTES + 1)
                .unwrap()
                .to_le_bytes()
                .to_vec(),
            frame(&LifecycleEvent::AgentReady)[..4].to_vec(),
            vec![1, 0, 0, 0, b'{'],
        ] {
            assert_eq!(
                read_event(&mut bytes.as_slice(), MAX_CONTROL_PAYLOAD_BYTES)
                    .now_or_never()
                    .unwrap(),
                None
            );
        }
    }
}
