#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use terra_protocol::{AgentOutput, ClientInput, ControlReply, ControlRequest, read_frame};

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) {
    let _ = read_frame::<T>(&mut Cursor::new(bytes));
}

fn decode_broker<T>(mut bytes: &[u8])
where
    T: serde::de::DeserializeOwned + serde::Serialize + PartialEq,
{
    use terra_protocol::network::MAX_NETWORK_FRAME_BYTES;
    while let Ok(Some(message)) =
        terra_protocol::read_frame_with_limit::<T>(&mut bytes, MAX_NETWORK_FRAME_BYTES)
    {
        let encoded = terra_protocol::encode_frame_with_limit(&message, MAX_NETWORK_FRAME_BYTES);
        assert!(encoded.is_ok());
        if let Ok(frame) = encoded {
            let mut remaining = frame.as_slice();
            assert!(
                terra_protocol::read_frame_with_limit::<T>(&mut remaining, MAX_NETWORK_FRAME_BYTES)
                    .is_ok_and(|decoded| decoded == Some(message))
            );
            assert_eq!(remaining, []);
        }
    }
}

fn decode_agent(bytes: &[u8]) {
    let _ = terra_protocol::read_frame_with_limit::<terra_protocol::AgentService>(
        &mut Cursor::new(bytes),
        terra_protocol::MAX_SERVICE_FRAME_BYTES,
    );
    let _ = terra_protocol::decode_clock_sync(bytes);
    let events = terra_agent_component::read_lifecycle_frames_for_fuzzing(bytes);
    assert!(events.len() * 5 <= bytes.len());
    for event in events {
        if let terra_protocol::control::LifecycleEvent::Diagnostic { bytes } = event {
            assert!(bytes.len() <= terra_protocol::MAX_DIAGNOSTIC_EVENT_BYTES);
        }
    }
    let mut plan_bytes = bytes;
    if let Ok(Some(boot_plan)) = terra_protocol::read_frame_with_limit::<terra_protocol::BootPlan>(
        &mut plan_bytes,
        terra_protocol::MAX_PLAN_BYTES,
    ) {
        let _ = boot_plan.validate_protocol_versions();
    }
    if let Some(frame) = terra_runtime::component::agent::enrich_boot_plan_for_fuzzing(bytes) {
        let mut frame_bytes = frame.as_slice();
        let decoded = terra_protocol::read_frame_with_limit::<terra_protocol::BootPlan>(
            &mut frame_bytes,
            terra_protocol::MAX_PLAN_BYTES,
        );
        assert!(decoded.is_ok_and(|boot_plan| {
            boot_plan.is_some_and(|boot_plan| boot_plan.validate_protocol_versions().is_ok())
        }));
        assert_eq!(frame_bytes, []);
    }
}

fuzz_target!(|bytes: &[u8]| {
    decode_agent(bytes);
    decode::<terra_protocol::Plan>(bytes);
    decode::<terra_protocol::SyncRequest>(bytes);
    decode::<terra_protocol::SyncReply>(bytes);
    decode::<terra_protocol::ExecRequest>(bytes);
    decode::<terra_protocol::control::LifecycleEvent>(bytes);
    decode::<ClientInput>(bytes);
    decode::<AgentOutput>(bytes);
    decode::<ControlRequest>(bytes);
    decode::<ControlReply>(bytes);
    decode_broker::<terra_protocol::network::Open>(bytes);
    decode_broker::<Result<terra_protocol::network::Opened, terra_protocol::network::Error>>(bytes);
    decode_broker::<terra_protocol::network::TcpEvent>(bytes);
    decode_broker::<terra_protocol::network::UdpRequest>(bytes);
    decode_broker::<terra_protocol::network::UdpReply>(bytes);
});
