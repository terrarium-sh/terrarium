#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use terra_protocol::{AgentOutput, ClientInput, ControlReply, ControlRequest, read_frame};

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) {
    let _ = read_frame::<T>(&mut Cursor::new(bytes));
}

fuzz_target!(|bytes: &[u8]| {
    decode::<terra_protocol::Plan>(bytes);
    decode::<terra_protocol::SyncRequest>(bytes);
    decode::<terra_protocol::SyncReply>(bytes);
    decode::<terra_protocol::ExecRequest>(bytes);
    decode::<terra_protocol::control::LifecycleEvent>(bytes);
    decode::<ClientInput>(bytes);
    decode::<AgentOutput>(bytes);
    decode::<ControlRequest>(bytes);
    decode::<ControlReply>(bytes);
});
