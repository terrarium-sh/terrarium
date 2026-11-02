//! Host/guest messages, launch plans, and control-channel wire types.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod application;
mod bounded;
mod control;
pub mod dns;
mod frames;
pub mod guest_image;
pub mod guest_root;
pub mod kernel_abi;
#[cfg(feature = "mux")]
pub mod mux;
pub mod network;
pub mod network_control;
#[cfg(feature = "packed-image")]
pub mod packed_image;
mod plan;
mod session;
pub mod socket;
mod sync;
pub mod vsock;

pub use control::{
    AGENT_HELLO, AGENT_PROTOCOL_VERSION, AgentCommand, AgentService, DEFAULT_STOP_GRACE_SECS,
    HostState, HostTime, LifecycleEvent, MAX_DIAGNOSTIC_EVENT_BYTES, STOP_SIGNAL,
};
#[cfg(feature = "futures-io")]
pub use frames::read_frame_futures;
pub use frames::{Message, decode_frame_payload, encode_frame, frame_payload_len, read_frame};
#[cfg(feature = "tokio")]
pub use frames::{read_frame_async, write_frame_async};
pub use guest_root::{WORKLOAD_HOME, WORKLOAD_ID, WORKLOAD_USER_NAME};
pub use plan::{
    KERNEL_CMDLINE, MAX_PLAN_BYTES, MAX_PUBLISHED_PORTS, Net, Plan, PlanMode, RESIZE2FS_GUEST_PATH,
    ROOT_DEVICE, RootfsMount, Share, VolumeMount, to_volume_device,
};
pub use session::{
    AgentOutput, ClientInput, DetachOutcome, ExecRequest, MAX_TERMINAL_CHUNK_BYTES, SessionClient,
    SessionControlReply, SessionControlRequest, TermSize,
};
pub use sync::{
    MAX_SYNC_FILE_BYTES, MAX_SYNC_PATH_BYTES, RootStatus, SyncEntry, SyncEntryKind, SyncReply,
    SyncRequest, sync_file_times, truncate_nanos, validate_relative_path,
};
