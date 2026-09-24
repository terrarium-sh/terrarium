//! Host/guest messages, launch plans, and control-channel wire types.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod control;
mod frames;
pub mod mux;
mod plan;
pub mod session;
pub mod sync;

pub use control::{
    AGENT_HELLO, AGENT_PROTOCOL_VERSION, AGENT_READY_NOTIFICATION, AgentService, CLOCK_SYNC,
    CLOCK_SYNC_BYTES, DEFAULT_STOP_GRACE_SECS, LifecycleEvent, MAX_DIAGNOSTIC_EVENT_BYTES,
    MAX_DIAGNOSTIC_FRAME_BYTES, MAX_SERVICE_FRAME_BYTES, STOP_SIGNAL, decode_clock_sync,
    encode_clock_sync,
};
pub use frames::{encode_frame, encode_frame_with_limit, read_frame, read_frame_with_limit};
#[cfg(feature = "tokio")]
pub use frames::{read_frame_async, read_frame_async_with_limit, write_frame_async};
pub use plan::{
    Disk, HostTime, KERNEL_CMDLINE, MAX_PLAN_BYTES, MAX_PLAN_HOST_STATE_BYTES, MAX_VOLUMES, Net,
    Plan, PlanMode, RECIPE_STAMP_PATH, RESIZE2FS_GUEST_PATH, ROOT_DEVICE, Share, WORKLOAD_HOME,
    WORKLOAD_ID, WORKLOAD_USER_NAME, to_volume_device,
};
pub use session::{AgentOutput, ClientInput, ControlReply, ControlRequest, ExecRequest, TermSize};
pub use sync::{
    MAX_FILE_BYTES, MAX_SYNC_ENTRIES, MAX_SYNC_ERROR_BYTES, MAX_SYNC_METADATA_BYTES,
    MAX_SYNC_PATH_BYTES, RootStatus, SYNC_TIMESTAMP_PRECISION_NANOS, SyncDirection, SyncEntry,
    SyncEntryKind, SyncManifestBudget, SyncManifestLimit, SyncReply, SyncRequest, sync_file_times,
    truncate_nanos, validate_relative_path, validate_wire_relative_path,
};
