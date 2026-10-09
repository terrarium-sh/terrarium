//! Bounded connection and credit state for one virtio-vsock device.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod packet;
mod switch;

pub use packet::{VSOCK_HEADER_BYTES, VsockHeader};
pub use switch::*;
#[cfg(test)]
use switch::{CONTROL_RX_ALLOC, MAX_AGENT_TX_BYTES, MAX_FLOW_TX_BYTES};

#[cfg(test)]
mod tests;
