//! Bounded virtio-vsock device logic used by the WASI worker and native tests.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod packet;
mod switch;

pub use packet::{HeaderError, VSOCK_HEADER_BYTES, VsockHeader};
pub use switch::*;
