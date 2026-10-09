//! terra-runtime integration tests, built as one binary so Wasmtime links once.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod support;

mod agent_component;
mod agent_stream;
mod agent_worker;
mod all_device_lifecycle;
mod component_grants;
mod component_imports;
mod component_streams;
mod filesystem_component;
mod native_boundary;
mod runtime_lifecycle;
mod shared_store_grants;
mod stream_relay;
mod vmm_boundary;
mod wasi_version;
