use crate::support;

use std::sync::Arc;
use std::time::Duration;

use terra_runtime::box_runtime::{BoxHost, BoxRuntime};
use terra_runtime::component::InterruptCallback;
use terra_runtime::component::agent::Agent;
use terra_runtime::component::block::backing::{BoundedDisk, DiskGrant};
use terra_runtime::component::context::DeviceContext;
use terra_runtime::component::fs::{FsHost, ShareGrant};
use terra_runtime::component::network::{HostServiceAddresses, start_test_broker};
use terra_runtime::component::vsock::streams::{FrontendStreams, StreamEndpoint};
use terra_runtime::engine::device_engine;
use terra_runtime::memory::GuestRam;
use wasmtime::component::Component;

const STATUS: u64 = 0x70;
const STATUS_RESET: [u8; 4] = 0_u32.to_le_bytes();
const STATUS_ACKNOWLEDGE: [u8; 4] = 1_u32.to_le_bytes();
const STATUS_DRIVER: [u8; 4] = 3_u32.to_le_bytes();
const MAGIC: [u8; 4] = 0x7472_6976_u32.to_le_bytes();

fn no_interrupt() -> InterruptCallback {
    Arc::new(|_| Ok(()))
}

fn component(engine: &wasmtime::Engine, bytes: &[u8]) -> Component {
    Component::new(engine, bytes).expect("test component")
}

fn reset_device(
    write: impl Fn(u64, &[u8]) -> wasmtime::Result<()>,
    read: impl Fn(u64, usize) -> wasmtime::Result<Vec<u8>>,
) {
    write(STATUS, &STATUS_ACKNOWLEDGE).expect("status acknowledge");
    write(STATUS, &STATUS_DRIVER).expect("status driver");
    write(STATUS, &STATUS_RESET).expect("status reset");
    assert_eq!(read(STATUS, 4).expect("status read"), STATUS_RESET);
    assert_eq!(read(0, 4).expect("magic read"), MAGIC);
}

fn load_components(engine: &wasmtime::Engine) -> [Component; 3] {
    let block_component = component(engine, support::artifacts::wasm::BLOCK);
    let fs_component = component(engine, support::artifacts::wasm::FS);
    let mem_component = component(engine, support::artifacts::wasm::MEM);
    [block_component, fs_component, mem_component]
}

fn start_agent(runtime: &mut BoxRuntime, stream: StreamEndpoint) -> Agent {
    let artifact = support::artifacts::trusted_artifacts().agent();
    Agent::from_trusted_artifact(
        runtime,
        stream,
        artifact,
        terra_protocol::encode_frame(&terra_protocol::BootPlan::new(
            support::artifacts::create_boot_plan(),
        ))
        .expect("plan encodes"),
        None,
        None,
        None,
    )
    .expect("agent")
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn every_device_resets_and_closes_in_one_box_runtime() {
    let engine = device_engine().expect("engine");
    let [block_component, fs_component, mem_component] = load_components(&engine);
    let ram = GuestRam::new(64 * 1024).expect("RAM");
    let root = tempfile::tempdir().expect("mount directory");
    let mount = std::fs::canonicalize(root.path()).expect("canonical mount directory");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime.initialize_mmio().expect("MMIO service");

    let block_host = terra_runtime::component::block::BlockHost::new(
        ram.clone(),
        DiskGrant::Mem(BoundedDisk::new(4096, false)),
    );
    let block = terra_runtime::component::block::register_device(
        &mut runtime,
        block_host,
        &block_component,
        false,
        no_interrupt(),
    )
    .expect("block");
    let filesystem = terra_runtime::component::fs::register_device(
        &mut runtime,
        FsHost::new(
            DeviceContext::with_ram(ram.clone()),
            ShareGrant::new(&mount, false).expect("mount grant"),
        ),
        &fs_component,
        "test",
        8192,
        no_interrupt(),
    )
    .expect("filesystem");
    let memory = terra_runtime::component::mem::register_device(
        &mut runtime,
        DeviceContext::with_ram(ram.clone()),
        &mem_component,
        no_interrupt(),
    )
    .expect("memory");
    let backend = start_test_broker(terra_network::config::Config {
        policy: terra_network::config::Network::default(),
        gateways: [
            HostServiceAddresses::default().gateway_ip.into(),
            HostServiceAddresses::default().gateway_ip6.into(),
        ],
        listeners: Vec::new(),
        limits: terra_network::config::Limits::default(),
    })
    .expect("network broker");
    let artifacts = support::artifacts::trusted_artifacts();
    let (streams, agent_stream) = FrontendStreams::new();
    let vsock = terra_runtime::component::vsock::register_device(
        &mut runtime,
        ram,
        artifacts.vsock(),
        streams,
        Some(backend),
        Vec::new(),
        no_interrupt(),
    )
    .expect("vsock frontend");
    let agent = start_agent(&mut runtime, agent_stream);

    let teardown = runtime.native_teardown();
    let runtime = runtime.prepare().await.expect("runtime prepared").start();
    for _ in 0..3 {
        reset_device(
            |offset, bytes| block.write(offset, bytes),
            |offset, len| block.read(offset, len),
        );
        reset_device(
            |offset, bytes| filesystem.write(offset, bytes),
            |offset, len| filesystem.read(offset, len),
        );
        reset_device(
            |offset, bytes| memory.write(offset, bytes),
            |offset, len| memory.read(offset, len),
        );
        reset_device(
            |offset, bytes| vsock.write(offset, bytes),
            |offset, len| vsock.read(offset, len),
        );
    }

    block.close().expect("block close");
    filesystem.close().expect("filesystem close");
    memory.close().expect("memory close");
    vsock.close().expect("vsock close");
    agent.close_async().await.expect("agent close");
    teardown
        .wait_until(std::time::Instant::now() + Duration::from_secs(5))
        .await
        .expect("native teardown");
    tokio::time::timeout(Duration::from_secs(5), runtime.join())
        .await
        .expect("runtime shutdown deadline")
        .expect("runtime shutdown");
}
