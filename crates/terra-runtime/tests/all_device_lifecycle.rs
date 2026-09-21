#![allow(clippy::expect_used)]

#[path = "support/artifacts.rs"]
mod support;

use std::sync::Arc;
use std::time::Duration;

use terra_network::{GuestNetworkConfig, Policy, PolicyHandle};
use terra_runtime::box_runtime::{BoxHost, BoxRuntime};
use terra_runtime::component::InterruptCallback;
use terra_runtime::component::block::backing::{BoundedDisk, DiskGrant};
use terra_runtime::component::context::DeviceContext;
use terra_runtime::component::fs::{FsHost, ShareGrant};
use terra_runtime::component::vsock::VsockChannel;
use terra_runtime::engine::device_engine;
use terra_runtime::memory::GuestRam;
use wasmtime::component::Component;

const STATUS: u64 = 0x70;
const STATUS_RESET: [u8; 4] = 0_u32.to_le_bytes();
const STATUS_ACKNOWLEDGE: [u8; 4] = 1_u32.to_le_bytes();
const STATUS_DRIVER: [u8; 4] = 3_u32.to_le_bytes();
const MAGIC: [u8; 4] = 0x7472_6976_u32.to_le_bytes();

struct NoNetwork;

impl Policy for NoNetwork {
    fn allows(&self, _: std::net::IpAddr, _: Option<u16>) -> bool {
        false
    }
}

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

fn load_components(engine: &wasmtime::Engine) -> [Component; 5] {
    let router = component(engine, support::artifacts::wasm::VMM);
    let block_component = component(engine, support::artifacts::wasm::BLOCK);
    let fs_component = component(engine, support::artifacts::wasm::FS);
    let mem_component = component(engine, support::artifacts::wasm::MEM);
    let network_component = component(engine, support::artifacts::wasm::NETWORK);
    [
        router,
        block_component,
        fs_component,
        mem_component,
        network_component,
    ]
}

fn start_vsock(runtime: &mut BoxRuntime, ram: GuestRam) -> VsockChannel {
    let artifact = support::artifacts::trusted_artifacts().vsock();
    VsockChannel::from_trusted_artifact(
        runtime,
        ram,
        artifact,
        vec![2, 0, 0, 0, b'{', b'}'],
        None,
        None,
        None,
        no_interrupt(),
    )
    .expect("vsock")
}

#[tokio::test(flavor = "multi_thread")]
async fn every_device_resets_and_closes_in_one_box_runtime() {
    let engine = device_engine().expect("engine");
    let [
        router,
        block_component,
        fs_component,
        mem_component,
        network_component,
    ] = load_components(&engine);
    let ram = GuestRam::new(64 * 1024).expect("RAM");
    let root = tempfile::tempdir().expect("mount directory");
    let mount = std::fs::canonicalize(root.path()).expect("canonical mount directory");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime.initialize_mmio(&router).await.expect("MMIO router");

    let block_host = terra_runtime::component::block::host::BlockHost::new(
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
    let policy: PolicyHandle = Arc::new(NoNetwork);
    let network = terra_runtime::component::network::register_device(
        &mut runtime,
        terra_runtime::component::context::DeviceContext::with_ram(ram.clone()),
        &network_component,
        policy,
        Vec::new(),
        GuestNetworkConfig::default(),
        no_interrupt(),
    )
    .expect("network");
    let vsock = start_vsock(&mut runtime, ram);

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
            |offset, bytes| network.write(offset, bytes),
            |offset, len| network.read(offset, len),
        );
        reset_device(
            |offset, bytes| vsock.write_mmio(offset, bytes),
            |offset, len| vsock.read_mmio(offset, len),
        );
    }

    block.close().expect("block close");
    filesystem.close().expect("filesystem close");
    memory.close().expect("memory close");
    network.close().expect("network close");
    vsock.close_async().await.expect("vsock close");
    tokio::time::timeout(Duration::from_secs(5), runtime.join())
        .await
        .expect("runtime shutdown deadline")
        .expect("runtime shutdown");
}
