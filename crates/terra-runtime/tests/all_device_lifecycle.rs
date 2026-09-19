#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use terra_network::{GuestNetworkConfig, Policy, PolicyHandle};
use terra_runtime::{
    BoundedDisk, SyntheticRam,
    box_runtime::{BoxHost, BoxRuntime},
    component::{
        Interrupt,
        fs::host::{FsHost, ShareGrant},
        mem::host::MemHost,
        vsock::VsockChannel,
    },
    engine::{DeviceHost, DiskGrant, device_engine},
};
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

fn no_interrupt() -> Interrupt {
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
    let router = component(
        engine,
        include_bytes!(
            "../../../components/vmm/target/wasm32-wasip3/release/terra_vmm_component.wasm"
        ),
    );
    let block_component = component(
        engine,
        include_bytes!(
            "../../../components/block/target/wasm32-wasip3/release/terra_block_component.wasm"
        ),
    );
    let fs_component = component(
        engine,
        include_bytes!(
            "../../../components/fs/target/wasm32-wasip3/release/terra_fs_component.wasm"
        ),
    );
    let mem_component = component(
        engine,
        include_bytes!(
            "../../../components/mem/target/wasm32-wasip3/release/terra_mem_component.wasm"
        ),
    );
    let network_component = component(
        engine,
        include_bytes!(
            "../../../components/network/target/wasm32-wasip3/release/terra_network_component.wasm"
        ),
    );
    [
        router,
        block_component,
        fs_component,
        mem_component,
        network_component,
    ]
}

async fn start_vsock(runtime: &mut BoxRuntime, ram: SyntheticRam) -> VsockChannel {
    // SAFETY: this test embeds the build's trusted AOT vsock artifact.
    #[allow(unsafe_code)]
    unsafe {
        VsockChannel::from_trusted_shared(
            runtime,
            ram,
            include_bytes!("../../../build/terra-vsock-component.cwasm"),
            vec![2, 0, 0, 0, b'{', b'}'],
            None,
            None,
            None,
            no_interrupt(),
        )
        .await
    }
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
    let ram = SyntheticRam::new(64 * 1024).expect("RAM");
    let root = tempfile::tempdir().expect("mount directory");
    let mount = std::fs::canonicalize(root.path()).expect("canonical mount directory");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime.initialize_mmio(&router).await.expect("MMIO router");

    let mut block_host = DeviceHost::with_ram(ram.clone());
    block_host.set_disk(DiskGrant::Mem(BoundedDisk::new(4096, false)));
    let block = terra_runtime::component::block::instantiate_shared(
        &mut runtime,
        block_host,
        &block_component,
        false,
        no_interrupt(),
    )
    .await
    .expect("block");
    let filesystem = terra_runtime::component::fs::instantiate_shared(
        &mut runtime,
        FsHost::new(
            DeviceHost::with_ram(ram.clone()),
            ShareGrant::new(&mount, false).expect("mount grant"),
        ),
        &fs_component,
        "test",
        8192,
        no_interrupt(),
    )
    .await
    .expect("filesystem");
    let memory = terra_runtime::component::mem::instantiate_shared(
        &mut runtime,
        MemHost::new(DeviceHost::with_ram(ram.clone())),
        &mem_component,
        no_interrupt(),
    )
    .await
    .expect("memory");
    let policy: PolicyHandle = Arc::new(NoNetwork);
    let network = terra_runtime::component::network::instantiate_shared(
        &mut runtime,
        DeviceHost::with_ram(ram.clone()),
        &network_component,
        policy,
        Vec::new(),
        GuestNetworkConfig::default(),
        no_interrupt(),
    )
    .await
    .expect("network");
    let vsock = start_vsock(&mut runtime, ram).await;

    let runtime = runtime.start();
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
