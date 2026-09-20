//! Block component bindings over the box-wide MMIO router.

pub mod backing;
pub mod host;

#[cfg(any(test, feature = "test-support"))]
use std::sync::Arc;

use wasmtime::component::Component;

use host::{BlockDevice, BlockHost, DeviceError, block_component_linker};

pub use crate::component::Interrupt;

use crate::component::DeviceChannel;

type BlockState = crate::component::worker::Worker<DeviceError>;

#[cfg(any(test, feature = "test-support"))]
pub async fn instantiate(
    engine: &wasmtime::Engine,
    host: BlockHost,
    component: &Component,
    readonly: bool,
    interrupt: Interrupt,
) -> wasmtime::Result<crate::component::StandaloneDevice> {
    let mut runtime =
        crate::box_runtime::BoxRuntime::new(engine, crate::box_runtime::BoxHost::new())?;
    crate::component::vmm::mmio::initialize_test_router(&mut runtime).await?;
    let channel = instantiate_shared(&mut runtime, host, component, readonly, interrupt)?;
    Ok(crate::component::StandaloneDevice {
        _runtime: Arc::new(runtime.prepare().await?.start()),
        device: channel,
    })
}

pub fn instantiate_shared(
    runtime: &mut crate::box_runtime::BoxRuntime,
    host: BlockHost,
    component: &Component,
    readonly: bool,
    interrupt: Interrupt,
) -> wasmtime::Result<DeviceChannel> {
    grant_shared(runtime, move || Ok(host), component, readonly, interrupt)
}

pub fn grant_shared(
    runtime: &mut crate::box_runtime::BoxRuntime,
    host: impl FnOnce() -> wasmtime::Result<BlockHost> + Send + 'static,
    component: &Component,
    readonly: bool,
    interrupt: Interrupt,
) -> wasmtime::Result<DeviceChannel> {
    let child = runtime.child_factory();
    let component = component.clone();
    runtime.grant_device_worker(
        crate::component::vmm::machine::DeviceKind::Block,
        async move { create_worker(child(host()?), &component, readonly, interrupt).await },
    )
}

async fn create_worker(
    mut child: crate::box_runtime::DeviceWorker<BlockHost>,
    component: &Component,
    readonly: bool,
    interrupt: Interrupt,
) -> wasmtime::Result<(
    crate::box_runtime::DeviceWorker<BlockHost>,
    crate::component::vmm::mmio::Serve,
)> {
    let wake = child.store.data().context.interrupt_notification();
    let linker = block_component_linker(child.store.engine())?;
    let instance = BlockDevice::instantiate_async(&mut child.store, component, &linker)
        .await
        .map_err(|error| error.context("block component initialization"))?;
    let api = instance.terra_host_device_api();
    let configure = api.func_configure();
    let (result,) = configure
        .call_async(&mut child.store, (readonly,))
        .await
        .map_err(|error| error.context("block component configuration"))?;
    result.map_err(|error| wasmtime::Error::msg(format!("block configure: {error:?}")))?;
    let state = BlockState {
        run: api.func_run(),
        interrupt,
    };
    let serve = instance.terra_mmio_device().func_serve();
    state.register(&mut child, wake, "block")?;
    Ok((child, serve))
}

#[cfg(test)]
mod tests {

    use crate::engine::{BlockHost, DiskGrant, device_engine};
    use crate::{BoundedDisk, BoundedMemory, SyntheticRam};
    #[cfg(any(test, feature = "test-support"))]
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use wasmtime::component::Component;

    #[tokio::test(flavor = "multi_thread")]
    async fn actor_configures_and_serves_component_mmio() {
        let engine = device_engine().expect("engine builds");
        let component_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/block/target/wasm32-wasip3/release/terra_block_component.wasm");
        let component = Component::new(
            &engine,
            std::fs::read(component_path).expect("block component built"),
        )
        .expect("component compiles");
        let host = crate::engine::BlockHost::new(
            crate::SyntheticRam::new(64 * 1024).unwrap(),
            DiskGrant::Mem(BoundedDisk::new(4096, false)),
        );

        let channel = crate::component::block::instantiate(
            &engine,
            host,
            &component,
            false,
            Arc::new(|_| Ok(())),
        )
        .await
        .expect("actor instantiates");

        assert_eq!(
            channel.read(0, 4).expect("magic read"),
            0x7472_6976u32.to_le_bytes()
        );
        assert!(channel.read(0, 3).is_err());
        assert_eq!(channel.request_counts(), (1, 0));
        channel.write(0x70, &[0]).expect("one-byte reset");
        channel.write(0x70, &[0x80]).expect("failed reset");
        assert_eq!(
            channel.read(0, 4).expect("worker survives resets"),
            0x7472_6976_u32.to_le_bytes()
        );
        channel.close().expect("actor closes");
        assert_eq!(channel.request_counts(), (5, 0));
        assert!(channel.read(0, 4).is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::too_many_lines)]
    async fn shared_box_keeps_block_backings_and_readonly_state_separate() {
        let engine = device_engine().expect("engine builds");
        let component = Component::new(
            &engine,
            include_bytes!(
                "../../../../components/block/target/wasm32-wasip3/release/terra_block_component.wasm"
            ),
        )
        .expect("component compiles");
        let ram = SyntheticRam::new(64 * 1024).expect("RAM");
        let mut runtime =
            crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new())
                .expect("box runtime");
        let router = Component::new(
            &engine,
            include_bytes!(
                "../../../../components/vmm/target/wasm32-wasip3/release/terra_vmm_component.wasm"
            ),
        )
        .expect("MMIO router compiles");
        runtime
            .initialize_mmio(&router)
            .await
            .expect("MMIO router initializes");
        runtime
            .configure_mmio_vcpus(2)
            .await
            .expect("vCPU router setup");
        let writable = BlockHost::new(ram.clone(), DiskGrant::Mem(BoundedDisk::new(4096, false)));
        let readonly = BlockHost::new(ram, DiskGrant::Mem(BoundedDisk::new(8192, true)));
        let first = crate::component::block::instantiate_shared(
            &mut runtime,
            writable,
            &component,
            false,
            Arc::new(|_| Ok(())),
        )
        .expect("first block instantiates");
        let second = crate::component::block::instantiate_shared(
            &mut runtime,
            readonly,
            &component,
            true,
            Arc::new(|_| Ok(())),
        )
        .expect("second block instantiates");
        let mut other_box =
            crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new())
                .unwrap();
        other_box.initialize_mmio(&router).await.unwrap();
        let other_device = crate::component::block::instantiate_shared(
            &mut other_box,
            BlockHost::new(
                crate::SyntheticRam::new(4096).unwrap(),
                crate::engine::DiskGrant::Mem(crate::BoundedDisk::new(0, false)),
            ),
            &component,
            false,
            Arc::new(|_| Ok(())),
        )
        .unwrap();
        assert_eq!(
            first
                .map_mmio(&mut other_box, 0xf000_0000, 0x1000)
                .unwrap_err()
                .to_string(),
            "device belongs to another box"
        );
        let other_running = other_box.prepare().await.unwrap().start();
        assert_eq!(
            other_device.read(0, 4).unwrap(),
            0x7472_6976_u32.to_le_bytes()
        );
        other_device.close().unwrap();
        other_running.join().await.unwrap();
        first
            .map_mmio(&mut runtime, 0xd000_0000, 0x1000)
            .expect("first physical mapping");
        second
            .map_mmio(&mut runtime, 0xe000_0000, 0x1000)
            .expect("second physical mapping");
        let runtime = runtime.prepare().await.unwrap().start();
        assert_eq!(
            first.read(0x100, 4).expect("first capacity"),
            8_u32.to_le_bytes()
        );
        assert_eq!(
            second.read(0x100, 4).expect("second capacity"),
            16_u32.to_le_bytes()
        );
        let first_features = u32::from_le_bytes(
            first
                .read(0x10, 4)
                .expect("first features")
                .try_into()
                .unwrap(),
        );
        let second_features = u32::from_le_bytes(
            second
                .read(0x10, 4)
                .expect("second features")
                .try_into()
                .unwrap(),
        );
        assert_eq!(first_features & (1 << 5), 0);
        assert_ne!(second_features & (1 << 5), 0);
        first.close().expect("first closes");
        second.close().expect("second closes");
        runtime.join().await.expect("box stops cleanly");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn component_resyncs_overfull_guest_queue_and_completes_new_work() {
        let engine = device_engine().unwrap();
        let component = Component::new(
            &engine,
            include_bytes!(
                "../../../../components/block/target/wasm32-wasip3/release/terra_block_component.wasm"
            ),
        )
        .unwrap();
        let mut host = crate::engine::BlockHost::new(
            crate::SyntheticRam::new(64 * 1024).unwrap(),
            DiskGrant::Mem(BoundedDisk::new(4096, false)),
        );
        let ram = host.context.guest_ram().clone();

        host.context
            .guest_write(0x2002, &257u16.to_le_bytes())
            .unwrap();
        let channel = crate::component::block::instantiate(
            &engine,
            host,
            &component,
            false,
            Arc::new(|_| Ok(())),
        )
        .await
        .unwrap();
        for (offset, value) in [
            (0x70, 1u32),
            (0x70, 3),
            (0x24, 1),
            (0x20, 1),
            (0x70, 11),
            (0x38, 256),
            (0x80, 0x1000),
            (0x90, 0x2000),
            (0xa0, 0x3000),
            (0x44, 1),
            (0x70, 15),
        ] {
            channel.write(offset, &value.to_le_bytes()).unwrap();
        }
        channel.write(0x50, &0u32.to_le_bytes()).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(channel.failure().is_none());
        assert_eq!(channel.read(0, 4).unwrap(), 0x7472_6976u32.to_le_bytes());
        assert_eq!(
            crate::BoundedMemory::new(&ram).read(0x3002, 2).unwrap(),
            [0, 0]
        );
        crate::BoundedMemory::new(&ram)
            .write(0x2002, &258u16.to_le_bytes())
            .unwrap();
        channel.write(0x50, &0u32.to_le_bytes()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while crate::BoundedMemory::new(&ram).read(0x3002, 2).unwrap() != [1, 0] {
                assert!(channel.failure().is_none());
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker completes a new request after resynchronizing");
        channel.close().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn worker_completes_queue_and_injects_interrupt() {
        let engine = device_engine().unwrap();
        let component = Component::new(
            &engine,
            include_bytes!(
                "../../../../components/block/target/wasm32-wasip3/release/terra_block_component.wasm"
            ),
        )
        .unwrap();
        let ram = SyntheticRam::new(64 * 1024).unwrap();
        let memory = BoundedMemory::new(&ram);
        let host = crate::engine::BlockHost::new(
            ram.clone(),
            DiskGrant::Mem(BoundedDisk::new(4096, false)),
        );
        let interrupted = Arc::new(AtomicBool::new(false));
        let interrupt = Arc::clone(&interrupted);
        let channel = crate::component::block::instantiate(
            &engine,
            host,
            &component,
            false,
            Arc::new(move |level| {
                interrupt.store(level, Ordering::Release);
                Ok(())
            }),
        )
        .await
        .unwrap();
        let descriptor = |addr: u64, len: u32, flags: u16, next: u16| {
            let mut bytes = [0; 16];
            bytes[..8].copy_from_slice(&addr.to_le_bytes());
            bytes[8..12].copy_from_slice(&len.to_le_bytes());
            bytes[12..14].copy_from_slice(&flags.to_le_bytes());
            bytes[14..].copy_from_slice(&next.to_le_bytes());
            bytes
        };
        let mut table = Vec::new();
        table.extend(descriptor(0x4000, 16, 1, 1));
        table.extend(descriptor(0x4100, 20, 3, 2));
        table.extend(descriptor(0x4200, 1, 2, 0));
        memory.write(0x1000, &table).unwrap();
        memory.write(0x4000, &8u32.to_le_bytes()).unwrap();
        memory.write(0x2002, &1u16.to_le_bytes()).unwrap();
        memory.write(0x2004, &0u16.to_le_bytes()).unwrap();
        for (offset, value) in [
            (0x70, 1u32),
            (0x70, 3),
            (0x24, 1),
            (0x20, 1),
            (0x70, 11),
            (0x38, 256),
            (0x80, 0x1000),
            (0x90, 0x2000),
            (0xa0, 0x3000),
            (0x44, 1),
            (0x70, 15),
        ] {
            channel.write(offset, &value.to_le_bytes()).unwrap();
        }
        let _ = channel.write(0x50, &0u32.to_le_bytes());
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while memory.read(0x3002, 2).unwrap() != 1u16.to_le_bytes()
                || !interrupted.load(Ordering::Acquire)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker completes and interrupts");
        assert_eq!(memory.read(0x4100, 9).unwrap(), b"terra-vda".to_vec());
        assert_eq!(memory.read(0x4200, 1).unwrap(), vec![0]);
        channel.close().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while interrupted.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("closing the device deasserts the published interrupt");
    }
}
