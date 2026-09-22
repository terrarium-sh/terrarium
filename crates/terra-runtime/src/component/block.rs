//! Block component bindings over the box-wide MMIO router.

pub mod backing;
mod bindings;
mod host;

use crate::machine::DeviceKind;

#[cfg(test)]
use std::sync::Arc;

use wasmtime::component::Component;

use bindings::BlockDevice;
#[cfg(test)]
pub(crate) use bindings::disk::HostWithStore as DiskHostWithStore;
pub use host::{BlockHost, block_component_linker};

use crate::component::InterruptCallback;

use crate::component::MmioDevice;

use crate::component::device_loop::DeviceLoop;

#[cfg(test)]
pub(crate) async fn instantiate(
    engine: &wasmtime::Engine,
    host: BlockHost,
    component: &Component,
    readonly: bool,
    interrupt: InterruptCallback,
) -> wasmtime::Result<crate::component::StandaloneDevice> {
    let mut runtime =
        crate::box_runtime::BoxRuntime::new(engine, crate::box_runtime::store::BoxHost::new())?;
    crate::component::mmio::initialize_test_mmio(&mut runtime).await?;
    let channel = register_device(&mut runtime, host, component, readonly, interrupt)?;
    Ok(crate::component::StandaloneDevice {
        _runtime: Arc::new(runtime.prepare().await?.start()),
        device: channel,
    })
}

pub fn register_device(
    runtime: &mut crate::box_runtime::BoxRuntime,
    host: BlockHost,
    component: &Component,
    readonly: bool,
    interrupt: InterruptCallback,
) -> wasmtime::Result<MmioDevice> {
    register_device_with_host_factory(runtime, move || Ok(host), component, readonly, interrupt)
}

pub fn register_device_with_host_factory(
    runtime: &mut crate::box_runtime::BoxRuntime,
    create_host: impl FnOnce() -> wasmtime::Result<BlockHost> + Send + 'static,
    component: &Component,
    readonly: bool,
    interrupt: InterruptCallback,
) -> wasmtime::Result<MmioDevice> {
    let child = runtime.child_factory();
    let component = component.clone();
    runtime.grant_device_worker(DeviceKind::Block, async move {
        create_worker(child(create_host()?), &component, readonly, interrupt).await
    })
}

async fn create_worker(
    mut child: crate::box_runtime::DeviceWorker<BlockHost>,
    component: &Component,
    readonly: bool,
    interrupt: InterruptCallback,
) -> wasmtime::Result<(
    crate::box_runtime::DeviceWorker<BlockHost>,
    crate::component::mmio::Serve,
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
    let device_loop = DeviceLoop {
        run: api.func_run(),
        interrupt,
    };
    let serve = instance.terra_mmio_device().func_serve();
    device_loop.register(&mut child, wake, "block")?;
    Ok((child, serve))
}

#[cfg(test)]
mod tests {

    use crate::component::block::BlockHost;
    use crate::component::block::backing::BoundedDisk;
    use crate::component::block::backing::DiskGrant;
    use crate::engine::device_engine;
    use crate::memory::BoundedMemory;
    use crate::memory::GuestRam;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use wasmtime::component::Component;

    #[tokio::test(flavor = "multi_thread")]
    async fn actor_configures_and_serves_component_mmio() {
        let engine = device_engine().expect("engine builds");
        let component =
            Component::new(&engine, crate::test_fixtures::wasm::BLOCK).expect("component compiles");
        let host = crate::component::block::BlockHost::new(
            crate::memory::GuestRam::new(64 * 1024).unwrap(),
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
        let component =
            Component::new(&engine, crate::test_fixtures::wasm::BLOCK).expect("component compiles");
        let ram = GuestRam::new(64 * 1024).expect("RAM");
        let mut runtime =
            crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::store::BoxHost::new())
                .expect("box runtime");
        let mmio = Component::new(&engine, crate::test_fixtures::wasm::MMIO)
            .expect("MMIO service compiles");
        runtime
            .initialize_mmio(&mmio)
            .await
            .expect("MMIO service initializes");
        let writable = BlockHost::new(ram.clone(), DiskGrant::Mem(BoundedDisk::new(4096, false)));
        let readonly = BlockHost::new(ram, DiskGrant::Mem(BoundedDisk::new(8192, true)));
        let first = crate::component::block::register_device(
            &mut runtime,
            writable,
            &component,
            false,
            Arc::new(|_| Ok(())),
        )
        .expect("first block instantiates");
        let second = crate::component::block::register_device(
            &mut runtime,
            readonly,
            &component,
            true,
            Arc::new(|_| Ok(())),
        )
        .expect("second block instantiates");
        let mut other_box =
            crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::store::BoxHost::new())
                .unwrap();
        other_box.initialize_mmio(&mmio).await.unwrap();
        let other_device = crate::component::block::register_device(
            &mut other_box,
            BlockHost::new(
                crate::memory::GuestRam::new(4096).unwrap(),
                crate::component::block::backing::DiskGrant::Mem(
                    crate::component::block::backing::BoundedDisk::new(0, false),
                ),
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
        let component = Component::new(&engine, crate::test_fixtures::wasm::BLOCK).unwrap();
        let mut host = crate::component::block::BlockHost::new(
            crate::memory::GuestRam::new(64 * 1024).unwrap(),
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
            crate::memory::BoundedMemory::new(&ram)
                .read(0x3002, 2)
                .unwrap(),
            [0, 0]
        );
        crate::memory::BoundedMemory::new(&ram)
            .write(0x2002, &258u16.to_le_bytes())
            .unwrap();
        channel.write(0x50, &0u32.to_le_bytes()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while crate::memory::BoundedMemory::new(&ram)
                .read(0x3002, 2)
                .unwrap()
                != [1, 0]
            {
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
        let component = Component::new(&engine, crate::test_fixtures::wasm::BLOCK).unwrap();
        let ram = GuestRam::new(64 * 1024).unwrap();
        let memory = BoundedMemory::new(&ram);
        let host = crate::component::block::BlockHost::new(
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

#[cfg(test)]
mod component_tests;
