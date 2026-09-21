//! Memory component bindings over the box-wide MMIO router.

pub mod host;

#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;

use crate::component::context::DeviceContext;
use wasmtime::Store;
use wasmtime::component::Component;

use crate::component::mem::host::{MemComponent, MemDeviceError, mem_component_linker};

use crate::component::InterruptCallback;

use crate::component::DeviceChannel;

use crate::component::device_loop::DeviceLoop;

fn transport_error(operation: &str, error: MemDeviceError) -> wasmtime::Error {
    wasmtime::Error::msg(format!("memory {operation}: {error:?}"))
}

async fn configure_device<T: Send + 'static>(
    store: &mut Store<T>,
    component: &Component,
    linker: &wasmtime::component::Linker<T>,
    interrupt: InterruptCallback,
) -> wasmtime::Result<(MemComponent, DeviceLoop<MemDeviceError>)> {
    let instance = MemComponent::instantiate_async(&mut *store, component, linker).await?;
    let transport = instance.terra_mem_transport();
    let configure = transport.func_configure();
    let (configured,) = configure.call_async(&mut *store, ()).await?;
    configured.map_err(|error| transport_error("configure", error))?;
    let device_loop = DeviceLoop {
        run: transport.func_run(),
        interrupt,
    };
    Ok((instance, device_loop))
}

#[cfg(test)]
pub(crate) async fn instantiate(
    engine: &wasmtime::Engine,
    host: DeviceContext,
    component: &Component,
    interrupt: InterruptCallback,
) -> wasmtime::Result<crate::component::StandaloneDevice> {
    let mut runtime =
        crate::box_runtime::BoxRuntime::new(engine, crate::box_runtime::store::BoxHost::new())?;
    crate::component::vmm::mmio::initialize_test_router(&mut runtime).await?;
    let channel = register_device(&mut runtime, host, component, interrupt)?;
    Ok(crate::component::StandaloneDevice {
        _runtime: Arc::new(runtime.prepare().await?.start()),
        device: channel,
    })
}

pub fn register_device(
    runtime: &mut crate::box_runtime::BoxRuntime,
    host: DeviceContext,
    component: &Component,
    interrupt: InterruptCallback,
) -> wasmtime::Result<DeviceChannel> {
    register_device_with_host_factory(runtime, move || Ok(host), component, interrupt)
}

pub fn register_device_with_host_factory(
    runtime: &mut crate::box_runtime::BoxRuntime,
    create_host: impl FnOnce() -> wasmtime::Result<DeviceContext> + Send + 'static,
    component: &Component,
    interrupt: InterruptCallback,
) -> wasmtime::Result<DeviceChannel> {
    if runtime.has_component(crate::component::vmm::bindings::machine::DeviceKind::Memory) {
        return Err(wasmtime::Error::msg("box already has a memory component"));
    }
    let child = runtime.child_factory();
    let component = component.clone();
    runtime.grant_device_worker(
        crate::component::vmm::bindings::machine::DeviceKind::Memory,
        async move { create_worker(child(create_host()?), &component, interrupt).await },
    )
}

async fn create_worker(
    mut child: crate::box_runtime::DeviceWorker<DeviceContext>,
    component: &Component,
    interrupt: InterruptCallback,
) -> wasmtime::Result<(
    crate::box_runtime::DeviceWorker<DeviceContext>,
    crate::component::vmm::mmio::Serve,
)> {
    let wake = child.store.data().interrupt_notification();
    let linker = mem_component_linker(child.store.engine())?;
    let (instance, device_loop) = configure_device(&mut child.store, component, &linker, interrupt)
        .await
        .map_err(|error| error.context("memory component setup"))?;
    let serve = instance.terra_mmio_device().func_serve();
    device_loop.register(&mut child, wake, "mem")?;
    Ok((child, serve))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component::context::DeviceContext;
    use crate::engine::device_engine;
    use crate::memory::GuestRam;

    async fn channel() -> crate::component::StandaloneDevice {
        let engine = device_engine().expect("engine builds");
        let component =
            Component::new(&engine, crate::test_fixtures::wasm::MEM).expect("component compiles");
        let ram = GuestRam::new(64 * 1024).expect("RAM");
        let host = DeviceContext::with_ram(ram.clone());
        crate::component::mem::instantiate(&engine, host, &component, Arc::new(|_| Ok(())))
            .await
            .expect("actor instantiates")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn actor_configures_and_serves_component_mmio() {
        let channel = channel().await;

        assert_eq!(
            channel.read(0, 4).expect("magic read"),
            0x7472_6976_u32.to_le_bytes()
        );
        assert!(channel.read(0, 3).is_err());
        assert_eq!(channel.request_counts(), (1, 0));
        channel.close().expect("actor closes");
        assert_eq!(channel.request_counts(), (2, 0));
        assert!(channel.read(0, 4).is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn shared_box_worker_serves_and_stops() {
        let engine = device_engine().expect("engine builds");
        let component =
            Component::new(&engine, crate::test_fixtures::wasm::MEM).expect("component compiles");
        let ram = GuestRam::new(64 * 1024).expect("RAM");
        let mut runtime =
            crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::store::BoxHost::new())
                .expect("box runtime");
        crate::component::vmm::mmio::initialize_test_router(&mut runtime)
            .await
            .expect("MMIO router");
        let interrupts = Arc::new(tokio::sync::Notify::new());
        let notification = Arc::clone(&interrupts);
        let channel = crate::component::mem::register_device(
            &mut runtime,
            DeviceContext::with_ram(ram),
            &component,
            Arc::new(move |_| {
                notification.notify_one();
                Ok(())
            }),
        )
        .expect("shared worker instantiates");
        let runtime = runtime.prepare().await.unwrap().start();
        for _ in 0..32 {
            assert_eq!(
                channel.read(0, 4).expect("magic read"),
                0x7472_6976_u32.to_le_bytes()
            );
        }
        assert_eq!(channel.request_counts(), (32, 0));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), interrupts.notified())
                .await
                .is_err(),
            "register reads must not invoke the IRQ capability"
        );
        channel.close().expect("worker closes");
        runtime.join().await.expect("box stops cleanly");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn worker_reclaims_on_third_queue_without_stats_or_hints() {
        let engine = device_engine().unwrap();
        let component = Component::new(&engine, crate::test_fixtures::wasm::MEM).unwrap();
        let ram = GuestRam::new(64 * 1024).unwrap();
        let memory = crate::memory::BoundedMemory::new(&ram);
        let host = DeviceContext::with_ram(ram.clone());
        let interrupted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let interrupt = Arc::clone(&interrupted);
        let channel = crate::component::mem::instantiate(
            &engine,
            host,
            &component,
            Arc::new(move |level| {
                interrupt.store(level, std::sync::atomic::Ordering::Release);
                Ok(())
            }),
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        let mut descriptor = [0; 16];
        descriptor[..8].copy_from_slice(&0x4000u64.to_le_bytes());
        descriptor[8..12].copy_from_slice(&4096u32.to_le_bytes());
        descriptor[12..14].copy_from_slice(&2u16.to_le_bytes());
        memory.write(0x1000, &descriptor).unwrap();
        memory.write(0x2002, &1u16.to_le_bytes()).unwrap();
        memory.write(0x2004, &0u16.to_le_bytes()).unwrap();
        memory.write(0x4000, &[0x5a; 4096]).unwrap();
        for (offset, value) in [
            (0x70, 1u32),
            (0x70, 3),
            (0x24, 0),
            (0x20, (1 << 4) | (1 << 5)),
            (0x24, 1),
            (0x20, 1),
            (0x70, 11),
            (0x30, 2),
            (0x38, 256),
            (0x80, 0x1000),
            (0x90, 0x2000),
            (0xa0, 0x3000),
            (0x44, 1),
            (0x70, 15),
        ] {
            channel.write(offset, &value.to_le_bytes()).unwrap();
        }
        channel.write(0x50, &2u32.to_le_bytes()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while memory.read(0x3002, 2).unwrap() != 1u16.to_le_bytes()
                || !interrupted.load(std::sync::atomic::Ordering::Acquire)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker completes and interrupts");
        #[cfg(target_os = "linux")]
        assert_eq!(memory.read(0x4000, 4096).unwrap(), vec![0; 4096]);
        channel.write(0x10c, &[0xaa; 4]).unwrap();
        assert_eq!(channel.read(0x10c, 4).unwrap(), vec![0xaa; 4]);
        let mut descriptor = [0; 16];
        descriptor[..8].copy_from_slice(&0x5000u64.to_le_bytes());
        descriptor[8..12].copy_from_slice(&4096u32.to_le_bytes());
        descriptor[12..14].copy_from_slice(&2u16.to_le_bytes());
        memory.write(0x1010, &descriptor).unwrap();
        memory.write(0x2002, &2u16.to_le_bytes()).unwrap();
        memory.write(0x2006, &1u16.to_le_bytes()).unwrap();
        memory.write(0x5000, &[0x5a; 4096]).unwrap();
        channel.write(0x50, &2u32.to_le_bytes()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while memory.read(0x3002, 2).unwrap() != 2u16.to_le_bytes() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker completes poisoned report");
        assert_eq!(memory.read(0x5000, 4096).unwrap(), vec![0x5a; 4096]);
        channel.write(0x64, &1u32.to_le_bytes()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while interrupted.load(std::sync::atomic::Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("acknowledging the used buffer deasserts the published interrupt");
        channel.close().unwrap();
    }
}
