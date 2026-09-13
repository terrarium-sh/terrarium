//! Memory component bindings over the box-wide MMIO router.

pub mod host;

#[cfg(any(test, feature = "test-support"))]
use std::sync::Arc;
use std::time::Duration;

use wasmtime::Store;
use wasmtime::component::{Component, Instance, TypedFunc};

use crate::component::mem::host::{MemDeviceError, MemHost, shared_mem_component_linker};
use crate::engine::component_export;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

type Configure = TypedFunc<(), (Result<(), MemDeviceError>,)>;

pub use crate::component::Interrupt;

use crate::component::DeviceChannel;

type MemState = crate::component::worker::Worker<MemDeviceError>;

fn transport_error(operation: &str, error: MemDeviceError) -> wasmtime::Error {
    wasmtime::Error::msg(format!("memory {operation}: {error:?}"))
}

async fn configure_state<T: Send + 'static>(
    store: &mut Store<T>,
    component: &Component,
    linker: &wasmtime::component::Linker<T>,
    interrupt: Interrupt,
) -> wasmtime::Result<(Instance, MemState)> {
    let export = |name| component_export(component, "terra:mem/transport@0.1.0", name, "memory");
    let instance: Instance = linker.instantiate_async(&mut *store, component).await?;
    let configure: Configure = instance.get_typed_func(&mut *store, export("configure")?)?;
    let (configured,) = configure.call_async(&mut *store, ()).await?;
    configured.map_err(|error| transport_error("configure", error))?;
    let state = MemState {
        run: instance.get_typed_func(&mut *store, export("run")?)?,
        interrupt,
    };
    Ok((instance, state))
}

#[cfg(any(test, feature = "test-support"))]
pub async fn instantiate(
    store: Store<MemHost>,
    component: &Component,
    interrupt: Interrupt,
) -> wasmtime::Result<DeviceChannel> {
    let engine = store.engine().clone();
    let mut runtime =
        crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new())?;
    let channel = instantiate_shared(&mut runtime, store.into_data(), component, interrupt).await?;
    Ok(DeviceChannel {
        _runtime: Some(Arc::new(runtime.start())),
        ..channel
    })
}

pub async fn instantiate_shared(
    runtime: &mut crate::box_runtime::BoxRuntime,
    host: MemHost,
    component: &Component,
    interrupt: Interrupt,
) -> wasmtime::Result<DeviceChannel> {
    grant_shared(runtime, move || Ok(host), component, interrupt).await
}

pub async fn grant_shared(
    runtime: &mut crate::box_runtime::BoxRuntime,
    host: impl FnOnce() -> wasmtime::Result<MemHost> + Send + 'static,
    component: &Component,
    interrupt: Interrupt,
) -> wasmtime::Result<DeviceChannel> {
    if runtime.has_component(crate::component::vmm::machine::DeviceKind::Memory) {
        return Err(wasmtime::Error::msg("box already has a memory component"));
    }
    let child = runtime.child_factory();
    let component = component.clone();
    let factory: crate::component::vmm::workers::Factory = Box::new(move || {
        Box::pin(async move {
            create_worker(
                child(crate::box_runtime::BoxHost::new())?,
                host()?,
                &component,
                interrupt,
            )
            .await
        })
    });
    let mmio = crate::component::vmm::mmio::MmioDevice::grant_worker(
        runtime,
        crate::component::vmm::machine::DeviceKind::Memory,
        factory,
    )
    .await?;
    Ok(DeviceChannel {
        mmio,
        _runtime: None,
    })
}

async fn create_worker(
    mut child: crate::box_runtime::BoxRuntime,
    host: MemHost,
    component: &Component,
    interrupt: Interrupt,
) -> wasmtime::Result<(
    crate::box_runtime::BoxRuntime,
    crate::component::vmm::mmio::Serve,
)> {
    let wake = host.device.interrupt_notification();
    child.add_mem(host)?;
    let linker = shared_mem_component_linker(child.store.engine())?;
    let (instance, state) = tokio::time::timeout(
        REQUEST_TIMEOUT,
        configure_state(&mut child.store, component, &linker, interrupt),
    )
    .await
    .map_err(|_| wasmtime::Error::msg("memory component setup timed out"))??;
    let serve: crate::component::vmm::mmio::Serve = instance.get_typed_func(
        &mut child.store,
        component_export(component, "terra:mmio/device@0.1.0", "serve", "memory")?,
    )?;
    state.register(&mut child, wake, "mem", move |host| {
        let host = host
            .memory
            .get_mut(0)
            .ok_or_else(|| wasmtime::Error::msg("mem host missing"))?;
        host.device.end_window();
        Ok(host.device.interrupt_level())
    })?;
    Ok((child, serve))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SyntheticRam;
    use crate::engine::{DeviceHost, device_engine};

    async fn channel() -> DeviceChannel {
        let engine = device_engine().expect("engine builds");
        let component_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/mem/target/wasm32-wasip3/release/terra_mem_component.wasm");
        let component = Component::new(
            &engine,
            std::fs::read(component_path).expect("memory component built"),
        )
        .expect("component compiles");
        let ram = SyntheticRam::new(64 * 1024).expect("RAM");
        let store = Store::new(&engine, MemHost::new(DeviceHost::with_ram(ram.clone())));
        crate::component::mem::instantiate(store, &component, Arc::new(|_| Ok(())))
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
        let component = Component::new(
            &engine,
            include_bytes!(
                "../../../../components/mem/target/wasm32-wasip3/release/terra_mem_component.wasm"
            ),
        )
        .expect("component compiles");
        let ram = SyntheticRam::new(64 * 1024).expect("RAM");
        let mut runtime =
            crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new())
                .expect("box runtime");
        let interrupts = Arc::new(tokio::sync::Notify::new());
        let notification = Arc::clone(&interrupts);
        let channel = crate::component::mem::instantiate_shared(
            &mut runtime,
            MemHost::new(DeviceHost::with_ram(ram)),
            &component,
            Arc::new(move |_| {
                notification.notify_one();
                Ok(())
            }),
        )
        .await
        .expect("shared worker instantiates");
        let runtime = runtime.start();
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
        let component = Component::new(
            &engine,
            include_bytes!(
                "../../../../components/mem/target/wasm32-wasip3/release/terra_mem_component.wasm"
            ),
        )
        .unwrap();
        let ram = SyntheticRam::new(64 * 1024).unwrap();
        let memory = crate::BoundedMemory::new(&ram);
        let store = Store::new(&engine, MemHost::new(DeviceHost::with_ram(ram.clone())));
        let interrupted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let interrupt = Arc::clone(&interrupted);
        let channel = crate::component::mem::instantiate(
            store,
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
