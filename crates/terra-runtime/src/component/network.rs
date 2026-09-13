//! Network component bindings over the box-wide MMIO router.

pub mod host;
mod limits;
pub mod policy;

use std::sync::Arc;
use std::time::Duration;

use terra_network::{GuestNetworkConfig, PolicyHandle, PortMapping};
use wasmtime::Store;
use wasmtime::component::{Component, Instance};

use crate::component::network::host::{NetworkConfig, NetworkError};
use crate::engine::{DeviceError, DeviceHost, component_export};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

pub use crate::component::Interrupt;

use crate::component::DeviceChannel;

type NetworkState = crate::component::worker::Worker<NetworkError>;

fn transport_error(error: DeviceError) -> wasmtime::Error {
    wasmtime::Error::msg(format!("network transport: {error:?}"))
}

fn api_error(error: NetworkError) -> wasmtime::Error {
    wasmtime::Error::msg(format!("network configuration: {error:?}"))
}

impl crate::component::network::host::NetworkHostState for crate::box_runtime::BoxHost {
    fn network_sockets(&mut self) -> wasmtime_wasi::sockets::WasiSocketsCtxView<'_> {
        wasmtime_wasi::sockets::WasiSocketsView::sockets(&mut self.network[0])
    }

    fn network_lookups(&mut self) -> Arc<tokio::sync::Semaphore> {
        self.network[0].network_lookups()
    }

    fn network_policy_calls(&mut self) -> Arc<tokio::sync::Semaphore> {
        self.network[0].network_policy_calls()
    }
}

fn network_config(
    config: GuestNetworkConfig,
    host_service_ports: Vec<Option<u16>>,
    port_mappings: Vec<PortMapping>,
) -> NetworkConfig {
    NetworkConfig {
        gateway_mac: config.gateway_mac.to_vec(),
        gateway_ip: config.gateway_ip.octets().to_vec(),
        gateway_ip6: config.gateway_ip6.octets().to_vec(),
        host_service_ports,
        published_ports: port_mappings
            .into_iter()
            .map(|mapping| crate::component::network::host::PublishedPort {
                host_port: mapping.host,
                guest_port: mapping.guest,
            })
            .collect(),
        mtu: 1500,
    }
}

async fn configure_state<T: Send + 'static>(
    store: &mut Store<T>,
    component: &Component,
    linker: &wasmtime::component::Linker<T>,
    config: NetworkConfig,
    interrupt: Interrupt,
) -> wasmtime::Result<(Instance, NetworkState)> {
    let api_export = |name| component_export(component, "terra:network/api@0.1.0", name, "network");
    let transport_export =
        |name| component_export(component, "terra:network/transport@0.1.0", name, "network");
    let instance: Instance = tokio::time::timeout(
        REQUEST_TIMEOUT,
        linker.instantiate_async(&mut *store, component),
    )
    .await
    .map_err(|_| wasmtime::Error::msg("network component instantiation timed out"))??;
    let configure = instance.get_typed_func::<(NetworkConfig,), (Result<(), NetworkError>,)>(
        &mut *store,
        api_export("configure")?,
    )?;
    let (configured,) = tokio::time::timeout(
        REQUEST_TIMEOUT,
        configure.call_async(&mut *store, (config,)),
    )
    .await
    .map_err(|_| wasmtime::Error::msg("network component configuration timed out"))??;
    configured.map_err(api_error)?;
    let transport_configure = instance.get_typed_func::<(), (Result<(), DeviceError>,)>(
        &mut *store,
        transport_export("configure")?,
    )?;
    let (configured,) = tokio::time::timeout(
        REQUEST_TIMEOUT,
        transport_configure.call_async(&mut *store, ()),
    )
    .await
    .map_err(|_| wasmtime::Error::msg("network transport configuration timed out"))??;
    configured.map_err(transport_error)?;
    let state = NetworkState {
        run: instance.get_typed_func(&mut *store, api_export("run")?)?,
        interrupt,
    };
    Ok((instance, state))
}

#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::too_many_arguments)]
pub async fn instantiate(
    store: Store<DeviceHost>,
    component: &Component,
    policy: PolicyHandle,
    port_mappings: Vec<PortMapping>,
    config: GuestNetworkConfig,
    interrupt: Interrupt,
) -> wasmtime::Result<DeviceChannel> {
    let engine = store.engine().clone();
    let mut runtime =
        crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new())?;
    let channel = instantiate_shared(
        &mut runtime,
        store.into_data(),
        component,
        policy,
        port_mappings,
        config,
        interrupt,
    )
    .await?;
    Ok(DeviceChannel {
        _runtime: Some(Arc::new(runtime.start())),
        ..channel
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn instantiate_shared(
    runtime: &mut crate::box_runtime::BoxRuntime,
    host: DeviceHost,
    component: &Component,
    policy: PolicyHandle,
    port_mappings: Vec<PortMapping>,
    config: GuestNetworkConfig,
    interrupt: Interrupt,
) -> wasmtime::Result<DeviceChannel> {
    grant_shared(
        runtime,
        move || Ok(host),
        component,
        policy,
        port_mappings,
        config,
        interrupt,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn grant_shared(
    runtime: &mut crate::box_runtime::BoxRuntime,
    host: impl FnOnce() -> wasmtime::Result<DeviceHost> + Send + 'static,
    component: &Component,
    policy: PolicyHandle,
    port_mappings: Vec<PortMapping>,
    config: GuestNetworkConfig,
    interrupt: Interrupt,
) -> wasmtime::Result<DeviceChannel> {
    let host_service_ports = policy.host_service_ports().to_vec();
    let policy_ports = host_service_ports.clone();
    let policy_mappings = port_mappings.clone();
    if runtime.has_component(crate::component::vmm::machine::DeviceKind::Net) {
        return Err(wasmtime::Error::msg(
            "box network component already configured",
        ));
    }
    let config = network_config(config, host_service_ports, port_mappings);
    let child = runtime.child_factory();
    let component = component.clone();
    let factory: crate::component::vmm::workers::Factory = Box::new(move || {
        Box::pin(async move {
            let mut host = host()?;
            host.set_network_policy(policy, policy_ports, policy_mappings);
            create_worker(
                child(crate::box_runtime::BoxHost::new())?,
                host,
                &component,
                config,
                interrupt,
            )
            .await
        })
    });
    let mmio = crate::component::vmm::mmio::MmioDevice::grant_worker(
        runtime,
        crate::component::vmm::machine::DeviceKind::Net,
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
    host: DeviceHost,
    component: &Component,
    config: NetworkConfig,
    interrupt: Interrupt,
) -> wasmtime::Result<(
    crate::box_runtime::BoxRuntime,
    crate::component::vmm::mmio::Serve,
)> {
    let wake = host.interrupt_notification();
    child.add_network(host)?;
    let linker = crate::component::network::host::network_component_linker_with(
        child.store.engine(),
        crate::engine::DeviceWasiGetters {
            cli: |host: &mut crate::box_runtime::BoxHost| {
                wasmtime_wasi::cli::WasiCliView::cli(&mut host.network[0])
            },
            clocks: |host: &mut crate::box_runtime::BoxHost| {
                wasmtime_wasi::clocks::WasiClocksView::clocks(&mut host.network[0])
            },
        },
        |host: &mut crate::box_runtime::BoxHost| &mut host.network[0],
    )?;
    let (instance, state) =
        configure_state(&mut child.store, component, &linker, config, interrupt).await?;
    let serve: crate::component::vmm::mmio::Serve = instance.get_typed_func(
        &mut child.store,
        component_export(component, "terra:mmio/device@0.1.0", "serve", "network")?,
    )?;
    state.register(&mut child, wake, "network", move |host| {
        let host = host
            .network
            .get_mut(0)
            .ok_or_else(|| wasmtime::Error::msg("network host missing"))?;
        host.end_window();
        Ok(host.interrupt_level())
    })?;
    Ok((child, serve))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{device_engine, device_store};

    struct Open;

    impl terra_network::Policy for Open {
        fn allows(&self, _: std::net::IpAddr, _: Option<u16>) -> bool {
            true
        }
    }

    async fn wait_for_used(
        channel: &DeviceChannel,
        memory: &crate::BoundedMemory<'_>,
        expected: [u8; 2],
    ) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while memory.read(0x3002, 2).expect("used index") != expected {
                assert!(channel.failure().is_none());
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker completes request");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn actor_configures_and_serves_component_mmio() {
        let engine = device_engine().expect("engine builds");
        let component_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../components/network/target/wasm32-wasip3/release/terra_network_component.wasm",
        );
        let component = Component::new(
            &engine,
            std::fs::read(component_path).expect("network component built"),
        )
        .expect("component compiles");
        let store = device_store(&engine, 64 * 1024).expect("store builds");
        let interrupts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&interrupts);
        let channel = crate::component::network::instantiate(
            store,
            &component,
            Arc::new(Open),
            Vec::new(),
            GuestNetworkConfig::default(),
            Arc::new(move |_| {
                observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }),
        )
        .await
        .expect("actor instantiates");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(channel.failure().is_none(), "{:?}", channel.failure());
        assert_eq!(
            channel.read(0, 4).expect("magic read"),
            0x7472_6976u32.to_le_bytes()
        );
        assert!(channel.read(0, 3).is_err());
        channel.close().expect("actor closes");
        assert!(channel.failure().is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn shared_box_network_serves_and_closes() {
        let engine = device_engine().expect("engine");
        let component = Component::new(&engine, include_bytes!(
            "../../../../components/network/target/wasm32-wasip3/release/terra_network_component.wasm"
        )).expect("component");
        let mut runtime =
            crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new())
                .expect("runtime");
        let host = DeviceHost::with_ram(crate::SyntheticRam::new(64 * 1024).expect("RAM"));
        let channel = crate::component::network::instantiate_shared(
            &mut runtime,
            host,
            &component,
            Arc::new(Open),
            Vec::new(),
            GuestNetworkConfig::default(),
            Arc::new(|_| Ok(())),
        )
        .await
        .expect("shared network");
        let running = runtime.start();
        tokio::task::spawn_blocking(move || {
            assert_eq!(
                channel.read(0, 4).expect("read"),
                0x7472_6976u32.to_le_bytes()
            );
            channel.close().expect("close");
        })
        .await
        .expect("caller");
        running.join().await.expect("runtime closes");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn queue_doorbell_resyncs_an_overfull_queue_and_accepts_new_work() {
        let engine = device_engine().expect("engine builds");
        let component = Component::new(
            &engine,
            include_bytes!(
                "../../../../components/network/target/wasm32-wasip3/release/terra_network_component.wasm"
            ),
        )
        .expect("component compiles");
        let mut store = device_store(&engine, 64 * 1024).expect("store builds");
        let ram = store.data().guest_ram().clone();
        store
            .data_mut()
            .guest_write(0x2002, &257u16.to_le_bytes())
            .expect("avail index writes");
        let channel = crate::component::network::instantiate(
            store,
            &component,
            Arc::new(Open),
            Vec::new(),
            GuestNetworkConfig::default(),
            Arc::new(|_| Ok(())),
        )
        .await
        .expect("actor instantiates");
        for (offset, value) in [
            (0x70, 1u32),
            (0x70, 3),
            (0x24, 1),
            (0x20, 1),
            (0x70, 11),
            (0x30, 1),
            (0x38, 256),
            (0x80, 0x1000),
            (0x90, 0x2000),
            (0xa0, 0x3000),
            (0x44, 1),
            (0x70, 15),
        ] {
            channel
                .write(offset, &value.to_le_bytes())
                .expect("MMIO setup");
        }
        channel
            .write(0x50, &1u32.to_le_bytes())
            .expect("notify invalid queue");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(channel.failure().is_none());
        assert_eq!(
            channel.read(0, 4).expect("worker survives"),
            0x7472_6976u32.to_le_bytes()
        );
        let memory = crate::BoundedMemory::new(&ram);
        assert_eq!(memory.read(0x3002, 2).expect("used index"), [0, 0]);
        memory
            .write(0x2002, &258u16.to_le_bytes())
            .expect("new request");
        channel
            .write(0x50, &1u32.to_le_bytes())
            .expect("notify new request");
        wait_for_used(&channel, &memory, [1, 0]).await;
        let mut descriptor = [0; 16];
        descriptor[..8].copy_from_slice(&0xfff0_u64.to_le_bytes());
        descriptor[8..12].copy_from_slice(&26_u32.to_le_bytes());
        memory.write(0x1020, &descriptor).expect("bad descriptor");
        memory
            .write(0x2008, &2_u16.to_le_bytes())
            .expect("bad head");
        memory
            .write(0x2002, &259_u16.to_le_bytes())
            .expect("bad request");
        channel
            .write(0x50, &1_u32.to_le_bytes())
            .expect("notify bad request");
        wait_for_used(&channel, &memory, [2, 0]).await;
        descriptor[..8].copy_from_slice(&0x4000_u64.to_le_bytes());
        memory.write(0x1030, &descriptor).expect("valid descriptor");
        memory
            .write(0x200a, &3_u16.to_le_bytes())
            .expect("valid head");
        memory.write(0x4000, &[0; 26]).expect("valid frame");
        memory
            .write(0x2002, &260_u16.to_le_bytes())
            .expect("valid request");
        channel
            .write(0x50, &1_u32.to_le_bytes())
            .expect("notify valid request");
        wait_for_used(&channel, &memory, [3, 0]).await;
        channel.close().expect("close worker");
    }
}
