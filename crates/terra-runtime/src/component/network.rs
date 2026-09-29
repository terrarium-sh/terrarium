//! Network component bindings over the box-wide MMIO router.

mod authorization;
mod bindings;
mod config;
mod host;
mod limits;
mod policy;
mod resource_linker;

use crate::component::device_loop::DeviceLoop;
use crate::component::{InterruptCallback, MmioDevice};
use crate::machine::DeviceKind;
use bindings::{DeviceError, NetworkComponent, NetworkConfig, NetworkError};
use wasmtime::Store;
use wasmtime::component::Component;

#[cfg(test)]
use std::{sync::Arc, time::Duration};

pub(crate) use authorization::MAX_POLICY_CALLS;
#[cfg(test)]
pub(crate) use authorization::PolicyClient;
pub use config::{GuestNetworkConfig, PortMapping};
pub use host::{NetworkHost, network_component_linker};
pub use policy::{AsyncPolicy, DecisionFuture, DecisionLease, NameLookup, Policy, PolicyHandle};

fn transport_error(error: DeviceError) -> wasmtime::Error {
    wasmtime::Error::msg(format!("network transport: {error:?}"))
}

fn api_error(error: NetworkError) -> wasmtime::Error {
    wasmtime::Error::msg(format!("network configuration: {error:?}"))
}

async fn configure_device<T: Send + 'static>(
    store: &mut Store<T>,
    component: &Component,
    linker: &wasmtime::component::Linker<T>,
    config: NetworkConfig,
    interrupt: InterruptCallback,
) -> wasmtime::Result<(NetworkComponent, DeviceLoop<NetworkError>)> {
    let instance = NetworkComponent::instantiate_async(&mut *store, component, linker)
        .await
        .map_err(|error| error.context("network component instantiation"))?;
    let api = instance.terra_network_api();
    let configure = api.func_configure();
    let (configured,) = configure
        .call_async(&mut *store, (&config,))
        .await
        .map_err(|error| error.context("network component configuration"))?;
    configured.map_err(api_error)?;
    let transport_configure = instance.terra_network_transport().func_configure();
    let (configured,) = transport_configure
        .call_async(&mut *store, ())
        .await
        .map_err(|error| error.context("network transport configuration"))?;
    configured.map_err(transport_error)?;
    let device_loop = DeviceLoop {
        run: api.func_run(),
        interrupt,
    };
    Ok((instance, device_loop))
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn instantiate(
    engine: &wasmtime::Engine,
    host: crate::component::context::DeviceContext,
    component: &Component,
    policy: PolicyHandle,
    port_mappings: Vec<PortMapping>,
    config: GuestNetworkConfig,
    interrupt: InterruptCallback,
) -> wasmtime::Result<crate::component::StandaloneDevice> {
    let mut runtime =
        crate::box_runtime::BoxRuntime::new(engine, crate::box_runtime::store::BoxHost::new())?;
    crate::component::mmio::initialize_test_mmio(&mut runtime).await?;
    let channel = register_device(
        &mut runtime,
        host,
        component,
        policy,
        port_mappings,
        config,
        interrupt,
    )?;
    Ok(crate::component::StandaloneDevice {
        _runtime: Arc::new(runtime.prepare().await?.start()),
        device: channel,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn register_device(
    runtime: &mut crate::box_runtime::BoxRuntime,
    host: crate::component::context::DeviceContext,
    component: &Component,
    policy: PolicyHandle,
    port_mappings: Vec<PortMapping>,
    config: GuestNetworkConfig,
    interrupt: InterruptCallback,
) -> wasmtime::Result<MmioDevice> {
    register_device_with_host_factory(
        runtime,
        move || Ok(host),
        component,
        policy,
        port_mappings,
        config,
        interrupt,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn register_device_with_host_factory(
    runtime: &mut crate::box_runtime::BoxRuntime,
    create_host: impl FnOnce() -> wasmtime::Result<crate::component::context::DeviceContext>
    + Send
    + 'static,
    component: &Component,
    policy: PolicyHandle,
    port_mappings: Vec<PortMapping>,
    config: GuestNetworkConfig,
    interrupt: InterruptCallback,
) -> wasmtime::Result<MmioDevice> {
    let host_service_ports = policy.host_service_ports().to_vec();
    let policy_mappings = port_mappings.clone();
    if runtime.has_component(DeviceKind::Net) {
        return Err(wasmtime::Error::msg(
            "box network component already configured",
        ));
    }
    let config = config.into_component_config(
        host_service_ports,
        port_mappings,
        runtime.store.data().network_memory_limit(),
    );
    let child = runtime.child_factory();
    let component = component.clone();
    runtime.grant_device_worker(DeviceKind::Net, async move {
        let host = NetworkHost::new(create_host()?, policy, policy_mappings);
        create_worker(child(host), &component, config, interrupt).await
    })
}

async fn create_worker(
    mut child: crate::box_runtime::DeviceWorker<NetworkHost>,
    component: &Component,
    config: NetworkConfig,
    interrupt: InterruptCallback,
) -> wasmtime::Result<(
    crate::box_runtime::DeviceWorker<NetworkHost>,
    crate::component::mmio::Serve,
)> {
    child.store.data_mut().use_network_memory_limit();
    let wake = child.store.data().context.interrupt_notification();
    let linker = network_component_linker(child.store.engine())?;
    let (instance, device_loop) =
        configure_device(&mut child.store, component, &linker, config, interrupt).await?;
    let serve = instance.terra_mmio_device().func_serve();
    device_loop.register(&mut child, wake, "network")?;
    Ok((child, serve))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::device_engine;

    struct Open;

    impl Policy for Open {
        fn allows(&self, _: std::net::IpAddr, _: Option<u16>) -> bool {
            true
        }
    }

    async fn wait_for_used(
        channel: &MmioDevice,
        memory: &crate::memory::BoundedMemory<'_>,
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
        let component = Component::new(&engine, crate::test_fixtures::wasm::NETWORK)
            .expect("component compiles");
        let host = crate::component::context::DeviceContext::new(64 * 1024).unwrap();
        let interrupts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&interrupts);
        let channel = crate::component::network::instantiate(
            &engine,
            host,
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
        let component =
            Component::new(&engine, crate::test_fixtures::wasm::NETWORK).expect("component");
        let mut runtime =
            crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::store::BoxHost::new())
                .expect("runtime");
        crate::component::mmio::initialize_test_mmio(&mut runtime)
            .await
            .expect("MMIO service");
        let host = crate::component::context::DeviceContext::with_ram(
            crate::memory::GuestRam::new(64 * 1024).expect("RAM"),
        );
        let channel = crate::component::network::register_device(
            &mut runtime,
            host,
            &component,
            Arc::new(Open),
            Vec::new(),
            GuestNetworkConfig::default(),
            Arc::new(|_| Ok(())),
        )
        .expect("shared network");
        let running = runtime.prepare().await.unwrap().start();
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
        let component = Component::new(&engine, crate::test_fixtures::wasm::NETWORK)
            .expect("component compiles");
        let mut host = crate::component::context::DeviceContext::new(64 * 1024).unwrap();
        let memory_calls = host.memory_read_import_counters();
        let ram = host.guest_ram().clone();
        host.guest_write(0x2002, &257u16.to_le_bytes())
            .expect("avail index writes");
        let channel = crate::component::network::instantiate(
            &engine,
            host,
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
        let memory = crate::memory::BoundedMemory::new(&ram);
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
        descriptor[8..12].copy_from_slice(&12_u32.to_le_bytes());
        descriptor[12..14].copy_from_slice(&1_u16.to_le_bytes());
        descriptor[14..16].copy_from_slice(&4_u16.to_le_bytes());
        memory.write(0x1030, &descriptor).expect("first descriptor");
        descriptor[..8].copy_from_slice(&0x4010_u64.to_le_bytes());
        descriptor[8..12].copy_from_slice(&14_u32.to_le_bytes());
        descriptor[12..14].copy_from_slice(&0_u16.to_le_bytes());
        memory
            .write(0x1040, &descriptor)
            .expect("second descriptor");
        memory
            .write(0x200a, &3_u16.to_le_bytes())
            .expect("valid head");
        memory.write(0x4000, &[0; 26]).expect("valid frame");
        let before = memory_calls[1].load(std::sync::atomic::Ordering::Relaxed);
        memory
            .write(0x2002, &260_u16.to_le_bytes())
            .expect("valid request");
        channel
            .write(0x50, &1_u32.to_le_bytes())
            .expect("notify valid request");
        wait_for_used(&channel, &memory, [3, 0]).await;
        assert_eq!(
            memory_calls[1].load(std::sync::atomic::Ordering::Relaxed) - before,
            1
        );
        channel.close().expect("close worker");
    }

    fn stage_scattered_tx_queue(memory: &crate::memory::BoundedMemory<'_>) {
        let mut descriptors = [0; 32];
        descriptors[..8].copy_from_slice(&0x4000_u64.to_le_bytes());
        descriptors[8..12].copy_from_slice(&12_u32.to_le_bytes());
        descriptors[12..14].copy_from_slice(&1_u16.to_le_bytes());
        descriptors[14..16].copy_from_slice(&1_u16.to_le_bytes());
        descriptors[16..24].copy_from_slice(&0x4010_u64.to_le_bytes());
        descriptors[24..28].copy_from_slice(&14_u32.to_le_bytes());
        memory.write(0x1000, &descriptors).expect("descriptors");
        memory.write(0x2004, &[0; 512]).expect("available heads");
        memory.write(0x4000, &[0; 26]).expect("frame");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "component transport microbenchmark; run with --release --ignored --nocapture"]
    #[allow(unsafe_code)]
    async fn benchmark_scattered_tx_component_memory_calls() {
        use crate::engine::precompile_component;
        use std::sync::atomic::Ordering;

        const FRAMES_PER_SAMPLE: u16 = 128;
        const SAMPLES: usize = 7;

        let engine = device_engine().expect("engine");
        let current_wasm =
            std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
                "../../components/target/wasm-components/release/terra_network_component.wasm",
            ))
            .expect("current network component");
        let mut components = Vec::new();
        if let Some(path) = std::env::var_os("TERRA_BASELINE_NETWORK_COMPONENT") {
            let baseline_aot = std::fs::read(path).expect("baseline network AOT");
            // SAFETY: The benchmark reads the trusted artifact saved from this repository's baseline build.
            let baseline = unsafe { Component::deserialize(&engine, baseline_aot) }
                .expect("baseline network component");
            components.push(("baseline", baseline));
        }
        let current_aot =
            precompile_component(&engine, &current_wasm).expect("current network AOT");
        // SAFETY: `precompile_component` produced this artifact with the same engine above.
        let current = unsafe { Component::deserialize(&engine, current_aot) }
            .expect("current network component");
        components.push(("candidate", current));

        if std::env::var_os("TERRA_BENCH_CANDIDATE_FIRST").is_some() {
            components.reverse();
        }
        for (version, component) in components {
            let host = crate::component::context::DeviceContext::new(64 * 1024).expect("RAM");
            let calls = host.memory_read_import_counters();
            let ram = host.guest_ram().clone();
            let channel = crate::component::network::instantiate(
                &engine,
                host,
                &component,
                Arc::new(Open),
                Vec::new(),
                GuestNetworkConfig::default(),
                Arc::new(|_| Ok(())),
            )
            .await
            .expect("network actor");
            for (offset, value) in [
                (0x70, 1_u32),
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
                    .expect("queue setup");
            }
            let memory = crate::memory::BoundedMemory::new(&ram);
            stage_scattered_tx_queue(&memory);
            let mut times = Vec::new();
            for sample in 0..=SAMPLES {
                let before = [
                    calls[0].load(Ordering::Relaxed),
                    calls[1].load(Ordering::Relaxed),
                ];
                let available = u16::try_from(sample + 1).expect("sample") * FRAMES_PER_SAMPLE;
                let start = std::time::Instant::now();
                memory
                    .write(0x2002, &available.to_le_bytes())
                    .expect("available index");
                channel
                    .write(0x50, &1_u32.to_le_bytes())
                    .expect("queue bell");
                wait_for_used(&channel, &memory, available.to_le_bytes()).await;
                let elapsed = start.elapsed();
                let direct = calls[0].load(Ordering::Relaxed) - before[0];
                let batched = calls[1].load(Ordering::Relaxed) - before[1];
                if sample != 0 {
                    assert_eq!(
                        batched,
                        if version == "baseline" {
                            0
                        } else {
                            u64::from(FRAMES_PER_SAMPLE)
                        }
                    );
                    times.push(elapsed.as_nanos() / u128::from(FRAMES_PER_SAMPLE));
                }
                if sample == SAMPLES {
                    times.sort_unstable();
                    println!(
                        "terra_network_memory_bench version={version} workload=transport_tx_scattered frames_per_sample={FRAMES_PER_SAMPLE} samples={SAMPLES} median_ns_per_frame={} direct_read_calls_per_sample={direct} read_ranges_calls_per_sample={batched}",
                        times[SAMPLES / 2],
                    );
                }
            }
            channel.close().expect("network close");
        }
    }
}
