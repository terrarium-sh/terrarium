pub mod streams;

pub(crate) mod bindings {
    wasmtime::component::bindgen!({
        world: "device",
        path: "../../components/vsock-frontend/wit",
        imports: { default: trappable },
        exports: { default: async },
        with: {
            "terra:vsock/frontend-stream@0.1.0": super::streams::frontend_stream,
            "terra:mmio/types@0.1.0": crate::component::mmio::bindings::canonical::types,
        },
    });
}

use crate::box_runtime::{BoxRuntime, StoreHost, StoreState};
use crate::component::context::{DeviceContext, DeviceHost};
use crate::component::network::{HostServiceAddresses, NetworkBackend, NetworkHost, PortMapping};
use crate::component::vmm::virtualization::RamGrant;
use crate::component::{InterruptCallback, MmioDevice};
use crate::machine::DeviceKind;
use streams::FrontendStreams;
use wasmtime_wasi::{WasiCtxView, WasiView};

const TABLE_SLACK_ENTRIES: usize = 256;

pub struct VsockHost {
    context: DeviceContext,
    streams: FrontendStreams,
    network: NetworkHost,
}

impl VsockHost {
    #[must_use]
    pub fn new(
        mut context: DeviceContext,
        streams: FrontendStreams,
        backend: Option<NetworkBackend>,
    ) -> Self {
        context.ctx().table.set_max_capacity(
            terra_network::MAX_RESOURCES + terra_network::MAX_LISTENERS + TABLE_SLACK_ENTRIES,
        );
        Self {
            context,
            streams,
            network: NetworkHost::new(backend),
        }
    }
}

impl AsMut<NetworkHost> for VsockHost {
    fn as_mut(&mut self) -> &mut NetworkHost {
        &mut self.network
    }
}

impl AsMut<NetworkHost> for StoreState<VsockHost> {
    fn as_mut(&mut self) -> &mut NetworkHost {
        &mut self.network
    }
}

impl DeviceHost for VsockHost {
    fn context(&mut self) -> &mut DeviceContext {
        &mut self.context
    }
}

impl WasiView for VsockHost {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        self.context.ctx()
    }
}

impl StoreHost for VsockHost {
    fn retire(mut self) {
        self.streams.retire();
        self.network.disconnect();
    }
}

pub fn vsock_component_linker(
    engine: &wasmtime::Engine,
) -> wasmtime::Result<wasmtime::component::Linker<StoreState<VsockHost>>> {
    let mut linker = wasmtime::component::Linker::new(engine);
    crate::component::bindings::memory::add_to_linker::<
        StoreState<VsockHost>,
        wasmtime::component::HasSelf<DeviceContext>,
    >(&mut linker, |state| &mut state.context)?;
    crate::component::bindings::interrupt::add_to_linker::<
        StoreState<VsockHost>,
        wasmtime::component::HasSelf<DeviceContext>,
    >(&mut linker, |state| &mut state.context)?;
    streams::add_frontend_stream_to_linker(&mut linker, |state: &mut StoreState<VsockHost>| {
        &mut state.streams
    })?;
    crate::component::clocks::add_monotonic_wait_for(&mut linker)?;
    crate::component::network::add_broker_to_linker(&mut linker)?;
    Ok(linker)
}

pub fn register_device(
    runtime: &mut BoxRuntime,
    ram: impl Into<RamGrant> + Send,
    artifact: crate::TrustedArtifact,
    streams: FrontendStreams,
    network_backend: Option<NetworkBackend>,
    port_mappings: Vec<PortMapping>,
    interrupt: InterruptCallback,
) -> wasmtime::Result<MmioDevice> {
    let component = artifact.deserialize(runtime.store.engine())?;
    let child = runtime.child_factory();
    let ram = ram.into();
    let network_config = network_backend.as_ref().map(|backend| {
        HostServiceAddresses::build_component_config(
            backend.host_service_ports().to_vec(),
            port_mappings,
            runtime.store.data().network_memory_limit(),
        )
    });
    let is_network_enabled = network_backend.is_some();
    runtime.grant_device_worker(DeviceKind::Vsock, async move {
        let mut child = child(VsockHost::new(
            DeviceContext::with_ram(ram.resolve()?),
            streams,
            network_backend,
        ));
        if is_network_enabled {
            child.store.data_mut().use_network_memory_limit();
        }
        let linker = vsock_component_linker(child.store.engine())?;
        let instance =
            bindings::Device::instantiate_async(&mut child.store, &component, &linker).await?;
        let api = instance.terra_vsock_frontend_api();
        let (configured,) = api
            .func_configure_device()
            .call_async(&mut child.store, (network_config.as_ref(),))
            .await?;
        configured
            .map_err(|error| wasmtime::Error::msg(format!("vsock configuration: {error:?}")))?;
        let serve = instance.terra_mmio_device().func_serve();
        let wake = child.store.data_mut().context.interrupt_notification();
        crate::component::device_loop::DeviceLoop {
            run: api.func_run(),
            interrupt,
        }
        .register(&mut child, wake, "vsock")?;
        Ok((child, serve))
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn frontend_clock_linker_supplies_opening_deadline_timer() {
        let engine = crate::engine::device_engine().unwrap();
        let component = wasmtime::component::Component::new(
            &engine,
            r#"(component
            (import "wasi:clocks/monotonic-clock@0.3.1" (instance
                (export "wait-for" (func async (param "duration" u64))))))"#,
        )
        .unwrap();
        super::vsock_component_linker(&engine)
            .unwrap()
            .instantiate_pre(&component)
            .unwrap();
    }
}
