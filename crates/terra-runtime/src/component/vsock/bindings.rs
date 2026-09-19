use crate::box_runtime::BoxHost;
use crate::engine::{DeviceHost, component_export};
use std::time::Duration;
use wasmtime::Store;
use wasmtime::component::{
    Component, ComponentNamedList, ComponentType, Instance, Lift, Lower, StreamReader, TypedFunc,
};

const COMPONENT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, ComponentType, Lift)]
#[component(enum)]
#[repr(u8)]
pub enum Error {
    #[component(name = "table-full")]
    TableFull,
    #[component(name = "backpressure")]
    Backpressure,
    #[component(name = "unknown-connection")]
    UnknownConnection,
    #[component(name = "malformed")]
    Malformed,
}

#[derive(ComponentType, Lift, Lower)]
#[component(variant)]
pub enum HostEvent {
    #[component(name = "diagnostic")]
    Diagnostic(Vec<u8>),
    #[component(name = "exit")]
    Exit(i32),
}

type Events = TypedFunc<(), (StreamReader<HostEvent>,)>;

pub struct VsockComponent {
    events: Events,
    run: TypedFunc<(), (Result<(), Error>,)>,
    mmio_serve: crate::component::vmm::mmio::Serve,
}

impl VsockComponent {
    async fn bind(
        component: &Component,
        instance: &Instance,
        mut store: &mut Store<BoxHost>,
    ) -> wasmtime::Result<Self> {
        let get = |name| component_export(component, "terra:vsock/api@0.1.0", name, "vsock");
        let events = instance.get_typed_func(&mut store, get("events")?)?;
        let run = instance.get_typed_func(&mut store, get("run")?)?;
        let configure = instance.get_typed_func::<(), (Result<(), crate::engine::DeviceError>,)>(
            &mut store,
            get("configure-device")?,
        )?;
        let configured =
            tokio::time::timeout(COMPONENT_TIMEOUT, configure.call_async(&mut store, ()))
                .await
                .map_err(|_| wasmtime::Error::msg("vsock component configure timed out"))??;
        configured
            .0
            .map_err(|error| wasmtime::Error::msg(format!("vsock configure: {error:?}")))?;
        let mmio_serve = instance.get_typed_func(
            &mut store,
            component_export(component, "terra:mmio/device@0.1.0", "serve", "vsock")?,
        )?;
        Ok(Self {
            events,
            run,
            mmio_serve,
        })
    }

    pub async fn instantiate_shared(
        runtime: &mut crate::box_runtime::BoxRuntime,
        host: DeviceHost,
        component: &Component,
    ) -> wasmtime::Result<Self> {
        if !runtime.store.data().vsock.is_empty() {
            return Err(wasmtime::Error::msg("box already has a vsock component"));
        }
        runtime.add_vsock(host)?;
        let engine = runtime.store.engine();
        let linker = crate::engine::vsock_component_linker_with_host(
            engine,
            crate::engine::DeviceWasiGetters {
                cli: BoxHost::vsock_cli,
                clocks: BoxHost::vsock_clocks,
            },
            BoxHost::vsock_device,
            BoxHost::vsock_random,
            BoxHost::vsock_service,
        )?;
        let instance = tokio::time::timeout(
            COMPONENT_TIMEOUT,
            linker.instantiate_async(&mut runtime.store, component),
        )
        .await
        .map_err(|_| wasmtime::Error::msg("vsock component initialization timed out"))??;
        Self::bind(component, &instance, &mut runtime.store).await
    }

    pub async fn events_store(
        &self,
        store: &mut Store<BoxHost>,
    ) -> wasmtime::Result<StreamReader<HostEvent>> {
        self.call_store(store, self.events, ())
            .await
            .map(|events| events.0)
    }
    async fn call_store<P, R>(
        &self,
        store: &mut Store<BoxHost>,
        function: TypedFunc<P, R>,
        params: P,
    ) -> wasmtime::Result<R>
    where
        P: ComponentNamedList + Lower + 'static,
        R: ComponentNamedList + Lift + 'static,
    {
        tokio::time::timeout(COMPONENT_TIMEOUT, function.call_async(store, params))
            .await
            .map_err(|_| wasmtime::Error::msg("vsock component timed out"))?
    }

    #[must_use]
    pub fn run_function(&self) -> TypedFunc<(), (Result<(), Error>,)> {
        self.run
    }

    #[must_use]
    pub fn mmio_serve(&self) -> crate::component::vmm::mmio::Serve {
        self.mmio_serve
    }
}
