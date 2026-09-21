//! Filesystem component bindings over the box-wide MMIO router.

mod file_events;
pub mod host;
#[cfg(test)]
mod stalled_io;
#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "test-support"))]
use std::sync::Arc;

use wasmtime::component::Component;

use crate::component::fs::host::{FsComponent, FsDeviceError, FsHost, fs_component_linker};

pub(crate) const MAX_BLOCKING_THREADS: usize = 33;

pub(crate) struct FilesystemRuntime {
    runtime: Option<tokio::runtime::Runtime>,
    handle: tokio::runtime::Handle,
}

impl FilesystemRuntime {
    fn new() -> std::io::Result<Self> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(MAX_BLOCKING_THREADS)
            .thread_name("terra-filesystem")
            .enable_all()
            .build()
            .map(|runtime| Self {
                handle: runtime.handle().clone(),
                runtime: Some(runtime),
            })
    }

    pub(crate) fn handle(&self) -> tokio::runtime::Handle {
        self.handle.clone()
    }
}

impl Drop for FilesystemRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

pub use crate::component::Interrupt;

use crate::component::DeviceChannel;

type FsState = crate::component::worker::Worker<FsDeviceError>;

fn transport_error(operation: &str, error: FsDeviceError) -> wasmtime::Error {
    wasmtime::Error::msg(format!("filesystem {operation}: {error:?}"))
}

#[cfg(any(test, feature = "test-support"))]
pub async fn instantiate(
    engine: &wasmtime::Engine,
    host: FsHost,
    component: &Component,
    tag: &str,
    max_nodes: u32,
    interrupt: Interrupt,
) -> wasmtime::Result<crate::component::StandaloneDevice> {
    let mut runtime =
        crate::box_runtime::BoxRuntime::new(engine, crate::box_runtime::store::BoxHost::new())?;
    crate::component::vmm::mmio::initialize_test_router(&mut runtime).await?;
    let channel = instantiate_shared(&mut runtime, host, component, tag, max_nodes, interrupt)?;
    Ok(crate::component::StandaloneDevice {
        _runtime: Arc::new(runtime.prepare().await?.start()),
        device: channel,
    })
}

pub fn instantiate_shared(
    runtime: &mut crate::box_runtime::BoxRuntime,
    host: FsHost,
    component: &Component,
    tag: &str,
    max_nodes: u32,
    interrupt: Interrupt,
) -> wasmtime::Result<DeviceChannel> {
    grant_shared(
        runtime,
        move || Ok(host),
        component,
        tag,
        max_nodes,
        interrupt,
    )
}

pub fn grant_shared(
    runtime: &mut crate::box_runtime::BoxRuntime,
    host: impl FnOnce() -> wasmtime::Result<FsHost> + Send + 'static,
    component: &Component,
    tag: &str,
    max_nodes: u32,
    interrupt: Interrupt,
) -> wasmtime::Result<DeviceChannel> {
    let tag = tag.to_owned();
    let child = runtime.child_factory();
    let component = component.clone();
    let setup = crate::component::vmm::workers::setup(
        async move { create_worker(child(host()?), &component, tag, max_nodes, interrupt).await },
        runtime.shutdown_receiver(),
    );
    let setup: crate::component::vmm::workers::Setup = Box::new(move |requests| {
        Box::pin(async move {
            let executor = FilesystemRuntime::new()?;
            let handle = executor.handle();
            let worker_handle = handle.clone();
            tokio_util::task::AbortOnDropHandle::new(handle.spawn(async move {
                let mut prepared = setup(requests).await?;
                prepared.worker = prepared.worker.run_on(worker_handle, executor);
                Ok(prepared)
            }))
            .await?
        })
    });
    runtime.grant_device_setup(
        crate::component::vmm::bindings::machine::DeviceKind::Fs,
        setup,
    )
}

async fn create_worker(
    mut child: crate::box_runtime::DeviceWorker<FsHost>,
    component: &Component,
    tag: String,
    max_nodes: u32,
    interrupt: Interrupt,
) -> wasmtime::Result<(
    crate::box_runtime::DeviceWorker<FsHost>,
    crate::component::vmm::mmio::Serve,
)> {
    child.store.data_mut().initialize_events().await;
    #[cfg(test)]
    let io_gate = child.store.data().io_gate.clone();
    let wake = child.store.data().device.interrupt_notification();
    let linker = fs_component_linker(child.store.engine())?;
    #[cfg(test)]
    let linker = stalled_io::install_io_gate(linker, io_gate)?;
    let instance = FsComponent::instantiate_async(&mut child.store, component, &linker)
        .await
        .map_err(|error| error.context("filesystem component initialization"))?;
    let transport = instance.terra_fs_transport();
    let configure = transport.func_configure();
    let (configured,) = configure
        .call_async(&mut child.store, (tag, max_nodes))
        .await
        .map_err(|error| error.context("filesystem component configuration"))?;
    configured.map_err(|error| transport_error("configure", error))?;
    let state = FsState {
        run: transport.func_run(),
        interrupt,
    };
    let serve = instance.terra_mmio_device().func_serve();
    state.register(&mut child, wake, "fs")?;
    Ok((child, serve))
}
