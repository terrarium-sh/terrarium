//! Filesystem component bindings over the box-wide MMIO router.

mod bindings;
mod file_events;
mod grant;
mod host;
mod metadata;
mod resource_linker;
#[cfg(test)]
mod stalled_io;
#[cfg(test)]
mod tests;

use crate::machine::DeviceKind;

#[cfg(test)]
use std::sync::Arc;

use wasmtime::component::Component;

use bindings::FsComponent;
pub use bindings::{FilesystemStat, FsDeviceError, FsError};
pub use grant::{ShareGrant, share_notification_budgets, share_tag};
pub use host::{FsHost, fs_component_linker};

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

use crate::component::InterruptCallback;
use crate::component::MmioDevice;
use crate::component::device_loop::DeviceLoop;

fn transport_error(operation: &str, error: FsDeviceError) -> wasmtime::Error {
    wasmtime::Error::msg(format!("filesystem {operation}: {error:?}"))
}

#[cfg(test)]
pub(crate) async fn instantiate(
    engine: &wasmtime::Engine,
    host: FsHost,
    component: &Component,
    tag: &str,
    max_nodes: u32,
    interrupt: InterruptCallback,
) -> wasmtime::Result<crate::component::StandaloneDevice> {
    let mut runtime =
        crate::box_runtime::BoxRuntime::new(engine, crate::box_runtime::store::BoxHost::new())?;
    crate::component::mmio::initialize_test_mmio(&mut runtime).await?;
    let channel = register_device(&mut runtime, host, component, tag, max_nodes, interrupt)?;
    Ok(crate::component::StandaloneDevice {
        _runtime: Arc::new(runtime.prepare().await?.start()),
        device: channel,
    })
}

pub fn register_device(
    runtime: &mut crate::box_runtime::BoxRuntime,
    host: FsHost,
    component: &Component,
    tag: &str,
    max_nodes: u32,
    interrupt: InterruptCallback,
) -> wasmtime::Result<MmioDevice> {
    register_device_with_host_factory(
        runtime,
        move || Ok(host),
        component,
        tag,
        max_nodes,
        interrupt,
    )
}

pub fn register_device_with_host_factory(
    runtime: &mut crate::box_runtime::BoxRuntime,
    create_host: impl FnOnce() -> wasmtime::Result<FsHost> + Send + 'static,
    component: &Component,
    tag: &str,
    max_nodes: u32,
    interrupt: InterruptCallback,
) -> wasmtime::Result<MmioDevice> {
    let tag = tag.to_owned();
    let child = runtime.child_factory();
    let component = component.clone();
    let setup = crate::box_runtime::setup::setup(
        async move { create_worker(child(create_host()?), &component, tag, max_nodes, interrupt).await },
        runtime.shutdown_receiver(),
    );
    let setup: crate::box_runtime::setup::Setup = Box::new(move |requests| {
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
    runtime.grant_device_setup(DeviceKind::Fs, setup)
}

async fn create_worker(
    mut child: crate::box_runtime::DeviceWorker<FsHost>,
    component: &Component,
    tag: String,
    max_nodes: u32,
    interrupt: InterruptCallback,
) -> wasmtime::Result<(
    crate::box_runtime::DeviceWorker<FsHost>,
    crate::component::mmio::Serve,
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
    let device_loop = DeviceLoop {
        run: transport.func_run(),
        interrupt,
    };
    let serve = instance.terra_mmio_device().func_serve();
    device_loop.register(&mut child, wake, "fs")?;
    Ok((child, serve))
}
