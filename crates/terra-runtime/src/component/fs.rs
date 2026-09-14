//! Filesystem component bindings over the box-wide MMIO router.

pub mod host;
#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "test-support"))]
use std::sync::Arc;
use std::time::Duration;

use wasmtime::component::{Component, Instance, TypedFunc};

use crate::component::fs::host::{FsHost, fs_component_linker_with};
use crate::engine::{DeviceError, component_export};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

type Configure = TypedFunc<(String, u32), (Result<(), DeviceError>,)>;

pub use crate::component::Interrupt;

use crate::component::DeviceChannel;

type FsState = crate::component::worker::Worker<DeviceError>;

fn transport_error(operation: &str, error: DeviceError) -> wasmtime::Error {
    wasmtime::Error::msg(format!("filesystem {operation}: {error:?}"))
}

#[cfg(any(test, feature = "test-support"))]
pub async fn instantiate(
    store: wasmtime::Store<FsHost>,
    component: &Component,
    tag: &str,
    max_nodes: u32,
    interrupt: Interrupt,
) -> wasmtime::Result<DeviceChannel> {
    let engine = store.engine().clone();
    let mut runtime =
        crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new())?;
    let channel = instantiate_shared(
        &mut runtime,
        store.into_data(),
        component,
        tag,
        max_nodes,
        interrupt,
    )
    .await?;
    Ok(DeviceChannel {
        _runtime: Some(Arc::new(runtime.start())),
        ..channel
    })
}

pub async fn instantiate_shared(
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
    .await
}

pub async fn grant_shared(
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
    let factory: crate::component::vmm::workers::Factory = Box::new(move || {
        Box::pin(async move {
            create_worker(
                child(crate::box_runtime::BoxHost::new())?,
                host()?,
                &component,
                tag,
                max_nodes,
                interrupt,
            )
            .await
        })
    });
    let mmio = crate::component::vmm::mmio::MmioDevice::grant_worker(
        runtime,
        crate::component::vmm::machine::DeviceKind::Fs,
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
    host: FsHost,
    component: &Component,
    tag: String,
    max_nodes: u32,
    interrupt: Interrupt,
) -> wasmtime::Result<(
    crate::box_runtime::BoxRuntime,
    crate::component::vmm::mmio::Serve,
)> {
    let wake = host.device.interrupt_notification();
    let slot = child.add_fs(host)?;
    let linker = fs_component_linker_with(
        child.store.engine(),
        crate::engine::DeviceWasiGetters {
            cli: shared_fs_cli,
            clocks: shared_fs_clocks,
        },
        shared_filesystem,
        shared_fs_host,
    )?;
    let export = |name| component_export(component, "terra:fs/transport@0.1.0", name, "filesystem");
    let instance: Instance = tokio::time::timeout(
        REQUEST_TIMEOUT,
        linker.instantiate_async(&mut child.store, component),
    )
    .await
    .map_err(|_| wasmtime::Error::msg("filesystem component setup timed out"))??;
    let configure: Configure = instance.get_typed_func(&mut child.store, export("configure")?)?;
    let (configured,) = tokio::time::timeout(
        REQUEST_TIMEOUT,
        configure.call_async(&mut child.store, (tag, max_nodes)),
    )
    .await
    .map_err(|_| wasmtime::Error::msg("filesystem component configuration timed out"))??;
    configured.map_err(|error| transport_error("configure", error))?;
    let state = FsState {
        run: instance.get_typed_func(&mut child.store, export("run")?)?,
        interrupt,
    };
    let serve: crate::component::vmm::mmio::Serve = instance.get_typed_func(
        &mut child.store,
        component_export(component, "terra:mmio/device@0.1.0", "serve", "filesystem")?,
    )?;
    state.register(&mut child, wake, "fs", move |host| {
        let host = host
            .filesystems
            .get_mut(slot)
            .ok_or_else(|| wasmtime::Error::msg("fs host missing"))?;
        host.device.end_window();
        Ok(host.device.interrupt_level())
    })?;
    Ok((child, serve))
}

fn shared_fs_cli(host: &mut crate::box_runtime::BoxHost) -> wasmtime_wasi::cli::WasiCliCtxView<'_> {
    use wasmtime_wasi::cli::WasiCliView;

    host.filesystems[0].device.cli()
}

fn shared_fs_clocks(
    host: &mut crate::box_runtime::BoxHost,
) -> wasmtime_wasi::clocks::WasiClocksCtxView<'_> {
    use wasmtime_wasi::clocks::WasiClocksView;

    host.filesystems[0].device.clocks()
}

fn shared_filesystem(
    host: &mut crate::box_runtime::BoxHost,
) -> wasmtime_wasi::filesystem::WasiFilesystemCtxView<'_> {
    use wasmtime_wasi::filesystem::WasiFilesystemView;

    host.filesystems[0].filesystem()
}

fn shared_fs_host(host: &mut crate::box_runtime::BoxHost) -> &mut FsHost {
    &mut host.filesystems[0]
}
