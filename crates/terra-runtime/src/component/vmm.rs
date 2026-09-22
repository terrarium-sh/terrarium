//! Wasm VMM initialization and scoped native host capabilities.

pub(crate) mod bindings;
pub(crate) mod boot;
pub mod lifecycle;
mod native_task;
pub mod teardown;
mod vcpu;
pub(crate) mod virtualization;

pub use boot::BootEntry;
pub use native_task::VcpuReaper;
pub(crate) use vcpu::EXIT_TIMEOUT;
pub use vcpu::{NativeVcpu, Vcpu};
pub use virtualization::{MachineHandle, PreparedMachine, RamGrant, StartedVcpus, VirtualMachine};

use std::sync::{Arc, Mutex};
use wasmtime::component::Component;

use crate::box_runtime::BoxRuntime;
use bindings::Vmm;
use bindings::exports;
use wasmtime::component::ResourceTable;

use crate::box_runtime::store::BoxHost;
pub use crate::component::vmm::bindings::platform;
pub use crate::component::vmm::bindings::platform::{Completion, Error, Exit};

pub(crate) struct PlatformHost {
    table: ResourceTable,
    virtualization: virtualization::VirtualizationHost,
    pending_vcpus: Vec<NativeVcpu>,
    pub(crate) native_teardown: teardown::NativeTeardown,
}

impl PlatformHost {
    pub(crate) fn with_native_teardown(native_teardown: teardown::NativeTeardown) -> Self {
        Self {
            table: ResourceTable::new(),
            virtualization: virtualization::VirtualizationHost::default(),
            pending_vcpus: Vec::new(),
            native_teardown,
        }
    }
}

impl Default for PlatformHost {
    fn default() -> Self {
        Self::with_native_teardown(teardown::NativeTeardown::new())
    }
}

pub(crate) struct Platform;

impl wasmtime::component::HasData for Platform {
    type Data<'a> = &'a mut PlatformHost;
}

impl platform::Host for PlatformHost {}

pub(crate) fn add_to_linker(
    linker: &mut wasmtime::component::Linker<BoxHost>,
) -> wasmtime::Result<()> {
    platform::add_to_linker::<BoxHost, Platform>(linker, |host| &mut host.platform)?;
    virtualization::add_to_linker(linker)?;
    lifecycle::add_to_linker(linker)
}

#[derive(Clone)]
pub struct FailureObservation {
    failure: Arc<Mutex<Option<String>>>,
}

impl FailureObservation {
    #[must_use]
    pub fn failure(&self) -> Option<String> {
        self.failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

pub(crate) struct VmmInstance {
    pub(crate) lifecycle_loop: crate::box_runtime::ComponentLoop,
    pub(crate) machine: exports::terra::mmio::machine::Guest,
    pub(crate) failure: Arc<Mutex<Option<String>>>,
}

impl VmmInstance {
    #[must_use]
    pub fn failure_observation(&self) -> FailureObservation {
        FailureObservation {
            failure: Arc::clone(&self.failure),
        }
    }
    #[cfg(test)]
    pub(crate) fn failure_sink(&self) -> Arc<Mutex<Option<String>>> {
        Arc::clone(&self.failure)
    }
    pub(crate) fn record_failure_in(failure: &Mutex<Option<String>>, error: &wasmtime::Error) {
        let mut failure = failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if failure.is_none() {
            *failure = Some(format!("{error:#}"));
        }
    }
}

impl BoxRuntime {
    pub async fn initialize_vmm(&mut self, component: &Component) -> wasmtime::Result<()> {
        if self.vmm.is_some() {
            return Err(wasmtime::Error::msg("VMM already initialized"));
        }
        let mmio = self
            .mmio
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("MMIO service missing"))?;
        self.store.data_mut().mmio_client = Some(mmio.client());
        let linker = vmm_component_linker(self.store.engine())?;
        let instance = Vmm::instantiate_async(&mut self.store, component, &linker).await?;
        let machine = instance.terra_mmio_machine();
        let lifecycle_bindings = instance.terra_mmio_lifecycle();
        let lifecycle_loop = lifecycle::create_component_loop(
            lifecycle_bindings.func_run(),
            self.lifecycle_notifier(),
        );
        self.vmm = Some(VmmInstance {
            lifecycle_loop,
            machine: machine.clone(),
            failure: Arc::clone(&mmio.failure),
        });
        Ok(())
    }

    pub async fn initialize_vmm_artifact(
        &mut self,
        artifacts: &crate::TrustedArtifacts,
    ) -> wasmtime::Result<()> {
        let component = artifacts.vmm().deserialize(self.store.engine())?;
        self.initialize_vmm(&component).await
    }
}

pub fn vmm_component_linker(
    engine: &wasmtime::Engine,
) -> wasmtime::Result<wasmtime::component::Linker<BoxHost>> {
    let mut linker = wasmtime::component::Linker::new(engine);
    crate::component::vmm::add_to_linker(&mut linker)?;
    crate::component::mmio::add_vmm_client_to_linker(&mut linker)?;
    Ok(linker)
}
