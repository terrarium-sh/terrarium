//! Wasm VMM initialization and scoped native host capabilities.

pub(crate) mod bindings;
pub(crate) mod boot;
pub mod interrupts;
pub mod lifecycle;
pub mod mmio;
mod native_task;
pub mod teardown;
mod vcpu;
pub(crate) mod virtualization;

pub use boot::BootEntry;
pub use native_task::VcpuReaper;
pub(crate) use vcpu::EXIT_TIMEOUT;
pub use vcpu::{NativeVcpu, Vcpu};
pub use virtualization::{MachineHandle, PreparedMachine, RamGrant, StartedVcpus, VirtualMachine};

use std::sync::{Arc, Mutex, OnceLock};
use wasmtime::component::Component;

use crate::box_runtime::BoxRuntime;
use crate::machine::DeviceKind;
use bindings::{Vmm, exports};
use mmio::bridge::BridgeContext;
use mmio::{COMMAND_CAPACITY, CONTROL_CAPACITY, DevicePlan, DeviceRegistry, Pending};
use wasmtime::component::ResourceTable;

use crate::box_runtime::store::BoxHost;
pub use crate::component::vmm::bindings::platform;
pub use crate::component::vmm::bindings::platform::{Completion, Error, Exit};

type Completed = Arc<dyn Fn(u32, bool) -> wasmtime::Result<()> + Send + Sync>;

pub(crate) struct PlatformHost {
    table: ResourceTable,
    completed: Option<Completed>,
    virtualization: virtualization::VirtualizationHost,
    pending_vcpus: Vec<NativeVcpu>,
    pub(crate) native_teardown: teardown::NativeTeardown,
}

impl PlatformHost {
    pub(crate) fn with_native_teardown(native_teardown: teardown::NativeTeardown) -> Self {
        Self {
            table: ResourceTable::new(),
            completed: None,
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

impl platform::Host for PlatformHost {
    fn completed(&mut self, slot: u32, failed: bool) -> wasmtime::Result<Result<(), Error>> {
        let Some(completed) = &self.completed else {
            return Ok(Err(Error::Unavailable));
        };
        Ok(completed(slot, failed).map_err(|_| Error::BadExit))
    }
}

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
    pub(crate) bridge: crate::box_runtime::ComponentLoop,
    pub(crate) lifecycle_loop: crate::box_runtime::ComponentLoop,
    pub(crate) machine: exports::terra::mmio::machine::Guest,
    pub(crate) interrupts: exports::terra::mmio::interrupts::Guest,
    pub(crate) routing: exports::terra::mmio::router::Guest,
    sender: tokio::sync::mpsc::Sender<Pending>,
    control_sender: tokio::sync::mpsc::Sender<Pending>,
    admission: Arc<Mutex<Option<String>>>,
    pub(crate) devices: DeviceRegistry,
    pub(crate) device_plan: Vec<DevicePlan>,
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
    pub(crate) fn unprepared_count(&self) -> usize {
        self.device_plan.len()
    }
    pub(crate) fn has_component(&self, kind: DeviceKind) -> bool {
        self.device_plan.iter().any(|plan| plan.device.kind == kind)
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
        let linker = vmm_component_linker(self.store.engine())?;
        let instance = Vmm::instantiate_async(&mut self.store, component, &linker).await?;
        let router = instance.terra_mmio_router();
        let machine = instance.terra_mmio_machine();
        let interrupts = instance.terra_mmio_interrupts();
        let lifecycle_bindings = instance.terra_mmio_lifecycle();
        let (sender, receiver) = tokio::sync::mpsc::channel(COMMAND_CAPACITY);
        let (control_sender, control_receiver) = tokio::sync::mpsc::channel(CONTROL_CAPACITY);
        let admission = Arc::new(Mutex::new(None));
        let failure = Arc::new(Mutex::new(None));
        let devices: DeviceRegistry = Arc::new(OnceLock::new());
        let bridge = mmio::bridge::create_component_loop(
            BridgeContext {
                access: router.func_access(),
                control: router.func_control(),
                devices: Arc::clone(&devices),
                admission: Arc::clone(&admission),
            },
            sender.clone(),
            control_sender.clone(),
            receiver,
            control_receiver,
        );
        let lifecycle_loop = lifecycle::create_component_loop(
            lifecycle_bindings.func_run(),
            self.lifecycle_notifier(),
        );
        self.store.data_mut().platform.completed =
            Some(mmio::completion_callback(Arc::clone(&devices)));
        self.vmm = Some(VmmInstance {
            bridge,
            lifecycle_loop,
            machine: machine.clone(),
            interrupts: interrupts.clone(),
            routing: router.clone(),
            sender,
            control_sender,
            admission,
            devices,
            device_plan: Vec::new(),
            failure,
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
    let mut linker = crate::component::context::device_component_linker(engine)?;
    crate::component::vmm::add_to_linker(&mut linker)?;
    Ok(linker)
}

#[cfg(test)]
pub(crate) async fn initialize_test_vmm(root: &mut BoxRuntime) -> wasmtime::Result<()> {
    let component = Component::new(root.store.engine(), crate::test_fixtures::wasm::VMM)?;
    root.initialize_vmm(&component).await
}
