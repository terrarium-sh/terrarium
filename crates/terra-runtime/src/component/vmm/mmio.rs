//! Native setup and bindings for the Wasm MMIO router.

mod bridge;
mod device;

use bridge::{BridgeContext, run_bridge};
pub use device::MmioDevice;

use crate::box_runtime::{BoxHost, BoxRuntime};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use wasmtime::component::{Component, StreamReader, TypedFunc};

wasmtime::component::bindgen!({
    world: "vmm", path: "../../components/vmm/wit",
    imports: { default: trappable },
    with: {
        "terra:mmio/platform.vcpu": crate::component::vmm::Vcpu,
        "terra:mmio/virtualization.vm": crate::component::vmm::virtualization::Vm,
    },
});
pub use terra::mmio::types::{ControlReply, Error, Operation, Reply, Request, RoutedReply};
pub type Serve = TypedFunc<(StreamReader<Request>,), (StreamReader<Reply>,)>;
type ComposeWorkers = TypedFunc<(), (Result<(), Error>,)>;
type Remap = TypedFunc<(u32, u64, u64), (Result<(), Error>,)>;
type Access = TypedFunc<(u64, u8, u64, bool), (Result<RoutedReply, Error>,)>;
type Control = TypedFunc<(u32, Operation), (Result<ControlReply, Error>,)>;
type ConfigureVcpus = TypedFunc<(u8,), (Result<(), Error>,)>;
type RunLifecycle = TypedFunc<
    (),
    (Result<terra::mmio::lifecycle_platform::Event, terra::mmio::lifecycle_platform::Error>,),
>;
const DEVICE_SPAN: u64 = 0x1000;
const COMMAND_CAPACITY: usize = 64;
const CONTROL_CAPACITY: usize = 64;
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
const RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

enum Command {
    Access(u64, u8, u64, bool),
    Control(u32, Operation),
}
struct Pending {
    command: Command,
    reply: mpsc::SyncSender<wasmtime::Result<RoutedReply>>,
}

#[derive(Clone)]
struct DeviceRequestCounts {
    completed: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
}

fn submit(
    sender: &tokio::sync::mpsc::Sender<Pending>,
    admission: &Mutex<bool>,
    failure: &Mutex<Option<String>>,
    command: Command,
) -> wasmtime::Result<RoutedReply> {
    if let Some(failure) = recorded_failure(failure) {
        return Err(wasmtime::Error::msg(failure));
    }
    let response = enqueue(sender, admission, command)?;
    wait_for_reply(failure, &response)
}

fn recorded_failure(failure: &Mutex<Option<String>>) -> Option<String> {
    failure
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn wait_for_reply(
    failure: &Mutex<Option<String>>,
    response: &mpsc::Receiver<wasmtime::Result<RoutedReply>>,
) -> wasmtime::Result<RoutedReply> {
    response
        .recv_timeout(RESPONSE_TIMEOUT)
        .map_err(|error| wasmtime::Error::msg(format!("MMIO response: {error}")))?
        .map_err(|error| recorded_failure(failure).map_or(error, wasmtime::Error::msg))
}

fn enqueue(
    sender: &tokio::sync::mpsc::Sender<Pending>,
    admission: &Mutex<bool>,
    command: Command,
) -> wasmtime::Result<mpsc::Receiver<wasmtime::Result<RoutedReply>>> {
    let (reply, response) = mpsc::sync_channel(1);
    let admission = admission
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !*admission {
        return Err(wasmtime::Error::msg("MMIO bridge stopping"));
    }
    sender
        .try_send(Pending { command, reply })
        .map_err(|error| wasmtime::Error::msg(format!("MMIO bridge unavailable: {error}")))?;
    Ok(response)
}

pub(crate) struct Router {
    pub(crate) bridge: Option<crate::box_runtime::ComponentLoop>,
    pub(crate) entrypoint: Option<crate::box_runtime::ComponentLoop>,
    pub(crate) initialize_machine: crate::component::vmm::virtualization::InitializeMachine,
    pub(crate) compose_machine: crate::component::vmm::virtualization::ControlMachine,
    pub(crate) irq_lines_stage: crate::component::vmm::interrupts::Stage,
    pub(crate) device_irq_line: crate::component::vmm::interrupts::GsiLine,
    pub(crate) clear_irq_lines: crate::component::vmm::interrupts::ClearLines,
    pub(crate) ioapic_stage: crate::component::vmm::interrupts::Stage,
    pub(crate) ioapic_access: crate::component::vmm::interrupts::Access,
    pub(crate) ioapic_line: crate::component::vmm::interrupts::Line,
    pub(crate) ioapic_device_line: crate::component::vmm::interrupts::DeviceLine,
    pub(crate) ioapic_eoi: crate::component::vmm::interrupts::Eoi,
    compose_workers: ComposeWorkers,
    remap: Remap,
    configure_vcpus: ConfigureVcpus,
    sender: tokio::sync::mpsc::Sender<Pending>,
    control_sender: tokio::sync::mpsc::Sender<Pending>,
    admission: Arc<Mutex<bool>>,
    slots: Arc<AtomicUsize>,
    callbacks: Arc<Mutex<Vec<DeviceRequestCounts>>>,
    failure: Arc<Mutex<Option<String>>>,
}

impl Router {
    pub(crate) fn record_failure(&self, error: &wasmtime::Error) {
        Self::record_failure_in(&self.failure, error);
    }

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

fn router_error(error: Error) -> wasmtime::Error {
    wasmtime::Error::msg(format!("MMIO router: {error:?}"))
}

fn lifecycle_loop(
    function: RunLifecycle,
    lifecycle: crate::component::vmm::lifecycle::LifecycleNotifier,
) -> crate::box_runtime::ComponentLoop {
    Box::new(move |accessor| {
        Box::pin(async move {
            let (result,) = function.call_concurrent(accessor, ()).await?;
            let outcome = match result {
                Ok(terra::mmio::lifecycle_platform::Event::GuestExit(code)) => {
                    crate::component::vmm::lifecycle::Outcome::GuestExit(code)
                }
                Ok(terra::mmio::lifecycle_platform::Event::ComponentFailed) => {
                    crate::component::vmm::lifecycle::Outcome::ComponentFailed
                }
                Ok(terra::mmio::lifecycle_platform::Event::VcpuFinished) => {
                    crate::component::vmm::lifecycle::Outcome::VcpuFinished
                }
                Ok(terra::mmio::lifecycle_platform::Event::Deadline) => {
                    crate::component::vmm::lifecycle::Outcome::Deadline
                }
                Err(error) => {
                    return Err(wasmtime::Error::msg(format!("Wasm lifecycle: {error:?}")));
                }
            };
            lifecycle.complete(outcome);
            Ok(())
        })
    })
}

impl BoxRuntime {
    pub async fn configure_mmio_vcpus(&mut self, count: u32) -> wasmtime::Result<()> {
        let configure_vcpus = self
            .mmio
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("MMIO router missing"))?
            .configure_vcpus;
        let (result,) = configure_vcpus
            .call_async(&mut self.store, (u8::try_from(count)?,))
            .await?;
        result.map_err(router_error)
    }

    #[allow(clippy::too_many_lines)]
    pub async fn initialize_mmio(&mut self, component: &Component) -> wasmtime::Result<()> {
        if self.mmio.is_some() {
            return Err(wasmtime::Error::msg("MMIO router already initialized"));
        }
        let linker = mmio_component_linker(self.store.engine())?;
        let instance = linker.instantiate_async(&mut self.store, component).await?;
        let export = |name| {
            crate::engine::component_export(component, "terra:mmio/router@0.1.0", name, "MMIO")
        };
        let lifecycle_export = |name| {
            crate::engine::component_export(
                component,
                "terra:mmio/lifecycle@0.1.0",
                name,
                "VMM lifecycle",
            )
        };
        let run_lifecycle: RunLifecycle =
            instance.get_typed_func(&mut self.store, lifecycle_export("run")?)?;
        let machine_export = |name| {
            crate::engine::component_export(
                component,
                "terra:mmio/machine@0.1.0",
                name,
                "VMM machine",
            )
        };
        let initialize_machine =
            instance.get_typed_func(&mut self.store, machine_export("initialize")?)?;
        let compose_machine =
            instance.get_typed_func(&mut self.store, machine_export("compose")?)?;
        let irq_export = |name| {
            crate::engine::component_export(
                component,
                "terra:mmio/interrupts@0.1.0",
                name,
                "VMM interrupts",
            )
        };
        let irq_lines_stage =
            instance.get_typed_func(&mut self.store, irq_export("stage-irq-lines")?)?;
        let device_irq_line =
            instance.get_typed_func(&mut self.store, irq_export("device-irq-line")?)?;
        let clear_irq_lines =
            instance.get_typed_func(&mut self.store, irq_export("clear-irq-lines")?)?;
        let ioapic_stage = instance.get_typed_func(&mut self.store, irq_export("stage-ioapic")?)?;
        let ioapic_access =
            instance.get_typed_func(&mut self.store, irq_export("ioapic-access")?)?;
        let ioapic_line = instance.get_typed_func(&mut self.store, irq_export("ioapic-line")?)?;
        let ioapic_device_line =
            instance.get_typed_func(&mut self.store, irq_export("ioapic-device-line")?)?;
        let ioapic_eoi = instance.get_typed_func(&mut self.store, irq_export("ioapic-eoi")?)?;
        let compose_workers =
            instance.get_typed_func(&mut self.store, export("compose-workers")?)?;
        let remap = instance.get_typed_func(&mut self.store, export("remap-device")?)?;
        let access: Access = instance.get_typed_func(&mut self.store, export("access")?)?;
        let control: Control = instance.get_typed_func(&mut self.store, export("control")?)?;
        let configure_vcpus =
            instance.get_typed_func(&mut self.store, export("configure-vcpus")?)?;
        let (sender, receiver) = tokio::sync::mpsc::channel(COMMAND_CAPACITY);
        let (control_sender, control_receiver) = tokio::sync::mpsc::channel(CONTROL_CAPACITY);
        let admission = Arc::new(Mutex::new(true));
        let slots = Arc::new(AtomicUsize::new(0));
        let failure = Arc::new(Mutex::new(None));
        let callbacks = Arc::new(Mutex::new(Vec::new()));
        let loop_callbacks = Arc::clone(&callbacks);
        let loop_failure = Arc::clone(&failure);
        let loop_admission = Arc::clone(&admission);
        let bridge: crate::box_runtime::ComponentLoop = Box::new(move |accessor| {
            Box::pin(async move {
                let result = run_bridge(
                    accessor,
                    receiver,
                    control_receiver,
                    BridgeContext {
                        access,
                        control,
                        callbacks: loop_callbacks,
                        admission: loop_admission,
                    },
                )
                .await;
                if let Err(error) = &result {
                    *loop_failure
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(format!("{error:#}"));
                }
                result
            })
        });
        let entrypoint = lifecycle_loop(run_lifecycle, self.lifecycle_notifier());
        let vcpu_callbacks = Arc::clone(&callbacks);
        crate::component::vmm::configure_callbacks(
            &mut self.store.data_mut().platform,
            Arc::new(move |slot, failed| {
                let callbacks = vcpu_callbacks
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let device = callbacks
                    .get(usize::try_from(slot)?)
                    .ok_or_else(|| wasmtime::Error::msg("vCPU device callback outside box"))?;
                if failed {
                    device.failed.fetch_add(1, Ordering::Relaxed);
                } else {
                    device.completed.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            }),
        );
        self.mmio = Some(Router {
            bridge: Some(bridge),
            entrypoint: Some(entrypoint),
            initialize_machine,
            compose_machine,
            irq_lines_stage,
            device_irq_line,
            clear_irq_lines,
            ioapic_stage,
            ioapic_access,
            ioapic_line,
            ioapic_device_line,
            ioapic_eoi,
            compose_workers,
            remap,
            configure_vcpus,
            sender,
            control_sender,
            admission,
            slots,
            callbacks,
            failure,
        });
        Ok(())
    }

    #[allow(unsafe_code)]
    pub async fn initialize_mmio_artifact(
        &mut self,
        artifacts: &crate::TrustedArtifacts,
    ) -> wasmtime::Result<()> {
        // SAFETY: TrustedArtifacts accepts only the build's authenticated AOT artifacts.
        let component =
            unsafe { crate::engine::trusted_component(self.store.engine(), artifacts.mmio) }?;
        self.initialize_mmio(&component).await
    }
}

pub fn mmio_component_linker(
    engine: &wasmtime::Engine,
) -> wasmtime::Result<wasmtime::component::Linker<BoxHost>> {
    let mut linker = crate::engine::device_component_linker(engine)?;
    crate::component::vmm::add_to_linker(&mut linker)?;
    Ok(linker)
}

#[cfg(any(test, feature = "test-support"))]
async fn initialize_test_router(root: &mut BoxRuntime) -> wasmtime::Result<()> {
    if root.mmio.is_none() {
        let component = Component::new(
            root.store.engine(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../components/vmm/target/wasm32-wasip3/release/terra_vmm_component.wasm"
            )),
        )?;
        root.initialize_mmio(&component).await?;
    }
    Ok(())
}

pub(crate) struct PendingWorker {
    pub kind: crate::component::vmm::machine::DeviceKind,
    slot: u32,
    base: Arc<AtomicU64>,
    mapping: Option<terra::mmio::workers::Mapping>,
    factory: crate::component::vmm::workers::Factory,
}

impl BoxRuntime {
    pub(crate) fn grant_pending_workers(
        &mut self,
    ) -> wasmtime::Result<(usize, crate::component::vmm::workers::SetupGuard)> {
        let grants = std::mem::take(&mut self.pending_workers)
            .into_iter()
            .map(|worker| crate::component::vmm::workers::GrantedWorker {
                slot: worker.slot,
                kind: worker.kind,
                mapping: worker.mapping,
                base: worker.base,
                factory: Some(worker.factory),
            })
            .collect::<Vec<_>>();
        let count = grants.len();
        let setup = self.store.data_mut().platform.workers.grant_all(grants)?;
        Ok((count, setup))
    }

    pub(crate) fn finish_worker_creation(
        &mut self,
        count: usize,
        outcome: wasmtime::Result<()>,
    ) -> wasmtime::Result<()> {
        let workers = &mut self.store.data_mut().platform.workers;
        workers.factories.clear();
        let children = std::mem::take(&mut workers.children);
        outcome?;
        wasmtime::ensure!(
            children.len() == count,
            "VMM did not create every granted worker"
        );
        for child in children {
            self.attach_child(child)?;
        }
        Ok(())
    }

    pub(crate) async fn compose_workers(&mut self) -> wasmtime::Result<()> {
        if self.pending_workers.is_empty() {
            return Ok(());
        }
        let compose = self
            .mmio
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("MMIO router missing"))?
            .compose_workers;
        let (count, _setup) = self.grant_pending_workers()?;
        let outcome = tokio::time::timeout(
            crate::component::vmm::workers::SETUP_TIMEOUT.saturating_mul(u32::try_from(count)?),
            compose.call_async(&mut self.store, ()),
        )
        .await
        .map_err(wasmtime::Error::from)
        .and_then(std::convert::identity)
        .and_then(|(result,)| result.map_err(router_error));
        self.finish_worker_creation(count, outcome)
    }
}
