//! Native boundary for the isolated interrupt-controller component.

use crate::box_runtime::BoxRuntime;
use crate::box_runtime::store::{StoreHost, StoreState};
use crate::machine::{Architecture, DeviceKind, MachineConfig};
use std::sync::{Arc, Mutex, mpsc};
use tokio::sync::{mpsc as queue, watch};
use wasmtime::component::{Component, ResourceTable};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

#[allow(clippy::same_length_and_capacity)]
mod bindings {
    wasmtime::component::bindgen!({
        world: "interrupt-controller", path: "../../components/interrupt-controller/wit",
        additional_derives: [PartialEq, Eq],
        exports: { default: async },
    });
}

use bindings::exports::terra::interrupt_controller::controller;
pub use controller::{IoapicReply, X86Interrupt};

const IOAPIC_PINS: usize = terra_limits::X86_IOAPIC_PINS as usize;
const RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub type Inject = Arc<dyn Fn(X86Interrupt) -> wasmtime::Result<()> + Send + Sync>;

struct ControllerHost {
    ctx: WasiCtx,
    table: ResourceTable,
}

impl ControllerHost {
    fn new() -> Self {
        Self {
            ctx: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
        }
    }
}

impl WasiView for ControllerHost {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

impl StoreHost for ControllerHost {}

fn validate_x86_interrupts(interrupts: &[X86Interrupt], vcpus: u8) -> wasmtime::Result<()> {
    wasmtime::ensure!(
        interrupts.len() <= IOAPIC_PINS,
        "IOAPIC interrupt batch exceeds pins"
    );
    for interrupt in interrupts {
        wasmtime::ensure!(
            interrupt.vector >= 32,
            "IOAPIC interrupt vector is reserved"
        );
        wasmtime::ensure!(
            interrupt.destination == u8::MAX || interrupt.destination < vcpus,
            "IOAPIC interrupt destination outside vCPU grant"
        );
    }
    Ok(())
}

fn validate_irq_change(change: controller::IrqLevel, routes: &[u32]) -> wasmtime::Result<()> {
    wasmtime::ensure!(
        routes.contains(&change.gsi),
        "interrupt GSI outside device grant"
    );
    Ok(())
}

fn validate_irq_line(
    slot: u8,
    change: controller::IrqLevel,
    routes: &[u32],
) -> wasmtime::Result<()> {
    wasmtime::ensure!(
        routes.get(usize::from(slot)) == Some(&change.gsi),
        "interrupt GSI outside device line grant"
    );
    Ok(())
}

fn validate_irq_cleanup(changes: &[controller::IrqLevel], routes: &[u32]) -> wasmtime::Result<()> {
    wasmtime::ensure!(
        changes.len() <= IOAPIC_PINS,
        "IRQ cleanup batch exceeds grants"
    );
    for change in changes {
        validate_irq_change(*change, routes)?;
        wasmtime::ensure!(!change.asserted, "IRQ cleanup asserted a line");
    }
    Ok(())
}

type CompletionSender = watch::Sender<Option<Result<(), String>>>;

struct InterruptQueue<T> {
    sender: Arc<Mutex<Option<queue::Sender<T>>>>,
    completion: watch::Receiver<Option<Result<(), String>>>,
}

impl<T> Clone for InterruptQueue<T> {
    fn clone(&self) -> Self {
        Self {
            sender: Arc::clone(&self.sender),
            completion: self.completion.clone(),
        }
    }
}

impl<T> InterruptQueue<T> {
    fn send(&self, command: T) -> wasmtime::Result<()> {
        self.sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("interrupt queue closed"))?
            .try_send(command)
            .map_err(|error| wasmtime::Error::msg(format!("interrupt queue: {error}")))
    }

    async fn close(&self) -> wasmtime::Result<()> {
        self.sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let mut completion = self.completion.clone();
        tokio::time::timeout(RESPONSE_TIMEOUT, async {
            completion
                .wait_for(Option::is_some)
                .await
                .map_err(|_| wasmtime::Error::msg("interrupt worker stopped without completion"))?
                .clone()
                .ok_or_else(|| wasmtime::Error::msg("interrupt completion missing"))?
                .map_err(wasmtime::Error::msg)
        })
        .await
        .map_err(|_| wasmtime::Error::msg("interrupt shutdown timed out"))?
    }
}

fn interrupt_queue<T>() -> (InterruptQueue<T>, queue::Receiver<T>, CompletionSender) {
    let (sender, receiver) = queue::channel(256);
    let (finished, completion) = watch::channel(None);
    (
        InterruptQueue {
            sender: Arc::new(Mutex::new(Some(sender))),
            completion,
        },
        receiver,
        finished,
    )
}

async fn complete_worker(
    operation: impl Future<Output = wasmtime::Result<()>>,
    completion: CompletionSender,
) -> wasmtime::Result<()> {
    let result = operation.await;
    completion.send_replace(Some(
        result
            .as_ref()
            .copied()
            .map_err(|error| format!("{error:#}")),
    ));
    result
}

enum IoApicCommand {
    Line(u8, bool),
    Access(u8, u8, bool, u32),
    Eoi(u8),
}

struct IoApicPending {
    command: IoApicCommand,
    response: Option<mpsc::SyncSender<wasmtime::Result<u32>>>,
}

#[derive(Clone)]
pub struct IoApicHandle {
    queue: InterruptQueue<IoApicPending>,
    config: MachineConfig,
}

impl IoApicHandle {
    pub fn set_line(&self, slot: u8, level: bool) -> wasmtime::Result<()> {
        self.queue.send(IoApicPending {
            command: IoApicCommand::Line(slot, level),
            response: None,
        })
    }

    pub fn bind_interrupt(
        &self,
        kind: DeviceKind,
        ordinal: usize,
    ) -> wasmtime::Result<crate::component::InterruptCallback> {
        let slot = self.config.device_slot(kind, ordinal)?;
        let queue = self.queue.clone();
        Ok(Arc::new(move |level| {
            queue.send(IoApicPending {
                command: IoApicCommand::Line(slot, level),
                response: None,
            })
        }))
    }

    pub fn access(&self, offset: u8, width: u8, write: bool, value: u32) -> wasmtime::Result<u32> {
        self.request(IoApicCommand::Access(offset, width, write, value))
    }

    pub fn eoi(&self, vector: u8) -> wasmtime::Result<()> {
        self.request(IoApicCommand::Eoi(vector)).map(|_| ())
    }
    pub async fn close(&self) -> wasmtime::Result<()> {
        self.queue.close().await
    }

    fn request(&self, command: IoApicCommand) -> wasmtime::Result<u32> {
        let (response, receiver) = mpsc::sync_channel(1);
        self.queue.send(IoApicPending {
            command,
            response: Some(response),
        })?;
        receiver
            .recv_timeout(RESPONSE_TIMEOUT)
            .map_err(|error| wasmtime::Error::msg(format!("IOAPIC response: {error}")))?
    }
}

struct GsiCommand(u8, bool);

#[derive(Clone)]
pub struct IrqHandle {
    queue: InterruptQueue<GsiCommand>,
    config: MachineConfig,
    routes: Arc<[u32]>,
    inject: Arc<dyn Fn(u32, bool) -> wasmtime::Result<()> + Send + Sync>,
}

impl IrqHandle {
    pub fn bind_interrupt(
        &self,
        kind: DeviceKind,
        ordinal: usize,
    ) -> wasmtime::Result<crate::component::InterruptCallback> {
        let slot = self.config.device_slot(kind, ordinal)?;
        let queue = self.queue.clone();
        Ok(Arc::new(move |level| queue.send(GsiCommand(slot, level))))
    }
    pub async fn close(&self) -> wasmtime::Result<()> {
        let result = self.queue.close().await;
        let cleanup = self.deassert();
        result.and(cleanup)
    }

    fn deassert(&self) -> wasmtime::Result<()> {
        let mut first_error = None;
        for (index, gsi) in self.routes.iter().enumerate() {
            if !self.routes[..index].contains(gsi)
                && let Err(error) = (self.inject)(*gsi, false)
            {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

fn controller_config(config: &MachineConfig, mode: controller::Mode) -> controller::Config {
    controller::Config {
        mode,
        routes: config.devices().iter().map(|device| device.irq).collect(),
        vcpus: config.vcpus(),
    }
}

async fn instantiate(
    root: &mut BoxRuntime,
    component: &Component,
    config: controller::Config,
) -> wasmtime::Result<(
    crate::box_runtime::DeviceWorker<ControllerHost>,
    controller::Guest,
)> {
    let mut worker = root.new_child(ControllerHost::new());
    let linker =
        wasmtime::component::Linker::<StoreState<ControllerHost>>::new(worker.store.engine());
    let instance =
        bindings::InterruptController::instantiate_async(&mut worker.store, component, &linker)
            .await?;
    let controller = instance.terra_interrupt_controller_controller();
    let (result,) = controller
        .func_configure()
        .call_async(&mut worker.store, (&config,))
        .await?;
    result.map_err(controller_error)?;
    Ok((worker, controller.clone()))
}

impl BoxRuntime {
    #[allow(clippy::too_many_lines)]
    pub async fn grant_ioapic(
        &mut self,
        component: &Component,
        inject: Inject,
    ) -> wasmtime::Result<IoApicHandle> {
        let config = self
            .store
            .data()
            .platform
            .machine_config()
            .ok_or_else(|| wasmtime::Error::msg("VM has no machine configuration"))?
            .clone();
        wasmtime::ensure!(
            config.architecture() == Architecture::X86,
            "software IOAPIC requires x86"
        );
        wasmtime::ensure!(
            !self.store.data().platform.is_machine_running(),
            "interrupt controller must be configured before vCPUs start"
        );
        wasmtime::ensure!(
            !self.interrupt_controller_configured,
            "interrupt controller already configured"
        );
        let (mut worker, controller) = tokio::time::timeout(
            RESPONSE_TIMEOUT,
            instantiate(
                self,
                component,
                controller_config(&config, controller::Mode::Ioapic),
            ),
        )
        .await
        .map_err(|_| wasmtime::Error::msg("interrupt controller setup timed out"))??;
        let (queue, mut receiver, completion) = interrupt_queue::<IoApicPending>();
        let access = controller.func_access();
        let line = controller.func_ioapic_line();
        let eoi = controller.func_eoi();
        let vcpus = config.vcpus();
        worker.register_loop(Box::new(move |accessor| {
            Box::pin(complete_worker(
                async move {
                    while let Some(pending) = receiver.recv().await {
                        let result = async {
                            let (value, interrupts) = match pending.command {
                                IoApicCommand::Line(slot, level) => {
                                    let (result,) = tokio::time::timeout(
                                        RESPONSE_TIMEOUT,
                                        line.call_concurrent(accessor, (slot, level)),
                                    )
                                    .await
                                    .map_err(|_| {
                                        wasmtime::Error::msg("interrupt controller call timed out")
                                    })??;
                                    (0, result.map_err(controller_error)?)
                                }
                                IoApicCommand::Eoi(vector) => {
                                    let (result,) = tokio::time::timeout(
                                        RESPONSE_TIMEOUT,
                                        eoi.call_concurrent(accessor, (vector,)),
                                    )
                                    .await
                                    .map_err(|_| {
                                        wasmtime::Error::msg("interrupt controller call timed out")
                                    })??;
                                    (0, result.map_err(controller_error)?)
                                }
                                IoApicCommand::Access(offset, width, write, value) => {
                                    let (result,) = tokio::time::timeout(
                                        RESPONSE_TIMEOUT,
                                        access.call_concurrent(
                                            accessor,
                                            (offset, width, write, value),
                                        ),
                                    )
                                    .await
                                    .map_err(|_| {
                                        wasmtime::Error::msg("interrupt controller call timed out")
                                    })??;
                                    match result {
                                        Ok(reply) => (reply.value, reply.interrupts),
                                        Err(
                                            controller::Error::BadWidth
                                            | controller::Error::Unmapped,
                                        ) => (0, Vec::new()),
                                        Err(error) => return Err(controller_error(error)),
                                    }
                                }
                            };
                            validate_x86_interrupts(&interrupts, vcpus)?;
                            for interrupt in interrupts {
                                inject(interrupt)?;
                            }
                            Ok(value)
                        }
                        .await;
                        match (pending.response, result) {
                            (Some(response), Ok(value)) => {
                                let _ = response.send(Ok(value));
                            }
                            (Some(response), Err(error)) => {
                                let message = error.to_string();
                                let _ = response.send(Err(error));
                                return Err(wasmtime::Error::msg(message));
                            }
                            (None, Ok(_)) => {}
                            (None, Err(error)) => return Err(error),
                        }
                    }
                    Ok(())
                },
                completion,
            ))
        }))?;
        self.attach_worker(worker.prepare(self.shutdown_receiver()))?;
        self.interrupt_controller_configured = true;
        Ok(IoApicHandle { queue, config })
    }

    pub async fn grant_irq_lines(
        &mut self,
        component: &Component,
        inject: impl Fn(u32, bool) -> wasmtime::Result<()> + Send + Sync + 'static,
    ) -> wasmtime::Result<IrqHandle> {
        let config = self
            .store
            .data()
            .platform
            .machine_config()
            .ok_or_else(|| wasmtime::Error::msg("VM has no machine configuration"))?
            .clone();
        wasmtime::ensure!(
            config.architecture() == Architecture::X86,
            "software IRQ lines require x86"
        );
        wasmtime::ensure!(
            !self.store.data().platform.is_machine_running(),
            "interrupt controller must be configured before vCPUs start"
        );
        wasmtime::ensure!(
            !self.interrupt_controller_configured,
            "interrupt controller already configured"
        );
        let routes: Arc<[u32]> = config.devices().iter().map(|device| device.irq).collect();
        let inject: Arc<dyn Fn(u32, bool) -> wasmtime::Result<()> + Send + Sync> = Arc::new(inject);
        let (mut worker, controller) = tokio::time::timeout(
            RESPONSE_TIMEOUT,
            instantiate(
                self,
                component,
                controller_config(&config, controller::Mode::IrqLines),
            ),
        )
        .await
        .map_err(|_| wasmtime::Error::msg("interrupt controller setup timed out"))??;
        let (queue, mut receiver, completion) = interrupt_queue::<GsiCommand>();
        let line = controller.func_irq_line();
        let clear = controller.func_clear();
        let worker_routes = Arc::clone(&routes);
        let worker_inject = Arc::clone(&inject);
        worker.register_loop(Box::new(move |accessor| {
            Box::pin(complete_worker(
                async move {
                    while let Some(GsiCommand(slot, level)) = receiver.recv().await {
                        let (result,) = tokio::time::timeout(
                            RESPONSE_TIMEOUT,
                            line.call_concurrent(accessor, (slot, level)),
                        )
                        .await
                        .map_err(|_| {
                            wasmtime::Error::msg("interrupt controller call timed out")
                        })??;
                        if let Some(change) = result.map_err(controller_error)? {
                            validate_irq_line(slot, change, &worker_routes)?;
                            worker_inject(change.gsi, change.asserted)?;
                        }
                    }
                    let (result,) =
                        tokio::time::timeout(RESPONSE_TIMEOUT, clear.call_concurrent(accessor, ()))
                            .await
                            .map_err(|_| {
                                wasmtime::Error::msg("interrupt controller call timed out")
                            })??;
                    let changes = result.map_err(controller_error)?;
                    validate_irq_cleanup(&changes, &worker_routes)?;
                    for change in changes {
                        worker_inject(change.gsi, false)?;
                    }
                    Ok(())
                },
                completion,
            ))
        }))?;
        self.attach_worker(worker.prepare(self.shutdown_receiver()))?;
        self.interrupt_controller_configured = true;
        Ok(IrqHandle {
            queue,
            config,
            routes,
            inject,
        })
    }
}

fn controller_error(error: controller::Error) -> wasmtime::Error {
    wasmtime::Error::msg(format!("interrupt controller: {error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn busy_mmio_store_yields_to_controller_progress_and_cancellation() {
        use std::future::{Future as _, poll_fn};
        use std::task::Poll;
        use std::time::Duration;

        let engine = crate::engine::device_engine().unwrap();
        let mut root = BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new()).unwrap();
        crate::component::mmio::initialize_test_mmio(&mut root)
            .await
            .unwrap();
        let component = crate::test_fixtures::trusted_artifacts()
            .interrupt_controller()
            .deserialize(&engine)
            .unwrap();
        let (mut interrupts, controller) = instantiate(
            &mut root,
            &component,
            controller::Config {
                mode: controller::Mode::IrqLines,
                routes: vec![3],
                vcpus: 1,
            },
        )
        .await
        .unwrap();
        let mmio = root.mmio.as_mut().unwrap().worker.as_mut().unwrap();
        let spin =
            wasmtime::Module::new(&engine, "(module (func (export \"run\") (loop br 0)))").unwrap();
        let spin = wasmtime::Instance::new_async(&mut mmio.store, &spin, &[])
            .await
            .unwrap()
            .get_typed_func::<(), ()>(&mut mmio.store, "run")
            .unwrap();
        let busy = spin.call_async(&mut mmio.store, ());
        tokio::pin!(busy);
        poll_fn(|context| {
            assert!(busy.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        let line = controller.func_irq_line();
        let progress = async {
            tokio::select! {
                result = &mut busy => panic!("MMIO spin ended unexpectedly: {result:?}"),
                result = line.call_async(&mut interrupts.store, (0, true)) => result,
            }
        };
        let (result,) = tokio::time::timeout(Duration::from_secs(1), progress)
            .await
            .unwrap()
            .unwrap();
        let change = result.unwrap().unwrap();
        assert_eq!(change.gsi, 3);
        assert!(change.asserted);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), busy)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn saturated_interrupt_queue_drains_after_a_cancelled_close() {
        use futures_util::FutureExt;

        let (queue, mut receiver, completion) = interrupt_queue();
        let retained = queue.clone();
        for value in 0..256 {
            queue.send(value).unwrap();
        }
        assert!(queue.send(256).is_err());
        {
            let closing = queue.close();
            tokio::pin!(closing);
            assert!(closing.as_mut().now_or_never().is_none());
        }
        assert!(retained.send(257).is_err());
        complete_worker(
            async move {
                for value in 0..256 {
                    assert_eq!(receiver.recv().await, Some(value));
                }
                assert_eq!(receiver.recv().await, None);
                Ok(())
            },
            completion,
        )
        .await
        .unwrap();
        retained.close().await.unwrap();
        queue.close().await.unwrap();
    }

    #[tokio::test]
    async fn interrupt_close_reports_worker_failure_and_abandonment() {
        let (queue, _receiver, completion) = interrupt_queue::<()>();
        let error = complete_worker(async { wasmtime::bail!("injection failed") }, completion)
            .await
            .unwrap_err();
        assert_eq!(
            queue.close().await.unwrap_err().to_string(),
            error.to_string()
        );
        let (queue, _receiver, completion) = interrupt_queue::<()>();
        drop(completion);
        assert!(
            queue
                .close()
                .await
                .unwrap_err()
                .to_string()
                .contains("without completion")
        );
    }

    #[test]
    fn interrupt_output_stays_within_native_vcpu_grants() {
        let interrupt = X86Interrupt {
            vector: 32,
            destination: 0,
            level_triggered: false,
        };
        assert!(validate_x86_interrupts(&[interrupt], 1).is_ok());
        assert!(
            validate_x86_interrupts(
                &[X86Interrupt {
                    vector: 31,
                    ..interrupt
                }],
                1
            )
            .is_err()
        );
        assert!(
            validate_x86_interrupts(
                &[X86Interrupt {
                    destination: 1,
                    ..interrupt
                }],
                1
            )
            .is_err()
        );
    }

    #[test]
    fn gsi_output_needs_a_native_line_grant() {
        assert!(
            validate_irq_change(
                controller::IrqLevel {
                    gsi: 3,
                    asserted: true
                },
                &[3]
            )
            .is_ok()
        );
        for gsi in [0, 8, 12, 24] {
            let change = controller::IrqLevel {
                gsi,
                asserted: true,
            };
            assert!(validate_irq_change(change, &[11, 23]).is_err());
            assert!(validate_irq_line(0, change, &[11, 23]).is_err());
        }
    }

    #[test]
    fn gsi_line_output_stays_bound_to_its_device() {
        let change = controller::IrqLevel {
            gsi: 4,
            asserted: true,
        };
        assert!(validate_irq_line(1, change, &[3, 4]).is_ok());
        assert!(validate_irq_line(0, change, &[3, 4]).is_err());
    }

    #[test]
    fn cleanup_validates_the_whole_batch_before_injection() {
        let valid = controller::IrqLevel {
            gsi: 3,
            asserted: false,
        };
        assert!(validate_irq_cleanup(&[valid], &[3]).is_ok());
        for invalid in [
            controller::IrqLevel {
                gsi: 4,
                asserted: false,
            },
            controller::IrqLevel {
                gsi: 3,
                asserted: true,
            },
        ] {
            assert!(validate_irq_cleanup(&[valid, invalid], &[3]).is_err());
        }
        assert!(validate_irq_cleanup(&[valid; IOAPIC_PINS + 1], &[3]).is_err());
    }

    #[tokio::test]
    async fn failed_controller_cleanup_deasserts_every_granted_line() {
        let (queue, _receiver, completion) = interrupt_queue();
        completion.send_replace(Some(Err("controller trapped".into())));
        let injected = Arc::new(Mutex::new(Vec::new()));
        let observed = injected.clone();
        let handle = IrqHandle {
            queue,
            config: MachineConfig::new(Architecture::X86, 4096, 1, Vec::new()).unwrap(),
            routes: vec![3, 3, 4].into(),
            inject: Arc::new(move |gsi, level| {
                observed.lock().unwrap().push((gsi, level));
                if gsi == 3 {
                    wasmtime::bail!("first line failed");
                }
                Ok(())
            }),
        };
        assert_eq!(
            handle.close().await.unwrap_err().to_string(),
            "controller trapped"
        );
        assert_eq!(*injected.lock().unwrap(), vec![(3, false), (4, false)]);
    }
}
