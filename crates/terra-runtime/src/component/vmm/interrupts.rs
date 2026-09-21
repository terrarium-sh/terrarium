//! Bounded rendezvous for Wasm IOAPIC emulation and native interrupt injection.

use crate::box_runtime::BoxRuntime;
pub use crate::component::vmm::bindings::interrupts::{IoapicReply, X86Interrupt};
use crate::component::vmm::bindings::types::Error;
use std::sync::{Arc, Mutex, mpsc};
use tokio::sync::{mpsc as queue, watch};
pub type Inject = Arc<dyn Fn(X86Interrupt) -> wasmtime::Result<()> + Send + Sync>;

const IOAPIC_PINS: usize = terra_limits::X86_IOAPIC_PINS as usize;

fn is_x86_irq_line(gsi: u32) -> bool {
    gsi < terra_limits::X86_IOAPIC_PINS
}

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
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
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

async fn complete_interrupt_worker(
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

enum Command {
    Line(u8, bool),
    Access(u8, u8, bool, u32),
    Eoi(u8),
}
struct Pending {
    command: Command,
    response: Option<mpsc::SyncSender<wasmtime::Result<u32>>>,
}

#[derive(Clone)]
pub struct IoApicHandle {
    queue: InterruptQueue<Pending>,
    config: super::virtualization::MachineConfig,
}

impl IoApicHandle {
    pub fn set_line(&self, slot: u8, level: bool) -> wasmtime::Result<()> {
        self.queue.send(Pending {
            command: Command::Line(slot, level),
            response: None,
        })
    }

    pub fn bind_interrupt(
        &self,
        kind: super::bindings::machine::DeviceKind,
        ordinal: usize,
    ) -> wasmtime::Result<crate::component::InterruptCallback> {
        let slot = self.config.device_slot(kind, ordinal)?;
        let queue = self.queue.clone();
        Ok(Arc::new(move |level| {
            queue.send(Pending {
                command: Command::Line(slot, level),
                response: None,
            })
        }))
    }

    pub fn access(&self, offset: u8, width: u8, write: bool, value: u32) -> wasmtime::Result<u32> {
        self.request(Command::Access(offset, width, write, value))
    }

    pub fn eoi(&self, vector: u8) -> wasmtime::Result<()> {
        self.request(Command::Eoi(vector)).map(|_| ())
    }

    pub async fn close(&self) -> wasmtime::Result<()> {
        self.queue.close().await
    }

    fn request(&self, command: Command) -> wasmtime::Result<u32> {
        let (response, receiver) = mpsc::sync_channel(1);
        self.queue.send(Pending {
            command,
            response: Some(response),
        })?;
        receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|error| wasmtime::Error::msg(format!("IOAPIC response: {error}")))?
    }
}

impl BoxRuntime {
    pub async fn grant_ioapic(&mut self, inject: Inject) -> wasmtime::Result<IoApicHandle> {
        let config = self
            .store
            .data()
            .platform
            .machine_config()
            .ok_or_else(|| wasmtime::Error::msg("VM has no machine configuration"))?
            .clone();
        let vcpus = config.vcpus();
        let router = self
            .mmio
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("VMM missing"))?;
        let (stage, access, line, eoi) = (
            router.interrupts.func_stage_ioapic(),
            router.interrupts.func_ioapic_access(),
            router.interrupts.func_ioapic_line(),
            router.interrupts.func_ioapic_eoi(),
        );
        let (result,) = stage.call_async(&mut self.store, ()).await?;
        result.map_err(|error| wasmtime::Error::msg(format!("IOAPIC grant: {error:?}")))?;
        let (queue, mut receiver, completion) = interrupt_queue::<Pending>();
        self.register_loop(Box::new(move |accessor| {
            Box::pin(complete_interrupt_worker(
                async move {
                    while let Some(pending) = receiver.recv().await {
                        let (value, interrupts) = match pending.command {
                            Command::Line(slot, level) => {
                                let (result,) =
                                    line.call_concurrent(accessor, (slot, level)).await?;
                                (0, result.map_err(wasm_error)?)
                            }
                            Command::Eoi(vector) => {
                                let (result,) = eoi.call_concurrent(accessor, (vector,)).await?;
                                (0, result.map_err(wasm_error)?)
                            }
                            Command::Access(offset, width, write, value) => {
                                let (result,) = access
                                    .call_concurrent(accessor, (offset, width, write, value))
                                    .await?;
                                match result {
                                    Ok(result) => (result.value, result.interrupts),
                                    Err(error) if is_guest_ioapic_error(error) => (0, Vec::new()),
                                    Err(error) => return Err(wasm_error(error)),
                                }
                            }
                        };
                        validate_x86_interrupts(&interrupts, vcpus)?;
                        for interrupt in interrupts {
                            inject(interrupt)?;
                        }
                        if let Some(response) = pending.response {
                            let _ = response.send(Ok(value));
                        }
                    }
                    Ok(())
                },
                completion,
            ))
        }))?;
        Ok(IoApicHandle { queue, config })
    }
}

fn wasm_error(error: Error) -> wasmtime::Error {
    wasmtime::Error::msg(format!("Wasm IOAPIC: {error:?}"))
}

fn is_guest_ioapic_error(error: Error) -> bool {
    match error {
        Error::BadWidth | Error::Unmapped => true,
        Error::InvalidSlot
        | Error::InvalidVcpu
        | Error::UnsupportedMsr
        | Error::BadArmExit
        | Error::Overlap
        | Error::Overflow
        | Error::Busy
        | Error::Closed
        | Error::Device => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        complete_interrupt_worker(
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
        let error =
            complete_interrupt_worker(async { wasmtime::bail!("injection failed") }, completion)
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

    fn interrupt(vector: u8, destination: u8) -> X86Interrupt {
        X86Interrupt {
            vector,
            destination,
            level_triggered: false,
        }
    }

    #[test]
    fn ioapic_interrupts_stay_within_native_vcpu_grants() {
        assert!(validate_x86_interrupts(&[interrupt(32, 0)], 1).is_ok());
        assert!(validate_x86_interrupts(&[interrupt(32, u8::MAX)], 1).is_ok());
        assert!(validate_x86_interrupts(&[interrupt(31, 0)], 1).is_err());
        assert!(validate_x86_interrupts(&[interrupt(32, 1)], 1).is_err());
        assert!(validate_x86_interrupts(&[interrupt(32, 0); IOAPIC_PINS + 1], 1).is_err());
    }

    #[test]
    fn malformed_guest_ioapic_accesses_are_contained() {
        assert!(is_guest_ioapic_error(Error::BadWidth));
        assert!(is_guest_ioapic_error(Error::Unmapped));
        assert!(!is_guest_ioapic_error(Error::Busy));
        assert!(!is_guest_ioapic_error(Error::Device));
    }
}

struct GsiCommand(u8, bool);

#[derive(Clone)]
pub struct IrqHandle {
    queue: InterruptQueue<GsiCommand>,
    config: super::virtualization::MachineConfig,
}

impl IrqHandle {
    pub fn bind_interrupt(
        &self,
        kind: super::bindings::machine::DeviceKind,
        ordinal: usize,
    ) -> wasmtime::Result<crate::component::InterruptCallback> {
        let slot = self.config.device_slot(kind, ordinal)?;
        let queue = self.queue.clone();
        Ok(Arc::new(move |level| queue.send(GsiCommand(slot, level))))
    }

    pub async fn close(&self) -> wasmtime::Result<()> {
        self.queue.close().await
    }
}

impl BoxRuntime {
    pub async fn grant_irq_lines(
        &mut self,
        inject: impl Fn(u32, bool) -> wasmtime::Result<()> + Send + Sync + 'static,
    ) -> wasmtime::Result<IrqHandle> {
        let router = self
            .mmio
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("VMM missing"))?;
        let (stage, line, clear) = (
            router.interrupts.func_stage_irq_lines(),
            router.interrupts.func_device_irq_line(),
            router.interrupts.func_clear_irq_lines(),
        );
        let (result,) = stage.call_async(&mut self.store, ()).await?;
        result.map_err(wasm_error)?;
        let (queue, mut receiver, completion) = interrupt_queue();
        self.register_loop(Box::new(move |accessor| {
            Box::pin(complete_interrupt_worker(
                async move {
                    while let Some(GsiCommand(slot, level)) = receiver.recv().await {
                        let (result,) = line.call_concurrent(accessor, (slot, level)).await?;
                        if let Some(change) = result.map_err(wasm_error)? {
                            inject(change.gsi, change.asserted)?;
                        }
                    }
                    let (result,) = clear.call_concurrent(accessor, ()).await?;
                    let changes = result.map_err(wasm_error)?;
                    if changes.len() > IOAPIC_PINS
                        || changes
                            .iter()
                            .any(|change| change.asserted || !is_x86_irq_line(change.gsi))
                    {
                        return Err(wasmtime::Error::msg("invalid IRQ cleanup batch"));
                    }
                    for change in changes {
                        inject(change.gsi, false)?;
                    }
                    Ok(())
                },
                completion,
            ))
        }))?;
        let config = self
            .store
            .data()
            .platform
            .machine_config()
            .ok_or_else(|| wasmtime::Error::msg("VM has no machine configuration"))?
            .clone();
        Ok(IrqHandle { queue, config })
    }
}

#[cfg(test)]
mod irq_line_tests {
    #[test]
    fn native_irq_cleanup_rejects_lines_outside_the_ioapic() {
        assert!(super::is_x86_irq_line(0));
        assert!(super::is_x86_irq_line(terra_limits::X86_IOAPIC_PINS - 1));
        assert!(!super::is_x86_irq_line(terra_limits::X86_IOAPIC_PINS));
    }
}
