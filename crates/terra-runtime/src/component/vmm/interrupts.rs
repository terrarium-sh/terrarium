//! Bounded rendezvous for Wasm IOAPIC emulation and native interrupt injection.

use crate::box_runtime::BoxRuntime;
use crate::component::vmm::mmio::Error;
pub use crate::component::vmm::mmio::exports::terra::mmio::interrupts::{
    IoapicReply, X86Interrupt,
};
use std::sync::{Arc, mpsc};
use wasmtime::component::TypedFunc;

pub(crate) type Stage = TypedFunc<(), (Result<(), Error>,)>;
pub(crate) type Access = TypedFunc<(u8, u8, bool, u32), (Result<IoapicReply, Error>,)>;
pub(crate) type Line = TypedFunc<(u8, bool), (Result<Vec<X86Interrupt>, Error>,)>;
pub(crate) type DeviceLine =
    TypedFunc<(super::machine::DeviceKind, u32, bool), (Result<Vec<X86Interrupt>, Error>,)>;
pub(crate) type Eoi = TypedFunc<(u8,), (Result<Vec<X86Interrupt>, Error>,)>;
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

enum Command {
    Line(u8, bool),
    DeviceLine(super::machine::DeviceKind, u32, bool),
    Access(u8, u8, bool, u32),
    Eoi(u8),
    Close,
}
struct Pending {
    command: Command,
    response: Option<mpsc::SyncSender<wasmtime::Result<u32>>>,
}

#[derive(Clone)]
pub struct IoApicHandle {
    sender: tokio::sync::mpsc::Sender<Pending>,
}

impl IoApicHandle {
    pub fn set_line(&self, slot: u8, level: bool) -> wasmtime::Result<()> {
        self.sender
            .try_send(Pending {
                command: Command::Line(slot, level),
                response: None,
            })
            .map_err(|error| wasmtime::Error::msg(format!("IOAPIC queue: {error}")))
    }

    #[must_use]
    pub fn bind_interrupt(
        &self,
        kind: super::machine::DeviceKind,
        ordinal: usize,
    ) -> crate::component::Interrupt {
        let handle = self.clone();
        Arc::new(move |level| {
            handle
                .sender
                .try_send(Pending {
                    command: Command::DeviceLine(kind, u32::try_from(ordinal)?, level),
                    response: None,
                })
                .map_err(|error| wasmtime::Error::msg(format!("IOAPIC queue: {error}")))
        })
    }

    pub fn access(&self, offset: u8, width: u8, write: bool, value: u32) -> wasmtime::Result<u32> {
        self.request(Command::Access(offset, width, write, value))
    }

    pub fn eoi(&self, vector: u8) -> wasmtime::Result<()> {
        self.request(Command::Eoi(vector)).map(|_| ())
    }

    pub fn close(&self) -> wasmtime::Result<()> {
        self.request(Command::Close).map(|_| ())
    }

    fn request(&self, command: Command) -> wasmtime::Result<u32> {
        let (response, receiver) = mpsc::sync_channel(1);
        self.sender
            .try_send(Pending {
                command,
                response: Some(response),
            })
            .map_err(|error| wasmtime::Error::msg(format!("IOAPIC queue: {error}")))?;
        receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|error| wasmtime::Error::msg(format!("IOAPIC response: {error}")))?
    }
}

impl BoxRuntime {
    pub async fn grant_ioapic(&mut self, inject: Inject) -> wasmtime::Result<IoApicHandle> {
        let vcpus = self.store.data().platform.machine_config()?.vcpus();
        let router = self
            .mmio
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("VMM missing"))?;
        let (stage, access, line, device_line, eoi) = (
            router.ioapic_stage,
            router.ioapic_access,
            router.ioapic_line,
            router.ioapic_device_line,
            router.ioapic_eoi,
        );
        let (result,) = stage.call_async(&mut self.store, ()).await?;
        result.map_err(|error| wasmtime::Error::msg(format!("IOAPIC grant: {error:?}")))?;
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<Pending>(256);
        self.register_loop(Box::new(move |accessor| {
            Box::pin(async move {
                while let Some(pending) = receiver.recv().await {
                    let close = matches!(pending.command, Command::Close);
                    let (value, interrupts) = match pending.command {
                        Command::Line(slot, level) => {
                            let (result,) = line.call_concurrent(accessor, (slot, level)).await?;
                            (0, result.map_err(wasm_error)?)
                        }
                        Command::DeviceLine(kind, ordinal, level) => {
                            let (result,) = device_line
                                .call_concurrent(accessor, (kind, ordinal, level))
                                .await?;
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
                        Command::Close => (0, Vec::new()),
                    };
                    validate_x86_interrupts(&interrupts, vcpus)?;
                    for interrupt in interrupts {
                        inject(interrupt)?;
                    }
                    if let Some(response) = pending.response {
                        let _ = response.send(Ok(value));
                    }
                    if close {
                        return Ok(());
                    }
                }
                Ok(())
            })
        }))?;
        Ok(IoApicHandle { sender })
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

pub(crate) type GsiLine = TypedFunc<
    (super::machine::DeviceKind, u32, bool),
    (
        Result<
            Option<crate::component::vmm::mmio::exports::terra::mmio::interrupts::IrqLevel>,
            Error,
        >,
    ),
>;
pub(crate) type ClearLines = TypedFunc<
    (),
    (Result<Vec<crate::component::vmm::mmio::exports::terra::mmio::interrupts::IrqLevel>, Error>,),
>;

enum GsiCommand {
    Level(super::machine::DeviceKind, u32, bool),
    Close(mpsc::SyncSender<()>),
}

#[derive(Clone)]
pub struct IrqHandle {
    sender: tokio::sync::mpsc::Sender<GsiCommand>,
}

impl IrqHandle {
    #[must_use]
    pub fn bind_interrupt(
        &self,
        kind: super::machine::DeviceKind,
        ordinal: usize,
    ) -> crate::component::Interrupt {
        let sender = self.sender.clone();
        Arc::new(move |level| {
            sender
                .try_send(GsiCommand::Level(kind, u32::try_from(ordinal)?, level))
                .map_err(|error| wasmtime::Error::msg(format!("IRQ queue: {error}")))
        })
    }

    pub fn close(&self) -> wasmtime::Result<()> {
        let (response, receiver) = mpsc::sync_channel(1);
        self.sender
            .try_send(GsiCommand::Close(response))
            .map_err(|error| wasmtime::Error::msg(format!("IRQ queue: {error}")))?;
        receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|error| wasmtime::Error::msg(format!("IRQ response: {error}")))
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
            router.irq_lines_stage,
            router.device_irq_line,
            router.clear_irq_lines,
        );
        let (result,) = stage.call_async(&mut self.store, ()).await?;
        result.map_err(wasm_error)?;
        let (sender, mut receiver) = tokio::sync::mpsc::channel(256);
        self.register_loop(Box::new(move |accessor| {
            Box::pin(async move {
                while let Some(command) = receiver.recv().await {
                    match command {
                        GsiCommand::Level(kind, ordinal, level) => {
                            let (result,) = line
                                .call_concurrent(accessor, (kind, ordinal, level))
                                .await?;
                            if let Some(change) = result.map_err(wasm_error)? {
                                inject(change.gsi, change.asserted)?;
                            }
                        }
                        GsiCommand::Close(response) => {
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
                            let _ = response.send(());
                            return Ok(());
                        }
                    }
                }
                Ok(())
            })
        }))?;
        Ok(IrqHandle { sender })
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
