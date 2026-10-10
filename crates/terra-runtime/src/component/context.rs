//! Shared device capabilities and host imports.

use crate::MAX_SINGLE_BYTES;
use crate::component::bindings::{interrupt, memory};
use crate::memory::{BoundedMemory, GuestRam};
use std::sync::Arc;
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

pub use crate::component::bindings::memory::Host as MemoryHost;

pub const MAX_SIGNALS_PER_WINDOW: u32 = 64;

/// One device's interrupt notification budget.
pub struct InterruptSignals {
    window_count: u32,
    dropped: u64,
}

impl InterruptSignals {
    #[must_use]
    pub fn new() -> Self {
        Self {
            window_count: 0,
            dropped: 0,
        }
    }

    pub fn signal(&mut self) -> bool {
        if self.window_count >= MAX_SIGNALS_PER_WINDOW {
            self.dropped += 1;
            return false;
        }
        self.window_count += 1;
        true
    }

    pub fn end_window(&mut self) {
        self.window_count = 0;
    }

    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

impl Default for InterruptSignals {
    fn default() -> Self {
        Self::new()
    }
}

/// Common WASI, guest memory and interrupt state for one device.
pub struct DeviceContext {
    ctx: WasiCtx,
    table: ResourceTable,
    ram: GuestRam,
    irq: InterruptSignals,
    interrupt_asserted: bool,
    interrupt_notification: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    memory_read_calls: Arc<[std::sync::atomic::AtomicU64; 2]>,
}

impl DeviceContext {
    #[must_use]
    pub fn new(ram_size: u64) -> Option<Self> {
        Some(Self::with_ram(GuestRam::new(ram_size)?))
    }

    /// Attach an already-mapped RAM alias (for example the VM worker's
    /// mapping) instead of allocating. The memory imports keep their
    /// bounds; only the backing mapping changes.
    #[must_use]
    pub fn with_ram(ram: GuestRam) -> Self {
        Self {
            ctx: WasiCtxBuilder::new()
                .max_random_size(MAX_SINGLE_BYTES)
                .allow_tcp(false)
                .allow_udp(false)
                .allow_ip_name_lookup(false)
                .build(),
            table: ResourceTable::new(),
            ram,
            irq: InterruptSignals::new(),
            interrupt_asserted: false,
            interrupt_notification: Arc::new(tokio::sync::Notify::new()),
            #[cfg(test)]
            memory_read_calls: Arc::new([
                std::sync::atomic::AtomicU64::new(0),
                std::sync::atomic::AtomicU64::new(0),
            ]),
        }
    }

    pub(crate) fn guest_ram(&self) -> &GuestRam {
        &self.ram
    }

    fn memory(&self) -> BoundedMemory<'_> {
        BoundedMemory::new(&self.ram)
    }

    #[must_use]
    pub fn interrupt_notification(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.interrupt_notification)
    }

    #[must_use]
    pub fn signals_dropped(&self) -> u64 {
        self.irq.dropped()
    }

    pub fn guest_write(
        &mut self,
        offset: u64,
        data: &[u8],
    ) -> Result<(), crate::memory::MemoryError> {
        self.memory().write(offset, data)
    }

    #[cfg(test)]
    pub(crate) fn memory_read_import_counters(&self) -> Arc<[std::sync::atomic::AtomicU64; 2]> {
        Arc::clone(&self.memory_read_calls)
    }

    pub(crate) fn interrupt_asserted(&self) -> bool {
        self.interrupt_asserted
    }

    /// End the interrupt coalescing window so the next burst is counted
    /// fresh. Called by the scheduler between turns, never by guests.
    pub fn end_window(&mut self) {
        self.irq.end_window();
    }
}

impl WasiView for DeviceContext {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

pub trait DeviceHost: WasiView + Send + 'static {
    fn context(&mut self) -> &mut DeviceContext;
}

impl DeviceHost for DeviceContext {
    fn context(&mut self) -> &mut DeviceContext {
        self
    }
}

fn memory_error(error: crate::memory::MemoryError) -> memory::MemoryError {
    match error {
        crate::memory::MemoryError::OutOfRange => memory::MemoryError::OutOfRange,
        crate::memory::MemoryError::TooLarge => memory::MemoryError::TooLarge,
        crate::memory::MemoryError::Unmapped => memory::MemoryError::Unmapped,
    }
}

impl memory::Host for DeviceContext {
    fn read(&mut self, offset: u64, len: u64) -> Result<Vec<u8>, memory::MemoryError> {
        #[cfg(test)]
        {
            self.memory_read_calls[0].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.memory().read(offset, len).map_err(memory_error)
    }

    fn read_ranges(
        &mut self,
        ranges: Vec<memory::ReadRange>,
    ) -> Result<Vec<u8>, memory::MemoryError> {
        if ranges.len() > terra_limits::MAX_BATCH_GUEST_COPY_RANGES {
            return Err(memory::MemoryError::TooLarge);
        }
        #[cfg(test)]
        {
            self.memory_read_calls[1].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let ranges = ranges
            .into_iter()
            .map(|range| terra_platform::memory::MemoryRange {
                addr: range.offset,
                len: range.len,
            })
            .collect::<Vec<_>>();
        self.memory().read_ranges(&ranges).map_err(memory_error)
    }

    fn write(&mut self, offset: u64, data: Vec<u8>) -> Result<(), memory::MemoryError> {
        self.memory().write(offset, &data).map_err(memory_error)
    }

    fn write_ranges(&mut self, ranges: Vec<memory::WriteRange>) -> Result<(), memory::MemoryError> {
        if ranges.len() > terra_limits::MAX_BATCH_GUEST_COPY_RANGES {
            return Err(memory::MemoryError::TooLarge);
        }
        let ranges = ranges
            .iter()
            .map(|range| (range.offset, range.data.as_slice()))
            .collect::<Vec<_>>();
        self.memory().write_ranges(&ranges).map_err(memory_error)
    }

    fn address_limit(&mut self) -> u64 {
        self.ram.address_limit()
    }
}

impl interrupt::Host for DeviceContext {
    fn set_asserted(&mut self, asserted: bool) {
        if self.interrupt_asserted != asserted {
            self.interrupt_asserted = asserted;
            if self.irq.signal() {
                self.interrupt_notification.notify_one();
            }
        }
    }
}

pub fn add_device_imports<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    context: fn(&mut T) -> &mut DeviceContext,
) -> wasmtime::Result<()> {
    use wasmtime::component::HasSelf;
    memory::add_to_linker::<T, HasSelf<DeviceContext>>(linker, context)?;
    interrupt::add_to_linker::<T, HasSelf<DeviceContext>>(linker, context)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::interrupt::Host as _;
    use std::assert_matches;

    /// Flips the line through the import so every call is a change that spends one wakeup.
    fn toggle_interrupt(context: &mut super::DeviceContext) {
        let asserted = context.interrupt_asserted();
        context.set_asserted(!asserted);
    }

    /// The address-limit import supplies the exclusive guest address bound
    /// used by device transports to validate descriptor addresses, including ARM RAM.
    #[test]
    fn device_memory_import_preserves_nonzero_guest_address_bounds() {
        use super::memory::Host as _;
        let ram = crate::memory::GuestRam::from_memory(
            terra_platform::memory::GuestMemory::allocate_at(0x4000_0000, 4096).unwrap(),
        );
        let mut host = super::DeviceContext::with_ram(ram);
        assert_eq!(host.address_limit(), 0x4000_1000);
        host.write(0x4000_0000, vec![7]).unwrap();
        assert_eq!(host.read(0x4000_0000, 1).unwrap(), vec![7]);
        assert!(host.read(0, 1).is_err());
        assert_eq!(
            host.write_ranges(vec![
                super::memory::WriteRange {
                    offset: 0x4000_0000,
                    data: vec![9],
                },
                super::memory::WriteRange {
                    offset: 0,
                    data: vec![1],
                },
            ]),
            Err(super::memory::MemoryError::OutOfRange)
        );
        assert_eq!(host.read(0x4000_0000, 1).unwrap(), vec![7]);
    }

    #[test]
    fn device_memory_import_rejects_oversized_writes_without_mutation() {
        use super::memory::Host as _;
        let size = usize::try_from(crate::MAX_SINGLE_BYTES).unwrap() + 1;
        let mut host = super::DeviceContext::new(size as u64).unwrap();
        host.write(0, vec![7]).unwrap();
        assert_matches!(
            host.write(0, vec![9; size]),
            Err(super::memory::MemoryError::TooLarge)
        );
        assert_eq!(host.read(0, 1).unwrap(), vec![7]);
    }

    #[test]
    fn device_memory_import_validates_batched_writes_before_mutation() {
        use super::memory::{Host as _, MemoryError, WriteRange};
        let mut host = super::DeviceContext::new(4096).unwrap();
        host.write(0, b"seed".to_vec()).unwrap();
        assert_eq!(
            host.write_ranges(vec![
                WriteRange {
                    offset: 0,
                    data: b"edit".to_vec(),
                },
                WriteRange {
                    offset: 4096,
                    data: vec![1],
                },
            ]),
            Err(MemoryError::OutOfRange)
        );
        assert_eq!(host.read(0, 4).unwrap(), b"seed");
        host.write_ranges(vec![
            WriteRange {
                offset: 0,
                data: b"first".to_vec(),
            },
            WriteRange {
                offset: 0,
                data: b"last".to_vec(),
            },
        ])
        .unwrap();
        assert_eq!(host.read(0, 5).unwrap(), b"lastt");
    }

    #[test]
    fn interrupt_wakeups_are_coalesced_and_device_scoped() {
        use std::future::Future as _;
        use std::task::{Context, Poll, Waker};

        let mut first = super::DeviceContext::new(4096).expect("first device");
        let second = super::DeviceContext::new(4096).expect("second device");
        let first_wake = first.interrupt_notification();
        let second_wake = second.interrupt_notification();
        toggle_interrupt(&mut first);
        toggle_interrupt(&mut first);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(
            std::pin::pin!(first_wake.notified()).poll(&mut context),
            Poll::Ready(())
        );
        assert!(
            std::pin::pin!(first_wake.notified())
                .poll(&mut context)
                .is_pending()
        );
        assert!(
            std::pin::pin!(second_wake.notified())
                .poll(&mut context)
                .is_pending()
        );
        toggle_interrupt(&mut first);
        assert_eq!(
            std::pin::pin!(first_wake.notified()).poll(&mut context),
            Poll::Ready(())
        );
        for _ in 0..crate::component::context::MAX_SIGNALS_PER_WINDOW {
            toggle_interrupt(&mut first);
        }
        assert_eq!(
            std::pin::pin!(first_wake.notified()).poll(&mut context),
            Poll::Ready(())
        );
        toggle_interrupt(&mut first);
        assert!(
            std::pin::pin!(first_wake.notified())
                .poll(&mut context)
                .is_pending()
        );
    }

    #[test]
    fn published_interrupt_asserted_states_are_device_scoped_and_survive_coalescing() {
        use std::future::Future as _;
        use std::task::{Context, Poll, Waker};

        let mut first = super::DeviceContext::new(4096).unwrap();
        let second = super::DeviceContext::new(4096).unwrap();
        let wake = first.interrupt_notification();
        first.set_asserted(true);
        assert!(first.interrupt_asserted());
        assert!(!second.interrupt_asserted());
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(
            std::pin::pin!(wake.notified()).poll(&mut context),
            Poll::Ready(())
        );
        first.set_asserted(true);
        assert!(
            std::pin::pin!(wake.notified())
                .poll(&mut context)
                .is_pending()
        );
        for _ in 0..crate::component::context::MAX_SIGNALS_PER_WINDOW {
            toggle_interrupt(&mut first);
        }
        first.set_asserted(false);
        assert!(!first.interrupt_asserted());
        assert!(first.signals_dropped() > 0);
        assert_eq!(
            std::pin::pin!(wake.notified()).poll(&mut context),
            Poll::Ready(())
        );
        assert!(
            std::pin::pin!(wake.notified())
                .poll(&mut context)
                .is_pending()
        );
        first.end_window();
        first.set_asserted(false);
        assert!(
            std::pin::pin!(wake.notified())
                .poll(&mut context)
                .is_pending()
        );
        first.set_asserted(true);
        assert_eq!(
            std::pin::pin!(wake.notified()).poll(&mut context),
            Poll::Ready(())
        );
    }
}
