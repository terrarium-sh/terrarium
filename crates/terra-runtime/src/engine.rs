//! Wasmtime engine configuration and bounded device capability imports.

use crate::component::block::host::terra;

use super::{BoundedMemory, Interrupt, MAX_SINGLE_BYTES, SyntheticRam};
use std::sync::Arc;
use wasmtime::{Config, Engine};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// Guest linear memory ceiling per device store. Debug components
/// start near 17 pages; release/opt builds shrink. Re-measure before
/// treating this as a budget.
pub const STORE_MEMORY_BYTES: usize =
    (crate::box_runtime::DEFAULT_COMPONENT_MEMORY_MIB as usize) << 20;
pub const MAX_DEVICE_RESOURCES: usize = 512;
pub(crate) const COMPONENT_EPOCH_DEADLINE: u64 = 10;

/// Common WASI, guest memory and interrupt state for one device.
pub struct DeviceContext {
    ctx: WasiCtx,
    table: ResourceTable,
    ram: SyntheticRam,
    irq: Interrupt,
    interrupt_level: bool,
    interrupt_notification: Arc<tokio::sync::Notify>,
}

impl DeviceContext {
    #[must_use]
    pub fn new(ram_size: u64) -> Option<Self> {
        Some(Self::with_ram(SyntheticRam::new(ram_size)?))
    }

    /// Attach an already-mapped RAM alias (for example the VM worker's
    /// mapping) instead of allocating. The memory imports keep their
    /// bounds; only the backing mapping changes.
    #[must_use]
    pub fn with_ram(ram: SyntheticRam) -> Self {
        let mut table = ResourceTable::new();
        table.set_max_capacity(MAX_DEVICE_RESOURCES);
        Self {
            ctx: WasiCtxBuilder::new()
                .max_random_size(MAX_SINGLE_BYTES)
                .allow_tcp(false)
                .allow_udp(false)
                .allow_ip_name_lookup(false)
                .build(),
            table,
            ram,
            irq: Interrupt::new(),
            interrupt_level: false,
            interrupt_notification: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub(crate) fn guest_ram(&self) -> &SyntheticRam {
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

    /// Drain one coalesced notification for injection. True when the
    /// guest needs an interrupt.
    pub fn drain_signal(&mut self) -> bool {
        self.irq.take()
    }

    /// Stage bytes into the synthetic guest RAM backing this device's
    /// memory import. The worker stages real virtqueue memory instead;
    /// the same bounds apply on both paths.
    pub fn guest_write(&mut self, offset: u64, data: &[u8]) -> Result<(), super::MemoryError> {
        self.memory().write(offset, data)
    }

    /// Read back bytes staged in this device's guest RAM.
    pub fn guest_read(&self, offset: u64, len: u64) -> Result<Vec<u8>, super::MemoryError> {
        self.memory().read(offset, len)
    }

    pub(crate) fn interrupt_level(&self) -> bool {
        self.interrupt_level
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

/// Engine for device stores with epoch interruption and async components.
pub fn device_engine() -> wasmtime::Result<Engine> {
    configured_device_engine(false)
}

pub fn policy_engine() -> wasmtime::Result<Engine> {
    configured_device_engine(true)
}

fn configured_device_engine(fuel: bool) -> wasmtime::Result<Engine> {
    let mut config = Config::new();
    apply_device_settings(&mut config, fuel)?;
    Engine::new(&config)
}

fn apply_device_settings(config: &mut Config, fuel: bool) -> wasmtime::Result<()> {
    // An explicit host triple disables Wasmtime's CPU feature inference, so
    // embedded AOT components load on any host of the build architecture
    // instead of only hosts matching the build machine's CPU.
    config.target(&target_lexicon::Triple::host().to_string())?;
    #[cfg(feature = "thread-experiments")]
    config.wasm_threads(false);
    config
        .consume_fuel(fuel)
        .epoch_interruption(true)
        .shared_memory(false)
        .wasm_memory64(false)
        .wasm_component_model_threading(false)
        .wasm_component_model_memory64(false)
        .wasm_component_model_async(true)
        .concurrency_support(true);
    Ok(())
}

pub mod test_support {
    use super::{DeviceContext, DeviceHost, Engine, WasiCtxView, WasiView};
    use wasmtime::{Store, StoreLimits, StoreLimitsBuilder};

    pub struct StandaloneHost<H> {
        host: H,
        pub(super) limits: StoreLimits,
    }

    impl<H> std::ops::Deref for StandaloneHost<H> {
        type Target = H;

        fn deref(&self) -> &H {
            &self.host
        }
    }

    impl<H> std::ops::DerefMut for StandaloneHost<H> {
        fn deref_mut(&mut self) -> &mut H {
            &mut self.host
        }
    }

    impl<H> AsMut<H> for StandaloneHost<H> {
        fn as_mut(&mut self) -> &mut H {
            &mut self.host
        }
    }

    impl<H: WasiView> WasiView for StandaloneHost<H> {
        fn ctx(&mut self) -> WasiCtxView<'_> {
            self.host.ctx()
        }
    }

    impl<H: DeviceHost> DeviceHost for StandaloneHost<H> {
        fn context(&mut self) -> &mut DeviceContext {
            self.host.context()
        }
    }

    #[must_use]
    pub fn device_store<H: DeviceHost>(engine: &Engine, host: H) -> Store<StandaloneHost<H>> {
        device_store_with_limits(
            engine,
            host,
            crate::box_runtime::ComponentMemoryLimits::default(),
        )
    }

    /// Store for one standalone device with a per-linear-memory limit.
    #[must_use]
    pub fn device_store_with_limits<H: DeviceHost>(
        engine: &Engine,
        host: H,
        limits: crate::box_runtime::ComponentMemoryLimits,
    ) -> Store<StandaloneHost<H>> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(limits.component_bytes())
            .table_elements(1024)
            .instances(16)
            .memories(4)
            .tables(8)
            .build();
        let mut store = Store::new(engine, StandaloneHost { host, limits });
        store.set_epoch_deadline(1);
        store.limiter(|host| &mut host.limits);
        store
    }
}

/// Running epoch ticker: bumps the engine clock until `stop` is set so
/// epoch deadlines actually fire. The worker owns one per VM; the
/// harness test proves the mechanism with a short interval.
#[must_use]
pub fn spawn_epoch_ticker(
    engine: Engine,
    interval: core::time::Duration,
    stop: std::sync::Arc<core::sync::atomic::AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("epoch-tick".to_string())
        .spawn(move || {
            while !stop.load(core::sync::atomic::Ordering::Acquire) {
                std::thread::sleep(interval);
                engine.increment_epoch();
            }
        })
        .ok()
}

pub fn device_component_linker<T: WasiView + 'static>(
    engine: &Engine,
) -> wasmtime::Result<wasmtime::component::Linker<T>> {
    let mut linker = wasmtime::component::Linker::new(engine);
    wasmtime_wasi::p3::cli::add_to_linker(&mut linker)?;
    wasmtime_wasi::p3::clocks::add_to_linker(&mut linker)?;
    Ok(linker)
}

fn memory_error(error: super::MemoryError) -> terra::host::memory::MemoryError {
    match error {
        super::MemoryError::OutOfRange => terra::host::memory::MemoryError::OutOfRange,
        super::MemoryError::TooLarge => terra::host::memory::MemoryError::TooLarge,
        super::MemoryError::Unmapped => terra::host::memory::MemoryError::Unmapped,
    }
}

impl terra::mmio::types::Host for DeviceContext {}

impl terra::host::memory::Host for DeviceContext {
    fn read(&mut self, offset: u64, len: u64) -> Result<Vec<u8>, terra::host::memory::MemoryError> {
        self.memory().read(offset, len).map_err(memory_error)
    }

    fn write(
        &mut self,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<(), terra::host::memory::MemoryError> {
        if u64::try_from(data.len()).unwrap_or(u64::MAX) > MAX_SINGLE_BYTES {
            return Err(terra::host::memory::MemoryError::TooLarge);
        }
        self.memory().write(offset, &data).map_err(memory_error)
    }

    fn ram_bytes(&mut self) -> u64 {
        self.ram.size()
    }
}

impl terra::host::interrupt::Host for DeviceContext {
    fn set_level(&mut self, level: bool) {
        if self.interrupt_level != level {
            self.interrupt_level = level;
            self.signal();
        }
    }

    fn signal(&mut self) {
        if self.irq.signal() {
            self.interrupt_notification.notify_one();
        }
    }
}

impl terra::host::diagnostics::Host for DeviceContext {
    fn event(&mut self, message: String) {
        log::warn!("network: {message}");
    }
}

pub fn add_device_imports<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    context: fn(&mut T) -> &mut DeviceContext,
) -> wasmtime::Result<()> {
    use wasmtime::component::HasSelf;
    terra::host::memory::add_to_linker::<T, HasSelf<DeviceContext>>(linker, context)?;
    terra::host::interrupt::add_to_linker::<T, HasSelf<DeviceContext>>(linker, context)?;
    Ok(())
}

/// Precompile a trusted component build into an AOT artifact for
/// embedding. The shipped runtime deserializes these bytes without
/// invoking the compiler.
#[cfg(any(test, feature = "compiler", feature = "test-support"))]
pub fn precompile_component(engine: &Engine, bytes: &[u8]) -> wasmtime::Result<Vec<u8>> {
    engine.precompile_component(bytes)
}

#[cfg(test)]
mod tests {
    #[test]
    fn standalone_device_store_applies_per_memory_limit() {
        use wasmtime::ResourceLimiter as _;

        let engine = super::device_engine().expect("engine");
        let limits = crate::box_runtime::ComponentMemoryLimits::new(65_536, 65_536)
            .expect("component limits");
        let mut store = super::test_support::device_store_with_limits(
            &engine,
            super::DeviceContext::new(4096).expect("RAM"),
            limits,
        );
        let memory = wasmtime::Memory::new(&mut store, wasmtime::MemoryType::new(1, None)).unwrap();
        assert!(memory.grow(&mut store, 1).is_err());
        assert_eq!(memory.size(&store), 1);
        wasmtime::Memory::new(&mut store, wasmtime::MemoryType::new(1, None)).unwrap();
        assert!(wasmtime::Memory::new(&mut store, wasmtime::MemoryType::new(2, None)).is_err());
        let limits = &mut store.data_mut().limits;
        assert!(limits.table_growing(0, 1024, None).unwrap());
        assert!(!limits.table_growing(0, 1025, None).unwrap());
        assert_eq!(
            (limits.instances(), limits.memories(), limits.tables()),
            (16, 4, 8)
        );
    }

    #[test]
    fn device_engine_rejects_unused_memory_models() {
        let engine = super::device_engine().expect("engine");
        for module in ["(module (memory i64 1))", "(module (memory 1 1 shared))"] {
            assert!(wasmtime::Module::new(&engine, module).is_err());
        }
        wasmtime::Module::new(&engine, "(module (memory 1))").expect("ordinary memory");
    }

    /// A precompiled artifact must not enable CPU features of the machine that
    /// produced it, or it fails to load on older hosts of the same architecture.
    #[test]
    #[allow(unsafe_code)]
    fn precompiled_artifacts_do_not_require_build_machine_cpu_features() {
        let producer = super::device_engine().expect("engine");
        let artifact = super::precompile_component(&producer, b"(component)").expect("compiles");
        let mut config = wasmtime::Config::new();
        super::apply_device_settings(&mut config, false).expect("settings");
        // SAFETY: the probe only gates ISA flags recorded in the artifact, and
        // denying every feature is exactly a host weaker than the producer's.
        unsafe {
            config.detect_host_feature(|_| Some(false));
        }
        let consumer = wasmtime::Engine::new(&config).expect("engine");
        // SAFETY: the artifact was produced by the trusted engine above.
        unsafe { wasmtime::component::Component::deserialize(&consumer, &artifact) }
            .expect("artifact is host-feature-free");
    }

    #[test]
    fn interrupt_wakeups_are_coalesced_and_device_scoped() {
        use super::terra::host::interrupt::Host as _;
        use std::future::Future as _;
        use std::task::{Context, Poll, Waker};

        let mut first = super::DeviceContext::new(4096).expect("first device");
        let second = super::DeviceContext::new(4096).expect("second device");
        let first_wake = first.interrupt_notification();
        let second_wake = second.interrupt_notification();
        first.signal();
        first.signal();
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
        first.signal();
        assert_eq!(
            std::pin::pin!(first_wake.notified()).poll(&mut context),
            Poll::Ready(())
        );
        for _ in 0..crate::MAX_SIGNALS_PER_WINDOW {
            first.signal();
        }
        assert_eq!(
            std::pin::pin!(first_wake.notified()).poll(&mut context),
            Poll::Ready(())
        );
        first.signal();
        assert!(
            std::pin::pin!(first_wake.notified())
                .poll(&mut context)
                .is_pending()
        );
    }

    #[test]
    fn published_interrupt_levels_are_device_scoped_and_survive_coalescing() {
        use super::terra::host::interrupt::Host as _;
        use std::future::Future as _;
        use std::task::{Context, Poll, Waker};

        let mut first = super::DeviceContext::new(4096).unwrap();
        let second = super::DeviceContext::new(4096).unwrap();
        let wake = first.interrupt_notification();
        first.set_level(true);
        assert!(first.interrupt_level());
        assert!(!second.interrupt_level());
        for _ in 0..crate::MAX_SIGNALS_PER_WINDOW {
            first.signal();
        }
        first.set_level(false);
        assert!(!first.interrupt_level());
        assert!(first.signals_dropped() > 0);
        let mut context = Context::from_waker(Waker::noop());
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
        first.set_level(false);
        assert!(
            std::pin::pin!(wake.notified())
                .poll(&mut context)
                .is_pending()
        );
        first.set_level(true);
        assert_eq!(
            std::pin::pin!(wake.notified()).poll(&mut context),
            Poll::Ready(())
        );
    }
}
