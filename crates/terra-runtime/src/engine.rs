//! Wasmtime engine configuration and bounded device capability imports.

use crate::component::block::backing::BlockBacking;
pub use crate::component::block::backing::DiskGrant;

use super::{BoundedDisk, BoundedMemory, Interrupt, MAX_SINGLE_BYTES, SyntheticRam};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use wasmtime::component::{Component, ComponentExportIndex};
use wasmtime::{Config, Engine, ResourceLimiter, Store};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// Guest linear memory ceiling per device store. Debug components
/// start near 17 pages; release/opt builds shrink. Re-measure before
/// treating this as a budget.
pub const STORE_MEMORY_BYTES: usize =
    (crate::box_runtime::DEFAULT_COMPONENT_MEMORY_MIB as usize) << 20;
pub const MAX_DEVICE_RESOURCES: usize = 512;
pub(crate) const COMPONENT_EPOCH_DEADLINE: u64 = 10;

/// One device's host state: the WASI context with no grants, the guest
/// RAM the bounded imports expose, the interrupt the device may
/// signal but never name, and the one fixed-capacity disk grant bound
/// at instantiation. Component-supplied values never select another
/// disk, VM, or interrupt line.
pub struct DeviceHost {
    ctx: WasiCtx,
    table: ResourceTable,
    ram: SyntheticRam,
    irq: Interrupt,
    interrupt_level: bool,
    interrupt_notification: Arc<tokio::sync::Notify>,
    disk: Arc<Mutex<DiskGrant>>,
    disk_capacity: u64,
    disk_job: Arc<AtomicBool>,
    network_policy: Option<terra_network::PolicyHandle>,
    network_lookups: Arc<tokio::sync::Semaphore>,
    network_policy_calls: Arc<tokio::sync::Semaphore>,
    vsock_service: crate::component::vsock::host::VsockHostService,
    component_memory_bytes: usize,
}

impl DeviceHost {
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
            disk: Arc::new(Mutex::new(DiskGrant::Mem(BoundedDisk::new(0, false)))),
            disk_capacity: 0,
            disk_job: Arc::new(AtomicBool::new(false)),
            network_policy: None,
            network_lookups: Arc::new(tokio::sync::Semaphore::new(
                crate::component::network::host::MAX_NAME_LOOKUPS,
            )),
            network_policy_calls: Arc::new(tokio::sync::Semaphore::new(
                crate::component::network::host::MAX_POLICY_CALLS,
            )),
            vsock_service: crate::component::vsock::host::VsockHostService::default(),
            component_memory_bytes: STORE_MEMORY_BYTES,
        }
    }

    pub fn set_disk(&mut self, disk: DiskGrant) {
        self.disk_capacity = disk.capacity();
        self.disk = Arc::new(Mutex::new(disk));
    }

    pub fn set_network_policy(
        &mut self,
        policy: terra_network::PolicyHandle,
        host_service_ports: Vec<Option<u16>>,
        published_ports: Vec<terra_network::PortMapping>,
    ) {
        self.ctx = crate::component::network::policy::build_network_context(
            Arc::clone(&policy),
            Arc::clone(&self.network_policy_calls),
            host_service_ports,
            published_ports,
        );
        self.network_policy = Some(policy);
    }

    pub fn set_vsock_service(&mut self, service: crate::component::vsock::host::VsockHostService) {
        self.vsock_service = service;
    }

    pub fn vsock_service_mut(&mut self) -> &mut crate::component::vsock::host::VsockHostService {
        &mut self.vsock_service
    }

    pub(crate) fn network_policy(&self) -> Option<terra_network::PolicyHandle> {
        self.network_policy.clone()
    }

    pub(crate) fn network_lookups(&self) -> Arc<tokio::sync::Semaphore> {
        Arc::clone(&self.network_lookups)
    }

    pub(crate) fn network_policy_calls(&self) -> Arc<tokio::sync::Semaphore> {
        Arc::clone(&self.network_policy_calls)
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

struct DiskJob(Arc<AtomicBool>);

impl DiskJob {
    fn acquire(slot: &Arc<AtomicBool>) -> Option<Self> {
        slot.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self(Arc::clone(slot)))
    }
}

impl Drop for DiskJob {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl WasiView for DeviceHost {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

impl ResourceLimiter for DeviceHost {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= self.component_memory_bytes)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= 1024)
    }

    fn instances(&self) -> usize {
        16
    }

    fn memories(&self) -> usize {
        4
    }

    fn tables(&self) -> usize {
        8
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
    Engine::new(&config)
}

/// Store for one device with an epoch deadline and fixed resource limits.
/// WASI starts with no env, no args, no preopens, and no network.
#[must_use]
pub fn device_store(engine: &Engine, ram_size: u64) -> Option<Store<DeviceHost>> {
    Some(device_store_with_ram(engine, SyntheticRam::new(ram_size)?))
}

/// Store for one device over an aliased RAM mapping. The worker passes
/// `machine.shared_ram()` here so the component's memory imports reach
/// the VM's RAM instead of a private copy.
#[must_use]
pub fn device_store_with_ram(engine: &Engine, ram: SyntheticRam) -> Store<DeviceHost> {
    device_store_with_ram_and_limits(
        engine,
        ram,
        crate::box_runtime::ComponentMemoryLimits::default(),
    )
}

/// Store for one device with the box's configured component-memory limit.
#[must_use]
pub fn device_store_with_ram_and_limits(
    engine: &Engine,
    ram: SyntheticRam,
    limits: crate::box_runtime::ComponentMemoryLimits,
) -> Store<DeviceHost> {
    let mut host = DeviceHost::with_ram(ram);
    host.component_memory_bytes = limits.component_bytes();
    let mut store = Store::new(engine, host);
    store.set_epoch_deadline(1);
    store.limiter(|host| host);
    store
}

pub(crate) fn component_export(
    component: &Component,
    interface: &str,
    export: &str,
    device: &str,
) -> wasmtime::Result<ComponentExportIndex> {
    let interface_index = component
        .get_export_index(None, interface)
        .ok_or_else(|| wasmtime::Error::msg(format!("{device} interface {interface} missing")))?;
    component
        .get_export_index(Some(&interface_index), export)
        .ok_or_else(|| wasmtime::Error::msg(format!("{device} export {export} missing")))
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

pub struct DeviceWasiGetters<T> {
    pub cli: for<'a> fn(&'a mut T) -> wasmtime_wasi::cli::WasiCliCtxView<'a>,
    pub clocks: for<'a> fn(&'a mut T) -> wasmtime_wasi::clocks::WasiClocksCtxView<'a>,
}

impl<T> Copy for DeviceWasiGetters<T> {}

impl<T> Clone for DeviceWasiGetters<T> {
    fn clone(&self) -> Self {
        *self
    }
}

pub fn device_component_linker_with_wasi<T>(
    engine: &Engine,
    wasi: DeviceWasiGetters<T>,
) -> wasmtime::Result<wasmtime::component::Linker<T>>
where
    T: Send + 'static,
{
    use wasmtime_wasi::{
        cli::WasiCli,
        clocks::WasiClocks,
        p3::bindings::{
            cli::{
                environment, exit, stderr, stdin, stdout, terminal_input, terminal_output,
                terminal_stderr, terminal_stdin, terminal_stdout,
            },
            clocks::{monotonic_clock, system_clock, types},
        },
    };

    let mut linker = wasmtime::component::Linker::new(engine);
    exit::add_to_linker::<T, WasiCli>(&mut linker, wasi.cli)?;
    environment::add_to_linker::<T, WasiCli>(&mut linker, wasi.cli)?;
    stdin::add_to_linker::<T, WasiCli>(&mut linker, wasi.cli)?;
    stdout::add_to_linker::<T, WasiCli>(&mut linker, wasi.cli)?;
    stderr::add_to_linker::<T, WasiCli>(&mut linker, wasi.cli)?;
    terminal_input::add_to_linker::<T, WasiCli>(&mut linker, wasi.cli)?;
    terminal_output::add_to_linker::<T, WasiCli>(&mut linker, wasi.cli)?;
    terminal_stdin::add_to_linker::<T, WasiCli>(&mut linker, wasi.cli)?;
    terminal_stdout::add_to_linker::<T, WasiCli>(&mut linker, wasi.cli)?;
    terminal_stderr::add_to_linker::<T, WasiCli>(&mut linker, wasi.cli)?;
    types::add_to_linker::<T, WasiClocks>(&mut linker, wasi.clocks)?;
    monotonic_clock::add_to_linker::<T, WasiClocks>(&mut linker, wasi.clocks)?;
    system_clock::add_to_linker::<T, WasiClocks>(&mut linker, wasi.clocks)?;
    Ok(linker)
}

wasmtime::component::bindgen!({
    world: "block-device",
    path: "../../components/wit/terra",
});

pub use exports::terra::host::device_api::Completion;
pub use terra::mmio::types::DeviceError;

fn memory_error(error: super::MemoryError) -> terra::host::memory::MemoryError {
    match error {
        super::MemoryError::OutOfRange => terra::host::memory::MemoryError::OutOfRange,
        super::MemoryError::TooLarge => terra::host::memory::MemoryError::TooLarge,
        super::MemoryError::Unmapped => terra::host::memory::MemoryError::Unmapped,
    }
}

impl terra::mmio::types::Host for DeviceHost {}

impl terra::host::memory::Host for DeviceHost {
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

impl terra::host::interrupt::Host for DeviceHost {
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

impl terra::host::diagnostics::Host for DeviceHost {
    fn event(&mut self, message: String) {
        log::warn!("network: {message}");
    }
}

fn run_disk_job<T: Send + 'static, F>(
    host: &mut DeviceHost,
    offset: u64,
    len: u64,
    operation: F,
) -> impl core::future::Future<Output = Result<T, terra::host::disk::DiskError>> + Send + use<T, F>
where
    F: FnOnce(&mut DiskGrant) -> Result<T, crate::component::block::backing::BackingError>
        + Send
        + 'static,
{
    let disk = Arc::clone(&host.disk);
    let capacity = host.disk_capacity;
    let job = DiskJob::acquire(&host.disk_job);
    async move {
        use crate::component::block::backing::BackingError;
        use terra::host::disk::DiskError;
        if len > MAX_SINGLE_BYTES {
            return Err(DiskError::TooLarge);
        }
        if offset.checked_add(len).is_none_or(|end| end > capacity) {
            return Err(DiskError::OutOfRange);
        }
        let job = job.ok_or(DiskError::Busy)?;
        tokio::task::spawn_blocking(move || {
            let _job = job;
            let mut disk = disk.lock().map_err(|_| DiskError::Io)?;
            operation(&mut disk).map_err(|error| match error {
                BackingError::OutOfRange => DiskError::OutOfRange,
                BackingError::ReadOnly => DiskError::Readonly,
                BackingError::Io => DiskError::Io,
            })
        })
        .await
        .map_err(|_| DiskError::Io)?
    }
}

impl<T: Send + 'static> terra::host::disk::HostWithStore<T> for TerraHost {
    fn read_at(
        host: &wasmtime::component::Accessor<T, Self>,
        offset: u64,
        len: u64,
    ) -> impl core::future::Future<Output = Result<Vec<u8>, terra::host::disk::DiskError>> + Send
    {
        host.with(|mut access| disk_read_at(access.get(), offset, len))
    }
    fn write_at(
        host: &wasmtime::component::Accessor<T, Self>,
        offset: u64,
        data: Vec<u8>,
    ) -> impl core::future::Future<Output = Result<(), terra::host::disk::DiskError>> + Send {
        host.with(|mut access| disk_write_at(access.get(), offset, data))
    }
    fn sync(
        host: &wasmtime::component::Accessor<T, Self>,
    ) -> impl core::future::Future<Output = Result<(), terra::host::disk::DiskError>> + Send {
        host.with(|mut access| disk_sync(access.get()))
    }
}

fn disk_read_at(
    host: &mut DeviceHost,
    offset: u64,
    len: u64,
) -> impl core::future::Future<Output = Result<Vec<u8>, terra::host::disk::DiskError>> + Send + use<>
{
    run_disk_job(host, offset, len, move |disk| {
        let len = usize::try_from(len)
            .map_err(|_| crate::component::block::backing::BackingError::OutOfRange)?;
        let mut bytes = vec![0; len];
        disk.read_at(offset, &mut bytes)?;
        Ok(bytes)
    })
}

fn disk_write_at(
    host: &mut DeviceHost,
    offset: u64,
    data: Vec<u8>,
) -> impl core::future::Future<Output = Result<(), terra::host::disk::DiskError>> + Send + use<> {
    run_disk_job(host, offset, data.len() as u64, move |disk| {
        disk.write_at(offset, &data)
    })
}

fn disk_sync(
    host: &mut DeviceHost,
) -> impl core::future::Future<Output = Result<(), terra::host::disk::DiskError>> + Send + use<> {
    run_disk_job(host, 0, 0, |disk| disk.sync())
}

impl terra::host::disk::Host for DeviceHost {
    fn capacity(&mut self) -> u64 {
        self.disk_capacity
    }
}

/// Marker for the terra host imports in [`block_component_linker`]:
/// the [`DeviceHost`] itself implements every generated [`terra`] host
/// trait, reached through a plain mutable borrow.
pub(crate) struct TerraHost;

impl wasmtime::component::HasData for TerraHost {
    type Data<'a> = &'a mut DeviceHost;
}

/// One validated guest data range passed to the block component per
/// request. Field names and order match `components/wit/terra/host.wit`.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    wasmtime::component::ComponentType,
    wasmtime::component::Lower,
)]
#[component(record)]
pub struct Range {
    #[component(name = "addr")]
    pub addr: u64,
    #[component(name = "len")]
    pub len: u64,
}

/// Linker for real block components: WASI P3 plus the terra
/// memory/interrupt/disk imports bound to this device's
/// checked adapters and its one disk grant. The import set is fixed
/// here; nothing is added at runtime.
pub fn block_component_linker(
    engine: &Engine,
) -> wasmtime::Result<wasmtime::component::Linker<DeviceHost>> {
    let mut linker = device_component_linker(engine)?;
    BlockDevice::add_to_linker::<DeviceHost, TerraHost>(&mut linker, |host| host)?;
    Ok(linker)
}

pub fn vsock_component_linker(
    engine: &Engine,
) -> wasmtime::Result<wasmtime::component::Linker<DeviceHost>> {
    let mut linker = device_component_linker(engine)?;
    wasmtime_wasi::p3::bindings::random::random::add_to_linker::<
        DeviceHost,
        wasmtime_wasi::random::WasiRandom,
    >(&mut linker, wasmtime_wasi::random::WasiRandomView::random)?;
    crate::component::vsock::host::terra::vsock::host_service::add_to_linker::<
        DeviceHost,
        crate::component::vsock::host::VsockHost,
    >(&mut linker, |host| host.vsock_service_mut())?;
    terra::host::memory::add_to_linker::<DeviceHost, TerraHost>(&mut linker, |host| host)?;
    terra::host::interrupt::add_to_linker::<DeviceHost, TerraHost>(&mut linker, |host| host)?;
    Ok(linker)
}

pub fn vsock_component_linker_with_host<T>(
    engine: &Engine,
    wasi: DeviceWasiGetters<T>,
    host: for<'a> fn(&'a mut T) -> &'a mut DeviceHost,
    random: for<'a> fn(&'a mut T) -> &'a mut wasmtime_wasi::random::WasiRandomCtx,
    vsock_service: for<'a> fn(&'a mut T) -> &'a mut crate::component::vsock::host::VsockHostService,
) -> wasmtime::Result<wasmtime::component::Linker<T>>
where
    T: Send + 'static,
{
    use wasmtime_wasi::{p3::bindings::random::random as random_bindings, random::WasiRandom};

    let mut linker = device_component_linker_with_wasi(engine, wasi)?;
    random_bindings::add_to_linker::<T, WasiRandom>(&mut linker, random)?;
    crate::component::vsock::host::terra::vsock::host_service::add_to_linker::<
        T,
        crate::component::vsock::host::VsockHost,
    >(&mut linker, vsock_service)?;
    terra::host::memory::add_to_linker::<T, TerraHost>(&mut linker, host)?;
    terra::host::interrupt::add_to_linker::<T, TerraHost>(&mut linker, host)?;
    Ok(linker)
}

/// Precompile a trusted component build into an AOT artifact for
/// embedding. The shipped runtime deserializes these bytes without
/// invoking the compiler.
#[cfg(any(test, feature = "compiler", feature = "test-support"))]
pub fn precompile_component(engine: &Engine, bytes: &[u8]) -> wasmtime::Result<Vec<u8>> {
    engine.precompile_component(bytes)
}

/// Deserialize a build-embedded component artifact.
///
/// # Safety
///
/// `artifact` must be trusted AOT output from this exact Wasmtime build,
/// never runtime input.
#[allow(unsafe_code)]
pub unsafe fn trusted_component(
    engine: &Engine,
    artifact: &'static [u8],
) -> wasmtime::Result<wasmtime::component::Component> {
    // SAFETY: the caller guarantees the artifact's trusted build provenance.
    unsafe { wasmtime::component::Component::deserialize(engine, artifact) }
}

pub fn add_device_imports<T, G>(
    linker: &mut wasmtime::component::Linker<T>,
    host: G,
) -> wasmtime::Result<()>
where
    T: Send + 'static,
    G: Fn(&mut T) -> &mut DeviceHost + Send + Sync + Copy + 'static,
{
    use terra::host::{interrupt::Host as _, memory::Host as _};
    let mut memory = linker.instance("terra:host/memory@0.1.0")?;
    memory.func_wrap("read", move |mut store, (offset, len): (u64, u64)| {
        Ok((host(store.data_mut()).read(offset, len),))
    })?;
    memory.func_wrap("write", move |mut store, (offset, data): (u64, Vec<u8>)| {
        Ok((host(store.data_mut()).write(offset, data),))
    })?;
    memory.func_wrap("ram-bytes", move |mut store, (): ()| {
        Ok((host(store.data_mut()).ram_bytes(),))
    })?;
    linker.instance("terra:host/interrupt@0.1.0")?.func_wrap(
        "set-level",
        move |mut store, (level,): (bool,)| {
            host(store.data_mut()).set_level(level);
            Ok(())
        },
    )?;
    linker.instance("terra:host/interrupt@0.1.0")?.func_wrap(
        "signal",
        move |mut store, (): ()| {
            host(store.data_mut()).signal();
            Ok(())
        },
    )?;
    Ok(())
}

pub fn block_component_linker_captured<T, G>(
    engine: &Engine,
    wasi: DeviceWasiGetters<T>,
    host: G,
) -> wasmtime::Result<wasmtime::component::Linker<T>>
where
    T: Send + 'static,
    G: Fn(&mut T) -> &mut DeviceHost + Send + Sync + Copy + 'static,
{
    let mut linker = device_component_linker_with_wasi(engine, wasi)?;
    add_device_imports(&mut linker, host)?;
    let mut disk = linker.instance("terra:host/disk@0.1.0")?;
    disk.func_wrap("capacity", move |mut store, (): ()| {
        Ok((host(store.data_mut()).disk_capacity,))
    })?;
    disk.func_wrap_concurrent("read-at", move |accessor, (offset, len): (u64, u64)| {
        let operation =
            accessor.with(|mut access| disk_read_at(host(access.data_mut()), offset, len));
        Box::pin(async move { Ok((operation.await,)) })
    })?;
    disk.func_wrap_concurrent(
        "write-at",
        move |accessor, (offset, data): (u64, Vec<u8>)| {
            let operation =
                accessor.with(|mut access| disk_write_at(host(access.data_mut()), offset, data));
            Box::pin(async move { Ok((operation.await,)) })
        },
    )?;
    disk.func_wrap_concurrent("sync", move |accessor, (): ()| {
        let operation = accessor.with(|mut access| disk_sync(host(access.data_mut())));
        Box::pin(async move { Ok((operation.await,)) })
    })?;
    Ok(linker)
}

#[cfg(test)]
mod tests {
    #[test]
    fn device_memory_limit_is_configurable() {
        use wasmtime::ResourceLimiter as _;

        let engine = super::device_engine().expect("engine");
        let limits = crate::box_runtime::ComponentMemoryLimits::new(65_536, 65_536)
            .expect("component limits");
        let mut store = super::device_store_with_ram_and_limits(
            &engine,
            crate::SyntheticRam::new(4096).expect("RAM"),
            limits,
        );
        assert!(store.data_mut().memory_growing(0, 65_536, None).unwrap());
        assert!(!store.data_mut().memory_growing(0, 65_537, None).unwrap());
    }

    #[test]
    fn device_engine_rejects_unused_memory_models() {
        let engine = super::device_engine().expect("engine");
        for module in ["(module (memory i64 1))", "(module (memory 1 1 shared))"] {
            assert!(wasmtime::Module::new(&engine, module).is_err());
        }
        wasmtime::Module::new(&engine, "(module (memory 1))").expect("ordinary memory");
    }

    #[test]
    fn interrupt_wakeups_are_coalesced_and_device_scoped() {
        use super::terra::host::interrupt::Host as _;
        use std::future::Future as _;
        use std::task::{Context, Poll, Waker};

        let mut first = super::DeviceHost::new(4096).expect("first device");
        let second = super::DeviceHost::new(4096).expect("second device");
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

        let mut first = super::DeviceHost::new(4096).unwrap();
        let second = super::DeviceHost::new(4096).unwrap();
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

    #[tokio::test]
    async fn disk_imports_enforce_bounds_and_readonly_without_a_guest() {
        use super::terra::host::disk::DiskError;
        use super::{BoundedDisk, DeviceHost, DiskGrant, disk_read_at, disk_sync, disk_write_at};

        let mut host = DeviceHost::new(4096).expect("host");
        host.set_disk(DiskGrant::Mem(BoundedDisk::new(4096, false)));
        assert_eq!(disk_write_at(&mut host, 4095, vec![7]).await, Ok(()));
        assert_eq!(disk_read_at(&mut host, 4095, 1).await, Ok(vec![7]));
        assert!(matches!(
            disk_read_at(&mut host, 0, super::MAX_SINGLE_BYTES + 1).await,
            Err(DiskError::TooLarge)
        ));
        assert!(matches!(
            disk_write_at(&mut host, u64::MAX, vec![1]).await,
            Err(DiskError::OutOfRange)
        ));
        assert!(matches!(
            disk_read_at(&mut host, 4096, 1).await,
            Err(DiskError::OutOfRange)
        ));
        host.set_disk(DiskGrant::Mem(BoundedDisk::new(4096, true)));
        assert!(matches!(
            disk_write_at(&mut host, 0, vec![1]).await,
            Err(DiskError::Readonly)
        ));
        assert_eq!(disk_sync(&mut host).await, Ok(()));
    }

    use super::{Arc, AtomicBool, DiskJob, Ordering};

    #[test]
    fn cancelled_waiter_keeps_its_disk_slot_until_blocking_work_returns() {
        let stalled_slot = Arc::new(AtomicBool::new(false));
        let other_slot = Arc::new(AtomicBool::new(false));
        let job = DiskJob::acquire(&stalled_slot).expect("first disk job admitted");
        let (started, started_rx) = std::sync::mpsc::sync_channel(0);
        let (release, release_rx) = std::sync::mpsc::sync_channel(0);
        let worker = std::thread::spawn(move || {
            let _job = job;
            started.send(()).expect("work started");
            release_rx.recv().expect("work released");
        });
        started_rx.recv().expect("work is running");
        assert!(DiskJob::acquire(&stalled_slot).is_none());
        assert!(DiskJob::acquire(&other_slot).is_some());
        release.send(()).expect("work unblocked");
        worker.join().expect("work joined");
        assert!(DiskJob::acquire(&stalled_slot).is_some());
        assert!(!stalled_slot.load(Ordering::Acquire));
    }
}
