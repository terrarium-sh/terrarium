use std::any::Any;
use std::sync::Arc;

use wasmtime::component::Resource;

pub use super::reaper::VcpuReaper;
use super::{Platform, PlatformHost};
use crate::box_runtime::{BoxHost, BoxRuntime};
use crate::component::vmm::mmio::terra::mmio::virtualization;
pub use crate::component::vmm::mmio::terra::mmio::virtualization::{Architecture, Config, Error};
pub(crate) type InitializeMachine = wasmtime::component::TypedFunc<
    (Config, Resource<Vm>, Vec<Resource<super::Vcpu>>),
    (Result<(), super::machine::Error>,),
>;
pub(crate) type ControlMachine =
    wasmtime::component::TypedFunc<(), (Result<(), super::machine::Error>,)>;
use crate::{BoundedMemory, SyntheticRam};

#[derive(Clone)]
pub struct MachineConfig {
    architecture: Architecture,
    ram_bytes: u64,
    vcpus: u8,
    devices: Vec<super::machine::Device>,
}

impl MachineConfig {
    pub fn new(
        architecture: Architecture,
        ram_bytes: u64,
        vcpus: u8,
        devices: Vec<super::machine::Device>,
    ) -> wasmtime::Result<Self> {
        wasmtime::ensure!(
            vcpus != 0
                && usize::from(vcpus)
                    <= match architecture {
                        Architecture::X86 => super::MAX_VCPUS,
                        Architecture::Arm => terra_limits::ARM_MAX_VCPUS as usize,
                    },
            "vCPU count outside VM grant"
        );
        wasmtime::ensure!(
            ram_bytes != 0 && ram_bytes.is_multiple_of(4096),
            "RAM size outside VM grant"
        );
        wasmtime::ensure!(
            devices.len()
                <= match architecture {
                    Architecture::X86 => terra_limits::X86_MAX_DEVICES,
                    Architecture::Arm => terra_limits::ARM_MAX_DEVICES,
                },
            "device count outside VM grant"
        );
        Ok(Self {
            architecture,
            ram_bytes,
            vcpus,
            devices,
        })
    }

    #[must_use]
    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    #[must_use]
    pub fn ram_bytes(&self) -> u64 {
        self.ram_bytes
    }

    #[must_use]
    pub fn vcpus(&self) -> u8 {
        self.vcpus
    }

    #[must_use]
    pub fn devices(&self) -> &[super::machine::Device] {
        &self.devices
    }

    #[must_use]
    pub fn is_valid_cpu(&self, id: u8) -> bool {
        id < self.vcpus
    }

    fn as_wit(&self) -> Config {
        Config {
            architecture: self.architecture,
            ram_bytes: self.ram_bytes,
            vcpus: self.vcpus,
            devices: self
                .devices
                .iter()
                .map(
                    |device| crate::component::vmm::mmio::terra::mmio::machine_types::Device {
                        kind: device.kind,
                        mmio_base: device.mmio_base,
                        irq: device.irq,
                    },
                )
                .collect(),
        }
    }
}
#[cfg(test)]
mod prepared_machine_tests {
    use super::*;

    struct TestVm(SyntheticRam);

    impl VirtualMachine for TestVm {
        fn memory(&self) -> wasmtime::Result<SyntheticRam> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn prepared_machine_accepts_boot_once() {
        let config = MachineConfig::new(Architecture::X86, 32768, 1, Vec::new()).unwrap();
        let mut machine = PreparedMachine::new(config, TestVm(SyntheticRam::new(32768).unwrap()));
        machine
            .accept_boot(super::super::boot::BootEntry {
                entry: 0,
                boot_argument: 0x7000,
            })
            .unwrap();
        assert!(
            machine
                .accept_boot(super::super::boot::BootEntry {
                    entry: 0,
                    boot_argument: 0x7000,
                })
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn aot_vmm_applies_boot_and_keeps_both_vcpus_responsive() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};
        use vm_memory::{GuestAddress, GuestMemoryMmap};

        for architecture in [Architecture::X86, Architecture::Arm] {
            let engine = crate::engine::device_engine().unwrap();
            // SAFETY: the artifact is produced by this repository's matching AOT build.
            #[allow(unsafe_code)]
            let vmm = unsafe {
                wasmtime::component::Component::deserialize(
                    &engine,
                    include_bytes!("../../../../../build/terra-vmm-component.cwasm"),
                )
                .unwrap()
            };
            let boot = wasmtime::component::Component::new(
                &engine,
                include_bytes!("../../../../../components/boot/target/wasm32-wasip3/release/terra_boot_component.wasm"),
            )
            .unwrap();
            let base = match architecture {
                Architecture::X86 => 0,
                Architecture::Arm => 0x4000_0000,
            };
            let devices = match architecture {
                Architecture::X86 => vec![
                    (super::super::machine::DeviceKind::Block, 0xd000_0000, 11),
                    (super::super::machine::DeviceKind::Block, 0xd000_1000, 12),
                    (super::super::machine::DeviceKind::Net, 0xd000_2000, 13),
                    (super::super::machine::DeviceKind::Vsock, 0xd000_3000, 14),
                    (super::super::machine::DeviceKind::Memory, 0xd000_4000, 15),
                ],
                Architecture::Arm => vec![
                    (super::super::machine::DeviceKind::Block, 0x0a00_0000, 16),
                    (super::super::machine::DeviceKind::Block, 0x0a00_0200, 17),
                    (super::super::machine::DeviceKind::Memory, 0x0a00_0400, 18),
                    (super::super::machine::DeviceKind::Net, 0x0a00_0600, 19),
                    (super::super::machine::DeviceKind::Vsock, 0x0a00_0800, 20),
                ],
            }
            .into_iter()
            .map(|(kind, mmio_base, irq)| super::super::machine::Device {
                kind,
                mmio_base,
                irq,
            })
            .collect();
            let ram = SyntheticRam::from_shared(Arc::new(
                GuestMemoryMmap::from_ranges(&[(GuestAddress(base), 8 << 20)]).unwrap(),
            ))
            .unwrap();
            let config = MachineConfig::new(architecture, 8 << 20, 2, devices).unwrap();
            let mut kernel = vec![0; 65536];
            let (entry, copied) = match architecture {
                Architecture::X86 => {
                    kernel[..4].copy_from_slice(b"\x7fELF");
                    kernel[4] = 2;
                    kernel[5] = 1;
                    kernel[18..20].copy_from_slice(&62_u16.to_le_bytes());
                    kernel[24..32].copy_from_slice(&0x10_0000_u64.to_le_bytes());
                    kernel[32..40].copy_from_slice(&64_u64.to_le_bytes());
                    kernel[56..58].copy_from_slice(&1_u16.to_le_bytes());
                    kernel[64..68].copy_from_slice(&1_u32.to_le_bytes());
                    kernel[72..80].copy_from_slice(&0x100_u64.to_le_bytes());
                    kernel[88..96].copy_from_slice(&0x10_0000_u64.to_le_bytes());
                    kernel[96..104].copy_from_slice(&0xff00_u64.to_le_bytes());
                    kernel[104..112].copy_from_slice(&0x10000_u64.to_le_bytes());
                    kernel[0x100..].fill(42);
                    (0x10_0000, kernel[0x100..].to_vec())
                }
                Architecture::Arm => {
                    kernel[8..16].copy_from_slice(&0x80_000_u64.to_le_bytes());
                    kernel[16..24].copy_from_slice(&0x20_0000_u64.to_le_bytes());
                    kernel[56..60].copy_from_slice(b"ARMd");
                    (base + 0x80_000, kernel.clone())
                }
            };
            let mut prepared = PreparedMachine::new(config, TestVm(ram));
            let boot_entry = BoxRuntime::new(&engine, BoxHost::new())
                .unwrap()
                .boot_prepared_machine(
                    &boot,
                    prepared.config(),
                    prepared.ram().unwrap(),
                    kernel,
                    "root=/dev/vda",
                )
                .await
                .unwrap();
            assert_eq!(boot_entry.entry, entry);
            prepared.accept_boot(boot_entry).unwrap();

            let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).unwrap();
            runtime.initialize_mmio(&vmm).await.unwrap();
            let handle = runtime.attach_machine(prepared).await.unwrap();
            let vcpus = runtime
                .grant_vcpus(move |controls, accepted| {
                    assert_eq!(accepted.entry, entry);
                    Ok(StartedVcpus::new(controls, || Ok(())))
                })
                .await
                .unwrap();
            let backend = handle.machine();
            let memory = BoundedMemory::new(&backend.0);
            for (index, chunk) in copied.chunks(16384).enumerate() {
                assert_eq!(
                    memory
                        .read(entry + index as u64 * 16384, chunk.len() as u64)
                        .unwrap(),
                    chunk
                );
            }
            assert_eq!(memory.read(entry + copied.len() as u64, 4).unwrap(), [0; 4]);
            match architecture {
                Architecture::X86 => {
                    assert_eq!(
                        memory.read(boot_entry.boot_argument + 0x202, 4).unwrap(),
                        b"HdrS"
                    );
                }
                Architecture::Arm => assert_eq!(
                    memory.read(boot_entry.boot_argument, 4).unwrap(),
                    0xd00d_feed_u32.to_be_bytes()
                ),
            }

            let running = runtime.start();
            let mut controls = vcpus.into_iter();
            let busy_cpu = controls.next().unwrap();
            let probe_cpu = controls.next().unwrap();
            let probe_done = Arc::new(AtomicBool::new(false));
            let stop = Arc::clone(&probe_done);
            let (ready, started) = tokio::sync::oneshot::channel();
            let busy = tokio::task::spawn_blocking(move || {
                busy_cpu.exchange(super::super::Exit::Halt).unwrap();
                ready.send(()).unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
                    assert!(matches!(
                        busy_cpu.exchange(super::super::Exit::Halt).unwrap(),
                        super::super::Completion::Reenter
                    ));
                }
            });
            started.await.unwrap();
            let (probe_cpu, completion, elapsed) = tokio::task::spawn_blocking(move || {
                let started = Instant::now();
                let result = probe_cpu.exchange(super::super::Exit::Halt);
                probe_done.store(true, Ordering::Release);
                (probe_cpu, result, started.elapsed())
            })
            .await
            .unwrap();
            busy.await.unwrap();
            drop(probe_cpu);
            running.abort_and_join().await;
            assert!(matches!(
                completion.unwrap(),
                super::super::Completion::Reenter
            ));
            assert!(
                elapsed < Duration::from_secs(1),
                "a busy vCPU starved its sibling"
            );
        }
    }
}

pub trait VirtualMachine: Send + Sync + 'static {
    fn memory(&self) -> wasmtime::Result<SyntheticRam>;
}

impl<T: VirtualMachine> VirtualMachine for Arc<T> {
    fn memory(&self) -> wasmtime::Result<SyntheticRam> {
        self.as_ref().memory()
    }
}

#[derive(Clone)]
pub struct RamGrant(Arc<dyn Fn() -> wasmtime::Result<SyntheticRam> + Send + Sync>);

impl RamGrant {
    pub fn resolve(&self) -> wasmtime::Result<SyntheticRam> {
        (self.0)()
    }
}

impl From<SyntheticRam> for RamGrant {
    fn from(ram: SyntheticRam) -> Self {
        Self(Arc::new(move || Ok(ram.clone())))
    }
}

struct CreatedMachine<M> {
    machine: Arc<M>,
    devices: Vec<super::machine::Device>,
}

pub struct MachineHandle<M>(Arc<CreatedMachine<M>>);

impl<M> Clone for MachineHandle<M> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<M: VirtualMachine> MachineHandle<M> {
    #[must_use]
    pub fn machine(&self) -> Arc<M> {
        Arc::clone(&self.0.machine)
    }

    pub fn bind_interrupt(
        &self,
        kind: super::machine::DeviceKind,
        ordinal: usize,
        inject: impl Fn(&M, u32, bool) -> wasmtime::Result<()> + Send + Sync + 'static,
    ) -> crate::component::Interrupt {
        let handle = self.clone();
        Arc::new(move |level| {
            let created = &handle.0;
            let machine = Arc::clone(&created.machine);
            let device = created
                .devices
                .iter()
                .filter(|device| device.kind == kind)
                .nth(ordinal)
                .ok_or_else(|| wasmtime::Error::msg("interrupt device outside VM grant"))?;
            inject(&machine, device.irq, level)
        })
    }

    pub fn inject_irq(
        &self,
        gsi: u32,
        level: bool,
        inject: impl FnOnce(&M, u32, bool) -> wasmtime::Result<()>,
    ) -> wasmtime::Result<()> {
        let created = &self.0;
        if !created.devices.iter().any(|device| device.irq == gsi) {
            return Err(wasmtime::Error::msg("interrupt line outside VM grant"));
        }
        let machine = self.machine();
        inject(&machine, gsi, level)
    }

    #[must_use]
    pub fn ram(&self) -> RamGrant {
        let handle = self.clone();
        RamGrant(Arc::new(move || handle.machine().memory()))
    }
}

pub struct PreparedMachine<M> {
    config: MachineConfig,
    backend: M,
    boot_entry: Option<super::boot::BootEntry>,
}

impl<M> PreparedMachine<M> {
    #[must_use]
    pub fn new(config: MachineConfig, backend: M) -> Self {
        Self {
            config,
            backend,
            boot_entry: None,
        }
    }

    #[must_use]
    pub fn config(&self) -> &MachineConfig {
        &self.config
    }
}

impl<M: VirtualMachine> PreparedMachine<M> {
    pub fn ram(&self) -> wasmtime::Result<SyntheticRam> {
        self.backend.memory()
    }

    pub fn accept_boot(&mut self, entry: super::boot::BootEntry) -> wasmtime::Result<()> {
        wasmtime::ensure!(self.boot_entry.is_none(), "VM boot already accepted");
        match self.config.architecture {
            Architecture::X86 => wasmtime::ensure!(
                entry.boot_argument == 0x7000,
                "x86 boot argument outside accepted layout"
            ),
            Architecture::Arm => {
                wasmtime::ensure!(entry.entry.is_multiple_of(4), "ARM boot entry is unaligned");
                wasmtime::ensure!(
                    entry.boot_argument.is_multiple_of(2 * 1024 * 1024),
                    "ARM boot argument is unaligned"
                );
            }
        }
        let ram = self.ram()?;
        let memory = BoundedMemory::new(&ram);
        wasmtime::ensure!(
            memory.read(entry.entry, 1).is_ok(),
            "VM boot entry outside RAM"
        );
        wasmtime::ensure!(
            memory.read(entry.boot_argument, 1).is_ok(),
            "VM boot argument outside RAM"
        );
        self.boot_entry = Some(entry);
        Ok(())
    }
}

pub struct Vm;

pub struct StartedVcpus<R> {
    runners: R,
    reaper: Option<VcpuReaper>,
    request_stop: Box<dyn FnOnce() -> wasmtime::Result<()> + Send>,
}

impl<R> StartedVcpus<R> {
    pub fn new(
        runners: R,
        request_stop: impl FnOnce() -> wasmtime::Result<()> + Send + 'static,
    ) -> Self {
        Self {
            runners,
            reaper: None,
            request_stop: Box::new(request_stop),
        }
    }
}

impl<R: Send + 'static> StartedVcpus<R> {
    pub fn with_reaper(
        self,
        stop: impl FnOnce(R) -> Result<Vec<Result<(), String>>, String> + Send + 'static,
    ) -> StartedVcpus<VcpuReaper> {
        let Self {
            runners,
            request_stop,
            reaper: _,
        } = self;
        let reaper = VcpuReaper::new(move || stop(runners), Some(Box::new(request_stop)));
        let cancellation = reaper.clone();
        StartedVcpus {
            runners: reaper.clone(),
            reaper: Some(reaper),
            request_stop: Box::new(move || cancellation.request_stop()),
        }
    }
}

type StartVcpus = Box<
    dyn FnOnce(
            Vec<super::NativeVcpu>,
            super::boot::BootEntry,
        ) -> wasmtime::Result<StartedVcpus<Box<dyn Any + Send>>>
        + Send,
>;

struct ReapingGrant {
    reaper: Option<VcpuReaper>,
    is_wait_claimed: bool,
}

pub(crate) struct MachineRecovery {
    reaper: Option<VcpuReaper>,
    _backend: Arc<dyn VirtualMachine>,
    _ram: SyntheticRam,
}

impl MachineRecovery {
    pub(crate) async fn wait(&self) -> wasmtime::Result<()> {
        if let Some(reaper) = &self.reaper {
            reaper
                .wait_until_finished()
                .await
                .map_err(wasmtime::Error::msg)?;
        }
        Ok(())
    }
}

#[derive(Default, PartialEq)]
enum MachinePhase {
    #[default]
    Prepared,
    BootReady,
    Running,
    Stopping,
    Stopped,
}

#[derive(Default)]
pub(super) struct VirtualizationHost {
    config: Option<MachineConfig>,
    ram: Option<SyntheticRam>,
    backend: Option<Arc<dyn VirtualMachine>>,
    boot_entry: Option<super::boot::BootEntry>,
    start_vcpus: Option<StartVcpus>,
    reaping: Option<ReapingGrant>,
    phase: MachinePhase,
    request_stop: Option<Box<dyn FnOnce() -> wasmtime::Result<()> + Send>>,
}

impl VirtualizationHost {
    fn claim_reaper(&mut self) -> wasmtime::Result<Option<VcpuReaper>> {
        wasmtime::ensure!(
            self.phase == MachinePhase::Stopping && self.request_stop.is_none(),
            "vCPU stop wait unavailable"
        );
        self.reaping
            .as_mut()
            .and_then(|grant| {
                if grant.is_wait_claimed {
                    None
                } else {
                    grant.is_wait_claimed = true;
                    Some(grant.reaper.clone())
                }
            })
            .ok_or_else(|| wasmtime::Error::msg("vCPU stop wait already claimed"))
    }
}

impl PlatformHost {
    pub(crate) fn machine_config(&self) -> wasmtime::Result<&MachineConfig> {
        self.virtualization
            .config
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("VM has no machine configuration"))
    }

    pub(crate) fn has_machine(&self) -> bool {
        self.virtualization.config.is_some()
    }

    pub(crate) fn completion_grant(&self) -> wasmtime::Result<(&MachineConfig, SyntheticRam)> {
        Ok((
            self.machine_config()?,
            self.virtualization
                .ram
                .clone()
                .ok_or_else(|| wasmtime::Error::msg("VM has no RAM grant"))?,
        ))
    }

    pub(crate) fn take_recovery_reaper(&mut self) -> wasmtime::Result<Option<MachineRecovery>> {
        let virtualization = &mut self.virtualization;
        if virtualization.phase == MachinePhase::Running {
            if let Some(stop) = virtualization.request_stop.take() {
                let _ = stop();
            }
            virtualization.phase = MachinePhase::Stopping;
        }
        if virtualization.phase != MachinePhase::Stopping {
            return Ok(None);
        }
        let reaper = virtualization
            .reaping
            .as_ref()
            .map(|grant| grant.reaper.clone())
            .ok_or_else(|| wasmtime::Error::msg("vCPU reaper unavailable"))?;
        let backend = virtualization
            .backend
            .take()
            .ok_or_else(|| wasmtime::Error::msg("VM backend unavailable"))?;
        let ram = virtualization
            .ram
            .take()
            .ok_or_else(|| wasmtime::Error::msg("VM RAM unavailable"))?;
        Ok(Some(MachineRecovery {
            reaper,
            _backend: backend,
            _ram: ram,
        }))
    }
}

impl virtualization::Host for PlatformHost {}

impl virtualization::HostVm for PlatformHost {
    fn request_stop(&mut self, resource: Resource<Vm>) -> wasmtime::Result<Result<(), Error>> {
        self.table.get(&resource)?;
        if self.virtualization.phase != MachinePhase::Running {
            return Ok(Err(Error::Unavailable));
        }
        if let Some(stop) = self.virtualization.request_stop.take() {
            stop()?;
            self.virtualization.phase = MachinePhase::Stopping;
        }
        Ok(Ok(()))
    }

    fn drop(&mut self, resource: Resource<Vm>) -> wasmtime::Result<()> {
        self.table.delete(resource)?;
        Ok(())
    }
}

impl<T: Send + 'static> virtualization::HostVmWithStore<T> for Platform {
    async fn wait_stopped(
        host: &wasmtime::component::Accessor<T, Self>,
        resource: Resource<Vm>,
    ) -> wasmtime::Result<Result<(), Error>> {
        let reaper = host.with(|mut access| {
            let host = access.get();
            host.table.get(&resource)?;
            host.virtualization.claim_reaper()
        })?;
        if let Some(reaper) = reaper {
            reaper.wait().await.map_err(wasmtime::Error::msg)?;
        }
        host.with(|mut access| {
            let virtualization = &mut access.get().virtualization;
            virtualization.phase = MachinePhase::Stopped;
            virtualization.backend = None;
            virtualization.ram = None;
        });
        Ok(Ok(()))
    }
}

pub(crate) fn add_to_linker(
    linker: &mut wasmtime::component::Linker<BoxHost>,
) -> wasmtime::Result<()> {
    virtualization::add_to_linker::<BoxHost, Platform>(linker, |host| &mut host.platform)
}

impl BoxRuntime {
    pub async fn grant_vcpus<R: Any + Send>(
        &mut self,
        start: impl FnOnce(
            Vec<super::NativeVcpu>,
            super::boot::BootEntry,
        ) -> wasmtime::Result<StartedVcpus<R>>
        + Send
        + 'static,
    ) -> wasmtime::Result<R> {
        let router = self
            .mmio
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("VMM missing"))?;
        wasmtime::ensure!(
            router.entrypoint.is_some(),
            "VMM entrypoint already selected"
        );
        self.install_vcpu_start(start)?;
        let router = self
            .mmio
            .as_mut()
            .ok_or_else(|| wasmtime::Error::msg("VMM missing"))?;
        let entrypoint = router
            .entrypoint
            .take()
            .ok_or_else(|| wasmtime::Error::msg("VMM entrypoint already selected"))?;
        self.register_loop(entrypoint)?;
        let compose = self
            .mmio
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("VMM missing"))?
            .compose_machine;
        let (worker_count, _setup) = self.grant_pending_workers()?;
        let outcome = tokio::time::timeout(
            super::workers::SETUP_TIMEOUT
                .saturating_mul(u32::try_from(worker_count)?)
                .saturating_add(super::EXIT_TIMEOUT),
            compose.call_async(&mut self.store, ()),
        )
        .await
        .map_err(wasmtime::Error::from)
        .and_then(std::convert::identity)
        .and_then(|(result,)| {
            result.map_err(|error| {
                wasmtime::Error::msg(format!("Wasm machine composition: {error:?}"))
            })
        });
        if let Err(error) = self.finish_worker_creation(worker_count, outcome) {
            let host = &mut self.store.data_mut().platform;
            host.pending_vcpus.clear();
            host.table = wasmtime::component::ResourceTable::new();
            return Err(error);
        }
        let started = self.start_native_vcpus();
        if started.is_err() {
            self.store.data_mut().platform.table = wasmtime::component::ResourceTable::new();
        }
        started
    }

    fn install_vcpu_start<R: Any + Send>(
        &mut self,
        start: impl FnOnce(
            Vec<super::NativeVcpu>,
            super::boot::BootEntry,
        ) -> wasmtime::Result<StartedVcpus<R>>
        + Send
        + 'static,
    ) -> wasmtime::Result<()> {
        let host = &self.store.data().platform.virtualization;
        wasmtime::ensure!(
            host.phase == MachinePhase::BootReady && host.start_vcpus.is_none(),
            "VM boot must complete before vCPU startup"
        );
        wasmtime::ensure!(self.mmio.is_some(), "VMM missing");
        let host = &mut self.store.data_mut().platform.virtualization;
        host.start_vcpus = Some(Box::new(move |controls, boot| {
            let StartedVcpus {
                runners,
                reaper,
                request_stop,
            } = start(controls, boot)?;
            Ok(StartedVcpus {
                runners: Box::new(runners) as Box<dyn Any + Send>,
                reaper,
                request_stop,
            })
        }));
        Ok(())
    }

    fn start_native_vcpus<R: Any + Send>(&mut self) -> wasmtime::Result<R> {
        let host = &mut self.store.data_mut().platform;
        let virtualization = &mut host.virtualization;
        wasmtime::ensure!(
            virtualization.phase == MachinePhase::BootReady,
            "VM boot must complete before vCPU startup"
        );
        let start = virtualization
            .start_vcpus
            .take()
            .ok_or_else(|| wasmtime::Error::msg("vCPU startup unavailable"))?;
        let controls = std::mem::take(&mut host.pending_vcpus)
            .into_iter()
            .map(|(_, cpu)| cpu)
            .collect();
        let boot = virtualization
            .boot_entry
            .take()
            .ok_or_else(|| wasmtime::Error::msg("VM boot is incomplete"))?;
        let StartedVcpus {
            runners,
            reaper,
            request_stop,
        } = start(controls, boot)?;
        virtualization.reaping = Some(ReapingGrant {
            reaper,
            is_wait_claimed: false,
        });
        virtualization.request_stop = Some(request_stop);
        virtualization.phase = MachinePhase::Running;
        runners
            .downcast::<R>()
            .map(|runners| *runners)
            .map_err(|_| wasmtime::Error::msg("vCPU startup result type mismatch"))
    }

    pub async fn attach_machine<M: VirtualMachine>(
        &mut self,
        prepared: PreparedMachine<M>,
    ) -> wasmtime::Result<MachineHandle<M>> {
        let PreparedMachine {
            config,
            backend,
            boot_entry,
        } = prepared;
        wasmtime::ensure!(
            boot_entry.is_some(),
            "VM boot must complete before attachment"
        );
        let initialize = self
            .mmio
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("VMM missing"))?
            .initialize_machine;
        let host = &mut self.store.data_mut().platform.virtualization;
        wasmtime::ensure!(host.config.is_none(), "VM already attached");
        let machine = Arc::new(backend);
        let retained_backend: Arc<dyn VirtualMachine> = machine.clone();
        let ram = machine.memory()?;
        wasmtime::ensure!(
            ram.mapped_bytes() == config.ram_bytes(),
            "backend RAM differs from machine configuration"
        );
        let devices = config.devices.clone();
        let handle = MachineHandle(Arc::new(CreatedMachine { machine, devices }));
        let vm = self.store.data_mut().platform.table.push(Vm)?;
        let mut native_vcpus = Vec::with_capacity(usize::from(config.vcpus));
        let mut vcpus = Vec::with_capacity(usize::from(config.vcpus));
        for id in 0..config.vcpus {
            let (native, vcpu) = super::vcpu_channel();
            native_vcpus.push((id, native));
            match self.store.data_mut().platform.table.push_child(vcpu, &vm) {
                Ok(vcpu) => vcpus.push(vcpu),
                Err(error) => {
                    clear_machine_attachment(&mut self.store.data_mut().platform);
                    return Err(error.into());
                }
            }
        }
        let host = &mut self.store.data_mut().platform;
        host.workers.machine_layout = Some(config.clone());
        host.pending_vcpus = native_vcpus;
        host.virtualization.config = Some(config.clone());
        host.virtualization.ram = Some(ram);
        host.virtualization.backend = Some(retained_backend);
        host.virtualization.boot_entry = boot_entry;
        host.virtualization.phase = MachinePhase::BootReady;
        let initialized = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            initialize.call_async(&mut self.store, (config.as_wit(), vm, vcpus)),
        )
        .await
        .map_err(wasmtime::Error::from)
        .and_then(std::convert::identity)
        .and_then(|(result,)| {
            result.map_err(|error| {
                wasmtime::Error::msg(format!("Wasm machine initialization: {error:?}"))
            })
        });
        if let Err(error) = initialized {
            self.mmio = None;
            clear_machine_attachment(&mut self.store.data_mut().platform);
            return Err(error);
        }
        Ok(handle)
    }
}

fn clear_machine_attachment(host: &mut PlatformHost) {
    host.table = wasmtime::component::ResourceTable::new();
    host.pending_vcpus.clear();
    host.workers.machine_layout = None;
    host.virtualization = VirtualizationHost::default();
}
