use std::sync::Arc;

use wasmtime::component::Resource;

use super::VcpuReaper;
use super::{Platform, PlatformHost};

use crate::box_runtime::BoxRuntime;
use crate::box_runtime::store::BoxHost;
use crate::component::vmm::bindings::virtualization;
use crate::component::vmm::bindings::virtualization::{Config, Error};
use crate::machine::{Architecture, Device, DeviceKind, MachineConfig};
pub(crate) type InitializeMachine = wasmtime::component::TypedFunc<
    (Config, Resource<Vm>, Vec<Resource<super::Vcpu>>),
    (Result<(), super::bindings::machine::Error>,),
>;
use crate::memory::{BoundedMemory, GuestRam};

pub trait VirtualMachine: Send + Sync + 'static {
    fn memory(&self) -> wasmtime::Result<GuestRam>;
}

impl<T: VirtualMachine> VirtualMachine for Arc<T> {
    fn memory(&self) -> wasmtime::Result<GuestRam> {
        self.as_ref().memory()
    }
}

impl VirtualMachine for terra_platform::vm::VmHandle {
    fn memory(&self) -> wasmtime::Result<GuestRam> {
        Ok(GuestRam::from_memory(self.memory()))
    }
}

#[derive(Clone)]
pub struct RamGrant(Arc<dyn Fn() -> wasmtime::Result<GuestRam> + Send + Sync>);

impl RamGrant {
    pub fn resolve(&self) -> wasmtime::Result<GuestRam> {
        (self.0)()
    }
}

impl From<GuestRam> for RamGrant {
    fn from(ram: GuestRam) -> Self {
        Self(Arc::new(move || Ok(ram.clone())))
    }
}

struct CreatedMachine<M> {
    machine: Arc<M>,
    devices: Vec<Device>,
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
        kind: DeviceKind,
        ordinal: usize,
        inject: impl Fn(&M, u32, bool) -> wasmtime::Result<()> + Send + Sync + 'static,
    ) -> wasmtime::Result<crate::component::InterruptCallback> {
        let irq = self
            .0
            .devices
            .iter()
            .filter(|device| device.kind == kind)
            .nth(ordinal)
            .map(|device| device.irq)
            .ok_or_else(|| wasmtime::Error::msg("interrupt device outside VM grant"))?;
        let machine = self.machine();
        Ok(Arc::new(move |level| inject(&machine, irq, level)))
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
    pub fn ram(&self) -> wasmtime::Result<GuestRam> {
        self.backend.memory()
    }

    pub fn accept_boot(&mut self, entry: super::boot::BootEntry) -> wasmtime::Result<()> {
        wasmtime::ensure!(self.boot_entry.is_none(), "VM boot already accepted");
        match self.config.architecture() {
            Architecture::X86 => {
                wasmtime::ensure!(
                    entry.boot_argument == terra_limits::X86_ZERO_PAGE,
                    "x86 boot argument outside accepted layout"
                );
                wasmtime::ensure!(
                    (0x10_0000..terra_limits::X86_RAM_LOW_END).contains(&entry.entry),
                    "x86 boot entry outside low RAM"
                );
            }
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

pub struct StartedVcpus(VcpuReaper);

impl StartedVcpus {
    pub fn new<R: Send + 'static>(
        runners: R,
        request_stop: impl FnOnce() -> wasmtime::Result<()> + Send + 'static,
        reap: impl FnOnce(R) -> Result<Vec<Result<(), String>>, String> + Send + 'static,
    ) -> Self {
        Self(VcpuReaper::new(
            move || reap(runners),
            Some(Box::new(request_stop)),
        ))
    }
}

pub(crate) struct MachineRecovery {
    reaper: VcpuReaper,
    _backend: Arc<dyn VirtualMachine>,
    _ram: GuestRam,
}

impl MachineRecovery {
    pub(crate) async fn wait(&mut self) -> wasmtime::Result<()> {
        self.reaper.request_stop()?;
        self.reaper
            .wait_until_finished()
            .await
            .map_err(wasmtime::Error::msg)?;
        Ok(())
    }
}

struct MachineGrant {
    config: MachineConfig,
    ram: GuestRam,
    backend: Arc<dyn VirtualMachine>,
}

struct BootReadyMachine {
    grant: MachineGrant,
    boot_entry: super::boot::BootEntry,
}

#[derive(Default)]
enum MachineState {
    #[default]
    Detached,
    BootReady(BootReadyMachine),
    Running(MachineGrant),
}

#[derive(Default)]
pub(super) struct VirtualizationHost {
    state: MachineState,
}

impl PlatformHost {
    pub(crate) fn is_machine_running(&self) -> bool {
        matches!(self.virtualization.state, MachineState::Running(_))
    }

    fn machine_grant(&self) -> Option<&MachineGrant> {
        match &self.virtualization.state {
            MachineState::Detached => None,
            MachineState::BootReady(machine) => Some(&machine.grant),
            MachineState::Running(machine) => Some(machine),
        }
    }

    pub(crate) fn machine_config(&self) -> Option<&MachineConfig> {
        self.machine_grant().map(|grant| &grant.config)
    }

    pub(crate) fn completion_grant(&self) -> wasmtime::Result<(&MachineConfig, GuestRam)> {
        let grant = self
            .machine_grant()
            .ok_or_else(|| wasmtime::Error::msg("VM has no machine configuration"))?;
        Ok((&grant.config, grant.ram.clone()))
    }
}

impl virtualization::Host for PlatformHost {}

impl virtualization::HostVm for PlatformHost {
    fn request_stop(&mut self, resource: Resource<Vm>) -> wasmtime::Result<Result<(), Error>> {
        self.table.get(&resource)?;
        if !matches!(self.virtualization.state, MachineState::Running(_)) {
            return Ok(Err(Error::Unavailable));
        }
        self.native_teardown.start();
        Ok(Ok(()))
    }

    fn drop(&mut self, resource: Resource<Vm>) -> wasmtime::Result<()> {
        self.table.delete(resource)?;
        Ok(())
    }
}

pub(crate) fn add_to_linker(
    linker: &mut wasmtime::component::Linker<BoxHost>,
) -> wasmtime::Result<()> {
    virtualization::add_to_linker::<BoxHost, Platform>(linker, |host| &mut host.platform)
}

impl PlatformHost {
    pub(crate) fn validate_runtime_start(&self) -> wasmtime::Result<()> {
        match self.virtualization.state {
            MachineState::Detached | MachineState::Running(_) => Ok(()),
            MachineState::BootReady(_) => {
                wasmtime::bail!("VM vCPU startup must complete before runtime preparation")
            }
        }
    }

    pub(crate) fn validate_vcpu_start(&self) -> wasmtime::Result<()> {
        wasmtime::ensure!(
            matches!(self.virtualization.state, MachineState::BootReady(_)),
            "VM boot must complete before vCPU startup"
        );
        Ok(())
    }

    pub(crate) fn start_native_vcpus(
        &mut self,
        start: impl FnOnce(
            Vec<super::NativeVcpu>,
            super::boot::BootEntry,
        ) -> wasmtime::Result<StartedVcpus>,
    ) -> wasmtime::Result<VcpuReaper> {
        let virtualization = &mut self.virtualization;
        let state = std::mem::replace(&mut virtualization.state, MachineState::Detached);
        let MachineState::BootReady(machine) = state else {
            virtualization.state = state;
            return Err(wasmtime::Error::msg(
                "VM boot must complete before vCPU startup",
            ));
        };
        let BootReadyMachine { grant, boot_entry } = machine;
        let controls = std::mem::take(&mut self.pending_vcpus);
        let StartedVcpus(reaper) = start(controls, boot_entry)?;
        self.native_teardown.install_machine(MachineRecovery {
            reaper: reaper.clone(),
            _backend: Arc::clone(&grant.backend),
            _ram: grant.ram.clone(),
        })?;
        virtualization.state = MachineState::Running(grant);
        Ok(reaper)
    }
}

impl BoxRuntime {
    pub(crate) async fn compose_machine(&mut self) -> wasmtime::Result<()> {
        let machine = &self
            .vmm
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("VMM missing"))?
            .machine;
        tokio::time::timeout(
            super::EXIT_TIMEOUT,
            machine.func_compose().call_async(&mut self.store, ()),
        )
        .await
        .map_err(wasmtime::Error::from)
        .and_then(std::convert::identity)
        .and_then(|(result,)| {
            result.map_err(|error| {
                wasmtime::Error::msg(format!("Wasm machine composition: {error:?}"))
            })
        })
    }

    pub async fn attach_machine<M: VirtualMachine>(
        mut self,
        prepared: PreparedMachine<M>,
    ) -> wasmtime::Result<(Self, MachineHandle<M>)> {
        let PreparedMachine {
            config,
            backend,
            boot_entry,
        } = prepared;
        let boot_entry = boot_entry
            .ok_or_else(|| wasmtime::Error::msg("VM boot must complete before attachment"))?;
        let machine_bindings = &self
            .vmm
            .as_ref()
            .ok_or_else(|| wasmtime::Error::msg("VMM missing"))?
            .machine;
        let initialize: InitializeMachine = machine_bindings
            .func_initialize()
            .func()
            .typed(&self.store)?;
        let host = &mut self.store.data_mut().platform.virtualization;
        wasmtime::ensure!(
            matches!(host.state, MachineState::Detached),
            "VM already attached"
        );
        let machine = Arc::new(backend);
        let retained_backend: Arc<dyn VirtualMachine> = machine.clone();
        let ram = machine.memory()?;
        wasmtime::ensure!(
            ram.mapped_bytes() == config.ram_bytes(),
            "backend RAM differs from machine configuration"
        );
        let devices = config.devices().to_vec();
        let handle = MachineHandle(Arc::new(CreatedMachine { machine, devices }));
        let vm = self.store.data_mut().platform.table.push(Vm)?;
        let mut native_vcpus = Vec::with_capacity(usize::from(config.vcpus()));
        let mut vcpus = Vec::with_capacity(usize::from(config.vcpus()));
        for _ in 0..config.vcpus() {
            let (native, vcpu) = super::vcpu::vcpu_channel();
            native_vcpus.push(native);
            vcpus.push(self.store.data_mut().platform.table.push_child(vcpu, &vm)?);
        }
        let host = &mut self.store.data_mut().platform;
        host.pending_vcpus = native_vcpus;
        host.virtualization.state = MachineState::BootReady(BootReadyMachine {
            grant: MachineGrant {
                config: config.clone(),
                ram,
                backend: retained_backend,
            },
            boot_entry,
        });
        let initialized = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            initialize.call_async(&mut self.store, (config.into_component_config(), vm, vcpus)),
        )
        .await
        .map_err(wasmtime::Error::from)
        .and_then(std::convert::identity)
        .and_then(|(result,)| {
            result.map_err(|error| {
                wasmtime::Error::msg(format!("Wasm machine initialization: {error:?}"))
            })
        });
        initialized?;
        Ok((self, handle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVm(GuestRam);

    impl VirtualMachine for TestVm {
        fn memory(&self) -> wasmtime::Result<GuestRam> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn prepared_machine_accepts_boot_once() {
        let config = MachineConfig::new(Architecture::X86, 2 << 20, 1, Vec::new()).unwrap();
        let mut machine = PreparedMachine::new(config, TestVm(GuestRam::new(2 << 20).unwrap()));
        machine
            .accept_boot(super::super::boot::BootEntry {
                entry: 0x10_0000,
                boot_argument: terra_limits::X86_ZERO_PAGE,
            })
            .unwrap();
        assert!(
            machine
                .accept_boot(super::super::boot::BootEntry {
                    entry: 0x10_0000,
                    boot_argument: terra_limits::X86_ZERO_PAGE,
                })
                .is_err()
        );
    }

    #[test]
    fn prepared_machine_rejects_mapped_entry_above_bootstrap_ram() {
        let config = MachineConfig::new(Architecture::X86, 2 << 20, 1, Vec::new()).unwrap();
        let memory = terra_platform::memory::GuestMemory::from_ranges(&[
            (terra_limits::X86_RAM_BASE, 2 << 20),
            (terra_limits::X86_HIGH_RAM_BASE, 4096),
        ])
        .unwrap();
        let mut machine = PreparedMachine::new(config, TestVm(GuestRam::from_memory(memory)));
        let error = machine
            .accept_boot(super::super::boot::BootEntry {
                entry: terra_limits::X86_HIGH_RAM_BASE,
                boot_argument: terra_limits::X86_ZERO_PAGE,
            })
            .unwrap_err();
        assert!(error.to_string().contains("x86 boot entry outside low RAM"));
    }

    #[test]
    fn interrupt_bindings_validate_the_device_during_setup() {
        let machine = MachineHandle(Arc::new(CreatedMachine {
            machine: Arc::new(TestVm(GuestRam::new(32768).unwrap())),
            devices: vec![Device {
                kind: DeviceKind::Memory,
                mmio_base: 0,
                irq: 15,
            }],
        }));
        let delivered = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let observed = Arc::clone(&delivered);
        let interrupt = machine
            .bind_interrupt(DeviceKind::Memory, 0, move |_, irq, level| {
                assert!(level);
                observed.store(irq, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            })
            .unwrap();
        assert!(
            machine
                .bind_interrupt(DeviceKind::Memory, 1, |_, _, _| Ok(()))
                .is_err()
        );
        interrupt(true).unwrap();
        assert_eq!(delivered.load(std::sync::atomic::Ordering::Relaxed), 15);
    }

    #[tokio::test]
    async fn failed_stop_keeps_machine_resources_with_native_teardown() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let backend = Arc::new(TestVm(GuestRam::new(32768).unwrap()));
        let backend_weak = Arc::downgrade(&backend);
        let stop_called = Arc::new(AtomicBool::new(false));
        let observed_stop = Arc::clone(&stop_called);
        let teardown = super::super::teardown::NativeTeardown::new();
        teardown
            .install_machine(MachineRecovery {
                reaper: VcpuReaper::new(
                    || Ok(Vec::new()),
                    Some(Box::new(move || {
                        observed_stop.store(true, Ordering::Relaxed);
                        Err(wasmtime::Error::msg("injected stop failure"))
                    })),
                ),
                _backend: backend.clone(),
                _ram: GuestRam::new(32768).unwrap(),
            })
            .unwrap();
        drop(backend);
        assert!(
            teardown
                .wait_until(std::time::Instant::now() + std::time::Duration::from_secs(1))
                .await
                .is_err()
        );
        assert!(stop_called.load(Ordering::Relaxed));
        assert!(backend_weak.upgrade().is_some());
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn aot_vmm_applies_boot_and_keeps_both_vcpus_responsive() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};
        use terra_platform::memory::GuestMemory;

        for architecture in [Architecture::X86, Architecture::Arm] {
            let engine = crate::engine::device_engine().unwrap();
            let vmm = crate::test_fixtures::trusted_artifacts()
                .vmm()
                .deserialize(&engine)
                .unwrap();
            let boot =
                wasmtime::component::Component::new(&engine, crate::test_fixtures::wasm::BOOT)
                    .unwrap();
            let base = match architecture {
                Architecture::X86 => 0,
                Architecture::Arm => 0x4000_0000,
            };
            let devices = match architecture {
                Architecture::X86 => vec![
                    (DeviceKind::Block, terra_limits::X86_MMIO_BASE, 11),
                    (
                        DeviceKind::Block,
                        terra_limits::X86_MMIO_BASE + terra_limits::X86_MMIO_STRIDE,
                        12,
                    ),
                    (
                        DeviceKind::Net,
                        terra_limits::X86_MMIO_BASE + 2 * terra_limits::X86_MMIO_STRIDE,
                        13,
                    ),
                    (
                        DeviceKind::Vsock,
                        terra_limits::X86_MMIO_BASE + 3 * terra_limits::X86_MMIO_STRIDE,
                        14,
                    ),
                    (
                        DeviceKind::Memory,
                        terra_limits::X86_MMIO_BASE + 4 * terra_limits::X86_MMIO_STRIDE,
                        15,
                    ),
                ],
                Architecture::Arm => vec![
                    (DeviceKind::Block, 0x0a00_0000, 16),
                    (DeviceKind::Block, 0x0a00_0200, 17),
                    (DeviceKind::Memory, 0x0a00_0400, 18),
                    (DeviceKind::Net, 0x0a00_0600, 19),
                    (DeviceKind::Vsock, 0x0a00_0800, 20),
                ],
            }
            .into_iter()
            .map(|(kind, mmio_base, irq)| Device {
                kind,
                mmio_base,
                irq,
            })
            .collect();
            let ram = GuestRam::from_memory(GuestMemory::allocate_at(base, 8 << 20).unwrap());
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
            let mmio =
                wasmtime::component::Component::new(&engine, crate::test_fixtures::wasm::MMIO)
                    .unwrap();
            runtime.initialize_mmio(&mmio).await.unwrap();
            runtime.initialize_vmm(&vmm).await.unwrap();
            let (runtime, handle) = runtime.attach_machine(prepared).await.unwrap();
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            let (runtime, _reaper) = runtime
                .prepare_vcpus(move |controls, accepted| {
                    assert_eq!(accepted.entry, entry);
                    sender.send(controls).unwrap();
                    Ok(StartedVcpus::new((), || Ok(()), |()| Ok(Vec::new())))
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
            let mut controls = receiver.recv().unwrap().into_iter();
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
