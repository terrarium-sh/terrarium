//! Observe VM outcomes and finish component and native shutdown.

use std::time::Duration;

use super::{PreparedVm, VmOutcome};

pub(super) struct VmObservation {
    reaper: crate::component::vmm::VcpuReaper,
    lifecycle: crate::component::vmm::lifecycle::LifecycleNotifier,
    deadline: Option<Duration>,
    failure: crate::component::vmm::FailureObservation,
    teardown: crate::component::vmm::teardown::NativeTeardown,
}

pub(super) async fn finish_preparation(
    runtime: crate::box_runtime::BoxRuntime,
    deadline: Option<Duration>,
    start: impl FnOnce(
        Vec<crate::component::vmm::NativeVcpu>,
        crate::component::vmm::BootEntry,
    ) -> wasmtime::Result<crate::component::vmm::StartedVcpus>
    + Send
    + 'static,
) -> wasmtime::Result<PreparedVm> {
    let failure = runtime.vmm_failure_observation()?;
    let lifecycle = runtime.lifecycle_notifier();
    let (runtime, reaper) = runtime.prepare_vcpus(start).await?;
    let teardown = runtime.native_teardown();
    Ok(PreparedVm {
        runtime,
        observation: VmObservation {
            reaper,
            lifecycle,
            deadline,
            failure,
            teardown,
        },
    })
}

impl VmObservation {
    pub(super) async fn observe(
        self,
        runtime: crate::box_runtime::BoxRuntimeHandle,
    ) -> Result<VmOutcome, String> {
        use crate::component::vmm::lifecycle::{Outcome, wait_for_outcome};
        let outcome = wait_for_outcome(
            &mut self.lifecycle.subscribe(),
            self.deadline,
            &self.lifecycle,
        )
        .await;
        let shutdown_deadline = self.lifecycle.begin_shutdown();
        let cleanup = self.teardown.wait_until(shutdown_deadline).await;
        let runtime = finish_component_runtime(runtime, cleanup, shutdown_deadline).await;
        let outcome = outcome.map_err(|error| format!("VMM lifecycle: {error:?}"))?;
        let exit_code = match outcome {
            Outcome::GuestExit(code) => Some(code),
            Outcome::VcpuFinished | Outcome::Deadline => None,
            Outcome::ComponentFailed => {
                return Err(self
                    .failure
                    .failure()
                    .unwrap_or_else(|| "VMM component failed".to_owned()));
            }
        };
        let vcpu_outcomes = self.reaper.wait_until(shutdown_deadline).await?;
        runtime?;
        Ok(VmOutcome {
            exit_code,
            vcpu_outcomes,
        })
    }
}

async fn finish_component_runtime(
    runtime: crate::box_runtime::BoxRuntimeHandle,
    cleanup: Result<(), String>,
    deadline: std::time::Instant,
) -> Result<(), String> {
    match cleanup {
        Ok(()) => runtime
            .join_until(deadline.into())
            .await
            .map_err(|error| error.to_string()),
        Err(error) => {
            runtime.abort_and_join_until(deadline.into()).await;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)]
    async fn prepared_vmm_observes_wasi_startup_and_shutdown() {
        use crate::component::context::DeviceContext;
        use crate::component::vmm::{PreparedMachine, StartedVcpus, VirtualMachine};
        use crate::machine::{Architecture, Device, DeviceKind, MachineConfig};
        use std::sync::Arc;

        struct TestVm(crate::memory::GuestRam);
        impl VirtualMachine for TestVm {
            fn memory(&self) -> wasmtime::Result<crate::memory::GuestRam> {
                Ok(self.0.clone())
            }
        }
        let engine = crate::engine::device_engine().unwrap();
        let mut runtime =
            crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new())
                .unwrap();
        let vmm =
            wasmtime::component::Component::new(&engine, crate::test_fixtures::wasm::VMM).unwrap();
        let mmio =
            wasmtime::component::Component::new(&engine, crate::test_fixtures::wasm::MMIO).unwrap();
        let devices = [
            (DeviceKind::Block, 11),
            (DeviceKind::Block, 12),
            (DeviceKind::Net, 13),
            (DeviceKind::Vsock, 14),
            (DeviceKind::Memory, 15),
        ]
        .into_iter()
        .zip(0..)
        .map(|((kind, irq), slot)| Device {
            kind,
            irq,
            mmio_base: 0xd000_0000 + slot * 0x1000,
        })
        .collect();
        let config = MachineConfig::new(Architecture::X86, 8 << 20, 1, devices).unwrap();
        let mut machine = PreparedMachine::new(
            config,
            TestVm(crate::memory::GuestRam::new(8 << 20).unwrap()),
        );
        let mut kernel = vec![0; 512];
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
        kernel[96..104].copy_from_slice(&16_u64.to_le_bytes());
        kernel[104..112].copy_from_slice(&32_u64.to_le_bytes());
        let boot =
            wasmtime::component::Component::new(&engine, crate::test_fixtures::wasm::BOOT).unwrap();
        let entry = runtime
            .boot_prepared_machine(&boot, machine.config(), machine.ram().unwrap(), kernel, "")
            .await
            .unwrap();
        machine.accept_boot(entry).unwrap();
        runtime.initialize_mmio(&mmio).await.unwrap();
        runtime.initialize_vmm(&vmm).await.unwrap();
        let (mut runtime, machine) = runtime.attach_machine(machine).await.unwrap();
        let component =
            wasmtime::component::Component::new(&engine, crate::test_fixtures::wasm::MEM).unwrap();
        let ram = machine.ram();
        let channel = crate::component::mem::register_device_with_host_factory(
            &mut runtime,
            move || Ok(DeviceContext::with_ram(ram.resolve()?)),
            &component,
            Arc::new(|_| Ok(())),
        )
        .unwrap();
        let injections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let delivered = Arc::clone(&injections);
        let interrupt = machine
            .bind_interrupt(DeviceKind::Memory, 0, move |_, irq, level| {
                assert_eq!(irq, 15);
                assert!(level);
                delivered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .unwrap();
        assert!(
            machine
                .bind_interrupt(DeviceKind::Memory, 1, |_, _, _| panic!(
                    "ungranted interrupt"
                ))
                .is_err()
        );
        let lifecycle = runtime.lifecycle_notifier();
        let startup_interrupt = Arc::clone(&interrupt);
        let deadline = Some(std::time::Duration::from_secs(5));
        let prepared = super::finish_preparation(runtime, deadline, move |controls, _| {
            startup_interrupt(true)?;
            Ok(StartedVcpus::new(
                controls,
                || Ok(()),
                |controls| {
                    drop(controls);
                    Ok(vec![Ok(())])
                },
            ))
        })
        .await
        .unwrap();
        assert_eq!(prepared.observation.deadline, deadline);
        lifecycle.guest_exit(7);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), prepared.run())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outcome.exit_code, Some(7));
        assert_eq!(outcome.vcpu_outcomes, vec![Ok(())]);
        assert!(machine.ram().resolve().is_ok());
        assert_eq!(injections.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(channel.read(0, 4).is_err());
    }

    #[tokio::test]
    async fn timed_out_device_close_does_not_start_later_devices() {
        use crate::component::vmm::teardown::DeviceShutdown;
        use crate::machine::DeviceKind;

        let (release, released) = std::sync::mpsc::channel();
        let (second_started, second_started_receiver) = std::sync::mpsc::channel();
        let first = DeviceShutdown::new(DeviceKind::Memory, async move {
            released.recv().expect("release first device");
            Ok(())
        });
        let second = DeviceShutdown::new(DeviceKind::Block, async move {
            second_started.send(()).expect("record second device");
            Ok(())
        });
        let engine = crate::engine::device_engine().unwrap();
        let mut runtime =
            crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new())
                .unwrap();
        runtime.add_device_shutdown(first).unwrap();
        runtime.add_device_shutdown(second).unwrap();
        let teardown = runtime.native_teardown();
        assert_eq!(
            teardown
                .wait_until(std::time::Instant::now() + std::time::Duration::from_millis(20))
                .await,
            Err("native task timed out".to_owned())
        );
        assert!(matches!(
            second_started_receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        release.send(()).expect("release first device");
        assert_eq!(
            teardown
                .wait_until(std::time::Instant::now() + std::time::Duration::from_secs(2))
                .await,
            Ok(())
        );
        second_started_receiver
            .recv()
            .expect("second device closes after the first");
    }
}
