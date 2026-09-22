//! Observe VM outcomes and finish component and native shutdown.

use std::time::Duration;

use super::{GUEST_BOOT_TIMEOUT, PreparedVm, VmOutcome};

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
        agent_ready: impl FnOnce() + Send,
    ) -> Result<VmOutcome, String> {
        use crate::component::vmm::lifecycle::wait_for_outcome;
        let mut outcomes = self.lifecycle.subscribe();
        let outcome = wait_for_outcome(&mut outcomes, self.deadline, &self.lifecycle);
        let result = wait_for_boot(&self.lifecycle, outcome, GUEST_BOOT_TIMEOUT, agent_ready).await;
        let boot_timed_out = result.is_none();
        let outcome = result.unwrap_or(Ok(crate::component::vmm::lifecycle::Outcome::Deadline));
        self.finish(runtime, outcome, boot_timed_out).await
    }

    async fn finish(
        &self,
        runtime: crate::box_runtime::BoxRuntimeHandle,
        outcome: Result<
            crate::component::vmm::lifecycle::Outcome,
            crate::component::vmm::lifecycle::WaitError,
        >,
        boot_timed_out: bool,
    ) -> Result<VmOutcome, String> {
        use crate::component::vmm::lifecycle::Outcome;
        let shutdown_deadline = self.lifecycle.begin_shutdown();
        let cleanup = self.teardown.wait_until(shutdown_deadline).await;
        let runtime = finish_component_runtime(runtime, cleanup, shutdown_deadline).await;
        let vcpu_outcomes = self.reaper.wait_until(shutdown_deadline).await;
        let vcpu_outcomes = collect_vcpu_outcomes(
            self.lifecycle.native_failure(),
            vcpu_outcomes,
            boot_timed_out,
        )?;
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
        runtime?;
        Ok(VmOutcome {
            exit_code,
            vcpu_outcomes,
        })
    }
}

fn collect_vcpu_outcomes(
    native_failure: Option<&str>,
    outcomes: Result<Vec<super::VcpuResult>, String>,
    boot_timed_out: bool,
) -> Result<Vec<super::VcpuResult>, String> {
    if let Some(error) = native_failure {
        return Err(error.to_owned());
    }
    let outcomes = outcomes?;
    if let Some(error) = outcomes.iter().find_map(|outcome| outcome.as_ref().err()) {
        return Err(error.clone());
    }
    if boot_timed_out {
        return Err(boot_timeout_message(GUEST_BOOT_TIMEOUT));
    }
    Ok(outcomes)
}

fn boot_timeout_message(timeout: Duration) -> String {
    format!(
        "guest agent did not become ready within {} seconds; last confirmed milestone: guest CPUs started",
        timeout.as_secs()
    )
}

/// `None` means the guest missed its readiness deadline.
async fn wait_for_boot<T>(
    lifecycle: &crate::component::vmm::lifecycle::LifecycleNotifier,
    outcome: impl std::future::Future<Output = T>,
    timeout: Duration,
    agent_ready: impl FnOnce(),
) -> Option<T> {
    let started = std::time::Instant::now();
    tokio::pin!(outcome);
    tokio::select! {
        biased;
        result = &mut outcome => {
            if lifecycle.is_agent_ready() {
                agent_ready();
            }
            return Some(result);
        },
        () = lifecycle.wait_for_agent_ready() => {
            log::info!("guest agent ready after {:.3}s", started.elapsed().as_secs_f64());
            agent_ready();
        }
        () = tokio::time::sleep(timeout) => {
            let timed_out = lifecycle.expire_boot_deadline();
            if timed_out {
                log::error!("{}; stopping VM", boot_timeout_message(timeout));
                return None;
            } else if lifecycle.is_agent_ready() {
                agent_ready();
            }
        }
    }
    Some(outcome.await)
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
    use super::*;
    use crate::component::vmm::lifecycle::{LifecycleHost, lifecycle_platform};

    #[test]
    fn native_errors_take_precedence_over_boot_timeout_and_cleanup() {
        for boot_timed_out in [false, true] {
            let failure = "vCPU 1: native hardware failure";
            assert_eq!(
                collect_vcpu_outcomes(
                    None,
                    Ok(vec![Ok(()), Err(failure.to_owned())]),
                    boot_timed_out,
                ),
                Err(failure.to_owned()),
            );
            assert_eq!(
                collect_vcpu_outcomes(
                    Some(failure),
                    Err("reaper timed out".to_owned()),
                    boot_timed_out,
                ),
                Err(failure.to_owned()),
            );
        }
        assert_eq!(
            collect_vcpu_outcomes(None, Err("reaper failed".to_owned()), true),
            Err("reaper failed".to_owned()),
        );
        assert_eq!(
            collect_vcpu_outcomes(None, Ok(vec![Ok(())]), true),
            Err(boot_timeout_message(GUEST_BOOT_TIMEOUT)),
        );
        assert_eq!(
            collect_vcpu_outcomes(None, Ok(vec![Ok(())]), false),
            Ok(vec![Ok(())]),
        );
    }

    #[tokio::test(start_paused = true)]
    async fn missing_agent_readiness_stops_boot() {
        let host = LifecycleHost::new();
        let lifecycle = host.notifier();
        let result = wait_for_boot(
            &lifecycle,
            std::future::pending::<()>(),
            GUEST_BOOT_TIMEOUT,
            || panic!("unresponsive guest reported ready"),
        )
        .await;
        assert!(result.is_none());
        assert!(matches!(
            host.next_event().await.unwrap().unwrap(),
            lifecycle_platform::Event::Deadline
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn readiness_permanently_cancels_the_boot_deadline() {
        let host = LifecycleHost::new();
        let lifecycle = host.notifier();
        lifecycle.agent_ready();
        let mut notified = false;
        let result = wait_for_boot(
            &lifecycle,
            async {
                tokio::time::sleep(GUEST_BOOT_TIMEOUT * 3).await;
                23
            },
            GUEST_BOOT_TIMEOUT,
            || notified = true,
        )
        .await;
        assert!(notified);
        assert_eq!(result, Some(23));
        assert!(!host.notifier().expire_boot_deadline());
    }

    #[tokio::test(start_paused = true)]
    async fn terminal_events_win_over_the_boot_deadline() {
        for native_failure in [false, true] {
            let host = LifecycleHost::new();
            let lifecycle = host.notifier();
            if native_failure {
                lifecycle.native_failed("vCPU 0: KVM fail-entry (0x80000021)");
            } else {
                lifecycle.guest_exit(7);
            }
            let result = wait_for_boot(&lifecycle, host.next_event(), Duration::ZERO, || {
                panic!("failed guest reported ready")
            })
            .await;
            assert!(result.unwrap().unwrap().is_ok());
            assert!(!lifecycle.expire_boot_deadline());
            if native_failure {
                lifecycle.native_failed("secondary cleanup failure");
                assert_eq!(
                    lifecycle.native_failure(),
                    Some("vCPU 0: KVM fail-entry (0x80000021)")
                );
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fast_workload_exit_does_not_hide_readiness() {
        let host = LifecycleHost::new();
        let lifecycle = host.notifier();
        lifecycle.agent_ready();
        lifecycle.guest_exit(0);
        let mut notified = false;
        let result = wait_for_boot(&lifecycle, host.next_event(), Duration::ZERO, || {
            notified = true;
        })
        .await;
        assert!(notified);
        assert!(result.is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prepared_vmm_observes_wasi_startup_and_shutdown() {
        let outcome = observe_test_vm(Ok(())).await.unwrap();
        assert_eq!(outcome.exit_code, Some(7));
        assert_eq!(outcome.vcpu_outcomes, vec![Ok(())]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_failure_is_not_hidden_by_guest_exit_status() {
        let failure = "vCPU 0: native run failed";
        let outcome = observe_test_vm(Err(failure.to_owned())).await;
        assert_eq!(outcome.unwrap_err(), failure);
    }

    #[allow(clippy::too_many_lines)]
    async fn observe_test_vm(vcpu_result: super::super::VcpuResult) -> Result<VmOutcome, String> {
        use crate::component::context::DeviceContext;
        use crate::component::vmm::{PreparedMachine, StartedVcpus, VirtualMachine};
        use crate::machine::{Architecture, Device, DeviceKind, MachineConfig};
        use std::sync::Arc;
        use terra_limits::{X86_MMIO_BASE, X86_MMIO_STRIDE};

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
            mmio_base: X86_MMIO_BASE + slot * X86_MMIO_STRIDE,
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
                move |controls| {
                    drop(controls);
                    Ok(vec![vcpu_result])
                },
            ))
        })
        .await
        .unwrap();
        assert_eq!(prepared.observation.deadline, deadline);
        lifecycle.guest_exit(7);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), prepared.run(|| {}))
            .await
            .unwrap();
        assert!(machine.ram().resolve().is_ok());
        assert_eq!(injections.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(channel.read(0, 4).is_err());
        outcome
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
