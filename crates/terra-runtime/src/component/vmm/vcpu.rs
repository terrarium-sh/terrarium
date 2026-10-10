//! Native vCPU rendezvous and validation of component completions.

use std::sync::mpsc;

use wasmtime::component::{Accessor, Resource};

use super::{Completion, Error, Exit, Platform, PlatformHost, platform};
use terra_platform::vm;

pub(crate) const EXIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

struct Pending {
    exit: Exit,
    reply: mpsc::SyncSender<Completion>,
}

enum VcpuState {
    AwaitingStart,
    AwaitingCompletion(Pending),
}

pub struct NativeVcpu {
    sender: tokio::sync::mpsc::Sender<Pending>,
}

impl NativeVcpu {
    pub fn exchange(&self, exit: Exit) -> wasmtime::Result<Completion> {
        let (reply, response) = mpsc::sync_channel(1);
        self.sender
            .try_send(Pending { exit, reply })
            .map_err(|error| wasmtime::Error::msg(format!("vCPU worker unavailable: {error}")))?;
        response
            .recv_timeout(EXIT_TIMEOUT)
            .map_err(|error| wasmtime::Error::msg(format!("vCPU completion: {error}")))
    }
}

fn native_exit(exit: vm::VcpuExit) -> Option<Exit> {
    match exit {
        vm::VcpuExit::Halt => Some(Exit::Halt),
        vm::VcpuExit::Shutdown => Some(Exit::Shutdown),
        vm::VcpuExit::Interrupted => Some(Exit::Interrupted),
        vm::VcpuExit::PioRead(vm::PioRead { port, length }) => {
            Some(Exit::PioRead(platform::PioRead { port, length }))
        }
        vm::VcpuExit::PioWrite(vm::PioWrite { port, length }) => {
            Some(Exit::PioWrite(platform::PioWrite { port, length }))
        }
        vm::VcpuExit::Rdmsr(vm::Msr { index, value }) => {
            Some(Exit::Rdmsr(platform::Msr { index, value }))
        }
        vm::VcpuExit::Wrmsr(vm::Msr { index, value }) => {
            Some(Exit::Wrmsr(platform::Msr { index, value }))
        }
        vm::VcpuExit::MmioRead(_)
        | vm::VcpuExit::MmioWrite(_)
        | vm::VcpuExit::IoApicAccess(_)
        | vm::VcpuExit::IoApicEoi(_) => None,
        vm::VcpuExit::Stopped => Some(Exit::Stopped),
    }
}

fn native_action(action: Completion) -> vm::VcpuAction {
    match action {
        Completion::Start => vm::VcpuAction::Start,
        Completion::Reenter => vm::VcpuAction::Reenter,
        Completion::PioZero => vm::VcpuAction::PioZero,
        Completion::Rdmsr(value) => vm::VcpuAction::Rdmsr(value),
        Completion::MsrFault => vm::VcpuAction::MsrFault,
        Completion::Wrmsr => vm::VcpuAction::Wrmsr,
    }
}

impl vm::VcpuHandler for NativeVcpu {
    fn exchange(&mut self, exit: vm::VcpuExit) -> Result<vm::VcpuAction, String> {
        let exit = native_exit(exit).ok_or_else(|| {
            "MMIO and IOAPIC exits are answered by the runtime, not the VMM".to_owned()
        })?;
        NativeVcpu::exchange(self, exit)
            .map(native_action)
            .map_err(|error| error.to_string())
    }

    fn finished(&mut self, outcome: vm::VcpuOutcome) {
        let exit = match outcome {
            vm::VcpuOutcome::Shutdown => Exit::Shutdown,
            vm::VcpuOutcome::Stopped => Exit::Stopped,
        };
        let (reply, _) = mpsc::sync_channel(1);
        let _ = self.sender.try_send(Pending { exit, reply });
    }
}

struct Rendezvous {
    exits: tokio::sync::mpsc::Receiver<Pending>,
    state: VcpuState,
}

pub struct Vcpu(Option<Rendezvous>);

impl PlatformHost {
    #[cfg(test)]
    pub(crate) fn add_test_vcpu(&mut self) -> (NativeVcpu, Resource<Vcpu>) {
        let (native, vcpu) = vcpu_channel();
        (native, self.table.push(vcpu).unwrap())
    }
}

pub(super) fn vcpu_channel() -> (NativeVcpu, Vcpu) {
    let (sender, exits) = tokio::sync::mpsc::channel(1);
    (
        NativeVcpu { sender },
        Vcpu(Some(Rendezvous {
            exits,
            state: VcpuState::AwaitingStart,
        })),
    )
}

fn accepts_completion(exit: &Exit, completion: &Completion) -> bool {
    match exit {
        Exit::Halt | Exit::Interrupted | Exit::PioWrite(_) => {
            matches!(completion, Completion::Reenter)
        }
        Exit::PioRead(_) => matches!(completion, Completion::PioZero),
        Exit::Rdmsr(_) => matches!(completion, Completion::Rdmsr(_) | Completion::MsrFault),
        Exit::Wrmsr(_) => matches!(completion, Completion::Wrmsr | Completion::MsrFault),
        Exit::Shutdown | Exit::Stopped => false,
    }
}

impl platform::HostVcpu for PlatformHost {
    fn drop(&mut self, resource: Resource<Vcpu>) -> wasmtime::Result<()> {
        self.table.delete(resource)?;
        Ok(())
    }
}

impl<T: Send + 'static> platform::HostVcpuWithStore<T> for Platform {
    async fn resume(
        accessor: &Accessor<T, Self>,
        resource: Resource<Vcpu>,
        completion: Completion,
    ) -> wasmtime::Result<Result<Exit, Error>> {
        let mut rendezvous = accessor.with(|mut store| {
            store
                .get()
                .table
                .get_mut(&resource)?
                .0
                .take()
                .ok_or_else(|| wasmtime::Error::msg("vCPU resume already pending"))
        })?;
        match rendezvous.state {
            VcpuState::AwaitingCompletion(pending) => {
                let valid = accepts_completion(&pending.exit, &completion);
                if !valid {
                    return Ok(Err(Error::BadExit));
                }
                if pending.reply.send(completion).is_err() {
                    return Ok(Err(Error::Cancelled));
                }
            }
            VcpuState::AwaitingStart if matches!(completion, Completion::Start) => {}
            VcpuState::AwaitingStart => return Ok(Err(Error::BadExit)),
        }
        let Some(pending) = rendezvous.exits.recv().await else {
            return Ok(Ok(Exit::Stopped));
        };
        let exit = pending.exit;
        rendezvous.state = VcpuState::AwaitingCompletion(pending);
        accessor.with(|mut store| {
            store.get().table.get_mut(&resource)?.0 = Some(rendezvous);
            Ok::<(), wasmtime::Error>(())
        })?;
        Ok(Ok(exit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    #[test]
    fn dropping_platform_disconnects_pending_vcpu_completion() {
        let (_native, mut vcpu) = vcpu_channel();
        let (reply, response) = mpsc::sync_channel(1);
        vcpu.0.as_mut().unwrap().state = VcpuState::AwaitingCompletion(Pending {
            exit: Exit::PioWrite(platform::PioWrite {
                port: 0x70,
                length: 4,
            }),
            reply,
        });
        let mut host = PlatformHost::default();
        host.table.push(vcpu).unwrap();
        assert_matches!(response.try_recv(), Err(mpsc::TryRecvError::Empty));
        drop(host);
        assert_matches!(response.try_recv(), Err(mpsc::TryRecvError::Disconnected));
    }

    /// Wasmtime keeps spawned host tasks in the Store after `run_concurrent` is
    /// dropped. A pending resume owns the receiver outside the resource table,
    /// so retiring the failed Store must disconnect queued native completions
    /// before native teardown begins.
    #[tokio::test]
    async fn child_failure_disconnects_a_queued_exit_in_a_retained_resume() {
        use crate::box_runtime::{BoxHost, BoxRuntime};
        use crate::component::vmm::teardown::DeviceShutdown;
        use crate::machine::DeviceKind;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use wasmtime::component::AccessorTask;

        struct RetainedResume {
            resource_index: u32,
            sender: tokio::sync::mpsc::Sender<Pending>,
            pending: Pending,
            ready: tokio::sync::oneshot::Sender<()>,
        }

        impl AccessorTask<BoxHost> for RetainedResume {
            async fn run(self, accessor: &Accessor<BoxHost>) -> wasmtime::Result<()> {
                let platform = accessor.with_getter::<Platform>(|host| &mut host.platform);
                let mut resume =
                    Box::pin(<Platform as platform::HostVcpuWithStore<BoxHost>>::resume(
                        &platform,
                        Resource::new_borrow(self.resource_index),
                        Completion::Start,
                    ));
                assert!(
                    std::future::poll_fn(|context| { Poll::Ready(resume.as_mut().poll(context)) })
                        .await
                        .is_pending()
                );
                platform.with(|mut access| {
                    let vcpu = access
                        .get()
                        .table
                        .get(&Resource::<Vcpu>::new_borrow(self.resource_index))
                        .unwrap();
                    assert!(vcpu.0.is_none());
                });
                self.sender.try_send(self.pending).unwrap();
                self.ready.send(()).unwrap();
                std::future::pending::<()>().await;
                drop(resume);
                Ok(())
            }
        }

        let engine = crate::engine::device_engine().unwrap();
        let mut root = BoxRuntime::new(&engine, BoxHost::new()).unwrap();
        let (native, resource) = root.store.data_mut().platform.add_test_vcpu();
        let (reply, response) = mpsc::sync_channel(1);
        let (ready, failed_child) = tokio::sync::oneshot::channel();
        let task = RetainedResume {
            resource_index: resource.rep(),
            sender: native.sender,
            pending: Pending {
                exit: Exit::Halt,
                reply,
            },
            ready,
        };
        root.register_loop(Box::new(move |accessor| {
            Box::pin(async move {
                drop(accessor.spawn(task)?);
                std::future::pending::<wasmtime::Result<()>>().await
            })
        }))
        .unwrap();
        let disconnected = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&disconnected);
        root.add_device_shutdown(DeviceShutdown::new(DeviceKind::Memory, async move {
            let is_disconnected =
                matches!(response.try_recv(), Err(mpsc::TryRecvError::Disconnected));
            observed.store(is_disconnected, Ordering::Release);
            if is_disconnected {
                Ok(())
            } else {
                Err("queued native completion retained during teardown".to_owned())
            }
        }))
        .unwrap();
        let mut child = root.new_child(crate::box_runtime::RootHost::new());
        child
            .register_loop(Box::new(move |_| {
                Box::pin(async move {
                    failed_child.await.unwrap();
                    Err(wasmtime::Error::msg("child failed"))
                })
            }))
            .unwrap();
        root.attach_child(child).unwrap();
        let error = root
            .prepare()
            .await
            .unwrap()
            .start()
            .join()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("child failed"), "{error}");
        assert!(disconnected.load(Ordering::Acquire));
    }

    #[test]
    fn native_terminal_notifications_preserve_the_outcome() {
        for (outcome, expected) in [
            (vm::VcpuOutcome::Shutdown, Exit::Shutdown),
            (vm::VcpuOutcome::Stopped, Exit::Stopped),
        ] {
            let (mut native, mut vcpu) = vcpu_channel();
            vm::VcpuHandler::finished(&mut native, outcome);
            let pending = vcpu.0.as_mut().unwrap().exits.try_recv().unwrap();
            assert_eq!(pending.exit, expected);
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn native_exits_preserve_every_payload() {
        let cases = [
            (vm::VcpuExit::Halt, Exit::Halt),
            (vm::VcpuExit::Shutdown, Exit::Shutdown),
            (vm::VcpuExit::Interrupted, Exit::Interrupted),
            (
                vm::VcpuExit::PioRead(vm::PioRead {
                    port: 0x1234,
                    length: 2,
                }),
                Exit::PioRead(platform::PioRead {
                    port: 0x1234,
                    length: 2,
                }),
            ),
            (
                vm::VcpuExit::PioWrite(vm::PioWrite {
                    port: 0x2345,
                    length: 4,
                }),
                Exit::PioWrite(platform::PioWrite {
                    port: 0x2345,
                    length: 4,
                }),
            ),
            (
                vm::VcpuExit::Rdmsr(vm::Msr {
                    index: 0x1234,
                    value: 0x5678,
                }),
                Exit::Rdmsr(platform::Msr {
                    index: 0x1234,
                    value: 0x5678,
                }),
            ),
            (
                vm::VcpuExit::Wrmsr(vm::Msr {
                    index: 0x2345,
                    value: 0x6789,
                }),
                Exit::Wrmsr(platform::Msr {
                    index: 0x2345,
                    value: 0x6789,
                }),
            ),
            (vm::VcpuExit::Stopped, Exit::Stopped),
        ];
        for (input, expected) in cases {
            assert_eq!(native_exit(input), Some(expected));
        }
        assert_eq!(
            native_exit(vm::VcpuExit::IoApicAccess(vm::IoApicAccess {
                offset: 0,
                width: 4,
                write: false,
                value: 0,
            })),
            None
        );
        assert_eq!(native_exit(vm::VcpuExit::IoApicEoi(32)), None);
        assert_eq!(
            native_exit(vm::VcpuExit::MmioRead(vm::MmioRead {
                address: 0x1234,
                width: 8,
            })),
            None
        );
        assert_eq!(
            native_exit(vm::VcpuExit::MmioWrite(vm::MmioWrite {
                address: 0x2345,
                width: 4,
                value: 0x5678,
            })),
            None
        );
    }

    #[test]
    fn native_actions_preserve_every_payload() {
        let cases = [
            (Completion::Start, vm::VcpuAction::Start),
            (Completion::Reenter, vm::VcpuAction::Reenter),
            (Completion::PioZero, vm::VcpuAction::PioZero),
            (Completion::Rdmsr(0x2345), vm::VcpuAction::Rdmsr(0x2345)),
            (Completion::MsrFault, vm::VcpuAction::MsrFault),
            (Completion::Wrmsr, vm::VcpuAction::Wrmsr),
        ];
        for (input, expected) in cases {
            assert_eq!(native_action(input), expected);
        }
    }

    async fn resume(
        accessor: &Accessor<PlatformHost>,
        resource: Resource<Vcpu>,
        completion: Completion,
    ) -> wasmtime::Result<Result<Exit, Error>> {
        let platform = accessor.with_getter::<Platform>(|host| host);
        <Platform as platform::HostVcpuWithStore<PlatformHost>>::resume(
            &platform, resource, completion,
        )
        .await
    }

    #[tokio::test]
    async fn hostile_vcpu_resources_and_completions_never_reach_native() {
        let engine = crate::engine::device_engine().unwrap();
        let (native, vcpu) = vcpu_channel();
        let mut host = PlatformHost::default();
        let resource = host.table.push(vcpu).unwrap();
        let wrong_type = host.table.push(String::new()).unwrap();
        let (_, stale_vcpu) = vcpu_channel();
        let stale = host.table.push(stale_vcpu).unwrap();
        let stale_rep = stale.rep();
        platform::HostVcpu::drop(&mut host, stale).unwrap();
        let mut store = wasmtime::Store::new(&engine, host);
        let result = store
            .run_concurrent(async |accessor| {
                assert!(
                    resume(accessor, Resource::new_borrow(u32::MAX), Completion::Start,)
                        .await
                        .is_err()
                );
                assert!(
                    resume(accessor, Resource::new_borrow(stale_rep), Completion::Start,)
                        .await
                        .is_err()
                );
                assert!(
                    resume(
                        accessor,
                        Resource::new_borrow(wrong_type.rep()),
                        Completion::Start,
                    )
                    .await
                    .is_err()
                );

                let native = tokio::task::spawn_blocking(move || native.exchange(Exit::Halt));
                assert_matches!(
                    resume(
                        accessor,
                        Resource::new_borrow(resource.rep()),
                        Completion::Start,
                    )
                    .await?,
                    Ok(Exit::Halt)
                );
                assert_matches!(
                    resume(
                        accessor,
                        Resource::new_borrow(resource.rep()),
                        Completion::PioZero,
                    )
                    .await?,
                    Err(Error::BadExit)
                );
                Ok::<_, wasmtime::Error>(native)
            })
            .await
            .unwrap()
            .unwrap();
        assert!(result.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn concurrent_vcpu_resumes_deliver_only_one_completion() {
        let engine = crate::engine::device_engine().unwrap();
        let (native, vcpu) = vcpu_channel();
        let mut host = PlatformHost::default();
        let resource = host.table.push(vcpu).unwrap();
        let mut store = wasmtime::Store::new(&engine, host);
        let native = store
            .run_concurrent(async |accessor| {
                let (release, wait) = std::sync::mpsc::sync_channel(0);
                let native = tokio::task::spawn_blocking(move || {
                    let completion = native.exchange(Exit::Halt);
                    wait.recv().unwrap();
                    completion
                });
                assert_matches!(
                    resume(
                        accessor,
                        Resource::new_borrow(resource.rep()),
                        Completion::Start,
                    )
                    .await?,
                    Ok(Exit::Halt)
                );
                let mut first = std::pin::pin!(resume(
                    accessor,
                    Resource::new_borrow(resource.rep()),
                    Completion::Reenter,
                ));
                assert_matches!(
                    first.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Pending
                );
                assert!(
                    resume(
                        accessor,
                        Resource::new_borrow(resource.rep()),
                        Completion::Reenter,
                    )
                    .await
                    .is_err()
                );
                release.send(()).unwrap();
                assert_matches!(first.await?, Ok(Exit::Stopped));
                Ok::<_, wasmtime::Error>(native)
            })
            .await
            .unwrap()
            .unwrap();
        assert_matches!(native.await.unwrap().unwrap(), Completion::Reenter);
    }

    #[test]
    fn rendezvous_rejects_completions_for_another_exit() {
        assert!(accepts_completion(&Exit::Halt, &Completion::Reenter));
        assert!(!accepts_completion(&Exit::Halt, &Completion::PioZero));
        assert!(!accepts_completion(
            &Exit::PioRead(platform::PioRead { port: 0, length: 1 }),
            &Completion::Reenter
        ));
        assert!(!accepts_completion(&Exit::Shutdown, &Completion::Reenter));
    }
}
