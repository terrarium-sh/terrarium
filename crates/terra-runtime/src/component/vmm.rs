//! Scoped hypervisor rendezvous for the long-running Wasm VMM.

pub mod boot;
pub mod interrupts;
pub mod lifecycle;
pub mod machine;
pub mod mmio;
pub mod reaper;
pub mod teardown;
pub mod virtualization;
pub(crate) mod workers;

use std::sync::{Arc, mpsc};
use std::time::Duration;
use wasmtime::component::{Accessor, Resource, ResourceTable};

use crate::BoundedMemory;
use crate::box_runtime::BoxHost;
pub use crate::component::vmm::mmio::terra::mmio::platform;
pub use crate::component::vmm::mmio::terra::mmio::platform::{Completion, Error, Exit};

const MAX_VCPUS: usize = terra_limits::X86_MAX_VCPUS as usize;
const EXIT_TIMEOUT: Duration = Duration::from_secs(5);

struct Pending {
    exit: Exit,
    reply: mpsc::SyncSender<Completion>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ProtocolPhase {
    AwaitingStart,
    Running,
}

pub struct NativeVcpu {
    sender: tokio::sync::mpsc::Sender<Pending>,
}

impl NativeVcpu {
    pub fn exchange_arm_exception(
        &self,
        address: u64,
        syndrome: u64,
        mut read_register: impl FnMut(u8) -> wasmtime::Result<u64>,
    ) -> wasmtime::Result<Completion> {
        let mut completion = self.exchange(Exit::ArmException(platform::ArmException {
            address,
            syndrome,
        }))?;
        for _ in 0..4 {
            let Completion::ArmRegister(register) = completion else {
                return Ok(completion);
            };
            wasmtime::ensure!(register <= 31, "ARM register outside vCPU grant");
            let value = read_register(register)?;
            completion = self.exchange(Exit::ArmRegisterValue(value))?;
        }
        wasmtime::ensure!(
            !matches!(completion, Completion::ArmRegister(_)),
            "VMM exceeded ARM register access budget"
        );
        Ok(completion)
    }

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

struct Rendezvous {
    exits: tokio::sync::mpsc::Receiver<Pending>,
    pending: Option<Pending>,
    phase: ProtocolPhase,
}

pub struct Vcpu(Option<Rendezvous>);

fn vcpu_channel() -> (NativeVcpu, Vcpu) {
    let (sender, exits) = tokio::sync::mpsc::channel(1);
    (
        NativeVcpu { sender },
        Vcpu(Some(Rendezvous {
            exits,
            pending: None,
            phase: ProtocolPhase::AwaitingStart,
        })),
    )
}

fn accepts_completion(
    exit: &Exit,
    completion: &Completion,
    completion_grant: Option<(&virtualization::MachineConfig, &crate::SyntheticRam)>,
) -> bool {
    match exit {
        Exit::Halt | Exit::Interrupted | Exit::MmioWrite(_) | Exit::PioWrite(_) => {
            matches!(completion, Completion::Reenter)
        }
        Exit::MmioRead(_) => matches!(completion, Completion::MmioRead(_)),
        Exit::PioRead(_) => matches!(completion, Completion::PioZero),
        Exit::Rdmsr(_) => matches!(completion, Completion::Rdmsr(_) | Completion::MsrFault),
        Exit::Wrmsr(_) => matches!(completion, Completion::Wrmsr | Completion::MsrFault),
        Exit::ArmException(_) | Exit::ArmRegisterValue(_) => {
            accepts_arm_completion(completion, completion_grant)
        }
        Exit::HvcResult(_) => matches!(completion, Completion::HvcReturn(_)),
        Exit::Shutdown | Exit::Stopped => false,
    }
}

fn accepts_arm_completion(
    completion: &Completion,
    completion_grant: Option<(&virtualization::MachineConfig, &crate::SyntheticRam)>,
) -> bool {
    match completion {
        Completion::ArmRead(read) => read.register.is_none_or(|register| register < 31),
        Completion::ArmRegister(register) => *register <= 31,
        Completion::HvcReturn(_) | Completion::CpuOff | Completion::SystemStop => true,
        Completion::CpuStart(start) => completion_grant.is_some_and(|(config, ram)| {
            config.architecture() == virtualization::Architecture::Arm
                && start.target != 0
                && config.is_valid_cpu(start.target)
                && start.entry.is_multiple_of(4)
                && BoundedMemory::new(ram).read(start.entry, 4).is_ok()
        }),
        Completion::Start
        | Completion::Reenter
        | Completion::MmioRead(_)
        | Completion::PioZero
        | Completion::Rdmsr(_)
        | Completion::MsrFault
        | Completion::Wrmsr => false,
    }
}

type Completed = Arc<dyn Fn(u32, bool) -> wasmtime::Result<()> + Send + Sync>;

#[derive(Default)]
pub struct PlatformHost {
    table: ResourceTable,
    completed: Option<Completed>,
    virtualization: virtualization::VirtualizationHost,
    pending_vcpus: Vec<(u8, NativeVcpu)>,
    pub(crate) workers: workers::WorkerHost,
}

pub struct Platform;

impl wasmtime::component::HasData for Platform {
    type Data<'a> = &'a mut PlatformHost;
}

impl platform::Host for PlatformHost {
    fn completed(&mut self, slot: u32, failed: bool) -> wasmtime::Result<Result<(), Error>> {
        let Some(completed) = &self.completed else {
            return Ok(Err(Error::Unavailable));
        };
        Ok(completed(slot, failed).map_err(|_| Error::BadExit))
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
        if let Some(pending) = rendezvous.pending.take() {
            let valid = if matches!(
                (&pending.exit, &completion),
                (
                    Exit::ArmException(_) | Exit::ArmRegisterValue(_),
                    Completion::CpuStart(_)
                )
            ) {
                accessor.with(|mut store| {
                    let (config, ram) = store.get().completion_grant()?;
                    Ok::<_, wasmtime::Error>(accepts_completion(
                        &pending.exit,
                        &completion,
                        Some((config, &ram)),
                    ))
                })?
            } else {
                accepts_completion(&pending.exit, &completion, None)
            };
            if !valid {
                return Ok(Err(Error::BadExit));
            }
            if pending.reply.send(completion).is_err() {
                return Ok(Err(Error::Cancelled));
            }
        } else if rendezvous.phase != ProtocolPhase::AwaitingStart
            || !matches!(completion, Completion::Start)
        {
            return Ok(Err(Error::BadExit));
        }
        rendezvous.phase = ProtocolPhase::Running;
        let Some(pending) = rendezvous.exits.recv().await else {
            return Ok(Ok(Exit::Stopped));
        };
        let exit = pending.exit;
        rendezvous.pending = Some(pending);
        accessor.with(|mut store| {
            store.get().table.get_mut(&resource)?.0 = Some(rendezvous);
            Ok::<(), wasmtime::Error>(())
        })?;
        Ok(Ok(exit))
    }
}

pub(crate) fn add_to_linker(
    linker: &mut wasmtime::component::Linker<BoxHost>,
) -> wasmtime::Result<()> {
    platform::add_to_linker::<BoxHost, Platform>(linker, |host| &mut host.platform)?;
    virtualization::add_to_linker(linker)?;
    workers::add_to_linker(linker)?;
    lifecycle::add_to_linker(linker)
}

pub(crate) fn configure_callbacks(host: &mut PlatformHost, completed: Completed) {
    host.completed = Some(completed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

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
                assert!(matches!(
                    resume(
                        accessor,
                        Resource::new_borrow(resource.rep()),
                        Completion::Start,
                    )
                    .await?,
                    Ok(Exit::Halt)
                ));
                assert!(matches!(
                    resume(
                        accessor,
                        Resource::new_borrow(resource.rep()),
                        Completion::PioZero,
                    )
                    .await?,
                    Err(Error::BadExit)
                ));
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
                assert!(matches!(
                    resume(
                        accessor,
                        Resource::new_borrow(resource.rep()),
                        Completion::Start,
                    )
                    .await?,
                    Ok(Exit::Halt)
                ));
                let mut first = std::pin::pin!(resume(
                    accessor,
                    Resource::new_borrow(resource.rep()),
                    Completion::Reenter,
                ));
                assert!(matches!(
                    first.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Pending
                ));
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
                assert!(matches!(first.await?, Ok(Exit::Stopped)));
                Ok::<_, wasmtime::Error>(native)
            })
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            native.await.unwrap().unwrap(),
            Completion::Reenter
        ));
    }

    #[test]
    fn rendezvous_rejects_completions_for_another_exit() {
        let arm_exception = Exit::ArmException(platform::ArmException {
            address: 0,
            syndrome: 0,
        });
        let arm_read = Completion::ArmRead(platform::ArmRead {
            register: Some(31),
            value: 0,
        });

        assert!(accepts_completion(&Exit::Halt, &Completion::Reenter, None));
        assert!(!accepts_completion(
            &Exit::Halt,
            &Completion::MmioRead(0),
            None
        ));
        assert!(accepts_completion(
            &Exit::MmioRead(platform::MmioRead {
                address: 0,
                width: 4,
            }),
            &Completion::MmioRead(0),
            None
        ));
        assert!(!accepts_completion(
            &Exit::MmioRead(platform::MmioRead {
                address: 0,
                width: 4,
            }),
            &Completion::Reenter,
            None
        ));
        assert!(accepts_completion(
            &arm_exception,
            &Completion::ArmRegister(31),
            None
        ));
        assert!(!accepts_completion(&arm_exception, &arm_read, None));
        assert!(!accepts_completion(
            &Exit::Shutdown,
            &Completion::Reenter,
            None
        ));

        let ram = crate::SyntheticRam::new(4096).unwrap();
        let config = virtualization::MachineConfig::new(
            virtualization::Architecture::Arm,
            ram.size(),
            2,
            Vec::new(),
        )
        .unwrap();
        for start in [
            platform::CpuStart {
                target: 0,
                entry: 0,
                context: 0,
            },
            platform::CpuStart {
                target: 2,
                entry: 0,
                context: 0,
            },
            platform::CpuStart {
                target: 1,
                entry: 2,
                context: 0,
            },
            platform::CpuStart {
                target: 1,
                entry: ram.size(),
                context: 0,
            },
        ] {
            assert!(!accepts_completion(
                &arm_exception,
                &Completion::CpuStart(start),
                Some((&config, &ram)),
            ));
        }
        assert!(accepts_completion(
            &arm_exception,
            &Completion::CpuStart(platform::CpuStart {
                target: 1,
                entry: 0,
                context: 0,
            }),
            Some((&config, &ram)),
        ));
    }

    #[test]
    fn arm_register_requests_are_bounded_independently_of_wasm() {
        for registers in [vec![255], vec![0, 1, 2, 3, 4]] {
            let (native, mut component) = vcpu_channel();
            let mut rendezvous = component.0.take().unwrap();
            let reads = std::sync::atomic::AtomicUsize::new(0);
            std::thread::scope(|scope| {
                let task = scope.spawn(|| {
                    native.exchange_arm_exception(0, 0, |_| {
                        reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Ok(42)
                    })
                });
                for register in &registers {
                    let pending = rendezvous.exits.blocking_recv().unwrap();
                    pending
                        .reply
                        .send(Completion::ArmRegister(*register))
                        .unwrap();
                }
                assert!(task.join().unwrap().is_err());
                assert_eq!(
                    reads.load(std::sync::atomic::Ordering::Relaxed),
                    registers.len() - 1
                );
            });
        }
    }

    #[test]
    fn arm_register_31_is_a_zero_source() {
        let (native, mut component) = vcpu_channel();
        let mut rendezvous = component.0.take().unwrap();
        std::thread::scope(|scope| {
            let task = scope.spawn(|| {
                native.exchange_arm_exception(0, 0, |register| {
                    assert_eq!(register, 31);
                    Ok(0)
                })
            });
            let pending = rendezvous.exits.blocking_recv().unwrap();
            pending.reply.send(Completion::ArmRegister(31)).unwrap();
            let pending = rendezvous.exits.blocking_recv().unwrap();
            assert!(matches!(pending.exit, Exit::ArmRegisterValue(0)));
            pending.reply.send(Completion::Reenter).unwrap();
            assert!(matches!(task.join().unwrap().unwrap(), Completion::Reenter));
        });
    }
}
