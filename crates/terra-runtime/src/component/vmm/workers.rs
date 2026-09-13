use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use wasmtime::component::{Accessor, StreamReader};

use super::{Platform, PlatformHost};
use crate::box_runtime::{BoxHost, BoxRuntime};
use crate::component::relay;
use crate::component::vmm::mmio::{Reply, Request, Serve, terra::mmio::workers};

pub(crate) const SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) type Factory = Box<
    dyn FnOnce() -> Pin<Box<dyn Future<Output = wasmtime::Result<(BoxRuntime, Serve)>> + Send>>
        + Send,
>;

#[derive(Default)]
struct SetupState {
    is_cancelled: bool,
    task: Option<tokio::task::AbortHandle>,
}

#[derive(Default)]
struct SetupTask {
    state: Mutex<SetupState>,
}

impl SetupTask {
    fn register(&self, task: tokio::task::AbortHandle) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.is_cancelled {
            task.abort();
        } else {
            state.task = Some(task);
        }
    }
}

pub(crate) struct SetupGuard(Arc<SetupTask>);

impl Drop for SetupGuard {
    fn drop(&mut self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.is_cancelled = true;
        if let Some(task) = state.task.take() {
            task.abort();
        }
    }
}

pub(crate) struct GrantedWorker {
    pub slot: u32,
    pub kind: super::machine::DeviceKind,
    pub mapping: Option<workers::Mapping>,
    pub base: Arc<AtomicU64>,
    pub factory: Option<Factory>,
}

#[derive(Default)]
pub(crate) struct WorkerHost {
    setup: Arc<SetupTask>,
    pub creation_unfinished: bool,
    pub factories: Vec<GrantedWorker>,
    pub machine_layout: Option<super::virtualization::MachineConfig>,
    pub children: Vec<BoxRuntime>,
}

impl WorkerHost {
    pub fn grant_all(&mut self, mut grants: Vec<GrantedWorker>) -> wasmtime::Result<SetupGuard> {
        wasmtime::ensure!(
            !self.creation_unfinished && self.factories.is_empty() && self.children.is_empty(),
            "worker creation already pending"
        );
        wasmtime::ensure!(
            grants.len() <= crate::box_runtime::MAX_BOX_COMPONENTS,
            "box has too many worker grants"
        );
        for index in 0..grants.len() {
            let (before, rest) = grants.split_at_mut(index);
            let worker = &mut rest[0];
            let mapping = worker.mapping.or_else(|| {
                let config = self.machine_layout.as_ref()?;
                let ordinal = before
                    .iter()
                    .filter(|other| other.kind == worker.kind)
                    .count();
                let device = config
                    .devices()
                    .iter()
                    .filter(|device| device.kind == worker.kind)
                    .nth(ordinal)?;
                Some(workers::Mapping {
                    base: device.mmio_base,
                    size: match config.architecture() {
                        super::virtualization::Architecture::X86 => 0x1000,
                        super::virtualization::Architecture::Arm => 0x200,
                    },
                })
            });
            let mapping =
                mapping.ok_or_else(|| wasmtime::Error::msg("worker grant has no mapping"))?;
            wasmtime::ensure!(
                usize::try_from(worker.slot)? < crate::box_runtime::MAX_BOX_COMPONENTS
                    && mapping.size != 0
                    && mapping.base.checked_add(mapping.size).is_some(),
                "worker grant outside box"
            );
            wasmtime::ensure!(
                !before.iter().any(|other| other.slot == worker.slot),
                "duplicate worker slot"
            );
            worker.mapping = Some(mapping);
        }
        self.setup = Arc::new(SetupTask::default());
        self.factories = grants;
        Ok(SetupGuard(Arc::clone(&self.setup)))
    }

    #[cfg(test)]
    fn grant(&mut self, slot: u32, factory: Factory) -> wasmtime::Result<SetupGuard> {
        self.grant_all(vec![GrantedWorker {
            slot,
            kind: super::machine::DeviceKind::Block,
            mapping: Some(workers::Mapping {
                base: 0,
                size: 4096,
            }),
            base: Arc::new(AtomicU64::new(0)),
            factory: Some(factory),
        }])
    }

    fn claim(&mut self, slot: u32) -> Option<Factory> {
        if self
            .setup
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_cancelled
        {
            return None;
        }
        if self.creation_unfinished {
            return None;
        }
        let index = self
            .factories
            .iter()
            .position(|worker| worker.slot == slot)?;
        let worker = &mut self.factories[index];
        let factory = worker.factory.take()?;
        worker.base.store(worker.mapping?.base, Ordering::Release);
        self.creation_unfinished = true;
        Some(factory)
    }
}

impl workers::Host for PlatformHost {
    fn grants(&mut self) -> wasmtime::Result<Vec<workers::Grant>> {
        self.workers
            .factories
            .iter()
            .filter(|worker| worker.factory.is_some())
            .map(|worker| {
                Ok(workers::Grant {
                    slot: worker.slot,
                    kind: worker.kind,
                    mapping: worker
                        .mapping
                        .ok_or_else(|| wasmtime::Error::msg("worker mapping missing"))?,
                })
            })
            .collect()
    }
}

impl<T: Send + 'static> workers::HostWithStore<T> for Platform {
    async fn create(
        accessor: &Accessor<T, Self>,
        slot: u32,
        requests: StreamReader<Request>,
    ) -> wasmtime::Result<Result<StreamReader<Reply>, workers::Error>> {
        let factory = accessor.with(|mut store| store.get().workers.claim(slot));
        let Some(factory) = factory else {
            return Ok(Err(workers::Error::Unavailable));
        };
        let (sink, stream) = relay::channel(relay::MMIO_CAPACITY);
        accessor.with(|mut store| requests.pipe(&mut store, sink))?;
        // Wasmtime rejects nested store event loops, including calls into a different store.
        let mut setup = tokio::task::JoinSet::new();
        let task = setup.spawn(create_worker(factory, stream));
        accessor.with(|mut store| store.get().workers.setup.register(task));
        let (child, stream) = setup
            .join_next()
            .await
            .ok_or_else(|| wasmtime::Error::msg("worker setup task missing"))???;
        let replies = accessor.with(|mut store| {
            let replies = StreamReader::new(&mut store, stream)?;
            let host = &mut store.get().workers;
            host.children.push(child);
            host.creation_unfinished = false;
            Ok::<_, wasmtime::Error>(replies)
        })?;
        Ok(Ok(replies))
    }
}

async fn create_worker(
    factory: Factory,
    requests: relay::Stream<Request>,
) -> wasmtime::Result<(BoxRuntime, relay::Stream<Reply>)> {
    tokio::time::timeout(SETUP_TIMEOUT, initialize_worker(factory, requests))
        .await
        .map_err(|_| wasmtime::Error::msg("worker setup timed out"))?
}

async fn initialize_worker(
    factory: Factory,
    requests: relay::Stream<Request>,
) -> wasmtime::Result<(BoxRuntime, relay::Stream<Reply>)> {
    let (mut child, serve) = factory().await?;
    let requests = StreamReader::new(&mut child.store, requests)?;
    let (replies,) = serve.call_async(&mut child.store, (requests,)).await?;
    let (sink, stream) = relay::channel(relay::MMIO_CAPACITY);
    replies.pipe(&mut child.store, sink)?;
    Ok((child, stream))
}

pub(crate) fn add_to_linker(
    linker: &mut wasmtime::component::Linker<BoxHost>,
) -> wasmtime::Result<()> {
    workers::add_to_linker::<BoxHost, Platform>(linker, |host| &mut host.platform)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NotifyDrop(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for NotifyDrop {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test]
    async fn cancelling_wasi_creation_aborts_the_native_setup_task() {
        let engine = crate::engine::device_engine().unwrap();
        let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).unwrap();
        let component = wasmtime::component::Component::new(&engine, include_bytes!(
            "../../../../../components/vmm/target/wasm32-wasip3/release/terra_vmm_component.wasm"
        )).unwrap();
        runtime.initialize_mmio(&component).await.unwrap();
        let (entered, started) = tokio::sync::oneshot::channel();
        let (dropped, stopped) = tokio::sync::oneshot::channel();
        let pending_factory: Factory = Box::new(move || {
            Box::pin(async move {
                let _guard = NotifyDrop(Some(dropped));
                let _ = entered.send(());
                std::future::pending().await
            })
        });
        {
            let creation = crate::component::vmm::mmio::MmioDevice::grant_worker(
                &mut runtime,
                crate::component::vmm::machine::DeviceKind::Block,
                pending_factory,
            );
            tokio::pin!(creation);
            tokio::select! {
                result = &mut creation => panic!("creation ended before cancellation: {}", result.is_ok()),
                result = started => result.unwrap(),
            }
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), stopped)
            .await
            .unwrap()
            .unwrap();
        assert!(runtime.store.data().platform.workers.creation_unfinished);
        assert!(
            runtime
                .store
                .data_mut()
                .platform
                .workers
                .grant(0, factory())
                .is_err()
        );
    }

    fn factory() -> Factory {
        Box::new(|| Box::pin(std::future::pending()))
    }

    #[test]
    fn fixed_mapping_is_bound_before_claiming_factory() {
        use super::super::machine::Device;
        use super::super::virtualization::{Architecture, MachineConfig};

        let mut host = WorkerHost::default();
        let base = Arc::new(AtomicU64::new(0));
        host.machine_layout = Some(
            MachineConfig::new(
                Architecture::X86,
                4096,
                1,
                vec![Device {
                    kind: super::super::machine::DeviceKind::Block,
                    mmio_base: 0xd000_1000,
                    irq: 11,
                }],
            )
            .unwrap(),
        );
        let _setup = host
            .grant_all(vec![GrantedWorker {
                slot: 0,
                kind: super::super::machine::DeviceKind::Block,
                mapping: None,
                base: Arc::clone(&base),
                factory: Some(factory()),
            }])
            .unwrap();
        assert!(host.claim(1).is_none());
        drop(host.claim(0).unwrap());
        assert_eq!(base.load(Ordering::Acquire), 0xd000_1000);
        assert!(host.factories[0].factory.is_none());
    }

    #[test]
    fn cancelled_grants_cannot_start_setup_later() {
        let mut host = WorkerHost::default();
        drop(host.grant(3, factory()).unwrap());
        assert!(host.claim(3).is_none());
        assert!(host.grant(4, factory()).is_err());
    }

    #[test]
    fn only_the_granted_slot_can_claim_one_creation() {
        let mut host = WorkerHost::default();
        assert!(host.claim(0).is_none());
        assert!(host.grant(37, factory()).is_err());
        let _setup = host.grant(3, factory()).unwrap();
        assert!(host.grant(4, factory()).is_err());
        assert!(host.claim(4).is_none());
        drop(host.claim(3).expect("granted factory"));
        assert!(host.claim(3).is_none());
        assert!(host.grant(3, factory()).is_err());
        assert!(host.children.is_empty());
    }
}
