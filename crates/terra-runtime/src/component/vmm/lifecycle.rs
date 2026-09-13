use std::time::Duration;

use tokio::sync::watch;

use crate::box_runtime::BoxHost;
pub use crate::component::vmm::mmio::terra::mmio::lifecycle_platform;

#[derive(Clone)]
pub struct LifecycleNotifier {
    event: watch::Sender<Option<Event>>,
    outcome: watch::Sender<Option<Outcome>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    GuestExit(i32),
    ComponentFailed,
    Deadline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    GuestExit(i32),
    ComponentFailed,
    VcpuFinished,
    Deadline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitError {
    Closed,
    Missing,
}

struct InterruptGrant {
    cleanup: Option<super::teardown::NativeCleanup>,
}

pub struct LifecycleHost {
    sender: LifecycleNotifier,
    receiver: watch::Receiver<Option<Event>>,
    devices: Option<Vec<Option<super::teardown::DeviceShutdown>>>,
    interrupts: Option<InterruptGrant>,
}

pub struct LifecyclePlatform;

impl LifecycleHost {
    pub(crate) fn take_shutdowns(
        &mut self,
    ) -> (
        Vec<super::teardown::DeviceShutdown>,
        Option<super::teardown::NativeCleanup>,
    ) {
        let devices = self
            .devices
            .take()
            .into_iter()
            .flatten()
            .flatten()
            .collect();
        let interrupts = self.interrupts.take().and_then(|grant| grant.cleanup);
        (devices, interrupts)
    }

    fn claim_interrupt_shutdown(
        &mut self,
    ) -> Result<Option<super::teardown::NativeCleanup>, lifecycle_platform::Error> {
        match &mut self.interrupts {
            Some(grant) => grant
                .cleanup
                .take()
                .map(Some)
                .ok_or(lifecycle_platform::Error::Closed),
            None => Ok(None),
        }
    }

    #[must_use]
    pub fn new() -> Self {
        let (event, receiver) = watch::channel(None);
        let (outcome, _) = watch::channel(None);
        Self {
            sender: LifecycleNotifier { event, outcome },
            receiver,
            devices: None,
            interrupts: None,
        }
    }

    #[must_use]
    pub fn notifier(&self) -> LifecycleNotifier {
        self.sender.clone()
    }

    #[must_use]
    pub fn from_notifier(sender: LifecycleNotifier) -> Self {
        Self {
            receiver: sender.event.subscribe(),
            sender,
            devices: None,
            interrupts: None,
        }
    }

    fn next_event(
        &self,
    ) -> impl core::future::Future<
        Output = wasmtime::Result<Result<lifecycle_platform::Event, lifecycle_platform::Error>>,
    > + Send
    + use<> {
        let mut receiver = self.receiver.clone();
        async move {
            let event = if let Some(event) = *receiver.borrow_and_update() {
                event
            } else {
                receiver
                    .changed()
                    .await
                    .map_err(|_| wasmtime::Error::msg("lifecycle event source closed"))?;
                (*receiver.borrow_and_update())
                    .ok_or_else(|| wasmtime::Error::msg("lifecycle event missing"))?
            };
            Ok(Ok(match event {
                Event::GuestExit(code) => lifecycle_platform::Event::GuestExit(code),
                Event::ComponentFailed => lifecycle_platform::Event::ComponentFailed,
                Event::Deadline => lifecycle_platform::Event::Deadline,
            }))
        }
    }
}

impl Default for LifecycleHost {
    fn default() -> Self {
        Self::new()
    }
}

impl LifecycleNotifier {
    pub fn guest_exit(&self, code: i32) {
        self.publish(Event::GuestExit(code));
    }

    pub fn component_failed(&self) {
        self.publish(Event::ComponentFailed);
    }

    pub fn deadline(&self) {
        self.publish(Event::Deadline);
    }

    fn publish(&self, event: Event) {
        let _ = self.event.send_if_modified(|current| {
            if current.is_some() {
                false
            } else {
                *current = Some(event);
                true
            }
        });
    }

    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<Option<Outcome>> {
        self.outcome.subscribe()
    }

    pub fn complete(&self, outcome: Outcome) {
        let _ = self.outcome.send_if_modified(|current| {
            if current.is_some() {
                false
            } else {
                *current = Some(outcome);
                true
            }
        });
    }
}

pub async fn wait_for_outcome(
    receiver: &mut watch::Receiver<Option<Outcome>>,
    deadline: Option<Duration>,
    notifier: &LifecycleNotifier,
) -> Result<Outcome, WaitError> {
    let next = async {
        if let Some(outcome) = *receiver.borrow_and_update() {
            Ok(outcome)
        } else {
            receiver.changed().await.map_err(|_| WaitError::Closed)?;
            (*receiver.borrow_and_update()).ok_or(WaitError::Missing)
        }
    };
    if let Some(deadline) = deadline {
        tokio::select! {
            outcome = next => outcome,
            () = tokio::time::sleep(deadline) => {
                notifier.deadline();
                Ok(Outcome::Deadline)
            }
        }
    } else {
        next.await
    }
}

impl wasmtime::component::HasData for LifecyclePlatform {
    type Data<'a> = &'a mut LifecycleHost;
}

impl lifecycle_platform::Host for LifecycleHost {
    fn devices(&mut self) -> wasmtime::Result<Vec<lifecycle_platform::DeviceGrant>> {
        self.devices
            .iter()
            .flatten()
            .enumerate()
            .filter_map(|(id, device)| device.as_ref().map(|device| (id, device)))
            .map(|(id, device)| {
                Ok(lifecycle_platform::DeviceGrant {
                    id: u32::try_from(id)?,
                    kind: device.kind,
                })
            })
            .collect()
    }
}

impl crate::box_runtime::BoxRuntime {
    pub fn grant_interrupt_shutdown(
        &mut self,
        close: impl FnOnce() -> Result<(), String> + Send + 'static,
    ) -> wasmtime::Result<super::teardown::NativeCleanup> {
        let host = &mut self.store.data_mut().lifecycle;
        wasmtime::ensure!(
            host.interrupts.is_none(),
            "interrupt shutdown already granted"
        );
        let cleanup = super::teardown::NativeCleanup::new(close, None);
        host.interrupts = Some(InterruptGrant {
            cleanup: Some(cleanup.clone()),
        });
        Ok(cleanup)
    }

    pub fn grant_device_shutdown(
        &mut self,
        devices: Vec<super::teardown::DeviceShutdown>,
    ) -> wasmtime::Result<()> {
        wasmtime::ensure!(
            devices.len() <= crate::box_runtime::MAX_BOX_COMPONENTS,
            "box has too many device shutdown grants"
        );
        let host = &mut self.store.data_mut().lifecycle;
        wasmtime::ensure!(host.devices.is_none(), "device shutdown already granted");
        host.devices = Some(devices.into_iter().map(Some).collect());
        Ok(())
    }
}

impl<T: Send + 'static> lifecycle_platform::HostWithStore<T> for LifecyclePlatform {
    async fn release_interrupts(
        host: &wasmtime::component::Accessor<T, Self>,
    ) -> wasmtime::Result<Result<(), lifecycle_platform::Error>> {
        let cleanup = host.with(|mut access| access.get().claim_interrupt_shutdown());
        let cleanup = match cleanup {
            Ok(Some(cleanup)) => cleanup,
            Ok(None) => return Ok(Ok(())),
            Err(error) => return Ok(Err(error)),
        };
        Ok(cleanup
            .wait()
            .await
            .map_err(|_| lifecycle_platform::Error::Closed))
    }

    async fn close_device(
        host: &wasmtime::component::Accessor<T, Self>,
        id: u32,
    ) -> wasmtime::Result<Result<(), lifecycle_platform::Error>> {
        let device = host.with(|mut access| {
            access
                .get()
                .devices
                .as_mut()?
                .get_mut(usize::try_from(id).ok()?)?
                .take()
        });
        let Some(device) = device else {
            return Ok(Err(lifecycle_platform::Error::Closed));
        };
        Ok(device
            .wait()
            .await
            .map_err(|_| lifecycle_platform::Error::Closed))
    }

    fn next_event(
        host: &wasmtime::component::Accessor<T, Self>,
    ) -> impl core::future::Future<
        Output = wasmtime::Result<Result<lifecycle_platform::Event, lifecycle_platform::Error>>,
    > + Send {
        host.with(|mut access| access.get().next_event())
    }
}

pub(crate) fn add_to_linker(
    linker: &mut wasmtime::component::Linker<BoxHost>,
) -> wasmtime::Result<()> {
    lifecycle_platform::add_to_linker::<BoxHost, LifecyclePlatform>(linker, |host| {
        &mut host.lifecycle
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Event, LifecycleHost, Outcome, lifecycle_platform, wait_for_outcome};

    #[tokio::test]
    async fn interrupt_cleanup_is_claimed_once_and_cannot_be_regranted() {
        let engine = crate::engine::device_engine().unwrap();
        let mut runtime =
            crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new())
                .unwrap();
        assert!(
            runtime
                .store
                .data_mut()
                .lifecycle
                .claim_interrupt_shutdown()
                .unwrap()
                .is_none()
        );
        let recovery = runtime
            .grant_interrupt_shutdown(|| Err("interrupt failure".to_owned()))
            .unwrap();
        assert!(runtime.grant_interrupt_shutdown(|| Ok(())).is_err());
        let claimed = runtime
            .store
            .data_mut()
            .lifecycle
            .claim_interrupt_shutdown()
            .unwrap()
            .unwrap();
        assert!(
            runtime
                .store
                .data_mut()
                .lifecycle
                .claim_interrupt_shutdown()
                .is_err()
        );
        assert!(runtime.grant_interrupt_shutdown(|| Ok(())).is_err());
        assert_eq!(claimed.wait().await, Err("interrupt failure".to_owned()));
        assert_eq!(recovery.wait().await, Err("interrupt failure".to_owned()));
    }

    #[tokio::test]
    async fn retains_the_first_terminal_event() {
        let host = LifecycleHost::new();
        let notifier = host.notifier();
        notifier.deadline();
        notifier.guest_exit(7);

        assert!(matches!(
            host.next_event().await.expect("event"),
            Ok(lifecycle_platform::Event::Deadline)
        ));
        assert_eq!(*host.receiver.borrow(), Some(Event::Deadline));
    }

    #[tokio::test]
    async fn publishes_the_first_supervisor_outcome() {
        let host = LifecycleHost::new();
        let notifier = host.notifier();
        let mut outcome = notifier.subscribe();
        notifier.complete(Outcome::VcpuFinished);
        notifier.complete(Outcome::Deadline);
        outcome.changed().await.expect("outcome");

        assert_eq!(*outcome.borrow_and_update(), Some(Outcome::VcpuFinished));
    }

    #[tokio::test]
    async fn deadline_completes_the_waiter() {
        let host = LifecycleHost::new();
        let notifier = host.notifier();
        let mut outcome = notifier.subscribe();

        assert_eq!(
            wait_for_outcome(&mut outcome, Some(Duration::ZERO), &notifier)
                .await
                .expect("deadline outcome"),
            Outcome::Deadline
        );
    }
}
