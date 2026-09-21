use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::box_runtime::store::BoxHost;
pub use crate::component::vmm::bindings::lifecycle_platform;

#[derive(Clone)]
pub struct LifecycleNotifier {
    event: watch::Sender<Option<Event>>,
    outcome: watch::Sender<Option<Outcome>>,
    shutdown_deadline: ShutdownDeadline,
}

#[derive(Clone)]
pub(crate) struct ShutdownDeadline(Arc<OnceLock<Instant>>);

impl ShutdownDeadline {
    pub(crate) fn start(&self) -> Instant {
        *self
            .0
            .get_or_init(|| Instant::now() + crate::box_runtime::BOX_SHUTDOWN_TIMEOUT)
    }
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

pub struct LifecycleHost {
    sender: LifecycleNotifier,
    teardown: super::teardown::NativeTeardown,
}

pub struct LifecyclePlatform;

impl LifecycleHost {
    #[must_use]
    pub fn new() -> Self {
        let (event, _) = watch::channel(None);
        let (outcome, _) = watch::channel(None);
        let shutdown_deadline = ShutdownDeadline(Arc::new(OnceLock::new()));
        Self {
            sender: LifecycleNotifier {
                event,
                outcome,
                shutdown_deadline,
            },
            teardown: super::teardown::NativeTeardown::new(),
        }
    }

    #[must_use]
    pub fn notifier(&self) -> LifecycleNotifier {
        self.sender.clone()
    }

    pub(crate) fn native_teardown(&self) -> super::teardown::NativeTeardown {
        self.teardown.clone()
    }

    pub(crate) fn next_event(
        &self,
    ) -> impl core::future::Future<
        Output = wasmtime::Result<Result<lifecycle_platform::Event, lifecycle_platform::Error>>,
    > + Send
    + use<> {
        let mut receiver = self.sender.event.subscribe();
        async move {
            let event = receiver
                .wait_for(Option::is_some)
                .await
                .map_err(|_| wasmtime::Error::msg("lifecycle event source closed"))?
                .ok_or_else(|| wasmtime::Error::msg("lifecycle event missing"))?;
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
    #[must_use]
    pub fn begin_shutdown(&self) -> Instant {
        self.shutdown_deadline.start()
    }

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
                self.shutdown_deadline.start();
                *current = Some(event);
                true
            }
        });
    }

    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<Option<Outcome>> {
        self.outcome.subscribe()
    }

    /// Publishes the first terminal decision; native teardown may still be running.
    pub fn publish_outcome(&self, outcome: Outcome) {
        let _ = self.outcome.send_if_modified(|current| {
            if current.is_some() {
                false
            } else {
                self.shutdown_deadline.start();
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
        receiver
            .wait_for(Option::is_some)
            .await
            .map_err(|_| WaitError::Closed)?
            .ok_or(WaitError::Missing)
    };
    if let Some(deadline) = deadline {
        tokio::select! {
            biased;
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

impl lifecycle_platform::Host for LifecycleHost {}

impl<T: Send + 'static> lifecycle_platform::HostWithStore<T> for LifecyclePlatform {
    async fn shutdown(
        host: &wasmtime::component::Accessor<T, Self>,
    ) -> wasmtime::Result<Result<(), lifecycle_platform::Error>> {
        let (teardown, deadline) = host.with(|mut access| {
            let host = access.get();
            (host.native_teardown(), host.sender.begin_shutdown())
        });
        Ok(teardown
            .wait_until(deadline)
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
    async fn retains_the_first_terminal_event() {
        let host = LifecycleHost::new();
        let notifier = host.notifier();
        notifier.deadline();
        notifier.guest_exit(7);

        assert!(matches!(
            host.next_event().await.expect("event"),
            Ok(lifecycle_platform::Event::Deadline)
        ));
        assert_eq!(*host.sender.event.borrow(), Some(Event::Deadline));
    }

    #[tokio::test]
    async fn publishes_the_first_supervisor_outcome() {
        let host = LifecycleHost::new();
        let notifier = host.notifier();
        let mut outcome = notifier.subscribe();
        notifier.publish_outcome(Outcome::VcpuFinished);
        notifier.publish_outcome(Outcome::Deadline);
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

    #[tokio::test]
    async fn closed_outcome_channels_keep_the_last_terminal_value() {
        let host = LifecycleHost::new();
        let notifier = host.notifier();
        for terminal in [None, Some(Outcome::GuestExit(7))] {
            let (sender, mut receiver) = tokio::sync::watch::channel(terminal);
            receiver.borrow_and_update();
            drop(sender);
            assert_eq!(
                wait_for_outcome(&mut receiver, None, &notifier).await,
                terminal.ok_or(super::WaitError::Closed)
            );
        }
    }

    #[tokio::test]
    async fn published_outcome_wins_over_an_expired_deadline() {
        let host = LifecycleHost::new();
        let notifier = host.notifier();
        let mut outcome = notifier.subscribe();
        notifier.publish_outcome(Outcome::GuestExit(7));

        assert_eq!(
            wait_for_outcome(&mut outcome, Some(Duration::ZERO), &notifier).await,
            Ok(Outcome::GuestExit(7))
        );
        assert_eq!(*host.sender.event.borrow(), None);
    }

    #[test]
    fn terminal_phases_keep_the_first_shutdown_deadline() {
        let host = LifecycleHost::new();
        let notifier = host.notifier();
        notifier.guest_exit(7);
        let deadline = notifier.begin_shutdown();
        notifier.publish_outcome(Outcome::GuestExit(7));

        assert_eq!(notifier.begin_shutdown(), deadline);
    }
}
