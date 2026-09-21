//! Run native cleanup independently of waiting tasks.

use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use tokio::sync::watch;

pub type VcpuReaper = NativeTask<Vec<Result<(), String>>>;
type Outcome<O> = Result<O, String>;
type Cancel = Box<dyn FnOnce() -> wasmtime::Result<()> + Send>;
type Stop<O> = Box<dyn FnOnce() -> Outcome<O> + Send>;
type Pending<O> = Option<(Stop<O>, watch::Sender<Option<Outcome<O>>>)>;

struct TaskState<O: Clone + Send + Sync + 'static> {
    launch: Once,
    pending: Arc<Mutex<Pending<O>>>,
    cancel: Mutex<Option<Cancel>>,
}

#[derive(Clone)]
pub struct NativeTask<O: Clone + Send + Sync + 'static> {
    state: Arc<TaskState<O>>,
    outcome: watch::Receiver<Option<Outcome<O>>>,
}

fn run<O: Clone + Send + Sync + 'static>(pending: &Mutex<Pending<O>>) {
    let task = pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some((stop, sender)) = task {
        let outcome = stop();
        sender.send_replace(Some(outcome));
    }
}

fn start<O: Clone + Send + Sync + 'static>(
    pending: &Arc<Mutex<Pending<O>>>,
    cancel: &Mutex<Option<Cancel>>,
) {
    if let Some(cancel) = cancel
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        let _ = cancel();
    }
    let worker_pending = Arc::clone(pending);
    if std::thread::Builder::new()
        .spawn(move || run(&worker_pending))
        .is_err()
    {
        run(pending);
    }
}

impl<O: Clone + Send + Sync + 'static> TaskState<O> {
    pub(super) fn start(&self) {
        self.launch.call_once(|| start(&self.pending, &self.cancel));
    }
}

impl<O: Clone + Send + Sync + 'static> Drop for TaskState<O> {
    fn drop(&mut self) {
        self.start();
    }
}

impl<O: Clone + Send + Sync + 'static> NativeTask<O> {
    pub(crate) fn new(
        stop: impl FnOnce() -> Outcome<O> + Send + 'static,
        cancel: Option<Cancel>,
    ) -> Self {
        let (sender, outcome) = watch::channel(None);
        Self {
            state: Arc::new(TaskState {
                launch: Once::new(),
                pending: Arc::new(Mutex::new(Some((Box::new(stop), sender)))),
                cancel: Mutex::new(cancel),
            }),
            outcome,
        }
    }

    pub(super) fn request_stop(&self) -> wasmtime::Result<()> {
        let cancel = self
            .state
            .cancel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        cancel.map_or(Ok(()), |cancel| cancel())
    }

    pub(super) fn start(&self) {
        self.state.start();
    }

    async fn wait_for_outcome(&self) -> Outcome<O> {
        self.start();
        let mut receiver = self.outcome.clone();
        receiver
            .wait_for(Option::is_some)
            .await
            .map_err(|_| "native task stopped without an outcome".to_owned())?
            .clone()
            .ok_or_else(|| "native task outcome missing".to_owned())?
    }

    pub async fn wait(&self) -> Outcome<O> {
        self.wait_until(Instant::now() + Duration::from_secs(10))
            .await
    }

    pub async fn wait_until(&self, deadline: Instant) -> Outcome<O> {
        tokio::time::timeout_at(deadline.into(), self.wait_for_outcome())
            .await
            .map_err(|_| "native task timed out".to_owned())?
    }

    pub(crate) async fn wait_until_finished(&self) -> Outcome<O> {
        self.wait_for_outcome().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn stalled_cleanup_releases_the_state_lock_for_other_waiters() {
        let (entered, started) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let cleanup = NativeTask::new(
            move || {
                entered.send(()).unwrap();
                released
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap();
                Ok(())
            },
            None,
        );
        cleanup.start();
        started
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let is_unlocked = cleanup.state.pending.try_lock().is_ok();
        release.send(()).unwrap();
        assert!(is_unlocked, "native cleanup must not hold the state lock");
        assert_eq!(cleanup.wait().await, Ok(()));
    }

    #[tokio::test]
    async fn cancelling_a_waiter_does_not_cancel_native_reaping() {
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::sync_channel(1);
        let reaper = VcpuReaper::new(
            move || {
                entered.send(()).unwrap();
                released
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap();
                Ok(vec![Ok(())])
            },
            Some(Box::new(|| Ok(()))),
        );
        {
            let waiting = reaper.wait();
            tokio::pin!(waiting);
            tokio::select! {
                result = &mut waiting => panic!("reaper completed before release: {result:?}"),
                result = started => result.unwrap(),
            }
        }
        release.send(()).unwrap();
        assert_eq!(reaper.wait().await, Ok(vec![Ok(())]));
    }

    #[tokio::test]
    async fn concurrent_waiters_share_one_native_reaper_and_its_outcome() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let cancelled = Arc::new(AtomicUsize::new(0));
        let cancellation = Arc::clone(&cancelled);
        let reaper = VcpuReaper::new(
            move || {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(vec![Ok(()), Err("CPU failed".to_owned())])
            },
            Some(Box::new(move || {
                cancellation.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })),
        );
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let reaper = &reaper;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    reaper.start();
                });
            }
        });
        assert_eq!(cancelled.load(Ordering::SeqCst), 1);
        let (first, second) = tokio::join!(reaper.wait(), reaper.wait());
        assert_eq!(first, second);
        assert_eq!(reaper.wait().await, first);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(cancelled.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dropping_the_last_capability_starts_native_reaping() {
        let (stop_sender, stop_receiver) = std::sync::mpsc::channel();
        let reaper = VcpuReaper::new(
            move || {
                stop_sender.send(()).unwrap();
                Ok(vec![Ok(())])
            },
            Some(Box::new(|| Ok(()))),
        );
        drop(reaper);
        stop_receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
    }
    #[tokio::test]
    async fn a_wait_timeout_keeps_native_ownership_until_reaping_finishes() {
        let resource = Arc::new(());
        let retained = Arc::downgrade(&resource);
        let (release, released) = std::sync::mpsc::channel();
        let reaper = VcpuReaper::new(
            move || {
                released
                    .recv_timeout(std::time::Duration::from_secs(15))
                    .unwrap();
                drop(resource);
                Ok(vec![Ok(())])
            },
            Some(Box::new(|| Ok(()))),
        );
        assert_eq!(
            reaper
                .wait_until(Instant::now() + Duration::from_millis(20))
                .await,
            Err("native task timed out".to_owned())
        );
        assert!(retained.upgrade().is_some());
        release.send(()).unwrap();
        assert_eq!(reaper.wait().await, Ok(vec![Ok(())]));
        assert!(retained.upgrade().is_none());
    }
}
