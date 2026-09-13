use std::sync::{Arc, Mutex};

use tokio::sync::watch;

pub type VcpuReaper = NativeTask<Vec<Result<(), String>>>;
type Outcome<O> = Result<O, String>;
type Cancel = Box<dyn FnOnce() -> wasmtime::Result<()> + Send>;
type Stop<O> = Box<dyn FnOnce() -> Outcome<O> + Send>;
type Pending<O> = Option<(Stop<O>, watch::Sender<Option<Outcome<O>>>)>;

struct TaskState<O: Clone + Send + Sync + 'static> {
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
    if pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_none()
    {
        return;
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
    fn start(&self) {
        start(&self.pending, &self.cancel);
    }
}

impl<O: Clone + Send + Sync + 'static> Drop for TaskState<O> {
    fn drop(&mut self) {
        self.start();
    }
}

impl<O: Clone + Send + Sync + 'static> NativeTask<O> {
    pub fn new(stop: impl FnOnce() -> Outcome<O> + Send + 'static, cancel: Option<Cancel>) -> Self {
        let (sender, outcome) = watch::channel(None);
        Self {
            state: Arc::new(TaskState {
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

    fn start(&self) {
        self.state.start();
    }

    async fn wait_for_outcome(&self) -> Outcome<O> {
        self.start();
        let mut receiver = self.outcome.clone();
        if let Some(outcome) = receiver.borrow_and_update().clone() {
            return outcome;
        }
        receiver
            .changed()
            .await
            .map_err(|_| "native task stopped without an outcome".to_owned())?;
        receiver
            .borrow_and_update()
            .clone()
            .ok_or_else(|| "native task outcome missing".to_owned())?
    }

    pub async fn wait(&self) -> Outcome<O> {
        tokio::time::timeout(std::time::Duration::from_secs(10), self.wait_for_outcome())
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
        reaper.start();
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
        assert_eq!(reaper.wait().await, Err("native task timed out".to_owned()));
        assert!(retained.upgrade().is_some());
        release.send(()).unwrap();
        assert_eq!(reaper.wait().await, Ok(vec![Ok(())]));
        assert!(retained.upgrade().is_none());
    }
}
