//! vCPU threads for every backend: readiness, the start handoff, stop requests, and a bounded join.

use crate::vm::{BootState, VcpuHandler};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long `spawn` waits for one vCPU's setup, and `join` for every vCPU to stop.
pub(crate) const STOP_DEADLINE: Duration = Duration::from_secs(5);
const KICK_INTERVAL: Duration = Duration::from_millis(10);

type StartCommand = (Box<dyn VcpuHandler>, BootState);

/// Forces one vCPU out of guest execution or out of a backend wait, so it observes [`Stop`].
pub(crate) trait Kick: Send + Sync {
    fn kick(&self, vcpu: usize);
}

/// The stop request a group's owner and its vCPU threads share.
pub(crate) struct Stop {
    is_requested: AtomicBool,
    kick: Arc<dyn Kick>,
    vcpus: usize,
}

impl Stop {
    pub(crate) fn is_requested(&self) -> bool {
        self.is_requested.load(Ordering::Acquire)
    }

    /// Sets the request before kicking, so every kicked vCPU observes it.
    pub(crate) fn request(&self) {
        self.is_requested.store(true, Ordering::Release);
        for vcpu in 0..self.vcpus {
            self.kick.kick(vcpu);
        }
    }
}

/// A vCPU thread's side of its group's startup.
pub(crate) struct Startup {
    ready: mpsc::SyncSender<()>,
    start: mpsc::Receiver<StartCommand>,
}

impl Startup {
    /// Reports setup complete and waits for this vCPU's handler; `None` means the group
    /// stopped before starting it.
    pub(crate) fn wait(self) -> Option<StartCommand> {
        let _ = self.ready.send(());
        self.start.recv().ok()
    }
}

/// One VM's vCPU threads; dropping the group stops and joins them.
pub(crate) struct Vcpus {
    starts: Vec<mpsc::SyncSender<StartCommand>>,
    threads: Vec<JoinHandle<Result<(), String>>>,
    stop: Arc<Stop>,
    hard_stop: Option<fn() -> !>,
    running: Option<mpsc::Sender<()>>,
    finished: mpsc::Receiver<()>,
}

impl Vcpus {
    pub(crate) fn new(vcpus: usize, kick: Arc<dyn Kick>, hard_stop: Option<fn() -> !>) -> Self {
        let (running, finished) = mpsc::channel();
        Self {
            starts: Vec::with_capacity(vcpus),
            threads: Vec::with_capacity(vcpus),
            stop: Arc::new(Stop {
                is_requested: AtomicBool::new(false),
                kick,
                vcpus,
            }),
            hard_stop,
            running: Some(running),
            finished,
        }
    }

    pub(crate) fn stop(&self) -> Arc<Stop> {
        Arc::clone(&self.stop)
    }

    /// Spawns the next vCPU's thread and returns once `run` calls [`Startup::wait`], so each
    /// vCPU's setup finishes before the next one starts. `Err` carries a failed setup.
    pub(crate) fn spawn(
        &mut self,
        run: impl FnOnce(Startup) -> Result<(), String> + Send + 'static,
    ) -> Result<(), String> {
        let id = self.threads.len();
        let (ready, is_ready) = mpsc::sync_channel(0);
        let (start, starts) = mpsc::sync_channel(1);
        let startup = Startup {
            ready,
            start: starts,
        };
        let running = self.running.clone().ok_or("vCPU group already stopped")?;
        let thread = std::thread::Builder::new()
            .name(format!("vcpu-{id}"))
            .spawn(move || {
                let _running = running;
                run(startup)
            })
            .map_err(|error| format!("spawning vCPU {id}: {error}"))?;
        self.threads.push(thread);
        self.starts.push(start);
        match is_ready.recv_timeout(STOP_DEADLINE) {
            Ok(()) => Ok(()),
            Err(RecvTimeoutError::Timeout) => Err(format!("vCPU {id} setup timed out")),
            Err(RecvTimeoutError::Disconnected) => {
                self.starts.pop();
                Err(self.threads.pop().map_or_else(
                    || format!("vCPU {id} disappeared during setup"),
                    |thread| match thread.join() {
                        Ok(Err(error)) => error,
                        Ok(Ok(())) => format!("vCPU {id} exited during setup"),
                        Err(_) => format!("vCPU {id} panicked during setup"),
                    },
                ))
            }
        }
    }

    pub(crate) fn start(
        &mut self,
        boot: BootState,
        handlers: Vec<Box<dyn VcpuHandler>>,
    ) -> Result<(), String> {
        if handlers.len() != self.starts.len() {
            return Err(format!(
                "expected {} vCPU handlers, got {}",
                self.starts.len(),
                handlers.len()
            ));
        }
        for (start, handler) in self.starts.drain(..).zip(handlers) {
            start
                .send((handler, boot))
                .map_err(|_| "vCPU thread exited before start")?;
        }
        Ok(())
    }

    /// Dropping the start senders wakes vCPU threads still waiting in [`Startup::wait`].
    pub(crate) fn request_stop(&mut self) {
        self.starts.clear();
        self.stop.request();
    }

    /// Stops every vCPU and joins its thread; a repeated join returns no results. A timeout calls
    /// `hard_stop`, or else keeps the threads, and the VM state they own, for a later join.
    pub(crate) fn join(&mut self) -> Result<Vec<Result<(), String>>, String> {
        self.request_stop();
        self.running = None;
        let deadline = Instant::now() + STOP_DEADLINE;
        loop {
            match self.finished.recv_timeout(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(KICK_INTERVAL),
            ) {
                Err(RecvTimeoutError::Disconnected) => break,
                Ok(()) | Err(RecvTimeoutError::Timeout) if Instant::now() >= deadline => {
                    if let Some(hard_stop) = self.hard_stop {
                        hard_stop();
                    }
                    return Err("vCPU stop timed out".to_owned());
                }
                Ok(()) | Err(RecvTimeoutError::Timeout) => self.stop.request(),
            }
        }
        Ok(std::mem::take(&mut self.threads)
            .into_iter()
            .map(|thread| {
                thread
                    .join()
                    .map_err(|_| "vCPU thread panicked".to_owned())
                    .and_then(|outcome| outcome)
            })
            .collect())
    }
}

impl Drop for Vcpus {
    fn drop(&mut self) {
        if !self.threads.is_empty() {
            let _ = self.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{VcpuAction, VcpuExit, VcpuOutcome};
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordedKicks(Mutex<Vec<usize>>);

    impl Kick for RecordedKicks {
        fn kick(&self, vcpu: usize) {
            self.0.lock().unwrap().push(vcpu);
        }
    }

    struct NoExits;

    impl VcpuHandler for NoExits {
        fn exchange(&mut self, exit: VcpuExit) -> Result<VcpuAction, String> {
            Err(format!("unexpected exit {exit:?}"))
        }

        fn finished(&mut self, _: VcpuOutcome) {}
    }

    const BOOT: BootState = BootState {
        entry: 0,
        boot_argument: 0,
    };

    fn group(vcpus: usize) -> (Vcpus, Arc<RecordedKicks>) {
        let kicks = Arc::new(RecordedKicks::default());
        (Vcpus::new(vcpus, kicks.clone(), None), kicks)
    }

    fn spawn_until_stopped(vcpus: &mut Vcpus) {
        let stop = vcpus.stop();
        vcpus
            .spawn(move |startup| {
                if startup.wait().is_some() {
                    while !stop.is_requested() {
                        std::thread::yield_now();
                    }
                }
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn started_vcpus_run_until_join_stops_them() {
        let (mut vcpus, kicks) = group(2);
        for _ in 0..2 {
            spawn_until_stopped(&mut vcpus);
        }
        vcpus
            .start(BOOT, vec![Box::new(NoExits), Box::new(NoExits)])
            .unwrap();
        assert_eq!(vcpus.join().unwrap(), [Ok(()), Ok(())]);
        assert!(kicks.0.lock().unwrap().starts_with(&[0, 1]));
        assert_eq!(vcpus.join().unwrap(), []);
    }

    /// A prepared VM dropped before `start` must not leave its threads waiting for handlers.
    #[test]
    fn dropping_an_unstarted_group_wakes_and_joins_waiting_vcpus() {
        let (mut vcpus, _) = group(2);
        let woke = Arc::new(Mutex::new(Vec::new()));
        for _ in 0..2 {
            let woke = Arc::clone(&woke);
            vcpus
                .spawn(move |startup| {
                    let was_stopped = startup.wait().is_none();
                    woke.lock().unwrap().push(was_stopped);
                    Ok(())
                })
                .unwrap();
        }
        let started = Instant::now();
        drop(vcpus);
        assert!(started.elapsed() < STOP_DEADLINE);
        assert_eq!(*woke.lock().unwrap(), [true, true]);
    }

    #[test]
    fn setup_failures_and_panics_are_returned_before_readiness() {
        let (mut vcpus, _) = group(1);
        assert_eq!(
            vcpus.spawn(|_| Err("no vCPU".to_owned())),
            Err("no vCPU".to_owned())
        );
        assert_eq!(
            vcpus.spawn(|_| panic!("setup failed")),
            Err("vCPU 0 panicked during setup".to_owned())
        );
        assert_eq!(vcpus.join().unwrap(), []);
    }

    #[test]
    fn handler_count_must_match_the_vcpus() {
        let (mut vcpus, _) = group(1);
        spawn_until_stopped(&mut vcpus);
        assert!(vcpus.start(BOOT, Vec::new()).is_err());
    }

    #[test]
    fn a_panic_after_startup_is_a_join_result() {
        let (mut vcpus, _) = group(1);
        vcpus
            .spawn(|startup| {
                startup.wait();
                panic!("vCPU failed")
            })
            .unwrap();
        vcpus.start(BOOT, vec![Box::new(NoExits)]).unwrap();
        assert_eq!(
            vcpus.join().unwrap(),
            [Err("vCPU thread panicked".to_owned())]
        );
    }

    /// A vCPU that ignores its kicks must keep the VM state it owns until a later join reaps it.
    #[test]
    fn a_stop_timeout_keeps_the_thread_for_a_later_join() {
        let (mut vcpus, _) = group(1);
        let resource = Arc::new(());
        let resource_lifetime = Arc::downgrade(&resource);
        let release = Arc::new(AtomicBool::new(false));
        let thread_release = Arc::clone(&release);
        vcpus
            .spawn(move |startup| {
                startup.wait();
                while !thread_release.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                drop(resource);
                Ok(())
            })
            .unwrap();
        vcpus.start(BOOT, vec![Box::new(NoExits)]).unwrap();
        assert_eq!(vcpus.join(), Err("vCPU stop timed out".to_owned()));
        assert!(resource_lifetime.upgrade().is_some());
        release.store(true, Ordering::Release);
        assert_eq!(vcpus.join().unwrap(), [Ok(())]);
        assert!(resource_lifetime.upgrade().is_none());
    }
}
