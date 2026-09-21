use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use terra_runtime::component::vmm::virtualization::StartedVcpus;

const STOP_DEADLINE: Duration = Duration::from_secs(5);

pub(super) struct VcpuGroup {
    pub(super) partition: Arc<crate::windows::whp::Partition>,
    pub(super) stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<Result<(), String>>>,
    hard_stop: Option<fn() -> !>,
    pub(super) on_stop: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl VcpuGroup {
    pub(super) fn new(
        partition: Arc<crate::windows::whp::Partition>,
        hard_stop: Option<fn() -> !>,
    ) -> Self {
        Self {
            partition,
            stop: Arc::new(AtomicBool::new(false)),
            threads: Vec::new(),
            hard_stop,
            on_stop: None,
        }
    }

    pub(super) fn into_started(self) -> StartedVcpus {
        let partition = Arc::clone(&self.partition);
        let stop = Arc::clone(&self.stop);
        let on_stop = self.on_stop.clone();
        let count = self.threads.len();
        StartedVcpus::new(
            self,
            move || {
                stop.store(true, Ordering::Relaxed);
                if let Some(on_stop) = on_stop {
                    on_stop();
                }
                for id in (0_u32..).take(count) {
                    let _ = partition.cancel_vcpu(id);
                }
                Ok(())
            },
            |mut group| group.stop(),
        )
    }

    pub(super) fn spawn(
        &mut self,
        run: impl FnOnce() -> Result<(), String> + Send + 'static,
    ) -> Result<(), String> {
        self.threads.push(
            std::thread::Builder::new()
                .spawn(move || {
                    run().inspect_err(|error| log::error!("Windows vCPU failed: {error}"))
                })
                .map_err(|error| error.to_string())?,
        );
        Ok(())
    }

    fn stop(&mut self) -> Result<Vec<Result<(), String>>, String> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(on_stop) = &self.on_stop {
            on_stop();
        }
        let threads = std::mem::take(&mut self.threads);
        let deadline = Instant::now() + STOP_DEADLINE;
        loop {
            for (id, thread) in (0_u32..).zip(&threads) {
                if !thread.is_finished() {
                    let _ = self.partition.cancel_vcpu(id);
                }
            }
            if threads.iter().all(std::thread::JoinHandle::is_finished) {
                break;
            }
            if Instant::now() >= deadline {
                if let Some(hard_stop) = self.hard_stop {
                    hard_stop();
                }
                return Err("Windows vCPU stop timed out".to_owned());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(threads
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

impl Drop for VcpuGroup {
    fn drop(&mut self) {
        if !self.threads.is_empty() {
            let _ = self.stop();
        }
    }
}
