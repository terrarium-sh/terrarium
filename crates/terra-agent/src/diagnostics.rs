//! The diagnostic stream to the host: boot stages and agent messages, best effort and bounded.

use std::fs::File;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use terra_protocol::control::MAX_DIAGNOSTIC_EVENT_BYTES;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const CHUNK_BYTES: usize = 4096;
const _: () = assert!(CHUNK_BYTES <= MAX_DIAGNOSTIC_EVENT_BYTES);
const QUEUE_BYTES: usize = 64 << 10;
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const FINISH_GRACE: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub(crate) struct Diagnostics {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    tasks: TaskTracker,
    cancellation: CancellationToken,
    started: Instant,
}

impl Diagnostics {
    pub(crate) fn new(writer: File) -> std::io::Result<Self> {
        let (sender, mut receiver) =
            tokio::sync::mpsc::channel::<Vec<u8>>(QUEUE_BYTES / CHUNK_BYTES);
        let mut writer = crate::into_async_file(writer)?;
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let tasks = TaskTracker::new();
        tasks.spawn(async move {
            worker_cancellation
                .run_until_cancelled(async move {
                    while let Some(bytes) = receiver.recv().await {
                        if write(&mut writer, bytes).await.is_err() {
                            break;
                        }
                    }
                })
                .await;
        });
        tasks.close();
        Ok(Self {
            sender,
            tasks,
            cancellation,
            started: Instant::now(),
        })
    }

    pub(crate) fn record(&self, bytes: &[u8]) {
        for bytes in bytes.chunks(CHUNK_BYTES) {
            if self.sender.try_send(bytes.to_vec()).is_err() {
                break;
            }
        }
    }

    pub(crate) fn record_boot_stage(&self, stage: &str) {
        self.record(
            format!(
                "terra boot_stage={stage} unix_time_ns={} agent_elapsed_ns={}\n",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
                self.started.elapsed().as_nanos()
            )
            .as_bytes(),
        );
    }

    pub(crate) async fn finish(self) {
        drop(self.sender);
        if tokio::time::timeout(FINISH_GRACE, self.tasks.wait())
            .await
            .is_err()
        {
            self.cancellation.cancel();
            self.tasks.wait().await;
        }
    }
}

pub(crate) async fn write(writer: &mut crate::AsyncFile, bytes: Vec<u8>) -> std::io::Result<()> {
    tokio::time::timeout(
        WRITE_TIMEOUT,
        terra_protocol::write_frame_async(
            writer,
            &terra_protocol::LifecycleEvent::Diagnostic { bytes },
        ),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "diagnostic write timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;
    use terra_protocol::LifecycleEvent;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn diagnostics_finish_flushes_a_queued_line() {
        let (agent, mut host) = UnixStream::pair().unwrap();
        let diagnostic = Diagnostics::new(File::from(OwnedFd::from(agent))).unwrap();
        diagnostic.record(b"queued diagnostic");
        diagnostic.finish().await;

        assert_eq!(
            terra_protocol::read_frame(&mut host).unwrap(),
            Some(LifecycleEvent::Diagnostic {
                bytes: b"queued diagnostic".to_vec()
            })
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn diagnostics_finish_bounds_a_stalled_sink() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let diagnostic = Diagnostics::new(File::from(OwnedFd::from(stream))).unwrap();
        let bytes = vec![b'x'; CHUNK_BYTES];
        let fill_until = std::time::Instant::now() + Duration::from_millis(100);
        while std::time::Instant::now() < fill_until {
            diagnostic.record(&bytes);
            tokio::task::yield_now().await;
        }
        let start = std::time::Instant::now();
        diagnostic.finish().await;
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
