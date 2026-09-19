use std::fs::File;
use std::time::Duration;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub(super) const CHUNK_BYTES: usize = 4096;
const QUEUE_BYTES: usize = 64 << 10;
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub(super) struct Diagnostics {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    tasks: TaskTracker,
    cancellation: CancellationToken,
}

impl Diagnostics {
    pub(super) fn new(writer: File) -> std::io::Result<Self> {
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
                        if write(&mut writer, &bytes).await.is_err() {
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
        })
    }

    pub(super) fn record(&self, bytes: &[u8]) {
        for bytes in bytes.chunks(CHUNK_BYTES) {
            if self.sender.try_send(bytes.to_vec()).is_err() {
                break;
            }
        }
    }

    pub(super) async fn finish(self) {
        let Self {
            sender,
            tasks,
            cancellation,
        } = self;
        drop(sender);
        if tokio::time::timeout(Duration::from_secs(1), tasks.wait())
            .await
            .is_err()
        {
            cancellation.cancel();
            tasks.wait().await;
        }
    }
}

pub(super) async fn write(writer: &mut crate::AsyncFile, bytes: &[u8]) -> std::io::Result<()> {
    let bytes = bytes[..bytes
        .len()
        .min(terra_protocol::control::MAX_DIAGNOSTIC_EVENT_BYTES)]
        .to_vec();
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
    use crate::diagnostics::{CHUNK_BYTES as DIAGNOSTIC_CHUNK_BYTES, Diagnostics};
    use crate::hooks::run;
    use std::time::Duration;
    use tokio_util::{sync::CancellationToken, task::TaskTracker};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn flood_does_not_block_hook_completion() {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        sender.send(vec![b'x']).await.unwrap();
        let diagnostic = Diagnostics {
            sender,
            tasks: TaskTracker::new(),
            cancellation: CancellationToken::new(),
        };
        run(
            "dd if=/dev/zero bs=4096 count=512 2>/dev/null",
            Some(Duration::from_secs(2)),
            Some(&diagnostic),
            None,
            &CancellationToken::new(),
        )
        .await
        .expect("hook exits despite a full diagnostic queue");
    }
    use std::fs::File;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
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
        let bytes = vec![b'x'; DIAGNOSTIC_CHUNK_BYTES];
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
