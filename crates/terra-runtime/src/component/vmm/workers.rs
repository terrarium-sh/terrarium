use std::future::Future;
use std::pin::Pin;

use wasmtime::component::StreamReader;

use crate::box_runtime::{DeviceWorker, StoreHost, WorkerTask};
use crate::component::relay;
use crate::component::vmm::mmio::{Reply, Request, Serve};

pub(crate) const SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) type Setup = Box<
    dyn FnOnce(
            relay::Stream<Request>,
        ) -> Pin<Box<dyn Future<Output = wasmtime::Result<PreparedWorker>> + Send>>
        + Send,
>;

pub(crate) struct PreparedWorker {
    pub worker: WorkerTask,
    pub replies: relay::Stream<Reply>,
}

impl crate::box_runtime::BoxRuntime {
    pub(crate) fn grant_device_worker<H: StoreHost>(
        &mut self,
        kind: super::machine::DeviceKind,
        initialize: impl Future<Output = wasmtime::Result<(DeviceWorker<H>, Serve)>> + Send + 'static,
    ) -> wasmtime::Result<super::mmio::MmioDevice> {
        let setup = setup(initialize, self.shutdown_receiver());
        super::mmio::MmioDevice::grant_worker(self, kind, setup)
    }
}

pub(crate) fn setup<H: StoreHost>(
    initialize: impl Future<Output = wasmtime::Result<(DeviceWorker<H>, Serve)>> + Send + 'static,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Setup {
    Box::new(move |requests| {
        Box::pin(async move {
            let (mut worker, serve) = initialize.await?;
            let requests = StreamReader::new(&mut worker.store, requests)?;
            let (reply_reader,) = serve.call_async(&mut worker.store, (requests,)).await?;
            let (sink, replies) = relay::channel(relay::MMIO_CAPACITY);
            reply_reader.pipe(&mut worker.store, sink)?;
            Ok(PreparedWorker {
                worker: worker.prepare(shutdown),
                replies,
            })
        })
    })
}

pub(crate) async fn within_setup_timeout<T>(
    slot: u32,
    operation: impl Future<Output = wasmtime::Result<T>>,
) -> wasmtime::Result<T> {
    tokio::time::timeout(SETUP_TIMEOUT, operation)
        .await
        .map_err(|_| wasmtime::Error::msg(format!("worker {slot} setup timed out")))?
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
    async fn setup_stays_lazy_and_timeout_cancels_preparation() {
        let (dropped, stopped) = tokio::sync::oneshot::channel();
        let (started, mut started_receiver) = tokio::sync::oneshot::channel();
        let setup = setup(
            async move {
                started.send(()).unwrap();
                let _guard = NotifyDrop(Some(dropped));
                std::future::pending::<
                    wasmtime::Result<(DeviceWorker<crate::engine::DeviceContext>, Serve)>,
                >()
                .await
            },
            tokio::sync::watch::channel(false).1,
        );
        assert_eq!(
            started_receiver.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        );
        let Err(error) = within_setup_timeout(3, async {
            let (_sink, requests) = relay::channel(relay::MMIO_CAPACITY);
            setup(requests).await
        })
        .await
        else {
            panic!("worker preparation completed");
        };
        assert_eq!(error.to_string(), "worker 3 setup timed out");
        started_receiver.await.unwrap();
        stopped.await.unwrap();
    }
}
