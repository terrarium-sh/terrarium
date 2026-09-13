use super::machine::DeviceKind;

pub type NativeCleanup = super::reaper::NativeTask<()>;
type Outcome = Result<(), String>;

#[derive(Clone)]
pub struct DeviceShutdown {
    pub(super) kind: DeviceKind,
    cleanup: NativeCleanup,
}

impl DeviceShutdown {
    pub fn new(kind: DeviceKind, close: impl FnOnce() -> Outcome + Send + 'static) -> Self {
        Self {
            kind,
            cleanup: NativeCleanup::new(close, None),
        }
    }

    pub async fn wait(&self) -> Outcome {
        self.cleanup.wait().await
    }

    pub(crate) async fn wait_until_closed(&self) -> Outcome {
        self.cleanup.wait_until_finished().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_wasi_waiter_and_native_recovery_share_one_close_result() {
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::sync_channel(1);
        let shutdown = DeviceShutdown::new(DeviceKind::Block, move || {
            entered.send(()).unwrap();
            released
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap();
            Err("flush failed".to_owned())
        });
        {
            let waiting = shutdown.wait();
            tokio::pin!(waiting);
            tokio::select! {
                result = &mut waiting => panic!("close completed before release: {result:?}"),
                result = started => result.unwrap(),
            }
        }
        release.send(()).unwrap();
        let (first, second) = tokio::join!(shutdown.wait(), shutdown.wait());
        assert_eq!(first, Err("flush failed".to_owned()));
        assert_eq!(second, first);
    }

    #[test]
    fn dropping_the_last_capability_starts_native_cleanup() {
        let (close_sender, close_receiver) = std::sync::mpsc::channel();
        let cleanup = NativeCleanup::new(
            move || {
                close_sender.send(()).unwrap();
                Ok(())
            },
            None,
        );
        drop(cleanup);
        close_receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
    }
}
