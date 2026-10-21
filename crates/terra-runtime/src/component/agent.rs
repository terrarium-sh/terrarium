//! Agent sessions over the fixed vsock endpoint.

mod bindings;
mod host;

use crate::component::relay;
use crate::component::vsock::streams::StreamEndpoint;
use futures_util::{
    FutureExt,
    future::{BoxFuture, Shared},
};

use crate::component::vmm::lifecycle::LifecycleNotifier;
use bindings::AgentBindings;
pub use bindings::AgentEvent;
pub use host::{AgentHost, AgentHostService, agent_component_linker};
use std::{
    io::Write,
    num::NonZeroUsize,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use terra_platform::local_socket::{LocalListener as UnixListener, LocalStream as UnixStream};

#[cfg(test)]
const MAX_DIAGNOSTIC_FILE_BYTES: u64 = terra_limits::MAX_LOG_FILE_BYTES;
const MAX_DIAGNOSTIC_BATCH_BYTES: usize = 65536;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

struct DiagnosticSink {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    finished: tokio::sync::oneshot::Receiver<std::io::Result<()>>,
}

impl DiagnosticSink {
    fn new(mut output: std::fs::File) -> std::io::Result<Self> {
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
        let (done, finished) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("guest-diagnostics".into())
            .spawn(move || {
                let result = std::iter::from_fn(|| receiver.blocking_recv())
                    .try_for_each(|bytes| {
                        terra_platform::filesystem::append_capped(
                            &mut output,
                            &bytes,
                            terra_limits::MAX_LOG_FILE_BYTES,
                        )
                    })
                    .and_then(|()| output.flush());
                let _ = done.send(result);
            })?;
        Ok(Self { sender, finished })
    }

    async fn finish(self) -> std::io::Result<()> {
        drop(self.sender);
        self.finished.await.map_err(std::io::Error::other)?
    }
}

async fn deliver_events(
    mut events: relay::Stream<AgentEvent>,
    lifecycle: LifecycleNotifier,
    diagnostics: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
) -> wasmtime::Result<()> {
    while let Some(event) = events.next().await {
        match event {
            AgentEvent::Connected => {
                log::info!(
                    "terra boot_stage=agent_connected unix_time_ns={}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                );
            }
            AgentEvent::Disconnected => lifecycle.agent_disconnected(),
            AgentEvent::Diagnostic(bytes) => {
                wasmtime::ensure!(
                    bytes.len() <= MAX_DIAGNOSTIC_BATCH_BYTES,
                    "agent diagnostic event limit"
                );
                if let Some(diagnostics) = &diagnostics {
                    diagnostics.send(bytes).await?;
                }
            }
            AgentEvent::AgentReady => lifecycle.agent_ready(),
            AgentEvent::Exit(code) => lifecycle.guest_exit(code),
        }
    }
    Ok(())
}

#[derive(Clone)]
pub struct Agent {
    close: Shared<BoxFuture<'static, Result<(), String>>>,
    failure: Arc<std::sync::Mutex<Option<String>>>,
}

struct AgentWorkerGrant {
    component: wasmtime::component::Component,
    endpoint: StreamEndpoint,
    plan: Vec<u8>,
    listener: Option<UnixListener>,
    control: Option<UnixStream>,
    diagnostics: Option<std::fs::File>,
    closing: Arc<AtomicBool>,
    close_notification: Arc<tokio::sync::Notify>,
    lifecycle: LifecycleNotifier,
    failure: Arc<std::sync::Mutex<Option<String>>>,
    completion: tokio::sync::oneshot::Sender<wasmtime::Result<()>>,
}

impl AgentWorkerGrant {
    async fn create(
        self,
        child: impl FnOnce(AgentHost) -> crate::box_runtime::DeviceWorker<AgentHost>,
    ) -> wasmtime::Result<(crate::box_runtime::DeviceWorker<AgentHost>, ())> {
        let host = AgentHost::new(
            self.endpoint,
            host::AgentHostService::new(&self.plan, self.listener, self.control)?,
        );
        let mut child = child(host);
        let linker = host::agent_component_linker(child.store.engine())?;
        let instance = AgentBindings::instantiate_async(&mut child.store, &self.component, &linker)
            .await
            .map_err(|error| error.context("agent component initialization"))?;
        let api = instance.terra_agent_api();
        let close = api.func_close();
        let diagnostics = self.diagnostics.map(DiagnosticSink::new).transpose()?;
        let (event_stream,) = api
            .func_events()
            .call_async(&mut child.store, ())
            .await
            .map_err(|error| error.context("agent component event stream"))?;
        let (event_sink, events) = relay::channel(NonZeroUsize::MIN);
        event_stream.pipe(&mut child.store, event_sink)?;
        let delivery = deliver_events(
            events,
            self.lifecycle,
            diagnostics.as_ref().map(|sink| sink.sender.clone()),
        );
        child.register_loop(Box::new(move |accessor| {
            Box::pin(async move {
                let result = async {
                    tokio::pin!(delivery);
                    tokio::select! {
                        result = &mut delivery => result?,
                        () = self.close_notification.notified() => {
                            tokio::try_join!(close.call_concurrent(accessor, ()), &mut delivery)?;
                        },
                    }
                    wasmtime::ensure!(
                        self.closing.load(Ordering::Acquire),
                        "agent worker disconnected"
                    );
                    Ok(())
                }
                .await;
                let flushed = match diagnostics {
                    Some(sink) => sink.finish().await.map_err(wasmtime::Error::from),
                    None => Ok(()),
                };
                let result = flushed.and(result);
                let failure = result
                    .as_ref()
                    .err()
                    .map(|error| format!("agent component: {error:#}"));
                self.failure
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone_from(&failure);
                let _ = self.completion.send(result);
                failure.map_or(Ok(()), |error| Err(wasmtime::Error::msg(error)))
            })
        }))?;
        Ok((child, ()))
    }
}

impl Agent {
    pub fn from_trusted_artifact(
        runtime: &mut crate::box_runtime::BoxRuntime,
        endpoint: StreamEndpoint,
        artifact: crate::TrustedArtifact,
        plan: Vec<u8>,
        listener: Option<UnixListener>,
        control: Option<UnixStream>,
        diagnostics: Option<std::fs::File>,
    ) -> wasmtime::Result<Self> {
        let shared_closing = Arc::new(AtomicBool::new(false));
        let close_notification = Arc::new(tokio::sync::Notify::new());
        let failure = Arc::new(std::sync::Mutex::new(None));
        let (completion, close_response) = tokio::sync::oneshot::channel();
        let setup = AgentWorkerGrant {
            component: artifact.deserialize(runtime.store.engine())?,
            endpoint,
            plan,
            listener,
            control,
            diagnostics,
            closing: Arc::clone(&shared_closing),
            close_notification: Arc::clone(&close_notification),
            lifecycle: runtime.lifecycle_notifier(),
            failure: Arc::clone(&failure),
            completion,
        };
        let child = runtime.child_factory();
        runtime.grant_agent_worker_unmanaged(async move { setup.create(child).await })?;
        let close = async move {
            shared_closing.store(true, Ordering::Release);
            close_notification.notify_one();
            tokio::time::timeout(RESPONSE_TIMEOUT, close_response)
                .await
                .map_err(|error| format!("agent component response: {error}"))?
                .map_err(|error| format!("agent component response: {error}"))?
                .map_err(|error| error.to_string())
        }
        .boxed()
        .shared();
        runtime.add_agent_shutdown(close.clone())?;
        Ok(Self { close, failure })
    }

    #[must_use]
    pub fn failure(&self) -> Option<String> {
        crate::component::recorded_failure(&self.failure).or_else(|| {
            self.close
                .peek()
                .and_then(|result| result.as_ref().err().cloned())
        })
    }

    pub async fn close_async(&self) -> wasmtime::Result<()> {
        self.close.clone().await.map_err(wasmtime::Error::msg)
    }
}

#[cfg(feature = "test-support")]
#[must_use]
pub fn enrich_boot_plan_for_fuzzing(bytes: &[u8]) -> Option<Vec<u8>> {
    host::enrich_plan_with_host_state(bytes, 0, 0, [0; 32]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    fn boot_plan() -> Vec<u8> {
        terra_protocol::encode_frame(&terra_protocol::BootPlan::new(
            terra_protocol::Plan::bare_run(vec!["/bin/sh".into()]),
        ))
        .expect("plan encodes")
    }

    #[test]
    fn diagnostic_finish_flushes_output_with_the_blocking_pool_occupied() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let (entered, started) = tokio::sync::oneshot::channel();
            let (release, blocked) = std::sync::mpsc::channel();
            let occupied_pool = tokio::task::spawn_blocking(move || {
                entered.send(()).unwrap();
                let _ = blocked.recv_timeout(Duration::from_secs(5));
            });
            started.await.unwrap();
            let output = tempfile::NamedTempFile::new().unwrap();
            let sink = DiagnosticSink::new(output.reopen().unwrap()).unwrap();
            sink.sender
                .send(b"failed bake output\n".to_vec())
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), sink.finish())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                std::fs::read(output.path()).unwrap(),
                b"failed bake output\n"
            );
            release.send(()).unwrap();
            occupied_pool.await.unwrap();
        });
    }

    #[tokio::test]
    async fn diagnostic_flood_drains_after_reaching_file_limit() {
        let output = tempfile::NamedTempFile::new().unwrap();
        let sink = DiagnosticSink::new(output.reopen().unwrap()).unwrap();
        for _ in 0..=(MAX_DIAGNOSTIC_FILE_BYTES / 4096) {
            sink.sender.send(vec![b'x'; 4096]).await.unwrap();
        }
        sink.finish().await.unwrap();
        assert_eq!(
            output.as_file().metadata().unwrap().len(),
            MAX_DIAGNOSTIC_FILE_BYTES
        );
    }

    #[tokio::test]
    async fn restarting_diagnostics_does_not_reset_the_file_budget() {
        let output = tempfile::NamedTempFile::new().unwrap();
        output
            .as_file()
            .set_len(MAX_DIAGNOSTIC_FILE_BYTES - 1)
            .unwrap();
        for _ in 0..2 {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .append(true)
                .open(output.path())
                .unwrap();
            let sink = DiagnosticSink::new(file).unwrap();
            sink.sender.send(vec![b'x'; 4096]).await.unwrap();
            sink.finish().await.unwrap();
        }
        assert_eq!(
            output.as_file().metadata().unwrap().len(),
            MAX_DIAGNOSTIC_FILE_BYTES
        );
    }

    /// Pipes `events` through a component stream, as the agent's event export does, into [`deliver_events`].
    async fn deliver(
        events: Vec<AgentEvent>,
        lifecycle: LifecycleNotifier,
        diagnostics: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    ) -> wasmtime::Result<()> {
        let engine = crate::engine::device_engine()?;
        let mut store = crate::engine::device_store(&engine, ());
        let (event_sink, stream) = relay::channel(NonZeroUsize::MIN);
        wasmtime::component::StreamReader::new(&mut store, events)?.pipe(&mut store, event_sink)?;
        store
            .run_concurrent(async |_| deliver_events(stream, lifecycle, diagnostics).await)
            .await?
    }

    #[tokio::test]
    async fn typed_events_update_the_bounded_native_observers() {
        let lifecycle = crate::component::vmm::lifecycle::LifecycleHost::new();
        deliver(vec![AgentEvent::Exit(7)], lifecycle.notifier(), None)
            .await
            .unwrap();
        let event = tokio::time::timeout(Duration::from_secs(1), lifecycle.next_event())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_matches!(
            event,
            crate::component::vmm::lifecycle::lifecycle_platform::Event::GuestExit(7)
        );
    }

    #[tokio::test]
    async fn diagnostic_backpressure_retains_bytes_and_resumes_readiness_and_exit() {
        let lifecycle = crate::component::vmm::lifecycle::LifecycleHost::new();
        let (diagnostic_sender, mut diagnostic_receiver) = tokio::sync::mpsc::channel(1);
        diagnostic_sender
            .try_send(vec![0])
            .expect("diagnostic queue fills");
        let delivery = deliver(
            vec![
                AgentEvent::Diagnostic(b"slow disk\n".to_vec()),
                AgentEvent::AgentReady,
                AgentEvent::Exit(9),
            ],
            lifecycle.notifier(),
            Some(diagnostic_sender),
        );
        let observer = async {
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
            assert!(!lifecycle.notifier().is_agent_ready());
            assert_eq!(diagnostic_receiver.recv().await.unwrap(), [0]);
            assert_eq!(diagnostic_receiver.recv().await.unwrap(), b"slow disk\n");
            let event = tokio::time::timeout(Duration::from_secs(1), lifecycle.next_event())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_matches!(
                event,
                crate::component::vmm::lifecycle::lifecycle_platform::Event::GuestExit(9)
            );
        };
        let (delivered, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(delivery, observer)
        })
        .await
        .unwrap();
        delivered.unwrap();
        assert!(lifecycle.notifier().is_agent_ready());
    }

    #[tokio::test]
    async fn connection_loss_clears_readiness_before_failure() {
        let lifecycle = crate::component::vmm::lifecycle::LifecycleHost::new();
        lifecycle.notifier().agent_ready();
        deliver(vec![AgentEvent::Disconnected], lifecycle.notifier(), None)
            .await
            .unwrap();
        assert!(!lifecycle.notifier().is_agent_ready());
    }

    #[tokio::test]
    async fn oversized_diagnostics_fail_before_enqueueing() {
        let (diagnostic_sender, mut diagnostic_receiver) = tokio::sync::mpsc::channel(1);
        let oversized = AgentEvent::Diagnostic(vec![0; MAX_DIAGNOSTIC_BATCH_BYTES + 1]);
        let lifecycle = crate::component::vmm::lifecycle::LifecycleHost::new();
        assert!(
            deliver(
                vec![oversized],
                lifecycle.notifier(),
                Some(diagnostic_sender)
            )
            .await
            .is_err()
        );
        assert!(diagnostic_receiver.try_recv().is_err());
    }

    #[test]
    fn agent_runs_in_a_store_without_guest_memory_or_device_imports() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let engine = crate::engine::device_engine().unwrap();
            let mut runtime = crate::box_runtime::BoxRuntime::new(
                &engine,
                crate::box_runtime::store::BoxHost::new(),
            )
            .unwrap();
            let agent = Agent::from_trusted_artifact(
                &mut runtime,
                StreamEndpoint::new(),
                crate::test_fixtures::trusted_artifacts().agent,
                boot_plan(),
                None,
                None,
                None,
            )
            .unwrap();
            let (finished, finish) = tokio::sync::oneshot::channel();
            runtime
                .register_loop(Box::new(move |_| {
                    Box::pin(async move {
                        finish.await.map_err(wasmtime::Error::from)?;
                        Ok(())
                    })
                }))
                .unwrap();
            let runtime_task = runtime.prepare().await.unwrap().start();
            let mut cancelled = Box::pin(agent.close_async());
            assert!(futures_util::poll!(&mut cancelled).is_pending());
            drop(cancelled);
            let peer = agent.clone();
            let (first, second) = tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(agent.close_async(), peer.close_async())
            })
            .await
            .unwrap();
            first.unwrap();
            second.unwrap();
            agent.close_async().await.unwrap();
            finished.send(()).unwrap();
            runtime_task.join().await.unwrap();
        });
    }
}
