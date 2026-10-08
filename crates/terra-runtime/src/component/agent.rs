//! Agent sessions over the fixed vsock endpoint.

mod bindings;
mod host;

use crate::box_runtime::ComponentRole;
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
    pin::Pin,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use terra_platform::io::local::{LocalListener as UnixListener, LocalStream as UnixStream};
#[cfg(test)]
use wasmtime::Store;
use wasmtime::StoreContextMut;
use wasmtime::component::{Source, StreamConsumer, StreamResult};

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
                        terra_platform::io::log::write_capped(
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

struct EventSink {
    diagnostic_sender: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    lifecycle: LifecycleNotifier,
    pending_diagnostic: Option<BoxFuture<'static, wasmtime::Result<()>>>,
    ended: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for EventSink {
    fn drop(&mut self) {
        if let Some(ended) = self.ended.take() {
            let _ = ended.send(());
        }
    }
}

impl<H: 'static> StreamConsumer<H> for EventSink {
    type Item = AgentEvent;

    fn poll_consume(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        store: StoreContextMut<H>,
        source: Source<'_, Self::Item>,
        finish: bool,
    ) -> std::task::Poll<wasmtime::Result<StreamResult>> {
        if let Some(pending) = self.pending_diagnostic.as_mut() {
            std::task::ready!(pending.as_mut().poll(context))?;
            self.pending_diagnostic = None;
            return std::task::Poll::Ready(Ok(StreamResult::Completed));
        }
        if finish {
            return std::task::Poll::Ready(Ok(StreamResult::Cancelled));
        }
        let mut source = source;
        let mut events = Vec::with_capacity(1);
        source.read(store, &mut events)?;
        let Some(event) = events.pop() else {
            return std::task::Poll::Ready(Ok(StreamResult::Completed));
        };
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
            AgentEvent::Disconnected => self.lifecycle.agent_disconnected(),
            AgentEvent::Diagnostic(bytes) => {
                if bytes.len() > MAX_DIAGNOSTIC_BATCH_BYTES {
                    return std::task::Poll::Ready(Err(wasmtime::Error::msg(
                        "agent diagnostic event limit",
                    )));
                }
                let Some(sender) = &self.diagnostic_sender else {
                    return std::task::Poll::Ready(Ok(StreamResult::Completed));
                };
                let sender = sender.clone();
                let mut pending =
                    async move { sender.send(bytes).await.map_err(wasmtime::Error::from) }.boxed();
                match pending.as_mut().poll(context) {
                    std::task::Poll::Ready(result) => result?,
                    std::task::Poll::Pending => {
                        self.pending_diagnostic = Some(pending);
                        return std::task::Poll::Pending;
                    }
                }
            }
            AgentEvent::AgentReady => self.lifecycle.agent_ready(),
            AgentEvent::Exit(code) => {
                self.lifecycle.guest_exit(code);
            }
        }
        std::task::Poll::Ready(Ok(StreamResult::Completed))
    }
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
        let (events,) = api
            .func_events()
            .call_async(&mut child.store, ())
            .await
            .map_err(|error| error.context("agent component event stream"))?;
        let (ended, stream_end) = tokio::sync::oneshot::channel();
        events.pipe(
            &mut child.store,
            EventSink {
                diagnostic_sender: diagnostics.as_ref().map(|sink| sink.sender.clone()),
                lifecycle: self.lifecycle,
                pending_diagnostic: None,
                ended: Some(ended),
            },
        )?;
        child.register_loop(Box::new(move |accessor| {
            Box::pin(async move {
                let result = async {
                    tokio::pin!(stream_end);
                    tokio::select! {
                        _ = &mut stream_end => {},
                        () = self.close_notification.notified() => {
                            close.call_concurrent(accessor, ()).await?;
                            stream_end.await?;
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
                let result = result.and(flushed);
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
    #[allow(clippy::too_many_arguments)]
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
        runtime.grant_role_worker_unmanaged(ComponentRole::Agent, async move {
            setup.create(child).await
        })?;
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
        runtime.add_role_shutdown(ComponentRole::Agent, close.clone())?;
        Ok(Self { close, failure })
    }

    #[must_use]
    pub fn failure(&self) -> Option<String> {
        self.failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .or_else(|| {
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
    use std::collections::BTreeMap;

    fn boot_plan() -> Vec<u8> {
        terra_protocol::encode_frame(&terra_protocol::BootPlan::new(terra_protocol::Plan {
            mode: terra_protocol::PlanMode::Run,
            workdir: None,
            shares: Vec::new(),
            volumes: Vec::new(),
            net: terra_protocol::Net::Tsi,
            published_ports: Vec::new(),
            published_udp_ports: Vec::new(),
            env: BTreeMap::new(),
            root: false,
            sudo: Vec::new(),
            on_create: Vec::new(),
            on_start: Vec::new(),
            pre_stop: Vec::new(),
            daemons: Vec::new(),
            workload: vec!["/bin/sh".into()],
            sandbox_info: String::new(),
            await_initial_session: false,
            host_tz: None,
            host_time: None,
            host_seed: None,
        }))
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

    #[tokio::test]
    async fn typed_events_update_the_bounded_native_observers() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut store = Store::new(&engine, ());
        let lifecycle = crate::component::vmm::lifecycle::LifecycleHost::new();
        let events = wasmtime::component::StreamReader::new(&mut store, vec![AgentEvent::Exit(7)])
            .expect("event stream");
        events
            .pipe(
                &mut store,
                EventSink {
                    lifecycle: lifecycle.notifier(),
                    diagnostic_sender: None,
                    pending_diagnostic: None,
                    ended: None,
                },
            )
            .expect("event sink");
        store
            .run_concurrent(async |_| {
                let event = tokio::time::timeout(Duration::from_secs(1), lifecycle.next_event())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert!(matches!(
                    event,
                    crate::component::vmm::lifecycle::lifecycle_platform::Event::GuestExit(7)
                ));
            })
            .await
            .expect("event stream runs");
    }

    #[tokio::test]
    async fn diagnostic_backpressure_retains_bytes_and_resumes_readiness_and_exit() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut store = Store::new(&engine, ());
        let lifecycle = crate::component::vmm::lifecycle::LifecycleHost::new();
        let (diagnostic_sender, mut diagnostic_receiver) = tokio::sync::mpsc::channel(1);
        diagnostic_sender
            .try_send(vec![0])
            .expect("diagnostic queue fills");
        let (ended, stream_end) = tokio::sync::oneshot::channel();
        let events = wasmtime::component::StreamReader::new(
            &mut store,
            vec![
                AgentEvent::Diagnostic(b"slow disk\n".to_vec()),
                AgentEvent::AgentReady,
                AgentEvent::Exit(9),
            ],
        )
        .expect("event stream");
        events
            .pipe(
                &mut store,
                EventSink {
                    lifecycle: lifecycle.notifier(),
                    diagnostic_sender: Some(diagnostic_sender),
                    pending_diagnostic: None,
                    ended: Some(ended),
                },
            )
            .expect("event sink");
        store
            .run_concurrent(async |_| {
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
                assert!(matches!(
                    event,
                    crate::component::vmm::lifecycle::lifecycle_platform::Event::GuestExit(9)
                ));
                assert!(lifecycle.notifier().is_agent_ready());
                tokio::time::timeout(Duration::from_secs(1), stream_end)
                    .await
                    .unwrap()
                    .unwrap();
            })
            .await
            .expect("event stream runs");
    }

    #[tokio::test]
    async fn connection_loss_clears_readiness_before_failure() {
        let engine = crate::engine::device_engine().unwrap();
        let mut store = Store::new(&engine, ());
        let lifecycle = crate::component::vmm::lifecycle::LifecycleHost::new();
        lifecycle.notifier().agent_ready();
        let events =
            wasmtime::component::StreamReader::new(&mut store, vec![AgentEvent::Disconnected])
                .unwrap();
        events
            .pipe(
                &mut store,
                EventSink {
                    lifecycle: lifecycle.notifier(),
                    diagnostic_sender: None,
                    pending_diagnostic: None,
                    ended: None,
                },
            )
            .unwrap();
        store
            .run_concurrent(async |_| {
                tokio::time::timeout(Duration::from_secs(1), async {
                    while lifecycle.notifier().is_agent_ready() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
            })
            .await
            .unwrap();
        assert!(!lifecycle.notifier().is_agent_ready());
    }

    #[tokio::test]
    async fn oversized_diagnostics_fail_before_enqueueing() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut store = Store::new(&engine, ());
        let (diagnostic_sender, mut diagnostic_receiver) = tokio::sync::mpsc::channel(1);
        let events = wasmtime::component::StreamReader::new(
            &mut store,
            vec![AgentEvent::Diagnostic(vec![
                0;
                MAX_DIAGNOSTIC_BATCH_BYTES + 1
            ])],
        )
        .expect("event stream");
        events
            .pipe(
                &mut store,
                EventSink {
                    lifecycle: crate::component::vmm::lifecycle::LifecycleHost::new().notifier(),
                    diagnostic_sender: Some(diagnostic_sender),
                    pending_diagnostic: None,
                    ended: None,
                },
            )
            .expect("event sink");
        assert!(
            store
                .run_concurrent(async |_| {
                    for _ in 0..1024 {
                        tokio::task::yield_now().await;
                    }
                })
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
                crate::test_fixtures::trusted_artifacts().agent(),
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
