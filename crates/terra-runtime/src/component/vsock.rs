//! Native control streams for the compartmentalized vsock device.

pub mod host;
#[cfg(any(test, feature = "test-support"))]
pub mod protocol;

use futures_util::{
    FutureExt,
    future::{BoxFuture, Shared},
};

use crate::box_runtime::StoreState;
use crate::component::vmm::lifecycle::LifecycleNotifier;
use crate::component::vmm::virtualization::RamGrant;
use host::VsockDeviceHost;
use host::{VsockBindings, VsockError, VsockEvent};
use std::{
    io::Write,
    pin::Pin,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use terra_io::local::{LocalListener as UnixListener, LocalStream as UnixStream};
#[cfg(test)]
use wasmtime::Store;
use wasmtime::StoreContextMut;
use wasmtime::component::{Accessor, Source, StreamConsumer, StreamResult};

#[cfg(test)]
const MAX_DIAGNOSTIC_FILE_BYTES: usize = terra_io::log::MAX_LOG_FILE_BYTES;
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
                    .try_for_each(|bytes| terra_io::log::write_capped(&mut output, &bytes))
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
}

impl<H: 'static> StreamConsumer<H> for EventSink {
    type Item = VsockEvent;

    fn poll_consume(
        self: Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
        store: StoreContextMut<H>,
        source: Source<'_, Self::Item>,
        finish: bool,
    ) -> std::task::Poll<wasmtime::Result<StreamResult>> {
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
            VsockEvent::Diagnostic(bytes) => {
                if bytes.len() > MAX_DIAGNOSTIC_BATCH_BYTES {
                    return std::task::Poll::Ready(Err(wasmtime::Error::msg(
                        "vsock diagnostic event limit",
                    )));
                }
                let Some(sender) = &self.diagnostic_sender else {
                    return std::task::Poll::Ready(Ok(StreamResult::Completed));
                };
                let _ = sender.try_send(bytes);
            }
            VsockEvent::Exit(code) => {
                self.lifecycle.guest_exit(code);
            }
        }
        std::task::Poll::Ready(Ok(StreamResult::Completed))
    }
}

#[derive(Clone)]
pub struct VsockChannel {
    close: Shared<BoxFuture<'static, Result<(), String>>>,
    mmio: crate::component::vmm::mmio::MmioDevice,
}

struct VsockWorkerGrant {
    component: wasmtime::component::Component,
    plan: Vec<u8>,
    listener: Option<UnixListener>,
    control: Option<UnixStream>,
    diagnostics: Option<std::fs::File>,
    interrupt: crate::component::Interrupt,
    ram: RamGrant,
    closing: Arc<AtomicBool>,
    lifecycle: crate::component::vmm::lifecycle::LifecycleNotifier,
    completion: tokio::sync::oneshot::Sender<wasmtime::Result<()>>,
}

impl VsockWorkerGrant {
    async fn create(
        self,
        child: impl FnOnce(VsockDeviceHost) -> crate::box_runtime::DeviceWorker<VsockDeviceHost>,
    ) -> wasmtime::Result<(
        crate::box_runtime::DeviceWorker<VsockDeviceHost>,
        crate::component::vmm::mmio::Serve,
    )> {
        let device_host = VsockDeviceHost::new(
            self.ram.resolve()?,
            host::VsockHostService::new(self.plan, self.listener, self.control)?,
        );
        let wake = device_host.context.interrupt_notification();
        let mut child = child(device_host);
        let linker = host::vsock_component_linker(child.store.engine())?;
        let instance = VsockBindings::instantiate_async(&mut child.store, &self.component, &linker)
            .await
            .map_err(|error| error.context("vsock component initialization"))?;
        let api = instance.terra_vsock_api();
        let (configured,) = api
            .func_configure_device()
            .call_async(&mut child.store, ())
            .await
            .map_err(|error| error.context("vsock component configuration"))?;
        configured.map_err(|error| wasmtime::Error::msg(format!("vsock configure: {error:?}")))?;
        let serve = instance.terra_mmio_device().func_serve();
        let worker = crate::component::worker::Worker {
            run: api.func_run(),
            interrupt: self.interrupt,
        };
        let diagnostics = self.diagnostics.map(DiagnosticSink::new).transpose()?;
        let (events,) = api
            .func_events()
            .call_async(&mut child.store, ())
            .await
            .map_err(|error| error.context("vsock component event stream"))?;
        events.pipe(
            &mut child.store,
            EventSink {
                diagnostic_sender: diagnostics.as_ref().map(|sink| sink.sender.clone()),
                lifecycle: self.lifecycle,
            },
        )?;
        child.register_loop(Box::new(move |accessor| {
            Box::pin(run_worker(
                accessor,
                worker,
                diagnostics,
                self.completion,
                wake,
                self.closing,
            ))
        }))?;
        Ok((child, serve))
    }
}

impl VsockChannel {
    #[allow(clippy::too_many_arguments)]
    pub fn from_trusted_artifact(
        runtime: &mut crate::box_runtime::BoxRuntime,
        ram: impl Into<RamGrant> + Send,
        artifact: crate::TrustedArtifact,
        plan: Vec<u8>,
        listener: Option<UnixListener>,
        control: Option<UnixStream>,
        diagnostics: Option<std::fs::File>,
        interrupt: crate::component::network::Interrupt,
    ) -> wasmtime::Result<Self> {
        Self::from_component(
            runtime,
            ram,
            artifact.deserialize(runtime.store.engine())?,
            plan,
            listener,
            control,
            diagnostics,
            interrupt,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_component(
        runtime: &mut crate::box_runtime::BoxRuntime,
        ram: impl Into<RamGrant> + Send,
        component: wasmtime::component::Component,
        plan: Vec<u8>,
        listener: Option<UnixListener>,
        control: Option<UnixStream>,
        diagnostics: Option<std::fs::File>,
        interrupt: crate::component::network::Interrupt,
    ) -> wasmtime::Result<Self> {
        if runtime.has_component(crate::component::vmm::machine::DeviceKind::Vsock) {
            return Err(wasmtime::Error::msg("box already has a vsock component"));
        }
        let ram = ram.into();
        let shared_closing = Arc::new(AtomicBool::new(false));
        let (completion, close_response) = tokio::sync::oneshot::channel();
        let setup = VsockWorkerGrant {
            component,
            plan,
            listener,
            control,
            diagnostics,
            interrupt,
            ram,
            closing: Arc::clone(&shared_closing),
            lifecycle: runtime.lifecycle_notifier(),
            completion,
        };
        let child = runtime.child_factory();
        let mmio = runtime.grant_device_worker_unmanaged(
            crate::component::vmm::machine::DeviceKind::Vsock,
            async move { setup.create(child).await },
        )?;
        let closing_device = mmio.clone();
        let close = async move {
            shared_closing.store(true, Ordering::Release);
            closing_device
                .close_async()
                .await
                .map_err(|error| error.to_string())?;
            tokio::time::timeout(RESPONSE_TIMEOUT, close_response)
                .await
                .map_err(|error| format!("vsock component response: {error}"))?
                .map_err(|error| format!("vsock component response: {error}"))?
                .map_err(|error| error.to_string())
        }
        .boxed()
        .shared();
        if let Err(error) =
            runtime.add_device_shutdown(crate::component::vmm::teardown::DeviceShutdown::new(
                crate::component::vmm::machine::DeviceKind::Vsock,
                close.clone(),
            ))
        {
            mmio.revoke_worker(runtime)?;
            return Err(error);
        }
        Ok(Self { close, mmio })
    }

    #[must_use]
    pub fn failure(&self) -> Option<String> {
        self.mmio.failure().or_else(|| {
            self.close
                .peek()
                .and_then(|result| result.as_ref().err().cloned())
        })
    }

    pub fn read_mmio(&self, offset: u64, len: usize) -> wasmtime::Result<Vec<u8>> {
        self.mmio.read(offset, len)
    }

    pub fn write_mmio(&self, offset: u64, bytes: &[u8]) -> wasmtime::Result<()> {
        self.mmio.write(offset, bytes)
    }

    pub async fn close_async(&self) -> wasmtime::Result<()> {
        self.close.clone().await.map_err(wasmtime::Error::msg)
    }
}

async fn run_worker(
    accessor: &Accessor<StoreState<VsockDeviceHost>>,
    worker: crate::component::worker::Worker<VsockError>,
    diagnostics: Option<DiagnosticSink>,
    completion: tokio::sync::oneshot::Sender<wasmtime::Result<()>>,
    wake: Arc<tokio::sync::Notify>,
    shared_closing: Arc<AtomicBool>,
) -> wasmtime::Result<()> {
    let result = async {
        worker.drive(accessor, wake, "vsock").await?;
        wasmtime::ensure!(
            shared_closing.load(Ordering::Acquire),
            "vsock worker stopped"
        );
        if let Some(sink) = diagnostics {
            sink.finish().await?;
        }
        Ok(())
    }
    .await;
    let error = result
        .as_ref()
        .err()
        .map(|error| format!("vsock component: {error:#}"));
    let _ = completion.send(result);
    error.map_or(Ok(()), |error| Err(wasmtime::Error::msg(error)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SyntheticRam;
    use std::collections::BTreeMap;

    fn boot_plan() -> Vec<u8> {
        terra_protocol::encode_frame(&terra_protocol::Plan {
            mode: terra_protocol::PlanMode::Run,
            workdir: None,
            shares: Vec::new(),
            volumes: Vec::new(),
            net: terra_protocol::Net {
                guest_ip: "100.96.0.2".parse().expect("guest address"),
                prefix: 30,
                gateway: "100.96.0.1".parse().expect("gateway"),
                dns: "100.96.0.1".parse().expect("DNS"),
            },
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
        })
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
            MAX_DIAGNOSTIC_FILE_BYTES as u64
        );
    }

    #[tokio::test]
    async fn restarting_diagnostics_does_not_reset_the_file_budget() {
        let output = tempfile::NamedTempFile::new().unwrap();
        output
            .as_file()
            .set_len(MAX_DIAGNOSTIC_FILE_BYTES as u64 - 1)
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
            MAX_DIAGNOSTIC_FILE_BYTES as u64
        );
    }

    #[tokio::test]
    async fn typed_events_update_the_bounded_native_observers() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut store = Store::new(&engine, ());
        let lifecycle = crate::component::vmm::lifecycle::LifecycleHost::new();
        let events = wasmtime::component::StreamReader::new(&mut store, vec![VsockEvent::Exit(7)])
            .expect("event stream");
        events
            .pipe(
                &mut store,
                EventSink {
                    lifecycle: lifecycle.notifier(),
                    diagnostic_sender: None,
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
    async fn saturated_diagnostics_do_not_delay_exit_events() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut store = Store::new(&engine, ());
        let lifecycle = crate::component::vmm::lifecycle::LifecycleHost::new();
        let (diagnostic_sender, _diagnostic_receiver) = tokio::sync::mpsc::channel(1);
        diagnostic_sender
            .try_send(vec![0])
            .expect("diagnostic queue fills");
        let events = wasmtime::component::StreamReader::new(
            &mut store,
            vec![
                VsockEvent::Diagnostic(b"slow disk\n".to_vec()),
                VsockEvent::Exit(9),
            ],
        )
        .expect("event stream");
        events
            .pipe(
                &mut store,
                EventSink {
                    lifecycle: lifecycle.notifier(),
                    diagnostic_sender: Some(diagnostic_sender),
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
                    crate::component::vmm::lifecycle::lifecycle_platform::Event::GuestExit(9)
                ));
            })
            .await
            .expect("event stream runs");
    }

    #[tokio::test]
    async fn oversized_diagnostics_fail_before_enqueueing() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut store = Store::new(&engine, ());
        let (diagnostic_sender, mut diagnostic_receiver) = tokio::sync::mpsc::channel(1);
        let events = wasmtime::component::StreamReader::new(
            &mut store,
            vec![VsockEvent::Diagnostic(vec![
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
    fn shared_channel_runs_vsock_in_a_child_store() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let engine = crate::engine::device_engine().expect("engine");
            let mut runtime =
                crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new())
                    .expect("runtime");
            let router = wasmtime::component::Component::new(
                &engine,
                include_bytes!(
                    "../../../../components/target/wasm32-wasip3/release/terra_vmm_component.wasm"
                ),
            )
            .expect("router component");
            runtime.initialize_mmio(&router).await.expect("router");
            let ram = SyntheticRam::new(4096).expect("test RAM maps");
            // SAFETY: the test embeds the trusted build's component artifact.
            #[allow(unsafe_code)]
            let artifact = unsafe {
                crate::TrustedArtifact::from_trusted_bytes(include_bytes!(
                    "../../../../build/terra-vsock-component.cwasm"
                ))
            };
            let channel = VsockChannel::from_trusted_artifact(
                &mut runtime,
                ram,
                artifact,
                boot_plan(),
                None,
                None,
                None,
                Arc::new(|_| Ok(())),
            )
            .expect("component");
            assert!(runtime.has_component(crate::component::vmm::machine::DeviceKind::Vsock));
            let runtime_task = runtime.prepare().await.unwrap().start();
            let request = channel.clone();
            assert_eq!(
                tokio::task::spawn_blocking(move || request.read_mmio(0, 4))
                    .await
                    .expect("request thread")
                    .expect("component request"),
                0x7472_6976_u32.to_le_bytes()
            );
            assert_eq!(channel.mmio.request_counts(), (1, 0));
            let (entered, started) = tokio::sync::oneshot::channel();
            let (release, blocked) = std::sync::mpsc::channel();
            let occupied_pool = tokio::task::spawn_blocking(move || {
                entered.send(()).unwrap();
                let _ = blocked.recv_timeout(Duration::from_secs(5));
            });
            started.await.unwrap();
            let mut cancelled = Box::pin(channel.close_async());
            assert!(futures_util::poll!(&mut cancelled).is_pending());
            drop(cancelled);
            let peer = channel.clone();
            let (first, second) = tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(channel.close_async(), peer.close_async())
            })
            .await
            .expect("close does not need the blocking pool");
            first.expect("close survives cancelled waiter");
            second.expect("concurrent waiter shares completion");
            release.send(()).unwrap();
            occupied_pool.await.unwrap();
            channel
                .close_async()
                .await
                .expect("repeated close shares completion");
            runtime_task
                .join()
                .await
                .expect("runtime stops after the final component closes");
        });
    }
}
