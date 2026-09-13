//! Native control streams for the compartmentalized vsock device.

pub mod bindings;
pub mod host;
#[cfg(any(test, feature = "test-support"))]
pub mod protocol;

use crate::component::vmm::virtualization::RamGrant;
use crate::component::vsock::bindings::VsockComponent;
use std::{
    io::Write,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};
use terra_io::local::{LocalListener as UnixListener, LocalStream as UnixStream};
use wasmtime::Store;
use wasmtime::StoreContextMut;
use wasmtime::component::{Accessor, Source, StreamConsumer, StreamResult};

#[cfg(test)]
const MAX_DIAGNOSTIC_FILE_BYTES: usize = terra_io::log::MAX_LOG_FILE_BYTES;
const MAX_DIAGNOSTIC_BATCH_BYTES: usize = 65536;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

struct DiagnosticSink {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    finished: std::sync::mpsc::Receiver<std::io::Result<()>>,
}

impl DiagnosticSink {
    fn new(mut output: std::fs::File) -> std::io::Result<Self> {
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
        let (done, finished) = std::sync::mpsc::sync_channel(1);
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

    fn finish(self) -> std::io::Result<()> {
        drop(self.sender);
        self.finished
            .recv_timeout(std::time::Duration::from_secs(1))
            .map_err(std::io::Error::other)?
    }
}

struct EventSink {
    exit_code: Arc<Mutex<Option<i32>>>,
    diagnostic_sender: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    lifecycle: Option<crate::component::vmm::lifecycle::LifecycleNotifier>,
}

impl EventSink {
    fn new(
        exit_code: Arc<Mutex<Option<i32>>>,
        diagnostic_sender: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    ) -> Self {
        Self {
            exit_code,
            diagnostic_sender,
            lifecycle: None,
        }
    }
}

impl<H: 'static> StreamConsumer<H> for EventSink {
    type Item = crate::component::vsock::bindings::HostEvent;

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
            crate::component::vsock::bindings::HostEvent::Diagnostic(bytes) => {
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
            crate::component::vsock::bindings::HostEvent::Exit(code) => {
                *self
                    .exit_code
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(code);
                if let Some(lifecycle) = &self.lifecycle {
                    lifecycle.guest_exit(code);
                }
            }
        }
        std::task::Poll::Ready(Ok(StreamResult::Completed))
    }
}

pub struct VsockDev {
    component: VsockComponent,
    diagnostic_sink: Option<DiagnosticSink>,
    exit_code: Arc<Mutex<Option<i32>>>,
    lifecycle: Option<crate::component::vmm::lifecycle::LifecycleNotifier>,
}

#[derive(Clone)]
pub struct VsockChannel {
    close_response: Arc<Mutex<mpsc::Receiver<wasmtime::Result<()>>>>,
    failure: Arc<Mutex<Option<String>>>,
    mmio: crate::component::vmm::mmio::MmioDevice,
    shared_closing: Arc<AtomicBool>,
}

impl VsockDev {
    pub fn grant_diagnostics(&mut self, output: std::fs::File) -> std::io::Result<()> {
        self.diagnostic_sink = Some(DiagnosticSink::new(output)?);
        Ok(())
    }

    pub async fn finish_diagnostics(&mut self) -> wasmtime::Result<()> {
        let sink = self.diagnostic_sink.take();
        if let Some(sink) = sink {
            tokio::task::spawn_blocking(move || sink.finish())
                .await
                .map_err(|_| wasmtime::Error::msg("vsock diagnostic writer stopped"))??;
        }
        Ok(())
    }

    fn event_sink(&self) -> EventSink {
        let mut sink = EventSink::new(
            Arc::clone(&self.exit_code),
            self.diagnostic_sink
                .as_ref()
                .map(|sink| sink.sender.clone()),
        );
        sink.lifecycle.clone_from(&self.lifecycle);
        sink
    }

    pub async fn configure_worker_store(
        &mut self,
        store: &mut Store<crate::box_runtime::BoxHost>,
        control_events: bool,
    ) -> wasmtime::Result<()> {
        self.component
            .configure_worker_store(store, control_events)
            .await?;
        self.component
            .events_store(store)
            .await?
            .pipe(store, self.event_sink())
    }
}

struct VsockWorkerGrant {
    component: wasmtime::component::Component,
    plan: Vec<u8>,
    control_events: bool,
    listener: Option<UnixListener>,
    control: Option<UnixStream>,
    diagnostics: Option<std::fs::File>,
    interrupt: crate::component::Interrupt,
    ram: RamGrant,
    exit_code: Arc<Mutex<Option<i32>>>,
    failure: Arc<Mutex<Option<String>>>,
    closing: Arc<AtomicBool>,
    lifecycle: crate::component::vmm::lifecycle::LifecycleNotifier,
    completion: mpsc::SyncSender<wasmtime::Result<()>>,
}

impl VsockWorkerGrant {
    async fn create(
        self,
        mut child: crate::box_runtime::BoxRuntime,
    ) -> wasmtime::Result<(
        crate::box_runtime::BoxRuntime,
        crate::component::vmm::mmio::Serve,
    )> {
        let mut device_host = crate::engine::DeviceHost::with_ram(self.ram.resolve()?);
        device_host.set_vsock_service(host::VsockHostService::new(
            self.plan,
            self.listener,
            self.control,
        )?);
        let wake = device_host.interrupt_notification();
        let component =
            VsockComponent::instantiate_shared(&mut child, device_host, &self.component).await?;
        let serve = component.mmio_serve();
        let mut device_state = VsockDev {
            component,
            diagnostic_sink: None,
            exit_code: self.exit_code,
            lifecycle: Some(self.lifecycle),
        };
        if let Some(diagnostics) = self.diagnostics {
            device_state.grant_diagnostics(diagnostics)?;
        }
        device_state
            .configure_worker_store(&mut child.store, self.control_events)
            .await?;
        child.register_loop(Box::new(move |accessor| {
            Box::pin(run_worker(
                accessor,
                device_state,
                self.completion,
                self.interrupt,
                wake,
                self.closing,
                self.failure,
            ))
        }))?;
        Ok((child, serve))
    }
}

impl VsockChannel {
    /// # Safety
    /// `artifact` must be trusted AOT output from this exact Wasmtime build.
    #[allow(unsafe_code, clippy::too_many_arguments)]
    pub async unsafe fn from_trusted_shared(
        runtime: &mut crate::box_runtime::BoxRuntime,
        ram: impl Into<RamGrant> + Send,
        artifact: &'static [u8],
        plan: Vec<u8>,
        control_events: bool,
        listener: Option<UnixListener>,
        control: Option<UnixStream>,
        diagnostics: Option<std::fs::File>,
        interrupt: crate::component::network::Interrupt,
    ) -> wasmtime::Result<Self> {
        if runtime.has_component(crate::component::vmm::machine::DeviceKind::Vsock) {
            return Err(wasmtime::Error::msg("box already has a vsock component"));
        }
        let ram = ram.into();
        // SAFETY: the caller supplies AOT output for this exact Wasmtime build.
        let component = unsafe {
            wasmtime::component::Component::deserialize(runtime.store.engine(), artifact)?
        };
        let exit_code = Arc::new(Mutex::new(None));
        let failure = Arc::new(Mutex::new(None));
        let shared_closing = Arc::new(AtomicBool::new(false));
        let (completion, close_response) = mpsc::sync_channel(1);
        let setup = VsockWorkerGrant {
            component,
            plan,
            control_events,
            listener,
            control,
            diagnostics,
            interrupt,
            ram,
            exit_code: Arc::clone(&exit_code),
            failure: Arc::clone(&failure),
            closing: Arc::clone(&shared_closing),
            lifecycle: runtime.lifecycle_notifier(),
            completion,
        };
        let child = runtime.child_factory();
        let factory: crate::component::vmm::workers::Factory = Box::new(move || {
            Box::pin(async move {
                setup
                    .create(child(crate::box_runtime::BoxHost::new())?)
                    .await
            })
        });
        let mmio = crate::component::vmm::mmio::MmioDevice::grant_worker(
            runtime,
            crate::component::vmm::machine::DeviceKind::Vsock,
            factory,
        )
        .await?;
        Ok(Self {
            close_response: Arc::new(Mutex::new(close_response)),
            failure,
            mmio,
            shared_closing,
        })
    }

    #[must_use]
    pub fn failure(&self) -> Option<String> {
        self.mmio.failure().or_else(|| {
            self.failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        })
    }

    fn finish_close(&self) -> wasmtime::Result<()> {
        self.close_response
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv_timeout(RESPONSE_TIMEOUT)
            .map_err(|error| {
                let error = format!("vsock component response: {error}");
                set_failure(&self.failure, error.clone());
                wasmtime::Error::msg(error)
            })?
    }

    pub fn read_mmio(&self, offset: u64, len: usize) -> wasmtime::Result<Vec<u8>> {
        if !matches!(len, 1 | 2 | 4 | 8) {
            return Err(wasmtime::Error::msg("invalid vsock MMIO width"));
        }
        self.mmio.read(offset, len)
    }

    pub fn write_mmio(&self, offset: u64, bytes: &[u8]) -> wasmtime::Result<()> {
        if !matches!(bytes.len(), 1 | 2 | 4 | 8) {
            return Err(wasmtime::Error::msg("invalid vsock MMIO width"));
        }
        self.mmio.write(offset, bytes)
    }

    pub fn close(&self) -> wasmtime::Result<()> {
        if self.shared_closing.swap(true, Ordering::AcqRel) {
            return Err(wasmtime::Error::msg("vsock component is already closing"));
        }
        if let Some(error) = self.failure() {
            return Err(wasmtime::Error::msg(format!(
                "vsock component unavailable: {error}"
            )));
        }
        if let Err(error) = self.mmio.close() {
            self.shared_closing.store(false, Ordering::Release);
            return Err(error);
        }
        self.finish_close()
    }

    pub async fn close_async(&self) -> wasmtime::Result<()> {
        let channel = self.clone();
        tokio::task::spawn_blocking(move || channel.close())
            .await
            .map_err(|_| wasmtime::Error::msg("vsock close task stopped"))?
    }
}

async fn run_worker(
    accessor: &Accessor<crate::box_runtime::BoxHost>,
    mut device: VsockDev,
    completion: mpsc::SyncSender<wasmtime::Result<()>>,
    interrupt: crate::component::Interrupt,
    wake: Arc<tokio::sync::Notify>,
    shared_closing: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<String>>>,
) -> wasmtime::Result<()> {
    let result = async {
        crate::component::worker::Worker {
            run: device.component.run_function(),
            interrupt,
        }
        .drive(accessor, wake, "vsock", |host| {
            let host = host
                .vsock
                .first_mut()
                .ok_or_else(|| wasmtime::Error::msg("vsock host missing"))?;
            host.end_window();
            Ok(host.interrupt_level())
        })
        .await?;
        wasmtime::ensure!(
            shared_closing.load(Ordering::Acquire),
            "vsock worker stopped"
        );
        device.finish_diagnostics().await
    }
    .await;
    let error = result
        .as_ref()
        .err()
        .map(|error| format!("vsock component: {error:#}"));
    if let Some(error) = &error {
        set_failure(&failure, error.clone());
    }
    let _ = completion.send(result);
    error.map_or(Ok(()), |error| Err(wasmtime::Error::msg(error)))
}

fn set_failure(failure: &Mutex<Option<String>>, error: String) {
    let mut slot = failure
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if slot.is_none() {
        *slot = Some(error);
    }
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
            workload_on_console: false,
            await_initial_session: false,
            lifecycle_protocol: terra_protocol::LifecycleProtocol::EventsV1,
            host_tz: None,
            host_time: None,
            host_seed: None,
        })
        .expect("plan encodes")
    }

    #[test]
    fn diagnostic_finish_flushes_queued_output() {
        let output = tempfile::NamedTempFile::new().unwrap();
        let sink = DiagnosticSink::new(output.reopen().unwrap()).unwrap();
        sink.sender
            .blocking_send(b"failed bake output\n".to_vec())
            .unwrap();
        sink.finish().unwrap();
        assert_eq!(
            std::fs::read(output.path()).unwrap(),
            b"failed bake output\n"
        );
    }

    #[test]
    fn diagnostic_flood_drains_after_reaching_file_limit() {
        let output = tempfile::NamedTempFile::new().unwrap();
        let sink = DiagnosticSink::new(output.reopen().unwrap()).unwrap();
        for _ in 0..=(MAX_DIAGNOSTIC_FILE_BYTES / 4096) {
            sink.sender.blocking_send(vec![b'x'; 4096]).unwrap();
        }
        sink.finish().unwrap();
        assert_eq!(
            output.as_file().metadata().unwrap().len(),
            MAX_DIAGNOSTIC_FILE_BYTES as u64
        );
    }

    #[test]
    fn restarting_diagnostics_does_not_reset_the_file_budget() {
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
            sink.sender.blocking_send(vec![b'x'; 4096]).unwrap();
            sink.finish().unwrap();
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
        let exit_code = Arc::new(Mutex::new(None));
        let events = wasmtime::component::StreamReader::new(
            &mut store,
            vec![crate::component::vsock::bindings::HostEvent::Exit(7)],
        )
        .expect("event stream");
        events
            .pipe(&mut store, EventSink::new(Arc::clone(&exit_code), None))
            .expect("event sink");
        store
            .run_concurrent(async |_| {
                while *exit_code
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    != Some(7)
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("event stream runs");
    }

    #[tokio::test]
    async fn saturated_diagnostics_do_not_delay_exit_events() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut store = Store::new(&engine, ());
        let exit_code = Arc::new(Mutex::new(None));
        let (diagnostic_sender, _diagnostic_receiver) = tokio::sync::mpsc::channel(1);
        diagnostic_sender
            .try_send(vec![0])
            .expect("diagnostic queue fills");
        let events = wasmtime::component::StreamReader::new(
            &mut store,
            vec![
                crate::component::vsock::bindings::HostEvent::Diagnostic(b"slow disk\n".to_vec()),
                crate::component::vsock::bindings::HostEvent::Exit(9),
            ],
        )
        .expect("event stream");
        events
            .pipe(
                &mut store,
                EventSink::new(Arc::clone(&exit_code), Some(diagnostic_sender)),
            )
            .expect("event sink");
        store
            .run_concurrent(async |_| {
                while *exit_code
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    != Some(9)
                {
                    tokio::task::yield_now().await;
                }
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
            vec![crate::component::vsock::bindings::HostEvent::Diagnostic(
                vec![0; MAX_DIAGNOSTIC_BATCH_BYTES + 1],
            )],
        )
        .expect("event stream");
        events
            .pipe(
                &mut store,
                EventSink::new(Arc::new(Mutex::new(None)), Some(diagnostic_sender)),
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

    #[tokio::test(flavor = "current_thread")]
    async fn shared_channel_runs_vsock_in_a_child_store() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut runtime =
            crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new())
                .expect("runtime");
        let router = wasmtime::component::Component::new(
            &engine,
            include_bytes!(
                "../../../../components/vmm/target/wasm32-wasip3/release/terra_vmm_component.wasm"
            ),
        )
        .expect("router component");
        runtime.initialize_mmio(&router).await.expect("router");
        let ram = SyntheticRam::new(4096).expect("test RAM maps");
        // SAFETY: the test embeds the trusted build's component artifact.
        #[allow(unsafe_code)]
        let channel = unsafe {
            VsockChannel::from_trusted_shared(
                &mut runtime,
                ram,
                include_bytes!("../../../../build/terra-vsock-component.cwasm"),
                boot_plan(),
                false,
                None,
                None,
                None,
                Arc::new(|_| Ok(())),
            )
            .await
        }
        .expect("component");
        assert!(runtime.store.data().vsock.is_empty());
        assert!(runtime.has_component(crate::component::vmm::machine::DeviceKind::Vsock));
        let runtime_task = runtime.start();
        let request = channel.clone();
        assert_eq!(
            tokio::task::spawn_blocking(move || request.read_mmio(0, 4))
                .await
                .expect("request thread")
                .expect("component request"),
            0x7472_6976_u32.to_le_bytes()
        );
        assert_eq!(channel.mmio.request_counts(), (1, 0));
        channel.close_async().await.expect("component close");
        assert!(channel.close_async().await.is_err());
        runtime_task
            .join()
            .await
            .expect("runtime stops after the final component closes");
    }
}
