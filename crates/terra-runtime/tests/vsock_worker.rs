#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[path = "support/artifacts.rs"]
mod support;

use futures_channel::{mpsc, oneshot};
use futures_util::{
    AsyncReadExt as _, AsyncWriteExt as _, Stream as _, StreamExt as _, future::poll_fn,
};
use std::{
    collections::VecDeque,
    future::Future,
    io::{self, Read as _, Write as _},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use terra_runtime::component::mmio::{Operation, Reply as MmioReply, Request};
use terra_runtime::component::vsock::{VsockDeviceHost, VsockEvent, vsock_component_linker};
use terra_runtime::engine::device_engine;
use terra_runtime::test_support::{StandaloneHost, device_store};
use terra_vsock_device::VsockHeader;
use wasmtime::StoreContextMut;
use wasmtime::component::{
    Accessor, Component, ComponentType, Lift, Source, StreamConsumer, StreamReader, StreamResult,
    TypedFunc,
};

const CARRIER_SOURCE: u32 = 6003;
const CARRIER_PORT: u32 = terra_protocol::mux::MUX_VSOCK_PORT;
const PAYLOAD_BYTES: usize = 300 * 1024;

#[derive(ComponentType, Lift)]
#[component(record)]
struct Reply {
    header: Vec<u8>,
    payload: Vec<u8>,
}

type Replies = TypedFunc<(u32, u32), (Vec<Reply>,)>;
type Receive = TypedFunc<(Vec<u8>,), (Result<(), terra_runtime::component::vsock::VsockError>,)>;
type Serve = TypedFunc<(StreamReader<Request>,), (StreamReader<MmioReply>,)>;

struct Worker {
    run: TypedFunc<(), (Result<(), terra_runtime::component::vsock::VsockError>,)>,
    close: TypedFunc<(), ()>,
    reset: TypedFunc<(), ()>,
    replies: Replies,
    receive: Receive,
    events: Arc<Mutex<Vec<VsockEvent>>>,
}

struct ReplySink(Arc<Mutex<Vec<MmioReply>>>);

impl StreamConsumer<StandaloneHost<VsockDeviceHost>> for ReplySink {
    type Item = MmioReply;

    fn poll_consume(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        store: StoreContextMut<StandaloneHost<VsockDeviceHost>>,
        mut source: Source<'_, Self::Item>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        let mut reply = None;
        source.read(store, &mut reply)?;
        if let Some(reply) = reply {
            self.0.lock().expect("reply sink lock").push(reply);
        }
        Poll::Ready(Ok(StreamResult::Completed))
    }
}

struct EventSink(Arc<Mutex<Vec<VsockEvent>>>);

impl StreamConsumer<StandaloneHost<VsockDeviceHost>> for EventSink {
    type Item = VsockEvent;

    fn poll_consume(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        store: StoreContextMut<StandaloneHost<VsockDeviceHost>>,
        mut source: Source<'_, Self::Item>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        let mut event = None;
        source.read(store, &mut event)?;
        if let Some(event) = event {
            self.0.lock().expect("event sink lock").push(event);
        }
        Poll::Ready(Ok(StreamResult::Completed))
    }
}

async fn drive_transport_ready(
    store: &mut wasmtime::Store<StandaloneHost<VsockDeviceHost>>,
    serve: Serve,
) {
    let requests = StreamReader::new(
        &mut *store,
        [1_u8, 3, 11, 15]
            .into_iter()
            .map(|status| Request {
                sequence: u64::from(status),
                operation: Operation::Write,
                offset: 0x70,
                width: 4,
                value: u64::from(status),
            })
            .collect::<Vec<_>>(),
    )
    .expect("status stream");
    let (replies,) = serve
        .call_async(&mut *store, (requests,))
        .await
        .expect("MMIO server starts");
    let received = Arc::new(Mutex::new(Vec::new()));
    replies
        .pipe(&mut *store, ReplySink(Arc::clone(&received)))
        .expect("reply stream attaches");
    tokio::time::timeout(Duration::from_secs(2), async {
        store
            .run_concurrent(async |_| {
                while received.lock().expect("reply sink lock").len() != 4 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("MMIO server runs");
    })
    .await
    .expect("MMIO status replies");
}

async fn create_worker(
    listener: terra_platform::io::local::LocalListener,
) -> (wasmtime::Store<StandaloneHost<VsockDeviceHost>>, Worker) {
    let engine = device_engine().expect("engine");
    let mut store = device_store(
        &engine,
        VsockDeviceHost::new(
            terra_runtime::memory::GuestRam::new(4096).expect("guest memory"),
            terra_runtime::component::vsock::VsockHostService::new(
                vec![2, 0, 0, 0, b'{', b'}'],
                Some(listener),
                None,
            )
            .expect("host service"),
        ),
    );
    let component = Component::new(&engine, support::artifacts::wasm::VSOCK).expect("component");
    let instance = vsock_component_linker(&engine)
        .expect("linker")
        .instantiate_async(&mut store, &component)
        .await
        .expect("instance");
    let interface = component
        .get_export_index(None, "terra:vsock/api@0.1.0")
        .expect("interface");
    let export = |name| {
        component
            .get_export_index(Some(&interface), name)
            .expect("export")
    };
    let configure = instance
        .get_typed_func::<(), (Result<(), terra_runtime::component::mmio::DeviceError>,)>(
            &mut store,
            export("configure-device"),
        )
        .expect("configure");
    assert!(
        configure
            .call_async(&mut store, ())
            .await
            .expect("configure call")
            .0
            .is_ok()
    );
    let device = component
        .get_export_index(None, "terra:mmio/device@0.1.0")
        .expect("device interface");
    let serve = instance
        .get_typed_func(
            &mut store,
            component
                .get_export_index(Some(&device), "serve")
                .expect("serve"),
        )
        .expect("serve function");
    drive_transport_ready(&mut store, serve).await;
    let events = instance
        .get_typed_func::<(), (StreamReader<terra_runtime::component::vsock::VsockEvent>,)>(
            &mut store,
            export("events"),
        )
        .expect("events");
    let (events,) = events
        .call_async(&mut store, ())
        .await
        .expect("event stream");
    let received_events = Arc::new(Mutex::new(Vec::new()));
    events
        .pipe(&mut store, EventSink(Arc::clone(&received_events)))
        .expect("event sink attaches");
    let run = instance
        .get_typed_func::<(), (Result<(), terra_runtime::component::vsock::VsockError>,)>(
            &mut store,
            export("run"),
        )
        .expect("run");
    let close = instance
        .get_typed_func::<(), ()>(&mut store, export("close"))
        .expect("close");
    let reset = instance
        .get_typed_func::<(), ()>(&mut store, export("reset"))
        .expect("reset");
    let replies = instance
        .get_typed_func(&mut store, export("take-replies"))
        .expect("replies");
    let receive = instance
        .get_typed_func(&mut store, export("receive"))
        .expect("receive");
    (
        store,
        Worker {
            run,
            close,
            reset,
            replies,
            receive,
            events: received_events,
        },
    )
}

fn packet(source: u32, operation: u16, forward_count: u32, payload: &[u8]) -> Vec<u8> {
    let header = VsockHeader {
        src_cid: 3,
        dst_cid: 2,
        src_port: source,
        dst_port: CARRIER_PORT,
        len: u32::try_from(payload.len()).expect("packet length"),
        type_: 1,
        op: operation,
        flags: 0,
        buf_alloc: 64 * 1024,
        fwd_cnt: forward_count,
    };
    let mut bytes = header.encode().to_vec();
    bytes.extend_from_slice(payload);
    bytes
}

async fn write_local(stream: &mut terra_platform::io::local::LocalStream, bytes: &[u8]) {
    let mut written = 0;
    while written < bytes.len() {
        match stream.write(&bytes[written..]) {
            Ok(count) => written += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Err(error) => panic!("host input: {error}"),
        }
    }
}

async fn wait_for_lifecycle_events(events: &Arc<Mutex<Vec<VsockEvent>>>) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let received = {
                let events = events.lock().expect("event sink lock");
                let ready = events
                    .iter()
                    .any(|event| matches!(event, VsockEvent::AgentReady));
                let diagnostic = events.iter().any(
                    |event| matches!(event, VsockEvent::Diagnostic(bytes) if bytes == b"diagnostic"),
                );
                ready && diagnostic
            };
            if received {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("host receives lifecycle events");
}

struct GuestCarrier {
    writer: mpsc::UnboundedSender<Vec<u8>>,
    reader: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    pending: VecDeque<u8>,
}

impl futures_util::io::AsyncRead for GuestCarrier {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending.is_empty() {
            match Pin::new(&mut self.reader).poll_next(context) {
                Poll::Ready(Some(Ok(next))) => self.pending.extend(next),
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error)),
                Poll::Ready(None) => return Poll::Ready(Ok(0)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let count = bytes.len().min(self.pending.len());
        for byte in &mut bytes[..count] {
            *byte = self.pending.pop_front().expect("pending byte");
        }
        Poll::Ready(Ok(count))
    }
}

impl futures_util::io::AsyncWrite for GuestCarrier {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .writer
            .unbounded_send(bytes.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "carrier closed"))?;
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().writer.close_channel();
        Poll::Ready(Ok(()))
    }
}

async fn pump_carrier(
    accessor: &Accessor<StandaloneHost<VsockDeviceHost>>,
    receive: Receive,
    replies: Replies,
    source: u32,
    mut outbound_data: mpsc::UnboundedReceiver<Vec<u8>>,
    incoming_data: mpsc::UnboundedSender<io::Result<Vec<u8>>>,
    started: oneshot::Sender<()>,
) {
    receive
        .call_concurrent(&accessor, (packet(source, 1, 0, &[]),))
        .await
        .expect("carrier request call")
        .0
        .expect("carrier request accepted");
    let mut started = Some(started);
    let mut received = 0_u32;
    let mut sent = 0_u32;
    let mut peer_credit = 0_u32;
    let mut peer_forward_count = 0_u32;
    let mut acknowledged = 0_u32;
    let mut pending = VecDeque::new();
    loop {
        match tokio::time::timeout(Duration::from_millis(1), outbound_data.next()).await {
            Ok(Some(bytes)) => pending.extend(bytes),
            Ok(None) => return,
            Err(_) => {}
        }
        let available = peer_credit.saturating_sub(sent.wrapping_sub(peer_forward_count));
        if available != 0 && !pending.is_empty() {
            let count = pending
                .len()
                .min(usize::try_from(available).expect("credit fits usize"))
                .min(terra_protocol::mux::MAX_STREAM_FRAME_BYTES);
            let bytes = pending.drain(..count).collect::<Vec<_>>();
            receive
                .call_concurrent(&accessor, (packet(source, 5, received, &bytes),))
                .await
                .expect("carrier write call")
                .0
                .expect("carrier write accepted");
            sent = sent.wrapping_add(u32::try_from(count).expect("frame length"));
        }
        let (batch,) = replies
            .call_concurrent(&accessor, (16, 64 * 1024))
            .await
            .expect("carrier replies");
        for reply in batch {
            let (header, _) = VsockHeader::parse(&reply.header).expect("reply header");
            assert_eq!(header.src_port, CARRIER_PORT);
            assert_eq!(header.dst_port, source);
            peer_credit = header.buf_alloc;
            peer_forward_count = header.fwd_cnt;
            match header.op {
                2 => {
                    if let Some(started) = started.take() {
                        started.send(()).expect("carrier startup receiver");
                    }
                }
                5 => {
                    received = received.wrapping_add(header.len);
                    incoming_data
                        .unbounded_send(Ok(reply.payload))
                        .expect("guest remains connected");
                }
                3 => {
                    let _ = incoming_data.unbounded_send(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "carrier reset",
                    )));
                    return;
                }
                _ => {}
            }
        }
        if acknowledged != received {
            receive
                .call_concurrent(&accessor, (packet(source, 6, received, &[]),))
                .await
                .expect("carrier credit update call")
                .0
                .expect("carrier credit update accepted");
            acknowledged = received;
        }
    }
}

fn guest_carrier(
    accessor: &Accessor<StandaloneHost<VsockDeviceHost>>,
    receive: Receive,
    replies: Replies,
    source: u32,
) -> (
    GuestCarrier,
    oneshot::Receiver<()>,
    impl Future<Output = ()> + '_,
) {
    let (outbound_data, outbound_receiver) = mpsc::unbounded();
    let (incoming_sender, reader) = mpsc::unbounded();
    let (started_sender, started_receiver) = oneshot::channel();
    let pump = async move {
        pump_carrier(
            accessor,
            receive,
            replies,
            source,
            outbound_receiver,
            incoming_sender,
            started_sender,
        )
        .await;
    };
    let carrier = GuestCarrier {
        writer: outbound_data,
        reader,
        pending: VecDeque::new(),
    };
    (carrier, started_receiver, pump)
}

/// The component carries control, diagnostics, and every host client through
/// one guest-initiated Yamux connection.
#[tokio::test(flavor = "current_thread")]
#[allow(clippy::too_many_lines)]
async fn client_round_trip_uses_the_shared_carrier() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("agent.sock");
    let listener = terra_platform::io::local::LocalListener::bind(&path).expect("listener");
    let mut client = terra_platform::io::local::LocalStream::connect(&path).expect("client");
    client.set_nonblocking(true).expect("nonblocking client");
    let (mut store, worker) = create_worker(listener).await;
    Box::pin(tokio::time::timeout(
        Duration::from_secs(15),
        store.run_concurrent(async |accessor| {
            let (carrier, started, pump) =
                guest_carrier(accessor, worker.receive, worker.replies, CARRIER_SOURCE);
            let run = worker.run.call_concurrent(accessor, ());
            let guest = Box::pin(async {
                started.await.expect("carrier handshake");
                let mut connection = yamux::Connection::new(
                    carrier,
                    terra_protocol::mux::yamux_config(),
                    yamux::Mode::Client,
                );
                let mut control = poll_fn(|context| connection.poll_new_outbound(context))
                    .await
                    .expect("control stream");
                assert_eq!(control.write(&[]).await.expect("control SYN"), 0);
                let mut diagnostics = poll_fn(|context| connection.poll_new_outbound(context))
                    .await
                    .expect("diagnostic stream");
                assert_eq!(diagnostics.write(&[]).await.expect("diagnostic SYN"), 0);
                control
                    .write_all(
                        &terra_protocol::encode_frame(&terra_protocol::LifecycleEvent::AgentReady)
                            .expect("ready frame"),
                    )
                    .await
                    .expect("guest ready");
                diagnostics
                    .write_all(
                        &terra_protocol::encode_frame(
                            &terra_protocol::LifecycleEvent::Diagnostic {
                                bytes: b"diagnostic".to_vec(),
                            },
                        )
                        .expect("diagnostic frame"),
                    )
                    .await
                    .expect("guest diagnostic");
                let request = vec![b'q'; PAYLOAD_BYTES];
                let mut stream = poll_fn(|context| connection.poll_next_inbound(context))
                    .await
                    .expect("carrier remains open")
                    .expect("client stream");
                let exchange = async {
                    write_local(&mut client, &request).await;
                    let mut received = vec![0; PAYLOAD_BYTES];
                    stream.read_exact(&mut received).await.expect("guest input");
                    assert_eq!(received, request);
                    let response = vec![b'r'; PAYLOAD_BYTES];
                    stream.write_all(&response).await.expect("guest output");
                    stream.close().await.expect("guest finish");
                    let mut received = Vec::with_capacity(PAYLOAD_BYTES);
                    loop {
                        let mut buffer = [0; 16 * 1024];
                        match std::io::Read::read(&mut client, &mut buffer) {
                            Ok(0) => panic!("host output closed early"),
                            Ok(count) => received.extend_from_slice(&buffer[..count]),
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                tokio::time::sleep(Duration::from_millis(1)).await;
                            }
                            Err(error) => panic!("host output: {error}"),
                        }
                        if received.len() == PAYLOAD_BYTES {
                            return received;
                        }
                    }
                };
                let driver = async {
                    loop {
                        let inbound =
                            poll_fn(|context| connection.poll_next_inbound(context)).await;
                        assert!(
                            inbound.is_some(),
                            "carrier stays open while exchanging client data"
                        );
                        assert!(
                            inbound.expect("inbound result").is_err(),
                            "no extra guest streams"
                        );
                    }
                };
                futures_util::pin_mut!(exchange, driver);
                match futures_util::future::select(exchange, driver).await {
                    futures_util::future::Either::Left((response, _)) => {
                        assert_eq!(response, vec![b'r'; PAYLOAD_BYTES]);
                    }
                    futures_util::future::Either::Right(_) => panic!("carrier driver stopped"),
                }
            });
            let close = async {
                guest.await;
                wait_for_lifecycle_events(&worker.events).await;
                worker
                    .close
                    .call_concurrent(accessor, ())
                    .await
                    .expect("close");
            };
            let ((), (), result) = tokio::join!(close, pump, run);
            result.expect("worker call").0.expect("worker result");
            Ok::<(), wasmtime::Error>(())
        }),
    ))
    .await
    .expect("carrier test timeout")
    .expect("component run")
    .expect("component result");
}

/// Reset aborts the session bridge before a later device lifetime can reuse
/// the carrier tuple.
#[tokio::test(flavor = "current_thread")]
async fn reset_releases_the_open_client() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("reset.sock");
    let listener = terra_platform::io::local::LocalListener::bind(&path).expect("listener");
    let mut client = terra_platform::io::local::LocalStream::connect(&path).expect("client");
    client.set_nonblocking(true).expect("nonblocking client");
    let (mut store, worker) = create_worker(listener).await;
    tokio::time::timeout(
        Duration::from_secs(5),
        store.run_concurrent(async |accessor| {
            let (carrier, started, pump) =
                guest_carrier(accessor, worker.receive, worker.replies, CARRIER_SOURCE);
            let run = worker.run.call_concurrent(accessor, ());
            let reset = async {
                started.await.expect("carrier handshake");
                let mut connection = yamux::Connection::new(
                    carrier,
                    terra_protocol::mux::yamux_config(),
                    yamux::Mode::Client,
                );
                let mut control = poll_fn(|context| connection.poll_new_outbound(context))
                    .await
                    .expect("control stream");
                assert_eq!(control.write(&[]).await.expect("control SYN"), 0);
                let mut diagnostics = poll_fn(|context| connection.poll_new_outbound(context))
                    .await
                    .expect("diagnostic stream");
                assert_eq!(diagnostics.write(&[]).await.expect("diagnostic SYN"), 0);
                let guest_client = poll_fn(|context| connection.poll_next_inbound(context))
                    .await
                    .expect("carrier remains open")
                    .expect("client stream");
                worker
                    .reset
                    .call_concurrent(accessor, ())
                    .await
                    .expect("reset");
                (connection, control, diagnostics, guest_client)
            };
            let close = async {
                let _guest_session = reset.await;
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        match client.read(&mut [0; 1]) {
                            Ok(0) => return,
                            Ok(_) => panic!("reset client received data"),
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                tokio::time::sleep(Duration::from_millis(1)).await;
                            }
                            Err(error) => panic!("reset client read: {error}"),
                        }
                    }
                })
                .await
                .expect("reset closes host client");
                assert_eq!(
                    accessor.with(|mut access| access.get().vsock_service_mut().live_clients()),
                    0
                );
                worker
                    .close
                    .call_concurrent(accessor, ())
                    .await
                    .expect("close");
            };
            let ((), (), result) = tokio::join!(close, pump, run);
            result.expect("worker call").0.expect("worker result");
            Ok::<(), wasmtime::Error>(())
        }),
    )
    .await
    .expect("reset test timeout")
    .expect("component run")
    .expect("component result");
}
