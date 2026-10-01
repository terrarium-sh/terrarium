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
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use terra_runtime::component::mmio::{Operation, Reply as MmioReply, Request};
use terra_runtime::component::vsock::{VsockDeviceHost, VsockEvent, vsock_component_linker};
use terra_runtime::engine::device_engine;
use terra_runtime::memory::{BoundedMemory, GuestRam};
use terra_runtime::test_support::{StandaloneHost, device_store};
use terra_vsock_device::{VSOCK_HEADER_BYTES, VsockHeader};
use wasmtime::StoreContextMut;
use wasmtime::component::{
    Component, Destination, Source, StreamConsumer, StreamProducer, StreamReader, StreamResult,
    TypedFunc, VecBuffer,
};

const CARRIER_SOURCE: u32 = 6003;
const CARRIER_PORT: u32 = terra_protocol::mux::MUX_VSOCK_PORT;
const PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const QUEUE_SIZE: u16 = 16;
const RX_DESC: u64 = 0x1000;
const RX_AVAIL: u64 = 0x2000;
const RX_USED: u64 = 0x3000;
const RX_DATA: u64 = 0x4000;
const TX_DESC: u64 = 0x1_5000;
const TX_AVAIL: u64 = 0x1_6000;
const TX_USED: u64 = 0x1_7000;
const TX_HEADER: u64 = 0x1_8000;
const TX_DATA: u64 = 0x1_9000;
const RX_PACKET_BYTES: u32 = 4096;

type Serve = TypedFunc<(StreamReader<Request>,), (StreamReader<MmioReply>,)>;

struct Worker {
    run: TypedFunc<(), (Result<(), terra_runtime::component::vsock::VsockError>,)>,
    close: TypedFunc<(), ()>,
    mmio: Mmio,
    ram: GuestRam,
    events: Arc<Mutex<Vec<VsockEvent>>>,
}

struct Mmio {
    requests: mpsc::UnboundedSender<Request>,
    replies: Arc<Mutex<Vec<MmioReply>>>,
    sequence: AtomicU64,
    is_reset: AtomicBool,
}

impl Mmio {
    async fn write(&self, offset: u64, value: u32) {
        if offset == 0x70 && value == 0 {
            self.is_reset.store(true, Ordering::Release);
        }
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        self.requests
            .unbounded_send(Request {
                sequence,
                operation: Operation::Write,
                offset,
                width: 4,
                value: u64::from(value),
            })
            .expect("MMIO request");
        loop {
            let reply = {
                let mut replies = self.replies.lock().expect("reply sink lock");
                replies
                    .iter()
                    .position(|reply| reply.sequence == sequence)
                    .map(|index| replies.remove(index))
            };
            if let Some(reply) = reply {
                assert_eq!(reply.error, 0, "MMIO write at {offset:#x}");
                return;
            }
            tokio::task::yield_now().await;
        }
    }
}

struct RequestSource(mpsc::UnboundedReceiver<Request>);

impl StreamProducer<StandaloneHost<VsockDeviceHost>> for RequestSource {
    type Item = Request;
    type Buffer = VecBuffer<Request>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        _: StoreContextMut<'a, StandaloneHost<VsockDeviceHost>>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        match std::task::ready!(Pin::new(&mut self.0).poll_next(context)) {
            Some(request) => {
                destination.set_buffer(vec![request].into());
                Poll::Ready(Ok(StreamResult::Completed))
            }
            None => Poll::Ready(Ok(StreamResult::Dropped)),
        }
    }
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

fn write_memory(ram: &GuestRam, address: u64, bytes: &[u8]) {
    BoundedMemory::new(ram)
        .write(address, bytes)
        .expect("guest memory write");
}

fn read_memory(ram: &GuestRam, address: u64, len: u64) -> Vec<u8> {
    BoundedMemory::new(ram)
        .read(address, len)
        .expect("guest memory read")
}

fn read_index(ram: &GuestRam, address: u64) -> u16 {
    u16::from_le_bytes(
        read_memory(ram, address + 2, 2)
            .try_into()
            .expect("ring index"),
    )
}

fn descriptor(address: u64, len: u32, flags: u16, next: u16) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&address.to_le_bytes());
    bytes[8..12].copy_from_slice(&len.to_le_bytes());
    bytes[12..14].copy_from_slice(&flags.to_le_bytes());
    bytes[14..].copy_from_slice(&next.to_le_bytes());
    bytes
}

async fn configure_transport(mmio: &Mmio, ram: &GuestRam) {
    for index in 0..QUEUE_SIZE {
        write_memory(
            ram,
            RX_DESC + u64::from(index) * 16,
            &descriptor(
                RX_DATA + u64::from(index) * u64::from(RX_PACKET_BYTES),
                RX_PACKET_BYTES,
                2,
                0,
            ),
        );
        write_memory(
            ram,
            RX_AVAIL + 4 + u64::from(index) * 2,
            &index.to_le_bytes(),
        );
    }
    write_memory(ram, RX_AVAIL + 2, &QUEUE_SIZE.to_le_bytes());
    for (offset, value) in [(0x70, 1), (0x70, 3), (0x24, 1), (0x20, 1), (0x70, 11)] {
        mmio.write(offset, value).await;
    }
    for (queue, desc, avail, used) in [
        (0, RX_DESC, RX_AVAIL, RX_USED),
        (1, TX_DESC, TX_AVAIL, TX_USED),
    ] {
        for (offset, value) in [
            (0x30, queue),
            (0x38, u32::from(QUEUE_SIZE)),
            (0x80, u32::try_from(desc).expect("descriptor address")),
            (0x90, u32::try_from(avail).expect("available address")),
            (0xa0, u32::try_from(used).expect("used address")),
            (0x44, 1),
        ] {
            mmio.write(offset, value).await;
        }
    }
    mmio.write(0x70, 15).await;
    mmio.write(0x50, 0).await;
}

async fn start_mmio(
    store: &mut wasmtime::Store<StandaloneHost<VsockDeviceHost>>,
    serve: Serve,
    ram: &GuestRam,
) -> Mmio {
    let (request_sender, request_receiver) = mpsc::unbounded();
    let requests =
        StreamReader::new(&mut *store, RequestSource(request_receiver)).expect("MMIO stream");
    let (replies,) = serve
        .call_async(&mut *store, (requests,))
        .await
        .expect("MMIO server starts");
    let received_replies = Arc::new(Mutex::new(Vec::new()));
    replies
        .pipe(&mut *store, ReplySink(Arc::clone(&received_replies)))
        .expect("reply stream attaches");
    let mmio = Mmio {
        requests: request_sender,
        replies: received_replies,
        sequence: AtomicU64::new(1),
        is_reset: AtomicBool::new(false),
    };
    tokio::time::timeout(
        Duration::from_secs(2),
        store.run_concurrent(async |_| {
            configure_transport(&mmio, ram).await;
        }),
    )
    .await
    .expect("transport configuration timeout")
    .expect("transport configured");
    mmio
}

async fn create_worker(
    listener: terra_platform::io::local::LocalListener,
) -> (wasmtime::Store<StandaloneHost<VsockDeviceHost>>, Worker) {
    let engine = device_engine().expect("engine");
    let ram = GuestRam::new(256 * 1024).expect("guest memory");
    let mut store = device_store(
        &engine,
        VsockDeviceHost::new(
            ram.clone(),
            terra_runtime::component::vsock::VsockHostService::new(
                terra_protocol::encode_frame(&support::artifacts::create_boot_plan())
                    .expect("plan encodes"),
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
    let serve: Serve = instance
        .get_typed_func(
            &mut store,
            component
                .get_export_index(Some(&device), "serve")
                .expect("serve"),
        )
        .expect("serve function");
    let mmio = start_mmio(&mut store, serve, &ram).await;
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
    (
        store,
        Worker {
            run,
            close,
            mmio,
            ram,
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
            Ok(0) => panic!("host input closed early"),
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

async fn send_guest_packet(worker: &Worker, available: &mut u16, bytes: &[u8]) -> bool {
    if worker.mmio.is_reset.load(Ordering::Acquire) {
        return false;
    }
    let (header, payload) = bytes.split_at(VSOCK_HEADER_BYTES);
    write_memory(&worker.ram, TX_HEADER, header);
    write_memory(
        &worker.ram,
        TX_DESC,
        &descriptor(
            TX_HEADER,
            u32::try_from(VSOCK_HEADER_BYTES).expect("header length"),
            u16::from(!payload.is_empty()),
            1,
        ),
    );
    if !payload.is_empty() {
        write_memory(&worker.ram, TX_DATA, payload);
        write_memory(
            &worker.ram,
            TX_DESC + 16,
            &descriptor(
                TX_DATA,
                u32::try_from(payload.len()).expect("payload length"),
                0,
                0,
            ),
        );
    }
    write_memory(
        &worker.ram,
        TX_AVAIL + 4 + u64::from(*available % QUEUE_SIZE) * 2,
        &0_u16.to_le_bytes(),
    );
    *available = available.wrapping_add(1);
    write_memory(&worker.ram, TX_AVAIL + 2, &available.to_le_bytes());
    worker.mmio.write(0x50, 1).await;
    while read_index(&worker.ram, TX_USED) != *available {
        if worker.mmio.is_reset.load(Ordering::Acquire) {
            return false;
        }
        tokio::task::yield_now().await;
    }
    true
}

async fn read_guest_replies(
    worker: &Worker,
    used: &mut u16,
    available: &mut u16,
) -> Vec<(VsockHeader, Vec<u8>)> {
    let mut replies = Vec::new();
    while *used != read_index(&worker.ram, RX_USED) {
        let entry = read_memory(
            &worker.ram,
            RX_USED + 4 + u64::from(*used % QUEUE_SIZE) * 8,
            8,
        );
        let head = u32::from_le_bytes(entry[..4].try_into().expect("used head"));
        let len = u32::from_le_bytes(entry[4..].try_into().expect("used length"));
        assert!(head < u32::from(QUEUE_SIZE));
        assert!(len <= RX_PACKET_BYTES);
        let bytes = read_memory(
            &worker.ram,
            RX_DATA + u64::from(head) * u64::from(RX_PACKET_BYTES),
            u64::from(len),
        );
        let (header, payload) = VsockHeader::parse(&bytes).expect("reply packet");
        replies.push((header, payload.to_vec()));
        write_memory(
            &worker.ram,
            RX_AVAIL + 4 + u64::from(*available % QUEUE_SIZE) * 2,
            &u16::try_from(head).expect("descriptor head").to_le_bytes(),
        );
        *available = available.wrapping_add(1);
        *used = used.wrapping_add(1);
    }
    if !replies.is_empty() && !worker.mmio.is_reset.load(Ordering::Acquire) {
        write_memory(&worker.ram, RX_AVAIL + 2, &available.to_le_bytes());
        worker.mmio.write(0x50, 0).await;
    }
    replies
}

async fn pump_carrier(
    worker: &Worker,
    source: u32,
    mut outbound_data: mpsc::UnboundedReceiver<Vec<u8>>,
    incoming_data: mpsc::UnboundedSender<io::Result<Vec<u8>>>,
    started: oneshot::Sender<()>,
) {
    let mut tx_available = 0;
    let mut rx_used = 0;
    let mut rx_available = QUEUE_SIZE;
    if !send_guest_packet(worker, &mut tx_available, &packet(source, 1, 0, &[])).await {
        return;
    }
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
            if !send_guest_packet(
                worker,
                &mut tx_available,
                &packet(source, 5, received, &bytes),
            )
            .await
            {
                return;
            }
            sent = sent.wrapping_add(u32::try_from(count).expect("frame length"));
        }
        if worker.mmio.is_reset.load(Ordering::Acquire) {
            return;
        }
        for (header, payload) in read_guest_replies(worker, &mut rx_used, &mut rx_available).await {
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
                    if incoming_data.unbounded_send(Ok(payload)).is_err() {
                        return;
                    }
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
            if !send_guest_packet(worker, &mut tx_available, &packet(source, 6, received, &[]))
                .await
            {
                return;
            }
            acknowledged = received;
        }
    }
}

fn guest_carrier(
    worker: &Worker,
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
            worker,
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
/// one guest-initiated Yamux connection. Each sender runs alongside its receiver
/// so payloads larger than socket buffers and stream windows make progress.
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
            let (carrier, started, pump) = guest_carrier(&worker, CARRIER_SOURCE);
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
                diagnostics.close().await.expect("diagnostic EOF");
                let request = vec![b'q'; PAYLOAD_BYTES];
                let mut stream = poll_fn(|context| connection.poll_next_inbound(context))
                    .await
                    .expect("carrier remains open")
                    .expect("client stream");
                let exchange = async {
                    let mut received = vec![0; PAYLOAD_BYTES];
                    let ((), result) = tokio::join!(
                        write_local(&mut client, &request),
                        stream.read_exact(&mut received),
                    );
                    result.expect("guest input");
                    assert_eq!(received, request);
                    let response = vec![b'r'; PAYLOAD_BYTES];
                    let send = async {
                        stream.write_all(&response).await.expect("guest output");
                        stream.close().await.expect("guest finish");
                    };
                    let receive = async {
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
                    let ((), received) = tokio::join!(send, receive);
                    received
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
                tokio::join!(guest, pump);
                wait_for_lifecycle_events(&worker.events).await;
                worker
                    .close
                    .call_concurrent(accessor, ())
                    .await
                    .expect("close");
            };
            let ((), result) = tokio::join!(close, run);
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
    assert_session_releases_client(SessionEnd::DeviceReset).await;
}

#[tokio::test(flavor = "current_thread")]
async fn control_eof_releases_the_open_client() {
    assert_session_releases_client(SessionEnd::ControlEof).await;
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_lifecycle_releases_the_open_client() {
    assert_session_releases_client(SessionEnd::MalformedLifecycle).await;
}

enum SessionEnd {
    DeviceReset,
    ControlEof,
    MalformedLifecycle,
}

async fn assert_session_releases_client(end: SessionEnd) {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("reset.sock");
    let listener = terra_platform::io::local::LocalListener::bind(&path).expect("listener");
    let mut client = terra_platform::io::local::LocalStream::connect(&path).expect("client");
    client.set_nonblocking(true).expect("nonblocking client");
    let (mut store, worker) = create_worker(listener).await;
    tokio::time::timeout(
        Duration::from_secs(5),
        store.run_concurrent(async |accessor| {
            let (carrier, started, pump) = guest_carrier(&worker, CARRIER_SOURCE);
            let run = worker.run.call_concurrent(accessor, ());
            let end_session = async {
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
                match end {
                    SessionEnd::DeviceReset => worker.mmio.write(0x70, 0).await,
                    SessionEnd::ControlEof => control.close().await.expect("control EOF"),
                    SessionEnd::MalformedLifecycle => control
                        .write_all(&u32::MAX.to_le_bytes())
                        .await
                        .expect("malformed lifecycle"),
                }
                (connection, control, diagnostics, guest_client)
            };
            let guest = async {
                let (mut connection, _control, _diagnostics, _guest_client) = end_session.await;
                let drive = poll_fn(|context| {
                    let _ = connection.poll_next_inbound(context);
                    Poll::<()>::Pending
                });
                let disconnected = async {
                    tokio::time::timeout(Duration::from_secs(2), async {
                        loop {
                            match client.read(&mut [0; 1]) {
                                Ok(0) => return,
                                Ok(_) => panic!("closed session client received data"),
                                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                    tokio::time::sleep(Duration::from_millis(1)).await;
                                }
                                Err(error) => panic!("closed session client read: {error}"),
                            }
                        }
                    })
                    .await
                    .expect("session end closes host client");
                };
                futures_util::pin_mut!(disconnected, drive);
                let _ = futures_util::future::select(disconnected, drive).await;
                assert_eq!(
                    accessor.with(|mut access| access.get().vsock_service_mut().live_clients()),
                    0
                );
            };
            let close = async {
                tokio::join!(guest, pump);
                worker
                    .close
                    .call_concurrent(accessor, ())
                    .await
                    .expect("close");
            };
            let ((), result) = tokio::join!(close, run);
            result.expect("worker call").0.expect("worker result");
            Ok::<(), wasmtime::Error>(())
        }),
    )
    .await
    .expect("session teardown test timeout")
    .expect("component run")
    .expect("component result");
}
