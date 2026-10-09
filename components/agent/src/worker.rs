use crate::byte_stream::ByteStream;
use crate::exports::terra::agent::api::Event;
use crate::lifecycle::{Diagnostic, read_diagnostics, read_lifecycle};
use crate::terra::agent::host_service;
use crate::wasi::clocks::{monotonic_clock, system_clock};
use crate::{is_closed, wait_closed};
use futures_channel::{
    mpsc::{self, Sender},
    oneshot,
};
use futures_io::AsyncWrite;
use futures_util::{
    FutureExt as _, SinkExt as _, Stream, StreamExt as _,
    future::{self, poll_fn},
    io::{AsyncReadExt, AsyncWriteExt as _},
    stream::{self, FuturesUnordered, PollNext},
};
use std::{pin::pin, task::Poll};
use terra_protocol::{
    control::{STOP_SIGNAL, encode_clock_sync},
    mux::{MAX_CLIENT_STREAMS, MAX_STREAM_FRAME_BYTES},
};

type StreamReader<T> = wit_bindgen::rt::async_support::StreamReader<T>;
type StreamWriter<T> = wit_bindgen::rt::async_support::StreamWriter<T>;
type StreamResult = wit_bindgen::rt::async_support::StreamResult;

struct Worker {
    events: StreamWriter<Event>,
    plan: Vec<u8>,
    stop: StreamReader<u8>,
    listener: Option<StreamReader<host_service::Client>>,
}

pub(crate) fn events() -> StreamReader<Event> {
    let (writer, reader) = crate::wit_stream::new();
    if !is_closed() && !STARTED.swap(true, std::sync::atomic::Ordering::AcqRel) {
        let worker = Worker {
            events: writer,
            plan: host_service::plan(),
            stop: host_service::stop(),
            listener: host_service::listener(),
        };
        wit_bindgen::rt::async_support::spawn_local(run_worker(worker));
    }
    reader
}

static STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Polls `side` alongside `main` and returns `main`'s output; `side` finishing first is ignored.
async fn alongside<T>(main: impl Future<Output = T>, side: impl Future<Output = ()>) -> T {
    let side = side.then(|()| future::pending());
    future::select(pin!(main), pin!(side))
        .await
        .factor_first()
        .0
}

/// Writes lifecycle events ahead of diagnostics, acknowledging each diagnostic once the host takes it.
async fn forward_events(
    mut writer: StreamWriter<Event>,
    lifecycle: mpsc::Receiver<Event>,
    diagnostics: mpsc::Receiver<Diagnostic>,
) {
    let lifecycle = lifecycle.map(|event| (event, None));
    let diagnostics =
        diagnostics.map(|diagnostic| (Event::Diagnostic(diagnostic.bytes), diagnostic.delivered));
    let mut events =
        stream::select_with_strategy(lifecycle, diagnostics, |(): &mut ()| PollNext::Left);
    while let Some((event, delivered)) = events.next().await {
        if writer.write_one(event).await.is_some() {
            return;
        }
        if let Some(delivered) = delivered {
            let _ = delivered.send(());
        }
    }
}

/// Resolves when the host requests a graceful stop; never when the stop stream ends without one.
async fn wait_for_stop(mut stop: StreamReader<u8>) {
    if stop.next().await != Some(STOP_SIGNAL) {
        future::pending::<()>().await;
    }
}

fn clock_syncs() -> impl Stream<Item = Vec<u8>> {
    stream::unfold(None, |mut previous| async move {
        loop {
            monotonic_clock::wait_for(1_000_000_000).await;
            let monotonic = monotonic_clock::now();
            let instant = system_clock::now();
            let sample = (
                monotonic,
                i128::from(instant.seconds) * 1_000_000_000 + i128::from(instant.nanoseconds),
            );
            if previous.is_some_and(|previous| !crate::clock_update_due(previous, sample)) {
                continue;
            }
            previous = Some(sample);
            return Some((
                encode_clock_sync(instant.seconds, instant.nanoseconds).to_vec(),
                previous,
            ));
        }
    })
}

/// Writes the boot plan, then the stop signal and clock syncs as they come.
async fn write_control(mut stream: impl AsyncWrite + Unpin, plan: Vec<u8>, stop: StreamReader<u8>) {
    if stream.write_all(&plan).await.is_err() {
        return;
    }
    let stop = stream::once(wait_for_stop(stop)).map(|()| vec![STOP_SIGNAL]);
    let mut messages = pin!(stream::select_with_strategy(
        stop,
        clock_syncs(),
        |(): &mut ()| PollNext::Left
    ));
    while let Some(bytes) = messages.next().await {
        if stream.write_all(&bytes).await.is_err() {
            return;
        }
    }
}

fn read_clients(
    listener: StreamReader<host_service::Client>,
) -> impl Stream<Item = host_service::Client> {
    stream::unfold(listener, |mut listener| async move {
        listener.next().await.map(|client| (client, listener))
    })
}

async fn bridge_client(stream: yamux::Stream, client: host_service::Client) {
    let (mut guest_reader, mut guest_writer) = AsyncReadExt::split(stream);
    let (mut output_writer, output) = crate::wit_stream::new();
    let mut host_reader = client.input();
    let to_host = async move {
        let mut bytes = vec![0; MAX_STREAM_FRAME_BYTES];
        loop {
            let Ok(count) = guest_reader.read(&mut bytes).await else {
                return;
            };
            if count == 0 {
                return;
            }
            bytes.truncate(count);
            bytes = output_writer.write_all(bytes).await;
            if !bytes.is_empty() {
                return;
            }
            bytes.resize(MAX_STREAM_FRAME_BYTES, 0);
        }
    };
    let to_guest = async move {
        let mut bytes = Vec::with_capacity(MAX_STREAM_FRAME_BYTES);
        loop {
            let (result, buffer) = host_reader.read(bytes).await;
            bytes = buffer;
            if guest_writer.write_all(&bytes).await.is_err() {
                break;
            }
            if !matches!(result, StreamResult::Complete(_)) {
                break;
            }
            bytes.clear();
        }
        let _ = guest_writer.close().await;
    };
    let _ = future::join3(client.output(output), to_host, to_guest).await;
}

fn poll_new_client(
    connection: &mut yamux::Connection<ByteStream>,
    context: &mut std::task::Context<'_>,
) -> Poll<Result<yamux::Stream, ()>> {
    match connection.poll_next_inbound(context) {
        Poll::Ready(Some(Ok(_) | Err(_)) | None) => {
            return Poll::Ready(Err(()));
        }
        Poll::Pending => {}
    }
    connection.poll_new_outbound(context).map_err(|_| ())
}

async fn next_inbound(connection: &mut yamux::Connection<ByteStream>) -> Option<yamux::Stream> {
    match poll_fn(|context| connection.poll_next_inbound(context)).await {
        Some(Ok(stream)) => Some(stream),
        Some(Err(_)) | None => None,
    }
}

async fn run_mux(
    carrier: ByteStream,
    plan: Vec<u8>,
    stop: StreamReader<u8>,
    listener: Option<StreamReader<host_service::Client>>,
    events: Sender<Event>,
    diagnostics: Sender<Diagnostic>,
) {
    let mut connection = yamux::Connection::new(
        carrier,
        terra_protocol::mux::yamux_config(),
        yamux::Mode::Server,
    );
    let Some(control) = next_inbound(&mut connection).await else {
        return;
    };
    if control.id().val() != terra_protocol::mux::CONTROL_STREAM_ID {
        return;
    }
    let (control_reader, control_writer) = AsyncReadExt::split(control);
    let control = async {
        future::select(
            pin!(write_control(control_writer, plan, stop)),
            pin!(read_lifecycle(control_reader, events)),
        )
        .await;
    };
    let clients = async move {
        let Some(diagnostic_stream) = next_inbound(&mut connection).await else {
            return;
        };
        if diagnostic_stream.id().val() != terra_protocol::mux::DIAGNOSTIC_STREAM_ID {
            return;
        }
        alongside(
            serve_clients(connection, listener),
            read_diagnostics(diagnostic_stream, diagnostics),
        )
        .await;
    };
    future::select(pin!(control), pin!(clients)).await;
}

enum MuxEvent {
    /// The guest opened an unexpected stream or the connection ended.
    SessionEnded,
    Client(host_service::Client),
    ListenerClosed,
}

async fn serve_clients(
    mut connection: yamux::Connection<ByteStream>,
    listener: Option<StreamReader<host_service::Client>>,
) {
    let mut clients = listener.map(|listener| Box::pin(read_clients(listener)));
    let mut bridges = FuturesUnordered::new();
    loop {
        let event = poll_fn(|context| {
            while let Poll::Ready(Some(())) = bridges.poll_next_unpin(context) {}
            if connection.poll_next_inbound(context).is_ready() {
                return Poll::Ready(MuxEvent::SessionEnded);
            }
            match clients
                .as_mut()
                .map(|clients| clients.poll_next_unpin(context))
            {
                Some(Poll::Ready(Some(client))) => Poll::Ready(MuxEvent::Client(client)),
                Some(Poll::Ready(None)) => Poll::Ready(MuxEvent::ListenerClosed),
                Some(Poll::Pending) | None => Poll::Pending,
            }
        })
        .await;
        match event {
            MuxEvent::SessionEnded => return,
            MuxEvent::ListenerClosed => clients = None,
            MuxEvent::Client(client) => {
                if bridges.len() >= MAX_CLIENT_STREAMS {
                    continue;
                }
                let Ok(mut stream) =
                    poll_fn(|context| poll_new_client(&mut connection, context)).await
                else {
                    return;
                };
                if stream.write(&[]).await.is_err() {
                    return;
                }
                bridges.push(bridge_client(stream, client));
            }
        }
    }
}

async fn run_session(
    plan: Vec<u8>,
    stop: StreamReader<u8>,
    listener: Option<StreamReader<host_service::Client>>,
    mut events: Sender<Event>,
    mut diagnostics: Sender<Diagnostic>,
) {
    let Some(carrier) = ByteStream::accept_carrier().await else {
        return future::pending().await;
    };
    if events.send(Event::Connected).await.is_err() {
        return;
    }
    Box::pin(run_mux(
        carrier,
        plan,
        stop,
        listener,
        events.clone(),
        diagnostics.clone(),
    ))
    .await;
    if is_closed() {
        return;
    }
    let _ = events.send(Event::Disconnected).await;
    let (delivered, delivery) = oneshot::channel();
    let _ = diagnostics
        .send(Diagnostic {
            bytes: b"terra: agent vsock connection lost; restart the box".to_vec(),
            delivered: Some(delivered),
        })
        .await;
    let _ = delivery.await;
}

async fn run_worker(worker: Worker) {
    let Worker {
        events,
        plan,
        stop,
        listener,
    } = worker;
    let (event_sender, event_receiver) = mpsc::channel(8);
    let (diagnostic_sender, diagnostic_receiver) = mpsc::channel(64);
    let work = alongside(
        run_session(plan, stop, listener, event_sender, diagnostic_sender),
        forward_events(events, event_receiver, diagnostic_receiver),
    );
    future::select(pin!(work), pin!(wait_closed())).await;
}
