use crate::exports::terra::vsock::api::{Error, Event};
use crate::terra::vsock::host_service;
use crate::wasi::{
    clocks::{monotonic_clock, system_clock},
    random::random,
};
use crate::{CLOSED, carrier, sample_clock, transport, wait_for_work, wake_worker};
use futures_channel::mpsc::{self, Sender};
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::{
    SinkExt as _, StreamExt,
    future::{AbortHandle, Abortable, Either, poll_fn},
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    task::AtomicWaker,
};
use std::{
    collections::BTreeMap,
    sync::{LazyLock, Mutex},
    task::Poll,
};
use terra_protocol::{
    MAX_PLAN_BYTES, MAX_PLAN_HOST_STATE_BYTES,
    control::{MAX_DIAGNOSTIC_FRAME_BYTES, encode_clock_sync},
    mux::{MAX_CLIENT_STREAMS, MAX_STREAM_FRAME_BYTES},
};

const MAX_PLAN_FRAME_BYTES: usize = MAX_PLAN_BYTES + 4;
const STOP_SIGNAL: u8 = b'S';
const MAX_WORKER_TASKS: usize = MAX_CLIENT_STREAMS + 4;

type StreamReader<T> = wit_bindgen::rt::async_support::StreamReader<T>;
type StreamResult = wit_bindgen::rt::async_support::StreamResult;

struct Worker {
    plan: StreamReader<u8>,
    stop: StreamReader<u8>,
    listener: Option<StreamReader<host_service::Client>>,
    event_sender: Sender<Event>,
}

static RUN: futures_util::lock::Mutex<()> = futures_util::lock::Mutex::new(());
static WORKER: LazyLock<Mutex<Option<Worker>>> = LazyLock::new(|| Mutex::new(None));
static PENDING_PLAN: LazyLock<Mutex<Vec<u8>>> = LazyLock::new(|| Mutex::new(Vec::new()));
static PENDING_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static CLOCK_TICK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static PLAN_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static TRANSPORT_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static CONTROL_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static CONTROL_WAKER: AtomicWaker = AtomicWaker::new();
static TASKS: LazyLock<Mutex<BTreeMap<u64, AbortHandle>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static SESSION_TASKS: LazyLock<Mutex<BTreeMap<u64, AbortHandle>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static NEXT_TASK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static CARRIER_SESSION: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static ACTIVE_CLIENTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn spawn_task(future: impl core::future::Future<Output = ()> + 'static) -> bool {
    let (handle, registration) = AbortHandle::new_pair();
    let id = NEXT_TASK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    {
        let mut tasks = TASKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if tasks.len() >= MAX_WORKER_TASKS {
            return false;
        }
        tasks.insert(id, handle);
    }
    wit_bindgen::rt::async_support::spawn_local(async move {
        let _ = Abortable::new(future, registration).await;
        TASKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
        wake_worker();
    });
    true
}

fn abort_tasks() {
    for task in TASKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .values()
    {
        task.abort();
    }
}

fn spawn_session_task(future: impl core::future::Future<Output = ()> + 'static) -> bool {
    let (handle, registration) = AbortHandle::new_pair();
    let id = NEXT_TASK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    {
        let mut tasks = SESSION_TASKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if tasks.len() >= MAX_WORKER_TASKS {
            return false;
        }
        tasks.insert(id, handle);
    }
    wit_bindgen::rt::async_support::spawn_local(async move {
        let _ = Abortable::new(future, registration).await;
        SESSION_TASKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
        wake_worker();
    });
    true
}

fn abort_session_tasks() {
    for task in SESSION_TASKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .values()
    {
        task.abort();
    }
}

async fn finish_tasks() {
    while !TASKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_empty()
    {
        wit_bindgen::rt::async_support::yield_async().await;
    }
}

async fn finish_session_tasks() {
    while !SESSION_TASKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_empty()
    {
        wit_bindgen::rt::async_support::yield_async().await;
    }
}

pub(crate) fn events() -> StreamReader<Event> {
    if WORKER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_some()
    {
        let (writer, reader) = crate::wit_stream::new();
        drop(writer);
        return reader;
    }
    PENDING_PLAN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    PENDING_STOP.store(false, std::sync::atomic::Ordering::Release);
    CLOCK_TICK.store(false, std::sync::atomic::Ordering::Release);
    PLAN_READY.store(false, std::sync::atomic::Ordering::Release);
    let (mut event_writer, event_reader) = crate::wit_stream::new();
    let (event_sender, mut event_receiver) = mpsc::channel(64);
    let _ = spawn_task(async move {
        while let Some(event) = event_receiver.next().await {
            if !event_writer.write_all(vec![event]).await.is_empty() {
                return;
            }
            wake_worker();
        }
    });
    *WORKER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Worker {
        plan: host_service::plan(),
        stop: host_service::stop(),
        listener: host_service::listener(),
        event_sender,
    });
    event_reader
}

pub(crate) fn wake_carrier() {
    carrier::wake();
}

pub(crate) fn schedule_receive_queue() {
    if transport::queue_notify(0).is_ok() {
        wake_worker();
    }
}

fn wake_control() {
    CONTROL_EPOCH.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    CONTROL_WAKER.wake();
}

pub(crate) fn begin_carrier_session() {
    CARRIER_SESSION.store(true, std::sync::atomic::Ordering::Release);
    ACTIVE_CLIENTS.store(0, std::sync::atomic::Ordering::Release);
}

pub(crate) fn reset_session() {
    if !CARRIER_SESSION.swap(false, std::sync::atomic::Ordering::AcqRel) {
        return;
    }
    abort_session_tasks();
    ACTIVE_CLIENTS.store(0, std::sync::atomic::Ordering::Release);
    wake_control();
    wake_carrier();
    wake_worker();
}

pub(crate) fn set_transport_ready(ready: bool) {
    TRANSPORT_READY.store(ready, std::sync::atomic::Ordering::Release);
}

async fn read_all(mut stream: StreamReader<u8>, limit: usize) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(limit);
    loop {
        let (result, next) = stream.read(bytes).await;
        bytes = next;
        if bytes.len() > limit {
            return None;
        }
        match result {
            StreamResult::Complete(read) if read > 0 => {}
            StreamResult::Complete(_) | StreamResult::Dropped => return Some(bytes),
            StreamResult::Cancelled => return None,
        }
    }
}

fn enrich_plan(frame: Vec<u8>) -> Option<Vec<u8>> {
    let instant = system_clock::now();
    let seed = (0..4)
        .flat_map(|_| random::get_random_u64().to_le_bytes())
        .map(serde_json::Value::from)
        .collect();
    enrich_plan_with_host_state(frame, instant.seconds, instant.nanoseconds, seed)
}

fn enrich_plan_with_host_state(
    mut frame: Vec<u8>,
    seconds: i64,
    nanoseconds: u32,
    seed: Vec<serde_json::Value>,
) -> Option<Vec<u8>> {
    let payload_len = usize::try_from(u32::from_le_bytes(frame.get(..4)?.try_into().ok()?)).ok()?;
    if payload_len > MAX_PLAN_BYTES || frame.len() != payload_len.checked_add(4)? {
        return None;
    }
    let mut plan: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&frame[4..]).ok()?;
    if nanoseconds >= 1_000_000_000 || seed.len() != 32 {
        return None;
    }
    plan.insert(
        "host_time".into(),
        serde_json::json!({"seconds": seconds, "nanoseconds": nanoseconds}),
    );
    plan.insert("host_seed".into(), serde_json::Value::Array(seed));
    let payload = serde_json::to_vec(&plan).ok()?;
    if payload.len() > MAX_PLAN_BYTES
        || payload.len().saturating_sub(payload_len) > MAX_PLAN_HOST_STATE_BYTES
        || payload.len() > u32::MAX as usize
    {
        return None;
    }
    frame.clear();
    frame.extend_from_slice(&u32::try_from(payload.len()).ok()?.to_le_bytes());
    frame.extend_from_slice(&payload);
    Some(frame)
}

fn start_plan(plan: StreamReader<u8>) {
    let _ = spawn_task(async move {
        let Some(frame) = read_all(plan, MAX_PLAN_FRAME_BYTES)
            .await
            .and_then(enrich_plan)
        else {
            CLOSED.store(true, std::sync::atomic::Ordering::Release);
            wake_worker();
            return;
        };
        *PENDING_PLAN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = frame;
        PLAN_READY.store(true, std::sync::atomic::Ordering::Release);
        wake_control();
        wake_worker();
    });
}

fn start_stop(mut stop: StreamReader<u8>) {
    let _ = spawn_task(async move {
        let (result, bytes) = stop.read(Vec::with_capacity(1)).await;
        if matches!(result, StreamResult::Complete(1)) && bytes.as_slice() == [STOP_SIGNAL] {
            PENDING_STOP.store(true, std::sync::atomic::Ordering::Release);
            wake_control();
        }
    });
}

fn start_clock() {
    let _ = spawn_task(async {
        while !CLOSED.load(std::sync::atomic::Ordering::Acquire) {
            monotonic_clock::wait_for(1_000_000_000).await;
            CLOCK_TICK.store(true, std::sync::atomic::Ordering::Release);
            wake_control();
        }
    });
}

fn start_listener(
    mut listener: StreamReader<host_service::Client>,
    mut clients: Sender<host_service::Client>,
) {
    let _ = spawn_task(async move {
        loop {
            let (result, batch) = listener.read(Vec::with_capacity(1)).await;
            let StreamResult::Complete(count) = result else {
                return;
            };
            if count == 0 {
                return;
            }
            for client in batch.into_iter().take(count) {
                if clients.try_send(client).is_err() {
                    return;
                }
            }
        }
    });
}

fn next_control() -> Option<Vec<u8>> {
    let mut plan = PENDING_PLAN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !plan.is_empty() {
        let count = plan.len().min(MAX_STREAM_FRAME_BYTES);
        return Some(plan.drain(..count).collect());
    }
    if !PLAN_READY.load(std::sync::atomic::Ordering::Acquire) {
        return None;
    }
    if PENDING_STOP.swap(false, std::sync::atomic::Ordering::AcqRel) {
        return Some(vec![STOP_SIGNAL]);
    }
    if CLOCK_TICK.swap(false, std::sync::atomic::Ordering::AcqRel)
        && let Some((seconds, nanoseconds)) = sample_clock()
    {
        return Some(encode_clock_sync(seconds, nanoseconds).to_vec());
    }
    None
}

async fn wait_for_control(observed: &mut u64) {
    poll_fn(|context| {
        CONTROL_WAKER.register(context.waker());
        let epoch = CONTROL_EPOCH.load(std::sync::atomic::Ordering::Acquire);
        if CLOSED.load(std::sync::atomic::Ordering::Acquire) || epoch != *observed {
            *observed = epoch;
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

async fn write_control(mut stream: impl AsyncWrite + Unpin) {
    let mut observed = CONTROL_EPOCH.load(std::sync::atomic::Ordering::Acquire);
    while !CLOSED.load(std::sync::atomic::Ordering::Acquire) {
        if let Some(bytes) = next_control() {
            if stream.write_all(&bytes).await.is_err() {
                return;
            }
        } else {
            wait_for_control(&mut observed).await;
        }
    }
}

async fn read_lifecycle(mut stream: impl AsyncRead + Unpin, mut sender: Sender<Event>) {
    let mut bytes = Vec::new();
    let mut buffer = [0; MAX_STREAM_FRAME_BYTES];
    loop {
        let remaining = MAX_PLAN_BYTES.saturating_sub(bytes.len());
        if remaining == 0 {
            return;
        }
        let Ok(count) = stream
            .read(&mut buffer[..remaining.min(MAX_STREAM_FRAME_BYTES)])
            .await
        else {
            return;
        };
        if count == 0 || bytes.len().saturating_add(count) > MAX_PLAN_BYTES {
            return;
        }
        bytes.extend_from_slice(&buffer[..count]);
        while !bytes.is_empty() {
            let Ok(result) = crate::lifecycle::decode_control(&bytes) else {
                return;
            };
            let consumed = result.consumed as usize;
            if consumed > bytes.len() {
                return;
            }
            bytes.drain(..consumed);
            if result.agent_ready && sender.send(Event::AgentReady).await.is_err() {
                return;
            }
            if let Some(code) = result.exit_code
                && sender.send(Event::Exit(code)).await.is_err()
            {
                return;
            }
            if consumed == 0 {
                break;
            }
        }
    }
}

async fn read_diagnostics(mut stream: impl AsyncRead + Unpin, mut sender: Sender<Event>) {
    let mut bytes = Vec::new();
    let mut buffer = [0; MAX_STREAM_FRAME_BYTES];
    loop {
        let remaining = MAX_DIAGNOSTIC_FRAME_BYTES.saturating_sub(bytes.len());
        if remaining == 0 {
            return;
        }
        let Ok(count) = stream
            .read(&mut buffer[..remaining.min(MAX_STREAM_FRAME_BYTES)])
            .await
        else {
            return;
        };
        if count == 0 || bytes.len().saturating_add(count) > MAX_DIAGNOSTIC_FRAME_BYTES {
            return;
        }
        bytes.extend_from_slice(&buffer[..count]);
        while !bytes.is_empty() {
            let Ok(result) = crate::lifecycle::decode_diagnostics(&bytes) else {
                return;
            };
            let consumed = result.consumed as usize;
            if consumed > bytes.len() {
                return;
            }
            bytes.drain(..consumed);
            if !result.output.is_empty()
                && sender.send(Event::Diagnostic(result.output)).await.is_err()
            {
                return;
            }
            if consumed == 0 {
                break;
            }
        }
    }
}

fn bridge_client(stream: yamux::Stream, client: host_service::Client) {
    let (mut reader, mut writer) = futures_util::io::AsyncReadExt::split(stream);
    let mut input = client.input();
    let (mut output_writer, output) = crate::wit_stream::new();
    let started = spawn_session_task(async move {
        let client_output = client.output(output);
        let to_host = async {
            let mut buffer = [0; MAX_STREAM_FRAME_BYTES];
            loop {
                let Ok(count) = reader.read(&mut buffer).await else {
                    return;
                };
                if count == 0
                    || !output_writer
                        .write_all(buffer[..count].to_vec())
                        .await
                        .is_empty()
                {
                    return;
                }
            }
        };
        let to_guest = async {
            loop {
                let (result, bytes) = input.read(Vec::with_capacity(MAX_STREAM_FRAME_BYTES)).await;
                match result {
                    StreamResult::Complete(count) if count > 0 && count <= bytes.len() => {
                        if writer.write_all(&bytes[..count]).await.is_err() {
                            return;
                        }
                    }
                    StreamResult::Complete(_) | StreamResult::Dropped | StreamResult::Cancelled => {
                        let _ = writer.close().await;
                        return;
                    }
                }
            }
        };
        let _ = Box::pin(futures_util::future::join3(
            client_output,
            to_host,
            to_guest,
        ))
        .await;
        ACTIVE_CLIENTS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        wake_worker();
    });
    if !started {
        ACTIVE_CLIENTS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

fn reserve_client() -> bool {
    let mut active = ACTIVE_CLIENTS.load(std::sync::atomic::Ordering::Acquire);
    loop {
        if active >= MAX_CLIENT_STREAMS {
            return false;
        }
        match ACTIVE_CLIENTS.compare_exchange_weak(
            active,
            active + 1,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(current) => active = current,
        }
    }
}

fn poll_new_client(
    connection: &mut yamux::Connection<carrier::Carrier>,
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

async fn next_inbound(
    connection: &mut yamux::Connection<carrier::Carrier>,
) -> Option<yamux::Stream> {
    match poll_fn(|context| connection.poll_next_inbound(context)).await {
        Some(Ok(stream)) => Some(stream),
        Some(Err(_)) | None => None,
    }
}

async fn run_mux(
    carrier: carrier::Carrier,
    clients: Option<mpsc::Receiver<host_service::Client>>,
    event_sender: Sender<Event>,
) {
    run_mux_inner(carrier, clients, event_sender).await;
    reset_session();
}

async fn run_mux_inner(
    carrier: carrier::Carrier,
    mut clients: Option<mpsc::Receiver<host_service::Client>>,
    event_sender: Sender<Event>,
) {
    let mut connection = yamux::Connection::new(
        carrier,
        terra_protocol::mux::yamux_config(),
        yamux::Mode::Server,
    );
    let Some(control) = next_inbound(&mut connection).await else {
        return;
    };
    let Some(diagnostics) = next_inbound(&mut connection).await else {
        return;
    };
    if control.id().val() != terra_protocol::mux::CONTROL_STREAM_ID
        || diagnostics.id().val() != terra_protocol::mux::DIAGNOSTIC_STREAM_ID
    {
        return;
    }
    let (control_reader, control_writer) = futures_util::io::AsyncReadExt::split(control);
    let _ = spawn_session_task(write_control(control_writer));
    let _ = spawn_session_task(read_lifecycle(control_reader, event_sender.clone()));
    let _ = spawn_session_task(read_diagnostics(diagnostics, event_sender));
    loop {
        let Some(client_receiver) = clients.as_mut() else {
            let _ = next_inbound(&mut connection).await;
            return;
        };
        let inbound = poll_fn(|context| connection.poll_next_inbound(context));
        let client = client_receiver.next();
        futures_util::pin_mut!(inbound, client);
        match futures_util::future::select(inbound, client).await {
            Either::Left((_unexpected, _)) => return,
            Either::Right((Some(client), _)) => {
                if !reserve_client() {
                    continue;
                }
                let Ok(mut stream) =
                    poll_fn(|context| poll_new_client(&mut connection, context)).await
                else {
                    ACTIVE_CLIENTS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                    return;
                };
                if stream.write(&[]).await.is_err() {
                    return;
                }
                bridge_client(stream, client);
            }
            Either::Right((None, _)) => clients = None,
        }
    }
}

pub(crate) async fn finish() {
    let _running = RUN.lock().await;
    WORKER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    CARRIER_SESSION.store(false, std::sync::atomic::Ordering::Release);
    abort_tasks();
    abort_session_tasks();
    finish_tasks().await;
    finish_session_tasks().await;
}

pub(crate) async fn run() -> Result<(), Error> {
    let _running = RUN.lock().await;
    let worker = WORKER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let result = match worker {
        Some(worker) if !CLOSED.load(std::sync::atomic::Ordering::Acquire) => {
            run_worker(worker).await
        }
        Some(_) => Ok(()),
        None => CLOSED
            .load(std::sync::atomic::Ordering::Acquire)
            .then_some(())
            .ok_or(Error::Malformed),
    };
    CARRIER_SESSION.store(false, std::sync::atomic::Ordering::Release);
    abort_tasks();
    abort_session_tasks();
    finish_tasks().await;
    finish_session_tasks().await;
    result
}

async fn run_worker(worker: Worker) -> Result<(), Error> {
    start_plan(worker.plan);
    start_stop(worker.stop);
    let (client_sender, client_receiver) = mpsc::channel(MAX_CLIENT_STREAMS);
    let clients = worker.listener.map(|listener| {
        start_listener(listener, client_sender);
        client_receiver
    });
    start_clock();
    let mut clients = Some(clients);
    let mut session_started = false;
    while !CLOSED.load(std::sync::atomic::Ordering::Acquire) {
        wait_for_work().await;
        let mut pending = false;
        for _ in 0..8 {
            pending = transport::process_pending().unwrap_or(false);
            wake_carrier();
            if !pending {
                break;
            }
            wit_bindgen::rt::async_support::yield_async().await;
        }
        if pending {
            wake_worker();
        }
        if !session_started
            && TRANSPORT_READY.load(std::sync::atomic::Ordering::Acquire)
            && let Some(carrier) = carrier::Carrier::accept()
            && let Some(clients) = clients.take()
        {
            session_started = true;
            begin_carrier_session();
            let _ = spawn_session_task(run_mux(carrier, clients, worker.event_sender.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_enrichment_preserves_plan_fields_and_adds_host_state() {
        let payload = br#"{"timezone":"Europe/Bratislava","mounts":["work"]}"#;
        let mut frame = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
        frame.extend_from_slice(payload);
        let seed = (0..32).map(serde_json::Value::from).collect();
        let frame = enrich_plan_with_host_state(frame, 12, 34, seed).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&frame[4..]).unwrap();
        assert_eq!(value["timezone"], "Europe/Bratislava");
        assert_eq!(value["mounts"][0], "work");
        assert_eq!(value["host_time"]["seconds"], 12);
        assert_eq!(value["host_seed"].as_array().unwrap().len(), 32);
    }
    #[test]
    fn maximum_host_plan_fits_after_host_state_enrichment() {
        let limit = MAX_PLAN_BYTES - MAX_PLAN_HOST_STATE_BYTES;
        let mut plan = serde_json::json!({"padding": ""});
        let overhead = serde_json::to_vec(&plan).unwrap().len();
        plan["padding"] = serde_json::Value::String("x".repeat(limit - overhead));
        let frame = terra_protocol::encode_frame_with_limit(&plan, limit).unwrap();
        assert_eq!(frame.len(), limit + 4);
        let seed = vec![serde_json::Value::from(u8::MAX); 32];
        let frame = enrich_plan_with_host_state(frame, i64::MIN, 999_999_999, seed).unwrap();
        assert!(frame.len() <= MAX_PLAN_FRAME_BYTES);
        let decoded: serde_json::Value =
            terra_protocol::read_frame_with_limit(&mut frame.as_slice(), MAX_PLAN_BYTES)
                .unwrap()
                .unwrap();
        assert_eq!(decoded["padding"], plan["padding"]);
    }
}
