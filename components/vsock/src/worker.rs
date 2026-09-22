use crate::exports::terra::vsock::api::{Error, Event};
use crate::terra::vsock::host_service;
use crate::wasi::{
    clocks::{monotonic_clock, system_clock},
    random::random,
};
use crate::{CLOSED, sample_clock, switch, transport, wait_for_work, wake_worker};
use futures_channel::mpsc::{self, Sender};
use futures_util::StreamExt;
use futures_util::{
    future::{AbortHandle, Abortable, poll_fn},
    task::AtomicWaker,
};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, LazyLock, Mutex};
use std::task::Poll;
use terra_protocol::control::encode_clock_sync;
use terra_protocol::{
    MAX_PLAN_BYTES, MAX_PLAN_HOST_STATE_BYTES,
    control::{AGENT_VSOCK_PORT, MAX_DIAGNOSTIC_FRAME_BYTES},
};
use terra_vsock_device::{CONTROL_VSOCK_PORT, DIAGNOSTIC_VSOCK_PORT};

const MAX_CLIENTS: usize = 64;
const MAX_STREAM_BYTES: usize = 1 << 20;
const MAX_CLIENT_BYTES: usize = 16 * 1024;
const MAX_PLAN_BYTES_PER_TURN: usize = 16 * 1024;
const PLAN_CHUNK_BYTES: usize = 2048;
const MAX_PLAN_FRAME_BYTES: usize = MAX_PLAN_BYTES + 4;
const STOP_SIGNAL: u8 = b'S';
const MAX_WORKER_TASKS: usize = MAX_CLIENTS * 5 + 5;
const CONNECT_RETRY_DELAY: u64 = 100_000_000;
const CLIENT_WAIT_TIMEOUT: u64 = 5_000_000_000;

type StreamReader<T> = wit_bindgen::rt::async_support::StreamReader<T>;
type StreamResult = wit_bindgen::rt::async_support::StreamResult;

struct Worker {
    plan: StreamReader<u8>,
    stop: StreamReader<u8>,
    listener: Option<StreamReader<host_service::Client>>,
    event_sender: Sender<Event>,
}

struct ClientWake {
    port: u32,
    waker: Arc<AtomicWaker>,
}

static RUN: futures_util::lock::Mutex<()> = futures_util::lock::Mutex::new(());

static WORKER: LazyLock<Mutex<Option<Worker>>> = LazyLock::new(|| Mutex::new(None));
static PENDING_PLAN: LazyLock<Mutex<Vec<u8>>> = LazyLock::new(|| Mutex::new(Vec::new()));
static PENDING_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static CLOCK_TICK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static RETRY_TICK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static RETRY_SCHEDULED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static PLAN_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static TRANSPORT_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static TRANSPORT_WAKER: AtomicWaker = AtomicWaker::new();
static PENDING_CLOCK: LazyLock<Mutex<Option<Vec<u8>>>> = LazyLock::new(|| Mutex::new(None));
static CLIENT_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static CLIENT_WAKERS: LazyLock<Mutex<Vec<ClientWake>>> = LazyLock::new(|| Mutex::new(Vec::new()));
static TASKS: LazyLock<Mutex<BTreeMap<u64, AbortHandle>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static NEXT_TASK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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
    let tasks = TASKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for task in tasks.values() {
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
    RETRY_TICK.store(false, std::sync::atomic::Ordering::Release);
    RETRY_SCHEDULED.store(false, std::sync::atomic::Ordering::Release);
    *PENDING_CLOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    PLAN_READY.store(false, std::sync::atomic::Ordering::Release);
    CLIENT_WAKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
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
    let worker = Worker {
        plan: host_service::plan(),
        stop: host_service::stop(),
        listener: host_service::listener(),
        event_sender,
    };
    *WORKER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(worker);
    event_reader
}

pub(crate) fn wake_clients() {
    CLIENT_EPOCH.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    for client in CLIENT_WAKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
    {
        client.waker.wake();
    }
}

fn register_client(port: u32) -> Arc<AtomicWaker> {
    let waker = Arc::new(AtomicWaker::new());
    CLIENT_WAKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(ClientWake {
            port,
            waker: Arc::clone(&waker),
        });
    waker
}

fn unregister_client(port: u32) {
    CLIENT_WAKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|client| client.port != port);
}

fn unregister_waker(waker: &Arc<AtomicWaker>) {
    CLIENT_WAKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|client| !Arc::ptr_eq(&client.waker, waker));
}

pub(crate) fn set_transport_ready(ready: bool) {
    TRANSPORT_READY.store(ready, std::sync::atomic::Ordering::Release);
    if ready {
        TRANSPORT_WAKER.wake();
    }
}

async fn wait_for_transport_ready() {
    poll_fn(|context| {
        TRANSPORT_WAKER.register(context.waker());
        if CLOSED.load(std::sync::atomic::Ordering::Acquire)
            || TRANSPORT_READY.load(std::sync::atomic::Ordering::Acquire)
        {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

async fn wait_for_client(waker: &AtomicWaker, observed: &mut u64) -> bool {
    let signal = wait_for_client_signal(waker, observed);
    let timeout = monotonic_clock::wait_for(CLIENT_WAIT_TIMEOUT);
    futures_util::pin_mut!(signal, timeout);
    matches!(
        futures_util::future::select(signal, timeout).await,
        futures_util::future::Either::Left(_)
    )
}

async fn wait_for_client_signal(waker: &AtomicWaker, observed: &mut u64) {
    poll_fn(|context| {
        let epoch = CLIENT_EPOCH.load(std::sync::atomic::Ordering::Acquire);
        if epoch != *observed {
            *observed = epoch;
            return Poll::Ready(());
        }
        waker.register(context.waker());
        let epoch = CLIENT_EPOCH.load(std::sync::atomic::Ordering::Acquire);
        if CLOSED.load(std::sync::atomic::Ordering::Acquire) || epoch != *observed {
            *observed = epoch;
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

fn abandon_client(port: u32) {
    if switch().reset_connection(AGENT_VSOCK_PORT, port).is_ok() {
        schedule_receive_queue();
    }
    unregister_client(port);
    wake_clients();
    wake_worker();
}

fn start_connect_timeout(port: u32) -> bool {
    spawn_task(async move {
        monotonic_clock::wait_for(CLIENT_WAIT_TIMEOUT).await;
        if switch().connection_exists(AGENT_VSOCK_PORT, port)
            && !switch().connection_connected(AGENT_VSOCK_PORT, port)
        {
            abandon_client(port);
        }
    })
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
            wake_clients();
            wake_worker();
            return;
        };
        *PENDING_PLAN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = frame;
        PLAN_READY.store(true, std::sync::atomic::Ordering::Release);
        wake_worker();
    });
}

fn start_stop(mut stop: StreamReader<u8>) {
    let _ = spawn_task(async move {
        let (result, bytes) = stop.read(Vec::with_capacity(1)).await;
        if matches!(result, StreamResult::Complete(1)) && bytes.as_slice() == [STOP_SIGNAL] {
            PENDING_STOP.store(true, std::sync::atomic::Ordering::Release);
            wake_worker();
        }
    });
}

fn start_clock() {
    let _ = spawn_task(async {
        while !CLOSED.load(std::sync::atomic::Ordering::Acquire) {
            monotonic_clock::wait_for(1_000_000_000).await;
            CLOCK_TICK.store(true, std::sync::atomic::Ordering::Release);
            wake_worker();
        }
    });
}

fn start_listener(mut listener: StreamReader<host_service::Client>) {
    let _ = spawn_task(async move {
        loop {
            wait_for_transport_ready().await;
            if CLOSED.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            let (result, clients) = listener.read(Vec::with_capacity(1)).await;
            let StreamResult::Complete(count) = result else {
                return;
            };
            if count == 0 {
                return;
            }
            for client in clients.into_iter().take(count) {
                wait_for_transport_ready().await;
                if CLOSED.load(std::sync::atomic::Ordering::Acquire) {
                    return;
                }
                let port = {
                    let mut switch = switch();
                    (switch.connection_count() < MAX_CLIENTS)
                        .then(|| switch.connect(AGENT_VSOCK_PORT))
                        .transpose()
                };
                if let Ok(Some(port)) = port {
                    schedule_receive_queue();
                    if !start_connect_timeout(port) {
                        abandon_client(port);
                        continue;
                    }
                    if !spawn_task(async move { start_client(port, client) })
                        && switch().reset_connection(AGENT_VSOCK_PORT, port).is_ok()
                    {
                        schedule_receive_queue();
                    }
                }
            }
        }
    });
}

#[allow(clippy::too_many_lines)]
fn start_client(port: u32, client: host_service::Client) {
    let input = client.input();
    let (writer, output) = crate::wit_stream::new();
    let input_waker = register_client(port);
    let output_waker = register_client(port);
    let output_completion_waker = Arc::clone(&output_waker);
    let output_cleanup_waker = Arc::clone(&output_waker);
    let (input_abort, input_registration) = AbortHandle::new_pair();
    let completion_abort = input_abort.clone();
    let (output_abort, output_registration) = AbortHandle::new_pair();
    let input_output_abort = output_abort.clone();
    let completion_output_abort = output_abort.clone();
    if !spawn_task(async move {
        let _ = Abortable::new(
            async move {
                let mut input = input;
                let mut observed = CLIENT_EPOCH.load(std::sync::atomic::Ordering::Acquire);
                loop {
                    let (result, bytes) = input.read(Vec::with_capacity(MAX_CLIENT_BYTES)).await;
                    match result {
                        StreamResult::Complete(count) if count > 0 && count <= bytes.len() => {
                            loop {
                                let delivery =
                                    { switch().deliver(AGENT_VSOCK_PORT, port, &bytes[..count]) };
                                match delivery {
                                    Ok(()) => {
                                        schedule_receive_queue();
                                        break;
                                    }
                                    Err(
                                        terra_vsock_device::VsockError::Backpressure
                                        | terra_vsock_device::VsockError::UnknownConnection,
                                    ) if switch().connection_exists(AGENT_VSOCK_PORT, port) => {
                                        if !wait_for_client(&input_waker, &mut observed).await {
                                            input_output_abort.abort();
                                            abandon_client(port);
                                            return;
                                        }
                                        if CLOSED.load(std::sync::atomic::Ordering::Acquire) {
                                            return;
                                        }
                                    }
                                    Err(_) => return,
                                }
                            }
                        }
                        StreamResult::Complete(_)
                        | StreamResult::Dropped
                        | StreamResult::Cancelled => loop {
                            if switch().connection_exists(AGENT_VSOCK_PORT, port)
                                && !switch().connection_connected(AGENT_VSOCK_PORT, port)
                            {
                                let _ = switch().reset_connection(AGENT_VSOCK_PORT, port);
                                schedule_receive_queue();
                                input_output_abort.abort();
                                unregister_client(port);
                                wake_clients();
                                wake_worker();
                                return;
                            }
                            let shutdown = { switch().shutdown(AGENT_VSOCK_PORT, port) };
                            match shutdown {
                                Ok(()) => {
                                    schedule_receive_queue();
                                    if !switch().connection_exists(AGENT_VSOCK_PORT, port) {
                                        unregister_client(port);
                                    }
                                    wake_clients();
                                    wake_worker();
                                    return;
                                }
                                Err(terra_vsock_device::VsockError::UnknownConnection)
                                    if !switch().connection_exists(AGENT_VSOCK_PORT, port) =>
                                {
                                    wake_clients();
                                    wake_worker();
                                    return;
                                }
                                Err(
                                    terra_vsock_device::VsockError::Backpressure
                                    | terra_vsock_device::VsockError::UnknownConnection,
                                ) => {
                                    if !wait_for_client(&input_waker, &mut observed).await {
                                        input_output_abort.abort();
                                        abandon_client(port);
                                        return;
                                    }
                                }
                                Err(terra_vsock_device::VsockError::TableFull) => return,
                            }
                        },
                    }
                }
            },
            input_registration,
        )
        .await;
    }) {
        input_abort.abort();
        if switch().reset_connection(AGENT_VSOCK_PORT, port).is_ok() {
            schedule_receive_queue();
        }
        unregister_client(port);
        return;
    }
    if !spawn_task(async move {
        let preserve_input = client.output(output).await.is_ok()
            && switch().connection_exists(AGENT_VSOCK_PORT, port)
            && switch().guest_send_closed(AGENT_VSOCK_PORT, port);
        if preserve_input {
            unregister_waker(&output_completion_waker);
        } else {
            completion_abort.abort();
            completion_output_abort.abort();
            if switch().connection_exists(AGENT_VSOCK_PORT, port)
                && switch().reset_connection(AGENT_VSOCK_PORT, port).is_ok()
            {
                schedule_receive_queue();
            }
            unregister_client(port);
            wake_clients();
            wake_worker();
        }
    }) {
        input_abort.abort();
        if switch().reset_connection(AGENT_VSOCK_PORT, port).is_ok() {
            schedule_receive_queue();
        }
        unregister_client(port);
        return;
    }
    if !spawn_task(async move {
        let _ = Abortable::new(
            async move {
                let mut writer = writer;
                let mut observed = CLIENT_EPOCH.load(std::sync::atomic::Ordering::Acquire);
                loop {
                    if CLOSED.load(std::sync::atomic::Ordering::Acquire) {
                        return;
                    }
                    let bytes: Vec<u8> = switch()
                        .take_upstream_for_up_to(AGENT_VSOCK_PORT, port, MAX_CLIENT_BYTES)
                        .into_iter()
                        .flat_map(|item| item.data)
                        .collect();
                    if !bytes.is_empty() {
                        if !writer.write_all(bytes).await.is_empty() {
                            if switch().reset_connection(AGENT_VSOCK_PORT, port).is_ok() {
                                schedule_receive_queue();
                            }
                            wake_clients();
                            wake_worker();
                            return;
                        }
                    } else if switch().guest_send_closed(AGENT_VSOCK_PORT, port) {
                        return;
                    } else if switch().connection_exists(AGENT_VSOCK_PORT, port) {
                        wait_for_client_signal(&output_waker, &mut observed).await;
                    } else {
                        return;
                    }
                }
            },
            output_registration,
        )
        .await;
        unregister_waker(&output_cleanup_waker);
    }) {
        input_abort.abort();
        if switch().reset_connection(AGENT_VSOCK_PORT, port).is_ok() {
            schedule_receive_queue();
        }
        unregister_client(port);
    }
}

fn source(port: u32) -> Option<u32> {
    switch()
        .connections_up_to(MAX_CLIENTS)
        .into_iter()
        .find_map(|(guest_port, host_port)| (host_port == port).then_some(guest_port))
}

pub(crate) fn schedule_receive_queue() {
    if transport::queue_notify(0).is_ok() {
        wake_worker();
    }
}

fn feed(source: Option<u32>, bytes: &[u8]) -> bool {
    source.is_some_and(|source| {
        let delivered = switch().deliver(source, CONTROL_VSOCK_PORT, bytes).is_ok();
        if delivered {
            schedule_receive_queue();
        }
        delivered
    })
}

fn feed_plan(source: Option<u32>) {
    let mut plan = PENDING_PLAN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut sent = 0;
    while sent < MAX_PLAN_BYTES_PER_TURN && !plan.is_empty() {
        let count = plan
            .len()
            .min(PLAN_CHUNK_BYTES)
            .min(MAX_PLAN_BYTES_PER_TURN - sent);
        if !feed(source, &plan[..count]) {
            break;
        }
        plan.drain(..count);
        sent += count;
    }
}

fn feed_stop(source: Option<u32>) {
    if PENDING_STOP.load(std::sync::atomic::Ordering::Acquire)
        && PLAN_READY.load(std::sync::atomic::Ordering::Acquire)
        && PENDING_PLAN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
        && feed(source, &[STOP_SIGNAL])
    {
        PENDING_STOP.store(false, std::sync::atomic::Ordering::Release);
    }
}

fn feed_clock(source: Option<u32>) {
    if source.is_none()
        || !PLAN_READY.load(std::sync::atomic::Ordering::Acquire)
        || !PENDING_PLAN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    {
        return;
    }
    let mut pending = PENDING_CLOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if pending.is_none()
        && CLOCK_TICK.swap(false, std::sync::atomic::Ordering::AcqRel)
        && let Some((seconds, nanoseconds)) = sample_clock()
    {
        *pending = Some(encode_clock_sync(seconds, nanoseconds).to_vec());
    }
    if pending.as_ref().is_some_and(|clock| feed(source, clock)) {
        *pending = None;
    }
}

fn schedule_connect_retry() {
    if RETRY_SCHEDULED.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return;
    }
    if !spawn_task(async {
        monotonic_clock::wait_for(CONNECT_RETRY_DELAY).await;
        RETRY_SCHEDULED.store(false, std::sync::atomic::Ordering::Release);
        RETRY_TICK.store(true, std::sync::atomic::Ordering::Release);
        wake_worker();
    }) {
        RETRY_SCHEDULED.store(false, std::sync::atomic::Ordering::Release);
        RETRY_TICK.store(true, std::sync::atomic::Ordering::Release);
        wake_worker();
    }
}

fn queue_event(sender: &mut Sender<Event>, pending: &mut VecDeque<Event>, event: Event) {
    if let Err(error) = sender.try_send(event) {
        pending.push_back(error.into_inner());
    }
}

fn flush_events(sender: &mut Sender<Event>, pending: &mut VecDeque<Event>) {
    while let Some(event) = pending.pop_front() {
        if let Err(error) = sender.try_send(event) {
            pending.push_front(error.into_inner());
            break;
        }
    }
}

fn drain_lifecycle(
    sender: &mut Sender<Event>,
    pending: &mut VecDeque<Event>,
    control: &mut Vec<u8>,
    diagnostics: &mut Vec<u8>,
) {
    flush_events(sender, pending);
    if !pending.is_empty() {
        return;
    }
    if let Some(source) = source(CONTROL_VSOCK_PORT) {
        let bytes: Vec<u8> = switch()
            .take_upstream_for_up_to(source, CONTROL_VSOCK_PORT, MAX_STREAM_BYTES - control.len())
            .into_iter()
            .flat_map(|item| item.data)
            .collect();
        if !bytes.is_empty() {
            control.extend_from_slice(&bytes);
        }
        if !control.is_empty() {
            let Ok(result) = crate::lifecycle::decode_control(control) else {
                reset_lifecycle_connection(source, CONTROL_VSOCK_PORT, control);
                return;
            };
            let consumed = result.consumed as usize;
            if consumed > control.len() {
                reset_lifecycle_connection(source, CONTROL_VSOCK_PORT, control);
                return;
            }
            control.drain(..consumed);
            if result.agent_ready {
                queue_event(sender, pending, Event::AgentReady);
            }
            if let Some(code) = result.exit_code {
                queue_event(sender, pending, Event::Exit(code));
            }
        }
    }
    if let Some(source) = source(DIAGNOSTIC_VSOCK_PORT) {
        let bytes: Vec<u8> = switch()
            .take_upstream_for_up_to(
                source,
                DIAGNOSTIC_VSOCK_PORT,
                MAX_DIAGNOSTIC_FRAME_BYTES.saturating_sub(diagnostics.len()),
            )
            .into_iter()
            .flat_map(|item| item.data)
            .collect();
        if !bytes.is_empty() {
            diagnostics.extend_from_slice(&bytes);
        }
        if !diagnostics.is_empty() {
            let Ok(result) = crate::lifecycle::decode_diagnostics(diagnostics) else {
                reset_lifecycle_connection(source, DIAGNOSTIC_VSOCK_PORT, diagnostics);
                return;
            };
            let consumed = result.consumed as usize;
            if consumed > diagnostics.len() {
                reset_lifecycle_connection(source, DIAGNOSTIC_VSOCK_PORT, diagnostics);
                return;
            }
            diagnostics.drain(..consumed);
            if !result.output.is_empty() {
                queue_event(sender, pending, Event::Diagnostic(result.output));
            }
        }
    }
}

fn reset_lifecycle_connection(source: u32, port: u32, buffer: &mut Vec<u8>) {
    buffer.clear();
    if switch().reset_connection(source, port).is_ok() {
        schedule_receive_queue();
    }
}

pub(crate) async fn finish() {
    let _running = RUN.lock().await;
    WORKER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    abort_tasks();
    finish_tasks().await;
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
    abort_tasks();
    finish_tasks().await;
    CLIENT_WAKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    result
}

async fn run_worker(worker: Worker) -> Result<(), Error> {
    start_plan(worker.plan);
    start_stop(worker.stop);
    if let Some(listener) = worker.listener {
        start_listener(listener);
    }
    start_clock();
    let mut event_sender = worker.event_sender;
    let mut control = Vec::new();
    let mut diagnostics = Vec::new();
    let mut pending_events = VecDeque::new();
    while !CLOSED.load(std::sync::atomic::Ordering::Acquire) {
        wait_for_work().await;
        if CLOSED.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        let mut pending = false;
        for _ in 0..8 {
            // An unaddressable ring cannot be completed; wait for reset or another doorbell.
            pending = transport::process_pending().unwrap_or(false);
            wake_clients();
            if !pending {
                break;
            }
            wit_bindgen::rt::async_support::yield_async().await;
        }
        if pending {
            wake_worker();
        }
        if RETRY_TICK.swap(false, std::sync::atomic::Ordering::AcqRel)
            && switch().retry_connecting()
        {
            schedule_receive_queue();
        }
        if switch().has_pending_connect_retry() {
            schedule_connect_retry();
        }
        let control_source = source(CONTROL_VSOCK_PORT);
        feed_plan(control_source);
        feed_stop(control_source);
        feed_clock(control_source);
        drain_lifecycle(
            &mut event_sender,
            &mut pending_events,
            &mut control,
            &mut diagnostics,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_lifecycle_connections_reset_without_stopping_the_worker() {
        use terra_vsock_device::{GUEST_CID, HOST_CID, VsockHeader};
        let _guard = crate::SWITCH_TEST_LOCK.lock().unwrap();
        let (mut sender, _receiver) = mpsc::channel(32);
        let mut pending = VecDeque::new();
        let mut control = Vec::new();
        let mut diagnostics = Vec::new();
        for port in [CONTROL_VSOCK_PORT, DIAGNOSTIC_VSOCK_PORT] {
            for malformed in [vec![255; 4], vec![1, 0, 0, 0, b'{']] {
                *switch() = terra_vsock_device::VsockSwitch::new();
                let mut header = VsockHeader {
                    src_cid: GUEST_CID,
                    dst_cid: HOST_CID,
                    src_port: 100,
                    dst_port: port,
                    len: 0,
                    type_: 1,
                    op: 1,
                    flags: 0,
                    buf_alloc: 65536,
                    fwd_cnt: 0,
                };
                switch().rx(&header, &[]);
                assert!(switch().connection_exists(100, port));
                header.op = 5;
                header.len = u32::try_from(malformed.len()).unwrap();
                switch().rx(&header, &malformed);
                drain_lifecycle(&mut sender, &mut pending, &mut control, &mut diagnostics);
                assert!(!switch().connection_exists(100, port));
                assert_eq!(control, [] as [u8; 0]);
                assert_eq!(diagnostics, [] as [u8; 0]);
                switch().take_replies();
            }
        }
    }

    #[test]
    fn control_waits_for_the_enriched_plan_to_drain() {
        PLAN_READY.store(false, std::sync::atomic::Ordering::Release);
        PENDING_PLAN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(b"plan");
        assert!(!PLAN_READY.load(std::sync::atomic::Ordering::Acquire));
        PLAN_READY.store(true, std::sync::atomic::Ordering::Release);
        assert!(
            !PENDING_PLAN
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
        PENDING_PLAN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        assert!(PLAN_READY.load(std::sync::atomic::Ordering::Acquire));
    }

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

    #[test]
    fn saturated_event_queue_preserves_exit_for_later_delivery() {
        let (mut sender, _receiver) = mpsc::channel(1);
        while sender.try_send(Event::Diagnostic(vec![1])).is_ok() {}
        let mut pending = VecDeque::new();
        queue_event(&mut sender, &mut pending, Event::Exit(7));
        assert!(matches!(pending.pop_front(), Some(Event::Exit(7))));
    }

    #[test]
    fn client_epoch_advances_for_every_wake() {
        let before = CLIENT_EPOCH.load(std::sync::atomic::Ordering::Acquire);
        wake_clients();
        assert!(CLIENT_EPOCH.load(std::sync::atomic::Ordering::Acquire) > before);
    }

    #[test]
    fn client_cleanup_releases_input_and_output_wakers() {
        let mut clients = CLIENT_WAKERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clients.clear();
        drop(clients);
        register_client(9);
        register_client(9);
        assert_eq!(
            CLIENT_WAKERS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            2
        );
        unregister_client(9);
        assert!(
            CLIENT_WAKERS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
    }
}
