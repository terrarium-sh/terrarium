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
    FutureExt as _, SinkExt as _, StreamExt,
    future::{AbortHandle, Abortable, Either, poll_fn},
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    task::AtomicWaker,
};
use std::{
    collections::BTreeMap,
    sync::{
        LazyLock, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
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
static PENDING_STOP: AtomicBool = AtomicBool::new(false);
static CLOCK_TICK: AtomicBool = AtomicBool::new(false);
static PLAN_READY: AtomicBool = AtomicBool::new(false);
static TRANSPORT_READY: AtomicBool = AtomicBool::new(false);
static CONTROL_EPOCH: AtomicU64 = AtomicU64::new(0);
static CONTROL_WAKER: AtomicWaker = AtomicWaker::new();
static TASKS: LazyLock<TaskGroup> = LazyLock::new(TaskGroup::default);
static SESSION_TASKS: LazyLock<TaskGroup> = LazyLock::new(TaskGroup::default);
static CARRIER_SESSION: AtomicBool = AtomicBool::new(false);
static ACTIVE_CLIENTS: AtomicUsize = AtomicUsize::new(0);

#[derive(Default)]
struct TaskGroup {
    tasks: Mutex<BTreeMap<u64, AbortHandle>>,
    next_id: AtomicU64,
}

impl TaskGroup {
    fn spawn(&'static self, future: impl core::future::Future<Output = ()> + 'static) -> bool {
        let (handle, registration) = AbortHandle::new_pair();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut tasks = self
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if tasks.len() >= MAX_WORKER_TASKS {
                return false;
            }
            tasks.insert(id, handle);
        }
        wit_bindgen::rt::async_support::spawn_local(async move {
            let _ = Abortable::new(future, registration).await;
            self.tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id);
            wake_worker();
        });
        true
    }

    fn abort(&self) {
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
        {
            task.abort();
        }
    }

    async fn finish(&self) {
        while !self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
        {
            wit_bindgen::rt::async_support::yield_async().await;
        }
    }
}

async fn finish_tasks() {
    CARRIER_SESSION.store(false, Ordering::Release);
    TASKS.abort();
    SESSION_TASKS.abort();
    TASKS.finish().await;
    SESSION_TASKS.finish().await;
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
    PENDING_STOP.store(false, Ordering::Release);
    CLOCK_TICK.store(false, Ordering::Release);
    PLAN_READY.store(false, Ordering::Release);
    let (mut event_writer, event_reader) = crate::wit_stream::new();
    let (event_sender, mut event_receiver) = mpsc::channel(64);
    let _ = TASKS.spawn(async move {
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

pub(crate) fn schedule_receive_queue() {
    if transport::queue_notify(0).is_ok() {
        wake_worker();
    }
}

fn wake_control() {
    CONTROL_EPOCH.fetch_add(1, Ordering::AcqRel);
    CONTROL_WAKER.wake();
}

fn begin_carrier_session() {
    CARRIER_SESSION.store(true, Ordering::Release);
    ACTIVE_CLIENTS.store(0, Ordering::Release);
}

pub(crate) fn reset_session() {
    if !CARRIER_SESSION.swap(false, Ordering::AcqRel) {
        return;
    }
    SESSION_TASKS.abort();
    ACTIVE_CLIENTS.store(0, Ordering::Release);
    wake_control();
    carrier::wake();
    wake_worker();
}

pub(crate) fn set_transport_ready(ready: bool) {
    TRANSPORT_READY.store(ready, Ordering::Release);
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

fn enrich_plan(frame: &[u8]) -> Option<Vec<u8>> {
    let instant = system_clock::now();
    let seed = (0..4)
        .flat_map(|_| random::get_random_u64().to_le_bytes())
        .collect::<Vec<_>>()
        .try_into()
        .ok()?;
    enrich_plan_with_host_state(frame, instant.seconds, instant.nanoseconds, seed)
}

fn enrich_plan_with_host_state(
    frame: &[u8],
    seconds: i64,
    nanoseconds: u32,
    seed: [u8; 32],
) -> Option<Vec<u8>> {
    let payload_len = usize::try_from(u32::from_le_bytes(frame.get(..4)?.try_into().ok()?)).ok()?;
    if payload_len > MAX_PLAN_BYTES || frame.len() != payload_len.checked_add(4)? {
        return None;
    }
    let mut plan: terra_protocol::Plan = terra_protocol::decode_frame_payload(&frame[4..]).ok()?;
    if nanoseconds >= 1_000_000_000 {
        return None;
    }
    plan.host_time = Some(terra_protocol::HostTime {
        seconds,
        nanoseconds,
    });
    plan.host_seed = Some(seed);
    let frame = terra_protocol::encode_frame_with_limit(&plan, MAX_PLAN_BYTES).ok()?;
    if (frame.len() - 4).saturating_sub(payload_len) > MAX_PLAN_HOST_STATE_BYTES {
        return None;
    }
    Some(frame)
}

fn start_plan(plan: StreamReader<u8>) {
    let _ = TASKS.spawn(async move {
        let Some(frame) = read_all(plan, MAX_PLAN_FRAME_BYTES)
            .await
            .and_then(|frame| enrich_plan(&frame))
        else {
            CLOSED.store(true, Ordering::Release);
            wake_worker();
            return;
        };
        *PENDING_PLAN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = frame;
        PLAN_READY.store(true, Ordering::Release);
        wake_control();
        wake_worker();
    });
}

fn start_stop(mut stop: StreamReader<u8>) {
    let _ = TASKS.spawn(async move {
        let (result, bytes) = stop.read(Vec::with_capacity(1)).await;
        if matches!(result, StreamResult::Complete(1)) && bytes.as_slice() == [STOP_SIGNAL] {
            PENDING_STOP.store(true, Ordering::Release);
            wake_control();
        }
    });
}

fn start_clock() {
    let _ = TASKS.spawn(async {
        while !CLOSED.load(Ordering::Acquire) {
            monotonic_clock::wait_for(1_000_000_000).await;
            CLOCK_TICK.store(true, Ordering::Release);
            wake_control();
        }
    });
}

fn start_listener(
    mut listener: StreamReader<host_service::Client>,
    mut clients: Sender<host_service::Client>,
) {
    let _ = TASKS.spawn(async move {
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
    if !PLAN_READY.load(Ordering::Acquire) {
        return None;
    }
    if PENDING_STOP.swap(false, Ordering::AcqRel) {
        return Some(vec![STOP_SIGNAL]);
    }
    if CLOCK_TICK.swap(false, Ordering::AcqRel)
        && let Some((seconds, nanoseconds)) = sample_clock()
    {
        return Some(encode_clock_sync(seconds, nanoseconds).to_vec());
    }
    None
}

async fn wait_for_control(observed: &mut u64) {
    poll_fn(|context| {
        CONTROL_WAKER.register(context.waker());
        let epoch = CONTROL_EPOCH.load(Ordering::Acquire);
        if CLOSED.load(Ordering::Acquire) || epoch != *observed {
            *observed = epoch;
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

async fn write_control(mut stream: impl AsyncWrite + Unpin) {
    let mut observed = CONTROL_EPOCH.load(Ordering::Acquire);
    while !CLOSED.load(Ordering::Acquire) {
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
    let started = SESSION_TASKS.spawn(async move {
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
        ACTIVE_CLIENTS.fetch_sub(1, Ordering::AcqRel);
        wake_worker();
    });
    if !started {
        ACTIVE_CLIENTS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn reserve_client() -> bool {
    ACTIVE_CLIENTS
        .try_update(Ordering::AcqRel, Ordering::Acquire, |active| {
            (active < MAX_CLIENT_STREAMS).then_some(active + 1)
        })
        .is_ok()
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
    clients: Option<mpsc::Receiver<host_service::Client>>,
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
    let _ = SESSION_TASKS.spawn(read_diagnostics(diagnostics, event_sender.clone()));
    futures_util::future::select_all([
        write_control(control_writer).boxed_local(),
        read_lifecycle(control_reader, event_sender).boxed_local(),
        serve_clients(connection, clients).boxed_local(),
    ])
    .await;
}

async fn serve_clients(
    mut connection: yamux::Connection<carrier::Carrier>,
    mut clients: Option<mpsc::Receiver<host_service::Client>>,
) {
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
                    ACTIVE_CLIENTS.fetch_sub(1, Ordering::AcqRel);
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
    finish_tasks().await;
}

pub(crate) async fn run() -> Result<(), Error> {
    let _running = RUN.lock().await;
    let worker = WORKER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let result = match worker {
        Some(worker) if !CLOSED.load(Ordering::Acquire) => run_worker(worker).await,
        Some(_) => Ok(()),
        None => CLOSED
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or(Error::Malformed),
    };
    finish_tasks().await;
    result
}

async fn run_worker(worker: Worker) -> Result<(), Error> {
    start_plan(worker.plan);
    start_stop(worker.stop);
    let (client_sender, client_receiver) = mpsc::channel(MAX_CLIENT_STREAMS);
    let mut clients = worker.listener.map(|listener| {
        start_listener(listener, client_sender);
        client_receiver
    });
    start_clock();
    let mut session_started = false;
    while !CLOSED.load(Ordering::Acquire) {
        wait_for_work().await;
        let mut pending = false;
        for _ in 0..8 {
            pending = transport::process_pending().unwrap_or(false);
            carrier::wake();
            if !pending {
                break;
            }
            wit_bindgen::rt::async_support::yield_async().await;
        }
        if pending {
            wake_worker();
        }
        if !session_started
            && TRANSPORT_READY.load(Ordering::Acquire)
            && let Some(carrier) = carrier::Carrier::accept()
        {
            session_started = true;
            begin_carrier_session();
            let _ = SESSION_TASKS.spawn(run_mux(
                carrier,
                clients.take(),
                worker.event_sender.clone(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_plan() -> terra_protocol::Plan {
        terra_protocol::Plan {
            mode: terra_protocol::PlanMode::Run,
            workdir: Some("/work".into()),
            shares: vec![terra_protocol::Share {
                tag: "work".into(),
                guest: "/work".into(),
                readonly: false,
            }],
            volumes: vec![],
            net: terra_protocol::Net {
                guest_ip: "100.96.0.2".parse().unwrap(),
                prefix: 30,
                gateway: "100.96.0.1".parse().unwrap(),
                dns: "100.96.0.1".parse().unwrap(),
            },
            env: BTreeMap::new(),
            root: false,
            sudo: vec![],
            on_create: vec![],
            on_start: vec![],
            pre_stop: vec![],
            daemons: vec![],
            workload: vec!["sh".into()],
            sandbox_info: String::new(),
            await_initial_session: false,
            host_tz: Some(vec![1, 2, 3]),
            host_time: None,
            host_seed: None,
        }
    }

    #[test]
    fn plan_enrichment_preserves_plan_fields_and_adds_host_state() {
        let mut plan = test_plan();
        let frame = terra_protocol::encode_frame(&plan).unwrap();
        let seed = std::array::from_fn(|index| u8::try_from(index).unwrap());
        let frame = enrich_plan_with_host_state(&frame, 12, 34, seed).unwrap();
        let decoded: terra_protocol::Plan = terra_protocol::read_frame(&mut frame.as_slice())
            .unwrap()
            .unwrap();
        plan.host_time = Some(terra_protocol::HostTime {
            seconds: 12,
            nanoseconds: 34,
        });
        plan.host_seed = Some(seed);
        assert_eq!(decoded, plan);
    }

    #[test]
    fn maximum_host_plan_fits_after_host_state_enrichment() {
        let limit = MAX_PLAN_BYTES - MAX_PLAN_HOST_STATE_BYTES;
        let mut plan = test_plan();
        plan.sandbox_info = "x".repeat(limit);
        let overhead = terra_protocol::encode_frame(&plan).unwrap().len() - 4 - limit;
        plan.sandbox_info.truncate(limit - overhead);
        let frame = terra_protocol::encode_frame_with_limit(&plan, limit).unwrap();
        assert_eq!(frame.len(), limit + 4);
        let frame =
            enrich_plan_with_host_state(&frame, i64::MIN, 999_999_999, [u8::MAX; 32]).unwrap();
        assert!(frame.len() <= MAX_PLAN_FRAME_BYTES);
        let decoded: terra_protocol::Plan =
            terra_protocol::read_frame_with_limit(&mut frame.as_slice(), MAX_PLAN_BYTES)
                .unwrap()
                .unwrap();
        assert_eq!(decoded.sandbox_info, plan.sandbox_info);
    }
}
