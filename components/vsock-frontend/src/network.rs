use crate::bindings::wasi::clocks::monotonic_clock;
use crate::{switch, terra, transport, wake_worker};
use futures_util::{
    FutureExt as _,
    future::{AbortHandle, Abortable, Either, poll_fn, select},
};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Poll, Waker},
};
use terra::network::broker::{self, IpAddress as HostIpAddress, SocketAddress};
use terra_protocol::application::{Direction, Message, StreamDecoder};
use terra_protocol::socket::Error as SocketError;
use terra_vsock_device::{ConnectionId, Role};

mod control;
mod publish;
mod tcp;
mod udp;

const CHUNK_BYTES: usize = terra_protocol::network::MAX_NETWORK_CHUNK_BYTES;

pub(crate) struct Flow {
    pub(crate) connection: ConnectionId,
    pub(crate) task: Option<Task>,
    finished: Arc<AtomicBool>,
}

struct Completion(Arc<AtomicBool>);

impl Drop for Completion {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
        wake_worker();
    }
}

pub(crate) fn spawn_flow(
    connection: ConnectionId,
    future: impl std::future::Future<Output = ()> + 'static,
) -> Flow {
    let finished = Arc::new(AtomicBool::new(false));
    let completion = Completion(finished.clone());
    let task = spawn_task(async move {
        let _completion = completion;
        future.await;
    });
    Flow {
        connection,
        task: Some(task),
        finished,
    }
}

pub(crate) fn is_flow_drained(flow: &Flow) -> bool {
    flow.finished.load(Ordering::Acquire)
        && (!switch().is_current(flow.connection)
            || (!switch().has_pending_replies_for(flow.connection)
                && !transport::has_pending_reply_for(flow.connection)))
}

pub(crate) struct Task(AbortHandle);

impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Default)]
struct State {
    config: Option<crate::terra::network::types::Config>,
    control: Option<(ConnectionId, Task)>,
    is_control_ready: bool,
    flows: Vec<Flow>,
    listeners: Vec<Task>,
    broker_watcher: Option<Task>,
    waiters: BTreeMap<ConnectionId, Vec<Waker>>,
    publication_waiters: Vec<Waker>,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| Mutex::new(State::default()));

fn lock_network() -> std::sync::MutexGuard<'static, State> {
    STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn register_waiter(waiters: &mut Vec<Waker>, waker: &Waker) {
    if !waiters.iter().any(|waiting| waiting.will_wake(waker)) {
        waiters.push(waker.clone());
    }
}

fn wait(state: &mut State, connection: ConnectionId, waker: &Waker) {
    register_waiter(state.waiters.entry(connection).or_default(), waker);
}

fn wait_for_publication(state: &mut State, waker: &Waker) {
    register_waiter(&mut state.publication_waiters, waker);
}

pub(crate) fn notify_connection(connection: ConnectionId) {
    let waiters = lock_network()
        .waiters
        .remove(&connection)
        .unwrap_or_default();
    for waker in waiters {
        waker.wake();
    }
}

pub(crate) fn notify_admission() {
    let waiters = std::mem::take(&mut lock_network().publication_waiters);
    for waker in waiters {
        waker.wake();
    }
}

pub(crate) fn spawn_task(future: impl std::future::Future<Output = ()> + 'static) -> Task {
    let (abort, registration) = AbortHandle::new_pair();
    wit_bindgen::spawn_local(async move {
        let _ = Abortable::new(future, registration).await;
    });
    Task(abort)
}

pub fn configure(
    config: crate::terra::network::types::Config,
) -> Result<(), crate::terra::network::types::Error> {
    use crate::terra::network::types::Error;
    if crate::WORK.is_closed() || crate::CONFIGURED.load(std::sync::atomic::Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    validate_config(&config)?;
    reset();
    lock_network().config = Some(config);
    wake_worker();
    Ok(())
}

fn validate_config(
    config: &crate::terra::network::types::Config,
) -> Result<(), crate::terra::network::types::Error> {
    use crate::terra::network::types::{Error, Transport};
    if config.flow_capacity == 0
        || config.flow_capacity as usize > terra_vsock_device::MAX_NETWORK_SOCKETS
        || config.host_service_ports.len() > terra_policy::MAX_RULES
        || config.host_service_ports.contains(&Some(0))
        || config.published_ports.len() > terra_protocol::MAX_PUBLISHED_PORTS
        || config
            .published_ports
            .iter()
            .enumerate()
            .any(|(index, port)| {
                port.host_port == 0
                    || port.guest_port == 0
                    || config.published_ports[..index].iter().any(|other| {
                        other.host_port == port.host_port && other.transport == port.transport
                    })
            })
    {
        return Err(Error::Malformed);
    }
    let udp_stream_count = config
        .published_ports
        .iter()
        .filter(|port| port.transport == Transport::Udp)
        .count()
        * 2;
    if udp_stream_count > config.flow_capacity as usize {
        return Err(Error::Backpressure);
    }
    Ok(())
}

pub fn reset() {
    let mut state = lock_network();
    let config = state.config.take();
    let broker_watcher = state.broker_watcher.take();
    let waiters = std::mem::take(&mut state.waiters);
    let publication_waiters = std::mem::take(&mut state.publication_waiters);
    let retired = std::mem::replace(
        &mut *state,
        State {
            config,
            broker_watcher,
            ..State::default()
        },
    );
    drop(state);
    drop(retired);
    for waker in waiters.into_values().flatten().chain(publication_waiters) {
        waker.wake();
    }
}

pub fn close() {
    reset();
    let mut state = lock_network();
    let retired = (state.config.take(), state.broker_watcher.take());
    drop(state);
    drop(retired);
}

/// Retire every network connection and refuse new ones while agent control continues.
fn disable_networking() {
    switch().disable_network();
    close();
    transport::schedule_receive_queue();
}

pub(crate) fn reset_flow(connection: ConnectionId) {
    let _ = switch().reset_connection(connection);
    transport::schedule_receive_queue();
}

fn finish_flow(connection: ConnectionId) {
    if let Some(flow) = lock_network()
        .flows
        .iter_mut()
        .find(|flow| flow.connection == connection)
    {
        flow.finished.store(true, Ordering::Release);
    }
    wake_worker();
}

pub(crate) fn shutdown_flow(connection: ConnectionId) {
    let _ = switch().shutdown(connection);
    transport::schedule_receive_queue();
}

pub(crate) async fn wait_upstream(
    connection: ConnectionId,
    max_bytes: usize,
) -> Result<Vec<u8>, ()> {
    poll_fn(|context| {
        let mut state = lock_network();
        let device = switch();
        if !device.is_current(connection) {
            return Poll::Ready(Err(()));
        }
        let bytes = device.peek_upstream(connection, max_bytes);
        if !bytes.is_empty() || device.guest_send_closed(connection) {
            Poll::Ready(Ok(bytes))
        } else {
            wait(&mut state, connection, context.waker());
            Poll::Pending
        }
    })
    .await
}

pub(crate) fn consume_upstream(connection: ConnectionId, count: usize) -> Result<(), ()> {
    switch()
        .consume_upstream(connection, count)
        .map_err(|_| ())?;
    transport::schedule_receive_queue();
    Ok(())
}

pub(crate) async fn wait_capacity(
    connection: ConnectionId,
    minimum_bytes: usize,
    maximum_bytes: usize,
) -> Result<usize, ()> {
    poll_fn(|context| {
        let mut state = lock_network();
        let mut device = switch();
        if !device.is_current(connection) {
            return Poll::Ready(Err(()));
        }
        if device.guest_receive_closed(connection) {
            return Poll::Ready(Ok(0));
        }
        let capacity = device.send_capacity(connection).min(maximum_bytes);
        if capacity >= minimum_bytes {
            return Poll::Ready(Ok(capacity));
        }
        let requested = device.request_credit(connection).unwrap_or(false);
        wait(&mut state, connection, context.waker());
        drop(device);
        drop(state);
        if requested {
            transport::schedule_receive_queue();
        }
        Poll::Pending
    })
    .await
}

pub(crate) async fn wait_receive_closed(connection: ConnectionId) {
    poll_fn(|context| {
        let mut state = lock_network();
        let device = switch();
        if !device.is_current(connection) || device.guest_receive_closed(connection) {
            Poll::Ready(())
        } else {
            wait(&mut state, connection, context.waker());
            Poll::Pending
        }
    })
    .await;
}

pub(crate) async fn deliver_bytes(
    connection: ConnectionId,
    mut bytes: Vec<u8>,
) -> Result<(), SocketError> {
    while !bytes.is_empty() {
        let capacity = wait_capacity(connection, 1, terra_vsock_device::MAX_DATA_BYTES as usize)
            .await
            .map_err(|()| SocketError::Cancelled)?;
        if capacity == 0 {
            return Err(SocketError::Closed);
        }
        let remainder = bytes.split_off(capacity.min(bytes.len()));
        let chunk = std::mem::replace(&mut bytes, remainder);
        switch()
            .deliver(connection, chunk)
            .map_err(|_| SocketError::Cancelled)?;
        transport::schedule_receive_queue();
    }
    Ok(())
}

async fn deliver_message(connection: ConnectionId, message: &Message) -> Result<(), SocketError> {
    let bytes = message.encode().map_err(|_| SocketError::Protocol)?;
    deliver_bytes(connection, bytes).await
}

async fn deliver_opening(connection: ConnectionId, message: &Message) -> Result<(), SocketError> {
    let bytes = message.encode().map_err(|_| SocketError::Protocol)?;
    if wait_capacity(connection, bytes.len(), CHUNK_BYTES)
        .await
        .map_err(|()| SocketError::Cancelled)?
        == 0
    {
        return Err(SocketError::Closed);
    }
    switch()
        .deliver(connection, bytes)
        .map_err(|_| SocketError::Cancelled)?;
    transport::schedule_receive_queue();
    Ok(())
}

fn reject_opening(connection: ConnectionId, reply: &Message) {
    let delivered = reply
        .encode()
        .is_ok_and(|bytes| switch().deliver(connection, bytes).is_ok());
    if delivered {
        shutdown_flow(connection);
    } else {
        reset_flow(connection);
    }
}

/// Decode the next guest frame from bytes already queued; `Ok(None)` means none is complete yet.
fn read_queued_message(
    connection: ConnectionId,
    decoder: &mut StreamDecoder,
) -> Result<Option<Message>, SocketError> {
    loop {
        if let Some(message) = decoder
            .next(Direction::GuestToHost)
            .map_err(|_| SocketError::Protocol)?
        {
            return Ok(Some(message));
        }
        let bytes =
            switch().peek_upstream(connection, decoder.remaining_capacity().min(CHUNK_BYTES));
        if bytes.is_empty() {
            return Ok(None);
        }
        decoder.push(&bytes).map_err(|_| SocketError::Protocol)?;
        consume_upstream(connection, bytes.len()).map_err(|()| SocketError::Cancelled)?;
    }
}

/// Read the next guest frame; `Ok(None)` means the guest closed its sending side.
async fn read_message(
    connection: ConnectionId,
    decoder: &mut StreamDecoder,
) -> Result<Option<Message>, SocketError> {
    loop {
        if let Some(message) = read_queued_message(connection, decoder)? {
            return Ok(Some(message));
        }
        let bytes = wait_upstream(connection, decoder.remaining_capacity().min(CHUNK_BYTES))
            .await
            .map_err(|()| SocketError::Cancelled)?;
        if bytes.is_empty() {
            return if decoder.is_empty() {
                Ok(None)
            } else {
                Err(SocketError::Protocol)
            };
        }
        decoder.push(&bytes).map_err(|_| SocketError::Protocol)?;
        consume_upstream(connection, bytes.len()).map_err(|()| SocketError::Cancelled)?;
    }
}

async fn read_opening(connection: ConnectionId) -> Result<Message, SocketError> {
    let mut decoder = StreamDecoder::default();
    let opening = read_message(connection, &mut decoder)
        .await?
        .ok_or(SocketError::Closed)?;
    if decoder.is_empty() {
        Ok(opening)
    } else {
        Err(SocketError::Protocol)
    }
}

async fn run_before_deadline<T>(
    seconds: u64,
    future: impl std::future::Future<Output = T>,
) -> Result<T, SocketError> {
    let timer = monotonic_clock::wait_for(seconds * 1_000_000_000);
    match select(future.boxed_local(), timer.boxed_local()).await {
        futures_util::future::Either::Left((result, _)) => Ok(result),
        futures_util::future::Either::Right(_) => Err(SocketError::TimedOut),
    }
}

fn host_socket_address(peer: SocketAddr) -> SocketAddress {
    SocketAddress {
        address: match peer.ip() {
            IpAddr::V4(address) => HostIpAddress::Ipv4(address.octets().into()),
            IpAddr::V6(address) => HostIpAddress::Ipv6(address.segments().into()),
        },
        port: peer.port(),
    }
}

fn native_socket_address(address: SocketAddress) -> SocketAddr {
    SocketAddr::new(host_ip_address(address.address), address.port)
}

fn host_ip_address(address: HostIpAddress) -> IpAddr {
    match address {
        HostIpAddress::Ipv4((a, b, c, d)) => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        HostIpAddress::Ipv6(segments) => IpAddr::V6(Ipv6Addr::from(<[u16; 8]>::from(segments))),
    }
}

fn broker_error(error: broker::Error) -> SocketError {
    match error {
        broker::Error::AccessDenied => SocketError::AccessDenied,
        broker::Error::InvalidArgument => SocketError::InvalidArgument,
        broker::Error::InvalidState => SocketError::InvalidState,
        broker::Error::StaleHandle => SocketError::StaleHandle,
        broker::Error::WrongKind => SocketError::WrongKind,
        broker::Error::Busy => SocketError::Busy,
        broker::Error::LimitExceeded => SocketError::LimitExceeded,
        broker::Error::DuplicateRequest => SocketError::DuplicateRequest,
        broker::Error::Cancelled => SocketError::Cancelled,
        broker::Error::ConnectionRefused => SocketError::ConnectionRefused,
        broker::Error::ConnectionReset => SocketError::ConnectionReset,
        broker::Error::TimedOut => SocketError::TimedOut,
        broker::Error::NameUnresolvable => SocketError::NameUnresolvable,
        broker::Error::ResolverBusy => SocketError::ResolverBusy,
        broker::Error::DatagramTooLarge => SocketError::DatagramTooLarge,
        broker::Error::Closed => SocketError::Closed,
        broker::Error::Io => SocketError::Io,
    }
}

/// Map a guest destination to the host address the broker connects; synthetic host-service
/// addresses select only granted host loopback ports.
fn resolve_destination(peer: SocketAddr) -> Result<SocketAddr, SocketError> {
    let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
    if peer.ip() == IpAddr::V4(terra_protocol::socket::HOST_SERVICE_IPV4)
        || peer.ip() == IpAddr::V6(terra_protocol::socket::HOST_SERVICE_IPV6)
    {
        host_service_peer(peer.port(), peer.is_ipv6())
    } else {
        Ok(peer)
    }
}

fn host_service_peer(port: u16, ipv6: bool) -> Result<SocketAddr, SocketError> {
    let state = lock_network();
    let config = state.config.as_ref().ok_or(SocketError::NotReady)?;
    if port == 0
        || !config
            .host_service_ports
            .iter()
            .any(|grant| grant.is_none_or(|granted| granted == port))
    {
        return Err(SocketError::AccessDenied);
    }
    Ok(SocketAddr::new(
        if ipv6 {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        },
        port,
    ))
}

fn register_flow(connection: ConnectionId, task: Task) {
    lock_network().flows.push(Flow {
        connection,
        task: Some(task),
        finished: Arc::new(AtomicBool::new(false)),
    });
}

fn synchronize_control() -> bool {
    let current = switch().connection(Role::Control);
    let previous = lock_network()
        .control
        .as_ref()
        .map(|(connection, _)| *connection);
    if previous == current {
        return false;
    }
    if previous.is_some() {
        disable_networking();
        return true;
    }
    if let Some(connection) = current
        && lock_network().config.is_some()
    {
        let task = spawn_task(control::serve(connection));
        lock_network().control = Some((connection, task));
    }
    true
}

fn mark_control_ready() {
    let mut state = lock_network();
    if state.is_control_ready {
        return;
    }
    state.is_control_ready = true;
    let Some(config) = state.config.clone() else {
        return;
    };
    drop(state);
    let listeners = publish::start_listeners(&config.published_ports);
    lock_network().listeners = listeners;
}

pub fn service() -> bool {
    {
        let mut state = lock_network();
        if state.config.is_some() && state.broker_watcher.is_none() {
            state.broker_watcher = Some(spawn_task(async {
                broker::closed().await;
                disable_networking();
            }));
        }
    }
    let mut progressed = synchronize_control();
    let mut connections = switch().flow_connections();
    let (has_config, removed) = {
        let mut state = lock_network();
        let removed = state
            .flows
            .extract_if(.., |flow| {
                !connections.contains(&flow.connection) && !switch().is_connecting(flow.connection)
            })
            .collect::<Vec<_>>();
        connections.retain(|connection| {
            !state
                .flows
                .iter()
                .any(|flow| flow.connection == *connection)
        });
        (state.config.is_some(), removed)
    };
    drop(removed);
    for connection in connections {
        let task = match connection.role {
            Role::Tcp if has_config => spawn_task(tcp::serve(connection)),
            Role::Udp if has_config => spawn_task(udp::serve(connection)),
            Role::Tcp | Role::Udp | Role::Publication | Role::Agent | Role::Control => {
                reset_flow(connection);
                progressed = true;
                continue;
            }
        };
        register_flow(connection, task);
        progressed = true;
    }
    let finished = lock_network()
        .flows
        .iter()
        .filter(|flow| is_flow_drained(flow))
        .map(|flow| flow.connection)
        .collect::<Vec<_>>();
    for connection in finished {
        if !switch().has_pending_replies_for(connection)
            && !transport::has_pending_reply_for(connection)
        {
            reset_flow(connection);
            let removed = {
                let mut state = lock_network();
                state
                    .flows
                    .extract_if(.., |flow| flow.connection == connection)
                    .collect::<Vec<_>>()
            };
            drop(removed);
            progressed = true;
        }
    }
    progressed
}

pub(crate) async fn pump_upstream(
    connection: ConnectionId,
    mut writer: wit_bindgen::StreamWriter<u8>,
) -> Result<(), broker::Error> {
    loop {
        let bytes = wait_upstream(connection, CHUNK_BYTES)
            .await
            .map_err(|()| broker::Error::Cancelled)?;
        if bytes.is_empty() {
            return Ok(());
        }
        let count = bytes.len();
        if !writer.write_all(bytes).await.is_empty() {
            return Err(broker::Error::Closed);
        }
        consume_upstream(connection, count).map_err(|()| broker::Error::Cancelled)?;
    }
}

pub(crate) async fn pump_downstream(
    connection: ConnectionId,
    mut output: wit_bindgen::StreamReader<u8>,
    completion: Option<wit_bindgen::FutureReader<Result<(), broker::Error>>>,
) -> Result<(), broker::Error> {
    loop {
        let maximum_read_bytes = switch()
            .send_capacity(connection)
            .clamp(1, terra_protocol::network::MAX_NETWORK_READ_BYTES);
        let read = std::pin::pin!(output.read(Vec::with_capacity(maximum_read_bytes)));
        let closed = std::pin::pin!(wait_receive_closed(connection));
        let (result, bytes) = match select(read, closed).await {
            Either::Left((result, _)) => result,
            Either::Right(_) => return Ok(()),
        };
        let is_eof = !matches!(result, wit_bindgen::StreamResult::Complete(_)) || bytes.is_empty();
        if let Err(error) = deliver_bytes(connection, bytes).await {
            return if error == SocketError::Closed {
                Ok(())
            } else {
                Err(broker::Error::Cancelled)
            };
        }
        if is_eof {
            if let Some(completion) = completion {
                completion.await?;
            }
            shutdown_flow(connection);
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifying_one_connection_preserves_other_connections_and_publication_waiters() {
        use std::sync::{Arc, atomic::AtomicUsize};
        use std::task::Wake;

        struct WakeCount(AtomicUsize);
        impl Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let first = ConnectionId {
            role: Role::Tcp,
            guest_port: u32::MAX - 1,
            host_port: terra_vsock_device::TCP_VSOCK_PORT,
            number: u64::MAX - 1,
        };
        let second = ConnectionId {
            guest_port: u32::MAX,
            ..first
        };
        let wakes: [_; 3] = std::array::from_fn(|_| Arc::new(WakeCount(AtomicUsize::new(0))));
        {
            let mut state = lock_network();
            wait(&mut state, first, &Waker::from(wakes[0].clone()));
            wait(&mut state, second, &Waker::from(wakes[1].clone()));
            wait_for_publication(&mut state, &Waker::from(wakes[2].clone()));
        }
        notify_connection(first);
        assert_eq!(wakes[0].0.load(Ordering::Relaxed), 1);
        assert_eq!(wakes[1].0.load(Ordering::Relaxed), 0);
        assert_eq!(wakes[2].0.load(Ordering::Relaxed), 0);
        notify_connection(second);
        notify_admission();
        assert_eq!(wakes[1].0.load(Ordering::Relaxed), 1);
        assert_eq!(wakes[2].0.load(Ordering::Relaxed), 1);
    }

    /// Both UDP listener families need admission; TCP and UDP may publish the same host port.
    #[test]
    fn publication_configuration_reserves_udp_capacity_and_distinguishes_transports() {
        use crate::terra::network::types::{Config, Error, PublishedPort, Transport};
        let mut config = Config {
            host_service_ports: Vec::new(),
            published_ports: vec![PublishedPort {
                host_port: 5353,
                guest_port: 53,
                transport: Transport::Udp,
            }],
            flow_capacity: 1,
        };
        assert_eq!(validate_config(&config), Err(Error::Backpressure));
        config.flow_capacity = 2;
        assert_eq!(validate_config(&config), Ok(()));
        config.published_ports.push(PublishedPort {
            host_port: 5353,
            guest_port: 53,
            transport: Transport::Tcp,
        });
        assert_eq!(validate_config(&config), Ok(()));
        config.published_ports.push(config.published_ports[0]);
        assert_eq!(validate_config(&config), Err(Error::Malformed));
    }

    #[test]
    fn mapped_ipv6_destinations_are_canonical_before_broker_calls() {
        let mapped: SocketAddr = "[::ffff:203.0.113.1]:443".parse().unwrap();
        assert_eq!(
            resolve_destination(mapped).unwrap(),
            "203.0.113.1:443".parse().unwrap()
        );
    }

    #[test]
    fn host_service_destinations_require_a_granted_port() {
        lock_network().config = Some(crate::terra::network::types::Config {
            host_service_ports: vec![Some(8080)],
            published_ports: Vec::new(),
            flow_capacity: 128,
        });
        let granted = SocketAddr::new(IpAddr::V4(terra_protocol::socket::HOST_SERVICE_IPV4), 8080);
        assert_eq!(
            resolve_destination(granted),
            Ok("127.0.0.1:8080".parse().unwrap())
        );
        let denied = SocketAddr::new(IpAddr::V6(terra_protocol::socket::HOST_SERVICE_IPV6), 22);
        assert_eq!(resolve_destination(denied), Err(SocketError::AccessDenied));
        lock_network().config = None;
    }
}
