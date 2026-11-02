//! Fixed local socket grants for authorized agent sessions.

use std::io;
use std::sync::Arc;

use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use futures_util::stream;
use terra_platform::local_socket::{
    AsyncLocalListener as Listener, AsyncLocalStream, LocalListener, LocalStream, shutdown_write,
};
use terra_protocol::STOP_SIGNAL;
use terra_protocol::mux::{MAX_CLIENT_STREAMS, MAX_STREAM_FRAME_BYTES};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use wasmtime::Engine;
use wasmtime::component::{Access, FutureReader, Resource, ResourceTable, StreamReader};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

use super::bindings::wit as terra;
use crate::component::relay::{
    DirectBuffer, DirectSink, DirectSource, ResourceStream, TryRead, TryWrite,
};
use crate::component::vsock::streams::{StreamEndpoint, add_role_stream_to_linker};

pub struct AgentHost {
    ctx: WasiCtx,
    table: ResourceTable,
    endpoint: StreamEndpoint,
    agent_service: AgentHostService,
}

impl AgentHost {
    #[must_use]
    pub fn new(endpoint: StreamEndpoint, service: AgentHostService) -> Self {
        Self {
            ctx: crate::component::context::isolated_wasi_ctx(),
            table: ResourceTable::new(),
            endpoint,
            agent_service: service,
        }
    }

    pub fn agent_service_mut(&mut self) -> &mut AgentHostService {
        &mut self.agent_service
    }
}

impl WasiView for AgentHost {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

impl AsMut<AgentHost> for AgentHost {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl crate::box_runtime::store::StoreHost for AgentHost {}

pub fn agent_component_linker<T: WasiView + AsMut<AgentHost> + 'static>(
    engine: &Engine,
) -> wasmtime::Result<wasmtime::component::Linker<T>> {
    let mut linker = wasmtime::component::Linker::new(engine);
    wasmtime_wasi::p3::cli::add_to_linker(&mut linker)?;
    crate::component::clocks::add_monotonic_now_and_wait_for(&mut linker)?;
    crate::component::clocks::add_system_clock_now(&mut linker)?;
    terra::agent::host_service::add_to_linker::<T, AgentService>(&mut linker, |host| {
        host.as_mut().agent_service_mut()
    })?;
    add_role_stream_to_linker(&mut linker, |host: &mut T| &mut host.as_mut().endpoint)?;
    Ok(linker)
}

type Lease = Arc<OwnedSemaphorePermit>;
type Socket = Arc<AsyncLocalStream>;

pub struct AgentService;

pub struct AgentHostService {
    listener: Option<Listener>,
    plan: Option<Vec<u8>>,
    stop: StopClaim,
    resources: ResourceTable,
    client_slots: Arc<Semaphore>,
}

/// The stop socket, if the box has one, which the guest claims once as its stop future.
enum StopClaim {
    Unclaimed(Option<Socket>),
    Claimed,
}

/// The client resource and its two streams each hold a lease, so `client_slots` bounds open sockets.
struct ClientState {
    /// The socket until `connect` takes it.
    socket: Option<Socket>,
    lease: Lease,
}

impl AgentHostService {
    pub fn new(
        plan: &[u8],
        listener: Option<LocalListener>,
        stop: Option<LocalStream>,
    ) -> io::Result<Self> {
        Ok(Self {
            listener: listener.map(Listener::from_std).transpose()?,
            plan: Some(append_host_state(plan.to_vec())?),
            stop: StopClaim::Unclaimed(stop.map(prepare_socket).transpose()?),
            ..Self::default()
        })
    }

    #[must_use]
    pub fn live_clients(&self) -> usize {
        MAX_CLIENT_STREAMS - self.client_slots.available_permits()
    }

    fn client_mut(
        &mut self,
        resource: &Resource<terra::agent::host_service::Client>,
    ) -> Option<&mut ClientState> {
        self.resources
            .get_mut(&Resource::new_own(resource.rep()))
            .ok()
    }
}

impl Default for AgentHostService {
    fn default() -> Self {
        Self {
            listener: None,
            plan: Some(Vec::new()),
            stop: StopClaim::Unclaimed(None),
            resources: ResourceTable::new(),
            client_slots: Arc::new(Semaphore::new(MAX_CLIENT_STREAMS)),
        }
    }
}

impl wasmtime::component::HasData for AgentService {
    type Data<'a> = &'a mut AgentHostService;
}

impl terra::agent::host_service::Host for AgentHostService {}

impl terra::agent::host_service::HostClient for AgentHostService {
    fn drop(
        &mut self,
        resource: Resource<terra::agent::host_service::Client>,
    ) -> wasmtime::Result<()> {
        self.resources
            .delete(Resource::<ClientState>::new_own(resource.rep()))?;
        Ok(())
    }
}

impl<T: Send + 'static> terra::agent::host_service::HostClientWithStore<T> for AgentService {
    fn connect(
        mut access: Access<'_, T, Self>,
        resource: Resource<terra::agent::host_service::Client>,
        output: StreamReader<u8>,
    ) -> wasmtime::Result<StreamReader<u8>> {
        let client = access
            .get()
            .client_mut(&resource)
            .ok_or_else(|| wasmtime::Error::msg("unknown agent client"))?;
        let socket = client
            .socket
            .take()
            .ok_or_else(|| wasmtime::Error::msg("agent client already connected"))?;
        let lease = Arc::clone(&client.lease);
        let sink = DirectSink::new(SocketOutput {
            socket: Arc::clone(&socket),
            _lease: Arc::clone(&lease),
        });
        output.pipe(&mut access, sink)?;
        let input = SocketInput {
            socket: Some(socket),
            _lease: Some(lease),
        };
        StreamReader::new(
            &mut access,
            DirectSource::new(input, MAX_STREAM_FRAME_BYTES),
        )
    }
}

impl<T: Send + 'static> terra::agent::host_service::HostWithStore<T> for AgentService {
    fn listener(
        mut access: Access<'_, T, Self>,
    ) -> wasmtime::Result<Option<StreamReader<Resource<terra::agent::host_service::Client>>>> {
        let service = access.get();
        let Some(listener) = service.listener.take() else {
            return Ok(None);
        };
        let clients = accept_clients(listener, Arc::clone(&service.client_slots));
        let getter = access.getter();
        let push = move |data: &mut T, client: io::Result<ClientState>| {
            let resource = getter(data).resources.push(client?)?;
            Ok(Some(Resource::new_own(resource.rep())))
        };
        StreamReader::new(&mut access, ResourceStream::new(clients, push)).map(Some)
    }

    fn plan(mut access: Access<'_, T, Self>) -> wasmtime::Result<Vec<u8>> {
        let plan = access
            .get()
            .plan
            .take()
            .ok_or_else(|| wasmtime::Error::msg("agent plan already claimed"))?;
        Ok(plan)
    }

    fn stop(mut access: Access<'_, T, Self>) -> wasmtime::Result<FutureReader<()>> {
        let StopClaim::Unclaimed(socket) =
            std::mem::replace(&mut access.get().stop, StopClaim::Claimed)
        else {
            return Err(wasmtime::Error::msg("agent stop already claimed"));
        };
        FutureReader::new(&mut access, async move {
            if let Some(socket) = socket
                && read_stop_signal(&socket).await
            {
                return Ok::<_, wasmtime::Error>(());
            }
            std::future::pending().await
        })
    }
}

fn accept_clients(
    listener: Listener,
    slots: Arc<Semaphore>,
) -> impl futures_util::Stream<Item = io::Result<ClientState>> + Send + 'static {
    stream::unfold((listener, slots), |(listener, slots)| async move {
        let client = accept_client(&listener, &slots).await;
        Some((client, (listener, slots)))
    })
}

/// Connections beyond `MAX_CLIENT_STREAMS` are accepted and closed at once, so the client sees EOF.
async fn accept_client(listener: &Listener, slots: &Arc<Semaphore>) -> io::Result<ClientState> {
    loop {
        let stream = listener.accept().await?;
        if let Some(lease) = reserve_client(slots) {
            return client_state(stream, lease);
        }
    }
}

fn reserve_client(slots: &Arc<Semaphore>) -> Option<Lease> {
    Arc::clone(slots).try_acquire_owned().ok().map(Arc::new)
}

/// A host socket's bytes, read straight into the guest; no socket reads as an immediate end.
struct SocketInput {
    socket: Option<Socket>,
    _lease: Option<Lease>,
}

impl DirectBuffer for SocketInput {
    fn changed(&mut self) -> BoxFuture<'static, ()> {
        let socket = self.socket.clone();
        async move {
            if let Some(socket) = socket {
                let _ = socket.readable().await;
            }
        }
        .boxed()
    }
}

/// A read error ends the stream like EOF.
impl TryRead for SocketInput {
    fn try_read(&mut self, buffer: &mut [u8]) -> Option<usize> {
        match self.socket.as_ref()?.try_read(buffer) {
            Ok(0) => None,
            Ok(count) => Some(count),
            Err(error) => would_block(&error),
        }
    }
}

/// The guest's bytes, written straight into a host socket; dropping it ends the socket's write
/// direction, so the client reads EOF.
struct SocketOutput {
    socket: Socket,
    _lease: Lease,
}

impl Drop for SocketOutput {
    fn drop(&mut self) {
        let _ = shutdown_write(&self.socket);
    }
}

impl DirectBuffer for SocketOutput {
    fn changed(&mut self) -> BoxFuture<'static, ()> {
        let socket = Arc::clone(&self.socket);
        async move {
            let _ = socket.writable().await;
        }
        .boxed()
    }
}

impl TryWrite for SocketOutput {
    fn try_write(&mut self, bytes: &[u8]) -> Option<usize> {
        match self.socket.try_write(bytes) {
            Ok(count) => Some(count),
            Err(error) => would_block(&error),
        }
    }
}

/// `Some(0)` when the socket is merely not ready, `None` for a real error.
fn would_block(error: &io::Error) -> Option<usize> {
    (error.kind() == io::ErrorKind::WouldBlock).then_some(0)
}

/// Whether the stop socket's first byte is [`STOP_SIGNAL`]; EOF or an error is no stop request.
async fn read_stop_signal(socket: &AsyncLocalStream) -> bool {
    let mut byte = [0];
    loop {
        if socket.readable().await.is_err() {
            return false;
        }
        match socket.try_read(&mut byte) {
            Ok(count) => return count == 1 && byte == [STOP_SIGNAL],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => return false,
        }
    }
}

fn prepare_socket(stream: LocalStream) -> io::Result<Socket> {
    stream.set_nonblocking(true)?;
    AsyncLocalStream::from_std(stream).map(Arc::new)
}

fn client_state(stream: LocalStream, lease: Lease) -> io::Result<ClientState> {
    Ok(ClientState {
        socket: Some(prepare_socket(stream)?),
        lease,
    })
}

/// Appends the host's clock and a fresh seed, sampled now, after the boot plan frame.
fn append_host_state(mut plan: Vec<u8>) -> io::Result<Vec<u8>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?;
    let mut seed = [0; 32];
    wasmtime_wasi::random::thread_rng().fill_bytes(&mut seed);
    let state = terra_protocol::HostState {
        time: terra_protocol::HostTime {
            seconds: i64::try_from(now.as_secs()).map_err(io::Error::other)?,
            nanoseconds: now.subsec_nanos(),
        },
        seed,
    };
    plan.extend(terra_protocol::encode_frame(&state)?);
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::terra::agent::host_service::{HostClient, HostClientWithStore, HostWithStore};
    use super::*;
    use crate::component::agent::AgentHost;

    fn connected_client(service: &mut AgentHostService) -> (Resource<ClientState>, LocalStream) {
        let root = tempfile::tempdir().expect("socket directory");
        let path = root.path().join("socket");
        let listener = LocalListener::bind(&path).expect("listener");
        let stream = LocalStream::connect(&path).expect("client");
        let (peer, _) = listener.accept().expect("peer");
        let lease = reserve_client(&service.client_slots).expect("client capacity");
        let state = client_state(stream, lease).expect("client state");
        (service.resources.push(state).expect("resource entry"), peer)
    }

    #[tokio::test]
    async fn endpoint_claims_are_single_use_and_stream_leases_hold_client_capacity() {
        let mut service = AgentHostService::default();
        let (entry, _peer) = connected_client(&mut service);
        let client = Resource::new_own(entry.rep());
        let state = service.client_mut(&client).expect("live client");
        let socket = state.socket.take();
        assert!(socket.is_some());
        assert!(state.socket.take().is_none());
        let lease = Arc::clone(&state.lease);
        service.drop(client).expect("drop client resource");
        assert_eq!(service.live_clients(), 1);
        drop(socket);
        drop(lease);
        assert_eq!(service.live_clients(), 0);
    }

    #[tokio::test]
    async fn repeated_host_claims_trap_before_allocating_a_transmit() {
        let mut service = AgentHostService::default();
        let (entry, _peer) = connected_client(&mut service);
        let client_rep = entry.rep();
        let host = AgentHost::new(StreamEndpoint::new(), service);
        let engine = crate::engine::device_engine().expect("engine");
        let mut store = crate::engine::device_store(&engine, host);
        store
            .run_concurrent(async |accessor| {
                let service = accessor.with_getter::<AgentService>(AgentHost::agent_service_mut);
                let connect = |mut access: Access<'_, AgentHost, AgentService>| {
                    let output = StreamReader::new(&mut access, Vec::<u8>::new())?;
                    AgentService::connect(access, Resource::new_own(client_rep), output)
                };
                assert!(service.with(connect).is_ok());
                assert!(service.with(connect).is_err());
                assert!(service.with(AgentService::plan).is_ok());
                assert!(service.with(AgentService::plan).is_err());
                assert!(service.with(AgentService::stop).is_ok());
                assert!(service.with(AgentService::stop).is_err());
            })
            .await
            .expect("concurrent store");
    }

    #[test]
    fn client_leases_bound_open_host_streams_after_resource_drop() {
        let service = AgentHostService::default();
        let leases = (0..MAX_CLIENT_STREAMS)
            .map(|_| reserve_client(&service.client_slots).expect("available client lease"))
            .collect::<Vec<_>>();
        assert!(reserve_client(&service.client_slots).is_none());
        drop(leases);
        assert_eq!(service.live_clients(), 0);
    }

    /// The guest's bytes reach the client, and ending the stream shuts the socket's write direction
    /// and frees the client slot.
    #[tokio::test]
    async fn output_reaches_the_client_then_shuts_down_and_releases_the_lease() {
        use std::io::Read;
        let slots = Arc::new(Semaphore::new(MAX_CLIENT_STREAMS));
        let (server, mut client) = terra_platform::local_socket::create_local_pair().unwrap();
        let output = SocketOutput {
            socket: prepare_socket(server).unwrap(),
            _lease: reserve_client(&slots).unwrap(),
        };
        let engine = crate::engine::device_engine().unwrap();
        let mut store = crate::engine::device_store(&engine, ());
        StreamReader::new(&mut store, b"session output".to_vec())
            .unwrap()
            .pipe(&mut store, DirectSink::new(output))
            .unwrap();
        store
            .run_concurrent(async |_| {
                tokio::time::timeout(std::time::Duration::from_secs(1), async {
                    while slots.available_permits() != MAX_CLIENT_STREAMS {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("the sink is dropped once the stream ends");
            })
            .await
            .unwrap();
        let mut received = Vec::new();
        client.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"session output");
    }

    #[tokio::test]
    async fn clients_beyond_capacity_see_eof_and_the_listener_accepts_after_release() {
        use tokio::io::AsyncReadExt;
        let slots = Arc::new(Semaphore::new(MAX_CLIENT_STREAMS));
        let leases = (0..MAX_CLIENT_STREAMS)
            .map(|_| reserve_client(&slots).unwrap())
            .collect::<Vec<_>>();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("socket");
        let listener = Listener::from_std(LocalListener::bind(&path).unwrap()).unwrap();
        let accepting = accept_client(&listener, &slots);
        tokio::pin!(accepting);
        let mut rejected = AsyncLocalStream::connect(&path).await.unwrap();
        let mut byte = [0];
        tokio::select! {
            _ = &mut accepting => panic!("a client beyond capacity was accepted"),
            read = rejected.read(&mut byte) => assert!(matches!(read, Ok(0) | Err(_))),
        }
        drop(leases);
        let _accepted = AsyncLocalStream::connect(&path).await.unwrap();
        let client = tokio::time::timeout(std::time::Duration::from_secs(1), accepting)
            .await
            .expect("capacity rejection must preserve the listener")
            .unwrap();
        assert_eq!(slots.available_permits(), MAX_CLIENT_STREAMS - 1);
        drop(client);
        assert_eq!(slots.available_permits(), MAX_CLIENT_STREAMS);
    }
}
