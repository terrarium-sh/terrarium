//! Fixed local socket grants for authorized agent sessions.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use terra_protocol::{MAX_PLAN_BYTES, MAX_PLAN_HOST_STATE_BYTES};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use terra_platform::io::local::{
    AsyncLocalListener as Listener, AsyncLocalStream, LocalListener, LocalStream,
};
type ReadHalf = AsyncLocalStream;
type WriteHalf = AsyncLocalStream;
use wasmtime::StoreContextMut;
use wasmtime::component::{
    Access, Accessor, Destination, Resource, ResourceTable, Source, StreamConsumer, StreamProducer,
    StreamReader, StreamResult, VecBuffer,
};

use super::bindings::wit as terra;
use crate::component::vsock::streams::{StreamEndpoint, add_role_stream_to_linker};
use wasmtime::Engine;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

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
            ctx: WasiCtxBuilder::new()
                .max_random_size(crate::MAX_SINGLE_BYTES)
                .allow_tcp(false)
                .allow_udp(false)
                .allow_ip_name_lookup(false)
                .build(),
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

const MAX_CLIENTS: usize = terra_protocol::mux::MAX_CLIENT_STREAMS;
const CHUNK_BYTES: usize = terra_protocol::mux::MAX_STREAM_FRAME_BYTES;

pub struct AgentService;

pub struct AgentHostService {
    listener: Option<Listener>,
    plan: Option<Vec<u8>>,
    stop: Option<ReadHalf>,
    stop_issued: bool,
    resources: ResourceTable,
    client_slots: Arc<Semaphore>,
}

struct ClientState {
    input: Option<ReadHalf>,
    output: Option<WriteHalf>,
    lease: Arc<OwnedSemaphorePermit>,
}

impl AgentHostService {
    pub fn new(
        plan: &[u8],
        listener: Option<LocalListener>,
        stop: Option<LocalStream>,
    ) -> io::Result<Self> {
        Ok(Self {
            listener: listener.map(prepare_listener).transpose()?,
            plan: Some(enrich_plan(plan)?),
            stop: stop.map(prepare_stream).transpose()?,
            stop_issued: false,
            resources: client_resources(),
            client_slots: Arc::new(Semaphore::new(MAX_CLIENTS)),
        })
    }

    #[must_use]
    pub fn live_clients(&self) -> usize {
        MAX_CLIENTS - self.client_slots.available_permits()
    }

    fn client_mut(
        &mut self,
        resource: &Resource<terra::agent::host_service::Client>,
    ) -> Option<&mut ClientState> {
        self.resources
            .get_mut(&Resource::new_own(resource.rep()))
            .ok()
    }

    fn reserve_client(&self) -> Option<Arc<OwnedSemaphorePermit>> {
        Arc::clone(&self.client_slots)
            .try_acquire_owned()
            .ok()
            .map(Arc::new)
    }

    fn poll_accept_client(
        &mut self,
        listener: &mut Listener,
        context: &mut core::task::Context<'_>,
        finish: bool,
    ) -> core::task::Poll<io::Result<Option<Resource<ClientState>>>> {
        let stream = match poll_listener_accept(listener, context, finish) {
            core::task::Poll::Ready(Ok(Some(stream))) => stream,
            result => return result.map_ok(|_| None),
        };
        let resource = if let Some(lease) = self.reserve_client() {
            self.resources.push(client_state(stream, lease)?).ok()
        } else {
            None
        };
        match resource {
            Some(resource) => core::task::Poll::Ready(Ok(Some(resource))),
            None if finish => core::task::Poll::Ready(Ok(None)),
            None => {
                context.waker().wake_by_ref();
                core::task::Poll::Pending
            }
        }
    }
}

impl Default for AgentHostService {
    fn default() -> Self {
        Self {
            listener: None,
            plan: Some(Vec::new()),
            stop: None,
            stop_issued: false,
            resources: client_resources(),
            client_slots: Arc::new(Semaphore::new(MAX_CLIENTS)),
        }
    }
}

fn client_resources() -> ResourceTable {
    let mut resources = ResourceTable::new();
    resources.set_max_capacity(MAX_CLIENTS);
    resources
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
    fn input(
        mut access: Access<'_, T, Self>,
        resource: Resource<terra::agent::host_service::Client>,
    ) -> wasmtime::Result<StreamReader<u8>> {
        let input = access.get().client_mut(&resource).and_then(|client| {
            client
                .input
                .take()
                .map(|input| (input, Arc::clone(&client.lease)))
        });
        let (input, lease) =
            input.ok_or_else(|| wasmtime::Error::msg("agent input already claimed"))?;
        StreamReader::new(
            &mut access,
            InputProducer {
                input: Some(input),
                _lease: Some(lease),
            },
        )
    }

    fn output(
        host: &Accessor<T, Self>,
        resource: Resource<terra::agent::host_service::Client>,
        mut bytes: StreamReader<u8>,
    ) -> impl core::future::Future<
        Output = wasmtime::Result<Result<(), terra::agent::host_service::EndpointError>>,
    > + Send {
        let completion = host.with(|mut access| {
            let output = access.get().client_mut(&resource).and_then(|client| {
                client
                    .output
                    .take()
                    .map(|output| (output, Arc::clone(&client.lease)))
            });
            let Some((output, lease)) = output else {
                let _ = bytes.close(&mut access);
                return Err(terra::agent::host_service::EndpointError::Closed);
            };
            let (sender, receiver) = tokio::sync::oneshot::channel();
            bytes
                .pipe(
                    &mut access,
                    OutputConsumer {
                        output: Some(output),
                        _lease: lease,
                        sender: Some(sender),
                    },
                )
                .map_err(|_| terra::agent::host_service::EndpointError::Io)?;
            Ok(receiver)
        });
        async move {
            let receiver = match completion {
                Ok(receiver) => receiver,
                Err(error) => return Ok(Err(error)),
            };
            Ok(receiver
                .await
                .unwrap_or(Err(terra::agent::host_service::EndpointError::Closed)))
        }
    }
}

impl<T: Send + 'static> terra::agent::host_service::HostWithStore<T> for AgentService {
    fn listener(
        mut access: Access<'_, T, Self>,
    ) -> wasmtime::Result<Option<StreamReader<Resource<terra::agent::host_service::Client>>>> {
        let Some(listener) = access.get().listener.take() else {
            return Ok(None);
        };
        let getter = access.getter();
        StreamReader::new(&mut access, ListenerProducer { listener, getter }).map(Some)
    }

    fn plan(mut access: Access<'_, T, Self>) -> wasmtime::Result<Vec<u8>> {
        let plan = access
            .get()
            .plan
            .take()
            .ok_or_else(|| wasmtime::Error::msg("agent plan already claimed"))?;
        Ok(plan)
    }

    fn stop(mut access: Access<'_, T, Self>) -> wasmtime::Result<StreamReader<u8>> {
        let stop = {
            let service = access.get();
            if service.stop_issued {
                return Err(wasmtime::Error::msg("agent stop already claimed"));
            }
            service.stop_issued = true;
            service.stop.take()
        };
        StreamReader::new(
            &mut access,
            InputProducer {
                input: stop,
                _lease: None,
            },
        )
    }
}

struct ListenerProducer<T> {
    listener: Listener,
    getter: for<'a> fn(&'a mut T) -> &'a mut AgentHostService,
}

impl<T: 'static> StreamProducer<T> for ListenerProducer<T> {
    type Item = Resource<terra::agent::host_service::Client>;
    type Buffer = Option<Self::Item>;

    fn poll_produce<'a>(
        mut self: core::pin::Pin<&mut Self>,
        context: &mut core::task::Context<'_>,
        mut store: StoreContextMut<'a, T>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> core::task::Poll<wasmtime::Result<StreamResult>> {
        let this = self.as_mut().get_mut();
        if destination.remaining(&mut store) == Some(0) {
            return poll_listener_ready(&mut this.listener, context, finish);
        }
        let service = (this.getter)(store.data_mut());
        let resource = match service.poll_accept_client(&mut this.listener, context, finish) {
            core::task::Poll::Ready(Ok(Some(resource))) => resource,
            core::task::Poll::Ready(Ok(None)) => {
                return core::task::Poll::Ready(Ok(StreamResult::Cancelled));
            }
            core::task::Poll::Ready(Err(error)) => {
                return core::task::Poll::Ready(Err(error.into()));
            }
            core::task::Poll::Pending => return core::task::Poll::Pending,
        };
        destination.set_buffer(Some(Resource::new_own(resource.rep())));
        core::task::Poll::Ready(Ok(StreamResult::Completed))
    }
}

struct InputProducer {
    input: Option<ReadHalf>,
    _lease: Option<Arc<OwnedSemaphorePermit>>,
}

impl<T: 'static> StreamProducer<T> for InputProducer {
    type Item = u8;
    type Buffer = VecBuffer<u8>;

    fn poll_produce<'a>(
        mut self: core::pin::Pin<&mut Self>,
        context: &mut core::task::Context<'_>,
        store: StoreContextMut<'a, T>,
        destination: Destination<'a, u8, Self::Buffer>,
        finish: bool,
    ) -> core::task::Poll<wasmtime::Result<StreamResult>> {
        let this = self.as_mut().get_mut();
        let Some(input) = this.input.as_mut() else {
            return core::task::Poll::Ready(Ok(StreamResult::Dropped));
        };
        poll_input(input, context, store, destination, finish)
    }
}

struct OutputConsumer {
    output: Option<WriteHalf>,
    _lease: Arc<OwnedSemaphorePermit>,
    sender:
        Option<tokio::sync::oneshot::Sender<Result<(), terra::agent::host_service::EndpointError>>>,
}

impl OutputConsumer {
    fn complete(&mut self, result: Result<(), terra::agent::host_service::EndpointError>) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(result);
        }
    }
}

impl Drop for OutputConsumer {
    fn drop(&mut self) {
        if let Some(mut output) = self.output.take() {
            shutdown_write(&mut output);
        }
        self.complete(Ok(()));
    }
}

impl<T: 'static> StreamConsumer<T> for OutputConsumer {
    type Item = u8;

    fn poll_consume(
        mut self: core::pin::Pin<&mut Self>,
        context: &mut core::task::Context<'_>,
        store: StoreContextMut<T>,
        source: Source<'_, u8>,
        finish: bool,
    ) -> core::task::Poll<wasmtime::Result<StreamResult>> {
        let this = self.as_mut().get_mut();
        let Some(output) = this.output.as_mut() else {
            return core::task::Poll::Ready(Ok(StreamResult::Dropped));
        };
        if finish {
            shutdown_write(output);
            this.complete(Err(terra::agent::host_service::EndpointError::Closed));
            return core::task::Poll::Ready(Ok(StreamResult::Cancelled));
        }
        let mut source = source.as_direct(store);
        let bytes = source.remaining();
        let count = bytes.len().min(CHUNK_BYTES);
        if count == 0 {
            return output
                .poll_write_ready(context)
                .map_ok(|()| StreamResult::Completed)
                .map_err(Into::into);
        }
        match Pin::new(output).poll_write(context, &bytes[..count]) {
            core::task::Poll::Ready(Ok(count)) => {
                source.mark_read(count);
                core::task::Poll::Ready(Ok(StreamResult::Completed))
            }
            core::task::Poll::Ready(Err(_)) => {
                this.complete(Err(terra::agent::host_service::EndpointError::Io));
                core::task::Poll::Ready(Ok(StreamResult::Dropped))
            }
            core::task::Poll::Pending => core::task::Poll::Pending,
        }
    }
}

fn poll_listener_ready(
    listener: &mut Listener,
    context: &mut core::task::Context<'_>,
    finish: bool,
) -> core::task::Poll<wasmtime::Result<StreamResult>> {
    match listener.poll_read_ready(context) {
        core::task::Poll::Ready(Ok(())) => core::task::Poll::Ready(Ok(StreamResult::Completed)),
        core::task::Poll::Ready(Err(error)) => core::task::Poll::Ready(Err(error.into())),
        core::task::Poll::Pending if finish => core::task::Poll::Ready(Ok(StreamResult::Cancelled)),
        core::task::Poll::Pending => core::task::Poll::Pending,
    }
}

fn poll_listener_accept(
    listener: &mut Listener,
    context: &mut core::task::Context<'_>,
    finish: bool,
) -> core::task::Poll<io::Result<Option<LocalStream>>> {
    match listener.poll_accept(context) {
        core::task::Poll::Pending if finish => core::task::Poll::Ready(Ok(None)),
        result => result.map_ok(Some),
    }
}

fn poll_input<T>(
    input: &mut ReadHalf,
    context: &mut core::task::Context<'_>,
    mut store: StoreContextMut<T>,
    destination: Destination<'_, u8, VecBuffer<u8>>,
    finish: bool,
) -> core::task::Poll<wasmtime::Result<StreamResult>> {
    if finish {
        return core::task::Poll::Ready(Ok(StreamResult::Cancelled));
    }
    if destination.remaining(&mut store) == Some(0) {
        return match input.poll_read_ready(context) {
            core::task::Poll::Ready(Ok(())) => core::task::Poll::Ready(Ok(StreamResult::Completed)),
            core::task::Poll::Ready(Err(error)) => core::task::Poll::Ready(Err(error.into())),
            core::task::Poll::Pending => core::task::Poll::Pending,
        };
    }
    let mut destination = destination.as_direct(store, CHUNK_BYTES);
    let bytes = destination.remaining();
    match poll_read_input(input, context, bytes) {
        core::task::Poll::Ready(Ok(0) | Err(_)) => {
            core::task::Poll::Ready(Ok(StreamResult::Dropped))
        }
        core::task::Poll::Ready(Ok(count)) => {
            destination.mark_written(count);
            core::task::Poll::Ready(Ok(StreamResult::Completed))
        }
        core::task::Poll::Pending => core::task::Poll::Pending,
    }
}

fn poll_read_input(
    input: &mut ReadHalf,
    context: &mut core::task::Context<'_>,
    bytes: &mut [u8],
) -> core::task::Poll<io::Result<usize>> {
    let mut buffer = ReadBuf::new(bytes);
    Pin::new(input)
        .poll_read(context, &mut buffer)
        .map_ok(|()| buffer.filled().len())
}

fn prepare_listener(listener: LocalListener) -> io::Result<Listener> {
    Listener::from_std(listener)
}

fn prepare_stream(stream: LocalStream) -> io::Result<AsyncLocalStream> {
    stream.set_nonblocking(true)?;
    AsyncLocalStream::from_std(stream)
}

fn client_state(stream: LocalStream, lease: Arc<OwnedSemaphorePermit>) -> io::Result<ClientState> {
    let writer = stream.try_clone()?;
    Ok(ClientState {
        input: Some(prepare_stream(stream)?),
        output: Some(prepare_stream(writer)?),
        lease,
    })
}

fn shutdown_write(stream: &mut WriteHalf) {
    let _ = Pin::new(stream).poll_shutdown(&mut core::task::Context::from_waker(
        core::task::Waker::noop(),
    ));
}

fn enrich_plan(frame: &[u8]) -> io::Result<Vec<u8>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?;
    let mut seed = [0; 32];
    wasmtime_wasi::random::thread_rng().fill_bytes(&mut seed);
    enrich_plan_with_host_state(
        frame,
        i64::try_from(now.as_secs()).map_err(io::Error::other)?,
        now.subsec_nanos(),
        seed,
    )
}

pub(crate) fn enrich_plan_with_host_state(
    frame: &[u8],
    seconds: i64,
    nanoseconds: u32,
    seed: [u8; 32],
) -> std::io::Result<Vec<u8>> {
    let length: [u8; 4] = frame
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "boot plan has no frame length",
            )
        })?;
    let payload_len = usize::try_from(u32::from_le_bytes(length)).map_err(std::io::Error::other)?;
    if payload_len > MAX_PLAN_BYTES || Some(frame.len()) != payload_len.checked_add(4) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "boot plan frame length is invalid",
        ));
    }
    let mut boot_plan: terra_protocol::BootPlan =
        terra_protocol::decode_frame_payload(&frame[4..])?;
    boot_plan.validate_protocol_versions()?;
    if nanoseconds >= 1_000_000_000 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "host clock nanoseconds are invalid",
        ));
    }
    boot_plan.plan.host_time = Some(terra_protocol::HostTime {
        seconds,
        nanoseconds,
    });
    boot_plan.plan.host_seed = Some(seed);
    let frame = terra_protocol::encode_frame_with_limit(&boot_plan, MAX_PLAN_BYTES)?;
    if (frame.len() - 4).saturating_sub(payload_len) > MAX_PLAN_HOST_STATE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "enriched boot plan exceeds its host-state bound",
        ));
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::terra::agent::host_service::{HostClient, HostClientWithStore, HostWithStore};
    use super::*;
    use crate::component::agent::AgentHost;
    use std::assert_matches;
    #[cfg(unix)]
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(unix)]
    struct ReadWake(AtomicUsize);

    #[cfg(unix)]
    impl std::task::Wake for ReadWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stale_readiness_registers_the_next_readers_waker() {
        use std::io::Write;
        use std::task::{Context, Poll, Waker};
        let directory = tempfile::tempdir().expect("socket directory");
        let path = directory.path().join("socket");
        let listener = LocalListener::bind(&path).expect("listener");
        let mut client = LocalStream::connect(&path).expect("client");
        let (server, _) = listener.accept().expect("peer");
        let mut input = prepare_stream(server).expect("async socket");
        client.write_all(b"first").expect("first write");
        std::future::poll_fn(|cx| input.poll_read_ready(cx))
            .await
            .expect("initial readiness");
        let mut buffer = [0; 5];
        assert_matches!(
            poll_read_input(
                &mut input,
                &mut Context::from_waker(Waker::noop()),
                &mut buffer
            ),
            Poll::Ready(Ok(5))
        );
        let wake = Arc::new(ReadWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wake));
        assert!(
            poll_read_input(&mut input, &mut Context::from_waker(&waker), &mut buffer).is_pending()
        );
        client.write_all(b"later").expect("second write");
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while wake.0.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the new reader must be woken after stale readiness is cleared");
        assert_matches!(
            poll_read_input(&mut input, &mut Context::from_waker(&waker), &mut buffer),
            Poll::Ready(Ok(5))
        );
        assert_eq!(&buffer, b"later");
    }

    #[tokio::test]
    async fn endpoint_claims_are_single_use_and_stream_leases_hold_client_capacity() {
        let mut service = AgentHostService::default();
        let root = tempfile::tempdir().expect("socket directory");
        let path = root.path().join("socket");
        let listener = LocalListener::bind(&path).expect("listener");
        let stream = LocalStream::connect(&path).expect("client");
        let (_peer, _) = listener.accept().expect("peer");
        let state = client_state(stream, service.reserve_client().expect("client capacity"))
            .expect("client state");
        let entry = service.resources.push(state).expect("resource entry");
        let client = Resource::new_own(entry.rep());
        let state = service.client_mut(&client).expect("live client");
        let input = state.input.take();
        assert!(input.is_some());
        assert!(state.input.take().is_none());
        let lease = Arc::clone(&state.lease);
        service.drop(client).expect("drop client resource");
        assert_eq!(service.live_clients(), 1);
        drop(input);
        drop(lease);
        assert_eq!(service.live_clients(), 0);
    }

    #[tokio::test]
    async fn repeated_host_stream_claims_trap_before_allocating_a_transmit() {
        let mut service = AgentHostService::default();
        let root = tempfile::tempdir().expect("socket directory");
        let path = root.path().join("socket");
        let listener = LocalListener::bind(&path).expect("listener");
        let stream = LocalStream::connect(&path).expect("client");
        let (_peer, _) = listener.accept().expect("peer");
        let state = client_state(stream, service.reserve_client().expect("client capacity"))
            .expect("client state");
        let entry = service.resources.push(state).expect("resource entry");
        let client_rep = entry.rep();
        let host = AgentHost::new(StreamEndpoint::new(), service);
        let engine = crate::engine::device_engine().expect("engine");
        let mut store = wasmtime::Store::new(&engine, host);
        store
            .run_concurrent(async |accessor| {
                let service = accessor.with_getter::<AgentService>(AgentHost::agent_service_mut);
                assert!(
                    service
                        .with(|access| AgentService::input(access, Resource::new_own(client_rep)))
                        .is_ok()
                );
                assert!(
                    service
                        .with(|access| AgentService::input(access, Resource::new_own(client_rep)))
                        .is_err()
                );
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
        let leases = (0..MAX_CLIENTS)
            .map(|_| service.reserve_client().expect("available client lease"))
            .collect::<Vec<_>>();
        assert!(service.reserve_client().is_none());
        drop(leases);
        assert_eq!(service.live_clients(), 0);
    }

    #[tokio::test]
    async fn listener_recovers_after_rejecting_a_client_at_capacity() {
        for exhaust_leases in [true, false] {
            let mut service = AgentHostService::default();
            let leases = if exhaust_leases {
                (0..MAX_CLIENTS)
                    .map(|_| service.reserve_client().unwrap())
                    .collect::<Vec<_>>()
            } else {
                service.resources.set_max_capacity(0);
                Vec::new()
            };
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("socket");
            let mut listener = prepare_listener(LocalListener::bind(&path).unwrap()).unwrap();
            let rejected = LocalStream::connect(&path).unwrap();
            std::future::poll_fn(|context| listener.poll_read_ready(context))
                .await
                .unwrap();
            assert!(
                service
                    .poll_accept_client(
                        &mut listener,
                        &mut core::task::Context::from_waker(core::task::Waker::noop()),
                        false,
                    )
                    .is_pending()
            );
            drop(rejected);
            drop(leases);
            service.resources.set_max_capacity(MAX_CLIENTS);
            let _accepted = LocalStream::connect(&path).unwrap();
            let resource = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                std::future::poll_fn(|context| {
                    service.poll_accept_client(&mut listener, context, false)
                }),
            )
            .await
            .expect("capacity rejection must preserve the listener")
            .unwrap()
            .unwrap();
            assert_eq!(service.live_clients(), 1);
            service.resources.delete(resource).unwrap();
            assert_eq!(service.live_clients(), 0);
        }
    }
}

#[cfg(test)]
mod enrichment_tests {
    use super::*;
    use std::collections::BTreeMap;

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
            net: terra_protocol::Net::Tsi,
            published_ports: Vec::new(),
            published_udp_ports: Vec::new(),
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
        let frame =
            terra_protocol::encode_frame(&terra_protocol::BootPlan::new(plan.clone())).unwrap();
        let seed = std::array::from_fn(|index| u8::try_from(index).unwrap());
        let frame = enrich_plan_with_host_state(&frame, 12, 34, seed).unwrap();
        let decoded: terra_protocol::BootPlan = terra_protocol::read_frame(&mut frame.as_slice())
            .unwrap()
            .unwrap();
        plan.host_time = Some(terra_protocol::HostTime {
            seconds: 12,
            nanoseconds: 34,
        });
        plan.host_seed = Some(seed);
        assert_eq!(decoded, terra_protocol::BootPlan::new(plan));
    }

    #[test]
    fn maximum_host_plan_fits_after_host_state_enrichment() {
        let limit = MAX_PLAN_BYTES - MAX_PLAN_HOST_STATE_BYTES;
        let mut boot_plan = terra_protocol::BootPlan::new(test_plan());
        boot_plan.plan.sandbox_info = "x".repeat(limit);
        let overhead = terra_protocol::encode_frame(&boot_plan).unwrap().len() - 4 - limit;
        boot_plan.plan.sandbox_info.truncate(limit - overhead);
        let frame = terra_protocol::encode_frame_with_limit(&boot_plan, limit).unwrap();
        assert_eq!(frame.len(), limit + 4);
        let frame =
            enrich_plan_with_host_state(&frame, i64::MIN, 999_999_999, [u8::MAX; 32]).unwrap();
        assert!(frame.len() <= MAX_PLAN_BYTES + 4);
        let decoded: terra_protocol::BootPlan =
            terra_protocol::read_frame_with_limit(&mut frame.as_slice(), MAX_PLAN_BYTES)
                .unwrap()
                .unwrap();
        assert_eq!(decoded.plan.sandbox_info, boot_plan.plan.sandbox_info);
    }

    #[test]
    fn incompatible_or_unversioned_boot_plan_never_reaches_control_carrier() {
        for (agent_version, socket_version) in [
            (
                terra_protocol::AGENT_PROTOCOL_VERSION - 1,
                terra_protocol::socket::VERSION,
            ),
            (
                terra_protocol::AGENT_PROTOCOL_VERSION,
                terra_protocol::socket::VERSION + 1,
            ),
        ] {
            let mut boot_plan = terra_protocol::BootPlan::new(test_plan());
            boot_plan.agent_version = agent_version;
            boot_plan.socket_version = socket_version;
            let frame = terra_protocol::encode_frame(&boot_plan).unwrap();
            assert!(enrich_plan_with_host_state(&frame, 12, 34, [0; 32]).is_err());
        }
        let bare_plan = terra_protocol::encode_frame(&test_plan()).unwrap();
        assert!(enrich_plan_with_host_state(&bare_plan, 12, 34, [0; 32]).is_err());
    }
}
