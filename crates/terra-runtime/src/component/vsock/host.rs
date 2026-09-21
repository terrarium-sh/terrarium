//! Fixed local-socket grants for the sandboxed vsock service.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use terra_io::local::{
    AsyncLocalListener as Listener, AsyncLocalStream, LocalListener, LocalStream,
};
type ReadHalf = AsyncLocalStream;
type WriteHalf = AsyncLocalStream;
use wasmtime::StoreContextMut;
use wasmtime::component::{
    Access, Accessor, Destination, Resource, ResourceTable, Source, StreamConsumer, StreamProducer,
    StreamReader, StreamResult, VecBuffer,
};

use crate::SyntheticRam;
use crate::engine::{DeviceContext, DeviceHost, add_device_imports, device_component_linker};
use wasmtime::Engine;
use wasmtime_wasi::{WasiCtxView, WasiView};

pub struct VsockDeviceHost {
    pub context: DeviceContext,
    vsock_service: VsockHostService,
}

impl VsockDeviceHost {
    #[must_use]
    pub fn new(ram: SyntheticRam, service: VsockHostService) -> Self {
        Self {
            context: DeviceContext::with_ram(ram),
            vsock_service: service,
        }
    }

    pub fn vsock_service_mut(&mut self) -> &mut VsockHostService {
        &mut self.vsock_service
    }
}

impl DeviceHost for VsockDeviceHost {
    fn context(&mut self) -> &mut DeviceContext {
        &mut self.context
    }
}
impl WasiView for VsockDeviceHost {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        self.context.ctx()
    }
}

impl AsMut<VsockDeviceHost> for VsockDeviceHost {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl crate::box_runtime::StoreHost for VsockDeviceHost {}

pub fn vsock_component_linker<T: WasiView + AsMut<VsockDeviceHost> + 'static>(
    engine: &Engine,
) -> wasmtime::Result<wasmtime::component::Linker<T>> {
    use wasmtime_wasi::{
        p3::bindings::random::random as random_bindings,
        random::{WasiRandom, WasiRandomView},
    };
    let mut linker = device_component_linker(engine)?;
    random_bindings::add_to_linker::<T, WasiRandom>(&mut linker, WasiRandomView::random)?;
    terra::vsock::host_service::add_to_linker::<T, VsockHost>(&mut linker, |host| {
        host.as_mut().vsock_service_mut()
    })?;
    add_device_imports(&mut linker, |host: &mut T| host.as_mut().context())?;
    Ok(linker)
}

wasmtime::component::bindgen!({
    world: "device",
    path: "../../components/vsock/wit",
    exports: { default: async },
    imports: {
        default: trappable,
        "terra:vsock/host-service.[method]client.input": store | trappable,
        "terra:vsock/host-service.listener": store | trappable,
        "terra:vsock/host-service.plan": store | trappable,
        "terra:vsock/host-service.stop": store | trappable,
    },
    with: {
        "terra:mmio/types@0.1.0": crate::component::vmm::mmio::terra::mmio::types,
    },
});

pub(crate) use Device as VsockBindings;
pub use exports::terra::vsock::api::{Error as VsockError, Event as VsockEvent};

const MAX_CLIENTS: usize = 64;
const CHUNK_BYTES: usize = 16 * 1024;

pub struct VsockHost;

pub struct VsockHostService {
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

impl VsockHostService {
    pub fn new(
        plan: Vec<u8>,
        listener: Option<LocalListener>,
        stop: Option<LocalStream>,
    ) -> io::Result<Self> {
        Ok(Self {
            listener: listener.map(prepare_listener).transpose()?,
            plan: Some(plan),
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
        resource: &Resource<terra::vsock::host_service::Client>,
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
}

impl Default for VsockHostService {
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

impl wasmtime::component::HasData for VsockHost {
    type Data<'a> = &'a mut VsockHostService;
}

impl terra::vsock::host_service::Host for VsockHostService {}

impl terra::vsock::host_service::HostClient for VsockHostService {
    fn shutdown_write(
        &mut self,
        resource: Resource<terra::vsock::host_service::Client>,
    ) -> wasmtime::Result<()> {
        let Some(client) = self.client_mut(&resource) else {
            return Ok(());
        };
        let output = client.output.take();
        if let Some(mut output) = output {
            shutdown_write(&mut output);
        }
        Ok(())
    }

    fn drop(
        &mut self,
        resource: Resource<terra::vsock::host_service::Client>,
    ) -> wasmtime::Result<()> {
        self.resources
            .delete(Resource::<ClientState>::new_own(resource.rep()))?;
        Ok(())
    }
}

impl<T: Send + 'static> terra::vsock::host_service::HostClientWithStore<T> for VsockHost {
    fn input(
        mut access: Access<'_, T, Self>,
        resource: Resource<terra::vsock::host_service::Client>,
    ) -> wasmtime::Result<StreamReader<u8>> {
        let input = access.get().client_mut(&resource).and_then(|client| {
            client
                .input
                .take()
                .map(|input| (input, Arc::clone(&client.lease)))
        });
        let (input, lease) =
            input.ok_or_else(|| wasmtime::Error::msg("vsock input already claimed"))?;
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
        resource: Resource<terra::vsock::host_service::Client>,
        mut bytes: StreamReader<u8>,
    ) -> impl core::future::Future<
        Output = wasmtime::Result<Result<(), terra::vsock::host_service::EndpointError>>,
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
                return Err(terra::vsock::host_service::EndpointError::Closed);
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
                .map_err(|_| terra::vsock::host_service::EndpointError::Io)?;
            Ok(receiver)
        });
        async move {
            let receiver = match completion {
                Ok(receiver) => receiver,
                Err(error) => return Ok(Err(error)),
            };
            Ok(receiver
                .await
                .unwrap_or(Err(terra::vsock::host_service::EndpointError::Closed)))
        }
    }
}

impl<T: Send + 'static> terra::vsock::host_service::HostWithStore<T> for VsockHost {
    fn listener(
        mut access: Access<'_, T, Self>,
    ) -> wasmtime::Result<Option<StreamReader<Resource<terra::vsock::host_service::Client>>>> {
        let Some(listener) = access.get().listener.take() else {
            return Ok(None);
        };
        let getter = access.getter();
        StreamReader::new(&mut access, ListenerProducer { listener, getter }).map(Some)
    }

    fn plan(mut access: Access<'_, T, Self>) -> wasmtime::Result<StreamReader<u8>> {
        let plan = access
            .get()
            .plan
            .take()
            .ok_or_else(|| wasmtime::Error::msg("vsock plan already claimed"))?;
        StreamReader::new(&mut access, plan)
    }

    fn stop(mut access: Access<'_, T, Self>) -> wasmtime::Result<StreamReader<u8>> {
        let stop = {
            let service = access.get();
            if service.stop_issued {
                return Err(wasmtime::Error::msg("vsock stop already claimed"));
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
    getter: for<'a> fn(&'a mut T) -> &'a mut VsockHostService,
}

impl<T: 'static> StreamProducer<T> for ListenerProducer<T> {
    type Item = Resource<terra::vsock::host_service::Client>;
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
        let stream = match poll_listener_accept(&mut this.listener, context, finish) {
            core::task::Poll::Ready(Ok(Some(stream))) => stream,
            core::task::Poll::Ready(Ok(None)) => {
                return core::task::Poll::Ready(Ok(StreamResult::Cancelled));
            }
            core::task::Poll::Ready(Err(error)) => {
                return core::task::Poll::Ready(Err(error.into()));
            }
            core::task::Poll::Pending => return core::task::Poll::Pending,
        };
        let service = (this.getter)(store.data_mut());
        let Some(lease) = service.reserve_client() else {
            return core::task::Poll::Ready(Ok(StreamResult::Completed));
        };
        let state = match client_state(stream, lease) {
            Ok(state) => state,
            Err(error) => {
                return core::task::Poll::Ready(Err(error.into()));
            }
        };
        let resource = match service.resources.push(state) {
            Ok(resource) => Resource::new_own(resource.rep()),
            Err(_) => return core::task::Poll::Ready(Ok(StreamResult::Completed)),
        };
        destination.set_buffer(Some(resource));
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
        Option<tokio::sync::oneshot::Sender<Result<(), terra::vsock::host_service::EndpointError>>>,
}

impl OutputConsumer {
    fn complete(&mut self, result: Result<(), terra::vsock::host_service::EndpointError>) {
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
            this.complete(Err(terra::vsock::host_service::EndpointError::Closed));
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
                this.complete(Err(terra::vsock::host_service::EndpointError::Io));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component::vsock::host::VsockDeviceHost;
    use crate::component::vsock::host::terra::vsock::host_service::{
        HostClient, HostClientWithStore, HostWithStore,
    };
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
        assert!(matches!(
            poll_read_input(
                &mut input,
                &mut Context::from_waker(Waker::noop()),
                &mut buffer
            ),
            Poll::Ready(Ok(5))
        ));
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
        assert!(matches!(
            poll_read_input(&mut input, &mut Context::from_waker(&waker), &mut buffer),
            Poll::Ready(Ok(5))
        ));
        assert_eq!(&buffer, b"later");
    }

    #[tokio::test]
    async fn endpoint_claims_are_single_use_and_stream_leases_hold_client_capacity() {
        let mut service = VsockHostService::default();
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
        let mut service = VsockHostService::default();
        let root = tempfile::tempdir().expect("socket directory");
        let path = root.path().join("socket");
        let listener = LocalListener::bind(&path).expect("listener");
        let stream = LocalStream::connect(&path).expect("client");
        let (_peer, _) = listener.accept().expect("peer");
        let state = client_state(stream, service.reserve_client().expect("client capacity"))
            .expect("client state");
        let entry = service.resources.push(state).expect("resource entry");
        let client_rep = entry.rep();
        let host = VsockDeviceHost::new(crate::SyntheticRam::new(4096).unwrap(), service);
        let engine = crate::engine::device_engine().expect("engine");
        let mut store = wasmtime::Store::new(&engine, host);
        store
            .run_concurrent(async |accessor| {
                let service = accessor.with_getter::<VsockHost>(VsockDeviceHost::vsock_service_mut);
                assert!(
                    service
                        .with(|access| VsockHost::input(access, Resource::new_own(client_rep)))
                        .is_ok()
                );
                assert!(
                    service
                        .with(|access| VsockHost::input(access, Resource::new_own(client_rep)))
                        .is_err()
                );
                assert!(service.with(VsockHost::plan).is_ok());
                assert!(service.with(VsockHost::plan).is_err());
                assert!(service.with(VsockHost::stop).is_ok());
                assert!(service.with(VsockHost::stop).is_err());
            })
            .await
            .expect("concurrent store");
    }

    #[test]
    fn client_leases_bound_open_host_streams_after_resource_drop() {
        let service = VsockHostService::default();
        let leases = (0..MAX_CLIENTS)
            .map(|_| service.reserve_client().expect("available client lease"))
            .collect::<Vec<_>>();
        assert!(service.reserve_client().is_none());
        drop(leases);
        assert_eq!(service.live_clients(), 0);
    }
}
