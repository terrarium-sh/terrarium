//! Fixed local-socket grants for the sandboxed vsock service.

use std::io;
#[cfg(windows)]
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use terra_io::local::{LocalListener, LocalStream};
use wasmtime::StoreContextMut;
use wasmtime::component::{
    Accessor, Destination, Resource, ResourceTable, Source, StreamConsumer, StreamProducer,
    StreamReader, StreamResult, VecBuffer,
};

wasmtime::component::bindgen!({
    world: "device",
    path: "../../components/vsock/wit",
    imports: { default: trappable },
});

const MAX_CLIENTS: usize = 64;
const CHUNK_BYTES: usize = 16 * 1024;

#[cfg(unix)]
type Listener = tokio::io::unix::AsyncFd<LocalListener>;
#[cfg(unix)]
type ReadHalf = tokio::io::unix::AsyncFd<LocalStream>;
#[cfg(unix)]
type WriteHalf = tokio::io::unix::AsyncFd<LocalStream>;
#[cfg(windows)]
type Listener = LocalListener;
#[cfg(windows)]
type ReadHalf = LocalStream;
#[cfg(windows)]
type WriteHalf = LocalStream;

pub struct VsockHost;

pub struct VsockHostService {
    listener: Option<Listener>,
    plan: Option<Vec<u8>>,
    stop: Option<ReadHalf>,
    stop_issued: bool,
    resources: ResourceTable,
    live_clients: Arc<AtomicUsize>,
}

struct ClientState {
    input: Option<ReadHalf>,
    output: Option<WriteHalf>,
    lease: Arc<ClientLease>,
}

struct ClientLease(Arc<AtomicUsize>);

impl Drop for ClientLease {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
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
            live_clients: Arc::new(AtomicUsize::new(0)),
        })
    }

    #[must_use]
    pub fn live_clients(&self) -> usize {
        self.live_clients.load(Ordering::Acquire)
    }

    fn client_mut(
        &mut self,
        resource: &Resource<terra::vsock::host_service::Client>,
    ) -> Option<&mut ClientState> {
        self.resources
            .get_mut(&Resource::new_own(resource.rep()))
            .ok()
    }

    fn reserve_client(&self) -> Option<Arc<ClientLease>> {
        self.live_clients
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_CLIENTS).then_some(count + 1)
            })
            .ok()
            .map(|_| Arc::new(ClientLease(Arc::clone(&self.live_clients))))
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
            live_clients: Arc::new(AtomicUsize::new(0)),
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
        if let Some(output) = output {
            shutdown_write(&output);
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
    async fn input(
        host: &Accessor<T, Self>,
        resource: Resource<terra::vsock::host_service::Client>,
    ) -> wasmtime::Result<StreamReader<u8>> {
        host.with(|mut access| {
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
                    #[cfg(windows)]
                    retry: None,
                },
            )
        })
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
                        #[cfg(windows)]
                        retry: None,
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
    async fn listener(
        host: &Accessor<T, Self>,
    ) -> wasmtime::Result<Option<StreamReader<Resource<terra::vsock::host_service::Client>>>> {
        host.with(|mut access| {
            let Some(listener) = access.get().listener.take() else {
                return Ok(None);
            };
            let getter = host.getter();
            StreamReader::new(
                &mut access,
                ListenerProducer {
                    listener,
                    getter,
                    #[cfg(windows)]
                    retry: None,
                },
            )
            .map(Some)
        })
    }

    async fn plan(host: &Accessor<T, Self>) -> wasmtime::Result<StreamReader<u8>> {
        host.with(|mut access| {
            let plan = access
                .get()
                .plan
                .take()
                .ok_or_else(|| wasmtime::Error::msg("vsock plan already claimed"))?;
            StreamReader::new(&mut access, plan)
        })
    }

    async fn stop(host: &Accessor<T, Self>) -> wasmtime::Result<StreamReader<u8>> {
        host.with(|mut access| {
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
                    #[cfg(windows)]
                    retry: None,
                },
            )
        })
    }
}

struct ListenerProducer<T> {
    listener: Listener,
    getter: for<'a> fn(&'a mut T) -> &'a mut VsockHostService,
    #[cfg(windows)]
    retry: Option<Pin<Box<tokio::time::Sleep>>>,
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
            return poll_listener_ready(
                &mut this.listener,
                context,
                finish,
                #[cfg(windows)]
                &mut this.retry,
            );
        }
        let stream = match poll_listener_accept(
            &mut this.listener,
            context,
            finish,
            #[cfg(windows)]
            &mut this.retry,
        ) {
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
    _lease: Option<Arc<ClientLease>>,
    #[cfg(windows)]
    retry: Option<Pin<Box<tokio::time::Sleep>>>,
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
        poll_input(
            input,
            context,
            store,
            destination,
            finish,
            #[cfg(windows)]
            &mut this.retry,
        )
    }
}

struct OutputConsumer {
    output: Option<WriteHalf>,
    _lease: Arc<ClientLease>,
    sender:
        Option<tokio::sync::oneshot::Sender<Result<(), terra::vsock::host_service::EndpointError>>>,
    #[cfg(windows)]
    retry: Option<Pin<Box<tokio::time::Sleep>>>,
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
        if let Some(output) = self.output.take() {
            shutdown_write(&output);
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
        #[cfg(windows)]
        return poll_output(
            output,
            context,
            store,
            source,
            &mut this.retry,
            &mut this.sender,
        );
        #[cfg(unix)]
        {
            let mut source = source.as_direct(store);
            let bytes = source.remaining();
            let count = bytes.len().min(CHUNK_BYTES);
            let mut ready = match output.poll_write_ready(context) {
                core::task::Poll::Ready(Ok(ready)) => ready,
                core::task::Poll::Ready(Err(error)) => {
                    return core::task::Poll::Ready(Err(error.into()));
                }
                core::task::Poll::Pending => return core::task::Poll::Pending,
            };
            if count == 0 {
                return core::task::Poll::Ready(Ok(StreamResult::Completed));
            }
            match ready
                .try_io(|stream| std::io::Write::write(&mut stream.get_ref(), &bytes[..count]))
            {
                Ok(Ok(count)) => {
                    source.mark_read(count);
                    core::task::Poll::Ready(Ok(StreamResult::Completed))
                }
                Ok(Err(_)) => {
                    this.complete(Err(terra::vsock::host_service::EndpointError::Io));
                    core::task::Poll::Ready(Ok(StreamResult::Dropped))
                }
                Err(_) => core::task::Poll::Pending,
            }
        }
    }
}

#[cfg(unix)]
fn poll_listener_ready(
    listener: &mut Listener,
    context: &mut core::task::Context<'_>,
    finish: bool,
) -> core::task::Poll<wasmtime::Result<StreamResult>> {
    match listener.poll_read_ready(context) {
        core::task::Poll::Ready(Ok(_)) => core::task::Poll::Ready(Ok(StreamResult::Completed)),
        core::task::Poll::Ready(Err(error)) => core::task::Poll::Ready(Err(error.into())),
        core::task::Poll::Pending if finish => core::task::Poll::Ready(Ok(StreamResult::Cancelled)),
        core::task::Poll::Pending => core::task::Poll::Pending,
    }
}

#[cfg(unix)]
fn poll_listener_accept(
    listener: &mut Listener,
    context: &mut core::task::Context<'_>,
    finish: bool,
) -> core::task::Poll<io::Result<Option<LocalStream>>> {
    let mut ready = match listener.poll_read_ready(context) {
        core::task::Poll::Ready(Ok(ready)) => ready,
        core::task::Poll::Ready(Err(error)) => return core::task::Poll::Ready(Err(error)),
        core::task::Poll::Pending if finish => return core::task::Poll::Ready(Ok(None)),
        core::task::Poll::Pending => return core::task::Poll::Pending,
    };
    match ready.try_io(|listener| listener.get_ref().accept().map(|(stream, _)| stream)) {
        Ok(stream) => core::task::Poll::Ready(stream.map(Some)),
        Err(_) => core::task::Poll::Pending,
    }
}

#[cfg(windows)]
fn poll_listener_ready(
    listener: &mut Listener,
    context: &mut core::task::Context<'_>,
    finish: bool,
    retry: &mut Option<Pin<Box<tokio::time::Sleep>>>,
) -> core::task::Poll<wasmtime::Result<StreamResult>> {
    if finish {
        return core::task::Poll::Ready(Ok(StreamResult::Cancelled));
    }
    let _ = listener;
    retry_pending(retry, context)
}

#[cfg(windows)]
fn poll_listener_accept(
    listener: &mut Listener,
    context: &mut core::task::Context<'_>,
    finish: bool,
    retry: &mut Option<Pin<Box<tokio::time::Sleep>>>,
) -> core::task::Poll<io::Result<Option<LocalStream>>> {
    match listener.accept() {
        Ok((stream, _)) => core::task::Poll::Ready(Ok(Some(stream))),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock && finish => {
            core::task::Poll::Ready(Ok(None))
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            match poll_retry(retry, context) {
                core::task::Poll::Ready(()) => {
                    context.waker().wake_by_ref();
                    core::task::Poll::Pending
                }
                core::task::Poll::Pending => core::task::Poll::Pending,
            }
        }
        Err(error) => core::task::Poll::Ready(Err(error)),
    }
}

#[cfg(windows)]
fn poll_retry(
    retry: &mut Option<Pin<Box<tokio::time::Sleep>>>,
    context: &mut core::task::Context<'_>,
) -> core::task::Poll<()> {
    use core::future::Future;

    let sleep = retry
        .get_or_insert_with(|| Box::pin(tokio::time::sleep(std::time::Duration::from_millis(1))));
    match sleep.as_mut().poll(context) {
        core::task::Poll::Ready(()) => {
            *retry = None;
            core::task::Poll::Ready(())
        }
        core::task::Poll::Pending => core::task::Poll::Pending,
    }
}

#[cfg(windows)]
fn retry_pending(
    retry: &mut Option<Pin<Box<tokio::time::Sleep>>>,
    context: &mut core::task::Context<'_>,
) -> core::task::Poll<wasmtime::Result<StreamResult>> {
    match poll_retry(retry, context) {
        core::task::Poll::Ready(()) => {
            context.waker().wake_by_ref();
            core::task::Poll::Pending
        }
        core::task::Poll::Pending => core::task::Poll::Pending,
    }
}

#[cfg(unix)]
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
            core::task::Poll::Ready(Ok(_)) => core::task::Poll::Ready(Ok(StreamResult::Completed)),
            core::task::Poll::Ready(Err(error)) => core::task::Poll::Ready(Err(error.into())),
            core::task::Poll::Pending => core::task::Poll::Pending,
        };
    }
    let mut destination = destination.as_direct(store, CHUNK_BYTES);
    let bytes = destination.remaining();
    let mut ready = match input.poll_read_ready(context) {
        core::task::Poll::Ready(Ok(ready)) => ready,
        core::task::Poll::Ready(Err(error)) => return core::task::Poll::Ready(Err(error.into())),
        core::task::Poll::Pending => return core::task::Poll::Pending,
    };
    match ready.try_io(|stream| std::io::Read::read(&mut stream.get_ref(), bytes)) {
        Ok(Ok(0) | Err(_)) => core::task::Poll::Ready(Ok(StreamResult::Dropped)),
        Ok(Ok(count)) => {
            destination.mark_written(count);
            core::task::Poll::Ready(Ok(StreamResult::Completed))
        }
        Err(_) => core::task::Poll::Pending,
    }
}

#[cfg(windows)]
fn poll_output<T>(
    output: &mut WriteHalf,
    context: &mut core::task::Context<'_>,
    store: StoreContextMut<T>,
    source: Source<'_, u8>,
    retry: &mut Option<Pin<Box<tokio::time::Sleep>>>,
    sender: &mut Option<
        tokio::sync::oneshot::Sender<Result<(), terra::vsock::host_service::EndpointError>>,
    >,
) -> core::task::Poll<wasmtime::Result<StreamResult>> {
    let mut source = source.as_direct(store);
    let bytes = source.remaining();
    let count = bytes.len().min(CHUNK_BYTES);
    if count == 0 {
        return poll_retry(retry, context).map(|()| Ok(StreamResult::Completed));
    }
    match std::io::Write::write(output, &bytes[..count]) {
        Ok(count) => {
            source.mark_read(count);
            core::task::Poll::Ready(Ok(StreamResult::Completed))
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => retry_pending(retry, context),
        Err(_) => {
            if let Some(sender) = sender.take() {
                let _ = sender.send(Err(terra::vsock::host_service::EndpointError::Io));
            }
            core::task::Poll::Ready(Ok(StreamResult::Dropped))
        }
    }
}

#[cfg(windows)]
fn poll_input<T>(
    input: &mut ReadHalf,
    context: &mut core::task::Context<'_>,
    mut store: StoreContextMut<T>,
    destination: Destination<'_, u8, VecBuffer<u8>>,
    finish: bool,
    retry: &mut Option<Pin<Box<tokio::time::Sleep>>>,
) -> core::task::Poll<wasmtime::Result<StreamResult>> {
    if finish {
        return core::task::Poll::Ready(Ok(StreamResult::Cancelled));
    }
    if destination.remaining(&mut store) == Some(0) {
        return poll_retry(retry, context).map(|()| Ok(StreamResult::Completed));
    }
    let mut destination = destination.as_direct(store, CHUNK_BYTES);
    let bytes = destination.remaining();
    match std::io::Read::read(input, bytes) {
        Ok(0) => core::task::Poll::Ready(Ok(StreamResult::Dropped)),
        Ok(count) => {
            destination.mark_written(count);
            core::task::Poll::Ready(Ok(StreamResult::Completed))
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => retry_pending(retry, context),
        Err(_) => core::task::Poll::Ready(Ok(StreamResult::Dropped)),
    }
}

#[cfg(unix)]
fn prepare_listener(listener: LocalListener) -> io::Result<Listener> {
    listener.set_nonblocking(true)?;
    tokio::io::unix::AsyncFd::new(listener)
}

#[cfg(windows)]
fn prepare_listener(listener: LocalListener) -> io::Result<Listener> {
    listener.set_nonblocking(true)?;
    Ok(listener)
}

#[cfg(unix)]
fn prepare_stream(stream: LocalStream) -> io::Result<ReadHalf> {
    stream.set_nonblocking(true)?;
    tokio::io::unix::AsyncFd::new(stream)
}

#[cfg(windows)]
fn prepare_stream(stream: LocalStream) -> io::Result<ReadHalf> {
    stream.set_nonblocking(true)?;
    Ok(stream)
}

#[cfg(unix)]
fn client_state(stream: LocalStream, lease: Arc<ClientLease>) -> io::Result<ClientState> {
    stream.set_nonblocking(true)?;
    let writer = stream.try_clone()?;
    Ok(ClientState {
        input: Some(tokio::io::unix::AsyncFd::new(stream)?),
        output: Some(tokio::io::unix::AsyncFd::new(writer)?),
        lease,
    })
}

#[cfg(windows)]
fn client_state(stream: LocalStream, lease: Arc<ClientLease>) -> io::Result<ClientState> {
    stream.set_nonblocking(true)?;
    let writer = stream.try_clone()?;
    Ok(ClientState {
        input: Some(stream),
        output: Some(writer),
        lease,
    })
}

#[cfg(unix)]
fn shutdown_write(stream: &WriteHalf) {
    let _ = stream.get_ref().shutdown(std::net::Shutdown::Write);
}

#[cfg(windows)]
fn shutdown_write(stream: &WriteHalf) {
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::component::vsock::host::terra::vsock::host_service::{
        HostClient, HostClientWithStore, HostWithStore,
    };
    use crate::engine::DeviceHost;

    #[tokio::test]
    async fn endpoint_claims_are_single_use_and_stream_leases_hold_client_capacity() {
        let live_clients = Arc::new(AtomicUsize::new(1));
        let (stream, _) = LocalStream::pair().expect("local stream pair");
        let state = client_state(stream, Arc::new(ClientLease(Arc::clone(&live_clients))))
            .expect("client state");
        let mut service = VsockHostService {
            live_clients: Arc::clone(&live_clients),
            ..VsockHostService::default()
        };
        let entry = service.resources.push(state).expect("resource entry");
        let client = Resource::new_own(entry.rep());
        let state = service.client_mut(&client).expect("live client");
        let input = state.input.take();
        assert!(input.is_some());
        assert!(state.input.take().is_none());
        let lease = Arc::clone(&state.lease);
        service.drop(client).expect("drop client resource");
        assert_eq!(live_clients.load(Ordering::Acquire), 1);
        drop(input);
        drop(lease);
        assert_eq!(live_clients.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn repeated_host_stream_claims_trap_before_allocating_a_transmit() {
        let live_clients = Arc::new(AtomicUsize::new(1));
        let (stream, _) = LocalStream::pair().expect("local stream pair");
        let state = client_state(stream, Arc::new(ClientLease(Arc::clone(&live_clients))))
            .expect("client state");
        let mut service = VsockHostService {
            live_clients,
            ..VsockHostService::default()
        };
        let entry = service.resources.push(state).expect("resource entry");
        let client_rep = entry.rep();
        let mut host = DeviceHost::new(4096).expect("host");
        host.set_vsock_service(service);
        let engine = crate::engine::device_engine().expect("engine");
        let mut store = wasmtime::Store::new(&engine, host);
        store
            .run_concurrent(async |accessor| {
                let service = accessor.with_getter::<VsockHost>(DeviceHost::vsock_service_mut);
                assert!(
                    VsockHost::input(&service, Resource::new_own(client_rep))
                        .await
                        .is_ok()
                );
                assert!(
                    VsockHost::input(&service, Resource::new_own(client_rep))
                        .await
                        .is_err()
                );
                assert!(VsockHost::plan(&service).await.is_ok());
                assert!(VsockHost::plan(&service).await.is_err());
                assert!(VsockHost::stop(&service).await.is_ok());
                assert!(VsockHost::stop(&service).await.is_err());
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
