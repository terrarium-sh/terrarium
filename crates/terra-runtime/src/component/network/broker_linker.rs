use super::NetworkHost;
use super::bindings::terra::network::broker::{
    Datagram as BrokerDatagram, Error as BrokerError, IpAddress, SendFailure as BrokerSendFailure,
    SocketAddress,
};
use futures_util::future::BoxFuture;
use futures_util::stream::{FuturesUnordered, StreamExt};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use terra_network::{Client, Error, Handle, Operation, Reply};
use terra_protocol::network::{
    Datagram, MAX_NETWORK_CHUNK_BYTES, MAX_NETWORK_DATAGRAM_BATCH_BYTES,
    MAX_NETWORK_DATAGRAM_BYTES, MAX_NETWORK_DATAGRAMS, MAX_NETWORK_NAME_BYTES,
    MAX_NETWORK_READ_BYTES, ResourceKind, SendFailure,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio_util::sync::{CancellationToken, PollSemaphore, PollSender};
use wasmtime::component::{
    Destination, FutureReader, Resource, ResourceType, Source, StreamConsumer, StreamProducer,
    StreamReader, StreamResult, VecBuffer, WasmList,
};
use wasmtime::{AsContext, StoreContextMut};
use wasmtime_wasi::WasiView;

struct Socket {
    client: Client,
    handle: Handle,
    closed: CancellationToken,
    peer: SocketAddr,
}

impl Socket {
    fn close(&self) {
        if !self.closed.is_cancelled() {
            self.closed.cancel();
            self.client.close(self.handle);
        }
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.close();
    }
}

struct BrokerTcp {
    socket: Arc<Socket>,
    terminal: watch::Receiver<Option<Error>>,
    terminal_outcome: watch::Sender<Option<Error>>,
    is_sending: bool,
    is_receiving: bool,
}

impl BrokerTcp {
    fn new(socket: Arc<Socket>) -> Self {
        let (errors, terminal) = watch::channel(None);
        Self {
            socket,
            terminal,
            terminal_outcome: errors,
            is_sending: false,
            is_receiving: false,
        }
    }
}

impl Drop for BrokerTcp {
    fn drop(&mut self) {
        self.socket.close();
    }
}

struct BrokerUdp {
    socket: Arc<Socket>,
    is_receiving: bool,
}

impl BrokerUdp {
    fn new(socket: Arc<Socket>) -> Self {
        Self {
            socket,
            is_receiving: false,
        }
    }
}

impl Drop for BrokerUdp {
    fn drop(&mut self) {
        self.socket.close();
    }
}

struct BrokerListener {
    client: Client,
    grant: terra_network::ListenerGrant,
    closed: CancellationToken,
    is_accepting: bool,
}

impl Drop for BrokerListener {
    fn drop(&mut self) {
        self.closed.cancel();
    }
}

struct Completion(Option<oneshot::Sender<Result<(), Error>>>);

impl Completion {
    fn finish(&mut self, result: Result<(), Error>) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(result);
        }
    }
}

impl Drop for Completion {
    fn drop(&mut self) {
        self.finish(Err(Error::Cancelled));
    }
}

fn create_completion<T: 'static>(
    store: &mut StoreContextMut<T>,
    terminal: Option<watch::Receiver<Option<Error>>>,
) -> wasmtime::Result<(Completion, FutureReader<Result<(), BrokerError>>)> {
    let (sender, receiver) = oneshot::channel();
    let future = FutureReader::new(store, async move {
        let result = if let Some(terminal) = terminal {
            tokio::select! {
                biased;
                result = receiver => result.unwrap_or(Err(Error::Cancelled)),
                error = wait_terminal(terminal) => Err(error),
            }
        } else {
            receiver.await.unwrap_or(Err(Error::Cancelled))
        };
        Ok::<_, wasmtime::Error>(result.map_err(broker_error))
    })?;
    Ok((Completion(Some(sender)), future))
}

async fn wait_terminal(mut terminal: watch::Receiver<Option<Error>>) -> Error {
    loop {
        if let Some(error) = *terminal.borrow_and_update() {
            return error;
        }
        if terminal.changed().await.is_err() {
            return Error::Closed;
        }
    }
}

struct UploadChunk {
    bytes: Vec<u8>,
    slot: OwnedSemaphorePermit,
}

struct TcpUpload {
    sender: PollSender<UploadChunk>,
    slots: PollSemaphore,
}

impl<T: 'static> StreamConsumer<T> for TcpUpload {
    type Item = u8;

    fn poll_consume(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        store: StoreContextMut<T>,
        source: Source<'_, u8>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            self.sender.abort_send();
            self.slots = self.slots.clone();
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        if std::task::ready!(self.sender.poll_reserve(context)).is_err() {
            return Poll::Ready(Ok(StreamResult::Dropped));
        }
        let Some(slot) = std::task::ready!(self.slots.poll_acquire(context)) else {
            self.sender.abort_send();
            return Poll::Ready(Ok(StreamResult::Dropped));
        };
        let mut source = source.as_direct(store);
        let count = source.remaining().len().min(MAX_NETWORK_CHUNK_BYTES);
        if count == 0 {
            self.sender.abort_send();
            return Poll::Ready(Ok(StreamResult::Completed));
        }
        let bytes = source.remaining()[..count].to_vec();
        source.mark_read(count);
        let result = self.sender.send_item(UploadChunk { bytes, slot });
        Poll::Ready(Ok(if result.is_ok() {
            StreamResult::Completed
        } else {
            StreamResult::Dropped
        }))
    }
}

fn start_upload(
    socket: Arc<Socket>,
    terminal: watch::Receiver<Option<Error>>,
    mut completion: Completion,
) -> TcpUpload {
    let (sender, receiver) = mpsc::channel(terra_network::MAX_TCP_WRITE_REQUESTS);
    let slots = Arc::new(Semaphore::new(terra_network::MAX_TCP_WRITE_REQUESTS));
    let upload_slots = slots.clone();
    tokio::spawn(async move {
        let result = drive_upload(socket.clone(), terminal, receiver).await;
        upload_slots.close();
        if result.is_err() {
            socket.close();
        }
        completion.finish(result);
    });
    TcpUpload {
        sender: PollSender::new(sender),
        slots: PollSemaphore::new(slots),
    }
}

async fn drive_upload(
    socket: Arc<Socket>,
    terminal: watch::Receiver<Option<Error>>,
    mut incoming: mpsc::Receiver<UploadChunk>,
) -> Result<(), Error> {
    let failure = wait_terminal(terminal);
    tokio::pin!(failure);
    let mut pending = FuturesUnordered::new();
    let mut is_eof = false;
    loop {
        if is_eof && pending.is_empty() {
            break;
        }
        tokio::select! {
            biased;
            error = &mut failure => return Err(error),
            () = socket.closed.cancelled() => return Err(Error::Closed),
            completed = pending.next(), if !pending.is_empty() => {
                if let Some(result) = completed { result?; }
            }
            chunk = incoming.recv(), if !is_eof => {
                match chunk {
                    Some(UploadChunk { bytes, slot }) => {
                        let admission = socket.client.reserve_write_all();
                        tokio::pin!(admission);
                        let admission = loop {
                            tokio::select! {
                                biased;
                                error = &mut failure => return Err(error),
                                () = socket.closed.cancelled() => return Err(Error::Closed),
                                completed = pending.next(), if !pending.is_empty() => {
                                    if let Some(result) = completed { result?; }
                                }
                                admission = &mut admission => break admission?,
                            }
                        };
                        let response = admission.start(socket.handle, bytes)?;
                        pending.push(async move {
                            let result = response.await;
                            drop(slot);
                            result
                        });
                    }
                    None => is_eof = true,
                }
            }
        }
    }
    match request_for(socket.clone(), Operation::ShutdownWrite(socket.handle)).await? {
        Reply::Done => Ok(()),
        Reply::Opened { .. }
        | Reply::Data(_)
        | Reply::Eof
        | Reply::Written(_)
        | Reply::Datagrams(_)
        | Reply::Sent(_)
        | Reply::Resolved(_)
        | Reply::Cancelled(_) => {
            socket.client.disconnect();
            Err(Error::Io)
        }
    }
}

async fn request_for(socket: Arc<Socket>, operation: Operation) -> Result<Reply, Error> {
    tokio::select! {
        biased;
        () = socket.closed.cancelled() => Err(Error::Closed),
        result = socket.client.request(operation) => result,
    }
}

async fn receive_terminal_error(socket: Arc<Socket>) -> Error {
    match request_for(socket.clone(), Operation::WaitError(socket.handle)).await {
        Err(error) => error,
        Ok(
            Reply::Opened { .. }
            | Reply::Data(_)
            | Reply::Eof
            | Reply::Written(_)
            | Reply::Datagrams(_)
            | Reply::Sent(_)
            | Reply::Resolved(_)
            | Reply::Cancelled(_)
            | Reply::Done,
        ) => {
            socket.client.disconnect();
            Error::Io
        }
    }
}

struct TcpReceive {
    socket: Arc<Socket>,
    terminal_outcome: watch::Sender<Option<Error>>,
    pending: Option<BoxFuture<'static, Result<Reply, Error>>>,
    completion: Completion,
    is_eof: bool,
}

impl<T: 'static> StreamProducer<T> for TcpReceive {
    type Item = u8;
    type Buffer = VecBuffer<u8>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        mut store: StoreContextMut<'a, T>,
        mut destination: Destination<'a, u8, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            self.pending = None;
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        if self.is_eof {
            return Poll::Ready(Ok(StreamResult::Dropped));
        }
        if destination.remaining(&mut store) == Some(0) {
            return Poll::Ready(Ok(StreamResult::Completed));
        }
        let socket = self.socket.clone();
        let max_bytes = u32::try_from(MAX_NETWORK_READ_BYTES)?;
        let pending = self.pending.get_or_insert_with(|| {
            Box::pin(request_for(
                socket.clone(),
                Operation::Read {
                    handle: socket.handle,
                    max_bytes,
                },
            ))
        });
        let result = std::task::ready!(pending.as_mut().poll(context));
        self.pending = None;
        match result {
            Ok(Reply::Data(bytes)) => {
                destination.set_buffer(bytes.into());
                Poll::Ready(Ok(StreamResult::Completed))
            }
            Ok(Reply::Eof) => {
                let socket = self.socket.clone();
                let errors = self.terminal_outcome.clone();
                tokio::spawn(async move {
                    errors.send_replace(Some(receive_terminal_error(socket).await));
                });
                self.is_eof = true;
                self.completion.finish(Ok(()));
                Poll::Ready(Ok(StreamResult::Dropped))
            }
            Ok(
                Reply::Opened { .. }
                | Reply::Written(_)
                | Reply::Datagrams(_)
                | Reply::Sent(_)
                | Reply::Resolved(_)
                | Reply::Cancelled(_)
                | Reply::Done,
            ) => {
                self.socket.client.disconnect();
                self.is_eof = true;
                self.terminal_outcome.send_replace(Some(Error::Io));
                self.completion.finish(Err(Error::Io));
                Poll::Ready(Ok(StreamResult::Dropped))
            }
            Err(error) => {
                self.is_eof = true;
                self.terminal_outcome.send_replace(Some(error));
                self.completion.finish(Err(error));
                Poll::Ready(Ok(StreamResult::Dropped))
            }
        }
    }
}

struct UdpReceive {
    socket: Arc<Socket>,
    pending: Option<BoxFuture<'static, Result<Reply, Error>>>,
    completion: Completion,
    is_eof: bool,
}

impl<T: 'static> StreamProducer<T> for UdpReceive {
    type Item = BrokerDatagram;
    type Buffer = VecBuffer<BrokerDatagram>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        mut store: StoreContextMut<'a, T>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            self.pending = None;
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        if self.is_eof {
            return Poll::Ready(Ok(StreamResult::Dropped));
        }
        if destination.remaining(&mut store) == Some(0) {
            return Poll::Ready(Ok(StreamResult::Completed));
        }
        let socket = self.socket.clone();
        let pending = self.pending.get_or_insert_with(|| {
            Box::pin(request_for(
                socket.clone(),
                Operation::ReceiveDatagram(socket.handle),
            ))
        });
        let result = std::task::ready!(pending.as_mut().poll(context));
        self.pending = None;
        match result {
            Ok(Reply::Datagrams(datagrams)) => {
                destination.set_buffer(
                    datagrams
                        .into_iter()
                        .map(|Datagram { peer, bytes }| BrokerDatagram {
                            peer: SocketAddress {
                                address: ip_address(peer.ip()),
                                port: peer.port(),
                            },
                            bytes,
                        })
                        .collect::<Vec<_>>()
                        .into(),
                );
                Poll::Ready(Ok(StreamResult::Completed))
            }
            Ok(
                Reply::Opened { .. }
                | Reply::Data(_)
                | Reply::Eof
                | Reply::Written(_)
                | Reply::Sent(_)
                | Reply::Resolved(_)
                | Reply::Cancelled(_)
                | Reply::Done,
            ) => {
                self.socket.client.disconnect();
                self.is_eof = true;
                self.completion.finish(Err(Error::Io));
                Poll::Ready(Ok(StreamResult::Dropped))
            }
            Err(error) => {
                self.is_eof = true;
                self.completion.finish(Err(error));
                Poll::Ready(Ok(StreamResult::Dropped))
            }
        }
    }
}

struct Accept {
    client: Client,
    grant: terra_network::ListenerGrant,
    closed: CancellationToken,
    pending: Option<BoxFuture<'static, Result<Arc<Socket>, Error>>>,
    completion: Completion,
    is_eof: bool,
}

impl<T: WasiView + 'static> StreamProducer<T> for Accept {
    type Item = Resource<BrokerTcp>;
    type Buffer = VecBuffer<Self::Item>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        mut store: StoreContextMut<'a, T>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            self.pending = None;
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        if self.is_eof {
            return Poll::Ready(Ok(StreamResult::Dropped));
        }
        if destination.remaining(&mut store) == Some(0) {
            return Poll::Ready(Ok(StreamResult::Completed));
        }
        let client = self.client.clone();
        let grant = self.grant;
        let closed = self.closed.clone();
        let pending = self.pending.get_or_insert_with(|| {
            Box::pin(async move {
                tokio::select! {
                    biased;
                    () = closed.cancelled() => Err(Error::Closed),
                    socket = open_socket(client, Operation::Accept(grant)) => socket,
                }
            })
        });
        let result = std::task::ready!(pending.as_mut().poll(context));
        self.pending = None;
        match result {
            Ok(socket) => {
                if let Ok(resource) = store.data_mut().ctx().table.push(BrokerTcp::new(socket)) {
                    destination.set_buffer(vec![resource].into());
                    Poll::Ready(Ok(StreamResult::Completed))
                } else {
                    self.is_eof = true;
                    self.completion.finish(Err(Error::LimitExceeded));
                    Poll::Ready(Ok(StreamResult::Dropped))
                }
            }
            Err(error) => {
                self.is_eof = true;
                self.completion.finish(Err(error));
                Poll::Ready(Ok(StreamResult::Dropped))
            }
        }
    }
}

fn broker_error(error: Error) -> BrokerError {
    match error {
        Error::AccessDenied => BrokerError::AccessDenied,
        Error::InvalidArgument | Error::NotSupported => BrokerError::InvalidArgument,
        Error::InvalidState | Error::NotReady => BrokerError::InvalidState,
        Error::StaleHandle => BrokerError::StaleHandle,
        Error::WrongKind => BrokerError::WrongKind,
        Error::Busy => BrokerError::Busy,
        Error::LimitExceeded => BrokerError::LimitExceeded,
        Error::DuplicateRequest => BrokerError::DuplicateRequest,
        Error::Cancelled => BrokerError::Cancelled,
        Error::ConnectionRefused => BrokerError::ConnectionRefused,
        Error::ConnectionReset => BrokerError::ConnectionReset,
        Error::TimedOut => BrokerError::TimedOut,
        Error::NameUnresolvable => BrokerError::NameUnresolvable,
        Error::ResolverBusy => BrokerError::ResolverBusy,
        Error::DatagramTooLarge => BrokerError::DatagramTooLarge,
        Error::Closed => BrokerError::Closed,
        Error::Io | Error::Protocol => BrokerError::Io,
    }
}

fn ip_address(address: IpAddr) -> IpAddress {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, d] = address.octets();
            IpAddress::Ipv4((a, b, c, d))
        }
        IpAddr::V6(address) => IpAddress::Ipv6(address.segments().into()),
    }
}

fn canonical_peer(address: SocketAddress) -> Result<SocketAddr, Error> {
    let ip = match address.address {
        IpAddress::Ipv4((a, b, c, d)) => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        IpAddress::Ipv6(segments) => {
            let address = Ipv6Addr::from(<[u16; 8]>::from(segments));
            if address.to_ipv4_mapped().is_some()
                || (address.segments()[..6] == [0; 6]
                    && !address.is_unspecified()
                    && !address.is_loopback())
            {
                return Err(Error::InvalidArgument);
            }
            IpAddr::V6(address)
        }
    };
    Ok(SocketAddr::new(ip, address.port))
}

async fn open_socket(client: Client, operation: Operation) -> Result<Arc<Socket>, Error> {
    match client.request(operation).await? {
        Reply::Opened { handle, peer, .. } => Ok(Arc::new(Socket {
            client,
            handle,
            closed: CancellationToken::new(),
            peer,
        })),
        Reply::Data(_)
        | Reply::Eof
        | Reply::Written(_)
        | Reply::Datagrams(_)
        | Reply::Sent(_)
        | Reply::Resolved(_)
        | Reply::Cancelled(_)
        | Reply::Done => {
            client.disconnect();
            Err(Error::Io)
        }
    }
}

fn grant_listener(host: &NetworkHost, host_port: u16, ipv6: bool) -> Result<BrokerListener, Error> {
    let client = host.clone_broker_client()?;
    let grant = resolve_listener_grant(host, host_port, ipv6, ResourceKind::Tcp)?;
    Ok(BrokerListener {
        client,
        grant,
        closed: CancellationToken::new(),
        is_accepting: false,
    })
}

fn resolve_listener_grant(
    host: &NetworkHost,
    host_port: u16,
    ipv6: bool,
    transport: ResourceKind,
) -> Result<terra_network::ListenerGrant, Error> {
    host.listener_grants
        .iter()
        .find(|listener| {
            listener.address.port() == host_port
                && listener.address.is_ipv6() == ipv6
                && listener.transport == transport
        })
        .map(|listener| listener.grant)
        .ok_or(Error::AccessDenied)
}

pub(crate) fn add<T: WasiView + AsMut<NetworkHost> + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
) -> wasmtime::Result<()> {
    let mut interface = linker.instance("terra:network/broker@0.1.0")?;
    interface.resource(
        "tcp",
        ResourceType::host::<BrokerTcp>(),
        |mut store, rep| {
            store
                .data_mut()
                .ctx()
                .table
                .delete(Resource::<BrokerTcp>::new_own(rep))?;
            Ok(())
        },
    )?;
    interface.resource(
        "udp",
        ResourceType::host::<BrokerUdp>(),
        |mut store, rep| {
            store
                .data_mut()
                .ctx()
                .table
                .delete(Resource::<BrokerUdp>::new_own(rep))?;
            Ok(())
        },
    )?;
    interface.resource(
        "listener",
        ResourceType::host::<BrokerListener>(),
        |mut store, rep| {
            store
                .data_mut()
                .ctx()
                .table
                .delete(Resource::<BrokerListener>::new_own(rep))?;
            Ok(())
        },
    )?;
    add_open(&mut interface)?;
    add_listener(&mut interface)?;
    add_tcp_io(&mut interface)?;
    add_udp(&mut interface)?;
    add_resolve(&mut interface)?;
    interface.func_wrap("closed", |mut store, (): ()| {
        let client = store.data_mut().as_mut().clone_broker_client();
        let closed = FutureReader::new(&mut store, async move {
            if let Ok(client) = client {
                client.wait_closed().await;
            }
            Ok::<_, wasmtime::Error>(())
        })?;
        Ok((closed,))
    })?;
    Ok(())
}

fn add_open<T: WasiView + AsMut<NetworkHost> + 'static>(
    interface: &mut wasmtime::component::LinkerInstance<'_, T>,
) -> wasmtime::Result<()> {
    interface.func_wrap_concurrent(
        "open-tcp",
        |access, (peer, inline_urgent): (SocketAddress, bool)| {
            Box::pin(async move {
                let client =
                    match access.with(|mut store| store.get().as_mut().clone_broker_client()) {
                        Ok(client) => client,
                        Err(error) => return Ok((Err(broker_error(error)),)),
                    };
                let peer = canonical_peer(peer);
                let result = match peer {
                    Ok(peer) => {
                        open_socket(
                            client,
                            Operation::OpenTcp {
                                peer,
                                inline_urgent,
                            },
                        )
                        .await
                    }
                    Err(error) => Err(error),
                };
                if matches!(result, Err(Error::AccessDenied))
                    && let Ok(peer) = peer
                {
                    access.with(|mut store| {
                        store.get().as_mut().report_denial(&peer.to_string(), false);
                    });
                }
                let result = match result {
                    Ok(socket) => access
                        .with(|mut store| store.get().ctx().table.push(BrokerTcp::new(socket)))
                        .map_err(|_| Error::LimitExceeded),
                    Err(error) => Err(error),
                };
                Ok((result.map_err(broker_error),))
            })
        },
    )?;
    interface.func_wrap_concurrent("open-udp", |access, (): ()| {
        Box::pin(async move {
            let client = match access.with(|mut store| store.get().as_mut().clone_broker_client()) {
                Ok(client) => client,
                Err(error) => return Ok((Err(broker_error(error)),)),
            };
            let result = open_socket(client, Operation::OpenUdp).await;
            let result = match result {
                Ok(socket) => access
                    .with(|mut store| store.get().ctx().table.push(BrokerUdp::new(socket)))
                    .map_err(|_| Error::LimitExceeded),
                Err(error) => Err(error),
            };
            Ok((result.map_err(broker_error),))
        })
    })?;
    Ok(())
}

fn add_listener<T: WasiView + AsMut<NetworkHost> + 'static>(
    interface: &mut wasmtime::component::LinkerInstance<'_, T>,
) -> wasmtime::Result<()> {
    interface.func_wrap_concurrent("published-udp", |access, (host_port, ipv6): (u16, bool)| {
        Box::pin(async move {
            let granted = access.with(|mut store| {
                let host = store.get().as_mut();
                Ok::<_, Error>((
                    host.clone_broker_client()?,
                    resolve_listener_grant(host, host_port, ipv6, ResourceKind::Udp)?,
                ))
            });
            let result = match granted {
                Ok((client, grant)) => {
                    open_socket(client, Operation::OpenPublishedUdp(grant)).await
                }
                Err(error) => Err(error),
            };
            let result = match result {
                Ok(socket) => access
                    .with(|mut store| store.get().ctx().table.push(BrokerUdp::new(socket)))
                    .map_err(|_| Error::LimitExceeded),
                Err(error) => Err(error),
            };
            Ok((result.map_err(broker_error),))
        })
    })?;
    interface.func_wrap(
        "published-listener",
        |mut store, (host_port, ipv6): (u16, bool)| {
            let result =
                grant_listener(store.data_mut().as_mut(), host_port, ipv6).and_then(|listener| {
                    store
                        .data_mut()
                        .ctx()
                        .table
                        .push(listener)
                        .map_err(|_| Error::LimitExceeded)
                });
            Ok((result.map_err(broker_error),))
        },
    )?;
    interface.func_wrap(
        "[method]listener.accept",
        |mut store, (resource,): (Resource<BrokerListener>,)| {
            let listener = store.data_mut().ctx().table.get_mut(&resource)?;
            let is_duplicate = std::mem::replace(&mut listener.is_accepting, true);
            let client = listener.client.clone();
            let grant = listener.grant;
            let closed = listener.closed.clone();
            let (mut completion, future) = create_completion(&mut store, None)?;
            if is_duplicate {
                completion.finish(Err(Error::InvalidState));
            }
            let stream = StreamReader::new(
                &mut store,
                Accept {
                    client,
                    grant,
                    closed,
                    pending: None,
                    completion,
                    is_eof: is_duplicate,
                },
            )?;
            Ok(((stream, future),))
        },
    )?;
    Ok(())
}

fn add_tcp_io<T: WasiView + AsMut<NetworkHost> + 'static>(
    interface: &mut wasmtime::component::LinkerInstance<'_, T>,
) -> wasmtime::Result<()> {
    interface.func_wrap(
        "[method]tcp.peer-address",
        |mut store, (resource,): (Resource<BrokerTcp>,)| {
            let tcp = store.data_mut().ctx().table.get(&resource)?;
            let address = SocketAddress {
                address: ip_address(tcp.socket.peer.ip()),
                port: tcp.socket.peer.port(),
            };
            Ok((Ok::<_, BrokerError>(address),))
        },
    )?;
    interface.func_wrap(
        "[method]tcp.send",
        |mut store, (resource, mut data): (Resource<BrokerTcp>, StreamReader<u8>)| {
            let tcp = store.data_mut().ctx().table.get_mut(&resource)?;
            let is_duplicate = std::mem::replace(&mut tcp.is_sending, true);
            let socket = tcp.socket.clone();
            let terminal = tcp.terminal.clone();
            let (mut completion, future) = create_completion(&mut store, None)?;
            if is_duplicate {
                data.close(&mut store)?;
                completion.finish(Err(Error::InvalidState));
            } else {
                data.pipe(&mut store, start_upload(socket, terminal, completion))?;
            }
            Ok((future,))
        },
    )?;
    interface.func_wrap(
        "[method]tcp.receive",
        |mut store, (resource,): (Resource<BrokerTcp>,)| {
            let tcp = store.data_mut().ctx().table.get_mut(&resource)?;
            let is_duplicate = std::mem::replace(&mut tcp.is_receiving, true);
            let socket = tcp.socket.clone();
            let terminal = tcp.terminal.clone();
            let terminal_outcome = tcp.terminal_outcome.clone();
            let (mut completion, future) = create_completion(&mut store, Some(terminal))?;
            if is_duplicate {
                completion.finish(Err(Error::InvalidState));
            }
            let stream = StreamReader::new(
                &mut store,
                TcpReceive {
                    socket,
                    terminal_outcome,
                    pending: None,
                    completion,
                    is_eof: is_duplicate,
                },
            )?;
            Ok(((stream, future),))
        },
    )?;
    Ok(())
}

fn add_udp<T: WasiView + AsMut<NetworkHost> + 'static>(
    interface: &mut wasmtime::component::LinkerInstance<'_, T>,
) -> wasmtime::Result<()> {
    interface.func_wrap_concurrent(
        "[method]udp.send-to",
        |access, (resource, datagrams): (Resource<BrokerUdp>, Vec<BrokerDatagram>)| {
            Box::pin(async move {
                let socket = access.with(|mut store| {
                    store
                        .get()
                        .ctx()
                        .table
                        .get(&resource)
                        .map(|udp| udp.socket.clone())
                })?;
                let result = send_datagrams(&socket, datagrams).await;
                if let Ok((_, denied)) = &result {
                    access.with(|mut store| {
                        for peer in denied {
                            store.get().as_mut().report_denial(&peer.to_string(), false);
                        }
                    });
                }
                Ok((result.map(|(failures, _)| failures).map_err(broker_error),))
            })
        },
    )?;
    interface.func_wrap(
        "[method]udp.receive-from",
        |mut store, (resource,): (Resource<BrokerUdp>,)| {
            let udp = store.data_mut().ctx().table.get_mut(&resource)?;
            let is_duplicate = std::mem::replace(&mut udp.is_receiving, true);
            let socket = udp.socket.clone();
            let (mut completion, future) = create_completion(&mut store, None)?;
            if is_duplicate {
                completion.finish(Err(Error::InvalidState));
            }
            let stream = StreamReader::new(
                &mut store,
                UdpReceive {
                    socket,
                    pending: None,
                    completion,
                    is_eof: is_duplicate,
                },
            )?;
            Ok(((stream, future),))
        },
    )?;
    Ok(())
}

/// Forward one guest batch in a single broker request; failures keep their guest index, and the
/// second list names the peers the broker denied.
async fn send_datagrams(
    socket: &Arc<Socket>,
    datagrams: Vec<BrokerDatagram>,
) -> Result<(Vec<BrokerSendFailure>, Vec<SocketAddr>), Error> {
    if datagrams.len() > MAX_NETWORK_DATAGRAMS {
        return Err(Error::InvalidArgument);
    }
    let mut failures = Vec::new();
    let mut denied = Vec::new();
    let mut forwarded = Vec::new();
    for (index, BrokerDatagram { peer, bytes }) in (0..).zip(datagrams) {
        let checked = canonical_peer(peer).and_then(|peer| {
            if bytes.len() > MAX_NETWORK_DATAGRAM_BYTES {
                Err(Error::DatagramTooLarge)
            } else {
                Ok(peer)
            }
        });
        match checked {
            Ok(peer) => forwarded.push((index, Datagram { peer, bytes })),
            Err(error) => failures.push((index, error)),
        }
    }
    if forwarded
        .iter()
        .map(|(_, datagram)| datagram.batch_bytes())
        .sum::<usize>()
        > MAX_NETWORK_DATAGRAM_BATCH_BYTES
    {
        return Err(Error::InvalidArgument);
    }
    if !forwarded.is_empty() {
        let (indices, datagrams): (Vec<u32>, Vec<Datagram>) = forwarded.into_iter().unzip();
        let peers = datagrams
            .iter()
            .map(|datagram| datagram.peer)
            .collect::<Vec<_>>();
        let operation = Operation::SendDatagrams {
            handle: socket.handle,
            datagrams,
        };
        match request_for(socket.clone(), operation).await? {
            Reply::Sent(sent) => {
                for SendFailure { index, error } in sent {
                    let position = index as usize;
                    let (Some(&guest_index), Some(&peer)) =
                        (indices.get(position), peers.get(position))
                    else {
                        socket.client.disconnect();
                        return Err(Error::Io);
                    };
                    failures.push((guest_index, error));
                    if error == Error::AccessDenied {
                        denied.push(peer);
                    }
                }
            }
            Reply::Opened { .. }
            | Reply::Data(_)
            | Reply::Eof
            | Reply::Written(_)
            | Reply::Datagrams(_)
            | Reply::Resolved(_)
            | Reply::Cancelled(_)
            | Reply::Done => {
                socket.client.disconnect();
                return Err(Error::Io);
            }
        }
    }
    failures.sort_by_key(|(index, _)| *index);
    let failures = failures
        .into_iter()
        .map(|(index, error)| BrokerSendFailure {
            index,
            error: broker_error(error),
        })
        .collect();
    Ok((failures, denied))
}

fn add_resolve<T: WasiView + AsMut<NetworkHost> + 'static>(
    interface: &mut wasmtime::component::LinkerInstance<'_, T>,
) -> wasmtime::Result<()> {
    interface.func_wrap_concurrent("resolve", |access, (name,): (WasmList<u8>,)| {
        Box::pin(async move {
            let (client, name) = access.with(|mut store| {
                let client = store.get().as_mut().clone_broker_client();
                let name = if name.len() <= MAX_NETWORK_NAME_BYTES {
                    std::str::from_utf8(name.as_le_slice(store.as_context()))
                        .map(|name| name.trim_end_matches('.').to_owned())
                        .map_err(|_| Error::InvalidArgument)
                } else {
                    Err(Error::InvalidArgument)
                };
                (client, name)
            });
            let client = match client {
                Ok(client) => client,
                Err(error) => return Ok((Err(broker_error(error)),)),
            };
            let result = match name {
                Ok(name) => {
                    let result = match client.request(Operation::Resolve(name.clone())).await {
                        Ok(Reply::Resolved(addresses)) => {
                            Ok(addresses.into_iter().map(ip_address).collect::<Vec<_>>())
                        }
                        Ok(
                            Reply::Opened { .. }
                            | Reply::Data(_)
                            | Reply::Eof
                            | Reply::Written(_)
                            | Reply::Datagrams(_)
                            | Reply::Sent(_)
                            | Reply::Cancelled(_)
                            | Reply::Done,
                        ) => {
                            client.disconnect();
                            Err(Error::Io)
                        }
                        Err(error) => Err(error),
                    };
                    if matches!(result, Err(Error::AccessDenied)) {
                        access.with(|mut store| {
                            store.get().as_mut().report_denial(&name, true);
                        });
                    }
                    result
                }
                Err(error) => Err(error),
            };
            Ok((result.map_err(broker_error),))
        })
    })?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use std::time::Duration;
    use terra_protocol::network::{Request, Response};
    use tokio::io::DuplexStream;

    fn connected_tcp() -> (BrokerTcp, Client, DuplexStream) {
        let (channel, peer) = tokio::io::duplex(64 * 1024);
        let client = Client::new(channel);
        let tcp = BrokerTcp::new(Arc::new(Socket {
            client: client.clone(),
            handle: 7,
            closed: CancellationToken::new(),
            peer: "127.0.0.1:443".parse().unwrap(),
        }));
        (tcp, client, peer)
    }

    async fn receive_request(peer: &mut DuplexStream) -> Request {
        tokio::time::timeout(
            Duration::from_secs(2),
            terra_protocol::read_frame_async(peer),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap()
    }

    async fn respond(peer: &mut DuplexStream, request: &Request, result: Result<Reply, Error>) {
        terra_protocol::write_frame_async(
            peer,
            &Response {
                id: request.id,
                result,
            },
        )
        .await
        .unwrap();
    }

    async fn assert_no_request(peer: &mut DuplexStream) {
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                terra_protocol::read_frame_async::<Request>(peer),
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn accepted_socket_preserves_the_broker_peer_address() {
        let (channel, mut peer) = tokio::io::duplex(64 * 1024);
        let client = Client::new(channel);
        let address = "127.0.0.1:43210".parse().unwrap();
        let broker = async {
            let request = receive_request(&mut peer).await;
            assert_matches!(request.operation, Operation::Accept(11));
            respond(
                &mut peer,
                &request,
                Ok(Reply::Opened {
                    handle: 1,
                    kind: terra_protocol::network::ResourceKind::Tcp,
                    peer: address,
                }),
            )
            .await;
        };
        let (socket, ()) = tokio::join!(open_socket(client.clone(), Operation::Accept(11)), broker);
        assert_eq!(socket.unwrap().peer, address);
        client.disconnect();
    }

    #[tokio::test]
    async fn terminal_error_wait_propagates_errors_and_rejects_success() {
        for (reply, expected) in [
            (Err(Error::ConnectionReset), Error::ConnectionReset),
            (Ok(Reply::Done), Error::Io),
        ] {
            let (tcp, client, mut peer) = connected_tcp();
            let broker = async {
                let request = receive_request(&mut peer).await;
                assert_eq!(request.operation, Operation::WaitError(7));
                respond(&mut peer, &request, reply).await;
            };
            let (result, ()) = tokio::join!(receive_terminal_error(tcp.socket.clone()), broker);
            assert_eq!(result, expected);
            assert_eq!(client.is_available(), expected == Error::ConnectionReset);
            client.disconnect();
        }
    }

    #[tokio::test]
    async fn published_listener_resources_have_only_the_configured_family_and_port() {
        let (channel, mut peer) = tokio::io::duplex(64 * 1024);
        let client = Client::new(channel);
        let host = NetworkHost::new(Some(super::super::NetworkBackend {
            client: client.clone(),
            ready: terra_network::config::Ready {
                version: terra_network::config::PROTOCOL_VERSION,
                host_service_ports: vec![],
                blocks_direct_dns: false,
            },
            listeners: vec![
                terra_network::config::PublishedListener {
                    grant: 11,
                    address: "127.0.0.1:4000".parse().unwrap(),
                    transport: ResourceKind::Tcp,
                },
                terra_network::config::PublishedListener {
                    grant: 12,
                    address: "127.0.0.1:4000".parse().unwrap(),
                    transport: ResourceKind::Udp,
                },
            ],
        }));
        assert_eq!(grant_listener(&host, 4000, false).unwrap().grant, 11);
        assert_eq!(
            resolve_listener_grant(&host, 4000, false, ResourceKind::Udp),
            Ok(12)
        );
        assert_eq!(
            resolve_listener_grant(&host, 4000, true, ResourceKind::Udp),
            Err(Error::AccessDenied)
        );
        assert_eq!(
            resolve_listener_grant(&host, 4001, false, ResourceKind::Udp),
            Err(Error::AccessDenied)
        );
        assert!(matches!(
            grant_listener(&host, 4000, true),
            Err(Error::AccessDenied)
        ));
        assert!(matches!(
            grant_listener(&host, 4001, false),
            Err(Error::AccessDenied)
        ));
        assert_no_request(&mut peer).await;
        client.disconnect();
    }
    struct CollectBytes(mpsc::UnboundedSender<Vec<u8>>);

    impl StreamConsumer<()> for CollectBytes {
        type Item = u8;

        fn poll_consume(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            store: StoreContextMut<()>,
            source: Source<'_, u8>,
            finish: bool,
        ) -> Poll<wasmtime::Result<StreamResult>> {
            if finish {
                return Poll::Ready(Ok(StreamResult::Cancelled));
            }
            let mut source = source.as_direct(store);
            let count = source.remaining().len().min(997);
            let bytes = source.remaining()[..count].to_vec();
            source.mark_read(count);
            let _ = self.0.send(bytes);
            Poll::Ready(Ok(StreamResult::Completed))
        }
    }

    #[tokio::test]
    async fn upload_stream_bounds_chunks_and_drains_acknowledgements_before_fin() {
        let (tcp, client, mut peer) = connected_tcp();
        let engine = crate::engine::device_engine().unwrap();
        let mut store = wasmtime::Store::new(&engine, ());
        let (sender, outcome) = oneshot::channel();
        let bytes = vec![7; MAX_NETWORK_CHUNK_BYTES * (terra_network::MAX_TCP_WRITE_REQUESTS + 1)];
        let input = StreamReader::new(&mut store, bytes).unwrap();
        input
            .pipe(
                &mut store,
                start_upload(
                    tcp.socket.clone(),
                    tcp.terminal.clone(),
                    Completion(Some(sender)),
                ),
            )
            .unwrap();
        store.run_concurrent(async |_| {
            let mut writes = Vec::new();
            for _ in 0..terra_network::MAX_TCP_WRITE_REQUESTS {
                let request = receive_request(&mut peer).await;
                assert_matches!(&request.operation, Operation::WriteAll { handle: 7, bytes } if bytes.len() == MAX_NETWORK_CHUNK_BYTES);
                writes.push(request);
            }
            assert_no_request(&mut peer).await;
            for write in writes.into_iter().rev() {
                respond(&mut peer, &write, Ok(Reply::Written(u32::try_from(MAX_NETWORK_CHUNK_BYTES).unwrap()))).await;
            }
            let write = receive_request(&mut peer).await;
            assert_matches!(write.operation, Operation::WriteAll { .. });
            assert_no_request(&mut peer).await;
            respond(&mut peer, &write, Ok(Reply::Written(u32::try_from(MAX_NETWORK_CHUNK_BYTES).unwrap()))).await;
            let fin = receive_request(&mut peer).await;
            assert_eq!(fin.operation, Operation::ShutdownWrite(7));
            respond(&mut peer, &fin, Ok(Reply::Done)).await;
            assert_eq!(outcome.await.unwrap(), Ok(()));
        }).await.unwrap();
        client.disconnect();
    }

    #[tokio::test]
    async fn upload_failure_releases_stream_capacity_without_fin() {
        let (tcp, client, mut peer) = connected_tcp();
        let (sender, receiver) = mpsc::channel(2);
        let slots = Arc::new(Semaphore::new(2));
        for byte in [1, 2] {
            sender
                .send(UploadChunk {
                    bytes: vec![byte],
                    slot: slots.clone().acquire_owned().await.unwrap(),
                })
                .await
                .unwrap();
        }
        drop(sender);
        let upload = drive_upload(tcp.socket.clone(), tcp.terminal.clone(), receiver);
        tokio::pin!(upload);
        let broker = async {
            let first = receive_request(&mut peer).await;
            let second = receive_request(&mut peer).await;
            assert_matches!(&first.operation, Operation::WriteAll { bytes, .. } if bytes == &[1]);
            assert_matches!(
                &second.operation,
                Operation::WriteAll { bytes, .. } if bytes == &[2]
            );
            respond(&mut peer, &second, Err(Error::ConnectionReset)).await;
        };
        let (result, ()) = tokio::join!(&mut upload, broker);
        assert_eq!(result, Err(Error::ConnectionReset));
        assert_no_request(&mut peer).await;
        assert_eq!(slots.available_permits(), 2);
        client.disconnect();
    }

    #[tokio::test]
    async fn receive_stream_preserves_partial_chunks_eof_and_idle_upload_reset() {
        let (tcp, client, mut peer) = connected_tcp();
        let engine = crate::engine::device_engine().unwrap();
        let mut store = wasmtime::Store::new(&engine, ());
        let (sender, outcome) = oneshot::channel();
        let (collected, mut chunks) = mpsc::unbounded_channel();
        let input = StreamReader::new(
            &mut store,
            TcpReceive {
                socket: tcp.socket.clone(),
                terminal_outcome: tcp.terminal_outcome.clone(),
                pending: None,
                completion: Completion(Some(sender)),
                is_eof: false,
            },
        )
        .unwrap();
        input.pipe(&mut store, CollectBytes(collected)).unwrap();
        store.run_concurrent(async |_| {
            let read = receive_request(&mut peer).await;
            assert_matches!(read.operation, Operation::Read { handle: 7, max_bytes } if max_bytes as usize == MAX_NETWORK_READ_BYTES);
            respond(&mut peer, &read, Ok(Reply::Data(vec![8; MAX_NETWORK_READ_BYTES]))).await;
            let mut received = Vec::new();
            while received.len() < MAX_NETWORK_READ_BYTES { received.extend(chunks.recv().await.unwrap()); }
            assert_eq!(received, vec![8; MAX_NETWORK_READ_BYTES]);
            let read = receive_request(&mut peer).await;
            assert_matches!(read.operation, Operation::Read { .. });
            respond(&mut peer, &read, Ok(Reply::Eof)).await;
            assert_eq!(outcome.await.unwrap(), Ok(()));
            let monitor = receive_request(&mut peer).await;
            assert_eq!(monitor.operation, Operation::WaitError(7));
            respond(&mut peer, &monitor, Err(Error::ConnectionReset)).await;
            assert_eq!(wait_terminal(tcp.terminal.clone()).await, Error::ConnectionReset);
        }).await.unwrap();
        client.disconnect();
    }

    #[tokio::test]
    async fn dropping_a_pending_listener_stream_cancels_the_accept_request() {
        struct AcceptSink;
        impl StreamConsumer<crate::component::vsock::VsockHost> for AcceptSink {
            type Item = Resource<BrokerTcp>;
            fn poll_consume(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: StoreContextMut<crate::component::vsock::VsockHost>,
                _: Source<'_, Self::Item>,
                _: bool,
            ) -> Poll<wasmtime::Result<StreamResult>> {
                Poll::Pending
            }
        }
        let (channel, mut peer) = tokio::io::duplex(64 * 1024);
        let client = Client::new(channel);
        let engine = crate::engine::device_engine().unwrap();
        let host = crate::component::vsock::VsockHost::new(
            crate::component::context::DeviceContext::new(4096).unwrap(),
            crate::component::vsock::streams::FrontendStreams::new().0,
            None,
        );
        let mut store = wasmtime::Store::new(&engine, host);
        let (sender, outcome) = oneshot::channel();
        let input = StreamReader::new(
            &mut store,
            Accept {
                client: client.clone(),
                grant: 11,
                closed: CancellationToken::new(),
                pending: None,
                completion: Completion(Some(sender)),
                is_eof: false,
            },
        )
        .unwrap();
        input.pipe(&mut store, AcceptSink).unwrap();
        let request = store
            .run_concurrent(async |_| {
                let request = receive_request(&mut peer).await;
                assert_eq!(request.operation, Operation::Accept(11));
                request
            })
            .await
            .unwrap();
        drop(store);
        assert_eq!(outcome.await.unwrap(), Err(Error::Cancelled));
        let cancellation = receive_request(&mut peer).await;
        assert_eq!(cancellation.operation, Operation::Cancel(request.id));
        respond(
            &mut peer,
            &request,
            Ok(Reply::Opened {
                handle: 17,
                kind: ResourceKind::Tcp,
                peer: "127.0.0.1:1234".parse().unwrap(),
            }),
        )
        .await;
        let cleanup = receive_request(&mut peer).await;
        assert_eq!(cleanup.operation, Operation::Close(17));
        client.disconnect();
    }
    #[tokio::test]
    async fn broker_closed_future_supports_idle_eof_absence_and_cancellation() {
        use wasmtime::component::FutureConsumer;
        struct Closed(Option<oneshot::Sender<()>>);
        impl FutureConsumer<crate::component::vsock::VsockHost> for Closed {
            type Item = ();
            fn poll_consume(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                store: StoreContextMut<crate::component::vsock::VsockHost>,
                mut source: Source<'_, ()>,
                finish: bool,
            ) -> Poll<wasmtime::Result<()>> {
                if !finish {
                    let mut value = None;
                    source.read(store, &mut value)?;
                    if value.is_some() {
                        let _ = self.0.take().unwrap().send(());
                    }
                }
                Poll::Ready(Ok(()))
            }
        }
        let engine = crate::engine::device_engine().unwrap();
        let component = wasmtime::component::Component::new(
            &engine,
            r#"(component
            (import "terra:network/broker@0.1.0" (instance $broker
                (export "closed" (func (result (future))))))
            (alias export $broker "closed" (func $closed))
            (core func $closed-lower (canon lower (func $closed)))
            (core instance $host (export "closed" (func $closed-lower)))
            (core module $wrapper
                (import "host" "closed" (func $closed (result i32)))
                (func (export "closed") (result i32) call $closed))
            (core instance $wrapper (instantiate $wrapper (with "host" (instance $host))))
            (alias core export $wrapper "closed" (core func $closed-wrapper))
            (func (export "closed") (result (future)) (canon lift (core func $closed-wrapper))))"#,
        )
        .unwrap();
        for is_enabled in [false, true] {
            let (channel, peer) = tokio::io::duplex(65536);
            let client = Client::new(channel);
            let backend = is_enabled.then(|| super::super::NetworkBackend {
                client: client.clone(),
                ready: terra_network::config::Ready {
                    version: terra_network::config::PROTOCOL_VERSION,
                    host_service_ports: Vec::new(),
                    blocks_direct_dns: false,
                },
                listeners: Vec::new(),
            });
            let host = crate::component::vsock::VsockHost::new(
                crate::component::context::DeviceContext::new(4096).unwrap(),
                crate::component::vsock::streams::FrontendStreams::new().0,
                backend,
            );
            let mut store = wasmtime::Store::new(&engine, host);
            store.set_epoch_deadline(1);
            let mut linker = wasmtime::component::Linker::new(&engine);
            add(&mut linker).unwrap();
            let instance = linker
                .instantiate_async(&mut store, &component)
                .await
                .unwrap();
            let closed = instance
                .get_typed_func::<(), (FutureReader<()>,)>(&mut store, "closed")
                .unwrap();
            let (mut cancelled,) = closed.call_async(&mut store, ()).await.unwrap();
            cancelled.close(&mut store).unwrap();
            assert!(client.is_available());
            let (future,) = closed.call_async(&mut store, ()).await.unwrap();
            let (sender, mut outcome) = oneshot::channel();
            future.pipe(&mut store, Closed(Some(sender))).unwrap();
            store
                .run_concurrent(async |_| {
                    if is_enabled {
                        assert!(
                            tokio::time::timeout(Duration::from_millis(20), &mut outcome)
                                .await
                                .is_err()
                        );
                    }
                    drop(peer);
                    tokio::time::timeout(Duration::from_secs(1), outcome)
                        .await
                        .unwrap()
                        .unwrap();
                })
                .await
                .unwrap();
            client.disconnect();
        }
    }
}
