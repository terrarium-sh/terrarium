use super::NetworkHost;
use super::bindings::terra::network::broker::{
    Datagram as BrokerDatagram, Error as BrokerError, IpAddress, SendFailure as BrokerSendFailure,
    SocketAddress,
};
use futures_util::StreamExt;
use futures_util::future::BoxFuture;
use futures_util::stream::BoxStream;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use terra_network::{Client, Error, TcpDownload, TcpFlow, TcpUpload, UdpFlow};
use terra_protocol::network::{
    Datagram, MAX_NETWORK_CHUNK_BYTES, MAX_NETWORK_DATAGRAM_BATCH_BYTES,
    MAX_NETWORK_DATAGRAM_BYTES, MAX_NETWORK_DATAGRAMS, MAX_NETWORK_NAME_BYTES, ResourceKind,
    SendFailure,
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::{CancellationToken, PollSender};
use wasmtime::component::{
    Destination, FutureReader, Resource, ResourceType, Source, StreamConsumer, StreamProducer,
    StreamReader, StreamResult, VecBuffer, WasmList,
};
use wasmtime::{AsContext, AsContextMut, StoreContextMut};
use wasmtime_wasi::WasiView;

const UPLOAD_QUEUE_CHUNKS: usize = 2;

/// Each half is handed to the guest by its first `send` or `receive`; a second call finds `None`.
struct BrokerTcp {
    peer: SocketAddr,
    unclaimed_upload: Option<TcpUpload>,
    unclaimed_download: Option<TcpDownload>,
    closed: CancellationToken,
}

impl BrokerTcp {
    fn new(flow: TcpFlow) -> Self {
        let peer = flow.peer();
        let closed = flow.close_token();
        let (upload, download) = flow.split();
        Self {
            peer,
            unclaimed_upload: Some(upload),
            unclaimed_download: Some(download),
            closed,
        }
    }
}

impl Drop for BrokerTcp {
    fn drop(&mut self) {
        self.closed.cancel();
    }
}

struct BrokerUdp {
    flow: UdpFlow,
    closed: CancellationToken,
    is_receiving: bool,
}

impl BrokerUdp {
    fn new(flow: UdpFlow) -> Self {
        Self {
            flow,
            closed: CancellationToken::new(),
            is_receiving: false,
        }
    }
}

impl Drop for BrokerUdp {
    fn drop(&mut self) {
        self.closed.cancel();
        self.flow.close();
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
) -> wasmtime::Result<(Completion, FutureReader<Result<(), BrokerError>>)> {
    let (sender, receiver) = oneshot::channel();
    let future = FutureReader::new(store, async move {
        let result = receiver.await.unwrap_or(Err(Error::Cancelled));
        Ok::<_, wasmtime::Error>(result.map_err(broker_error))
    })?;
    Ok((Completion(Some(sender)), future))
}

struct UploadPipe {
    sender: PollSender<Vec<u8>>,
    cancelled: CancellationToken,
}

impl<T: 'static> StreamConsumer<T> for UploadPipe {
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
            self.cancelled.cancel();
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        if std::task::ready!(self.sender.poll_reserve(context)).is_err() {
            return Poll::Ready(Ok(StreamResult::Dropped));
        }
        let mut source = source.as_direct(store);
        let count = source.remaining().len().min(MAX_NETWORK_CHUNK_BYTES);
        if count == 0 {
            self.sender.abort_send();
            return Poll::Ready(Ok(StreamResult::Completed));
        }
        let bytes = source.remaining()[..count].to_vec();
        source.mark_read(count);
        let result = self.sender.send_item(bytes);
        Poll::Ready(Ok(if result.is_ok() {
            StreamResult::Completed
        } else {
            StreamResult::Dropped
        }))
    }
}

/// Writes the guest's chunks in order, then finishes the upload when the guest stream ends.
/// A failed upload closes the whole flow; a cancelled one does not.
fn start_upload(
    mut upload: TcpUpload,
    closed: &CancellationToken,
    mut completion: Completion,
) -> UploadPipe {
    let (sender, mut chunks) = mpsc::channel::<Vec<u8>>(UPLOAD_QUEUE_CHUNKS);
    let cancelled = closed.child_token();
    let task_cancelled = cancelled.clone();
    let closed = closed.clone();
    tokio::spawn(async move {
        let uploading = async {
            loop {
                let chunk = tokio::select! {
                    chunk = chunks.recv() => chunk,
                    error = upload.wait_failed() => return Err(error),
                };
                let Some(chunk) = chunk else { break };
                upload.write(&chunk).await?;
            }
            upload.finish().await
        };
        let result = tokio::select! {
            biased;
            () = task_cancelled.cancelled() => Err(Error::Cancelled),
            result = uploading => result,
        };
        if result.is_err_and(|error| error != Error::Cancelled) {
            closed.cancel();
        }
        completion.finish(result);
    });
    UploadPipe {
        sender: PollSender::new(sender),
        cancelled,
    }
}

fn begin_send<D: 'static>(
    mut store: impl AsContextMut<Data = D>,
    upload: Option<TcpUpload>,
    closed: &CancellationToken,
    mut data: StreamReader<u8>,
    mut completion: Completion,
) -> wasmtime::Result<()> {
    let Some(upload) = upload else {
        data.close(&mut store)?;
        completion.finish(Err(Error::InvalidState));
        return Ok(());
    };
    data.pipe(store, start_upload(upload, closed, completion))
}

/// Hands the guest each batch the stream yields; the stream's end or error finishes the completion.
struct ItemStream<Item> {
    stream: BoxStream<'static, Result<Vec<Item>, Error>>,
    completion: Completion,
    is_ended: bool,
}

impl<T: 'static, Item: Send + Sync + 'static> StreamProducer<T> for ItemStream<Item> {
    type Item = Item;
    type Buffer = VecBuffer<Item>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        mut store: StoreContextMut<'a, T>,
        mut destination: Destination<'a, Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        if self.is_ended {
            return Poll::Ready(Ok(StreamResult::Dropped));
        }
        if destination.remaining(&mut store) == Some(0) {
            return Poll::Ready(Ok(StreamResult::Completed));
        }
        let result = match std::task::ready!(self.stream.poll_next_unpin(context)) {
            Some(Ok(items)) => {
                destination.set_buffer(items.into());
                return Poll::Ready(Ok(StreamResult::Completed));
            }
            Some(Err(error)) => Err(error),
            None => Ok(()),
        };
        self.is_ended = true;
        self.completion.finish(result);
        Poll::Ready(Ok(StreamResult::Dropped))
    }
}

type ReceiveState<Flow> = Option<(Flow, CancellationToken)>;

/// Yields each download chunk; the resource closing mid-flow is `Closed`, the peer's `Eof` is the end.
async fn next_chunk(
    state: ReceiveState<TcpDownload>,
) -> Option<(Result<Vec<u8>, Error>, ReceiveState<TcpDownload>)> {
    let (mut download, closed) = state?;
    match download.next().await {
        Some(Ok(bytes)) => Some((Ok(bytes), Some((download, closed)))),
        Some(Err(error)) => Some((Err(error), None)),
        None if closed.is_cancelled() => Some((Err(Error::Closed), None)),
        None => None,
    }
}

async fn next_datagrams(
    state: ReceiveState<UdpFlow>,
) -> Option<(Result<Vec<BrokerDatagram>, Error>, ReceiveState<UdpFlow>)> {
    let (flow, closed) = state?;
    Some(match until_closed(&closed, flow.receive()).await {
        Ok(datagrams) => (
            Ok(datagrams.into_iter().map(broker_datagram).collect()),
            Some((flow, closed)),
        ),
        Err(error) => (Err(error), None),
    })
}

fn broker_datagram(Datagram { peer, bytes }: Datagram) -> BrokerDatagram {
    BrokerDatagram {
        peer: SocketAddress {
            address: ip_address(peer.ip()),
            port: peer.port(),
        },
        bytes,
    }
}

/// Dropping the receive stream drops the download half; the flow keeps uploading.
fn begin_receive<D: 'static>(
    store: impl AsContextMut<Data = D>,
    download: Option<TcpDownload>,
    closed: &CancellationToken,
    mut completion: Completion,
) -> wasmtime::Result<StreamReader<u8>> {
    let stream = if let Some(download) = download {
        futures_util::stream::unfold(Some((download, closed.clone())), next_chunk).boxed()
    } else {
        completion.finish(Err(Error::InvalidState));
        futures_util::stream::empty().boxed()
    };
    StreamReader::new(
        store,
        ItemStream {
            stream,
            completion,
            is_ended: false,
        },
    )
}

async fn until_closed<R>(
    closed: &CancellationToken,
    operation: impl Future<Output = Result<R, Error>>,
) -> Result<R, Error> {
    tokio::select! {
        biased;
        () = closed.cancelled() => Err(Error::Closed),
        result = operation => result,
    }
}

struct Accept {
    client: Client,
    grant: terra_network::ListenerGrant,
    closed: CancellationToken,
    pending: Option<BoxFuture<'static, Result<TcpFlow, Error>>>,
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
            Box::pin(async move { until_closed(&closed, client.accept(grant)).await })
        });
        let result = std::task::ready!(pending.as_mut().poll(context));
        self.pending = None;
        match result {
            Ok(flow) => {
                if let Ok(resource) = store.data_mut().ctx().table.push(BrokerTcp::new(flow)) {
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

fn begin_accept<D: WasiView + 'static>(
    store: impl AsContextMut<Data = D>,
    client: Client,
    grant: terra_network::ListenerGrant,
    closed: CancellationToken,
    is_duplicate: bool,
    mut completion: Completion,
) -> wasmtime::Result<StreamReader<Resource<BrokerTcp>>> {
    if is_duplicate {
        completion.finish(Err(Error::InvalidState));
    }
    StreamReader::new(
        store,
        Accept {
            client,
            grant,
            closed,
            pending: None,
            completion,
            is_eof: is_duplicate,
        },
    )
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
                    Ok(peer) => client.open_tcp(peer, inline_urgent).await,
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
                    Ok(flow) => access
                        .with(|mut store| store.get().ctx().table.push(BrokerTcp::new(flow)))
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
            let result = match client.open_udp().await {
                Ok(flow) => access
                    .with(|mut store| store.get().ctx().table.push(BrokerUdp::new(flow)))
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
                Ok((client, grant)) => client.open_published_udp(grant).await,
                Err(error) => Err(error),
            };
            let result = match result {
                Ok(flow) => access
                    .with(|mut store| store.get().ctx().table.push(BrokerUdp::new(flow)))
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
            let (client, grant, closed) = (
                listener.client.clone(),
                listener.grant,
                listener.closed.clone(),
            );
            let (completion, future) = create_completion(&mut store)?;
            let stream = begin_accept(&mut store, client, grant, closed, is_duplicate, completion)?;
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
                address: ip_address(tcp.peer.ip()),
                port: tcp.peer.port(),
            };
            Ok((Ok::<_, BrokerError>(address),))
        },
    )?;
    interface.func_wrap(
        "[method]tcp.send",
        |mut store, (resource, data): (Resource<BrokerTcp>, StreamReader<u8>)| {
            let tcp = store.data_mut().ctx().table.get_mut(&resource)?;
            let upload = tcp.unclaimed_upload.take();
            let closed = tcp.closed.clone();
            let (completion, future) = create_completion(&mut store)?;
            begin_send(&mut store, upload, &closed, data, completion)?;
            Ok((future,))
        },
    )?;
    interface.func_wrap(
        "[method]tcp.receive",
        |mut store, (resource,): (Resource<BrokerTcp>,)| {
            let tcp = store.data_mut().ctx().table.get_mut(&resource)?;
            let download = tcp.unclaimed_download.take();
            let closed = tcp.closed.clone();
            let (completion, future) = create_completion(&mut store)?;
            let stream = begin_receive(&mut store, download, &closed, completion)?;
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
                let (flow, closed) = access.with(|mut store| {
                    store
                        .get()
                        .ctx()
                        .table
                        .get(&resource)
                        .map(|udp| (udp.flow.clone(), udp.closed.clone()))
                })?;
                let result = until_closed(&closed, send_datagrams(&flow, datagrams)).await;
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
            let (flow, closed) = (udp.flow.clone(), udp.closed.clone());
            let (mut completion, future) = create_completion(&mut store)?;
            if is_duplicate {
                completion.finish(Err(Error::InvalidState));
            }
            let stream = StreamReader::new(
                &mut store,
                ItemStream {
                    stream: if is_duplicate {
                        futures_util::stream::empty().boxed()
                    } else {
                        futures_util::stream::unfold(Some((flow, closed)), next_datagrams).boxed()
                    },
                    completion,
                    is_ended: false,
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
    flow: &UdpFlow,
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
        for SendFailure { index, error } in flow.send(datagrams).await? {
            let position = index as usize;
            let (Some(&guest_index), Some(&peer)) = (indices.get(position), peers.get(position))
            else {
                return Err(Error::Io);
            };
            failures.push((guest_index, error));
            if error == Error::AccessDenied {
                denied.push(peer);
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
                    let result = client
                        .resolve(name.clone())
                        .await
                        .map(|addresses| addresses.into_iter().map(ip_address).collect::<Vec<_>>());
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
    use std::time::Duration;
    use terra_network::config::{Config, Network, PublishedListener};
    use terra_protocol::network::MAX_NETWORK_READ_BYTES;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};

    async fn bounded<T>(future: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .expect("test stalled")
    }

    fn broker_client(listeners: Vec<PublishedListener>) -> Client {
        let broker = terra_network::Broker::bind(&Config {
            policy: Network {
                allow: vec!["HOST_LOOPBACK".into()],
                ..Network::default()
            },
            gateways: [
                "100.96.0.1".parse().unwrap(),
                "fd53:4d00::1".parse().unwrap(),
            ],
            listeners,
        })
        .unwrap();
        let (worker, endpoint) = tokio::io::duplex(1 << 20);
        tokio::spawn(broker.serve(endpoint));
        Client::new(worker)
    }

    async fn connected_tcp() -> (BrokerTcp, TcpStream, Client) {
        let client = broker_client(vec![]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (flow, accepted) = tokio::join!(client.open_tcp(address, false), listener.accept());
        (BrokerTcp::new(flow.unwrap()), accepted.unwrap().0, client)
    }

    fn unit_store() -> wasmtime::Store<()> {
        wasmtime::Store::new(&crate::engine::device_engine().unwrap(), ())
    }

    fn completion() -> (Completion, oneshot::Receiver<Result<(), Error>>) {
        let (sender, receiver) = oneshot::channel();
        (Completion(Some(sender)), receiver)
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
    async fn published_listener_resources_have_only_the_configured_family_and_port() {
        let client = broker_client(vec![]);
        let host = NetworkHost::new(Some(super::super::NetworkBackend {
            client: client.clone(),
            ready: terra_network::config::Ready {
                host_service_ports: vec![],
            },
            listeners: vec![
                PublishedListener {
                    grant: 11,
                    address: "127.0.0.1:4000".parse().unwrap(),
                    transport: ResourceKind::Tcp,
                },
                PublishedListener {
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
        client.disconnect();
    }

    #[tokio::test]
    async fn accepted_flows_keep_the_broker_peer_address() {
        bounded(async {
            let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = reserved.local_addr().unwrap();
            drop(reserved);
            let client = broker_client(vec![PublishedListener {
                grant: 11,
                address,
                transport: ResourceKind::Tcp,
            }]);
            let accepting = tokio::spawn({
                let client = client.clone();
                async move { client.accept(11).await }
            });
            let connected = loop {
                if let Ok(stream) = TcpStream::connect(address).await {
                    break stream;
                }
            };
            let tcp = BrokerTcp::new(accepting.await.unwrap().unwrap());
            assert_eq!(tcp.peer, connected.local_addr().unwrap());
            client.disconnect();
        })
        .await;
    }

    #[tokio::test]
    async fn upload_preserves_order_and_completes_after_finish() {
        bounded(async {
            let (mut tcp, mut remote, client) = connected_tcp().await;
            let bytes: Vec<u8> = (0..251)
                .cycle()
                .take(3 * MAX_NETWORK_CHUNK_BYTES + 5)
                .collect();
            let mut store = unit_store();
            let (completion, outcome) = completion();
            let input = StreamReader::new(&mut store, bytes.clone()).unwrap();
            begin_send(
                &mut store,
                tcp.unclaimed_upload.take(),
                &tcp.closed,
                input,
                completion,
            )
            .unwrap();
            store
                .run_concurrent(async |_| {
                    let mut received = Vec::new();
                    remote.read_to_end(&mut received).await.unwrap();
                    assert_eq!(received, bytes);
                    assert_eq!(outcome.await.unwrap(), Ok(()));
                })
                .await
                .unwrap();
            client.disconnect();
        })
        .await;
    }

    #[tokio::test]
    async fn dropping_the_resource_cancels_a_blocked_upload_and_resets_the_flow() {
        bounded(async {
            let (mut tcp, mut remote, client) = connected_tcp().await;
            let mut store = unit_store();
            let (completion, outcome) = completion();
            let input = StreamReader::new(&mut store, vec![7; 16 << 20]).unwrap();
            begin_send(
                &mut store,
                tcp.unclaimed_upload.take(),
                &tcp.closed,
                input,
                completion,
            )
            .unwrap();
            store
                .run_concurrent(async |_| {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    drop(tcp);
                    assert_eq!(outcome.await.unwrap(), Err(Error::Cancelled));
                    let mut sink = Vec::new();
                    let _ = remote.read_to_end(&mut sink).await;
                    assert!(sink.len() < 16 << 20);
                })
                .await
                .unwrap();
            client.disconnect();
        })
        .await;
    }

    async fn receive_outcome(
        mut tcp: BrokerTcp,
        remote: TcpStream,
        finish_remote: impl AsyncFnOnce(TcpStream),
    ) -> (Vec<u8>, Result<(), Error>) {
        let mut store = unit_store();
        let (completion, outcome) = completion();
        let (collected, mut chunks) = mpsc::unbounded_channel();
        let input = begin_receive(
            &mut store,
            tcp.unclaimed_download.take(),
            &tcp.closed,
            completion,
        )
        .unwrap();
        input.pipe(&mut store, CollectBytes(collected)).unwrap();
        store
            .run_concurrent(async |_| {
                finish_remote(remote).await;
                let outcome = outcome.await.unwrap();
                let mut received = Vec::new();
                while let Ok(chunk) = chunks.try_recv() {
                    received.extend(chunk);
                }
                drop(tcp);
                (received, outcome)
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn receive_delivers_data_then_ends_successfully_on_peer_fin() {
        bounded(async {
            let (tcp, remote, client) = connected_tcp().await;
            let payload = vec![8; MAX_NETWORK_READ_BYTES + 3];
            let (received, outcome) = receive_outcome(tcp, remote, async |mut remote| {
                remote.write_all(&payload).await.unwrap();
                remote.shutdown().await.unwrap();
                tokio::time::sleep(Duration::from_millis(200)).await;
            })
            .await;
            assert_eq!(outcome, Ok(()));
            assert_eq!(received, payload);
            client.disconnect();
        })
        .await;
    }

    #[tokio::test]
    async fn receive_reports_a_reset_as_the_future_error() {
        bounded(async {
            let (tcp, remote, client) = connected_tcp().await;
            let (_, outcome) = receive_outcome(tcp, remote, async |remote| {
                remote.set_zero_linger().unwrap();
                drop(remote);
            })
            .await;
            assert_eq!(outcome, Err(Error::ConnectionReset));
            client.disconnect();
        })
        .await;
    }

    #[tokio::test]
    async fn second_send_receive_and_accept_are_invalid_state() {
        bounded(async {
            let (mut tcp, _remote, client) = connected_tcp().await;
            let mut store = unit_store();
            tcp.unclaimed_upload = None;
            tcp.unclaimed_download = None;
            let (done, outcome) = completion();
            let input = StreamReader::new(&mut store, vec![1_u8]).unwrap();
            begin_send(
                &mut store,
                tcp.unclaimed_upload.take(),
                &tcp.closed,
                input,
                done,
            )
            .unwrap();
            assert_eq!(outcome.await.unwrap(), Err(Error::InvalidState));
            let (done, outcome) = completion();
            begin_receive(&mut store, tcp.unclaimed_download.take(), &tcp.closed, done).unwrap();
            assert_eq!(outcome.await.unwrap(), Err(Error::InvalidState));
            client.disconnect();
        })
        .await;
    }

    #[tokio::test]
    async fn second_accept_is_invalid_state() {
        let client = broker_client(vec![]);
        let host = crate::component::vsock::VsockHost::new(
            crate::component::context::DeviceContext::new(4096).unwrap(),
            crate::component::vsock::streams::FrontendStreams::new().0,
            None,
        );
        let mut store = wasmtime::Store::new(&crate::engine::device_engine().unwrap(), host);
        let (done, outcome) = completion();
        begin_accept(
            &mut store,
            client.clone(),
            11,
            CancellationToken::new(),
            true,
            done,
        )
        .unwrap();
        assert_eq!(outcome.await.unwrap(), Err(Error::InvalidState));
        client.disconnect();
    }

    #[tokio::test]
    async fn dropping_a_pending_accept_stream_releases_the_listener_grant() {
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
        bounded(async {
            let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = reserved.local_addr().unwrap();
            drop(reserved);
            let client = broker_client(vec![PublishedListener {
                grant: 11,
                address,
                transport: ResourceKind::Tcp,
            }]);
            let host = crate::component::vsock::VsockHost::new(
                crate::component::context::DeviceContext::new(4096).unwrap(),
                crate::component::vsock::streams::FrontendStreams::new().0,
                None,
            );
            let mut store = wasmtime::Store::new(&crate::engine::device_engine().unwrap(), host);
            let (done, outcome) = completion();
            let input = begin_accept(
                &mut store,
                client.clone(),
                11,
                CancellationToken::new(),
                false,
                done,
            )
            .unwrap();
            input.pipe(&mut store, AcceptSink).unwrap();
            store
                .run_concurrent(async |_| {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    assert!(
                        tokio::time::timeout(Duration::from_millis(200), client.accept(11))
                            .await
                            .is_err(),
                        "a second accept waits while the pending accept owns the grant"
                    );
                })
                .await
                .unwrap();
            drop(store);
            assert_eq!(outcome.await.unwrap(), Err(Error::Cancelled));
            let accepting = tokio::spawn({
                let client = client.clone();
                async move { client.accept(11).await }
            });
            tokio::time::sleep(Duration::from_millis(100)).await;
            let connected = tokio::net::TcpStream::connect(address).await.unwrap();
            let accepted = tokio::time::timeout(Duration::from_secs(5), accepting)
                .await
                .expect("the dropped accept released the grant")
                .unwrap()
                .unwrap();
            assert_eq!(accepted.peer(), connected.local_addr().unwrap());
            client.disconnect();
        })
        .await;
    }

    #[tokio::test]
    async fn send_to_maps_failures_to_guest_indices_and_lists_denied_peers() {
        bounded(async {
            let client = broker_client(vec![]);
            let flow = client.open_udp().await.unwrap();
            let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let denied: SocketAddr = "192.0.2.1:9".parse().unwrap();
            let to = |address: SocketAddr, bytes: Vec<u8>| BrokerDatagram {
                peer: SocketAddress {
                    address: ip_address(address.ip()),
                    port: address.port(),
                },
                bytes,
            };
            let mapped = BrokerDatagram {
                peer: SocketAddress {
                    address: IpAddress::Ipv6(
                        "::ffff:127.0.0.1"
                            .parse::<Ipv6Addr>()
                            .unwrap()
                            .segments()
                            .into(),
                    ),
                    port: 9,
                },
                bytes: vec![],
            };
            let (failures, denied_peers) = send_datagrams(
                &flow,
                vec![
                    mapped,
                    to(denied, vec![1]),
                    to(target.local_addr().unwrap(), vec![2]),
                    to(
                        target.local_addr().unwrap(),
                        vec![0; MAX_NETWORK_DATAGRAM_BYTES + 1],
                    ),
                ],
            )
            .await
            .unwrap();
            let failures: Vec<_> = failures.into_iter().map(|f| (f.index, f.error)).collect();
            assert_eq!(
                failures,
                vec![
                    (0, BrokerError::InvalidArgument),
                    (1, BrokerError::AccessDenied),
                    (3, BrokerError::DatagramTooLarge),
                ]
            );
            assert_eq!(denied_peers, vec![denied]);
            let mut received = [0; 4];
            let (length, _) = target.recv_from(&mut received).await.unwrap();
            assert_eq!(&received[..length], [2]);
            client.disconnect();
        })
        .await;
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
                    host_service_ports: Vec::new(),
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
