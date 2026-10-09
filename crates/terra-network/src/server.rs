use crate::config::{Config, Ready};
use crate::{Error, Handle, Operation, Reply, ResourceKind, map_io_error};
use futures_util::FutureExt;
use futures_util::future::{AbortHandle, Abortable, BoxFuture};
use futures_util::stream::{self, FuturesUnordered, Stream, StreamExt};
use socket2::SockRef;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::sync::Arc;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use terra_policy::{BoxPolicy, NameLookup};
use terra_protocol::network::{
    DATAGRAM_FRAME_OVERHEAD_BYTES, Datagram, MAX_NETWORK_CHUNK_BYTES,
    MAX_NETWORK_DATAGRAM_BATCH_BYTES, MAX_NETWORK_DATAGRAM_BYTES, MAX_NETWORK_DATAGRAMS,
    MAX_NETWORK_FRAME_BYTES, MAX_NETWORK_READ_BYTES, Request, RequestId, Response, SendFailure,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{Mutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::Instant;

const UDP_PEER_TTL: Duration = Duration::from_secs(terra_protocol::network::UDP_PEER_TTL_SECS);

pub struct Broker {
    policy: Arc<BoxPolicy>,
    listeners: BTreeMap<u32, Arc<TcpListener>>,
    udp_listeners: BTreeMap<u32, Arc<UdpSocket>>,
    limits: crate::config::Limits,
    resolvers: Arc<Semaphore>,
    resources: BTreeMap<Handle, Resource>,
    next_handle: Handle,
}

enum Resource {
    Tcp {
        socket: Arc<TcpStream>,
        peer: SocketAddr,
        write_closed: bool,
        #[cfg(windows)]
        write_shutdown_started: Arc<AtomicBool>,
        write_poisoned: Arc<Mutex<bool>>,
        write_slots: Arc<Semaphore>,
    },
    Udp(UdpResource),
}

#[derive(Clone)]
struct UdpResource {
    ipv4: Option<Arc<UdpSocket>>,
    ipv6: Option<Arc<UdpSocket>>,
    peers: Arc<std::sync::Mutex<std::collections::VecDeque<(SocketAddr, Instant)>>>,
    publication_grant: Option<crate::ListenerGrant>,
}

impl UdpResource {
    fn authorize_send(&self, policy: &BoxPolicy, peer: SocketAddr) -> bool {
        if self.publication_grant.is_some() {
            self.knows_peer(peer)
        } else {
            authorize_peer(policy, peer)
        }
    }

    fn remember_peer(&self, peer: SocketAddr) {
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        peers.retain(|(known, expires)| *known != peer && *expires > now);
        if peers.len() == crate::MAX_UDP_PEERS {
            peers.pop_front();
        }
        peers.push_back((peer, now + UDP_PEER_TTL));
    }

    fn knows_peer(&self, peer: SocketAddr) -> bool {
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        peers.retain(|(_, expires)| *expires > now);
        peers.iter().any(|(known, _)| *known == peer)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum WorkKey {
    Read(Handle),
    Error(Handle),
    Write(Handle),
    Upload(Handle),
    Listener(u32),
}

struct Pending {
    abort: AbortHandle,
    key: Option<WorkKey>,
    opens_resource: bool,
    is_shutdown: bool,
    admission: crate::RequestAdmission,
}

enum Completion {
    Reply(Reply),
    Open(Resource),
}

struct ActiveTcpWrite {
    socket: Arc<TcpStream>,
    poisoned: OwnedMutexGuard<bool>,
    incomplete_prefix: bool,
    #[cfg(windows)]
    write_shutdown_started: Arc<AtomicBool>,
}

impl Drop for ActiveTcpWrite {
    fn drop(&mut self) {
        if self.incomplete_prefix {
            *self.poisoned = true;
            #[cfg(windows)]
            self.write_shutdown_started.store(true, Ordering::SeqCst);
            let shutdown = SockRef::from(self.socket.as_ref()).shutdown(std::net::Shutdown::Write);
            #[cfg(windows)]
            if shutdown.is_err() {
                self.write_shutdown_started.store(false, Ordering::SeqCst);
            }
            let _ = shutdown;
        }
    }
}

#[cfg(not(windows))]
async fn wait_tcp_error(socket: &TcpStream) -> Error {
    if let Err(error) = socket.ready(tokio::io::Interest::ERROR).await {
        return map_io_error(error);
    }
    match socket.take_error() {
        Ok(None) => Error::ConnectionReset,
        Ok(Some(error)) | Err(error) => map_io_error(error),
    }
}

#[cfg(windows)]
async fn wait_tcp_error(socket: &TcpStream, write_shutdown_started: &AtomicBool) -> Error {
    loop {
        tokio::select! {
            ready = socket.ready(tokio::io::Interest::ERROR) => {
                if let Err(error) = ready {
                    return map_io_error(error);
                }
                return match socket.take_error() {
                    Ok(None) => Error::ConnectionReset,
                    Ok(Some(error)) | Err(error) => map_io_error(error),
                };
            }
            () = tokio::time::sleep(Duration::from_millis(50)) => {
                match socket.take_error() {
                    Ok(None) => {}
                    Ok(Some(error)) | Err(error) => return map_io_error(error),
                }
                match read_windows_tcp_state(socket) {
                    Ok(windows_sys::Win32::Networking::WinSock::TCPSTATE_CLOSED)
                        if !write_shutdown_started.load(Ordering::SeqCst) => return Error::ConnectionReset,
                    Ok(_) => {}
                    Err(error) => return map_io_error(error),
                }
            }
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn read_windows_tcp_state(socket: &TcpStream) -> io::Result<i32> {
    use windows_sys::Win32::Networking::WinSock::{
        SIO_TCP_INFO, SOCKET_ERROR, TCP_INFO_v0, WSAGetLastError, WSAIoctl,
    };

    let version = 0u32;
    let mut info = TCP_INFO_v0::default();
    let info_bytes = u32::try_from(std::mem::size_of::<TCP_INFO_v0>())
        .map_err(|_| io::Error::other("TCP info size exceeds ioctl limit"))?;
    let raw_socket = usize::try_from(socket.as_raw_socket())
        .map_err(|_| io::Error::other("socket handle exceeds ioctl limit"))?;
    let mut returned = 0u32;
    // SAFETY: WSAIoctl completes synchronously with live input and output buffers.
    let status = unsafe {
        WSAIoctl(
            raw_socket,
            SIO_TCP_INFO,
            (&raw const version).cast(),
            4,
            (&raw mut info).cast(),
            info_bytes,
            &raw mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if status == SOCKET_ERROR {
        // SAFETY: WSAGetLastError reads the calling thread's last Winsock error.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    if returned < info_bytes {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short TCP info"));
    }
    Ok(info.State)
}

type Work = BoxFuture<'static, (RequestId, Result<Completion, Error>)>;
type OperationFuture = BoxFuture<'static, Result<Completion, Error>>;

impl Broker {
    pub fn bind(config: Config) -> io::Result<Self> {
        config.limits.validate()?;
        if config.listeners.len() > crate::MAX_LISTENERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many published listeners",
            ));
        }
        let policy = Arc::new(
            BoxPolicy::new(&config.policy, config.gateways)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
        );
        let mut listeners = BTreeMap::new();
        let mut udp_listeners = BTreeMap::new();
        for grant in &config.listeners {
            if grant.grant == 0
                || !is_host_loopback(grant.address.ip())
                || grant.address.port() == 0
                || listeners.contains_key(&grant.grant)
                || udp_listeners.contains_key(&grant.grant)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid published listener grant",
                ));
            }
            let binding = match grant.transport {
                ResourceKind::Tcp => bind_tcp_listener(grant.address).map(|socket| {
                    listeners.insert(grant.grant, socket);
                }),
                ResourceKind::Udp => bind_udp(grant.address).map(|socket| {
                    udp_listeners.insert(grant.grant, socket);
                }),
            };
            if let Err(error) = binding {
                if grant.address.is_ipv6()
                    && config.listeners.iter().any(|other| {
                        other.address.is_ipv4()
                            && other.address.port() == grant.address.port()
                            && other.transport == grant.transport
                    })
                {
                    continue;
                }
                return Err(error);
            }
        }
        Ok(Self {
            policy,
            listeners,
            udp_listeners,
            limits: config.limits,
            resolvers: Arc::new(Semaphore::new(crate::MAX_RESOLVERS)),
            resources: BTreeMap::new(),
            next_handle: 1,
        })
    }

    #[must_use]
    pub fn ready(&self) -> Ready {
        Ready {
            version: crate::config::PROTOCOL_VERSION,
            host_service_ports: self.policy.host_service_ports().to_vec(),
            blocks_direct_dns: self.policy.blocks_direct_dns(),
        }
    }

    pub async fn serve(
        self,
        channel: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    ) -> io::Result<()> {
        let (read, mut write) = tokio::io::split(channel);
        let read = tokio::io::BufReader::with_capacity(crate::IPC_READ_BUFFER_BYTES, read);
        let capacity = self.limits.pending_requests.min(crate::MAX_QUEUED_REQUESTS);
        let requests = stream::unfold(read, |mut read| async move {
            let request = terra_protocol::read_frame_async_with_limit::<Request>(
                &mut read,
                MAX_NETWORK_FRAME_BYTES,
            )
            .await;
            Some((request, read))
        });
        let (replies, mut outgoing) = mpsc::channel::<Response>(capacity + 2);
        let writer_closed = tokio_util::sync::CancellationToken::new();
        let notification = writer_closed.clone();
        let writer = tokio::spawn(async move {
            let result = crate::writer::write_queued_frames(&mut write, &mut outgoing, |reply| {
                terra_protocol::encode_frame_with_limit(&reply, MAX_NETWORK_FRAME_BYTES)
            })
            .await;
            notification.cancel();
            result
        });
        let result = self.dispatch(requests, replies, writer_closed).await;
        writer.abort();
        let _ = writer.await;
        result
    }

    async fn dispatch(
        mut self,
        requests: impl Stream<Item = io::Result<Option<Request>>>,
        replies: mpsc::Sender<Response>,
        writer_closed: tokio_util::sync::CancellationToken,
    ) -> io::Result<()> {
        tokio::pin!(requests);
        let mut pending = BTreeMap::<RequestId, Pending>::new();
        let mut busy = BTreeSet::new();
        let mut work = FuturesUnordered::<Work>::new();
        loop {
            tokio::select! {
                () = writer_closed.cancelled() => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "broker reply writer stopped")),
                request = requests.next() => {
                    let Some(request) = request.transpose()?.flatten() else { return Ok(()); };
                    if request.id == 0 {
                        send_reply(&replies, request.id, Err(Error::InvalidArgument)).await?;
                    } else if pending.contains_key(&request.id) {
                        send_reply(&replies, request.id, Err(Error::DuplicateRequest)).await?;
                    } else {
                        match request.operation {
                            Operation::Cancel(target) => {
                                let cancelled = pending.get(&target).is_some_and(|operation| {
                                    if operation.abort.is_aborted() || operation.is_shutdown { return false; }
                                    operation.abort.abort();
                                    true
                                });
                                send_reply(&replies, request.id, Ok(Reply::Cancelled(cancelled))).await?;
                            }
                            Operation::Close(handle) => {
                                let result = if self.resources.remove(&handle).is_some() {
                                    for operation in pending.values().filter(|operation| matches!(operation.key, Some(WorkKey::Read(id) | WorkKey::Error(id) | WorkKey::Write(id) | WorkKey::Upload(id)) if id == handle)) {
                                        operation.abort.abort();
                                    }
                                    Ok(Reply::Done)
                                } else { Err(Error::StaleHandle) };
                                send_reply(&replies, request.id, result).await?;
                            }
                            operation => {
                                let admission = crate::RequestAdmission::from(&operation);
                                // ponytail: bounded pending scans; keep class counters if throughput needs them.
                                if pending.len() == self.limits.pending_requests
                                    || pending.values().filter(|operation| operation.admission == admission).count() >= admission.limit()
                                {
                                    send_reply(&replies, request.id, Err(Error::LimitExceeded)).await?;
                                    continue;
                                }
                                let opens_resource = matches!(operation, Operation::OpenTcp { .. } | Operation::OpenUdp | Operation::OpenPublishedUdp(_) | Operation::Accept(_));
                                let is_shutdown = matches!(operation, Operation::ShutdownWrite(_));
                                if opens_resource && self.resources.len() + pending.values().filter(|operation| operation.opens_resource).count() >= self.limits.resources {
                                    send_reply(&replies, request.id, Err(Error::LimitExceeded)).await?;
                                    continue;
                                }
                                match self.prepare(operation) {
                                    Err(error) => send_reply(&replies, request.id, Err(error)).await?,
                                    Ok((key, mut future)) => {
                                        if key.is_some_and(|key| !matches!(key, WorkKey::Upload(_)) && !busy.insert(key)) {
                                            send_reply(&replies, request.id, Err(Error::Busy)).await?;
                                            continue;
                                        }
                                        // Polling here fixes TCP write order before the next request is admitted.
                                        if let Some(completion) = future.as_mut().now_or_never() {
                                            if let Some(key) = key { busy.remove(&key); }
                                            let result = completion.and_then(|completed| self.complete(completed));
                                            send_reply(&replies, request.id, result).await?;
                                            continue;
                                        }
                                        let (abort, registration) = AbortHandle::new_pair();
                                        pending.insert(request.id, Pending { abort, key, opens_resource, is_shutdown, admission });
                                        work.push(Box::pin(async move { (request.id, Abortable::new(future, registration).await.unwrap_or(Err(Error::Cancelled))) }));
                                    }
                                }
                            }
                        }
                    }
                }
                Some((id, completion)) = work.next(), if !work.is_empty() => {
                    let operation = pending.remove(&id).ok_or_else(|| io::Error::other("broker lost pending operation"))?;
                    if let Some(key) = operation.key { busy.remove(&key); }
                    let result = if operation.abort.is_aborted() { Err(Error::Cancelled) } else { completion.and_then(|completed| self.complete(completed)) };
                    send_reply(&replies, id, result).await?;
                }
            }
        }
    }

    fn complete(&mut self, completion: Completion) -> Result<Reply, Error> {
        match completion {
            Completion::Reply(reply) => Ok(reply),
            Completion::Open(resource) => {
                let handle = self.next_handle;
                self.next_handle = handle.checked_add(1).ok_or(Error::LimitExceeded)?;
                let (kind, peer) = match &resource {
                    Resource::Tcp { peer, .. } => (ResourceKind::Tcp, *peer),
                    Resource::Udp(_) => {
                        (ResourceKind::Udp, terra_protocol::network::UNBOUND_UDP_PEER)
                    }
                };
                self.resources.insert(handle, resource);
                Ok(Reply::Opened { handle, kind, peer })
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn prepare(
        &mut self,
        operation: Operation,
    ) -> Result<(Option<WorkKey>, OperationFuture), Error> {
        let (key, future): (_, BoxFuture<'static, Result<Completion, Error>>) = match operation {
            Operation::OpenTcp {
                peer,
                inline_urgent,
            } => {
                validate_peer(peer)?;
                if !authorize_peer(&self.policy, peer) {
                    return Err(Error::AccessDenied);
                }
                (
                    None,
                    Box::pin(async move {
                        let socket =
                            create_tcp_socket(peer, inline_urgent).map_err(map_io_error)?;
                        let stream =
                            tokio::time::timeout(Duration::from_secs(30), socket.connect(peer))
                                .await
                                .map_err(|_| Error::TimedOut)?
                                .map_err(map_io_error)?;
                        stream.set_nodelay(true).map_err(map_io_error)?;
                        Ok(Completion::Open(Resource::Tcp {
                            socket: Arc::new(stream),
                            peer,
                            write_closed: false,
                            #[cfg(windows)]
                            write_shutdown_started: Arc::new(AtomicBool::new(false)),
                            write_poisoned: Arc::new(Mutex::new(false)),
                            write_slots: Arc::new(Semaphore::new(crate::MAX_TCP_WRITE_REQUESTS)),
                        }))
                    }),
                )
            }
            Operation::OpenUdp => (
                None,
                Box::pin(async move {
                    let ipv4 = bind_udp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).ok();
                    let ipv6 = bind_udp(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))).ok();
                    if ipv4.is_none() && ipv6.is_none() {
                        return Err(Error::Io);
                    }
                    Ok(Completion::Open(Resource::Udp(UdpResource {
                        ipv4,
                        ipv6,
                        peers: Arc::default(),
                        publication_grant: None,
                    })))
                }),
            ),
            Operation::OpenPublishedUdp(grant) => {
                let socket = self
                    .udp_listeners
                    .get(&grant)
                    .cloned()
                    .ok_or(Error::AccessDenied)?;
                if self.resources.values().any(|resource| {
                    matches!(resource, Resource::Udp(udp) if udp.publication_grant == Some(grant))
                }) {
                    return Err(Error::Busy);
                }
                let is_ipv4 = socket.local_addr().map_err(map_io_error)?.is_ipv4();
                (
                    Some(WorkKey::Listener(grant)),
                    Box::pin(async move {
                        Ok(Completion::Open(Resource::Udp(UdpResource {
                            ipv4: is_ipv4.then(|| socket.clone()),
                            ipv6: (!is_ipv4).then_some(socket),
                            peers: Arc::default(),
                            publication_grant: Some(grant),
                        })))
                    }),
                )
            }
            Operation::Accept(grant) => {
                let listener = self
                    .listeners
                    .get(&grant)
                    .cloned()
                    .ok_or(Error::AccessDenied)?;
                (
                    Some(WorkKey::Listener(grant)),
                    Box::pin(async move {
                        let (stream, peer) = listener.accept().await.map_err(map_io_error)?;
                        if !peer.ip().is_loopback() {
                            return Err(Error::AccessDenied);
                        }
                        bound_socket_buffers(&SockRef::from(&stream)).map_err(map_io_error)?;
                        stream.set_nodelay(true).map_err(map_io_error)?;
                        Ok(Completion::Open(Resource::Tcp {
                            socket: Arc::new(stream),
                            peer,
                            write_closed: false,
                            #[cfg(windows)]
                            write_shutdown_started: Arc::new(AtomicBool::new(false)),
                            write_poisoned: Arc::new(Mutex::new(false)),
                            write_slots: Arc::new(Semaphore::new(crate::MAX_TCP_WRITE_REQUESTS)),
                        }))
                    }),
                )
            }
            Operation::Read { handle, max_bytes } => {
                if max_bytes == 0 || max_bytes as usize > MAX_NETWORK_READ_BYTES {
                    return Err(Error::InvalidArgument);
                }
                let socket = self.tcp(handle)?;
                (
                    Some(WorkKey::Read(handle)),
                    Box::pin(async move {
                        loop {
                            socket.readable().await.map_err(map_io_error)?;
                            let mut bytes = vec![0; max_bytes as usize];
                            match socket.try_read(&mut bytes) {
                                Ok(0) => return Ok(Completion::Reply(Reply::Eof)),
                                Ok(length) => {
                                    bytes.truncate(length);
                                    return Ok(Completion::Reply(Reply::Data(bytes)));
                                }
                                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                                Err(error) => return Err(map_io_error(error)),
                            }
                        }
                    }),
                )
            }
            Operation::WaitError(handle) => {
                let Resource::Tcp {
                    socket,
                    #[cfg(windows)]
                    write_shutdown_started,
                    ..
                } = self.resources.get(&handle).ok_or(Error::StaleHandle)?
                else {
                    return Err(Error::WrongKind);
                };
                let socket = socket.clone();
                #[cfg(windows)]
                let write_shutdown_started = write_shutdown_started.clone();
                (
                    Some(WorkKey::Error(handle)),
                    Box::pin(async move {
                        #[cfg(windows)]
                        let error = wait_tcp_error(&socket, &write_shutdown_started).await;
                        #[cfg(not(windows))]
                        let error = wait_tcp_error(&socket).await;
                        Err(error)
                    }),
                )
            }
            Operation::WriteAll { handle, bytes } => {
                if bytes.len() > MAX_NETWORK_CHUNK_BYTES {
                    return Err(Error::InvalidArgument);
                }
                let Resource::Tcp {
                    socket,
                    write_closed,
                    #[cfg(windows)]
                    write_shutdown_started,
                    write_poisoned,
                    write_slots,
                    ..
                } = self.resources.get(&handle).ok_or(Error::StaleHandle)?
                else {
                    return Err(Error::WrongKind);
                };
                if *write_closed {
                    return Err(Error::InvalidState);
                }
                let socket = socket.clone();
                #[cfg(windows)]
                let write_shutdown_started = write_shutdown_started.clone();
                let write_poisoned = write_poisoned.clone();
                let permit = write_slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| Error::Busy)?;
                (
                    Some(WorkKey::Upload(handle)),
                    Box::pin(async move {
                        let _permit = permit;
                        let poisoned = write_poisoned.lock_owned().await;
                        if *poisoned {
                            return Err(Error::InvalidState);
                        }
                        let mut active = ActiveTcpWrite {
                            socket,
                            poisoned,
                            incomplete_prefix: false,
                            #[cfg(windows)]
                            write_shutdown_started,
                        };
                        let mut offset = 0;
                        loop {
                            if let Err(error) = active.socket.writable().await {
                                active.incomplete_prefix = true;
                                return Err(map_io_error(error));
                            }
                            if offset == bytes.len() {
                                active.incomplete_prefix = false;
                                return Ok(Completion::Reply(Reply::Written(
                                    u32::try_from(offset).map_err(|_| Error::Io)?,
                                )));
                            }
                            match active.socket.try_write(&bytes[offset..]) {
                                Ok(0) => {
                                    active.incomplete_prefix = true;
                                    return Err(Error::Io);
                                }
                                Ok(length) => {
                                    offset += length;
                                    if offset == bytes.len() {
                                        active.incomplete_prefix = false;
                                        return Ok(Completion::Reply(Reply::Written(
                                            u32::try_from(offset).map_err(|_| Error::Io)?,
                                        )));
                                    }
                                    active.incomplete_prefix = true;
                                }
                                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                                Err(error) => {
                                    active.incomplete_prefix = true;
                                    return Err(map_io_error(error));
                                }
                            }
                        }
                    }),
                )
            }
            Operation::ShutdownWrite(handle) => {
                let Resource::Tcp {
                    socket,
                    write_closed,
                    #[cfg(windows)]
                    write_shutdown_started,
                    write_poisoned,
                    ..
                } = self.resources.get_mut(&handle).ok_or(Error::StaleHandle)?
                else {
                    return Err(Error::WrongKind);
                };
                if *write_closed {
                    return Err(Error::InvalidState);
                }
                *write_closed = true;
                let socket = socket.clone();
                #[cfg(windows)]
                let write_shutdown_started = write_shutdown_started.clone();
                let write_poisoned = write_poisoned.clone();
                (
                    Some(WorkKey::Upload(handle)),
                    Box::pin(async move {
                        let mut poisoned = write_poisoned.lock_owned().await;
                        if *poisoned {
                            return Err(Error::InvalidState);
                        }
                        *poisoned = true;
                        #[cfg(windows)]
                        write_shutdown_started.store(true, Ordering::SeqCst);
                        let shutdown =
                            SockRef::from(socket.as_ref()).shutdown(std::net::Shutdown::Write);
                        #[cfg(windows)]
                        if shutdown.is_err() {
                            write_shutdown_started.store(false, Ordering::SeqCst);
                        }
                        shutdown.map_err(map_io_error)?;
                        Ok(Completion::Reply(Reply::Done))
                    }),
                )
            }
            Operation::SendDatagrams { handle, datagrams } => {
                let udp = self.udp(handle)?;
                let policy = self.policy.clone();
                (
                    Some(WorkKey::Write(handle)),
                    Box::pin(async move {
                        let mut failures = Vec::new();
                        for (index, datagram) in (0..).zip(datagrams) {
                            if let Err(error) = send_datagram(&udp, &policy, &datagram).await {
                                failures.push(SendFailure { index, error });
                            }
                        }
                        Ok(Completion::Reply(Reply::Sent(failures)))
                    }),
                )
            }
            Operation::ReceiveDatagram(handle) => {
                let udp = self.udp(handle)?;
                let policy = self.policy.clone();
                (
                    Some(WorkKey::Read(handle)),
                    Box::pin(async move {
                        let mut datagrams = Vec::new();
                        let mut budget = MAX_NETWORK_DATAGRAM_BATCH_BYTES;
                        while datagrams.len() < MAX_NETWORK_DATAGRAMS
                            && budget >= MAX_NETWORK_DATAGRAM_BYTES + DATAGRAM_FRAME_OVERHEAD_BYTES
                        {
                            let (bytes, peer) = if datagrams.is_empty() {
                                receive_datagram(&udp).await?
                            } else if let Some(received) = try_receive_datagram(&udp)? {
                                received
                            } else {
                                break;
                            };
                            let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
                            if bytes.len() > MAX_NETWORK_DATAGRAM_BYTES
                                || !accept_datagram_from(&udp, &policy, peer)
                            {
                                tokio::task::yield_now().await;
                                continue;
                            }
                            let datagram = Datagram {
                                peer,
                                bytes: bytes.into_boxed_slice().into_vec(),
                            };
                            budget -= datagram.batch_bytes();
                            datagrams.push(datagram);
                        }
                        Ok(Completion::Reply(Reply::Datagrams(datagrams)))
                    }),
                )
            }
            Operation::Resolve(name) => {
                if name.len() > terra_policy::MAX_NAME_BYTES {
                    return Err(Error::InvalidArgument);
                }
                let policy = self.policy.clone();
                let admission = self.resolvers.clone();
                (
                    None,
                    Box::pin(async move {
                        let addresses = match policy.lookup_name(&name) {
                            NameLookup::Denied => return Err(Error::AccessDenied),
                            NameLookup::Static(addresses) => addresses,
                            NameLookup::Resolve(name) => {
                                let permit = admission
                                    .try_acquire_owned()
                                    .map_err(|_| Error::ResolverBusy)?;
                                let addresses =
                                    resolve_addresses((name.clone(), 0), permit).await?;
                                policy.accept_resolved(&name, &addresses)
                            }
                        };
                        if addresses.is_empty() {
                            return Err(Error::NameUnresolvable);
                        }
                        Ok(Completion::Reply(Reply::Resolved(addresses)))
                    }),
                )
            }
            Operation::Cancel(_) | Operation::Close(_) => return Err(Error::InvalidState),
        };
        Ok((key, future))
    }

    fn tcp(&self, handle: Handle) -> Result<Arc<TcpStream>, Error> {
        match self.resources.get(&handle).ok_or(Error::StaleHandle)? {
            Resource::Tcp { socket, .. } => Ok(socket.clone()),
            Resource::Udp(_) => Err(Error::WrongKind),
        }
    }

    fn udp(&self, handle: Handle) -> Result<UdpResource, Error> {
        match self.resources.get(&handle).ok_or(Error::StaleHandle)? {
            Resource::Udp(udp) => Ok(udp.clone()),
            Resource::Tcp { .. } => Err(Error::WrongKind),
        }
    }
}

async fn resolve_addresses(
    name: impl ToSocketAddrs + Send + 'static,
    permit: OwnedSemaphorePermit,
) -> Result<Vec<IpAddr>, Error> {
    let resolver = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        name.to_socket_addrs().map(|addresses| {
            addresses
                .map(|address| address.ip().to_canonical())
                .filter(|address| has_host_route(*address))
                .take(terra_policy::MAX_RESOLVED_ADDRESSES)
                .collect::<Vec<_>>()
        })
    });
    tokio::time::timeout(Duration::from_secs(2), resolver)
        .await
        .map_err(|_| Error::TimedOut)?
        .map_err(|_| Error::Io)?
        .map_err(|_| Error::NameUnresolvable)
}

/// Guest UDP connect is local, so the guest's address selection cannot probe host routes; answers keep only routable addresses.
fn has_host_route(address: IpAddr) -> bool {
    let local = if address.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    std::net::UdpSocket::bind(local).is_ok_and(|socket| socket.connect((address, 53)).is_ok())
}

async fn send_reply(
    replies: &mpsc::Sender<Response>,
    id: RequestId,
    result: Result<Reply, Error>,
) -> io::Result<()> {
    replies
        .send(Response { id, result })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "broker reply queue closed"))
}

fn create_tcp_socket(peer: SocketAddr, inline_urgent: bool) -> io::Result<TcpSocket> {
    let socket = if peer.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if inline_urgent {
        SockRef::from(&socket).set_out_of_band_inline(true)?;
    }
    socket.set_send_buffer_size(crate::MAX_SOCKET_BUFFER_BYTES)?;
    socket.set_recv_buffer_size(crate::MAX_SOCKET_BUFFER_BYTES)?;
    Ok(socket)
}

fn bind_tcp_listener(address: SocketAddr) -> io::Result<Arc<TcpListener>> {
    let socket = create_tcp_socket(address, false)?;
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(64).map(Arc::new)
}

fn bound_socket_buffers(socket: &SockRef<'_>) -> io::Result<()> {
    socket.set_recv_buffer_size(crate::MAX_SOCKET_BUFFER_BYTES as usize)?;
    socket.set_send_buffer_size(crate::MAX_SOCKET_BUFFER_BYTES as usize)
}

fn bind_udp(local: SocketAddr) -> io::Result<Arc<UdpSocket>> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(local),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if local.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    bound_socket_buffers(&SockRef::from(&socket))?;
    socket.bind(&local.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into()).map(Arc::new)
}

async fn send_datagram(
    udp: &UdpResource,
    policy: &BoxPolicy,
    Datagram { peer, bytes }: &Datagram,
) -> Result<(), Error> {
    if bytes.len() > MAX_NETWORK_DATAGRAM_BYTES {
        return Err(Error::DatagramTooLarge);
    }
    validate_peer(*peer)?;
    let socket = if peer.is_ipv4() { &udp.ipv4 } else { &udp.ipv6 }
        .as_deref()
        .ok_or(Error::Io)?;
    loop {
        if !udp.authorize_send(policy, *peer) {
            return Err(Error::AccessDenied);
        }
        socket.writable().await.map_err(map_io_error)?;
        if !udp.authorize_send(policy, *peer) {
            return Err(Error::AccessDenied);
        }
        match socket.try_send_to(bytes, *peer) {
            Ok(length) if length == bytes.len() => {
                if udp.publication_grant.is_none() {
                    udp.remember_peer(*peer);
                }
                return Ok(());
            }
            Ok(_) => return Err(Error::Io),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(map_io_error(error)),
        }
    }
}

/// Publication sockets learn loopback senders; other sockets accept only recent authorized peers.
fn accept_datagram_from(udp: &UdpResource, policy: &BoxPolicy, peer: SocketAddr) -> bool {
    if udp.publication_grant.is_some() {
        if !peer.ip().is_loopback() {
            return false;
        }
        udp.remember_peer(peer);
        true
    } else {
        udp.knows_peer(peer) && authorize_peer(policy, peer)
    }
}

/// Take one already-queued datagram from either family without waiting.
fn try_receive_datagram(udp: &UdpResource) -> Result<Option<(Vec<u8>, SocketAddr)>, Error> {
    for socket in [udp.ipv4.as_deref(), udp.ipv6.as_deref()]
        .into_iter()
        .flatten()
    {
        let mut bytes = vec![0; MAX_NETWORK_DATAGRAM_BYTES + 1];
        match socket.try_recv_from(&mut bytes) {
            Ok((length, peer)) => {
                bytes.truncate(length);
                return Ok(Some((bytes, peer)));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => match map_datagram_error(error) {
                Error::ConnectionReset | Error::ConnectionRefused | Error::DatagramTooLarge => {}
                error => return Err(error),
            },
        }
    }
    Ok(None)
}

/// Wait for one datagram on either family; ICMP-reported peer errors are not socket failures.
async fn receive_datagram(udp: &UdpResource) -> Result<(Vec<u8>, SocketAddr), Error> {
    async fn receive_one(socket: Option<&UdpSocket>) -> io::Result<(Vec<u8>, SocketAddr)> {
        let Some(socket) = socket else {
            return std::future::pending().await;
        };
        loop {
            socket.readable().await?;
            let mut bytes = vec![0; MAX_NETWORK_DATAGRAM_BYTES + 1];
            match socket.try_recv_from(&mut bytes) {
                Ok((length, peer)) => {
                    bytes.truncate(length);
                    return Ok((bytes, peer));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
    }
    loop {
        let received = tokio::select! {
            received = receive_one(udp.ipv4.as_deref()) => received,
            received = receive_one(udp.ipv6.as_deref()) => received,
        };
        match received {
            Ok(received) => return Ok(received),
            Err(error) => match map_datagram_error(error) {
                Error::ConnectionReset | Error::ConnectionRefused | Error::DatagramTooLarge => {
                    tokio::task::yield_now().await;
                }
                error => return Err(error),
            },
        }
    }
}

fn map_datagram_error(error: io::Error) -> Error {
    #[cfg(windows)]
    if error.raw_os_error() == Some(windows_sys::Win32::Networking::WinSock::WSAEMSGSIZE) {
        return Error::DatagramTooLarge;
    }
    map_io_error(error)
}

fn is_host_loopback(address: IpAddr) -> bool {
    address == IpAddr::V4(Ipv4Addr::LOCALHOST) || address == IpAddr::V6(Ipv6Addr::LOCALHOST)
}

fn validate_peer(address: SocketAddr) -> Result<(), Error> {
    if address.port() == 0
        || address.ip().is_unspecified()
        || address.ip() != address.ip().to_canonical()
        || matches!(address, SocketAddr::V6(address) if address.scope_id() != 0 || address.flowinfo() != 0)
    {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

fn authorize_peer(policy: &BoxPolicy, peer: SocketAddr) -> bool {
    if peer.port() == 53 && policy.blocks_direct_dns() {
        return false;
    }
    is_host_loopback(peer.ip())
        && policy
            .host_service_ports()
            .iter()
            .any(|port| port.is_none_or(|port| port == peer.port()))
        || policy.allows(peer.ip(), Some(peer.port()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send_datagram(handle: Handle, peer: SocketAddr, bytes: Vec<u8>) -> Operation {
        Operation::SendDatagrams {
            handle,
            datagrams: vec![Datagram { peer, bytes }],
        }
    }

    fn datagram_reply(peer: SocketAddr, bytes: Vec<u8>) -> Reply {
        Reply::Datagrams(vec![Datagram { peer, bytes }])
    }

    fn send_failure(error: Error) -> Reply {
        Reply::Sent(vec![SendFailure { index: 0, error }])
    }
    use crate::Client;
    use crate::config::{Limits, PublishedListener};
    use terra_policy::config::{Network, StaticDnsRecord};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn config() -> Config {
        Config {
            policy: Network {
                allow: vec!["HOST_LOOPBACK".into(), "localhost".into()],
                hosts: vec![StaticDnsRecord {
                    name: "static.test".into(),
                    addr: "1.1.1.1".into(),
                }],
                ..Network::default()
            },
            gateways: [
                "100.96.0.1".parse().unwrap(),
                "fd53:4d00::1".parse().unwrap(),
            ],
            listeners: vec![],
            limits: Limits::default(),
        }
    }

    fn start(config: Config) -> (Client, tokio::task::JoinHandle<io::Result<()>>) {
        #[cfg(unix)]
        let (worker, endpoint) = {
            let (worker, endpoint) = std::os::unix::net::UnixStream::pair().unwrap();
            worker.set_nonblocking(true).unwrap();
            endpoint.set_nonblocking(true).unwrap();
            (
                tokio::net::UnixStream::from_std(worker).unwrap(),
                tokio::net::UnixStream::from_std(endpoint).unwrap(),
            )
        };
        #[cfg(not(unix))]
        let (worker, endpoint) = tokio::io::duplex(MAX_NETWORK_FRAME_BYTES * 4);
        let broker = Broker::bind(config).unwrap();
        (Client::new(worker), tokio::spawn(broker.serve(endpoint)))
    }

    async fn open(client: &Client, operation: Operation) -> Handle {
        match client.request(operation).await.unwrap() {
            Reply::Opened { handle, .. } => handle,
            other => panic!("unexpected open reply: {other:?}"),
        }
    }

    #[tokio::test]
    async fn ipv6_publication_conflicts_preserve_required_ipv4_listeners() {
        for transport in [ResourceKind::Tcp, ResourceKind::Udp] {
            let reserved_tcp;
            let reserved_udp;
            let address = match transport {
                ResourceKind::Tcp => {
                    reserved_tcp = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
                    reserved_tcp.local_addr().unwrap()
                }
                ResourceKind::Udp => {
                    reserved_udp = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
                    reserved_udp.local_addr().unwrap()
                }
            };
            let mut setup = config();
            setup.listeners = vec![
                PublishedListener {
                    grant: 1,
                    address: (Ipv4Addr::LOCALHOST, address.port()).into(),
                    transport,
                },
                PublishedListener {
                    grant: 2,
                    address,
                    transport,
                },
            ];
            let mut broker = Broker::bind(setup.clone()).unwrap();
            let operation = match transport {
                ResourceKind::Tcp => {
                    assert!(broker.listeners.contains_key(&1));
                    assert!(!broker.listeners.contains_key(&2));
                    Operation::Accept(2)
                }
                ResourceKind::Udp => {
                    assert!(broker.udp_listeners.contains_key(&1));
                    assert!(!broker.udp_listeners.contains_key(&2));
                    Operation::OpenPublishedUdp(2)
                }
            };
            assert!(matches!(
                broker.prepare(operation),
                Err(Error::AccessDenied)
            ));
            setup.listeners.remove(0);
            assert!(Broker::bind(setup).is_err());
        }
    }

    #[tokio::test]
    async fn static_dns_answers_when_all_non_dns_admission_is_reserved() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client, broker) = start(config());
            let bulk = (0..crate::MAX_NON_DNS_REQUESTS)
                .map(|_| client.try_reserve_write_all().unwrap())
                .collect::<Vec<_>>();
            assert!(matches!(
                client.try_reserve_write_all(),
                Err(Error::LimitExceeded)
            ));
            assert_eq!(
                client.request(Operation::OpenUdp).await,
                Err(Error::LimitExceeded)
            );
            assert_eq!(
                client
                    .request(Operation::Resolve("static.test".into()))
                    .await,
                Ok(Reply::Resolved(vec!["1.1.1.1".parse().unwrap()]))
            );
            assert_eq!(
                client
                    .request(Operation::Resolve("ungranted.test".into()))
                    .await,
                Err(Error::AccessDenied)
            );
            drop(bulk);
            client.disconnect();
            assert!(broker.await.unwrap().is_ok());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn every_guest_udp_flow_can_wait_without_spending_active_or_dns_admission() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (client, broker) = start(config());
            let mut handles = Vec::new();
            let mut pending_receives = Vec::new();
            for _ in 0..terra_protocol::vsock::MAX_NETWORK_SOCKETS {
                let handle = open(&client, Operation::OpenUdp).await;
                handles.push(handle);
                let socket_client = client.clone();
                let mut request = Box::pin(async move {
                    socket_client
                        .request(Operation::ReceiveDatagram(handle))
                        .await
                });
                futures_util::future::poll_fn(|context| {
                    assert!(request.as_mut().poll(context).is_pending());
                    std::task::Poll::Ready(())
                })
                .await;
                pending_receives.push(request);
            }
            let bulk = (0..crate::MAX_NON_DNS_REQUESTS)
                .map(|_| client.try_reserve_write_all().unwrap())
                .collect::<Vec<_>>();
            assert!(matches!(
                client.try_reserve_write_all(),
                Err(Error::LimitExceeded)
            ));
            assert_eq!(
                client
                    .request(Operation::Resolve("static.test".into()))
                    .await,
                Ok(Reply::Resolved(vec!["1.1.1.1".parse().unwrap()]))
            );
            client.close(handles[0]);
            assert_eq!(pending_receives.remove(0).await, Err(Error::Cancelled));
            drop(bulk);
            let replacement = open(&client, Operation::OpenUdp).await;
            assert!(replacement > *handles.last().unwrap());
            let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let handle = *handles.last().unwrap();
            assert_eq!(
                client
                    .request(send_datagram(
                        handle,
                        peer.local_addr().unwrap(),
                        b"ping".to_vec()
                    ))
                    .await,
                Ok(Reply::Sent(vec![]))
            );
            let mut bytes = [0; 4];
            let (length, address) = peer.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..length], b"ping");
            peer.send_to(b"pong", address).await.unwrap();
            assert_eq!(
                pending_receives.pop().unwrap().await,
                Ok(datagram_reply(peer.local_addr().unwrap(), b"pong".to_vec()))
            );
            drop(pending_receives);
            client.disconnect();
            assert!(broker.await.unwrap().is_ok());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_full_reply_queue_backpressures_dispatch_until_the_reader_catches_up() {
        let broker = Broker::bind(config()).unwrap();
        let (replies, mut outgoing) = mpsc::channel(1);
        let requests = stream::iter((1..=3).map(|id| {
            Ok(Some(Request {
                id,
                operation: Operation::Resolve("static.test".into()),
            }))
        }))
        .chain(stream::pending());
        let mut dispatch = Box::pin(broker.dispatch(
            requests,
            replies,
            tokio_util::sync::CancellationToken::new(),
        ));
        futures_util::future::poll_fn(|context| {
            assert!(dispatch.as_mut().poll(context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        for id in 1..=3 {
            assert_eq!(outgoing.recv().await.unwrap().id, id);
            futures_util::future::poll_fn(|context| {
                assert!(dispatch.as_mut().poll(context).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn all_idle_readers_and_published_accepts_leave_capacity_for_writes_dns_and_late_open() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let reservations = (0..crate::MAX_LISTENERS)
                .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
                .collect::<Vec<_>>();
            let mut setup = config();
            setup.policy.allow.push("static.test".into());
            setup.listeners = reservations
                .iter()
                .enumerate()
                .map(|(index, listener)| PublishedListener {
                    grant: u32::try_from(index + 1).unwrap(),
                    address: listener.local_addr().unwrap(),
                    transport: ResourceKind::Tcp,
                })
                .collect();
            drop(reservations);
            let (client, broker) = start(setup);
            let mut handles = Vec::new();
            let mut peers = Vec::new();
            let mut reads: Vec<BoxFuture<'static, Result<Reply, Error>>> = Vec::new();
            for _ in 0..128 {
                let handle = open(
                    &client,
                    Operation::OpenTcp {
                        peer: listener.local_addr().unwrap(),
                        inline_urgent: false,
                    },
                )
                .await;
                handles.push(handle);
                peers.push(listener.accept().await.unwrap().0);
                let reader = client.clone();
                reads.push(Box::pin(async move {
                    reader
                        .request(Operation::Read {
                            handle,
                            max_bytes: u32::try_from(MAX_NETWORK_READ_BYTES).unwrap(),
                        })
                        .await
                }));
            }
            let mut accepts: Vec<BoxFuture<'static, Result<Reply, Error>>> = (1
                ..=crate::MAX_LISTENERS)
                .map(|grant| {
                    let acceptor = client.clone();
                    Box::pin(async move {
                        acceptor
                            .request(Operation::Accept(u32::try_from(grant).unwrap()))
                            .await
                    }) as BoxFuture<'static, Result<Reply, Error>>
                })
                .collect();
            futures_util::future::poll_fn(|context| {
                for pending in reads.iter_mut().chain(accepts.iter_mut()) {
                    assert!(pending.as_mut().poll(context).is_pending());
                }
                std::task::Poll::Ready(())
            })
            .await;
            assert_eq!(
                client
                    .request(Operation::Resolve("static.test".into()))
                    .await,
                Ok(Reply::Resolved(vec!["1.1.1.1".parse().unwrap()]))
            );
            #[cfg(target_os = "linux")]
            if std::env::var_os("TERRA_NETWORK_STALLED_MEMORY").is_some() {
                let status = std::fs::read_to_string("/proc/self/status").unwrap();
                for line in status
                    .lines()
                    .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
                {
                    eprintln!("STALLED_NATIVE_READERS=128 PUBLISHED_ACCEPTS=64 {line}");
                }
            }
            let last = *handles.last().unwrap();
            assert_eq!(
                client
                    .request(Operation::WriteAll {
                        handle: last,
                        bytes: vec![7; MAX_NETWORK_CHUNK_BYTES]
                    })
                    .await,
                Ok(Reply::Written(
                    u32::try_from(MAX_NETWORK_CHUNK_BYTES).unwrap()
                ))
            );
            let mut uploaded = vec![0; MAX_NETWORK_CHUNK_BYTES];
            peers
                .last_mut()
                .unwrap()
                .read_exact(&mut uploaded)
                .await
                .unwrap();
            assert_eq!(uploaded, vec![7; MAX_NETWORK_CHUNK_BYTES]);
            let expected = (0..MAX_NETWORK_READ_BYTES)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect::<Vec<_>>();
            peers
                .last_mut()
                .unwrap()
                .write_all(&expected)
                .await
                .unwrap();
            let Reply::Data(mut downloaded) = reads.pop().unwrap().await.unwrap() else {
                panic!("expected read body");
            };
            while downloaded.len() < expected.len() {
                let Reply::Data(bytes) = client
                    .request(Operation::Read {
                        handle: last,
                        max_bytes: u32::try_from(MAX_NETWORK_READ_BYTES).unwrap(),
                    })
                    .await
                    .unwrap()
                else {
                    panic!("expected read suffix");
                };
                assert!(bytes.len() <= MAX_NETWORK_READ_BYTES);
                downloaded.extend(bytes);
            }
            assert_eq!(downloaded, expected);
            let first = handles.remove(0);
            assert_eq!(
                client.request(Operation::Close(first)).await,
                Ok(Reply::Done)
            );
            assert_eq!(reads.remove(0).await, Err(Error::Cancelled));
            let replacement = open(
                &client,
                Operation::OpenTcp {
                    peer: listener.local_addr().unwrap(),
                    inline_urgent: false,
                },
            )
            .await;
            let (mut replacement_peer, _) = listener.accept().await.unwrap();
            assert_eq!(
                client
                    .request(Operation::WriteAll {
                        handle: replacement,
                        bytes: b"late".to_vec()
                    })
                    .await,
                Ok(Reply::Written(4))
            );
            let mut bytes = [0; 4];
            replacement_peer.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"late");
            drop(reads);
            drop(accepts);
            for handle in handles.into_iter().chain([replacement]) {
                assert_eq!(
                    client.request(Operation::Close(handle)).await,
                    Ok(Reply::Done)
                );
            }
            client.disconnect();
            assert!(broker.await.unwrap().is_ok());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn requested_inline_urgent_data_stays_in_the_tcp_byte_stream() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (client, broker) = start(config());
            let handle = open(
                &client,
                Operation::OpenTcp {
                    peer: listener.local_addr().unwrap(),
                    inline_urgent: true,
                },
            )
            .await;
            let (mut peer, _) = listener.accept().await.unwrap();
            peer.write_all(b"before").await.unwrap();
            assert_eq!(SockRef::from(&peer).send_out_of_band(b"!").unwrap(), 1);
            peer.write_all(b"after").await.unwrap();
            peer.shutdown().await.unwrap();
            let mut received = Vec::new();
            loop {
                match client
                    .request(Operation::Read {
                        handle,
                        max_bytes: 64,
                    })
                    .await
                    .unwrap()
                {
                    Reply::Data(bytes) => received.extend(bytes),
                    Reply::Eof => break,
                    reply => panic!("unexpected TCP reply: {reply:?}"),
                }
            }
            assert_eq!(received, b"before!after");
            client.request(Operation::Close(handle)).await.unwrap();
            client.disconnect();
            broker.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn fragmented_requests_survive_socket_completions_and_cancellation() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let external = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let (channel, peer) = tokio::io::duplex(1);
            let (mut read, mut write) = tokio::io::split(peer);
            let broker = tokio::spawn(Broker::bind(config()).unwrap().serve(channel));
            let handle = match exchange(&mut read, &mut write, 1, Operation::OpenUdp).await {
                Reply::Opened { handle, .. } => handle,
                other => panic!("unexpected open reply: {other:?}"),
            };
            assert_eq!(
                exchange(
                    &mut read,
                    &mut write,
                    2,
                    send_datagram(handle, external.local_addr().unwrap(), b"peer".to_vec()),
                )
                .await,
                Reply::Sent(vec![])
            );
            let mut bytes = [0; 8];
            let (_, address) = external.recv_from(&mut bytes).await.unwrap();
            for (id, fragmented_header) in [(3, true), (5, false)] {
                terra_protocol::write_frame_async(
                    &mut write,
                    &Request {
                        id,
                        operation: Operation::ReceiveDatagram(handle),
                    },
                )
                .await
                .unwrap();
                let cancel = Request {
                    id: id + 1,
                    operation: Operation::Cancel(id),
                };
                let frame = terra_protocol::encode_frame(&cancel).unwrap();
                let split = if fragmented_header {
                    2
                } else {
                    frame.len() - 1
                };
                write.write_all(&frame[..split]).await.unwrap();
                external.send_to(b"complete", address).await.unwrap();
                assert_eq!(
                    terra_protocol::read_frame_async::<Response>(&mut read)
                        .await
                        .unwrap()
                        .unwrap(),
                    Response {
                        id,
                        result: Ok(datagram_reply(
                            external.local_addr().unwrap(),
                            b"complete".to_vec()
                        )),
                    }
                );
                write.write_all(&frame[split..]).await.unwrap();
                assert_eq!(
                    terra_protocol::read_frame_async::<Response>(&mut read)
                        .await
                        .unwrap()
                        .unwrap(),
                    Response {
                        id: cancel.id,
                        result: Ok(Reply::Cancelled(false)),
                    }
                );
            }
            assert_eq!(
                exchange(&mut read, &mut write, 7, Operation::Close(handle)).await,
                Reply::Done
            );
            drop((read, write));
            broker.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    async fn exchange(
        read: &mut (impl AsyncRead + Unpin),
        write: &mut (impl AsyncWrite + Unpin),
        id: RequestId,
        operation: Operation,
    ) -> Reply {
        terra_protocol::write_frame_async(write, &Request { id, operation })
            .await
            .unwrap();
        let response = terra_protocol::read_frame_async::<Response>(read)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.id, id);
        response.result.unwrap()
    }

    async fn blocked_tcp() -> (Broker, TcpStream, Arc<Mutex<bool>>, Arc<Semaphore>) {
        let listener = TcpSocket::new_v4().unwrap();
        listener.set_recv_buffer_size(1024).unwrap();
        listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = listener.listen(1).unwrap();
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_send_buffer_size(1024).unwrap();
        let socket = socket
            .connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        socket.set_nodelay(true).unwrap();
        let (external, _) = listener.accept().await.unwrap();
        let poisoned = Arc::new(Mutex::new(false));
        let slots = Arc::new(Semaphore::new(crate::MAX_TCP_WRITE_REQUESTS));
        let mut broker = Broker::bind(config()).unwrap();
        broker.resources.insert(
            1,
            Resource::Tcp {
                peer: socket.peer_addr().unwrap(),
                socket: Arc::new(socket),
                write_closed: false,
                #[cfg(windows)]
                write_shutdown_started: Arc::new(AtomicBool::new(false)),
                write_poisoned: poisoned.clone(),
                write_slots: slots.clone(),
            },
        );
        broker.next_handle = 2;
        (broker, external, poisoned, slots)
    }

    async fn send_request(
        channel: &mut (impl AsyncWrite + Unpin),
        id: RequestId,
        operation: Operation,
    ) {
        terra_protocol::write_frame_async(channel, &Request { id, operation })
            .await
            .unwrap();
    }

    async fn read_response(channel: &mut (impl AsyncRead + Unpin)) -> Response {
        terra_protocol::read_frame_async(channel)
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn upload_global_limit_applies_before_dispatch() {
        let (mut broker, external, poisoned, slots) = blocked_tcp().await;
        broker.limits.pending_requests = 1;
        let guard = poisoned.clone().lock_owned().await;
        let (mut peer, channel) = tokio::io::duplex(MAX_NETWORK_FRAME_BYTES * 4);
        let broker = tokio::spawn(broker.serve(channel));
        for (id, byte) in [(1, 1), (2, 2)] {
            send_request(
                &mut peer,
                id,
                Operation::WriteAll {
                    handle: 1,
                    bytes: vec![byte],
                },
            )
            .await;
        }
        assert_eq!(
            read_response(&mut peer).await,
            Response {
                id: 2,
                result: Err(Error::LimitExceeded)
            }
        );
        assert_eq!(slots.available_permits(), crate::MAX_TCP_WRITE_REQUESTS - 1);
        drop(peer);
        broker.await.unwrap().unwrap();
        assert_eq!(slots.available_permits(), crate::MAX_TCP_WRITE_REQUESTS);
        assert!(!*guard);
        drop((guard, external));
    }

    /// Shutdown admission commits the ordered FIN; cancellation reports false and leaves the FIN queued.
    #[tokio::test]
    async fn cancelling_admitted_shutdown_preserves_fin_after_uploads() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (broker, mut external, poisoned, slots) = blocked_tcp().await;
            let guard = poisoned.clone().lock_owned().await;
            let (mut peer, channel) = tokio::io::duplex(MAX_NETWORK_FRAME_BYTES * 4);
            let broker = tokio::spawn(broker.serve(channel));
            send_request(
                &mut peer,
                1,
                Operation::WriteAll {
                    handle: 1,
                    bytes: b"before fin".to_vec(),
                },
            )
            .await;
            send_request(&mut peer, 2, Operation::ShutdownWrite(1)).await;
            send_request(&mut peer, 3, Operation::Cancel(2)).await;
            assert_eq!(
                read_response(&mut peer).await,
                Response {
                    id: 3,
                    result: Ok(Reply::Cancelled(false))
                }
            );
            send_request(
                &mut peer,
                4,
                Operation::WriteAll {
                    handle: 1,
                    bytes: vec![4],
                },
            )
            .await;
            assert_eq!(
                read_response(&mut peer).await,
                Response {
                    id: 4,
                    result: Err(Error::InvalidState)
                }
            );
            drop(guard);
            let mut bytes = Vec::new();
            external.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"before fin");
            let mut replies = [
                read_response(&mut peer).await,
                read_response(&mut peer).await,
            ];
            replies.sort_by_key(|reply| reply.id);
            assert_eq!(
                replies,
                [
                    Response {
                        id: 1,
                        result: Ok(Reply::Written(10))
                    },
                    Response {
                        id: 2,
                        result: Ok(Reply::Done)
                    }
                ]
            );
            assert_eq!(slots.available_permits(), crate::MAX_TCP_WRITE_REQUESTS);
            drop(peer);
            broker.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn uploads_write_whole_chunks_in_fifo_order_before_half_close() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut broker, mut external, poisoned, slots) = blocked_tcp().await;
            let guard = poisoned.lock_owned().await;
            let mut writes = Vec::new();
            let mut expected = Vec::new();
            for index in 1..=crate::MAX_TCP_WRITE_REQUESTS {
                let bytes = vec![u8::try_from(index).unwrap(); MAX_NETWORK_CHUNK_BYTES];
                expected.extend_from_slice(&bytes);
                let (_, mut write) = broker.prepare(Operation::WriteAll { handle: 1, bytes }).unwrap();
                assert!(write.as_mut().now_or_never().is_none());
                writes.push(write);
            }
            assert_eq!(slots.available_permits(), 0);
            assert!(matches!(broker.prepare(Operation::WriteAll { handle: 1, bytes: vec![3] }), Err(Error::Busy)));
            let (_, mut shutdown) = broker.prepare(Operation::ShutdownWrite(1)).unwrap();
            assert!(shutdown.as_mut().now_or_never().is_none());
            assert!(matches!(broker.prepare(Operation::WriteAll { handle: 1, bytes: vec![3] }), Err(Error::InvalidState)));
            assert!(matches!(broker.prepare(Operation::WriteAll { handle: 1, bytes: vec![3] }), Err(Error::InvalidState)));
            drop(guard);
            let reader = async {
                let mut bytes = Vec::new();
                external.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, expected);
                external.write_all(b"reply").await.unwrap();
            };
            let writes = futures_util::future::join_all(writes.into_iter().rev());
            let (writes, shutdown, ()) = tokio::join!(writes, shutdown, reader);
            for completion in writes {
                assert!(matches!(completion, Ok(Completion::Reply(Reply::Written(length))) if length as usize == MAX_NETWORK_CHUNK_BYTES));
            }
            assert!(matches!(shutdown, Ok(Completion::Reply(Reply::Done))));
            assert_eq!(slots.available_permits(), crate::MAX_TCP_WRITE_REQUESTS);
            let (_, read) = broker.prepare(Operation::Read { handle: 1, max_bytes: 5 }).unwrap();
            assert!(matches!(read.await, Ok(Completion::Reply(Reply::Data(bytes))) if bytes == b"reply"));
        }).await.unwrap();
    }

    #[tokio::test]
    async fn cancelling_queued_upload_releases_only_its_slot() {
        let (mut broker, mut external, poisoned, slots) = blocked_tcp().await;
        let guard = poisoned.clone().lock_owned().await;
        let (_, mut cancelled) = broker
            .prepare(Operation::WriteAll {
                handle: 1,
                bytes: vec![1],
            })
            .unwrap();
        assert!(cancelled.as_mut().now_or_never().is_none());
        let mut accepted = Vec::new();
        for _ in 1..crate::MAX_TCP_WRITE_REQUESTS {
            let (_, mut write) = broker
                .prepare(Operation::WriteAll {
                    handle: 1,
                    bytes: b"ok".to_vec(),
                })
                .unwrap();
            assert!(write.as_mut().now_or_never().is_none());
            accepted.push(write);
        }
        assert_eq!(slots.available_permits(), 0);
        drop(cancelled);
        assert_eq!(slots.available_permits(), 1);
        assert!(!*guard);
        drop(guard);
        for completion in futures_util::future::join_all(accepted).await {
            assert!(matches!(
                completion,
                Ok(Completion::Reply(Reply::Written(2)))
            ));
        }
        let expected = b"ok".repeat(crate::MAX_TCP_WRITE_REQUESTS - 1);
        let mut bytes = vec![0; expected.len()];
        external.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, expected);
        assert!(!*poisoned.lock().await);
        assert_eq!(slots.available_permits(), crate::MAX_TCP_WRITE_REQUESTS);
    }

    /// Stage a partial write explicitly because a host TCP buffer can hold an entire chunk.
    #[tokio::test]
    async fn cancelled_partial_write_poisons_queued_chunks() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut broker, mut external, poisoned, slots) = blocked_tcp().await;
            let socket = broker.tcp(1).unwrap();
            #[cfg(windows)]
            let write_shutdown_started = Arc::new(AtomicBool::new(false));
            let active = ActiveTcpWrite {
                socket: socket.clone(),
                poisoned: poisoned.clone().lock_owned().await,
                incomplete_prefix: true,
                #[cfg(windows)]
                write_shutdown_started: write_shutdown_started.clone(),
            };
            socket.writable().await.unwrap();
            assert_eq!(socket.try_write(&[1]).unwrap(), 1);
            let mut prefix = [0];
            external.read_exact(&mut prefix).await.unwrap();
            assert_eq!(prefix, [1]);
            let mut queued = Vec::new();
            for _ in 0..crate::MAX_TCP_WRITE_REQUESTS {
                let (_, mut write) = broker
                    .prepare(Operation::WriteAll {
                        handle: 1,
                        bytes: vec![2; MAX_NETWORK_CHUNK_BYTES],
                    })
                    .unwrap();
                assert!(write.as_mut().now_or_never().is_none());
                queued.push(write);
            }
            drop(active);
            #[cfg(windows)]
            assert!(write_shutdown_started.load(Ordering::SeqCst));
            let mut remaining = Vec::new();
            external.read_to_end(&mut remaining).await.unwrap();
            assert!(remaining.is_empty());
            for completion in futures_util::future::join_all(queued).await {
                assert!(matches!(completion, Err(Error::InvalidState)));
            }
            assert!(*poisoned.lock().await);
            assert_eq!(slots.available_permits(), crate::MAX_TCP_WRITE_REQUESTS);
            let (_, rejected) = broker
                .prepare(Operation::WriteAll {
                    handle: 1,
                    bytes: vec![3],
                })
                .unwrap();
            assert!(matches!(rejected.await, Err(Error::InvalidState)));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn failed_upload_poisons_queued_chunks() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut broker, external, poisoned, slots) = blocked_tcp().await;
            let socket = broker.tcp(1).unwrap();
            let guard = poisoned.clone().lock_owned().await;
            let (_, mut active) = broker
                .prepare(Operation::WriteAll {
                    handle: 1,
                    bytes: vec![1; MAX_NETWORK_CHUNK_BYTES],
                })
                .unwrap();
            assert!(active.as_mut().now_or_never().is_none());
            let mut queued = Vec::new();
            for _ in 1..crate::MAX_TCP_WRITE_REQUESTS {
                let (_, mut write) = broker
                    .prepare(Operation::WriteAll {
                        handle: 1,
                        bytes: vec![2; MAX_NETWORK_CHUNK_BYTES],
                    })
                    .unwrap();
                assert!(write.as_mut().now_or_never().is_none());
                queued.push(write);
            }
            SockRef::from(&external)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
            drop(external);
            socket.readable().await.unwrap();
            drop(guard);
            assert!(active.await.is_err());
            for completion in futures_util::future::join_all(queued).await {
                assert!(matches!(completion, Err(Error::InvalidState)));
            }
            assert!(*poisoned.lock().await);
            assert_eq!(slots.available_permits(), crate::MAX_TCP_WRITE_REQUESTS);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn untrusted_upload_flood_close_and_disconnect_release_admission() {
        for closes_handle in [false, true] {
            let (broker, mut external, poisoned, slots) = blocked_tcp().await;
            let guard = poisoned.clone().lock_owned().await;
            let (mut peer, channel) = tokio::io::duplex(MAX_NETWORK_FRAME_BYTES * 4);
            let broker = tokio::spawn(broker.serve(channel));
            let admitted = u64::try_from(crate::MAX_TCP_WRITE_REQUESTS).unwrap();
            let rejected = admitted + 1;
            for id in 1..=rejected {
                send_request(
                    &mut peer,
                    id,
                    Operation::WriteAll {
                        handle: 1,
                        bytes: vec![u8::try_from(id).unwrap(); MAX_NETWORK_CHUNK_BYTES],
                    },
                )
                .await;
            }
            assert_eq!(
                read_response(&mut peer).await,
                Response {
                    id: rejected,
                    result: Err(Error::Busy)
                }
            );
            assert_eq!(slots.available_permits(), 0);
            if closes_handle {
                let close = rejected + 1;
                send_request(&mut peer, close, Operation::Close(1)).await;
                let mut expected = (1..=admitted)
                    .map(|id| Response {
                        id,
                        result: Err(Error::Cancelled),
                    })
                    .collect::<Vec<_>>();
                expected.push(Response {
                    id: close,
                    result: Ok(Reply::Done),
                });
                let mut replies = Vec::new();
                for _ in 0..expected.len() {
                    replies.push(read_response(&mut peer).await);
                }
                replies.sort_by_key(|reply| reply.id);
                assert_eq!(replies, expected);
                let stale = close + 1;
                send_request(
                    &mut peer,
                    stale,
                    Operation::WriteAll {
                        handle: 1,
                        bytes: vec![6],
                    },
                )
                .await;
                assert_eq!(
                    read_response(&mut peer).await,
                    Response {
                        id: stale,
                        result: Err(Error::StaleHandle)
                    }
                );
            }
            drop(peer);
            tokio::time::timeout(Duration::from_secs(1), broker)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(slots.available_permits(), crate::MAX_TCP_WRITE_REQUESTS);
            assert!(!*guard);
            drop(guard);
            let mut bytes = [0; 1];
            assert_eq!(external.read(&mut bytes).await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn resolver_admission_survives_request_cancellation_and_timeout() {
        struct BlockingLookup {
            entered: Arc<tokio::sync::Notify>,
            release: std::sync::mpsc::Receiver<()>,
        }

        impl ToSocketAddrs for BlockingLookup {
            type Iter = std::vec::IntoIter<SocketAddr>;

            fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
                self.entered.notify_one();
                self.release.recv().map_err(io::Error::other)?;
                Ok(vec!["1.1.1.1:0".parse().unwrap()].into_iter())
            }
        }

        for is_cancelled in [true, false] {
            let admission = Arc::new(Semaphore::new(1));
            let entered = Arc::new(tokio::sync::Notify::new());
            let (release, waiting) = std::sync::mpsc::channel();
            let resolver = tokio::spawn(resolve_addresses(
                BlockingLookup {
                    entered: entered.clone(),
                    release: waiting,
                },
                admission.clone().try_acquire_owned().unwrap(),
            ));
            entered.notified().await;
            if is_cancelled {
                resolver.abort();
                assert!(resolver.await.unwrap_err().is_cancelled());
            } else {
                assert_eq!(resolver.await.unwrap(), Err(Error::TimedOut));
            }
            assert_eq!(admission.available_permits(), 0);
            assert!(admission.try_acquire().is_err());
            release.send(()).unwrap();
            let permit = tokio::time::timeout(Duration::from_secs(1), admission.acquire())
                .await
                .unwrap()
                .unwrap();
            drop(permit);
            assert_eq!(admission.available_permits(), 1);
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn tcp_half_close_stalled_reads_cancellation_and_stale_handles() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, broker) = start(config());
        let first = open(
            &client,
            Operation::OpenTcp {
                peer: listener.local_addr().unwrap(),
                inline_urgent: false,
            },
        )
        .await;
        let (mut external, _) = listener.accept().await.unwrap();
        let mut blocked = Box::pin(client.request(Operation::Read {
            handle: first,
            max_bytes: 8,
        }));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut blocked)
                .await
                .is_err()
        );
        assert_eq!(
            client
                .request(Operation::Read {
                    handle: first,
                    max_bytes: 8
                })
                .await,
            Err(Error::Busy)
        );
        assert_eq!(
            client
                .request(Operation::WriteAll {
                    handle: first,
                    bytes: b"one".to_vec()
                })
                .await,
            Ok(Reply::Written(3))
        );
        let mut bytes = [0; 3];
        external.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"one");
        let second = open(
            &client,
            Operation::OpenTcp {
                peer: listener.local_addr().unwrap(),
                inline_urgent: false,
            },
        )
        .await;
        let (mut other, _) = listener.accept().await.unwrap();
        assert!(second > first);
        other.write_all(b"two").await.unwrap();
        assert_eq!(
            client
                .request(Operation::Read {
                    handle: second,
                    max_bytes: 8
                })
                .await,
            Ok(Reply::Data(b"two".to_vec()))
        );
        drop(blocked);
        external.write_all(b"in").await.unwrap();
        assert_eq!(
            client.request(Operation::ShutdownWrite(first)).await,
            Ok(Reply::Done)
        );
        assert_eq!(external.read(&mut bytes).await.unwrap(), 0);
        assert_eq!(
            client
                .request(Operation::WriteAll {
                    handle: first,
                    bytes: vec![1]
                })
                .await,
            Err(Error::InvalidState)
        );
        external.shutdown().await.unwrap();
        let result = client
            .request(Operation::Read {
                handle: first,
                max_bytes: 8,
            })
            .await
            .unwrap();
        assert!(result == Reply::Data(b"in".to_vec()) || result == Reply::Eof);
        if result != Reply::Eof {
            assert_eq!(
                client
                    .request(Operation::Read {
                        handle: first,
                        max_bytes: 8
                    })
                    .await,
                Ok(Reply::Eof)
            );
        }
        assert_eq!(
            client.request(Operation::Close(first)).await,
            Ok(Reply::Done)
        );
        assert_eq!(
            client
                .request(Operation::Read {
                    handle: first,
                    max_bytes: 8
                })
                .await,
            Err(Error::StaleHandle)
        );
        drop(client);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), broker)
                .await
                .unwrap()
                .unwrap()
                .is_ok()
        );
        assert_eq!(other.read(&mut bytes).await.unwrap(), 0);
    }

    /// An unread payload makes a reset after FIN observable to the error waiter on every host OS.
    #[tokio::test]
    async fn tcp_error_wait_observes_reset_after_fin() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let address = listener.local_addr().unwrap();
            let (client, broker) = start(config());
            let handle = open(
                &client,
                Operation::OpenTcp {
                    peer: address,
                    inline_urgent: false,
                },
            )
            .await;
            let (mut remote, _) = listener.accept().await.unwrap();
            remote.shutdown().await.unwrap();
            assert_eq!(
                client
                    .request(Operation::Read {
                        handle,
                        max_bytes: 8
                    })
                    .await,
                Ok(Reply::Eof)
            );
            let mut monitor = tokio::spawn({
                let client = client.clone();
                async move { client.request(Operation::WaitError(handle)).await }
            });
            assert!(
                tokio::time::timeout(Duration::from_millis(20), &mut monitor)
                    .await
                    .is_err()
            );
            assert_eq!(
                client
                    .request(Operation::WriteAll {
                        handle,
                        bytes: b"RX".to_vec(),
                    })
                    .await,
                Ok(Reply::Written(2))
            );
            let mut received = [0];
            remote.read_exact(&mut received).await.unwrap();
            assert_eq!(received, [b'R']);
            remote.peek(&mut received).await.unwrap();
            assert_eq!(received, [b'X']);
            SockRef::from(&remote)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
            drop(remote);
            assert_eq!(monitor.await.unwrap(), Err(Error::ConnectionReset));
            assert_eq!(
                client.request(Operation::Close(handle)).await,
                Ok(Reply::Done)
            );
            drop(client);
            broker.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    /// An orderly pair of FINs leaves the error waiter pending until Close cancels it.
    #[tokio::test]
    async fn tcp_error_wait_ignores_orderly_close_and_releases_on_handle_close() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let address = listener.local_addr().unwrap();
            let (client, broker) = start(config());
            let handle = open(
                &client,
                Operation::OpenTcp {
                    peer: address,
                    inline_urgent: false,
                },
            )
            .await;
            let (mut remote, _) = listener.accept().await.unwrap();
            remote.shutdown().await.unwrap();
            assert_eq!(
                client
                    .request(Operation::Read {
                        handle,
                        max_bytes: 8
                    })
                    .await,
                Ok(Reply::Eof)
            );
            let mut monitor = tokio::spawn({
                let client = client.clone();
                async move { client.request(Operation::WaitError(handle)).await }
            });
            assert!(
                tokio::time::timeout(Duration::from_millis(20), &mut monitor)
                    .await
                    .is_err()
            );
            assert_eq!(
                client.request(Operation::ShutdownWrite(handle)).await,
                Ok(Reply::Done)
            );
            let mut received = [0];
            assert_eq!(remote.read(&mut received).await.unwrap(), 0);
            assert!(
                tokio::time::timeout(Duration::from_millis(150), &mut monitor)
                    .await
                    .is_err()
            );
            assert_eq!(
                client.request(Operation::Close(handle)).await,
                Ok(Reply::Done)
            );
            assert_eq!(monitor.await.unwrap(), Err(Error::Cancelled));
            assert_eq!(
                client.request(Operation::WaitError(handle)).await,
                Err(Error::StaleHandle)
            );
            drop(client);
            broker.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn udp_peer_filter_refreshes_recent_peers_and_expires_them() {
        tokio::time::pause();
        let udp = UdpResource {
            ipv4: None,
            ipv6: None,
            peers: Arc::default(),
            publication_grant: Some(1),
        };
        let policy = BoxPolicy::new(&config().policy, config().gateways).unwrap();
        let first = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
        let second = SocketAddr::from((Ipv4Addr::LOCALHOST, 2));
        let nearly_expired = UDP_PEER_TTL.checked_sub(Duration::from_secs(1)).unwrap();
        assert!(!udp.authorize_send(&policy, first));
        for port in 1..=u16::try_from(crate::MAX_UDP_PEERS).unwrap() {
            udp.remember_peer(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        }
        tokio::time::advance(nearly_expired).await;
        assert!(udp.knows_peer(first));
        assert!(udp.authorize_send(&policy, first));
        udp.remember_peer(first);
        let newest = SocketAddr::from((Ipv4Addr::LOCALHOST, 100));
        udp.remember_peer(newest);
        assert!(udp.knows_peer(first));
        assert!(!udp.knows_peer(second));
        assert_eq!(udp.peers.lock().unwrap().len(), crate::MAX_UDP_PEERS);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(udp.knows_peer(first));
        assert!(udp.knows_peer(newest));
        assert_eq!(udp.peers.lock().unwrap().len(), 2);
        tokio::time::advance(nearly_expired).await;
        assert!(!udp.knows_peer(first));
        assert!(!udp.authorize_send(&policy, first));
        assert!(!udp.knows_peer(newest));
        assert!(udp.peers.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn udp_send_rechecks_peer_expiry_after_waiting_for_socket_readiness() {
        let peer_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer = peer_socket.local_addr().unwrap();
        let mut broker = Broker::bind(config()).unwrap();
        let udp = UdpResource {
            ipv4: Some(bind_udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap()),
            ipv6: None,
            peers: Arc::default(),
            publication_grant: Some(1),
        };
        tokio::time::pause();
        udp.remember_peer(peer);
        broker.resources.insert(1, Resource::Udp(udp));
        let (_, mut send) = broker.prepare(send_datagram(1, peer, vec![1])).unwrap();
        assert!(send.as_mut().now_or_never().is_none());
        tokio::time::advance(UDP_PEER_TTL).await;
        assert!(
            matches!(send.await, Ok(Completion::Reply(reply)) if reply == send_failure(Error::AccessDenied))
        );
        assert_eq!(
            peer_socket.try_recv(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn udp_publication_replies_do_not_extend_peer_expiry() {
        let peer_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer = peer_socket.local_addr().unwrap();
        let mut broker = Broker::bind(config()).unwrap();
        let udp = UdpResource {
            ipv4: Some(bind_udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap()),
            ipv6: None,
            peers: Arc::default(),
            publication_grant: Some(1),
        };
        tokio::time::pause();
        udp.remember_peer(peer);
        broker.resources.insert(1, Resource::Udp(udp));
        tokio::time::advance(UDP_PEER_TTL.checked_sub(Duration::from_secs(1)).unwrap()).await;
        let reply = send_datagram(1, peer, vec![1]);
        let (_, send) = broker.prepare(reply.clone()).unwrap();
        assert!(
            matches!(send.await, Ok(Completion::Reply(Reply::Sent(failures))) if failures.is_empty())
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        let (_, send) = broker.prepare(reply).unwrap();
        assert!(
            matches!(send.await, Ok(Completion::Reply(reply)) if reply == send_failure(Error::AccessDenied))
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn udp_publication_grants_one_owner_and_only_received_peers() {
        tokio::time::timeout(Duration::from_secs(5), async {
            for address in [
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
            ] {
                let reserved = std::net::UdpSocket::bind(address).unwrap();
                let published_address = reserved.local_addr().unwrap();
                drop(reserved);
                let reserved_tcp = std::net::TcpListener::bind(address).unwrap();
                let tcp_address = reserved_tcp.local_addr().unwrap();
                drop(reserved_tcp);
                let mut setup = config();
                setup.policy.allow.clear();
                setup.listeners = vec![
                    PublishedListener {
                        grant: 1,
                        address: published_address,
                        transport: ResourceKind::Udp,
                    },
                    PublishedListener {
                        grant: 2,
                        address: tcp_address,
                        transport: ResourceKind::Tcp,
                    },
                ];
                let (client, broker) = start(setup);
                for grant in [0, 2, 3] {
                    assert_eq!(
                        client.request(Operation::OpenPublishedUdp(grant)).await,
                        Err(Error::AccessDenied)
                    );
                }
                assert_eq!(
                    client.request(Operation::Accept(1)).await,
                    Err(Error::AccessDenied)
                );
                let (first, second) = tokio::join!(
                    client.request(Operation::OpenPublishedUdp(1)),
                    client.request(Operation::OpenPublishedUdp(1))
                );
                let handle = match (first, second) {
                    (
                        Ok(Reply::Opened {
                            handle,
                            kind: ResourceKind::Udp,
                            ..
                        }),
                        Err(Error::Busy),
                    )
                    | (
                        Err(Error::Busy),
                        Ok(Reply::Opened {
                            handle,
                            kind: ResourceKind::Udp,
                            ..
                        }),
                    ) => handle,
                    other => panic!("duplicate UDP publication opens: {other:?}"),
                };
                let peer = UdpSocket::bind(address).await.unwrap();
                let peer_address = peer.local_addr().unwrap();
                let stranger = UdpSocket::bind(address).await.unwrap();
                stranger
                    .send_to(&vec![0; MAX_NETWORK_DATAGRAM_BYTES + 2], published_address)
                    .await
                    .unwrap();
                assert_eq!(
                    client
                        .request(send_datagram(handle, peer_address, b"unsolicited".to_vec()))
                        .await,
                    Ok(send_failure(Error::AccessDenied))
                );
                for bytes in [Vec::new(), vec![0x37; MAX_NETWORK_DATAGRAM_BYTES]] {
                    peer.send_to(&bytes, published_address).await.unwrap();
                    assert_eq!(
                        client.request(Operation::ReceiveDatagram(handle)).await,
                        Ok(datagram_reply(peer_address, bytes.clone()))
                    );
                    assert_eq!(
                        client
                            .request(send_datagram(handle, peer_address, bytes.clone()))
                            .await,
                        Ok(Reply::Sent(vec![]))
                    );
                    let mut response = vec![0; MAX_NETWORK_DATAGRAM_BYTES + 1];
                    let (length, sender) = peer.recv_from(&mut response).await.unwrap();
                    assert_eq!(sender, published_address);
                    assert_eq!(&response[..length], &bytes);
                }
                assert_eq!(
                    client
                        .request(send_datagram(
                            handle,
                            stranger.local_addr().unwrap(),
                            vec![1]
                        ))
                        .await,
                    Ok(send_failure(Error::AccessDenied))
                );
                assert_eq!(
                    client.request(Operation::Close(handle)).await,
                    Ok(Reply::Done)
                );
                let replacement = open(&client, Operation::OpenPublishedUdp(1)).await;
                assert!(replacement > handle);
                assert_eq!(
                    client
                        .request(send_datagram(replacement, peer_address, vec![1]))
                        .await,
                    Ok(send_failure(Error::AccessDenied))
                );
                assert_eq!(
                    client.request(Operation::ReceiveDatagram(handle)).await,
                    Err(Error::StaleHandle)
                );
                drop(client);
                broker.await.unwrap().unwrap();
                assert!(std::net::UdpSocket::bind(published_address).is_ok());
            }
        })
        .await
        .unwrap();
    }

    /// Queued datagrams arrive in ordered batches, and a denied datagram fails alone by index.
    #[tokio::test]
    async fn udp_batches_preserve_order_and_report_failures_by_index() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let (client, broker) = start(config());
        let handle = open(&client, Operation::OpenUdp).await;
        let datagrams = [address, "192.0.2.1:9".parse().unwrap(), address]
            .into_iter()
            .zip(0..)
            .map(|(peer, index)| Datagram {
                peer,
                bytes: vec![index],
            })
            .collect();
        assert_eq!(
            client
                .request(Operation::SendDatagrams { handle, datagrams })
                .await,
            Ok(Reply::Sent(vec![SendFailure {
                index: 1,
                error: Error::AccessDenied
            }]))
        );
        let mut bytes = [0; 8];
        let (_, peer) = socket.recv_from(&mut bytes).await.unwrap();
        assert_eq!(bytes[0], 0);
        socket.recv_from(&mut bytes).await.unwrap();
        assert_eq!(bytes[0], 2);
        let count = u8::try_from(MAX_NETWORK_DATAGRAMS + 8).unwrap();
        for index in 0..count {
            socket.send_to(&[index], peer).await.unwrap();
        }
        let mut received = Vec::new();
        while received.len() < usize::from(count) {
            let Ok(Reply::Datagrams(batch)) =
                client.request(Operation::ReceiveDatagram(handle)).await
            else {
                panic!("expected a datagram batch");
            };
            assert!(!batch.is_empty() && batch.len() <= MAX_NETWORK_DATAGRAMS);
            received.extend(batch.into_iter().map(|datagram| datagram.bytes[0]));
        }
        assert_eq!(received, (0..count).collect::<Vec<_>>());
        drop(client);
        broker.await.unwrap().unwrap();
    }

    /// Queued replies retain only the datagram bytes covered by the broker's batch budget.
    #[tokio::test]
    async fn udp_receive_retained_bytes_fit_batch_budget() {
        let socket = bind_udp((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let sender = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut broker = Broker::bind(config()).unwrap();
        let udp = UdpResource {
            ipv4: Some(socket.clone()),
            ipv6: None,
            peers: Arc::default(),
            publication_grant: None,
        };
        udp.remember_peer(sender.local_addr().unwrap());
        broker.resources.insert(1, Resource::Udp(udp));
        for length in [0, 1] {
            let payload = vec![0x37; length];
            for _ in 0..MAX_NETWORK_DATAGRAMS {
                sender
                    .send_to(&payload, socket.local_addr().unwrap())
                    .unwrap();
            }
            let (_, receive) = broker.prepare(Operation::ReceiveDatagram(1)).unwrap();
            let completed = tokio::time::timeout(Duration::from_secs(1), receive)
                .await
                .unwrap()
                .unwrap();
            let Completion::Reply(Reply::Datagrams(batch)) = completed else {
                panic!("expected a datagram batch");
            };
            assert_eq!(batch.len(), MAX_NETWORK_DATAGRAMS);
            assert!(batch.iter().all(|datagram| datagram.bytes == payload));
            let retained_bytes: usize = batch
                .iter()
                .map(|datagram| datagram.bytes.capacity() + DATAGRAM_FRAME_OVERHEAD_BYTES)
                .sum();
            assert!(retained_bytes <= MAX_NETWORK_DATAGRAM_BATCH_BYTES);
        }
    }

    /// Rejected traffic yields even with readable sockets, while accepted datagrams keep their order.
    #[tokio::test]
    async fn udp_receive_rejections_yield_before_and_after_first_datagram() {
        for (has_prefix, is_oversized) in [(false, false), (true, false), (false, true)] {
            let socket = bind_udp((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
            let sender = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let stranger = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let mut broker = Broker::bind(config()).unwrap();
            let udp = UdpResource {
                ipv4: Some(socket.clone()),
                ipv6: None,
                peers: Arc::default(),
                publication_grant: None,
            };
            let peer = sender.local_addr().unwrap();
            udp.remember_peer(peer);
            broker.resources.insert(1, Resource::Udp(udp));
            let destination = socket.local_addr().unwrap();
            let mut expected = Vec::new();
            if has_prefix {
                sender.send_to(b"first", destination).unwrap();
                socket.peek_from(&mut [0; 5]).await.unwrap();
                expected.push(Datagram {
                    peer,
                    bytes: b"first".to_vec(),
                });
            }
            for _ in 0..=MAX_NETWORK_DATAGRAMS {
                if is_oversized {
                    sender
                        .send_to(&[0; MAX_NETWORK_DATAGRAM_BYTES + 1], destination)
                        .unwrap();
                } else {
                    stranger.send_to(b"rejected", destination).unwrap();
                }
            }
            socket.readable().await.unwrap();
            let (_, mut receive) = broker.prepare(Operation::ReceiveDatagram(1)).unwrap();
            let mut received = Vec::new();
            if let Some(completed) = receive.as_mut().now_or_never() {
                let Completion::Reply(Reply::Datagrams(batch)) = completed.unwrap() else {
                    panic!("expected a datagram batch");
                };
                assert_eq!(batch, expected);
                received.extend(batch);
                (_, receive) = broker.prepare(Operation::ReceiveDatagram(1)).unwrap();
            }
            let mut rejected = [0; MAX_NETWORK_DATAGRAM_BYTES + 1];
            let (length, rejected_peer) =
                tokio::time::timeout(Duration::from_secs(1), socket.peek_from(&mut rejected))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(
                rejected_peer,
                if is_oversized {
                    peer
                } else {
                    stranger.local_addr().unwrap()
                }
            );
            assert_eq!(
                length,
                if is_oversized {
                    MAX_NETWORK_DATAGRAM_BYTES + 1
                } else {
                    b"rejected".len()
                }
            );
            assert!(receive.as_mut().now_or_never().is_none());
            sender.send_to(b"last", destination).unwrap();
            expected.push(Datagram {
                peer,
                bytes: b"last".to_vec(),
            });
            while received.len() < expected.len() {
                let completed = tokio::time::timeout(Duration::from_secs(1), &mut receive)
                    .await
                    .unwrap()
                    .unwrap();
                let Completion::Reply(Reply::Datagrams(batch)) = completed else {
                    panic!("expected a datagram batch");
                };
                assert!(!batch.is_empty() && batch.len() <= MAX_NETWORK_DATAGRAMS);
                received.extend(batch);
                if received.len() < expected.len() {
                    (_, receive) = broker.prepare(Operation::ReceiveDatagram(1)).unwrap();
                }
            }
            assert_eq!(received, expected);
        }
    }

    #[tokio::test]
    async fn udp_preserves_messages_rejects_truncation_and_rechecks_expiry() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NOW: AtomicU64 = AtomicU64::new(0);

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (client, broker) = start(config());
        let handle = open(&client, Operation::OpenUdp).await;
        assert_eq!(
            client.request(Operation::WaitError(handle)).await,
            Err(Error::WrongKind)
        );
        assert_eq!(
            client
                .request(Operation::Read {
                    handle,
                    max_bytes: 8
                })
                .await,
            Err(Error::WrongKind)
        );
        assert_eq!(
            client.request(send_datagram(handle, address, vec![])).await,
            Ok(Reply::Sent(vec![]))
        );
        assert_eq!(
            client
                .request(send_datagram(
                    handle,
                    "192.0.2.1:9".parse().unwrap(),
                    vec![1]
                ))
                .await,
            Ok(send_failure(Error::AccessDenied))
        );
        let mut bytes = [0; 8];
        let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
        assert_eq!(length, 0);
        socket.send_to(&[], peer).await.unwrap();
        assert_eq!(
            client.request(Operation::ReceiveDatagram(handle)).await,
            Ok(datagram_reply(address, vec![]))
        );
        stranger.send_to(b"unsolicited", peer).await.unwrap();
        for size in [
            MAX_NETWORK_DATAGRAM_BYTES + 1,
            MAX_NETWORK_DATAGRAM_BYTES + 2,
        ] {
            socket.send_to(&vec![0; size], peer).await.unwrap();
        }
        socket.send_to(b"ok", peer).await.unwrap();
        assert_eq!(
            client.request(Operation::ReceiveDatagram(handle)).await,
            Ok(datagram_reply(address, b"ok".to_vec()))
        );
        drop(client);
        broker.await.unwrap().unwrap();

        let mut network = config().policy;
        network.allow = vec!["api.test:443".into()];
        let policy =
            BoxPolicy::with_clock(&network, config().gateways, || NOW.load(Ordering::Relaxed))
                .unwrap();
        let peer = "1.1.1.1:443".parse().unwrap();
        policy.accept_resolved("api.test", &["1.1.1.1".parse().unwrap()]);
        assert!(authorize_peer(&policy, peer));
        NOW.store(60_000_000_000, Ordering::Relaxed);
        assert!(!authorize_peer(&policy, peer));
    }

    #[tokio::test]
    async fn grants_resolution_resource_and_identifier_exhaustion_fail_closed() {
        let mut setup = config();
        setup.limits.resources = 1;
        let (client, broker) = start(setup);
        assert_eq!(
            client
                .request(Operation::OpenTcp {
                    peer: "192.0.2.1:443".parse().unwrap(),
                    inline_urgent: false
                })
                .await,
            Err(Error::AccessDenied)
        );
        assert_eq!(
            client.request(Operation::Accept(1)).await,
            Err(Error::AccessDenied)
        );
        assert_eq!(
            client
                .request(Operation::Resolve("denied.test".into()))
                .await,
            Err(Error::AccessDenied)
        );
        assert_eq!(
            client
                .request(Operation::Resolve("static.test".into()))
                .await,
            Ok(Reply::Resolved(vec!["1.1.1.1".parse().unwrap()]))
        );
        assert_eq!(
            client.request(Operation::Resolve("localhost".into())).await,
            Err(Error::NameUnresolvable)
        );
        let handle = open(&client, Operation::OpenUdp).await;
        assert_eq!(
            client.request(Operation::OpenUdp).await,
            Err(Error::LimitExceeded)
        );
        assert_eq!(
            client
                .request(Operation::Read {
                    handle,
                    max_bytes: 0
                })
                .await,
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            client.request(Operation::Close(handle)).await,
            Ok(Reply::Done)
        );
        let replacement = open(&client, Operation::OpenUdp).await;
        assert!(replacement > handle);
        drop(client);
        broker.await.unwrap().unwrap();
        let mut broker = Broker::bind(config()).unwrap();
        broker.next_handle = u64::MAX;
        assert!(matches!(
            broker.complete(Completion::Open(Resource::Udp(UdpResource {
                ipv4: Some(Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())),
                ipv6: None,
                peers: Arc::default(),
                publication_grant: None,
            }))),
            Err(Error::LimitExceeded)
        ));
        assert!(broker.resources.is_empty());
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn untrusted_duplicates_pending_limits_cancellation_and_framing_are_bounded() {
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);
        let mut setup = config();
        setup.listeners = vec![PublishedListener {
            grant: 1,
            address,
            transport: ResourceKind::Tcp,
        }];
        setup.limits.pending_requests = 1;
        let broker = Broker::bind(setup).unwrap();
        let (mut peer, channel) = tokio::io::duplex(MAX_NETWORK_FRAME_BYTES * 4);
        let broker = tokio::spawn(broker.serve(channel));
        for request in [
            Request {
                id: 1,
                operation: Operation::Accept(1),
            },
            Request {
                id: 1,
                operation: Operation::Accept(1),
            },
            Request {
                id: 2,
                operation: Operation::Resolve("static.test".into()),
            },
        ] {
            terra_protocol::write_frame_async(&mut peer, &request)
                .await
                .unwrap();
        }
        assert_eq!(
            terra_protocol::read_frame_async::<Response>(&mut peer)
                .await
                .unwrap()
                .unwrap(),
            Response {
                id: 1,
                result: Err(Error::DuplicateRequest)
            }
        );
        assert_eq!(
            terra_protocol::read_frame_async::<Response>(&mut peer)
                .await
                .unwrap()
                .unwrap(),
            Response {
                id: 2,
                result: Err(Error::LimitExceeded)
            }
        );
        terra_protocol::write_frame_async(
            &mut peer,
            &Request {
                id: 3,
                operation: Operation::Cancel(1),
            },
        )
        .await
        .unwrap();
        let mut results = vec![
            terra_protocol::read_frame_async::<Response>(&mut peer)
                .await
                .unwrap()
                .unwrap(),
            terra_protocol::read_frame_async::<Response>(&mut peer)
                .await
                .unwrap()
                .unwrap(),
        ];
        results.sort_by_key(|response| response.id);
        assert_eq!(
            results,
            [
                Response {
                    id: 1,
                    result: Err(Error::Cancelled)
                },
                Response {
                    id: 3,
                    result: Ok(Reply::Cancelled(true))
                }
            ]
        );
        terra_protocol::write_frame_async(
            &mut peer,
            &Request {
                id: 4,
                operation: Operation::Cancel(1),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            terra_protocol::read_frame_async::<Response>(&mut peer)
                .await
                .unwrap()
                .unwrap()
                .result,
            Ok(Reply::Cancelled(false))
        );
        peer.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        assert!(broker.await.unwrap().is_err());
        assert!(TcpStream::connect(address).await.is_err());
    }
}
