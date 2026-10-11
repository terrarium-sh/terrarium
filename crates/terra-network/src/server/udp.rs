//! UDP sockets and the pull-based request loop of one UDP stream.

use super::peer::validate_peer;
use super::tcp::bound_socket_buffers;
use crate::{Error, map_io_error};
use futures_util::future::BoxFuture;
use lru::LruCache;
use quinn_udp::{RecvMeta, Transmit, UdpSocketState};
use socket2::SockRef;
use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use terra_policy::BoxPolicy;
use terra_protocol::network::{
    DatagramBatch, MAX_NETWORK_CHUNK_BYTES, MAX_NETWORK_DATAGRAM_BYTES, SendFailure, UdpReply,
    UdpRequest,
};
use tokio::io::{Interest, ReadHalf};
use tokio::net::UdpSocket;
use tokio::time::Instant;
use tokio_util::compat::Compat;

pub(super) const UDP_PEER_TTL: Duration =
    Duration::from_secs(terra_protocol::network::UDP_PEER_TTL_SECS);

/// One receive buffer holds the largest run the kernel coalesces (GRO) into a single read.
const RECEIVE_BUFFER_BYTES: usize = MAX_NETWORK_CHUNK_BYTES;

/// A UDP socket with kernel segmentation offload (GSO/GRO on Linux, USO/URO on Windows) when available.
pub(super) struct OffloadSocket {
    pub(super) socket: UdpSocket,
    offload: UdpSocketState,
}

impl OffloadSocket {
    pub(super) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    async fn writable(&self) -> io::Result<()> {
        self.socket.writable().await
    }

    async fn readable(&self) -> io::Result<()> {
        self.socket.readable().await
    }

    fn try_send(
        &self,
        destination: SocketAddr,
        contents: &[u8],
        segment_size: Option<usize>,
    ) -> io::Result<()> {
        self.socket.try_io(Interest::WRITABLE, || {
            self.offload.try_send(
                (&self.socket).into(),
                &Transmit {
                    destination,
                    ecn: None,
                    contents,
                    segment_size,
                    src_ip: None,
                },
            )
        })
    }

    fn try_receive(&self, buffer: &mut [u8]) -> io::Result<RecvMeta> {
        self.socket.try_io(Interest::READABLE, || {
            let mut meta = [RecvMeta::default()];
            match self.offload.recv(
                (&self.socket).into(),
                &mut [IoSliceMut::new(buffer)],
                &mut meta,
            )? {
                0 => Err(io::ErrorKind::WouldBlock.into()),
                _ => Ok(meta[0]),
            }
        })
    }
}

/// Unbatched remainder of a read: `bytes` of the receive buffer, in `stride`-byte datagrams.
struct PendingRun {
    peer: SocketAddr,
    stride: usize,
    bytes: Range<usize>,
}

/// A read taken from a socket: kept for the batch, or dropped for its datagram size or its peer.
enum Received {
    Kept(PendingRun),
    Dropped,
}

#[derive(Default)]
pub(super) struct ReceiveState {
    buffer: Vec<u8>,
    pending: Option<PendingRun>,
}

impl ReceiveState {
    fn move_pending_into(&mut self, batch: &mut DatagramBatch) {
        let Some(run) = &mut self.pending else {
            return;
        };
        run.bytes.start += batch.push_run(run.peer, &self.buffer[run.bytes.clone()], run.stride);
        if run.bytes.is_empty() {
            self.pending = None;
        }
    }
}

#[derive(Clone)]
pub(super) struct UdpResource {
    pub(super) ipv4: Option<Arc<OffloadSocket>>,
    pub(super) ipv6: Option<Arc<OffloadSocket>>,
    pub(super) peers: Arc<Mutex<UdpPeers>>,
    pub(super) publication_grant: Option<crate::ListenerGrant>,
    pub(super) receiving: Arc<tokio::sync::Mutex<ReceiveState>>,
}

pub(super) struct UdpPeers {
    capacity: usize,
    /// Recency order is refresh order, so the least recent entry expires first.
    pub(super) remembered: LruCache<SocketAddr, Instant>,
    /// Policy grants as [`BoxPolicy::authorized_until`] reported them.
    authorized: LruCache<SocketAddr, u64>,
}

impl UdpPeers {
    /// The tables grow on demand: most sockets talk to one peer.
    pub(super) fn shared(capacity: usize) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            capacity,
            remembered: LruCache::unbounded(),
            authorized: LruCache::unbounded(),
        }))
    }

    fn forget_expired(&mut self, now: Instant) {
        while self
            .remembered
            .peek_lru()
            .is_some_and(|(_, expires)| *expires <= now)
        {
            self.remembered.pop_lru();
        }
    }
}

impl UdpResource {
    fn lock_peers(&self) -> MutexGuard<'_, UdpPeers> {
        self.peers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn authorize_send(&self, policy: &BoxPolicy, peer: SocketAddr) -> bool {
        if self.publication_grant.is_some() {
            self.knows_peer(peer)
        } else {
            self.authorize(policy, peer)
        }
    }

    /// Consults `policy` only once the cached grant for `peer` lapses.
    fn authorize(&self, policy: &BoxPolicy, peer: SocketAddr) -> bool {
        let now = policy.now();
        if self
            .lock_peers()
            .authorized
            .get(&peer)
            .is_some_and(|until| *until > now)
        {
            return true;
        }
        let granted_until = policy.authorized_until(peer);
        let peers = &mut *self.lock_peers();
        if let Some(until) = granted_until {
            put_bounded(&mut peers.authorized, peers.capacity, peer, until);
        } else {
            peers.authorized.pop(&peer);
        }
        granted_until.is_some()
    }

    pub(super) fn remember_peer(&self, peer: SocketAddr) {
        let now = Instant::now();
        let peers = &mut *self.lock_peers();
        peers.forget_expired(now);
        put_bounded(
            &mut peers.remembered,
            peers.capacity,
            peer,
            now + UDP_PEER_TTL,
        );
    }

    pub(super) fn knows_peer(&self, peer: SocketAddr) -> bool {
        let mut peers = self.lock_peers();
        peers.forget_expired(Instant::now());
        peers.remembered.contains(&peer)
    }
}

fn put_bounded<V>(
    cache: &mut LruCache<SocketAddr, V>,
    capacity: usize,
    peer: SocketAddr,
    value: V,
) {
    if cache.len() >= capacity && !cache.contains(&peer) {
        cache.pop_lru();
    }
    cache.put(peer, value);
}

/// Undoes the don't-fragment flag `UdpSocketState::new` sets for QUIC path-MTU probing: guest
/// datagrams up to `MAX_NETWORK_DATAGRAM_BYTES` must still leave over links with a smaller MTU.
fn allow_fragmentation(socket: &socket2::Socket, is_ipv6: bool) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if is_ipv6 {
        set_socket_option(
            socket,
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            libc::IPV6_PMTUDISC_WANT,
        )?;
        set_socket_option(socket, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 0)?;
    } else {
        set_socket_option(
            socket,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_WANT,
        )?;
    }
    #[cfg(target_vendor = "apple")]
    if is_ipv6 {
        set_socket_option(socket, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 0)?;
    } else {
        set_socket_option(socket, libc::IPPROTO_IP, libc::IP_DONTFRAG, 0)?;
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Networking::WinSock::{
            IP_DONTFRAGMENT, IPPROTO_IP, IPPROTO_IPV6, IPV6_DONTFRAG,
        };
        if is_ipv6 {
            set_socket_option(socket, IPPROTO_IPV6, IPV6_DONTFRAG, 0)?;
        } else {
            set_socket_option(socket, IPPROTO_IP, IP_DONTFRAGMENT, 0)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn set_socket_option(
    socket: &socket2::Socket,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;
    let length = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
        .map_err(|_| io::Error::other("socket option size exceeds socklen_t"))?;
    // SAFETY: setsockopt only reads `value` for `length` bytes during the call on a live descriptor.
    let status = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&raw const value).cast(),
            length,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn set_socket_option(
    socket: &socket2::Socket,
    level: i32,
    name: i32,
    value: i32,
) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket as _;
    use windows_sys::Win32::Networking::WinSock::{SOCKET_ERROR, WSAGetLastError, setsockopt};
    let raw_socket = usize::try_from(socket.as_raw_socket())
        .map_err(|_| io::Error::other("socket handle exceeds setsockopt limit"))?;
    let length = i32::try_from(std::mem::size_of::<i32>())
        .map_err(|_| io::Error::other("socket option size exceeds setsockopt limit"))?;
    // SAFETY: setsockopt only reads `value` for `length` bytes during the call on a live socket.
    let status = unsafe { setsockopt(raw_socket, level, name, (&raw const value).cast(), length) };
    if status == SOCKET_ERROR {
        // SAFETY: WSAGetLastError reads the calling thread's last Winsock error.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}

pub(super) fn bind_udp(local: SocketAddr) -> io::Result<Arc<OffloadSocket>> {
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
    let offload = UdpSocketState::new((&socket).into())?;
    allow_fragmentation(&socket, local.is_ipv6())?;
    Ok(Arc::new(OffloadSocket {
        socket: UdpSocket::from_std(socket.into())?,
        offload,
    }))
}

/// Sends `bytes` as `stride`-byte datagrams from `*sent` on, in the largest offloaded writes the
/// socket allows. After a failed offloaded write the socket stops offloading, and the write is retried unoffloaded.
fn send_pending(
    socket: &OffloadSocket,
    peer: SocketAddr,
    bytes: &[u8],
    stride: usize,
    sent: &mut usize,
) -> io::Result<()> {
    loop {
        let max_segments = socket.offload.max_gso_segments().max(1);
        let end = bytes.len().min(*sent + stride * max_segments);
        let write = &bytes[*sent..end];
        let segment_size = (write.len() > stride).then_some(stride);
        match socket.try_send(peer, write, segment_size) {
            Ok(()) => *sent = end,
            Err(error)
                if error.kind() != io::ErrorKind::WouldBlock
                    && socket.offload.max_gso_segments() < max_segments =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
        if *sent == bytes.len() {
            return Ok(());
        }
    }
}

async fn send_entry(
    udp: &UdpResource,
    policy: &BoxPolicy,
    peer: SocketAddr,
    segment: u16,
    bytes: &[u8],
) -> Result<(), Error> {
    if segment == 0 && bytes.len() > MAX_NETWORK_DATAGRAM_BYTES {
        return Err(Error::DatagramTooLarge);
    }
    validate_peer(peer)?;
    let socket = if peer.is_ipv4() { &udp.ipv4 } else { &udp.ipv6 }
        .as_deref()
        .ok_or(Error::Io)?;
    let stride = if segment == 0 {
        bytes.len()
    } else {
        usize::from(segment)
    };
    let mut sent = 0;
    loop {
        if !udp.authorize_send(policy, peer) {
            return Err(Error::AccessDenied);
        }
        socket.writable().await.map_err(map_io_error)?;
        if !udp.authorize_send(policy, peer) {
            return Err(Error::AccessDenied);
        }
        match send_pending(socket, peer, bytes, stride, &mut sent) {
            Ok(()) => {
                if udp.publication_grant.is_none() {
                    udp.remember_peer(peer);
                }
                return Ok(());
            }
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
        udp.knows_peer(peer) && udp.authorize(policy, peer)
    }
}

/// Reads one run of equal-size datagrams from one peer into `buffer`.
fn try_receive_run(
    socket: &OffloadSocket,
    udp: &UdpResource,
    policy: &BoxPolicy,
    buffer: &mut [u8],
) -> io::Result<Received> {
    let meta = socket.try_receive(buffer)?;
    let peer = SocketAddr::new(meta.addr.ip().to_canonical(), meta.addr.port());
    Ok(
        if meta.stride <= MAX_NETWORK_DATAGRAM_BYTES && accept_datagram_from(udp, policy, peer) {
            Received::Kept(PendingRun {
                peer,
                stride: meta.stride,
                bytes: 0..meta.len,
            })
        } else {
            Received::Dropped
        },
    )
}

/// Take one already-queued run from either family without waiting; `None` means none is queued.
fn try_receive_queued_run(
    udp: &UdpResource,
    policy: &BoxPolicy,
    buffer: &mut [u8],
) -> Result<Option<Received>, Error> {
    for socket in [udp.ipv4.as_deref(), udp.ipv6.as_deref()]
        .into_iter()
        .flatten()
    {
        match try_receive_run(socket, udp, policy, buffer) {
            Ok(run) => return Ok(Some(run)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => match map_datagram_error(error) {
                Error::ConnectionReset | Error::ConnectionRefused | Error::DatagramTooLarge => {}
                error => return Err(error),
            },
        }
    }
    Ok(None)
}

/// Wait for one run on either family; ICMP-reported peer errors are not socket failures.
async fn receive_run(
    udp: &UdpResource,
    policy: &BoxPolicy,
    buffer: &mut [u8],
) -> Result<Received, Error> {
    async fn readable(socket: Option<&OffloadSocket>) -> io::Result<&OffloadSocket> {
        let Some(socket) = socket else {
            return std::future::pending().await;
        };
        socket.readable().await?;
        Ok(socket)
    }
    loop {
        let socket = tokio::select! {
            socket = readable(udp.ipv4.as_deref()) => socket,
            socket = readable(udp.ipv6.as_deref()) => socket,
        };
        let received = socket.and_then(|socket| try_receive_run(socket, udp, policy, buffer));
        match received {
            Ok(run) => return Ok(run),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
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

pub(super) fn open() -> Result<UdpResource, Error> {
    let ipv4 = bind_udp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).ok();
    let ipv6 = bind_udp(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))).ok();
    if ipv4.is_none() && ipv6.is_none() {
        return Err(Error::Io);
    }
    Ok(UdpResource {
        ipv4,
        ipv6,
        peers: UdpPeers::shared(crate::MAX_UDP_OUTBOUND_PEERS),
        publication_grant: None,
        receiving: Arc::default(),
    })
}

pub(super) fn open_published(
    socket: Arc<OffloadSocket>,
    grant: crate::ListenerGrant,
) -> Result<UdpResource, Error> {
    let is_ipv4 = socket.local_addr().map_err(map_io_error)?.is_ipv4();
    Ok(UdpResource {
        ipv4: is_ipv4.then(|| socket.clone()),
        ipv6: (!is_ipv4).then_some(socket),
        peers: UdpPeers::shared(crate::MAX_UDP_PUBLICATION_PEERS),
        publication_grant: Some(grant),
        receiving: Arc::default(),
    })
}

pub(super) async fn send_datagrams(
    udp: UdpResource,
    policy: Arc<BoxPolicy>,
    datagrams: DatagramBatch,
) -> Vec<SendFailure> {
    let mut failures = Vec::new();
    for (index, (peer, segment, bytes)) in (0..).zip(datagrams.entries()) {
        if let Err(error) = send_entry(&udp, &policy, peer, segment, bytes).await {
            failures.push(SendFailure { index, error });
        }
    }
    failures
}

/// Batches the runs the kernel hands over, merging equal-size datagrams from one peer. A run
/// that does not fit the batch stays in `udp.receiving` for the next call.
pub(super) async fn receive_datagrams(
    udp: UdpResource,
    policy: Arc<BoxPolicy>,
) -> Result<DatagramBatch, Error> {
    let receiving = &mut *udp.receiving.lock().await;
    if receiving.buffer.is_empty() {
        receiving.buffer.resize(RECEIVE_BUFFER_BYTES, 0);
    }
    let mut batch = DatagramBatch::default();
    receiving.move_pending_into(&mut batch);
    while receiving.pending.is_none() && batch.has_room_for_datagram() {
        let run = if batch.is_empty() {
            receive_run(&udp, &policy, &mut receiving.buffer).await?
        } else if let Some(run) = try_receive_queued_run(&udp, &policy, &mut receiving.buffer)? {
            run
        } else {
            break;
        };
        match run {
            Received::Kept(run) => {
                receiving.pending = Some(run);
                receiving.move_pending_into(&mut batch);
            }
            Received::Dropped => tokio::task::yield_now().await,
        }
    }
    Ok(batch)
}

type StreamRead = ReadHalf<Compat<yamux::Stream>>;

async fn next_request(mut read: StreamRead) -> (StreamRead, Option<UdpRequest>) {
    let request = crate::frames::read_frame(&mut read).await.ok().flatten();
    (read, request)
}

/// Resolves when the slot's future completes, then empties the slot; pends while it is empty.
async fn finish<T>(slot: &mut Option<BoxFuture<'static, T>>) -> T {
    let output = match slot {
        Some(future) => future.await,
        None => std::future::pending().await,
    };
    *slot = None;
    output
}

/// Serves pull-based requests until the client closes the stream, sends a second concurrent
/// `Send` or `Receive`, or a socket fails (reported as `UdpReply::Failed`). Dropping the futures that remain abandons them.
pub(super) async fn serve(stream: Compat<yamux::Stream>, udp: UdpResource, policy: Arc<BoxPolicy>) {
    let (read, mut write) = tokio::io::split(stream);
    let mut request = Box::pin(next_request(read));
    let mut sending: Option<BoxFuture<'static, Vec<SendFailure>>> = None;
    let mut receiving: Option<BoxFuture<'static, Result<DatagramBatch, Error>>> = None;
    loop {
        let reply = tokio::select! {
            (read, next) = &mut request => {
                match next {
                    Some(UdpRequest::Send(datagrams)) if sending.is_none() => {
                        sending = Some(Box::pin(send_datagrams(udp.clone(), policy.clone(), datagrams)));
                    }
                    Some(UdpRequest::Receive) if receiving.is_none() => {
                        receiving = Some(Box::pin(receive_datagrams(udp.clone(), policy.clone())));
                    }
                    Some(UdpRequest::Send(_) | UdpRequest::Receive) | None => return,
                }
                request = Box::pin(next_request(read));
                continue;
            }
            failures = finish(&mut sending) => UdpReply::Sent(failures),
            datagrams = finish(&mut receiving) => match datagrams {
                Ok(datagrams) => UdpReply::Datagrams(datagrams),
                Err(error) => {
                    let _ = crate::frames::write_frame(&mut write, &UdpReply::Failed(error)).await;
                    return;
                }
            },
        };
        if crate::frames::write_frame(&mut write, &reply)
            .await
            .is_err()
        {
            return;
        }
    }
}
