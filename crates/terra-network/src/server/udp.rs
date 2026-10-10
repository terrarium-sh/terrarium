//! UDP sockets and the pull-based request loop of one UDP stream.

use super::peer::{authorize_peer, validate_peer};
use super::tcp::bound_socket_buffers;
use crate::{Error, map_io_error};
use futures_util::future::BoxFuture;
use socket2::SockRef;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use terra_policy::BoxPolicy;
use terra_protocol::network::{
    DATAGRAM_FRAME_OVERHEAD_BYTES, Datagram, MAX_NETWORK_DATAGRAM_BATCH_BYTES,
    MAX_NETWORK_DATAGRAM_BYTES, MAX_NETWORK_DATAGRAMS, SendFailure, UdpReply, UdpRequest,
};
use tokio::io::ReadHalf;
use tokio::net::UdpSocket;
use tokio::time::Instant;
use tokio_util::compat::Compat;

pub(super) const UDP_PEER_TTL: Duration =
    Duration::from_secs(terra_protocol::network::UDP_PEER_TTL_SECS);

#[derive(Clone)]
pub(super) struct UdpResource {
    pub(super) ipv4: Option<Arc<UdpSocket>>,
    pub(super) ipv6: Option<Arc<UdpSocket>>,
    pub(super) peers: Arc<std::sync::Mutex<std::collections::VecDeque<(SocketAddr, Instant)>>>,
    pub(super) publication_grant: Option<crate::ListenerGrant>,
}

impl UdpResource {
    pub(super) fn authorize_send(&self, policy: &BoxPolicy, peer: SocketAddr) -> bool {
        if self.publication_grant.is_some() {
            self.knows_peer(peer)
        } else {
            authorize_peer(policy, peer)
        }
    }

    pub(super) fn remember_peer(&self, peer: SocketAddr) {
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

    pub(super) fn knows_peer(&self, peer: SocketAddr) -> bool {
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        peers.retain(|(_, expires)| *expires > now);
        peers.iter().any(|(known, _)| *known == peer)
    }
}

pub(super) fn bind_udp(local: SocketAddr) -> io::Result<Arc<UdpSocket>> {
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

fn try_receive_from(socket: &UdpSocket) -> io::Result<(Vec<u8>, SocketAddr)> {
    let mut bytes = vec![0; MAX_NETWORK_DATAGRAM_BYTES + 1];
    let (length, peer) = socket.try_recv_from(&mut bytes)?;
    bytes.truncate(length);
    Ok((bytes, peer))
}

/// Take one already-queued datagram from either family without waiting.
fn try_receive_datagram(udp: &UdpResource) -> Result<Option<(Vec<u8>, SocketAddr)>, Error> {
    for socket in [udp.ipv4.as_deref(), udp.ipv6.as_deref()]
        .into_iter()
        .flatten()
    {
        match try_receive_from(socket) {
            Ok(received) => return Ok(Some(received)),
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
            match try_receive_from(socket) {
                Ok(received) => return Ok(received),
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

pub(super) fn open() -> Result<UdpResource, Error> {
    let ipv4 = bind_udp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).ok();
    let ipv6 = bind_udp(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))).ok();
    if ipv4.is_none() && ipv6.is_none() {
        return Err(Error::Io);
    }
    Ok(UdpResource {
        ipv4,
        ipv6,
        peers: Arc::default(),
        publication_grant: None,
    })
}

pub(super) fn open_published(
    socket: Arc<UdpSocket>,
    grant: crate::ListenerGrant,
) -> Result<UdpResource, Error> {
    let is_ipv4 = socket.local_addr().map_err(map_io_error)?.is_ipv4();
    Ok(UdpResource {
        ipv4: is_ipv4.then(|| socket.clone()),
        ipv6: (!is_ipv4).then_some(socket),
        peers: Arc::default(),
        publication_grant: Some(grant),
    })
}

pub(super) async fn send_datagrams(
    udp: UdpResource,
    policy: Arc<BoxPolicy>,
    datagrams: Vec<Datagram>,
) -> Vec<SendFailure> {
    let mut failures = Vec::new();
    for (index, datagram) in (0..).zip(datagrams) {
        if let Err(error) = send_datagram(&udp, &policy, &datagram).await {
            failures.push(SendFailure { index, error });
        }
    }
    failures
}

pub(super) async fn receive_datagrams(
    udp: UdpResource,
    policy: Arc<BoxPolicy>,
) -> Result<Vec<Datagram>, Error> {
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
        if bytes.len() > MAX_NETWORK_DATAGRAM_BYTES || !accept_datagram_from(&udp, &policy, peer) {
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
    Ok(datagrams)
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
    let mut receiving: Option<BoxFuture<'static, Result<Vec<Datagram>, Error>>> = None;
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
