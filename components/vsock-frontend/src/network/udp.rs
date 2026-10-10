//! One guest UDP socket per vsock stream: open once, then datagram frames both ways.

use super::{
    batches, broker_error, deliver_message, deliver_opening, finish_flow, host_socket_address,
    native_socket_address, read_message, read_opening, read_queued_message, reject_opening,
    reset_flow, resolve_destination, run_before_deadline, shutdown_flow,
};
use crate::terra::network::broker::{self, Udp};
use futures_util::{
    Stream, StreamExt as _,
    future::{Either, select},
    lock::Mutex,
};
use std::{cell::RefCell, net::SocketAddr, pin::Pin};
use terra_protocol::application::{Message, OPEN_TIMEOUT_SECS, StreamDecoder};
use terra_protocol::network::{
    DATAGRAM_FRAME_OVERHEAD_BYTES, MAX_NETWORK_DATAGRAM_BATCH_BYTES, MAX_NETWORK_DATAGRAM_BYTES,
    MAX_NETWORK_DATAGRAMS,
};
use terra_protocol::socket::Error as SocketError;
use terra_vsock_device::{ConnectionId, Role};
use wit_bindgen::rt::async_support::FutureReader;

const MAX_TRANSLATED_PEERS: usize = 16;

pub(super) struct DatagramReceiver {
    stream: Pin<Box<dyn Stream<Item = Vec<broker::Datagram>>>>,
    completion: Option<FutureReader<Result<(), broker::Error>>>,
    pub(super) first_datagrams: Vec<broker::Datagram>,
}

impl DatagramReceiver {
    pub(super) fn new(socket: &Udp) -> Self {
        let (stream, completion) = socket.receive_from();
        Self {
            stream: Box::pin(batches(stream, MAX_NETWORK_DATAGRAMS)),
            completion: Some(completion),
            first_datagrams: Vec::new(),
        }
    }

    pub(super) async fn read(&mut self) -> Result<Option<Vec<broker::Datagram>>, SocketError> {
        if !self.first_datagrams.is_empty() {
            return Ok(Some(std::mem::take(&mut self.first_datagrams)));
        }
        if let Some(datagrams) = self.stream.next().await {
            return Ok(Some(datagrams));
        }
        if let Some(completion) = self.completion.take() {
            completion.await.map_err(broker_error)?;
        }
        Ok(None)
    }
}

/// Host addresses the broker reports, paired with the guest-visible address the guest sent to.
#[derive(Default)]
struct PeerTranslations(RefCell<Vec<(SocketAddr, SocketAddr)>>);

impl PeerTranslations {
    fn remember(&self, host: SocketAddr, guest: SocketAddr) {
        let mut peers = self.0.borrow_mut();
        peers.retain(|(known, _)| *known != host);
        if host == guest {
            return;
        }
        if peers.len() == MAX_TRANSLATED_PEERS {
            peers.remove(0);
        }
        peers.push((host, guest));
    }

    fn guest_peer(&self, host: SocketAddr) -> SocketAddr {
        self.0
            .borrow()
            .iter()
            .find(|(known, _)| *known == host)
            .map_or(host, |(_, guest)| *guest)
    }
}

pub(super) async fn serve(connection: ConnectionId) {
    let opening = async {
        let outcome = async {
            if read_opening(connection).await? != Message::UdpOpen {
                return Err(SocketError::Protocol);
            }
            broker::open_udp().await.map_err(broker_error)
        }
        .await;
        let reply = Message::UdpOpened(outcome.as_ref().map(|_| ()).map_err(|error| *error));
        deliver_opening(connection, &reply).await?;
        outcome
    };
    match run_before_deadline(OPEN_TIMEOUT_SECS, opening).await {
        Ok(Ok(socket)) => {
            if relay(connection, &socket, None).await.is_err() {
                reset_flow(connection);
            } else {
                shutdown_flow(connection);
            }
        }
        Ok(Err(_)) => shutdown_flow(connection),
        Err(error) => reject_opening(connection, &Message::UdpOpened(Err(error))),
    }
    finish_flow(connection);
}

/// Forward datagrams until the guest closes its socket; frames from both directions share one writer.
pub(super) async fn relay(
    connection: ConnectionId,
    socket: &Udp,
    receiver: Option<DatagramReceiver>,
) -> Result<(), SocketError> {
    let peers = PeerTranslations::default();
    let receiver = receiver.unwrap_or_else(|| DatagramReceiver::new(socket));
    let writer = Mutex::new(());
    let upstream = send_datagrams(connection, socket, &writer, &peers);
    let downstream = receive_datagrams(connection, receiver, &writer, &peers);
    let upstream = std::pin::pin!(upstream);
    let downstream = std::pin::pin!(downstream);
    match select(upstream, downstream).await {
        Either::Left((result, _)) | Either::Right((result, _)) => result,
    }
}

fn resolve_datagram_peer(role: Role, peer: SocketAddr) -> Result<SocketAddr, SocketError> {
    match role {
        Role::Udp => resolve_destination(peer),
        Role::Publication => Ok(peer),
        Role::Agent | Role::Control | Role::Tcp => Err(SocketError::Protocol),
    }
}

/// Send each burst of queued guest frames as one broker batch; a failed datagram becomes an error frame.
async fn send_datagrams(
    connection: ConnectionId,
    socket: &Udp,
    writer: &Mutex<()>,
    peers: &PeerTranslations,
) -> Result<(), SocketError> {
    let mut decoder = StreamDecoder::default();
    while let Some(message) = read_message(connection, &mut decoder).await? {
        let mut errors = Vec::new();
        let mut guest_peers = Vec::new();
        let mut datagrams = Vec::new();
        let mut budget = MAX_NETWORK_DATAGRAM_BATCH_BYTES;
        let mut next = Some(message);
        while let Some(message) = next.take() {
            let Message::UdpSend { peer, bytes } = message else {
                return Err(SocketError::Protocol);
            };
            match resolve_datagram_peer(connection.role, peer) {
                Ok(destination) => {
                    if connection.role == Role::Udp {
                        peers.remember(destination, peer);
                    }
                    budget -= bytes.len() + DATAGRAM_FRAME_OVERHEAD_BYTES;
                    guest_peers.push(peer);
                    datagrams.push(broker::Datagram {
                        peer: host_socket_address(destination),
                        bytes,
                    });
                }
                Err(error) => errors.push((peer, error)),
            }
            if datagrams.len() < MAX_NETWORK_DATAGRAMS
                && budget >= MAX_NETWORK_DATAGRAM_BYTES + DATAGRAM_FRAME_OVERHEAD_BYTES
            {
                next = read_queued_message(connection, &mut decoder)?;
            }
        }
        if !datagrams.is_empty() {
            match socket.send_to(datagrams).await {
                Ok(failures) => errors.extend(failures.into_iter().filter_map(|failure| {
                    let peer = guest_peers.get(failure.index as usize)?;
                    Some((*peer, broker_error(failure.error)))
                })),
                Err(error) => {
                    let error = broker_error(error);
                    errors.extend(guest_peers.into_iter().map(|peer| (peer, error)));
                }
            }
        }
        if !errors.is_empty() {
            let _guard = writer.lock().await;
            for (peer, error) in errors {
                deliver_message(connection, &Message::UdpError { peer, error }).await?;
            }
        }
    }
    Ok(())
}

async fn receive_datagrams(
    connection: ConnectionId,
    mut receiver: DatagramReceiver,
    writer: &Mutex<()>,
    peers: &PeerTranslations,
) -> Result<(), SocketError> {
    while let Some(datagrams) = receiver.read().await? {
        let _guard = writer.lock().await;
        deliver_datagrams(connection, peers, datagrams).await?;
    }
    Ok(())
}

async fn deliver_datagrams(
    connection: ConnectionId,
    peers: &PeerTranslations,
    datagrams: Vec<broker::Datagram>,
) -> Result<(), SocketError> {
    for broker::Datagram { peer, bytes } in datagrams {
        let peer = peers.guest_peer(native_socket_address(peer));
        deliver_message(connection, &Message::UdpDatagram { peer, bytes }).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// UDP publication peers are host clients, so synthetic guest destinations cannot
    /// turn publication reply grants into host-service grants.
    #[test]
    fn publication_replies_preserve_the_broker_authorized_peer() {
        let peer = SocketAddr::new(terra_protocol::socket::HOST_SERVICE_IPV4.into(), 5353);
        assert_eq!(resolve_datagram_peer(Role::Publication, peer), Ok(peer));
        assert_eq!(
            resolve_datagram_peer(Role::Tcp, peer),
            Err(SocketError::Protocol)
        );
    }

    /// Replies from a translated host-service address reach the guest under the address it used.
    #[test]
    fn host_service_replies_keep_the_guest_visible_peer() {
        let peers = PeerTranslations::default();
        let host: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let guest: SocketAddr = "100.96.0.1:5353".parse().unwrap();
        peers.remember(host, guest);
        peers.remember(guest, guest);
        assert_eq!(peers.guest_peer(host), guest);
        peers.remember(host, host);
        assert_eq!(peers.guest_peer(host), host);
        peers.remember(host, guest);
        let other: SocketAddr = "192.0.2.1:53".parse().unwrap();
        assert_eq!(peers.guest_peer(other), other);
        for port in 0..u16::try_from(MAX_TRANSLATED_PEERS).unwrap() {
            peers.remember(SocketAddr::new(host.ip(), 6000 + port), guest);
        }
        assert_eq!(peers.0.borrow().len(), MAX_TRANSLATED_PEERS);
        assert_eq!(peers.guest_peer(host), host);
    }
}
