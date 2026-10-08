//! One guest TCP socket per vsock stream: an opening handshake, then raw bytes both ways.

use super::{
    broker_error, deliver_opening, finish_flow, host_service_peer, host_socket_address,
    pump_downstream, pump_upstream, read_opening, reject_opening, reset_flow, resolve_destination,
    run_before_deadline, shutdown_flow,
};
use crate::{
    terra::network::broker::{self, Tcp},
    wit_stream,
};
use futures_util::future::try_join;
use std::net::SocketAddr;
use terra_protocol::application::{Message, OPEN_TIMEOUT_SECS, TcpTarget};
use terra_protocol::socket::Error as SocketError;
use terra_vsock_device::ConnectionId;

pub(super) async fn serve(connection: ConnectionId) {
    let opening = async {
        let outcome = async {
            let Message::TcpOpen {
                target,
                inline_urgent,
            } = read_opening(connection).await?
            else {
                return Err(SocketError::Protocol);
            };
            open(target, inline_urgent).await
        }
        .await;
        let reply = Message::TcpOpened(
            outcome
                .as_ref()
                .map(|(_, peer)| *peer)
                .map_err(|error| *error),
        );
        deliver_opening(connection, &reply).await?;
        outcome
    };
    match run_before_deadline(OPEN_TIMEOUT_SECS, opening).await {
        Ok(Ok((socket, _))) => relay(connection, &socket).await,
        Ok(Err(_)) => shutdown_flow(connection),
        Err(error) => reject_opening(connection, &Message::TcpOpened(Err(error))),
    }
    finish_flow(connection);
}

async fn open(target: TcpTarget, inline_urgent: bool) -> Result<(Tcp, SocketAddr), SocketError> {
    let (destination, reported) = match target {
        TcpTarget::Peer(peer) => (resolve_destination(peer)?, peer),
        TcpTarget::HostService(port) => {
            let destination = host_service_peer(port, false)?;
            (destination, destination)
        }
    };
    broker::open_tcp(host_socket_address(destination), inline_urgent)
        .await
        .map(|socket| (socket, reported))
        .map_err(broker_error)
}

pub(super) async fn relay(connection: ConnectionId, socket: &Tcp) {
    let (writer, input) = wit_stream::new();
    let sent = socket.send(input);
    let (output, received) = socket.receive();
    let upstream = async {
        try_join(pump_upstream(connection, writer), async { sent.await }).await?;
        Ok::<_, broker::Error>(())
    };
    let downstream = pump_downstream(connection, output, Some(received));
    if try_join(upstream, downstream).await.is_err() {
        reset_flow(connection);
    }
}
