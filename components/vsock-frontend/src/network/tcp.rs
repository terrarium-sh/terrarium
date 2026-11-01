//! One guest TCP socket per vsock stream: an opening handshake, then raw bytes both ways.

use super::{
    broker_error, consume_upstream, finish_flow, host_socket_address, open_socket, pump_downstream,
    pump_upstream, reset_flow, resolve_destination, wait_upstream,
};
use crate::{
    terra::network::broker::{self, Tcp},
    wit_stream,
};
use futures_util::future::try_join;
use std::net::SocketAddr;
use terra_protocol::application::{self, Frame as _, GuestFrame, HEADER_BYTES, TcpOpenOptions};
use terra_protocol::socket::Error as SocketError;
use terra_vsock_device::ConnectionId;

pub(super) async fn serve(connection: ConnectionId) {
    let opening = async {
        let (peer, options) = read_tcp_open(connection).await?;
        open(peer, options).await
    };
    if let Some(socket) = open_socket(connection, opening).await {
        relay(connection, &socket).await;
    }
    finish_flow(connection);
}

/// Read the guest's `TcpOpen`; a byte already queued behind it is a protocol error, since the
/// guest sends nothing more until the frontend replies.
async fn read_tcp_open(
    connection: ConnectionId,
) -> Result<(SocketAddr, TcpOpenOptions), SocketError> {
    let header = wait_upstream(connection, HEADER_BYTES, HEADER_BYTES)
        .await
        .map_err(|()| SocketError::Cancelled)?;
    if header.is_empty() {
        return Err(SocketError::Closed);
    }
    let header = <[u8; HEADER_BYTES]>::try_from(header).map_err(|_| SocketError::Protocol)?;
    let frame_bytes = application::frame_len(header).map_err(|_| SocketError::Protocol)?;
    let queued = wait_upstream(connection, frame_bytes, frame_bytes + 1)
        .await
        .map_err(|()| SocketError::Cancelled)?;
    if queued.len() != frame_bytes {
        return Err(SocketError::Protocol);
    }
    let Ok(Some((GuestFrame::TcpOpen { peer, options }, _))) = GuestFrame::decode(&queued) else {
        return Err(SocketError::Protocol);
    };
    consume_upstream(connection, frame_bytes).map_err(|()| SocketError::Cancelled)?;
    Ok((peer, options))
}

async fn open(peer: SocketAddr, options: TcpOpenOptions) -> Result<Tcp, SocketError> {
    broker::open_tcp(
        host_socket_address(resolve_destination(peer)?),
        broker::TcpOpenOptions {
            inline_urgent: options.inline_urgent,
            keepalive: options.keepalive.map(|keepalive| broker::TcpKeepalive {
                idle_secs: keepalive.idle_secs(),
                interval_secs: keepalive.interval_secs(),
                probe_count: keepalive.probe_count(),
            }),
        },
    )
    .await
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
