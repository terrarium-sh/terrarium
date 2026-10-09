//! Trusted TCP and UDP publication over frontend-initiated vsock streams.

use super::{
    Task, deliver_opening, finish_flow, lock_network, native_socket_address, register_flow,
    reset_flow, run_before_deadline, shutdown_flow, spawn_task, tcp, udp, wait,
    wait_for_publication,
};
use crate::terra::network::broker::{self, Listener, Tcp, Udp};
use crate::terra::network::types::{PublishedPort, Transport};
use crate::{switch, transport};
use futures_util::future::{AbortHandle, AbortRegistration, Abortable, poll_fn};
use std::{
    sync::atomic::{AtomicU32, Ordering},
    task::Poll,
};
use terra_protocol::application::{Message, OPEN_TIMEOUT_SECS};
use terra_protocol::socket::Error as SocketError;
use terra_vsock_device::{ConnectionId, PUBLICATION_HOST_PORTS, VsockError};
use wit_bindgen::rt::async_support::StreamResult;

const MAX_HOST_PORT_ATTEMPTS: usize = terra_vsock_device::MAX_NETWORK_SOCKETS + 1;
static NEXT_HOST_PORT: AtomicU32 = AtomicU32::new(PUBLICATION_HOST_PORTS.start);

pub(super) fn start_listeners(ports: &[PublishedPort]) -> Vec<Task> {
    let mut listeners = Vec::new();
    for port in ports {
        for ipv6 in [false, true] {
            let guest_port = port.guest_port;
            let host_port = port.host_port;
            match port.transport {
                Transport::Tcp => {
                    if let Ok(listener) = broker::published_listener(host_port, ipv6) {
                        listeners.push(spawn_task(serve_tcp_listener(listener, guest_port)));
                    }
                }
                Transport::Udp => {
                    if let Some(connection) = connect_publication() {
                        let registration = register_udp_flow(connection);
                        listeners.push(spawn_task(serve_udp_listener(
                            connection,
                            registration,
                            guest_port,
                            host_port,
                            ipv6,
                        )));
                    }
                }
            }
        }
    }
    listeners
}

async fn serve_tcp_listener(listener: Listener, guest_port: u16) {
    let (mut accepted, completion) = listener.accept();
    loop {
        let (result, sockets) = accepted.read(Vec::with_capacity(1)).await;
        if !matches!(result, StreamResult::Complete(_)) || sockets.is_empty() {
            let _ = completion.await;
            return;
        }
        for socket in sockets {
            accept(guest_port, socket);
        }
    }
}

fn register_udp_flow(connection: ConnectionId) -> AbortRegistration {
    let (abort, registration) = AbortHandle::new_pair();
    register_flow(connection, Task(abort));
    registration
}

async fn wait_retired(connection: ConnectionId) {
    poll_fn(|context| {
        let mut state = lock_network();
        let device = switch();
        if device.is_current(connection)
            || device.is_connecting(connection)
            || device.is_retiring(connection)
        {
            wait(&mut state, connection, context.waker());
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
}

async fn wait_publication_capacity() -> ConnectionId {
    poll_fn(|context| {
        let mut state = lock_network();
        if let Some(connection) = connect_publication() {
            Poll::Ready(connection)
        } else {
            wait_for_publication(&mut state, context.waker());
            Poll::Pending
        }
    })
    .await
}

async fn serve_udp_listener(
    mut connection: ConnectionId,
    mut registration: AbortRegistration,
    guest_port: u16,
    host_port: u16,
    ipv6: bool,
) {
    let mut socket = None;
    loop {
        let relay = publish_udp(connection, guest_port, host_port, ipv6, socket.take());
        let _ = Abortable::new(relay, registration).await;
        wait_retired(connection).await;
        let Ok(Ok(reopened)) =
            run_before_deadline(OPEN_TIMEOUT_SECS, broker::published_udp(host_port, ipv6)).await
        else {
            return;
        };
        let mut receiver = udp::DatagramReceiver::new(&reopened);
        let Ok(Some(datagrams)) = receiver.read().await else {
            return;
        };
        receiver.first_datagrams = datagrams;
        connection = wait_publication_capacity().await;
        registration = register_udp_flow(connection);
        socket = Some((reopened, receiver));
    }
}

/// Open the guest stream for one accepted host connection; without capacity the host connection is dropped.
fn accept(guest_port: u16, socket: Tcp) {
    let Some(connection) = connect_publication() else {
        return;
    };
    register_flow(
        connection,
        spawn_task(publish(connection, guest_port, socket)),
    );
}

fn connect_publication() -> Option<ConnectionId> {
    let span = PUBLICATION_HOST_PORTS.end - PUBLICATION_HOST_PORTS.start;
    for _ in 0..MAX_HOST_PORT_ATTEMPTS {
        let host_port = NEXT_HOST_PORT.load(Ordering::Relaxed);
        NEXT_HOST_PORT.store(
            PUBLICATION_HOST_PORTS.start + (host_port - PUBLICATION_HOST_PORTS.start + 1) % span,
            Ordering::Relaxed,
        );
        let connected = switch().connect_publication(host_port);
        match connected {
            Ok(connection) => {
                transport::schedule_receive_queue();
                return Some(connection);
            }
            Err(VsockError::Busy) => {}
            Err(VsockError::Backpressure | VsockError::UnknownConnection) => return None,
        }
    }
    None
}

async fn open_publication(connection: ConnectionId, header: &Message) -> Result<(), SocketError> {
    if !wait_connected(connection).await {
        return Err(SocketError::Cancelled);
    }
    deliver_opening(connection, header).await
}

async fn wait_connected(connection: ConnectionId) -> bool {
    poll_fn(|context| {
        let mut state = lock_network();
        let device = switch();
        if device.is_current(connection) {
            Poll::Ready(true)
        } else if device.is_connecting(connection) {
            wait(&mut state, connection, context.waker());
            Poll::Pending
        } else {
            Poll::Ready(false)
        }
    })
    .await
}

async fn publish(connection: ConnectionId, guest_port: u16, socket: Tcp) {
    let opened = match socket.peer_address() {
        Ok(peer) => {
            matches!(
                run_before_deadline(
                    OPEN_TIMEOUT_SECS,
                    open_publication(
                        connection,
                        &Message::Publication {
                            guest_port,
                            peer: native_socket_address(peer),
                        },
                    )
                )
                .await,
                Ok(Ok(()))
            )
        }
        Err(_) => false,
    };
    if opened {
        tcp::relay(connection, &socket).await;
    } else {
        reset_flow(connection);
    }
    finish_flow(connection);
}

async fn publish_udp(
    connection: ConnectionId,
    guest_port: u16,
    host_port: u16,
    ipv6: bool,
    socket: Option<(Udp, udp::DatagramReceiver)>,
) {
    let opening = async {
        let (socket, receiver) = match socket {
            Some((socket, receiver)) => (socket, Some(receiver)),
            None => (
                broker::published_udp(host_port, ipv6)
                    .await
                    .map_err(super::broker_error)?,
                None,
            ),
        };
        open_publication(connection, &Message::PublicationUdp { guest_port }).await?;
        Ok::<_, SocketError>((socket, receiver))
    };
    match run_before_deadline(OPEN_TIMEOUT_SECS, opening).await {
        Ok(Ok((socket, receiver))) => {
            if udp::relay(connection, &socket, receiver).await.is_err() {
                reset_flow(connection);
            } else {
                shutdown_flow(connection);
            }
        }
        Ok(Err(_)) | Err(_) => reset_flow(connection),
    }
    finish_flow(connection);
}
