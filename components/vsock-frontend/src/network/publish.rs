//! Trusted TCP and UDP publication over frontend-initiated vsock streams.

use super::{
    Task, batches, deliver_opening, finish_flow, lock_network, message_bytes, reset_flow,
    run_before_deadline, shutdown_flow, spawn_abortable, spawn_task, tcp, udp, wait,
    wait_for_publication,
};
use crate::terra::network::broker::{self, Listener, Tcp, Udp};
use crate::terra::network::types::Transport;
use crate::{switch, transport};
use futures_util::StreamExt as _;
use futures_util::future::{AbortHandle, AbortRegistration, Abortable, poll_fn};
use std::{
    num::NonZeroU16,
    sync::atomic::{AtomicU32, Ordering},
    task::{Poll, Waker},
};
use terra_protocol::application::OPEN_TIMEOUT_SECS;
use terra_protocol::network_control::Publication;
use terra_protocol::socket::Error as SocketError;
use terra_protocol::vsock::PUBLICATION_HOST_PORTS;
use terra_vsock_device::{ConnectionId, VsockError};

const MAX_HOST_PORT_ATTEMPTS: usize = terra_protocol::vsock::MAX_NETWORK_SOCKETS + 1;
static NEXT_HOST_PORT: AtomicU32 = AtomicU32::new(PUBLICATION_HOST_PORTS.start);

/// A published port with both ports nonzero.
#[derive(Clone, Copy)]
pub(super) struct PublishedPort {
    pub(super) host_port: NonZeroU16,
    pub(super) guest_port: NonZeroU16,
    pub(super) transport: Transport,
}

pub(super) fn start_listeners(ports: &[PublishedPort]) -> Vec<Task> {
    let mut listeners = Vec::new();
    for port in ports {
        let guest_port = port.guest_port;
        for ipv6 in [false, true] {
            let host_port = port.host_port.get();
            match port.transport {
                Transport::Tcp => {
                    if let Ok(listener) = broker::published_listener(host_port, ipv6) {
                        listeners.push(spawn_task(serve_tcp_listener(listener, guest_port)));
                    }
                }
                Transport::Udp => {
                    listeners.push(spawn_task(serve_udp_listener(guest_port, host_port, ipv6)));
                }
            }
        }
    }
    listeners
}

async fn serve_tcp_listener(listener: Listener, guest_port: NonZeroU16) {
    let (accepted, completion) = listener.accept();
    let mut sockets = std::pin::pin!(batches(accepted, 1));
    while let Some(sockets) = sockets.next().await {
        for socket in sockets {
            accept(guest_port, socket);
        }
    }
    let _ = completion.await;
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

async fn wait_publication_capacity() -> (ConnectionId, AbortRegistration) {
    poll_fn(|context| connect_publication(Some(context.waker())).map_or(Poll::Pending, Poll::Ready))
        .await
}

async fn serve_udp_listener(guest_port: NonZeroU16, host_port: u16, ipv6: bool) {
    let mut socket = None;
    loop {
        let (connection, registration) = wait_publication_capacity().await;
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
        receiver.first_datagrams = Some(datagrams);
        socket = Some((reopened, receiver));
    }
}

/// Open the guest stream for one accepted host connection; without capacity the host connection is dropped.
fn accept(guest_port: NonZeroU16, socket: Tcp) {
    let Some((connection, registration)) = connect_publication(None) else {
        return;
    };
    spawn_abortable(publish(connection, guest_port, socket), registration);
}

fn connect_publication(
    capacity_waker: Option<&Waker>,
) -> Option<(ConnectionId, AbortRegistration)> {
    let mut state = lock_network();
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
                let (abort, registration) = AbortHandle::new_pair();
                state.flow_tasks.insert(connection, Task(abort));
                drop(state);
                transport::schedule_receive_queue();
                return Some((connection, registration));
            }
            Err(VsockError::Busy) => {}
            Err(VsockError::Backpressure | VsockError::UnknownConnection) => break,
        }
    }
    if let Some(waker) = capacity_waker {
        wait_for_publication(&mut state, waker);
    }
    None
}

async fn open_publication(
    connection: ConnectionId,
    publication: Publication,
) -> Result<(), SocketError> {
    if !wait_connected(connection).await {
        return Err(SocketError::Cancelled);
    }
    deliver_opening(connection, message_bytes(&publication)?).await
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

async fn publish(connection: ConnectionId, guest_port: NonZeroU16, socket: Tcp) {
    let opened = matches!(
        run_before_deadline(
            OPEN_TIMEOUT_SECS,
            open_publication(connection, Publication::Tcp { guest_port }),
        )
        .await,
        Ok(Ok(()))
    );
    if opened {
        tcp::relay(connection, &socket).await;
    } else {
        reset_flow(connection);
    }
    finish_flow(connection);
}

async fn publish_udp(
    connection: ConnectionId,
    guest_port: NonZeroU16,
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
        open_publication(connection, Publication::Udp { guest_port }).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{drain_flow_tasks, synchronize_flow_tasks};
    use std::{future::Future as _, task::Context};
    use terra_vsock_device::{VsockHeader, VsockSwitch};

    #[test]
    fn udp_listener_waits_for_publication_capacity_at_startup() {
        let _guard = crate::SWITCH_TEST.lock().unwrap();
        let mut device = VsockSwitch::with_network_socket_capacity(true, 1);
        device
            .connect_publication(PUBLICATION_HOST_PORTS.start)
            .unwrap();
        let previous = std::mem::replace(&mut *switch(), device);

        let mut listener = std::pin::pin!(serve_udp_listener(
            NonZeroU16::new(53).unwrap(),
            5353,
            false
        ));
        assert!(
            listener
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let mut state = lock_network();
        assert_eq!(state.publication_waiters.len(), 1);
        state.publication_waiters.clear();
        *switch() = previous;
    }

    #[test]
    fn publication_task_waits_for_reply_drain_or_connection_retirement() {
        let _guard = crate::SWITCH_TEST.lock().unwrap();
        *switch() = VsockSwitch::new();
        let (connection, registration) = connect_publication(None).unwrap();
        assert!(switch().is_connecting(connection));
        assert!(!synchronize_flow_tasks());
        assert!(!registration.handle().is_aborted());

        let request = switch().take_reply(usize::MAX).unwrap();
        let response = VsockHeader {
            src_cid: request.header.dst_cid,
            dst_cid: request.header.src_cid,
            src_port: connection.guest_port,
            dst_port: connection.host_port,
            op: 2,
            ..request.header
        };
        switch().rx(&response, &[]);
        shutdown_flow(connection);
        finish_flow(connection);
        assert!(!drain_flow_tasks());
        let shutdown = switch().take_reply(usize::MAX).unwrap();
        transport::set_test_pending_reply(Some(shutdown));
        assert!(!drain_flow_tasks());
        assert!(!registration.handle().is_aborted());
        transport::set_test_pending_reply(None);
        assert!(drain_flow_tasks());
        assert!(registration.handle().is_aborted());
        assert!(switch().is_retiring(connection));

        let (refused, registration) = connect_publication(None).unwrap();
        finish_flow(refused);
        switch().rx(
            &VsockHeader {
                op: 3,
                dst_port: refused.host_port,
                ..response
            },
            &[],
        );
        assert!(synchronize_flow_tasks());
        let state = lock_network();
        assert!(state.flow_tasks.is_empty());
        assert!(state.draining.is_empty());
        assert!(registration.handle().is_aborted());
    }
}
