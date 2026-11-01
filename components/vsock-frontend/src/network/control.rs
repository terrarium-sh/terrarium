//! The agent's network control stream: version readiness, then DNS queries answered by the broker.

use super::{
    broker_error, deliver_message, deliver_opening, disable_networking, host_ip_address,
    mark_control_ready, read_message, run_before_deadline,
};
use crate::terra::network::broker;
use futures_util::{
    FutureExt as _,
    future::{Either, select},
    lock::Mutex,
    stream::{FuturesUnordered, StreamExt as _},
};
use terra_protocol::application::{
    DnsTransport, MAX_DNS_QUERIES, Message, OPEN_TIMEOUT_SECS, StreamDecoder,
};
use terra_protocol::dns;
use terra_protocol::socket::Error as SocketError;
use terra_vsock_device::ConnectionId;

pub(super) async fn serve(connection: ConnectionId) {
    let _ = run(connection).await;
    disable_networking();
}

async fn run(connection: ConnectionId) -> Result<(), SocketError> {
    let mut decoder = StreamDecoder::default();
    run_before_deadline(OPEN_TIMEOUT_SECS, async {
        if read_message(connection, &mut decoder).await? != Some(Message::Hello) {
            return Err(SocketError::Protocol);
        }
        mark_control_ready();
        deliver_opening(connection, &Message::Ready).await
    })
    .await??;
    let writer = Mutex::new(());
    let mut queries = FuturesUnordered::new();
    loop {
        let next = if queries.len() < MAX_DNS_QUERIES {
            Either::Left(read_message(connection, &mut decoder).boxed_local())
        } else {
            Either::Right(std::future::pending().boxed_local())
        };
        let completed = if queries.is_empty() {
            Either::Right(std::future::pending().boxed_local())
        } else {
            Either::Left(queries.next())
        };
        let event = match select(next, completed).await {
            Either::Left((message, _)) => Either::Left(message?),
            Either::Right((completed, _)) => Either::Right(completed),
        };
        match event {
            Either::Left(Some(Message::DnsQuery {
                id,
                transport,
                bytes,
            })) => {
                let writer = &writer;
                queries.push(async move {
                    let bytes = resolve(transport, &bytes).await;
                    let _guard = writer.lock().await;
                    let result = Message::DnsResult {
                        id,
                        transport,
                        bytes,
                    };
                    deliver_message(connection, &result).await
                });
            }
            Either::Left(Some(_)) => return Err(SocketError::Protocol),
            Either::Left(None) => return Ok(()),
            Either::Right(Some(result)) => result?,
            Either::Right(None) => {}
        }
    }
}

async fn resolve(transport: DnsTransport, bytes: &[u8]) -> Vec<u8> {
    let query = transport.message(bytes);
    let mut response = if let Some(name) = dns::question_name(query) {
        match broker::resolve(name.into_bytes()).await {
            Ok(addresses) if addresses.len() <= terra_protocol::network::MAX_NETWORK_ADDRESSES => {
                dns::build_ip_response(
                    query,
                    &addresses
                        .into_iter()
                        .map(host_ip_address)
                        .collect::<Vec<_>>(),
                    60,
                )
            }
            Err(error) if broker_error(error) == SocketError::AccessDenied => {
                dns::error_response(query, dns::DNS_RCODE_NXDOMAIN)
            }
            Ok(_) | Err(_) => dns::error_response(query, dns::DNS_RCODE_SERVFAIL),
        }
    } else {
        dns::error_response(query, dns::DNS_RCODE_SERVFAIL)
    };
    if response.len() > terra_protocol::socket::MAX_DNS_BYTES {
        response = dns::error_response(query, dns::DNS_RCODE_SERVFAIL);
    }
    match transport {
        DnsTransport::Datagram => dns::bound_udp_response(query, response),
        DnsTransport::Stream => transport.frame(response).unwrap_or_default(),
    }
}
