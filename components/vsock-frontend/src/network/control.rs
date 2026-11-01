//! The agent's network control stream: readiness, then DNS queries answered by the broker.

use super::{
    broker_error, deliver_bytes, deliver_opening, disable_networking, host_ip_address,
    mark_control_ready, message_bytes, read_message, run_before_deadline,
};
use crate::terra::network::broker;
use futures_util::{
    FutureExt as _,
    future::{Either, select},
    lock::Mutex,
    stream::{FuturesUnordered, StreamExt as _},
};
use terra_protocol::application::OPEN_TIMEOUT_SECS;
use terra_protocol::dns;
use terra_protocol::network_control::{
    AgentControl, DnsPayload, DnsTransport, FrontendControl, MAX_DNS_QUERIES,
};
use terra_protocol::socket::Error as SocketError;
use terra_vsock_device::ConnectionId;

pub(super) async fn serve(connection: ConnectionId) {
    let _ = run(connection).await;
    disable_networking();
}

async fn run(connection: ConnectionId) -> Result<(), SocketError> {
    run_before_deadline(OPEN_TIMEOUT_SECS, async {
        if read_message(connection).await? != Some(AgentControl::Hello) {
            return Err(SocketError::Protocol);
        }
        mark_control_ready();
        deliver_opening(connection, message_bytes(&FrontendControl::Ready)?).await
    })
    .await??;
    let writer = Mutex::new(());
    let mut queries = FuturesUnordered::new();
    loop {
        let next = if queries.len() < MAX_DNS_QUERIES {
            Either::Left(read_message::<AgentControl>(connection).boxed_local())
        } else {
            Either::Right(std::future::pending().boxed_local())
        };
        let completed = if queries.is_empty() {
            Either::Right(std::future::pending().boxed_local())
        } else {
            Either::Left(queries.next())
        };
        let event = match select(next, completed).await {
            Either::Left((frame, _)) => Either::Left(frame?),
            Either::Right((completed, _)) => Either::Right(completed),
        };
        match event {
            Either::Left(Some(AgentControl::DnsQuery(DnsPayload {
                id,
                transport,
                bytes,
            }))) => {
                let writer = &writer;
                queries.push(async move {
                    let bytes = resolve(transport, &bytes).await;
                    let _guard = writer.lock().await;
                    let result = FrontendControl::DnsResult(DnsPayload {
                        id,
                        transport,
                        bytes,
                    });
                    deliver_bytes(connection, message_bytes(&result)?).await
                });
            }
            Either::Left(Some(AgentControl::Hello)) => return Err(SocketError::Protocol),
            Either::Left(None) => return Ok(()),
            Either::Right(Some(result)) => result?,
            Either::Right(None) => {}
        }
    }
}

async fn resolve(transport: DnsTransport, query: &[u8]) -> Vec<u8> {
    let Some(question) = dns::Question::parse(query) else {
        return dns::error_response(query, dns::Rcode::ServFail);
    };
    match broker::resolve(question.name.as_bytes().to_vec()).await {
        Ok(addresses) => {
            let addresses = addresses
                .into_iter()
                .map(host_ip_address)
                .collect::<Vec<_>>();
            question.answer(&addresses, transport)
        }
        Err(error) if broker_error(error) == SocketError::AccessDenied => {
            question.error(dns::Rcode::NxDomain)
        }
        Err(_) => question.error(dns::Rcode::ServFail),
    }
}
