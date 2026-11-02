//! The agent's network control stream: readiness, then DNS queries answered by the broker.

use super::{
    broker_error, deliver_bytes, deliver_opening, disable_networking, host_ip_address,
    mark_control_ready, message_bytes, read_message, run_before_deadline,
};
use crate::terra::network::broker;
use futures_util::{
    future,
    lock::Mutex,
    stream::{self, TryStreamExt as _},
};
use terra_protocol::application::OPEN_TIMEOUT_SECS;
use terra_protocol::dns::{self, DnsTransport};
use terra_protocol::network_control::{DnsQuery, DnsResult, FrontendControl, MAX_DNS_QUERIES};
use terra_protocol::socket::Error as SocketError;
use terra_vsock_device::ConnectionId;

pub(super) async fn serve(connection: ConnectionId) {
    let _ = run(connection).await;
    disable_networking();
}

/// Answers the agent's connection with Ready, then up to [`MAX_DNS_QUERIES`] queries at once.
async fn run(connection: ConnectionId) -> Result<(), SocketError> {
    run_before_deadline(OPEN_TIMEOUT_SECS, async {
        mark_control_ready();
        deliver_opening(connection, message_bytes(&FrontendControl::Ready)?).await
    })
    .await??;
    let writer = Mutex::new(());
    stream::unfold((), |()| async move {
        read_message::<DnsQuery>(connection)
            .await
            .transpose()
            .map(|query| (query, ()))
    })
    .map_ok(|query| answer(connection, &writer, query))
    .try_buffer_unordered(MAX_DNS_QUERIES)
    .try_for_each(future::ok)
    .await
}

/// Resolves `query` and delivers its result whole; `writer` keeps results from interleaving.
async fn answer(
    connection: ConnectionId,
    writer: &Mutex<()>,
    query: DnsQuery,
) -> Result<(), SocketError> {
    let bytes = resolve(query.transport, &query.bytes).await;
    let result = message_bytes(&FrontendControl::DnsResult(DnsResult {
        id: query.id,
        bytes,
    }))?;
    let _guard = writer.lock().await;
    deliver_bytes(connection, result).await
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
