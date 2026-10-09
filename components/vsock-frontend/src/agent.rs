use crate::{network, switch, terra, wit_stream};
use futures_util::future::try_join;
use terra::vsock::frontend_stream;
use terra_vsock_device::{ConnectionId, Role};

pub(crate) fn service(relay: &mut Option<network::Flow>) -> bool {
    let current = switch().connection(Role::Agent);
    if let Some(previous) = relay {
        if Some(previous.connection) != current {
            drop(previous.task.take());
        }
        if !network::is_flow_drained(previous) {
            return false;
        }
        if switch().is_current(previous.connection) {
            network::reset_flow(previous.connection);
        }
        *relay = None;
        return true;
    }
    let Some(connection) = current else {
        return false;
    };
    *relay = Some(network::spawn_flow(connection, async move {
        if run(connection).await.is_err() {
            network::reset_flow(connection);
        }
    }));
    true
}

async fn run(connection: ConnectionId) -> Result<(), ()> {
    let (input, host_input) = wit_stream::new();
    let output = frontend_stream::connect(connection.generation, host_input).map_err(|_| ())?;
    try_join(
        network::pump_upstream(connection, input),
        network::pump_downstream(connection, output, None),
    )
    .await
    .map(|_| ())
    .map_err(|_| ())
}
