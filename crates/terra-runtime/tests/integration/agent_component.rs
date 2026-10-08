use crate::support;

use terra_runtime::component::agent::{
    AgentEvent, AgentHost, AgentHostService, agent_component_linker,
};
use terra_runtime::component::vsock::streams::StreamEndpoint;
use terra_runtime::engine::device_engine;
use wasmtime::component::{Component, Source, StreamConsumer, StreamResult};

struct EventRecorder(tokio::sync::mpsc::UnboundedSender<AgentEvent>);

impl StreamConsumer<AgentHost> for EventRecorder {
    type Item = AgentEvent;

    fn poll_consume(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
        store: wasmtime::StoreContextMut<AgentHost>,
        mut source: Source<'_, AgentEvent>,
        finish: bool,
    ) -> std::task::Poll<wasmtime::Result<StreamResult>> {
        if finish {
            return std::task::Poll::Ready(Ok(StreamResult::Cancelled));
        }
        let mut events = Vec::with_capacity(1);
        source.read(store, &mut events)?;
        for event in events {
            let _ = self.0.send(event);
        }
        std::task::Poll::Ready(Ok(StreamResult::Completed))
    }
}

/// Subscribing to events starts the worker without a separate run export; closing
/// stays terminal across new subscriptions and endpoint replacements.
#[tokio::test(flavor = "current_thread")]
async fn events_start_worker_and_close_keeps_transport_terminal() {
    let engine = device_engine().expect("engine");
    let component = Component::new(&engine, support::artifacts::wasm::AGENT).expect("component");
    let (mut frontend, role) = StreamEndpoint::pair();
    let mut store =
        wasmtime::Store::new(&engine, AgentHost::new(role, AgentHostService::default()));
    store.set_hostcall_fuel(terra_limits::MAX_COMPONENT_HOSTCALL_BYTES);
    store.set_epoch_deadline(1);
    let instance = agent_component_linker(&engine)
        .expect("linker")
        .instantiate_async(&mut store, &component)
        .await
        .expect("instance");
    let api = component
        .get_export_index(None, "terra:agent/api@0.1.0")
        .expect("API");
    let close = instance
        .get_typed_func::<(), ()>(
            &mut store,
            component
                .get_export_index(Some(&api), "close")
                .expect("close export"),
        )
        .expect("close");
    let events = instance
        .get_typed_func::<(), (wasmtime::component::StreamReader<AgentEvent>,)>(
            &mut store,
            component
                .get_export_index(Some(&api), "events")
                .expect("events export"),
        )
        .expect("events");
    assert!(component.get_export_index(Some(&api), "run").is_none());
    frontend.connect(1).expect("initial connection");
    let (stream,) = events
        .call_async(&mut store, ())
        .await
        .expect("initial events");
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    stream
        .pipe(&mut store, EventRecorder(sender))
        .expect("event recorder");
    store
        .run_concurrent(async |accessor| {
            let connected =
                tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
                    .await
                    .expect("worker started")
                    .expect("connected event");
            assert!(matches!(connected, AgentEvent::Connected));
            close.call_concurrent(accessor, ()).await.expect("close");
        })
        .await
        .expect("worker lifecycle");
    frontend.disconnect(1);
    for generation in 2..=3 {
        frontend.connect(generation).expect("connect");
        let (mut subscription,) = events
            .call_async(&mut store, ())
            .await
            .expect("events after close");
        subscription
            .close(&mut store)
            .expect("closed event subscription");
        assert!(
            frontend
                .try_read(generation, 65536)
                .expect("output")
                .is_empty()
        );
        frontend.disconnect(generation);
    }
    close
        .call_async(&mut store, ())
        .await
        .expect("repeated close");
}
