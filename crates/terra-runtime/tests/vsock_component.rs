#![allow(clippy::expect_used)]

#[path = "support/artifacts.rs"]
mod support;

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use terra_runtime::component::mmio::{DeviceError, Operation, Reply, Request};
use terra_runtime::component::vsock::{VsockDeviceHost, vsock_component_linker};
use terra_runtime::engine::device_engine;
use terra_runtime::test_support::{StandaloneHost, device_store};
use wasmtime::StoreContextMut;
use wasmtime::component::{
    Component, Source, StreamConsumer, StreamReader, StreamResult, TypedFunc,
};

type Serve = TypedFunc<(StreamReader<Request>,), (StreamReader<Reply>,)>;

struct ReplySink(Arc<Mutex<Vec<Reply>>>);

impl StreamConsumer<StandaloneHost<VsockDeviceHost>> for ReplySink {
    type Item = Reply;

    fn poll_consume(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        store: StoreContextMut<StandaloneHost<VsockDeviceHost>>,
        mut source: Source<'_, Reply>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        let mut reply = None;
        source.read(store, &mut reply)?;
        if let Some(reply) = reply {
            self.0.lock().expect("reply sink").push(reply);
        }
        Poll::Ready(Ok(StreamResult::Completed))
    }
}

async fn reset_and_read(
    store: &mut wasmtime::Store<StandaloneHost<VsockDeviceHost>>,
    serve: Serve,
) -> Vec<Reply> {
    let requests = [Operation::Reset, Operation::Read]
        .into_iter()
        .enumerate()
        .map(|(sequence, operation)| Request {
            sequence: sequence as u64,
            operation,
            offset: 0,
            width: 4,
            value: 0,
        })
        .collect::<Vec<_>>();
    let requests = StreamReader::new(&mut *store, requests).expect("MMIO requests");
    let (replies,) = serve
        .call_async(&mut *store, (requests,))
        .await
        .expect("MMIO server");
    let received = Arc::new(Mutex::new(Vec::new()));
    replies
        .pipe(&mut *store, ReplySink(Arc::clone(&received)))
        .expect("MMIO reply sink");
    tokio::time::timeout(
        Duration::from_secs(2),
        store.run_concurrent(async |_| {
            while received.lock().expect("reply sink").len() < 2 {
                tokio::task::yield_now().await;
            }
        }),
    )
    .await
    .expect("MMIO reply deadline")
    .expect("MMIO server runs");
    std::mem::take(&mut *received.lock().expect("reply sink"))
}

/// Closing the component stays terminal across MMIO reset and configure calls.
#[tokio::test(flavor = "current_thread")]
async fn component_close_keeps_transport_terminal() {
    let engine = device_engine().expect("engine");
    let component = Component::new(&engine, support::artifacts::wasm::VSOCK).expect("component");
    let mut store = device_store(
        &engine,
        VsockDeviceHost::new(
            terra_runtime::memory::GuestRam::new(64 * 1024).expect("guest memory"),
            terra_runtime::component::vsock::VsockHostService::default(),
        ),
    );
    let instance = vsock_component_linker(&engine)
        .expect("linker")
        .instantiate_async(&mut store, &component)
        .await
        .expect("instance");
    let api = component
        .get_export_index(None, "terra:vsock/api@0.1.0")
        .expect("API");
    let configure = instance
        .get_typed_func::<(), (Result<(), DeviceError>,)>(
            &mut store,
            component
                .get_export_index(Some(&api), "configure-device")
                .expect("configure export"),
        )
        .expect("configure");
    let close = instance
        .get_typed_func::<(), ()>(
            &mut store,
            component
                .get_export_index(Some(&api), "close")
                .expect("close export"),
        )
        .expect("close");
    let mmio = component
        .get_export_index(None, "terra:mmio/device@0.1.0")
        .expect("MMIO");
    let serve: Serve = instance
        .get_typed_func(
            &mut store,
            component
                .get_export_index(Some(&mmio), "serve")
                .expect("serve export"),
        )
        .expect("serve");
    configure
        .call_async(&mut store, ())
        .await
        .expect("configure call")
        .0
        .expect("configure result");
    let ready = reset_and_read(&mut store, serve).await;
    assert_eq!(ready[0].error, 0);
    assert_eq!(ready[1].error, 0);
    assert_eq!(ready[1].value, 0x7472_6976);

    close.call_async(&mut store, ()).await.expect("close");
    let closed = reset_and_read(&mut store, serve).await;
    assert_eq!(closed[0].error, 0);
    assert_eq!(closed[1].error, 4);
    assert!(matches!(
        configure
            .call_async(&mut store, ())
            .await
            .expect("configure after close")
            .0,
        Err(DeviceError::NotReady)
    ));
}
