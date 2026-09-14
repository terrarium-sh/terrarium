#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use terra_runtime::component::vmm::mmio::{Operation, Reply as MmioReply, Request};
use terra_runtime::engine::{device_engine, device_store_with_ram, vsock_component_linker};
use terra_vsock_device::VsockHeader;
use wasmtime::StoreContextMut;
use wasmtime::component::{
    Accessor, Component, ComponentType, Lift, Source, StreamConsumer, StreamReader, StreamResult,
    TypedFunc,
};

#[derive(ComponentType, Lift)]
#[component(record)]
struct Reply {
    header: Vec<u8>,
    payload: Vec<u8>,
}

type Replies = TypedFunc<(u32, u32), (Vec<Reply>,)>;
type Receive =
    TypedFunc<(Vec<u8>,), (Result<(), terra_runtime::component::vsock::bindings::Error>,)>;
type Serve = TypedFunc<(StreamReader<Request>,), (StreamReader<MmioReply>,)>;

async fn next_reply(
    accessor: &Accessor<terra_runtime::engine::DeviceHost>,
    replies: Replies,
    operation: u16,
) -> Reply {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let (batch,) = replies
                .call_concurrent(accessor, (16, 65536))
                .await
                .unwrap();
            if let Some(reply) = batch
                .into_iter()
                .find(|reply| VsockHeader::parse(&reply.header).unwrap().0.op == operation)
            {
                return reply;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("guest reply progresses")
}

async fn guest_packet(
    accessor: &Accessor<terra_runtime::engine::DeviceHost>,
    receive: Receive,
    port: u32,
    operation: u16,
    flags: u32,
    payload: &[u8],
) {
    let header = VsockHeader {
        src_cid: 3,
        dst_cid: 2,
        src_port: 6000,
        dst_port: port,
        len: u32::try_from(payload.len()).unwrap(),
        type_: 1,
        op: operation,
        flags,
        buf_alloc: 65536,
        fwd_cnt: 0,
    };
    let mut packet = header.encode().to_vec();
    packet.extend_from_slice(payload);
    assert!(
        receive
            .call_concurrent(accessor, (packet,))
            .await
            .unwrap()
            .0
            .is_ok()
    );
}

async fn read_until_eof(socket: &mut terra_io::local::LocalStream) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut received = Vec::new();
        loop {
            let mut bytes = [0; 64];
            match socket.read(&mut bytes) {
                Ok(0) => return received,
                Ok(count) => received.extend_from_slice(&bytes[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(error) => panic!("host read: {error}"),
            }
        }
    })
    .await
    .expect("guest FIN reaches host socket")
}

async fn wait_for_no_connections(
    accessor: &Accessor<terra_runtime::engine::DeviceHost>,
    count: TypedFunc<(), (u32,)>,
) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while count.call_concurrent(accessor, ()).await.unwrap().0 != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("closed host client releases its pending guest connection");
}

fn live_clients(accessor: &Accessor<terra_runtime::engine::DeviceHost>) -> usize {
    accessor.with(|mut access| access.get().vsock_service_mut().live_clients())
}

async fn wait_for_no_clients(accessor: &Accessor<terra_runtime::engine::DeviceHost>) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while live_clients(accessor) != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("completed host client releases its native grant");
}

async fn serve_and_disconnect(
    accessor: &Accessor<terra_runtime::engine::DeviceHost>,
    replies: Replies,
    receive: Receive,
    count: TypedFunc<(), (u32,)>,
    client: &mut terra_io::local::LocalStream,
    payload: &[u8],
) {
    let request = next_reply(accessor, replies, 1).await;
    let port = VsockHeader::parse(&request.header).unwrap().0.src_port;
    guest_packet(accessor, receive, port, 2, 0, &[]).await;
    client.write_all(payload).unwrap();
    assert_eq!(next_reply(accessor, replies, 5).await.payload, payload);
    guest_packet(accessor, receive, port, 4, 2, &[]).await;
    assert!(read_until_eof(client).await.is_empty());
    client.shutdown(std::net::Shutdown::Write).unwrap();
    wait_for_no_connections(accessor, count).await;
    wait_for_no_clients(accessor).await;
}

struct Worker {
    run: TypedFunc<(), (Result<(), terra_runtime::component::vsock::bindings::Error>,)>,
    close: TypedFunc<(), ()>,
    replies: Replies,
    receive: Receive,
    count: TypedFunc<(), (u32,)>,
}

struct ReplySink(Arc<Mutex<Vec<MmioReply>>>);

impl StreamConsumer<terra_runtime::engine::DeviceHost> for ReplySink {
    type Item = MmioReply;

    fn poll_consume(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        store: StoreContextMut<terra_runtime::engine::DeviceHost>,
        mut source: Source<'_, Self::Item>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        let mut reply = None;
        source.read(store, &mut reply)?;
        if let Some(reply) = reply {
            self.0.lock().expect("reply sink lock").push(reply);
        }
        Poll::Ready(Ok(StreamResult::Completed))
    }
}

async fn drive_transport_ready(
    store: &mut wasmtime::Store<terra_runtime::engine::DeviceHost>,
    serve: Serve,
) {
    let requests = StreamReader::new(
        &mut *store,
        [1_u8, 3, 11, 15]
            .into_iter()
            .map(|status| Request {
                sequence: u64::from(status),
                operation: Operation::Write,
                offset: 0x70,
                width: 4,
                value: u64::from(status),
            })
            .collect::<Vec<_>>(),
    )
    .expect("status stream");
    let (replies,) = serve
        .call_async(&mut *store, (requests,))
        .await
        .expect("MMIO server starts");
    let received = Arc::new(Mutex::new(Vec::new()));
    replies
        .pipe(&mut *store, ReplySink(Arc::clone(&received)))
        .expect("reply stream attaches");
    tokio::time::timeout(Duration::from_secs(2), async {
        store
            .run_concurrent(async |_| {
                while received.lock().expect("reply sink lock").len() != 4 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("MMIO server runs");
    })
    .await
    .expect("MMIO status replies");
    assert!(
        received
            .lock()
            .expect("reply sink lock")
            .iter()
            .all(|reply| reply.error == 0)
    );
}

async fn create_worker(
    listener: terra_io::local::LocalListener,
) -> (wasmtime::Store<terra_runtime::engine::DeviceHost>, Worker) {
    let engine = device_engine().unwrap();
    let mut store = device_store_with_ram(&engine, terra_runtime::SyntheticRam::new(4096).unwrap());
    store.data_mut().set_vsock_service(
        terra_runtime::component::vsock::host::VsockHostService::new(
            vec![2, 0, 0, 0, b'{', b'}'],
            Some(listener),
            None,
        )
        .unwrap(),
    );
    let component = Component::new(
        &engine,
        include_bytes!(
            "../../../components/vsock/target/wasm32-wasip3/release/terra_vsock_component.wasm"
        ),
    )
    .unwrap();
    let instance = vsock_component_linker(&engine)
        .unwrap()
        .instantiate_async(&mut store, &component)
        .await
        .unwrap();
    let interface = component
        .get_export_index(None, "terra:vsock/api@0.1.0")
        .unwrap();
    let export = |name| component.get_export_index(Some(&interface), name).unwrap();
    let configure_device = instance
        .get_typed_func::<(), (Result<(), terra_runtime::engine::DeviceError>,)>(
            &mut store,
            export("configure-device"),
        )
        .unwrap();
    assert!(
        configure_device
            .call_async(&mut store, ())
            .await
            .unwrap()
            .0
            .is_ok()
    );
    let device = component
        .get_export_index(None, "terra:mmio/device@0.1.0")
        .unwrap();
    let serve = instance
        .get_typed_func(
            &mut store,
            component.get_export_index(Some(&device), "serve").unwrap(),
        )
        .unwrap();
    drive_transport_ready(&mut store, serve).await;
    let configure = instance
        .get_typed_func::<(bool,), ()>(&mut store, export("configure-worker"))
        .unwrap();
    configure.call_async(&mut store, (false,)).await.unwrap();
    let run = instance
        .get_typed_func::<(), (Result<(), terra_runtime::component::vsock::bindings::Error>,)>(
            &mut store,
            export("run"),
        )
        .unwrap();
    let close = instance
        .get_typed_func::<(), ()>(&mut store, export("close"))
        .unwrap();
    let replies: Replies = instance
        .get_typed_func(&mut store, export("take-replies"))
        .unwrap();
    let receive: Receive = instance
        .get_typed_func(&mut store, export("receive"))
        .unwrap();
    let count = instance
        .get_typed_func::<(), (u32,)>(&mut store, export("connection-count"))
        .unwrap();

    (
        store,
        Worker {
            run,
            close,
            replies,
            receive,
            count,
        },
    )
}

/// Exercise the real WASI worker and granted host socket: pre-handshake bytes
/// survive, guest FIN drains output, and the other half remains usable.
#[tokio::test(flavor = "current_thread")]
async fn client_handshake_and_half_close_preserve_both_directions() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("agent.sock");
    let listener = terra_io::local::LocalListener::bind(&path).unwrap();
    let mut client = terra_io::local::LocalStream::connect(&path).unwrap();
    client.set_nonblocking(true).unwrap();
    client.write_all(b"early").unwrap();

    let (
        mut store,
        Worker {
            run,
            close,
            replies,
            receive,
            count,
        },
    ) = create_worker(listener).await;

    store
        .run_concurrent(async |accessor| {
            let running = run.call_concurrent(accessor, ());
            tokio::pin!(running);
            let exchange = async {
                let request = next_reply(accessor, replies, 1).await;
                let port = VsockHeader::parse(&request.header).unwrap().0.src_port;
                tokio::time::sleep(Duration::from_millis(10)).await;
                guest_packet(accessor, receive, port, 2, 0, &[]).await;
                assert_eq!(next_reply(accessor, replies, 5).await.payload, b"early");
                guest_packet(accessor, receive, port, 5, 0, b"response").await;
                guest_packet(accessor, receive, port, 4, 2, &[]).await;
                assert_eq!(read_until_eof(&mut client).await, b"response");
                client.write_all(b"after-fin").unwrap();
                assert_eq!(next_reply(accessor, replies, 5).await.payload, b"after-fin");
                client.shutdown(std::net::Shutdown::Write).unwrap();
                tokio::time::timeout(Duration::from_secs(2), async {
                    while count.call_concurrent(accessor, ()).await.unwrap().0 != 0 {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .expect("both halves closed release the connection");
                wait_for_no_clients(accessor).await;
                tokio::time::timeout(Duration::from_secs(2), close.call_concurrent(accessor, ()))
                    .await
                    .expect("WASI close waits for worker cleanup")
                    .unwrap();
                assert_eq!(live_clients(accessor), 0);
            };
            let (result, ()) = tokio::join!(running, exchange);
            assert!(result.unwrap().0.is_ok());
            Ok::<(), wasmtime::Error>(())
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(store.data_mut().vsock_service_mut().live_clients(), 0);
}

/// A client disconnect does not retire the component's one granted listener.
#[tokio::test(flavor = "current_thread")]
async fn sequential_clients_share_one_running_vsock_component() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sequential.sock");
    let listener = terra_io::local::LocalListener::bind(&path).unwrap();
    let (
        mut store,
        Worker {
            run,
            close,
            replies,
            receive,
            count,
        },
    ) = create_worker(listener).await;

    store
        .run_concurrent(async |accessor| {
            let running = run.call_concurrent(accessor, ());
            tokio::pin!(running);
            let clients = async {
                for payload in [b"first".as_slice(), b"second".as_slice()] {
                    let mut client = terra_io::local::LocalStream::connect(&path).unwrap();
                    client.set_nonblocking(true).unwrap();
                    serve_and_disconnect(accessor, replies, receive, count, &mut client, payload)
                        .await;
                    assert_eq!(live_clients(accessor), 0);
                }
                tokio::time::timeout(Duration::from_secs(2), close.call_concurrent(accessor, ()))
                    .await
                    .expect("explicit close stops the component")
                    .unwrap();
            };
            let (result, ()) = tokio::join!(running, clients);
            assert!(result.unwrap().0.is_ok());
            Ok::<(), wasmtime::Error>(())
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(store.data_mut().vsock_service_mut().live_clients(), 0);
    assert!(terra_io::local::LocalStream::connect(&path).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn close_before_run_releases_configuration_and_finishes_without_starting_clients() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("unstarted.sock");
    let listener = terra_io::local::LocalListener::bind(&path).unwrap();
    let _client = terra_io::local::LocalStream::connect(&path).unwrap();
    let (mut store, worker) = create_worker(listener).await;
    tokio::time::timeout(
        Duration::from_secs(2),
        worker.close.call_async(&mut store, ()),
    )
    .await
    .expect("unstarted worker closes")
    .unwrap();
    assert_eq!(store.data_mut().vsock_service_mut().live_clients(), 0);
    assert!(
        worker
            .run
            .call_async(&mut store, ())
            .await
            .unwrap()
            .0
            .is_ok()
    );
}

/// Closing a device retires the live client I/O tasks before returning.
#[tokio::test(flavor = "current_thread")]
async fn close_releases_an_idle_client() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("idle.sock");
    let listener = terra_io::local::LocalListener::bind(&path).unwrap();
    let _client = terra_io::local::LocalStream::connect(&path).unwrap();
    let (
        mut store,
        Worker {
            run,
            close,
            replies,
            receive,
            count,
        },
    ) = create_worker(listener).await;
    store
        .run_concurrent(async |accessor| {
            let running = run.call_concurrent(accessor, ());
            tokio::pin!(running);
            let stop = async {
                let request = next_reply(accessor, replies, 1).await;
                let port = VsockHeader::parse(&request.header).unwrap().0.src_port;
                guest_packet(accessor, receive, port, 2, 0, &[]).await;
                assert_eq!(count.call_concurrent(accessor, ()).await.unwrap().0, 1);
                tokio::time::timeout(Duration::from_secs(2), close.call_concurrent(accessor, ()))
                    .await
                    .expect("WASI close waits for worker cleanup")
                    .unwrap();
                assert_eq!(live_clients(accessor), 0);
            };
            let (result, ()) = tokio::join!(running, stop);
            assert!(result.unwrap().0.is_ok());
            Ok::<(), wasmtime::Error>(())
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(store.data_mut().vsock_service_mut().live_clients(), 0);
}

/// A host retry that closes before the guest accepts must not retain one of
/// the fixed client grants. Otherwise repeated agent-hello retries exhaust the
/// listener before the agent becomes ready.
#[tokio::test(flavor = "current_thread")]
async fn pre_handshake_client_close_releases_the_listener_grant() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("retry.sock");
    let listener = terra_io::local::LocalListener::bind(&path).unwrap();
    let (
        mut store,
        Worker {
            run,
            close,
            replies,
            count,
            ..
        },
    ) = create_worker(listener).await;

    store
        .run_concurrent(async |accessor| {
            let running = run.call_concurrent(accessor, ());
            tokio::pin!(running);
            let retries = async {
                for _ in 0..65 {
                    drop(terra_io::local::LocalStream::connect(&path).unwrap());
                    let _ = next_reply(accessor, replies, 1).await;
                    wait_for_no_connections(accessor, count).await;
                    wait_for_no_clients(accessor).await;
                }
                tokio::time::timeout(Duration::from_secs(2), close.call_concurrent(accessor, ()))
                    .await
                    .expect("WASI close waits for worker cleanup")
                    .unwrap();
                assert_eq!(live_clients(accessor), 0);
            };
            let (result, ()) = tokio::join!(running, retries);
            assert!(result.unwrap().0.is_ok());
            Ok::<(), wasmtime::Error>(())
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(store.data_mut().vsock_service_mut().live_clients(), 0);
}

/// Diagnostic sink ownership must not keep a closing box worker alive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_close_releases_the_diagnostic_sink() {
    let engine = device_engine().unwrap();
    let mut runtime = terra_runtime::box_runtime::BoxRuntime::new(
        &engine,
        terra_runtime::box_runtime::BoxHost::new(),
    )
    .unwrap();
    let router = Component::new(
        &engine,
        include_bytes!(
            "../../../components/vmm/target/wasm32-wasip3/release/terra_vmm_component.wasm"
        ),
    )
    .unwrap();
    runtime.initialize_mmio(&router).await.unwrap();
    let output = tempfile::NamedTempFile::new().unwrap();
    // SAFETY: the embedded artifact is produced by the trusted build for this runtime.
    #[allow(unsafe_code)]
    let channel = unsafe {
        terra_runtime::component::vsock::VsockChannel::from_trusted_shared(
            &mut runtime,
            terra_runtime::SyntheticRam::new(4096).unwrap(),
            include_bytes!("../../../build/terra-vsock-component.cwasm"),
            vec![2, 0, 0, 0, b'{', b'}'],
            false,
            None,
            None,
            Some(output.reopen().unwrap()),
            std::sync::Arc::new(|_| Ok(())),
        )
        .await
        .unwrap()
    };
    let runtime = runtime.start();
    tokio::time::timeout(Duration::from_secs(3), channel.close_async())
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), runtime.join())
        .await
        .unwrap()
        .unwrap();
}
