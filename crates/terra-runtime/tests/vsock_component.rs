#![allow(clippy::expect_used, clippy::unwrap_used)]

use terra_runtime::engine::test_support::device_store;
use terra_runtime::engine::{device_engine, vsock_component_linker};
use wasmtime::component::{Component, TypedFunc, wit_parser::ItemName};

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    wasmtime::component::ComponentType,
    wasmtime::component::Lift,
    wasmtime::component::Lower,
)]
#[component(enum)]
#[repr(u8)]
#[allow(dead_code)]
enum ComponentError {
    #[component(name = "table-full")]
    TableFull,
    #[component(name = "backpressure")]
    Backpressure,
    #[component(name = "unknown-connection")]
    UnknownConnection,
    #[component(name = "malformed")]
    Malformed,
}

#[derive(wasmtime::component::ComponentType, wasmtime::component::Lift)]
#[component(record)]
struct ComponentConnection {
    #[component(name = "guest-port")]
    guest_port: u32,
    #[component(name = "host-port")]
    host_port: u32,
}

#[derive(wasmtime::component::ComponentType, wasmtime::component::Lift)]
#[component(record)]
#[allow(dead_code)]
struct ComponentReply {
    header: Vec<u8>,
    payload: Vec<u8>,
}

const COMPONENT: &[u8] = include_bytes!(
    "../../../components/vsock/target/wasm32-wasip3/release/terra_vsock_component.wasm"
);

type ComponentResult<T> = (Result<T, ComponentError>,);
type Receive = TypedFunc<(Vec<u8>,), ComponentResult<()>>;
type Deliver = TypedFunc<(u32, u32, Vec<u8>), ComponentResult<()>>;
type Consume = TypedFunc<(u32, u32, u32), (Vec<u8>,)>;
type Connections = TypedFunc<(u32,), (Vec<ComponentConnection>,)>;

fn export(name: &str) -> ItemName {
    format!("terra:vsock/api.{name}@0.1.0")
        .parse()
        .expect("component export name")
}

fn packet(op: u16, len: u32) -> Vec<u8> {
    let mut packet = Vec::with_capacity(44 + len as usize);
    packet.extend_from_slice(&3_u64.to_le_bytes());
    packet.extend_from_slice(&2_u64.to_le_bytes());
    packet.extend_from_slice(&100_u32.to_le_bytes());
    packet.extend_from_slice(&6001_u32.to_le_bytes());
    packet.extend_from_slice(&len.to_le_bytes());
    packet.extend_from_slice(&1_u16.to_le_bytes());
    packet.extend_from_slice(&op.to_le_bytes());
    packet.extend_from_slice(&0_u32.to_le_bytes());
    packet.extend_from_slice(&65536_u32.to_le_bytes());
    packet.extend_from_slice(&0_u32.to_le_bytes());
    packet
}

#[tokio::test(flavor = "current_thread")]
async fn component_releases_credit_after_consumer_drains_data() {
    let engine = device_engine().expect("engine");
    let linker = vsock_component_linker(&engine).expect("linker");
    let component = Component::new(&engine, COMPONENT).expect("component");
    let mut store = device_store(
        &engine,
        terra_runtime::engine::VsockDeviceHost::new(
            terra_runtime::SyntheticRam::new(64 * 1024).unwrap(),
            terra_runtime::component::vsock::host::VsockHostService::default(),
        ),
    );
    let instance = linker
        .instantiate_async(&mut store, &component)
        .await
        .expect("instance");
    let reset: TypedFunc<(), ()> = instance
        .get_typed_func(&mut store, export("reset"))
        .expect("reset");
    reset.call_async(&mut store, ()).await.expect("fresh state");
    let receive: Receive = instance
        .get_typed_func(&mut store, export("receive"))
        .expect("receive");
    let replies: TypedFunc<(u32, u32), (Vec<ComponentReply>,)> = instance
        .get_typed_func(&mut store, export("take-replies"))
        .expect("replies");
    assert_eq!(
        receive
            .call_async(&mut store, (packet(1, 0),))
            .await
            .expect("request"),
        (Ok(()),)
    );
    let _ = replies
        .call_async(&mut store, (8, 4096))
        .await
        .expect("response");
    let consume: Consume = instance
        .get_typed_func(&mut store, export("consume-upstream"))
        .expect("consume");
    let mut data = packet(5, 5);
    data.extend_from_slice(b"hello");
    assert_eq!(
        receive.call_async(&mut store, (data,)).await.expect("data"),
        (Ok(()),)
    );
    assert_eq!(
        consume
            .call_async(&mut store, (100, 6001, 4))
            .await
            .expect("bounded")
            .0,
        b"hell"
    );
    assert_eq!(
        consume
            .call_async(&mut store, (100, 6001, 1))
            .await
            .expect("drain")
            .0,
        b"o"
    );
    let reply = replies
        .call_async(&mut store, (8, 4096))
        .await
        .expect("credit")
        .0
        .pop()
        .expect("credit reply");
    assert_eq!(
        u32::from_le_bytes(reply.header[40..44].try_into().expect("counter")),
        5
    );
}

#[tokio::test(flavor = "current_thread")]
async fn component_drains_selected_stream_while_another_is_queued() {
    let engine = device_engine().expect("engine");
    let linker = vsock_component_linker(&engine).expect("linker");
    let component = Component::new(&engine, COMPONENT).expect("component");
    let mut store = device_store(
        &engine,
        terra_runtime::engine::VsockDeviceHost::new(
            terra_runtime::SyntheticRam::new(64 * 1024).unwrap(),
            terra_runtime::component::vsock::host::VsockHostService::default(),
        ),
    );
    let instance = linker
        .instantiate_async(&mut store, &component)
        .await
        .expect("instance");
    let events =
        instance
            .get_typed_func::<(), (
                wasmtime::component::StreamReader<
                    terra_runtime::component::vsock::host::VsockEvent,
                >,
            )>(&mut store, export("events"))
            .expect("events");
    let (_events,) = events
        .call_async(&mut store, ())
        .await
        .expect("framed lifecycle");
    let receive: Receive = instance
        .get_typed_func(&mut store, export("receive"))
        .expect("receive");
    let consume: Consume = instance
        .get_typed_func(&mut store, export("consume-upstream"))
        .expect("consume");
    let connections: Connections = instance
        .get_typed_func(&mut store, export("connections"))
        .expect("connections");
    let mut diagnostic_request = packet(1, 0);
    diagnostic_request[20..24].copy_from_slice(&6002_u32.to_le_bytes());
    assert_eq!(
        receive
            .call_async(&mut store, (packet(1, 0),))
            .await
            .expect("control request"),
        (Ok(()),)
    );
    assert_eq!(
        receive
            .call_async(&mut store, (diagnostic_request,))
            .await
            .expect("diagnostic request"),
        (Ok(()),)
    );
    let mut control = packet(5, 5);
    control.extend_from_slice(b"first");
    let mut diagnostic = packet(5, 6);
    diagnostic[20..24].copy_from_slice(&6002_u32.to_le_bytes());
    diagnostic.extend_from_slice(b"second");
    receive
        .call_async(&mut store, (control,))
        .await
        .expect("control data")
        .0
        .expect("control packet accepted");
    receive
        .call_async(&mut store, (diagnostic,))
        .await
        .expect("diagnostic data")
        .0
        .expect("diagnostic packet accepted");
    assert_eq!(
        connections
            .call_async(&mut store, (2,))
            .await
            .expect("connections")
            .0
            .iter()
            .map(|connection| (connection.guest_port, connection.host_port))
            .collect::<Vec<_>>(),
        vec![(100, 6001), (100, 6002)]
    );
    assert_eq!(
        consume
            .call_async(&mut store, (100, 6002, 6))
            .await
            .expect("diagnostic drain")
            .0,
        b"second"
    );
    assert_eq!(
        consume
            .call_async(&mut store, (100, 6001, 5))
            .await
            .expect("control drain")
            .0,
        b"first"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn component_close_clears_queued_state() {
    let engine = device_engine().expect("engine");
    let linker = vsock_component_linker(&engine).expect("linker");
    let component = Component::new(&engine, COMPONENT).expect("component");
    let mut store = device_store(
        &engine,
        terra_runtime::engine::VsockDeviceHost::new(
            terra_runtime::SyntheticRam::new(64 * 1024).unwrap(),
            terra_runtime::component::vsock::host::VsockHostService::default(),
        ),
    );
    let instance = linker
        .instantiate_async(&mut store, &component)
        .await
        .expect("instance");
    let receive: Receive = instance
        .get_typed_func(&mut store, export("receive"))
        .expect("receive");
    let close: TypedFunc<(), ()> = instance
        .get_typed_func(&mut store, export("close"))
        .expect("close");
    let replies: TypedFunc<(u32, u32), (Vec<ComponentReply>,)> = instance
        .get_typed_func(&mut store, export("take-replies"))
        .expect("replies");
    assert_eq!(
        receive
            .call_async(&mut store, (packet(1, 0),))
            .await
            .expect("request"),
        (Ok(()),)
    );
    close.call_async(&mut store, ()).await.expect("close");
    let reset: TypedFunc<(), ()> = instance
        .get_typed_func(&mut store, export("reset"))
        .expect("reset");
    reset
        .call_async(&mut store, ())
        .await
        .expect("reset remains terminal");
    assert!(
        replies
            .call_async(&mut store, (8, 4096))
            .await
            .expect("empty")
            .0
            .is_empty()
    );
    assert_eq!(
        receive
            .call_async(&mut store, (packet(1, 0),))
            .await
            .expect("closed request"),
        (Err(ComponentError::Backpressure),)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn component_rejects_backpressure_without_resetting_connection_state() {
    let engine = device_engine().expect("engine");
    let linker = vsock_component_linker(&engine).expect("linker");
    let component = Component::new(&engine, COMPONENT).expect("component");
    let mut store = device_store(
        &engine,
        terra_runtime::engine::VsockDeviceHost::new(
            terra_runtime::SyntheticRam::new(64 * 1024).unwrap(),
            terra_runtime::component::vsock::host::VsockHostService::default(),
        ),
    );
    let instance = linker
        .instantiate_async(&mut store, &component)
        .await
        .expect("instance");
    let receive: Receive = instance
        .get_typed_func(&mut store, export("receive"))
        .expect("receive");
    let deliver: Deliver = instance
        .get_typed_func(&mut store, export("deliver"))
        .expect("deliver");
    assert_eq!(
        receive
            .call_async(&mut store, (packet(1, 0),))
            .await
            .expect("request"),
        (Ok(()),)
    );
    assert_eq!(
        deliver
            .call_async(&mut store, (100, 6001, vec![0; 64 * 1024]))
            .await
            .expect("first delivery"),
        (Ok(()),)
    );
    assert_eq!(
        deliver
            .call_async(&mut store, (100, 6001, b"blocked".to_vec()))
            .await
            .expect("backpressure call"),
        (Err(ComponentError::Backpressure),)
    );
    let mut credit = packet(6, 0);
    credit[40..44].copy_from_slice(&(64 * 1024_u32).to_le_bytes());
    assert_eq!(
        receive
            .call_async(&mut store, (credit,))
            .await
            .expect("credit"),
        (Ok(()),)
    );
    assert_eq!(
        deliver
            .call_async(&mut store, (100, 6001, b"ok".to_vec()))
            .await
            .expect("connection remains usable"),
        (Ok(()),)
    );
}

#[derive(wasmtime::component::ComponentType, wasmtime::component::Lift)]
#[component(record)]
struct ControlResult {
    consumed: u32,
    #[component(name = "exit-code")]
    exit_code: Option<i32>,
}

#[derive(wasmtime::component::ComponentType, wasmtime::component::Lift)]
#[component(record)]
struct DiagnosticResult {
    consumed: u32,
    output: Vec<u8>,
}

#[tokio::test(flavor = "current_thread")]
async fn lifecycle_decoding_stays_in_component_and_handles_bounded_frames() {
    use terra_protocol::{LifecycleEvent, encode_frame};
    let engine = device_engine().unwrap();
    let component = Component::new(&engine, COMPONENT).unwrap();
    let mut store = device_store(
        &engine,
        terra_runtime::engine::VsockDeviceHost::new(
            terra_runtime::SyntheticRam::new(65536).unwrap(),
            terra_runtime::component::vsock::host::VsockHostService::default(),
        ),
    );
    let instance = vsock_component_linker(&engine)
        .unwrap()
        .instantiate_async(&mut store, &component)
        .await
        .unwrap();
    let control: TypedFunc<(Vec<u8>,), ComponentResult<ControlResult>> = instance
        .get_typed_func(&mut store, export("decode-control"))
        .unwrap();
    let diagnostics: TypedFunc<(Vec<u8>,), ComponentResult<DiagnosticResult>> = instance
        .get_typed_func(&mut store, export("decode-diagnostics"))
        .unwrap();
    let frame = encode_frame(&LifecycleEvent::Exit { code: -13 }).unwrap();
    let partial = control
        .call_async(&mut store, (frame[..frame.len() - 1].to_vec(),))
        .await
        .unwrap()
        .0
        .unwrap();
    assert_eq!(partial.consumed, 0);
    assert_eq!(partial.exit_code, None);
    let result = control
        .call_async(&mut store, (frame.clone(),))
        .await
        .unwrap()
        .0
        .unwrap();
    assert_eq!(result.consumed as usize, frame.len());
    assert_eq!(result.exit_code, Some(-13));
    assert!(
        control
            .call_async(&mut store, (encode_frame(&-13).unwrap(),))
            .await
            .unwrap()
            .0
            .is_err()
    );
    for bytes in [vec![255; 16300], vec![0; 32700]] {
        let frame = encode_frame(&LifecycleEvent::Diagnostic {
            bytes: bytes.clone(),
        })
        .unwrap();
        assert!(frame.len() < 65540);
        let result = diagnostics
            .call_async(&mut store, (frame.clone(),))
            .await
            .unwrap()
            .0
            .unwrap();
        assert_eq!(result.consumed as usize, frame.len());
        assert_eq!(result.output, bytes);
    }
}
