#![allow(clippy::expect_used)]

#[path = "support/stream_relay.rs"]
mod relay;

use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use wasmtime::component::{
    Component, Destination, Linker, StreamProducer, StreamReader, StreamResult, VecBuffer,
};
use wasmtime::{Engine, Store};

const FORWARD: &str = r#"(component
    (type $bytes (stream u8))
    (core module $module
        (func (export "forward") (param i32) (result i32) local.get 0))
    (core instance $instance (instantiate $module))
    (alias core export $instance "forward" (core func $forward))
    (func (export "forward") (param "input" $bytes) (result $bytes)
        (canon lift (core func $forward))))"#;

const CONSUME: &str = r#"(component
    (type $bytes (stream u8))
    (core module $storage (memory (export "memory") 1 1))
    (core instance $storage (instantiate $storage))
    (alias core export $storage "memory" (core memory $memory))
    (core func $read (canon stream.read $bytes (memory $memory) async))
    (core func $close (canon stream.drop-readable $bytes))
    (core func $new (canon waitable-set.new))
    (core func $drop (canon waitable-set.drop))
    (core func $join (canon waitable.join))
    (core func $return (canon task.return (result u32)))
    (core instance $io
        (export "read" (func $read)) (export "close" (func $close))
        (export "new" (func $new)) (export "drop" (func $drop))
        (export "join" (func $join)) (export "return" (func $return)))
    (core module $module
        (import "storage" "memory" (memory 1 1))
        (import "io" "read" (func $read (param i32 i32 i32) (result i32)))
        (import "io" "close" (func $close (param i32)))
        (import "io" "new" (func $new (result i32)))
        (import "io" "drop" (func $drop (param i32)))
        (import "io" "join" (func $join (param i32 i32)))
        (import "io" "return" (func $return (param i32)))
        (global $input (mut i32) (i32.const 0))
        (global $set (mut i32) (i32.const 0))
        (func $finish (param $result i32) (result i32)
            local.get $result i32.const 4 i32.shr_u i32.const 4 i32.ne
            if unreachable end
            global.get $input call $close
            global.get $set call $drop
            i32.const 0 i32.load call $return
            i32.const 0)
        (func (export "consume") (param $input i32) (result i32)
            (local $result i32)
            local.get $input global.set $input
            call $new global.set $set
            local.get $input global.get $set call $join
            local.get $input i32.const 0 i32.const 4 call $read local.tee $result
            i32.const -1 i32.eq
            if (result i32)
                global.get $set i32.const 4 i32.shl i32.const 2 i32.or
            else local.get $result call $finish end)
        (func (export "callback") (param i32 i32 i32) (result i32)
            local.get 2 call $finish))
    (core instance $instance (instantiate $module
        (with "storage" (instance $storage)) (with "io" (instance $io))))
    (alias core export $instance "consume" (core func $consume))
    (alias core export $instance "callback" (core func $callback))
    (func (export "consume") async (param "input" $bytes) (result u32)
        (canon lift (core func $consume) async (callback $callback))))"#;

fn store(engine: &Engine) -> Store<()> {
    let mut store = Store::new(engine, ());
    store.set_epoch_deadline(100);
    store
}

#[tokio::test]
async fn streams_pass_between_components_in_one_store_without_shared_memory() {
    let engine = terra_runtime::engine::device_engine().expect("engine");
    assert!(!engine.get_shared_memory());
    let mut store = store(&engine);
    let linker = Linker::new(&engine);
    let forwarding = Component::new(&engine, FORWARD).expect("forwarding component");
    let consuming = Component::new(&engine, CONSUME).expect("consuming component");
    let forwarding = linker
        .instantiate_async(&mut store, &forwarding)
        .await
        .expect("forwarder");
    let consuming = linker
        .instantiate_async(&mut store, &consuming)
        .await
        .expect("consumer");
    let forward = forwarding
        .get_typed_func::<(StreamReader<u8>,), (StreamReader<u8>,)>(&mut store, "forward")
        .expect("forward export");
    let consume = consuming
        .get_typed_func::<(StreamReader<u8>,), (u32,)>(&mut store, "consume")
        .expect("consume export");
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let dropped = Arc::new(AtomicBool::new(false));
    let input = StreamReader::new(
        &mut store,
        DelayedBytes {
            receiver,
            dropped: Arc::clone(&dropped),
        },
    )
    .expect("stream");
    let (input,) = forward
        .call_async(&mut store, (input,))
        .await
        .expect("transfer handle");
    let sending = async move {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        sender
            .send(vec![1, 2, 3, 4])
            .expect("receiver is still waiting");
    };
    let reading = consume.call_async(&mut store, (input,));
    let ((), result) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::join!(sending, reading)
    })
    .await
    .expect("async delivery deadline");
    assert_eq!(result.expect("consume bytes"), (0x0403_0201,));
    assert!(
        dropped.load(Ordering::Acquire),
        "consumer closed the stream"
    );
}

#[test]
fn an_empty_store_cannot_resolve_another_stores_stream() {
    let engine = terra_runtime::engine::device_engine().expect("engine");
    let mut owner = store(&engine);
    let mut other = store(&engine);
    let stream = StreamReader::new(&mut owner, vec![1_u8]).expect("stream");
    let error = stream
        .try_into_stream_any(&mut other)
        .expect_err("stream belongs to owner");
    assert!(
        error.to_string().contains("resource not present"),
        "{error:#}"
    );
}

#[test]
fn a_foreign_handle_does_not_transfer_the_source_even_when_slot_indices_collide() {
    let engine = terra_runtime::engine::device_engine().expect("engine");
    let mut owner = store(&engine);
    let mut other = store(&engine);
    let owner_dropped = Arc::new(AtomicBool::new(false));
    let other_dropped = Arc::new(AtomicBool::new(false));
    let (_owner_sender, owner_receiver) = tokio::sync::oneshot::channel();
    let (_other_sender, other_receiver) = tokio::sync::oneshot::channel();
    let stream = StreamReader::new(
        &mut owner,
        DelayedBytes {
            receiver: owner_receiver,
            dropped: Arc::clone(&owner_dropped),
        },
    )
    .expect("owner stream");
    let mut other_stream = StreamReader::new(
        &mut other,
        DelayedBytes {
            receiver: other_receiver,
            dropped: Arc::clone(&other_dropped),
        },
    )
    .expect("other stream");
    match stream.try_into_stream_any(&mut other) {
        Ok(mut aliased) => aliased
            .close(&mut other)
            .expect("colliding store-local endpoint"),
        Err(_) => other_stream
            .close(&mut other)
            .expect("rejected foreign endpoint"),
    }
    assert!(other_dropped.load(Ordering::Acquire));
    assert!(!owner_dropped.load(Ordering::Acquire));
    drop(owner);
    assert!(owner_dropped.load(Ordering::Acquire));
}

#[tokio::test]
async fn closing_an_idle_stream_releases_its_waiting_source() {
    let engine = terra_runtime::engine::device_engine().expect("engine");
    let mut store = store(&engine);
    let (mut sender, receiver) = tokio::sync::oneshot::channel();
    let dropped = Arc::new(AtomicBool::new(false));
    let mut stream = StreamReader::new(
        &mut store,
        DelayedBytes {
            receiver,
            dropped: Arc::clone(&dropped),
        },
    )
    .expect("stream");
    stream.close(&mut store).expect("close unused endpoint");
    tokio::time::timeout(std::time::Duration::from_secs(2), sender.closed())
        .await
        .expect("source released");
    assert!(dropped.load(Ordering::Acquire));
}

struct DelayedBytes {
    receiver: tokio::sync::oneshot::Receiver<Vec<u8>>,
    dropped: Arc<AtomicBool>,
}

impl Drop for DelayedBytes {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

impl StreamProducer<()> for DelayedBytes {
    type Item = u8;
    type Buffer = VecBuffer<u8>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        _: wasmtime::StoreContextMut<'a, ()>,
        mut destination: Destination<'a, u8, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        let bytes = std::task::ready!(Pin::new(&mut self.receiver).poll(context))?;
        destination.set_buffer(bytes.into());
        Poll::Ready(Ok(StreamResult::Dropped))
    }
}

#[tokio::test]
async fn bounded_relay_connects_components_without_moving_store_handles() {
    let engine = terra_runtime::engine::device_engine().expect("engine");
    let mut origin = store(&engine);
    let mut destination = store(&engine);
    let linker = Linker::new(&engine);
    let forwarder = Component::new(&engine, FORWARD).expect("forwarder");
    let consumer = Component::new(&engine, CONSUME).expect("consumer");
    let forwarder = linker
        .instantiate_async(&mut origin, &forwarder)
        .await
        .expect("forwarder instance");
    let consumer = linker
        .instantiate_async(&mut destination, &consumer)
        .await
        .expect("consumer instance");
    let forward = forwarder
        .get_typed_func::<(StreamReader<u8>,), (StreamReader<u8>,)>(&mut origin, "forward")
        .expect("forward export");
    let consume = consumer
        .get_typed_func::<(StreamReader<u8>,), (u32,)>(&mut destination, "consume")
        .expect("consume export");
    let input = StreamReader::new(&mut origin, vec![1_u8, 2, 3, 4]).expect("origin stream");
    let (input,) = forward
        .call_async(&mut origin, (input,))
        .await
        .expect("forward handle inside origin");
    let (sink, source) = relay::create_byte_channel();
    input
        .pipe(&mut origin, sink)
        .expect("attach origin endpoint");
    let input = StreamReader::new(&mut destination, source).expect("destination endpoint");
    let (finished, completion) = tokio::sync::oneshot::channel();
    let sending = origin.run_concurrent(async |_| completion.await);
    let receiving = async {
        let result = consume.call_async(&mut destination, (input,)).await;
        finished.send(()).expect("origin is active");
        result
    };
    let (sent, received) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::join!(sending, receiving)
    })
    .await
    .expect("cross-store delivery deadline");
    sent.expect("origin execution").expect("origin completion");
    assert_eq!(received.expect("received"), (0x0403_0201,));
}
