#![allow(clippy::expect_used)]

use std::time::Duration;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use terra_runtime::box_runtime::{BoxHost, BoxRuntime};
use wasmtime::component::{
    Component, Destination, Linker, StreamProducer, StreamReader, StreamResult, VecBuffer,
};

const FAST_COMPONENT: &str = r#"(component
    (core module $module
        (func (export "ping") (result i32) i32.const 7))
    (core instance $instance (instantiate $module))
    (alias core export $instance "ping" (core func $ping))
    (func (export "ping") (result u32)
        (canon lift (core func $ping))))"#;

const STALL_COMPONENT: &str = r#"(component
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

fn runtime() -> BoxRuntime {
    let engine = terra_runtime::engine::device_engine().expect("engine");
    BoxRuntime::new(&engine, BoxHost::new()).expect("runtime")
}

#[tokio::test]
async fn stalled_io_loop_does_not_delay_another_loop_in_the_same_box() {
    let mut runtime = runtime();
    let component = Component::new(runtime.store.engine(), FAST_COMPONENT).expect("component");
    let linker = Linker::<BoxHost>::new(runtime.store.engine());
    let instance = linker
        .instantiate_async(&mut runtime.store, &component)
        .await
        .expect("component instance");
    let ping = instance
        .get_typed_func::<(), (u32,)>(&mut runtime.store, "ping")
        .expect("ping export");
    let stalled =
        Component::new(runtime.store.engine(), STALL_COMPONENT).expect("stalled component");
    let stalled = linker
        .instantiate_async(&mut runtime.store, &stalled)
        .await
        .expect("stalled component instance");
    let consume = stalled
        .get_typed_func::<(StreamReader<u8>,), (u32,)>(&mut runtime.store, "consume")
        .expect("consume export");
    let (slow_release, slow_wait) = tokio::sync::oneshot::channel();
    let input = StreamReader::new(
        &mut runtime.store,
        DelayedBytes {
            receiver: slow_wait,
        },
    )
    .expect("stalled input stream");
    let (fast_started, fast_ready) = tokio::sync::oneshot::channel();
    runtime
        .register_loop(Box::new(move |accessor| {
            Box::pin(async move {
                assert_eq!(
                    consume.call_concurrent(accessor, (input,)).await?,
                    (0x0403_0201,)
                );
                Ok(())
            })
        }))
        .expect("slow loop");
    runtime
        .register_loop(Box::new(move |accessor| {
            Box::pin(async move {
                assert_eq!(ping.call_concurrent(accessor, ()).await?, (7,));
                let _ = fast_started.send(());
                Ok(())
            })
        }))
        .expect("fast loop");
    let handle = runtime.start();
    tokio::time::timeout(Duration::from_secs(1), fast_ready)
        .await
        .expect("fast loop is not blocked by stalled I/O")
        .expect("fast loop starts");
    let _ = slow_release.send(vec![1, 2, 3, 4]);
    handle.join().await.expect("box stops cleanly");
}

struct DelayedBytes {
    receiver: tokio::sync::oneshot::Receiver<Vec<u8>>,
}

impl StreamProducer<BoxHost> for DelayedBytes {
    type Item = u8;
    type Buffer = VecBuffer<u8>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        _: wasmtime::StoreContextMut<'a, BoxHost>,
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
async fn a_failed_box_does_not_stop_an_independent_box() {
    let mut failed = runtime();
    failed
        .register_loop(Box::new(|_| {
            Box::pin(async { Err(wasmtime::Error::msg("synthetic device failure")) })
        }))
        .expect("failing loop");
    let mut independent = runtime();
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = tokio::sync::oneshot::channel();
    independent
        .register_loop(Box::new(|_| {
            Box::pin(async move {
                let _ = started.send(());
                let _ = wait.await;
                Ok(())
            })
        }))
        .expect("independent loop");
    let failed = failed.start();
    let independent = independent.start();
    assert!(failed.join().await.is_err(), "failure reaches only its box");
    tokio::time::timeout(Duration::from_secs(1), ready)
        .await
        .expect("independent box stays scheduled")
        .expect("independent loop starts");
    let _ = release.send(());
    independent
        .join()
        .await
        .expect("independent box stops cleanly");
}
