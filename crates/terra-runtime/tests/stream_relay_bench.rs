#![allow(clippy::expect_used)]

#[path = "support/stream_relay.rs"]
mod relay;

use std::time::{Duration, Instant};

use relay::create_byte_channel;
use wasmtime::component::{Component, Linker, StreamReader, TypedFunc};
use wasmtime::{Engine, Store};

const SAMPLES: usize = 101;
const WARMUP_SAMPLES: usize = 10;

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
        (global $remaining (mut i32) (i32.const 0))
        (global $received (mut i32) (i32.const 0))
        (func $chunk (result i32)
            global.get $remaining i32.const 16384 i32.gt_u
            if (result i32) i32.const 16384 else global.get $remaining end)
        (func $finish (result i32)
            global.get $input call $close
            global.get $set call $drop
            i32.const 0 global.get $received i32.store
            i32.const 0 i32.load call $return
            i32.const 0)
        (func $accept (param $result i32) (result i32)
            (local $count i32)
            local.get $result i32.const -1 i32.eq
            if (result i32)
                global.get $set i32.const 4 i32.shl i32.const 2 i32.or
            else
                local.get $result i32.const 4 i32.shr_u local.tee $count
                global.get $remaining i32.gt_u
                if unreachable end
                global.get $remaining local.get $count i32.sub global.set $remaining
                global.get $received local.get $count i32.add global.set $received
                global.get $remaining i32.eqz
                if (result i32)
                    call $finish
                else
                    global.get $input i32.const 0 call $chunk
                    call $read call $accept
                end
            end)
        (func (export "consume") (param $input i32) (param $length i32) (result i32)
            local.get $input global.set $input
            local.get $length global.set $remaining
            i32.const 0 global.set $received
            call $new global.set $set
            local.get $input global.get $set call $join
            local.get $input i32.const 0 call $chunk
            call $read call $accept)
        (func (export "callback") (param i32 i32 i32) (result i32)
            local.get 2 call $accept))
    (core instance $instance (instantiate $module
        (with "storage" (instance $storage)) (with "io" (instance $io))))
    (alias core export $instance "consume" (core func $consume))
    (alias core export $instance "callback" (core func $callback))
    (func (export "consume") async (param "input" $bytes) (param "length" u32) (result u32)
        (canon lift (core func $consume) async (callback $callback))))"#;

fn store(engine: &Engine) -> Store<()> {
    let mut store = Store::new(engine, ());
    store.set_epoch_deadline(100);
    store
}

fn percentile(samples: &mut [Duration], numerator: usize, denominator: usize) -> Duration {
    samples.sort_unstable();
    samples[(samples.len() * numerator).div_ceil(denominator) - 1]
}

async fn same_store_sample(
    store: &mut Store<()>,
    consume: &TypedFunc<(StreamReader<u8>, u32), (u32,)>,
    payload: &[u8],
) -> Duration {
    let input = StreamReader::new(&mut *store, payload.to_vec()).expect("input stream");
    let start = Instant::now();
    let (received,) = consume
        .call_async(
            store,
            (input, u32::try_from(payload.len()).expect("payload length")),
        )
        .await
        .expect("consume payload");
    assert_eq!(
        usize::try_from(received).expect("received length"),
        payload.len()
    );
    start.elapsed()
}

async fn relay_sample(
    source_store: &mut Store<()>,
    target_store: &mut Store<()>,
    forward: &TypedFunc<(StreamReader<u8>,), (StreamReader<u8>,)>,
    consume: &TypedFunc<(StreamReader<u8>, u32), (u32,)>,
    payload: &[u8],
) -> Duration {
    let input = StreamReader::new(&mut *source_store, payload.to_vec()).expect("input stream");
    let (input,) = forward
        .call_async(&mut *source_store, (input,))
        .await
        .expect("forward payload");
    let (sink, source) = create_byte_channel();
    input
        .pipe(&mut *source_store, sink)
        .expect("attach relay sink");
    let input = StreamReader::new(&mut *target_store, source).expect("attach relay source");
    let (done, finished) = tokio::sync::oneshot::channel();
    let start = Instant::now();
    let source_drive = source_store.run_concurrent(async |_| {
        finished.await.expect("target completion");
    });
    let target_drive = target_store.run_concurrent(async |accessor| {
        let result = consume
            .call_concurrent(
                accessor,
                (input, u32::try_from(payload.len()).expect("payload length")),
            )
            .await;
        done.send(()).expect("source drive is waiting");
        result
    });
    let (source_result, target_result) = tokio::join!(source_drive, target_drive);
    source_result.expect("drive source stream");
    let (received,) = target_result
        .expect("drive target stream")
        .expect("consume relayed payload");
    assert_eq!(
        usize::try_from(received).expect("received length"),
        payload.len()
    );
    start.elapsed()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "microbenchmark: run with --ignored --nocapture in --release mode"]
async fn byte_relay_component_stream_overhead() {
    let engine = terra_runtime::engine::device_engine().expect("engine");
    let linker = Linker::new(&engine);
    let forward_component = Component::new(&engine, FORWARD).expect("forward component");
    let consume_component = Component::new(&engine, CONSUME).expect("consume component");
    let mut baseline_store = store(&engine);
    let baseline = linker
        .instantiate_async(&mut baseline_store, &consume_component)
        .await
        .expect("baseline component");
    let baseline_consume = baseline
        .get_typed_func::<(StreamReader<u8>, u32), (u32,)>(&mut baseline_store, "consume")
        .expect("baseline consume export");
    let mut source_store = store(&engine);
    let source = linker
        .instantiate_async(&mut source_store, &forward_component)
        .await
        .expect("source component");
    let forward = source
        .get_typed_func::<(StreamReader<u8>,), (StreamReader<u8>,)>(&mut source_store, "forward")
        .expect("forward export");
    let mut target_store = store(&engine);
    let target = linker
        .instantiate_async(&mut target_store, &consume_component)
        .await
        .expect("target component");
    let relay_consume = target
        .get_typed_func::<(StreamReader<u8>, u32), (u32,)>(&mut target_store, "consume")
        .expect("target consume export");

    println!(
        "warmed component-stream transfer only; excludes compilation, instantiation, VM, MMIO, and virtio"
    );

    for size in [4, 64, 4 * 1024, 16 * 1024, 128 * 1024] {
        let payload = vec![0xA5; size];
        for _ in 0..WARMUP_SAMPLES {
            same_store_sample(&mut baseline_store, &baseline_consume, &payload).await;
            relay_sample(
                &mut source_store,
                &mut target_store,
                &forward,
                &relay_consume,
                &payload,
            )
            .await;
        }
        let mut same_store = Vec::with_capacity(SAMPLES);
        let mut relay = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            same_store
                .push(same_store_sample(&mut baseline_store, &baseline_consume, &payload).await);
            relay.push(
                relay_sample(
                    &mut source_store,
                    &mut target_store,
                    &forward,
                    &relay_consume,
                    &payload,
                )
                .await,
            );
        }
        let same_median = percentile(&mut same_store, 1, 2);
        let same_p95 = percentile(&mut same_store, 95, 100);
        let relay_median = percentile(&mut relay, 1, 2);
        let relay_p95 = percentile(&mut relay, 95, 100);
        println!(
            "{size:>5} B: same-store median={same_median:?} p95={same_p95:?}; relay median={relay_median:?} p95={relay_p95:?}"
        );
    }
}
