#![allow(clippy::expect_used, unsafe_code)]

use std::sync::atomic::{AtomicU32, Ordering};
use wasmtime::component::Component;
use wasmtime::{Config, Engine, Instance, MemoryType, Module, SharedMemory, Store};

fn shared_engine() -> Engine {
    let mut config = Config::new();
    config
        .wasm_component_model_async(true)
        .concurrency_support(true)
        .shared_memory(true);
    Engine::new(&config).expect("shared-memory test engine")
}

#[test]
fn host_and_core_wasm_exchange_atomic_words() {
    let engine = shared_engine();
    let memory =
        SharedMemory::new(&engine, MemoryType::shared(1, 1)).expect("bounded shared memory");
    let module = Module::new(
        &engine,
        r#"(module
            (import "host" "ring" (memory 1 1 shared))
            (func (export "add") (param i32) (result i32)
                i32.const 0
                local.get 0
                i32.atomic.rmw.add))"#,
    )
    .expect("atomic core module");
    let mut store = Store::new(&engine, ());
    let instance = Instance::new(&mut store, &module, &[memory.clone().into()])
        .expect("core module shares the host allocation");
    let add = instance
        .get_typed_func::<u32, u32>(&mut store, "add")
        .expect("atomic add");
    assert_eq!(
        memory
            .data()
            .as_ptr()
            .align_offset(std::mem::align_of::<AtomicU32>()),
        0
    );
    // SAFETY: shared linear memory has a page-aligned, stable allocation; this
    // aligned word is accessed only atomically while `memory` remains alive.
    #[allow(clippy::cast_ptr_alignment)]
    let word = unsafe { &*memory.data().as_ptr().cast::<AtomicU32>() };
    word.store(41, Ordering::Release);
    assert_eq!(add.call(&mut store, 1).expect("Wasm atomic add"), 41);
    assert_eq!(word.load(Ordering::Acquire), 42);
    assert!(
        memory.grow(1).is_err(),
        "the ring cannot grow beyond its fixed grant"
    );
}

#[test]
fn canonical_component_memory_cannot_be_shared() {
    let engine = shared_engine();
    let component = r#"(component
        (core module $ring
            (memory (export "memory") 1 1 shared)
            (func (export "value") (result i32) i32.const 42))
        (core instance $ring (instantiate $ring))
        (alias core export $ring "memory" (core memory $memory))
        (alias core export $ring "value" (core func $value))
        (func (export "value") (result u32)
            (canon lift (core func $value) (memory $memory))))"#;
    let error = Component::new(&engine, component).expect_err("shared canonical memory rejected");
    let message = format!("{error:#}");
    assert!(
        message.contains("shared"),
        "unexpected rejection: {message}"
    );
    Component::new(&engine, component.replace("1 1 shared", "1 1"))
        .expect("otherwise identical ordinary canonical memory is supported");
}

#[tokio::test]
async fn component_can_use_auxiliary_shared_memory_without_exposing_it_to_the_host() {
    let engine = shared_engine();
    let component = Component::new(
        &engine,
        r#"(component
            (core module $ring
                (memory 1 1 shared)
                (func (export "add") (param i32) (result i32)
                    i32.const 0 local.get 0 i32.atomic.rmw.add))
            (core instance $ring (instantiate $ring))
            (alias core export $ring "add" (core func $add))
            (func (export "add") (param "value" u32) (result u32)
                (canon lift (core func $add))))"#,
    )
    .expect("auxiliary shared memory is distinct from canonical ABI memory");
    let linker = wasmtime::component::Linker::<()>::new(&engine);
    let mut store = Store::new(&engine, ());
    let instance = linker
        .instantiate_async(&mut store, &component)
        .await
        .expect("component instance");
    let add = instance
        .get_typed_func::<(u32,), (u32,)>(&mut store, "add")
        .expect("component add");
    assert_eq!(
        add.call_async(&mut store, (41,)).await.expect("first add"),
        (0,)
    );
    assert_eq!(
        add.call_async(&mut store, (1,)).await.expect("second add"),
        (41,)
    );
}

#[test]
fn device_engine_keeps_shared_memory_disabled() {
    let engine = terra_runtime::engine::device_engine().expect("device engine");
    assert!(!engine.get_shared_memory());
    assert!(SharedMemory::new(&engine, MemoryType::shared(1, 1)).is_err());
}

#[tokio::test]
async fn core_modules_exchange_a_bounded_ring_without_host_memory_access() {
    let engine = shared_engine();
    let component = Component::new(
        &engine,
        r#"(component
            (core module $storage (memory (export "ring") 1 1 shared))
            (core instance $storage (instantiate $storage))
            (core module $producer
                (import "storage" "ring" (memory 1 1 shared))
                (func (export "push") (param $value i32) (result i32)
                    (local $write i32)
                    i32.const 4 i32.atomic.load local.set $write
                    local.get $write i32.const 0 i32.atomic.load i32.sub
                    i32.const 4 i32.ge_u
                    if i32.const 0 return end
                    local.get $write i32.const 3 i32.and
                    i32.const 4 i32.mul i32.const 16 i32.add
                    local.get $value i32.atomic.store
                    i32.const 4 local.get $write i32.const 1 i32.add i32.atomic.store
                    i32.const 1))
            (core module $consumer
                (import "storage" "ring" (memory 1 1 shared))
                (func (export "pop") (result i32)
                    (local $read i32) (local $count i32) (local $value i32)
                    i32.const 0 i32.atomic.load local.set $read
                    i32.const 4 i32.atomic.load local.get $read i32.sub local.set $count
                    local.get $count i32.eqz
                    if i32.const -1 return end
                    local.get $count i32.const 4 i32.gt_u
                    if unreachable end
                    local.get $read i32.const 3 i32.and
                    i32.const 4 i32.mul i32.const 16 i32.add
                    i32.atomic.load local.set $value
                    i32.const 0 local.get $read i32.const 1 i32.add i32.atomic.store
                    local.get $value))
            (core instance $producer (instantiate $producer (with "storage" (instance $storage))))
            (core instance $consumer (instantiate $consumer (with "storage" (instance $storage))))
            (alias core export $producer "push" (core func $push))
            (alias core export $consumer "pop" (core func $pop))
            (func (export "push") (param "value" u32) (result u32)
                (canon lift (core func $push)))
            (func (export "pop") (result u32) (canon lift (core func $pop))))"#,
    )
    .expect("component with an internal shared ring");
    let linker = wasmtime::component::Linker::<()>::new(&engine);
    let mut store = Store::new(&engine, ());
    let instance = linker
        .instantiate_async(&mut store, &component)
        .await
        .expect("ring instance");
    let other = linker
        .instantiate_async(&mut store, &component)
        .await
        .expect("independent ring instance");
    let push = instance
        .get_typed_func::<(u32,), (u32,)>(&mut store, "push")
        .expect("producer");
    let pop = instance
        .get_typed_func::<(), (u32,)>(&mut store, "pop")
        .expect("consumer");
    let other_pop = other
        .get_typed_func::<(), (u32,)>(&mut store, "pop")
        .expect("other consumer");
    for batch in 0..8 {
        assert_eq!(
            pop.call_async(&mut store, ()).await.expect("empty"),
            (u32::MAX,)
        );
        for offset in 0..4 {
            assert_eq!(
                push.call_async(&mut store, (batch * 4 + offset,))
                    .await
                    .expect("push"),
                (1,)
            );
        }
        assert_eq!(
            push.call_async(&mut store, (99,)).await.expect("full"),
            (0,)
        );
        assert_eq!(
            other_pop
                .call_async(&mut store, ())
                .await
                .expect("separate ring"),
            (u32::MAX,)
        );
        for offset in 0..4 {
            assert_eq!(
                pop.call_async(&mut store, ()).await.expect("pop"),
                (batch * 4 + offset,)
            );
        }
    }
}

#[test]
fn component_interfaces_cannot_import_a_core_memory() {
    let engine = shared_engine();
    let error = Component::new(
        &engine,
        r#"(component (import "ring" (core memory 1 1 shared)))"#,
    )
    .expect_err("linear memory is not a component import kind");
    assert!(
        format!("{error:#}").contains("expected keyword `module`"),
        "{error:#}"
    );
    Component::new(
        &engine,
        r#"(component (import "storage" (core module (export "ring" (memory 1 1 shared)))))"#,
    )
    .expect("a memory-producing module can be imported, but not an existing memory");
}
