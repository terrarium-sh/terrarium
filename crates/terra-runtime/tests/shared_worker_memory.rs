#![allow(clippy::expect_used, unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use wasmtime::component::{Component, Linker};
use wasmtime::{
    Config, Engine, Instance, LinearMemory, MemoryCreator, MemoryType, Module, SharedMemory, Store,
};

fn shared_engine() -> Engine {
    let mut config = Config::new();
    config
        .wasm_component_model_async(true)
        .concurrency_support(true)
        .wasm_threads(true)
        .shared_memory(true);
    Engine::new(&config).expect("shared-memory test engine")
}

const SHARED_RING: &str = r#"(module
    (import "ring" "memory" (memory 1 1 shared))
    (func (export "add") (param i32) (result i32)
        i32.const 0 local.get 0 i32.atomic.rmw.add))"#;

#[test]
fn core_modules_share_one_memory_across_independent_stores() {
    let engine = shared_engine();
    let memory =
        SharedMemory::new(&engine, MemoryType::shared(1, 1)).expect("bounded shared memory");
    let module = Module::new(&engine, SHARED_RING).expect("core worker module");
    let mut producer_store = Store::new(&engine, ());
    let producer = Instance::new(&mut producer_store, &module, &[memory.clone().into()])
        .expect("producer instance");
    let producer = producer
        .get_typed_func::<u32, u32>(&mut producer_store, "add")
        .expect("producer add");
    let mut consumer_store = Store::new(&engine, ());
    let consumer = Instance::new(&mut consumer_store, &module, &[memory.clone().into()])
        .expect("consumer instance");
    let consumer = consumer
        .get_typed_func::<u32, u32>(&mut consumer_store, "add")
        .expect("consumer add");
    assert_eq!(
        memory
            .data()
            .as_ptr()
            .align_offset(std::mem::align_of::<AtomicU32>()),
        0
    );
    // SAFETY: the page-aligned allocation stays alive and this word is atomic.
    #[allow(clippy::cast_ptr_alignment)]
    let word = unsafe { &*memory.data().as_ptr().cast::<AtomicU32>() };
    word.store(40, Ordering::Release);

    assert_eq!(
        producer.call(&mut producer_store, 1).expect("producer add"),
        40
    );
    assert_eq!(
        consumer.call(&mut consumer_store, 1).expect("consumer add"),
        41
    );
    assert_eq!(word.load(Ordering::Acquire), 42);
}

const COMPONENT_RING_IMPORT: &str = r#"(component
    (import "storage" (core module $storage
        (export "ring" (memory 1 1 shared))))
    (core instance $storage-instance (instantiate $storage))
    (core module $worker
        (import "storage" "ring" (memory 1 1 shared))
        (func (export "add") (param i32) (result i32)
            i32.const 0 local.get 0 i32.atomic.rmw.add))
    (core instance $worker-instance
        (instantiate $worker (with "storage" (instance $storage-instance))))
    (alias core export $worker-instance "add" (core func $add))
    (func (export "add") (param "value" u32) (result u32)
        (canon lift (core func $add))))"#;

#[tokio::test]
async fn component_module_imports_are_reinstantiated_per_store() {
    let engine = shared_engine();
    let storage = Module::new(&engine, r#"(module (memory (export "ring") 1 1 shared))"#)
        .expect("shared storage module");
    let component = Component::new(&engine, COMPONENT_RING_IMPORT).expect("worker component");
    let mut linker = Linker::new(&engine);
    linker
        .root()
        .module("storage", &storage)
        .expect("storage import");
    let mut first_store = Store::new(&engine, ());
    let first = linker
        .instantiate_async(&mut first_store, &component)
        .await
        .expect("first component");
    let first = first
        .get_typed_func::<(u32,), (u32,)>(&mut first_store, "add")
        .expect("first add");
    let mut second_store = Store::new(&engine, ());
    let second = linker
        .instantiate_async(&mut second_store, &component)
        .await
        .expect("second component");
    let second = second
        .get_typed_func::<(u32,), (u32,)>(&mut second_store, "add")
        .expect("second add");

    assert_eq!(
        first
            .call_async(&mut first_store, (1,))
            .await
            .expect("first add"),
        (0,)
    );
    assert_eq!(
        second
            .call_async(&mut second_store, (1,))
            .await
            .expect("second add"),
        (0,)
    );
}

struct RejectingMemoryCreator {
    calls: AtomicUsize,
}

unsafe impl MemoryCreator for RejectingMemoryCreator {
    fn new_memory(
        &self,
        _ty: MemoryType,
        _minimum: usize,
        _maximum: Option<usize>,
        _reserved_size_in_bytes: Option<usize>,
        _guard_size_in_bytes: usize,
    ) -> Result<Box<dyn LinearMemory>, String> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Err("shared allocation reached MemoryCreator".to_owned())
    }
}

#[tokio::test]
async fn memory_creator_receives_component_auxiliary_shared_memory_allocations() {
    let creator = Arc::new(RejectingMemoryCreator {
        calls: AtomicUsize::new(0),
    });
    let mut config = Config::new();
    config
        .wasm_component_model_async(true)
        .concurrency_support(true)
        .wasm_threads(true)
        .shared_memory(true)
        .with_host_memory(creator.clone());
    let engine = Engine::new(&config).expect("shared-memory engine");
    let component = Component::new(
        &engine,
        r"(component
            (core module $ring (memory 1 1 shared))
            (core instance $ring (instantiate $ring)))",
    )
    .expect("component with auxiliary shared memory");
    let linker = Linker::<()>::new(&engine);
    let mut store = Store::new(&engine, ());
    let error = linker
        .instantiate_async(&mut store, &component)
        .await
        .expect_err("creator rejects the shared allocation");

    assert_eq!(creator.calls.load(Ordering::Relaxed), 1);
    assert!(format!("{error:#}").contains("shared allocation reached MemoryCreator"));
}

#[test]
fn core_workers_exchange_atomics_on_dedicated_tokio_threads() {
    let engine = shared_engine();
    let memory = SharedMemory::new(&engine, MemoryType::shared(1, 1)).expect("fixed memory");
    let module = Module::new(&engine, SHARED_RING).expect("atomic worker");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let engine = engine.clone();
            let memory = memory.clone();
            let module = module.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("worker runtime")
                    .block_on(async move {
                        let mut store = Store::new(&engine, ());
                        let instance = Instance::new_async(&mut store, &module, &[memory.into()])
                            .await
                            .expect("worker instance");
                        let add = instance
                            .get_typed_func::<u32, u32>(&mut store, "add")
                            .expect("atomic add");
                        barrier.wait();
                        for _ in 0..1024 {
                            add.call_async(&mut store, 1)
                                .await
                                .expect("atomic increment");
                            tokio::task::yield_now().await;
                        }
                        std::thread::current().id()
                    })
            })
        })
        .collect();
    let identities: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker exits"))
        .collect();
    assert_ne!(identities[0], identities[1]);
    let mut store = Store::new(&engine, ());
    let instance = Instance::new(&mut store, &module, &[memory.into()]).expect("observer");
    let add = instance
        .get_typed_func::<u32, u32>(&mut store, "add")
        .expect("observer add");
    assert_eq!(add.call(&mut store, 0).expect("read counter"), 2048);
}
