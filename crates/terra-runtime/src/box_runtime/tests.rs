use crate::box_runtime::ComponentMemoryLimits;
use crate::engine::STORE_MEMORY_BYTES;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use super::{BOX_WASM_MEMORY_BYTES, BoxHost, BoxRuntime, BoxRuntimeHandle, MAX_BOX_COMPONENTS};
use crate::component::vmm::lifecycle::Outcome;
use crate::engine::{DeviceHost, device_engine};
use wasmtime::{Module, ResourceLimiter};

#[tokio::test]
async fn completed_device_loops_retire_without_stopping_the_box() {
    let engine = device_engine().expect("engine");
    let mut host = BoxHost::new();
    host.block.push(DeviceHost::new(4096).expect("device host"));
    let mut runtime = BoxRuntime::new(&engine, host).expect("runtime");
    runtime
        .register_loop(Box::new(|_| Box::pin(async { Ok(()) })))
        .expect("first loop");
    runtime
        .register_loop(Box::new(|_| Box::pin(async { Ok(()) })))
        .expect("second loop");

    runtime.run().await.expect("all loops exit cleanly");
}

#[tokio::test]
async fn epochs_yield_spinning_wasm_for_deadline_and_cancellation() {
    let engine = device_engine().expect("engine");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    let spin =
        Module::new(&engine, "(module (func (export \"run\") (loop br 0)))").expect("spin module");
    let spin = wasmtime::Instance::new_async(&mut runtime.store, &spin, &[])
        .await
        .expect("spin instance")
        .get_typed_func::<(), ()>(&mut runtime.store, "run")
        .expect("spin function");
    let yielded = Arc::new(AtomicBool::new(false));
    let observer = Arc::clone(&yielded);
    tokio::spawn(async move {
        tokio::task::yield_now().await;
        observer.store(true, Ordering::Release);
    });
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(250),
            spin.call_async(&mut runtime.store, ()),
        )
        .await
        .is_err()
    );
    assert!(yielded.load(Ordering::Acquire));
}

#[test]
fn resource_limits_apply_per_independent_store() {
    let mut host = BoxHost::new();
    for _ in 0..MAX_BOX_COMPONENTS {
        host.block.push(DeviceHost::new(4096).expect("device host"));
    }

    assert_eq!(ResourceLimiter::instances(&host), 16);
    assert_eq!(ResourceLimiter::memories(&host), 4);
    assert_eq!(ResourceLimiter::tables(&host), 8);
}

#[test]
fn empty_child_stores_cannot_bypass_box_capacity() {
    let engine = device_engine().expect("engine");
    let mut root = BoxRuntime::new(&engine, BoxHost::new()).expect("root");
    for _ in 0..MAX_BOX_COMPONENTS {
        let child = root.new_child(BoxHost::new()).expect("child");
        root.attach_child(child).expect("available slot");
    }
    let child = root.new_child(BoxHost::new()).expect("child");
    assert!(root.attach_child(child).is_err());
}

#[test]
fn router_host_resources_have_a_native_limit() {
    let mut host = BoxHost::new();
    for _ in 0..crate::engine::MAX_DEVICE_RESOURCES {
        host.router_table.push(0_u8).expect("resource slot");
    }
    assert!(host.router_table.push(0_u8).is_err());
}

#[test]
fn component_loop_admission_counts_attached_children() {
    let engine = device_engine().expect("engine");
    let mut root = BoxRuntime::new(&engine, BoxHost::new()).expect("root");
    let mut child = root.new_child(BoxHost::new()).expect("child");
    for _ in 0..super::MAX_BOX_COMPONENT_LOOPS {
        child
            .register_loop(Box::new(|_| Box::pin(async { Ok(()) })))
            .expect("loop slot");
    }
    root.attach_child(child).expect("attach full child");
    assert!(
        root.register_loop(Box::new(|_| Box::pin(async { Ok(()) })))
            .is_err()
    );
    let mut child = root.new_child(BoxHost::new()).expect("child");
    child
        .register_loop(Box::new(|_| Box::pin(async { Ok(()) })))
        .expect("child slot");
    assert!(root.attach_child(child).is_err());
}

#[test]
fn component_memory_limit_sums_memories_and_releases_failed_growth() {
    let mut host = BoxHost::new();
    assert!(
        ResourceLimiter::memory_growing(&mut host, 0, crate::engine::STORE_MEMORY_BYTES, None,)
            .expect("first memory reservation")
    );
    ResourceLimiter::memory_grow_failed(&mut host, wasmtime::Error::msg("allocation"))
        .expect("allocation failure rolls back");
    assert_eq!(host.wasm_memory_bytes, 0);

    assert!(
        ResourceLimiter::memory_growing(&mut host, 0, crate::engine::STORE_MEMORY_BYTES, None)
            .unwrap()
    );
    assert!(!ResourceLimiter::memory_growing(&mut host, 0, 65_536, None).unwrap());
}

#[test]
fn failed_growth_releases_only_its_reservation() {
    let mut host = BoxHost::new();
    assert!(ResourceLimiter::memory_growing(&mut host, 0, 4096, None).expect("memory reservation"));
    assert!(
        ResourceLimiter::memory_growing(&mut host, 4096, 8192, None)
            .expect("incremental memory reservation")
    );
    ResourceLimiter::memory_grow_failed(
        &mut host,
        wasmtime::Error::msg("memory growth exceeds memory type's limits"),
    )
    .expect("memory type rejection");
    assert_eq!(host.wasm_memory_bytes, 4096);
    assert_eq!(host.memory_budget.reserved(), 4096);
    assert!(
            !ResourceLimiter::memory_growing(
                &mut host,
                0,
                crate::engine::STORE_MEMORY_BYTES + 1,
                None,
            )
            .expect("per-memory cap")
        );
}

#[test]
fn child_stores_share_the_box_memory_budget() {
    let engine = device_engine().expect("engine");
    let mut root = BoxRuntime::new(&engine, BoxHost::new()).expect("root runtime");
    let mut children = (0..(BOX_WASM_MEMORY_BYTES / crate::engine::STORE_MEMORY_BYTES - 1))
        .map(|_| root.new_child(BoxHost::new()).expect("child runtime"))
        .collect::<Vec<_>>();

    assert!(
        ResourceLimiter::memory_growing(
            root.store.data_mut(),
            0,
            crate::engine::STORE_MEMORY_BYTES,
            None,
        )
        .expect("root reservation")
    );
    for child in &mut children {
        assert!(
            ResourceLimiter::memory_growing(
                child.store.data_mut(),
                0,
                crate::engine::STORE_MEMORY_BYTES,
                None,
            )
            .expect("child reservation")
        );
    }

    let mut rejected = root
        .new_child(BoxHost::new())
        .expect("rejected child runtime");
    assert!(
        !ResourceLimiter::memory_growing(
            rejected.store.data_mut(),
            0,
            crate::engine::STORE_MEMORY_BYTES,
            None,
        )
        .expect("box cap")
    );
    drop(children);
    assert_eq!(
        root.memory_budget.reserved(),
        crate::engine::STORE_MEMORY_BYTES
    );
}

#[test]
fn dropped_boot_store_releases_its_shared_memory_reservation() {
    let engine = device_engine().expect("engine");
    let root = BoxRuntime::new(&engine, BoxHost::new()).expect("root runtime");
    let mut boot = root.new_child(BoxHost::new()).expect("boot store");
    assert!(
        ResourceLimiter::memory_growing(
            boot.store.data_mut(),
            0,
            crate::engine::STORE_MEMORY_BYTES,
            None,
        )
        .expect("boot memory reservation")
    );
    drop(boot);
    assert_eq!(root.memory_budget.reserved(), 0);
}

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

async fn wait_for_drop(dropped: &AtomicBool) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while !dropped.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("runtime task drops its resources");
}

async fn running_handle(dropped: Arc<AtomicBool>) -> BoxRuntimeHandle {
    let (started, ready) = tokio::sync::oneshot::channel();
    let handle = BoxRuntimeHandle(Some(tokio::spawn(async move {
        let _flag = DropFlag(dropped);
        let _ = started.send(());
        std::future::pending::<wasmtime::Result<()>>().await
    })));
    ready.await.expect("runtime task starts");
    handle
}

#[tokio::test]
async fn cancelling_join_aborts_the_runtime_task() {
    let dropped = Arc::new(AtomicBool::new(false));
    let handle = running_handle(Arc::clone(&dropped)).await;
    let join = tokio::spawn(async move { handle.join().await });
    tokio::task::yield_now().await;
    join.abort();
    let _ = join.await;
    wait_for_drop(&dropped).await;
}

#[tokio::test]
async fn shutdown_deadline_aborts_a_cooperative_runtime_task() {
    let dropped = Arc::new(AtomicBool::new(false));
    let mut handle = running_handle(Arc::clone(&dropped)).await;
    let error = handle
        .wait_for_task(Duration::ZERO, false)
        .await
        .expect_err("pending runtime exceeds shutdown deadline");
    assert_eq!(error.to_string(), "box runtime shutdown timed out");
    wait_for_drop(&dropped).await;
}

#[tokio::test]
async fn child_failure_stops_the_runtime_group() {
    let engine = device_engine().expect("engine");
    let mut root = BoxRuntime::new(&engine, BoxHost::new()).expect("root runtime");
    let mut outcome = root.lifecycle_notifier().subscribe();
    let dropped = Arc::new(AtomicBool::new(false));
    let child_drop = DropFlag(Arc::clone(&dropped));
    let mut child = root.new_child(BoxHost::new()).expect("child runtime");
    child
        .register_loop(Box::new(move |_| {
            let drop_flag = child_drop;
            Box::pin(async move {
                let _drop = drop_flag;
                std::future::pending::<wasmtime::Result<()>>().await
            })
        }))
        .expect("child loop");
    root.attach_child(child).expect("attach child");
    root.register_loop(Box::new(|_| {
        Box::pin(async { Err(wasmtime::Error::msg("root worker failed")) })
    }))
    .expect("root loop");

    root.start().join().await.expect_err("root worker failure");
    wait_for_drop(&dropped).await;
    assert_eq!(*outcome.borrow_and_update(), Some(Outcome::ComponentFailed));
}

#[tokio::test]
async fn completed_root_stops_child_workers() {
    let engine = device_engine().expect("engine");
    let mut root = BoxRuntime::new(&engine, BoxHost::new()).expect("root runtime");
    let dropped = Arc::new(AtomicBool::new(false));
    let child_drop = DropFlag(Arc::clone(&dropped));
    let mut child = root.new_child(BoxHost::new()).expect("child runtime");
    let mut shutdown = child.shutdown.subscribe();
    child
        .register_loop(Box::new(move |_| {
            let drop_flag = child_drop;
            Box::pin(async move {
                let _drop = drop_flag;
                shutdown.changed().await.expect("root shutdown signal");
                Ok(())
            })
        }))
        .expect("child loop");
    root.attach_child(child).expect("attach child");
    root.register_loop(Box::new(|_| Box::pin(async { Ok(()) })))
        .expect("root loop");

    root.start().join().await.expect("root completion");
    wait_for_drop(&dropped).await;
}

#[tokio::test]
async fn root_and_child_stores_make_progress_together() {
    let engine = device_engine().expect("engine");
    let mut root = BoxRuntime::new(&engine, BoxHost::new()).expect("root runtime");
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let completed = Arc::new(AtomicUsize::new(0));
    let mut child = root.new_child(BoxHost::new()).expect("child runtime");
    let child_barrier = Arc::clone(&barrier);
    let child_completed = Arc::clone(&completed);
    child
        .register_loop(Box::new(move |_| {
            Box::pin(async move {
                child_barrier.wait().await;
                child_completed.fetch_add(1, Ordering::AcqRel);
                Ok(())
            })
        }))
        .expect("child loop");
    root.attach_child(child).expect("attach child");
    let root_completed = Arc::clone(&completed);
    root.register_loop(Box::new(move |_| {
        let barrier = Arc::clone(&barrier);
        let completed = Arc::clone(&root_completed);
        Box::pin(async move {
            barrier.wait().await;
            completed.fetch_add(1, Ordering::AcqRel);
            Ok(())
        })
    }))
    .expect("root loop");

    tokio::time::timeout(Duration::from_secs(1), root.start().join())
        .await
        .expect("stores make progress in parallel")
        .expect("runtime completion");
    assert_eq!(completed.load(Ordering::Acquire), 2);
}

#[tokio::test]
async fn child_failure_during_shutdown_fails_the_group() {
    let engine = device_engine().expect("engine");
    let mut root = BoxRuntime::new(&engine, BoxHost::new()).expect("root");
    let outcome = root.lifecycle_notifier().subscribe();
    root.register_loop(Box::new(|_| Box::pin(async { Ok(()) })))
        .expect("root loop");
    let mut child = root.new_child(BoxHost::new()).expect("child");
    let mut shutdown = child.shutdown.subscribe();
    child
        .register_loop(Box::new(move |_| {
            Box::pin(async move {
                shutdown
                    .wait_for(|stopping| *stopping)
                    .await
                    .expect("shutdown");
                Err(wasmtime::Error::msg("child flush failed"))
            })
        }))
        .expect("child loop");
    root.attach_child(child).expect("attach child");
    let error = root
        .start()
        .join()
        .await
        .expect_err("flush error propagates");
    assert_eq!(error.to_string(), "child flush failed");
    assert_eq!(*outcome.borrow(), Some(Outcome::ComponentFailed));
}

#[tokio::test]
async fn configured_component_limit_counts_all_memories_and_is_inherited() {
    let engine = device_engine().unwrap();
    let limits = ComponentMemoryLimits::new(65_536, 131_072).unwrap();
    let root = BoxRuntime::new(&engine, BoxHost::with_memory_limits(limits)).unwrap();
    let mut first = root.new_child(BoxHost::new()).unwrap();
    let mut peer = root.new_child(BoxHost::new()).unwrap();
    let two_memories = wasmtime::Module::new(&engine, "(module (memory 1) (memory 1))").unwrap();
    let error = wasmtime::Instance::new_async(&mut first.store, &two_memories, &[])
        .await
        .expect_err("combined memory limit");
    assert!(error.to_string().contains("memory"), "{error}");
    let memory = wasmtime::Module::new(&engine, "(module (memory 1))").unwrap();
    wasmtime::Instance::new_async(&mut peer.store, &memory, &[])
        .await
        .unwrap();
    assert!(
        !ResourceLimiter::memory_growing(peer.store.data_mut(), 65_536, 131_072, None).unwrap()
    );
    drop(first);
    let mut replacement = root.new_child(BoxHost::new()).unwrap();
    wasmtime::Instance::new_async(&mut replacement.store, &memory, &[])
        .await
        .unwrap();
}

#[test]
fn component_limits_can_be_raised_and_invalid_limits_are_rejected() {
    assert!(ComponentMemoryLimits::new(0, 1).is_err());
    assert!(ComponentMemoryLimits::new(2, 1).is_err());
    let mut host = BoxHost::with_memory_limits(
        ComponentMemoryLimits::new(STORE_MEMORY_BYTES * 2, BOX_WASM_MEMORY_BYTES).unwrap(),
    );
    assert!(ResourceLimiter::memory_growing(&mut host, 0, STORE_MEMORY_BYTES * 2, None).unwrap());
}

#[test]
fn policy_memory_reservation_preserves_the_total_box_limit() {
    let limits = ComponentMemoryLimits::new(16 << 20, 128 << 20).unwrap();
    let (remaining, policy_bytes) = limits.reserve_policy().unwrap();
    assert_eq!(policy_bytes, 16 << 20);
    assert_eq!(remaining.total_bytes() + policy_bytes, limits.total_bytes());
    assert!(
        ComponentMemoryLimits::new(16 << 20, 16 << 20)
            .unwrap()
            .reserve_policy()
            .is_err()
    );
}

#[tokio::test]
async fn cancelled_recovery_retains_cleanup_order() {
    use crate::component::vmm::{machine::DeviceKind, teardown::DeviceShutdown};
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let (finished, completed) = tokio::sync::oneshot::channel();
    let first_finished = Arc::new(AtomicBool::new(false));
    let first_observer = Arc::clone(&first_finished);
    let devices = vec![
        DeviceShutdown::new(DeviceKind::Memory, move || {
            entered.send(()).unwrap();
            released.recv_timeout(Duration::from_secs(2)).unwrap();
            first_finished.store(true, Ordering::Release);
            Ok(())
        }),
        DeviceShutdown::new(DeviceKind::Block, move || {
            assert!(first_observer.load(Ordering::Acquire));
            finished.send(()).unwrap();
            Ok(())
        }),
    ];
    {
        let recovering = super::finish_native_recovery(super::DropRecovery {
            machine: None,
            devices,
            interrupts: None,
        });
        tokio::pin!(recovering);
        tokio::select! {
            result = &mut recovering => panic!("recovery completed before release: {result:?}"),
            result = started => result.unwrap(),
        }
    }
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), completed)
        .await
        .unwrap()
        .unwrap();
}
