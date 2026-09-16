//! Bounded host requests and shutdown for the Wasm router.

use std::future::Future;
use std::pin::Pin;
use wasmtime::component::Accessor;

use super::{
    Access, Arc, BoxHost, COMMAND_CAPACITY, CONTROL_CAPACITY, Command, Control,
    DeviceRequestCounts, Mutex, Operation, Ordering, Pending, REQUEST_TIMEOUT, RoutedReply, mpsc,
    router_error,
};

struct BridgeOperation<'a> {
    is_control: bool,
    reply: mpsc::SyncSender<wasmtime::Result<RoutedReply>>,
    future: Pin<Box<dyn Future<Output = wasmtime::Result<BridgeReply>> + Send + 'a>>,
}

struct BridgeReply {
    routed: RoutedReply,
    all_closed: bool,
}

pub(super) struct BridgeContext {
    pub(super) access: Access,
    pub(super) control: Control,
    pub(super) callbacks: Arc<Mutex<Vec<DeviceRequestCounts>>>,
    pub(super) admission: Arc<Mutex<bool>>,
}

enum BridgeEvent {
    Pending(Pending),
    Completion(usize, wasmtime::Result<BridgeReply>),
}

fn complete_device(context: &BridgeContext, routed: &RoutedReply) -> wasmtime::Result<()> {
    let device = context
        .callbacks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(usize::try_from(routed.slot)?)
        .cloned()
        .ok_or_else(|| wasmtime::Error::msg("invalid MMIO reply slot"))?;
    if routed.reply.error != 0 {
        device.failed.fetch_add(1, Ordering::Relaxed);
        return Err(wasmtime::Error::msg(format!(
            "MMIO device error {}",
            routed.reply.error
        )));
    }
    device.completed.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn dispatch_pending<'a>(
    accessor: &'a Accessor<BoxHost>,
    context: &'a BridgeContext,
    pending: Pending,
) -> BridgeOperation<'a> {
    let Pending { command, reply } = pending;
    let is_control = matches!(command, Command::Control(_, _));
    BridgeOperation {
        is_control,
        reply,
        future: Box::pin(async move {
            tokio::time::timeout(REQUEST_TIMEOUT, async {
                let reply = match command {
                    Command::Access(address, width, value, write) => {
                        let (result,) = context
                            .access
                            .call_concurrent(accessor, (address, width, value, write))
                            .await?;
                        let routed = result.map_err(router_error)?;
                        complete_device(context, &routed)?;
                        BridgeReply {
                            routed,
                            all_closed: false,
                        }
                    }
                    Command::Control(slot, operation) => {
                        let (result,) = context
                            .control
                            .call_concurrent(accessor, (slot, operation))
                            .await?;
                        let control = result.map_err(router_error)?;
                        wasmtime::ensure!(
                            !control.all_closed || operation == Operation::Close,
                            "MMIO service completed without a close request"
                        );
                        let routed = RoutedReply {
                            slot,
                            reply: control.reply,
                        };
                        complete_device(context, &routed)?;
                        BridgeReply {
                            routed,
                            all_closed: control.all_closed,
                        }
                    }
                };
                Ok(reply)
            })
            .await
            .unwrap_or_else(|_| Err(wasmtime::Error::msg("MMIO request timed out")))
        }),
    }
}

fn reject_pending(pending: &Pending, reason: &str) {
    let _ = pending
        .reply
        .send(Err(wasmtime::Error::msg(reason.to_owned())));
}

fn reject_receiver(receiver: &mut tokio::sync::mpsc::Receiver<Pending>, reason: &str) {
    while let Ok(pending) = receiver.try_recv() {
        reject_pending(&pending, reason);
    }
}

fn stop_bridge(
    admission: &Mutex<bool>,
    receiver: &mut tokio::sync::mpsc::Receiver<Pending>,
    control_receiver: &mut tokio::sync::mpsc::Receiver<Pending>,
    operations: Vec<BridgeOperation<'_>>,
    reason: &str,
) {
    *admission
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
    reject_receiver(receiver, reason);
    reject_receiver(control_receiver, reason);
    for operation in operations {
        let _ = operation
            .reply
            .send(Err(wasmtime::Error::msg(reason.to_owned())));
    }
}

fn bridge_error(
    admission: &Mutex<bool>,
    receiver: &mut tokio::sync::mpsc::Receiver<Pending>,
    control_receiver: &mut tokio::sync::mpsc::Receiver<Pending>,
    operations: Vec<BridgeOperation<'_>>,
    reason: &str,
) -> wasmtime::Result<()> {
    stop_bridge(admission, receiver, control_receiver, operations, reason);
    Err(wasmtime::Error::msg(reason.to_owned()))
}

fn poll_completion(
    operations: &mut [BridgeOperation<'_>],
    context: &mut std::task::Context<'_>,
) -> std::task::Poll<(usize, wasmtime::Result<BridgeReply>)> {
    for (index, operation) in operations.iter_mut().enumerate() {
        if let std::task::Poll::Ready(result) = operation.future.as_mut().poll(context) {
            return std::task::Poll::Ready((index, result));
        }
    }
    std::task::Poll::Pending
}

async fn drain_operations(mut operations: Vec<BridgeOperation<'_>>) {
    while !operations.is_empty() {
        let (index, result) =
            std::future::poll_fn(|context| poll_completion(&mut operations, context)).await;
        let operation = operations.swap_remove(index);
        let _ = operation.reply.send(result.map(|reply| reply.routed));
    }
}

pub(super) async fn run_bridge(
    accessor: &Accessor<BoxHost>,
    mut receiver: tokio::sync::mpsc::Receiver<Pending>,
    mut control_receiver: tokio::sync::mpsc::Receiver<Pending>,
    context: BridgeContext,
) -> wasmtime::Result<()> {
    let mut operations: Vec<BridgeOperation<'_>> =
        Vec::with_capacity(COMMAND_CAPACITY + CONTROL_CAPACITY);
    loop {
        let controls = operations
            .iter()
            .filter(|operation| operation.is_control)
            .count();
        let accepts_data = operations.len() - controls < COMMAND_CAPACITY;
        let accepts_control = controls < CONTROL_CAPACITY;
        let has_operations = !operations.is_empty();
        let next_completion =
            std::future::poll_fn(|context| poll_completion(&mut operations, context));
        let event = tokio::select! {
            (index, result) = next_completion, if has_operations => Some(BridgeEvent::Completion(index, result)),
            pending = control_receiver.recv(), if accepts_control => pending.map(BridgeEvent::Pending),
            pending = receiver.recv(), if accepts_data => pending.map(BridgeEvent::Pending),
        };
        match event {
            Some(BridgeEvent::Pending(pending)) => {
                operations.push(dispatch_pending(accessor, &context, pending));
            }
            Some(BridgeEvent::Completion(index, result)) => {
                let operation = operations.swap_remove(index);
                let failure = result
                    .as_ref()
                    .err()
                    .map(|error| format!("MMIO router failed: {error:#}"));
                let all_closed = result.as_ref().is_ok_and(|reply| reply.all_closed);
                let _ = operation.reply.send(result.map(|reply| reply.routed));
                if let Some(reason) = failure {
                    return bridge_error(
                        &context.admission,
                        &mut receiver,
                        &mut control_receiver,
                        operations,
                        &reason,
                    );
                }
                if all_closed {
                    stop_bridge(
                        &context.admission,
                        &mut receiver,
                        &mut control_receiver,
                        Vec::new(),
                        "MMIO bridge stopped",
                    );
                    drain_operations(operations).await;
                    return Ok(());
                }
            }
            None => {
                return bridge_error(
                    &context.admission,
                    &mut receiver,
                    &mut control_receiver,
                    operations,
                    "MMIO bridge closed",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{BoxRuntime, Reply, enqueue};
    use super::*;

    fn access() -> Command {
        Command::Access(0, 4, 0, false)
    }

    #[tokio::test]
    async fn aot_router_configures_bounded_vcpu_banks_and_preserves_failures() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
        // SAFETY: these test bytes are built AOT artifacts for this exact runtime.
        #[allow(unsafe_code)]
        let artifacts = unsafe {
            crate::TrustedArtifacts::new(
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../build/terra-block-component.cwasm"
                )),
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../build/terra-vsock-component.cwasm"
                )),
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../build/terra-network-component.cwasm"
                )),
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../build/terra-fs-component.cwasm"
                )),
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../build/terra-mem-component.cwasm"
                )),
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../build/terra-boot-component.cwasm"
                )),
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../build/terra-vmm-component.cwasm"
                )),
            )
        };
        runtime
            .initialize_mmio_artifact(&artifacts)
            .await
            .expect("AOT MMIO router initializes");
        runtime.configure_mmio_vcpus(2).await.expect("vCPU setup");
        assert!(runtime.configure_mmio_vcpus(33).await.is_err());

        let router = runtime.mmio.as_ref().expect("router");
        let response =
            enqueue(&router.sender, &router.admission, access()).expect("unmapped request queued");
        let failure = Arc::clone(&router.failure);
        let error = runtime
            .start()
            .join()
            .await
            .expect_err("unmapped access fails");
        assert!(error.to_string().contains("unmapped"), "{error:#}");
        assert!(
            response
                .recv()
                .expect("response")
                .unwrap_err()
                .to_string()
                .contains("unmapped")
        );
        assert!(
            failure
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .contains("unmapped")
        );
    }

    #[test]
    fn lifecycle_controls_bypass_a_saturated_data_queue() {
        let admission = Mutex::new(true);
        let (data_sender, mut data_receiver) = tokio::sync::mpsc::channel(COMMAND_CAPACITY);
        let (control_sender, mut control_receiver) = tokio::sync::mpsc::channel(CONTROL_CAPACITY);
        for _ in 0..COMMAND_CAPACITY {
            enqueue(&data_sender, &admission, access()).expect("data queue accepts capacity");
        }
        assert!(enqueue(&data_sender, &admission, access()).is_err());
        enqueue(
            &control_sender,
            &admission,
            Command::Control(0, Operation::Reset),
        )
        .expect("reset bypasses data saturation");
        enqueue(
            &control_sender,
            &admission,
            Command::Control(1, Operation::Close),
        )
        .expect("close bypasses data saturation");

        assert!(matches!(
            control_receiver
                .try_recv()
                .expect("reset is queued")
                .command,
            Command::Control(0, Operation::Reset)
        ));
        assert!(matches!(
            control_receiver
                .try_recv()
                .expect("close is queued")
                .command,
            Command::Control(1, Operation::Close)
        ));
        assert!(data_receiver.try_recv().is_ok());
    }

    #[test]
    fn stopping_rejects_new_work_and_completes_queued_callers() {
        let admission = Mutex::new(true);
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let first = enqueue(&sender, &admission, access()).expect("first request");
        let second = enqueue(&sender, &admission, access()).expect("second request");
        *admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
        assert!(enqueue(&sender, &admission, access()).is_err());
        reject_receiver(&mut receiver, "MMIO bridge stopped");
        assert!(first.recv().expect("first response").is_err());
        assert!(second.recv().expect("second response").is_err());
    }

    #[test]
    fn stopping_completes_in_flight_callers_without_waiting_for_the_component() {
        let admission = Mutex::new(true);
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let (_control_sender, mut control_receiver) = tokio::sync::mpsc::channel(1);
        let (reply, response) = mpsc::sync_channel(1);
        stop_bridge(
            &admission,
            &mut receiver,
            &mut control_receiver,
            vec![BridgeOperation {
                is_control: false,
                reply,
                future: Box::pin(std::future::pending()),
            }],
            "MMIO router failed",
        );
        assert!(response.recv().expect("in-flight response").is_err());
        assert!(enqueue(&sender, &admission, access()).is_err());
    }

    #[tokio::test]
    async fn normal_shutdown_drains_in_flight_replies_concurrently() {
        let (first_reply, first) = mpsc::sync_channel(1);
        let (second_reply, second) = mpsc::sync_channel(1);
        let (release, released) = tokio::sync::oneshot::channel();
        let reply = |slot| BridgeReply {
            routed: RoutedReply {
                slot,
                reply: Reply {
                    sequence: 0,
                    value: 0,
                    error: 0,
                    interrupt: false,
                },
            },
            all_closed: false,
        };
        let operations = vec![
            BridgeOperation {
                is_control: true,
                reply: first_reply,
                future: Box::pin(async move {
                    released.await.expect("second operation releases first");
                    Ok(reply(0))
                }),
            },
            BridgeOperation {
                is_control: true,
                reply: second_reply,
                future: Box::pin(async move {
                    release.send(()).expect("release first operation");
                    Ok(reply(1))
                }),
            },
        ];
        tokio::time::timeout(REQUEST_TIMEOUT, drain_operations(operations))
            .await
            .expect("shutdown polls all in-flight operations");
        assert_eq!(
            first
                .recv()
                .expect("first response")
                .expect("first reply")
                .slot,
            0
        );
        assert_eq!(
            second
                .recv()
                .expect("second response")
                .expect("second reply")
                .slot,
            1
        );
    }
}
