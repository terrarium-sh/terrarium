//! Bounded host requests and shutdown for the Wasm router.

use crate::machine::DeviceKind;
use futures_util::future::BoxFuture;
use wasmtime::component::Accessor;

use futures_util::stream::{FuturesUnordered, StreamExt};

use super::{
    Access, Arc, BoxHost, COMMAND_CAPACITY, CONTROL_CAPACITY, Command, Control, Mutex, Operation,
    Ordering, Pending, REQUEST_TIMEOUT, ReplyOwner, RoutedReply, router_error,
};

type BridgeOperation<'a> = BoxFuture<'a, Completion>;

struct BridgeReply {
    routed: RoutedReply,
    all_closed: bool,
}

pub(in crate::component::vmm) struct BridgeContext {
    pub(in crate::component::vmm) access: Access,
    pub(in crate::component::vmm) control: Control,
    pub(in crate::component::vmm) devices: super::DeviceRegistry,
    pub(in crate::component::vmm) admission: Arc<Mutex<Option<String>>>,
}

pub(in crate::component::vmm) fn create_component_loop(
    context: BridgeContext,
    sender: tokio::sync::mpsc::Sender<Pending>,
    control_sender: tokio::sync::mpsc::Sender<Pending>,
    receiver: tokio::sync::mpsc::Receiver<Pending>,
    control_receiver: tokio::sync::mpsc::Receiver<Pending>,
) -> crate::box_runtime::ComponentLoop {
    Box::new(move |accessor| {
        Box::pin(async move {
            let _senders = (sender, control_sender);
            run_bridge(accessor, receiver, control_receiver, context).await
        })
    })
}

type Operations<'a> = FuturesUnordered<BridgeOperation<'a>>;
type Completion = (ReplyOwner, wasmtime::Result<BridgeReply>);

enum BridgeEvent {
    Pending(Pending),
    Completion(Completion),
}

fn complete_device(context: &BridgeContext, routed: &RoutedReply) -> wasmtime::Result<()> {
    let device = context
        .devices
        .get()
        .and_then(|devices| devices.get(routed.slot as usize))
        .ok_or_else(|| wasmtime::Error::msg("invalid MMIO reply slot"))?;
    if routed.reply.error != 0 {
        device.counts.failed.fetch_add(1, Ordering::Relaxed);
        let kind = match device.kind {
            DeviceKind::Block => "block",
            DeviceKind::Fs => "filesystem",
            DeviceKind::Memory => "memory",
            DeviceKind::Vsock => "vsock",
            DeviceKind::Net => "network",
        };
        return Err(wasmtime::Error::msg(format!(
            "MMIO {kind} device error {}",
            routed.reply.error
        )));
    }
    device.counts.completed.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn dispatch_pending<'a>(
    accessor: &'a Accessor<BoxHost>,
    context: &'a BridgeContext,
    pending: Pending,
) -> BridgeOperation<'a> {
    let Pending { command, reply } = pending;
    Box::pin(async move {
        let result = tokio::time::timeout(REQUEST_TIMEOUT, async {
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
        .unwrap_or_else(|_| Err(wasmtime::Error::msg("MMIO request timed out")));
        (reply, result)
    })
}

fn stop_bridge(
    admission: &Mutex<Option<String>>,
    receiver: &mut tokio::sync::mpsc::Receiver<Pending>,
    control_receiver: &mut tokio::sync::mpsc::Receiver<Pending>,
    reason: &str,
) {
    *admission
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(reason.to_owned());
    while receiver.try_recv().is_ok() {}
    while control_receiver.try_recv().is_ok() {}
}

async fn drain_operations<'a>(control_operations: Operations<'a>, data_operations: Operations<'a>) {
    let mut operations = control_operations
        .into_iter()
        .chain(data_operations)
        .collect::<Operations<'a>>();
    while let Some((reply, result)) = operations.next().await {
        reply.send(result.map(|reply| reply.routed));
    }
}

async fn run_bridge(
    accessor: &Accessor<BoxHost>,
    mut receiver: tokio::sync::mpsc::Receiver<Pending>,
    mut control_receiver: tokio::sync::mpsc::Receiver<Pending>,
    context: BridgeContext,
) -> wasmtime::Result<()> {
    let mut control_operations = Operations::new();
    let mut data_operations = Operations::new();
    loop {
        let event = tokio::select! {
            completion = control_operations.next(), if !control_operations.is_empty() => completion.map(BridgeEvent::Completion),
            completion = data_operations.next(), if !data_operations.is_empty() => completion.map(BridgeEvent::Completion),
            pending = control_receiver.recv(), if control_operations.len() < CONTROL_CAPACITY => pending.map(BridgeEvent::Pending),
            pending = receiver.recv(), if data_operations.len() < COMMAND_CAPACITY => pending.map(BridgeEvent::Pending),
        };
        match event {
            Some(BridgeEvent::Pending(pending)) => {
                if matches!(&pending.command, Command::Control(_, _)) {
                    control_operations.push(dispatch_pending(accessor, &context, pending));
                } else {
                    data_operations.push(dispatch_pending(accessor, &context, pending));
                }
            }
            Some(BridgeEvent::Completion((reply, result))) => {
                let failure = result
                    .as_ref()
                    .err()
                    .map(|error| format!("MMIO router failed: {error:#}"));
                let all_closed = result.as_ref().is_ok_and(|reply| reply.all_closed);
                reply.send(result.map(|reply| reply.routed));
                if let Some(reason) = failure {
                    stop_bridge(
                        &context.admission,
                        &mut receiver,
                        &mut control_receiver,
                        &reason,
                    );
                    return Err(wasmtime::Error::msg(reason));
                }
                if all_closed {
                    stop_bridge(
                        &context.admission,
                        &mut receiver,
                        &mut control_receiver,
                        "MMIO bridge stopped",
                    );
                    drain_operations(control_operations, data_operations).await;
                    return Ok(());
                }
            }
            None => {
                stop_bridge(
                    &context.admission,
                    &mut receiver,
                    &mut control_receiver,
                    "MMIO bridge closed",
                );
                return Err(wasmtime::Error::msg("MMIO bridge closed"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{BoxRuntime, Reply, ReplySender, enqueue, mpsc};
    use super::*;

    fn access() -> Command {
        Command::Access(0, 4, 0, false)
    }

    #[tokio::test]
    async fn dropping_the_queue_resolves_async_callers_with_the_stop_reason() {
        let admission = Arc::new(Mutex::new(None));
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let (reply, response) = tokio::sync::oneshot::channel();
        super::super::enqueue_reply(
            &sender,
            &admission,
            access(),
            ReplySender::Async(reply),
            None,
        )
        .unwrap();
        *admission.lock().unwrap() = Some("original bridge failure".to_owned());
        drop(receiver);
        assert_eq!(
            response.await.unwrap().unwrap_err().to_string(),
            "original bridge failure"
        );
    }

    #[tokio::test]
    async fn aot_router_configures_bounded_vcpu_banks_and_preserves_failures() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
        let artifacts = crate::test_fixtures::trusted_artifacts();
        runtime
            .initialize_vmm_artifact(&artifacts)
            .await
            .expect("AOT MMIO router initializes");
        runtime.configure_mmio_vcpus(2).await.expect("vCPU setup");
        assert!(runtime.configure_mmio_vcpus(33).await.is_err());

        let router = runtime.vmm.as_ref().expect("router");
        let response =
            enqueue(&router.sender, &router.admission, access()).expect("unmapped request queued");
        let failure = Arc::clone(&router.failure);
        let error = runtime
            .prepare()
            .await
            .unwrap()
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
        let admission = Arc::new(Mutex::new(None));
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
        let admission = Arc::new(Mutex::new(None));
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let first = enqueue(&sender, &admission, access()).expect("first request");
        let second = enqueue(&sender, &admission, access()).expect("second request");
        *admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some("MMIO bridge stopped".to_owned());
        assert!(enqueue(&sender, &admission, access()).is_err());
        while receiver.try_recv().is_ok() {}
        assert!(first.recv().expect("first response").is_err());
        assert!(second.recv().expect("second response").is_err());
    }

    #[test]
    fn stopping_completes_in_flight_callers_without_waiting_for_the_component() {
        let admission = Arc::new(Mutex::new(None));
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let (_control_sender, mut control_receiver) = tokio::sync::mpsc::channel(1);
        let (reply, response) = mpsc::sync_channel(1);
        let reply = ReplyOwner {
            sender: Some(ReplySender::Sync(reply)),
            control: None,
            admission: Arc::clone(&admission),
        };
        let operation: BridgeOperation<'_> = Box::pin(async move {
            std::future::pending::<()>().await;
            (reply, Err(wasmtime::Error::msg("unreachable")))
        });
        stop_bridge(
            &admission,
            &mut receiver,
            &mut control_receiver,
            "MMIO router failed",
        );
        drop(operation);
        assert_eq!(
            response
                .recv()
                .expect("in-flight response")
                .unwrap_err()
                .to_string(),
            "MMIO router failed"
        );
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
        let admission = Arc::new(Mutex::new(None));
        let first_reply = ReplyOwner {
            sender: Some(ReplySender::Sync(first_reply)),
            control: None,
            admission: Arc::clone(&admission),
        };
        let second_reply = ReplyOwner {
            sender: Some(ReplySender::Sync(second_reply)),
            control: None,
            admission,
        };
        let control_operations = [
            Box::pin(async move {
                released.await.expect("second operation releases first");
                (first_reply, Ok(reply(0)))
            }) as BridgeOperation<'_>,
            Box::pin(async move {
                release.send(()).expect("release first operation");
                (second_reply, Ok(reply(1)))
            }) as BridgeOperation<'_>,
        ]
        .into_iter()
        .collect();
        tokio::time::timeout(
            REQUEST_TIMEOUT,
            drain_operations(control_operations, Operations::new()),
        )
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
