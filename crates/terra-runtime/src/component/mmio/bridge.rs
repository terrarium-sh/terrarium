//! Bounded host requests and shutdown for the Wasm router.

use crate::box_runtime::store::{StoreHost, StoreState};
use crate::machine::DeviceKind;
use futures_util::future::BoxFuture;
use wasmtime::component::Accessor;

use futures_util::stream::{FuturesUnordered, StreamExt};
use std::collections::{HashSet, VecDeque};

use super::{
    Access, Arc, COMMAND_CAPACITY, CONTROL_CAPACITY, Command, Control, Mutex, Operation, Ordering,
    Pending, Queue, QueueError, REQUEST_TIMEOUT, ReplyOwner, RoutedReply,
};

type BridgeOperation<'a> = BoxFuture<'a, Completion>;

struct BridgeReply {
    routed: RoutedReply,
}

pub(in crate::component) struct BridgeContext {
    pub(in crate::component) access: Access,
    pub(in crate::component) control: Control,
    pub(in crate::component) devices: super::DeviceRegistry,
    pub(in crate::component) admission: Arc<Mutex<Option<String>>>,
}

pub(in crate::component) fn create_component_loop<H: StoreHost>(
    context: BridgeContext,
    sender: Queue,
    receiver: tokio::sync::mpsc::Receiver<Pending>,
) -> crate::box_runtime::ComponentLoop<StoreState<H>> {
    Box::new(move |accessor| {
        Box::pin(async move {
            let _sender = sender;
            run_bridge(accessor, receiver, context).await
        })
    })
}

type Operations<'a> = FuturesUnordered<BridgeOperation<'a>>;
type Completion = (ReplyOwner, Option<u32>, Result<BridgeReply, QueueError>);

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

fn complete_access(
    context: &BridgeContext,
    address: u64,
    width: u8,
    routed: &RoutedReply,
) -> wasmtime::Result<()> {
    context
        .devices
        .get()
        .and_then(|devices| devices.get(routed.slot as usize))
        .filter(|device| super::owns_access(device, address, width))
        .ok_or_else(|| wasmtime::Error::msg("MMIO reply slot does not own the access"))?;
    complete_device(context, routed)
}

fn all_devices_closed(context: &BridgeContext) -> bool {
    context.devices.get().is_some_and(|devices| {
        !devices.is_empty()
            && devices
                .iter()
                .all(|device| device.closed.load(Ordering::Acquire))
    })
}

fn all_devices_closing_or_closed(context: &BridgeContext) -> bool {
    context.devices.get().is_some_and(|devices| {
        !devices.is_empty()
            && devices.iter().all(|device| {
                device.closing.load(Ordering::Acquire) || device.closed.load(Ordering::Acquire)
            })
    })
}

fn command_slot(context: &BridgeContext, command: &Command) -> Option<u32> {
    match command {
        Command::Control(slot, _) => Some(*slot),
        Command::Access(address, width, ..) => context
            .devices
            .get()
            .and_then(|devices| {
                devices
                    .iter()
                    .find(|device| super::owns_access(device, *address, *width))
            })
            .map(|device| device.slot),
    }
}

fn next_pending(
    pending: &VecDeque<(Pending, Option<u32>)>,
    active_slots: &HashSet<u32>,
    control_operations: usize,
    data_operations: usize,
) -> Option<usize> {
    pending
        .iter()
        .enumerate()
        .find_map(|(index, (request, slot))| {
            let capacity = if request.command.is_control() {
                control_operations < CONTROL_CAPACITY
            } else {
                data_operations < COMMAND_CAPACITY
            };
            let predecessor = pending
                .iter()
                .take(index)
                .any(|(_, earlier_slot)| earlier_slot == slot && slot.is_some());
            (capacity && !predecessor && slot.is_none_or(|slot| !active_slots.contains(&slot)))
                .then_some(index)
        })
}

fn router_failure(error: super::Error) -> QueueError {
    match error {
        super::Error::Unmapped | super::Error::BadWidth | super::Error::Overflow => {
            QueueError::Router(error)
        }
        super::Error::InvalidSlot
        | super::Error::InvalidVcpu
        | super::Error::UnsupportedMsr
        | super::Error::BadArmExit
        | super::Error::Overlap
        | super::Error::Busy
        | super::Error::Closed
        | super::Error::Device => QueueError::Failure(super::router_error(error)),
    }
}

fn dispatch_pending<'a, H: StoreHost>(
    accessor: &'a Accessor<StoreState<H>>,
    context: &'a BridgeContext,
    pending: Pending,
    slot: Option<u32>,
) -> BridgeOperation<'a> {
    let Pending {
        command,
        reply,
        queue_permit,
    } = pending;
    drop(queue_permit);
    Box::pin(async move {
        let result = tokio::time::timeout(REQUEST_TIMEOUT, async {
            let reply = match command {
                Command::Access(address, width, value, write) => {
                    let (result,) = context
                        .access
                        .call_concurrent(accessor, (address, width, value, write))
                        .await
                        .map_err(QueueError::Failure)?;
                    let routed = result.map_err(router_failure)?;
                    complete_access(context, address, width, &routed)
                        .map_err(QueueError::Failure)?;
                    BridgeReply { routed }
                }
                Command::Control(slot, operation) => {
                    let (result,) = context
                        .control
                        .call_concurrent(accessor, (slot, operation))
                        .await
                        .map_err(QueueError::Failure)?;
                    let control = result.map_err(router_failure)?;
                    if control.all_closed && operation != Operation::Close {
                        return Err(QueueError::Failure(wasmtime::Error::msg(
                            "MMIO service completed without a close request",
                        )));
                    }
                    if control.all_closed && !all_devices_closing_or_closed(context) {
                        return Err(QueueError::Failure(wasmtime::Error::msg(
                            "MMIO service close state disagrees with native devices",
                        )));
                    }
                    let routed = RoutedReply {
                        slot,
                        reply: control.reply,
                    };
                    complete_device(context, &routed).map_err(QueueError::Failure)?;
                    BridgeReply { routed }
                }
            };
            Ok::<_, QueueError>(reply)
        })
        .await
        .unwrap_or_else(|_| {
            Err(QueueError::Failure(wasmtime::Error::msg(
                "MMIO request timed out",
            )))
        });
        (reply, slot, result)
    })
}

fn stop_bridge(
    admission: &Mutex<Option<String>>,
    receiver: &mut tokio::sync::mpsc::Receiver<Pending>,
    reason: &str,
) {
    *admission
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(reason.to_owned());
    while receiver.try_recv().is_ok() {}
}

async fn drain_operations<'a>(control_operations: Operations<'a>, data_operations: Operations<'a>) {
    let mut operations = control_operations
        .into_iter()
        .chain(data_operations)
        .collect::<Operations<'a>>();
    while let Some((reply, _, result)) = operations.next().await {
        reply.send(result.map(|reply| reply.routed));
    }
}

async fn run_bridge<H: StoreHost>(
    accessor: &Accessor<StoreState<H>>,
    mut receiver: tokio::sync::mpsc::Receiver<Pending>,
    context: BridgeContext,
) -> wasmtime::Result<()> {
    let mut control_operations = Operations::new();
    let mut data_operations = Operations::new();
    let mut active_slots = HashSet::new();
    let mut pending: VecDeque<(Pending, Option<u32>)> = VecDeque::new();
    loop {
        let next = next_pending(
            &pending,
            &active_slots,
            control_operations.len(),
            data_operations.len(),
        );
        if let Some((request, slot)) = next.and_then(|index| pending.remove(index)) {
            if let Some(slot) = slot {
                active_slots.insert(slot);
            }
            if request.command.is_control() {
                control_operations.push(dispatch_pending(accessor, &context, request, slot));
            } else {
                data_operations.push(dispatch_pending(accessor, &context, request, slot));
            }
            continue;
        }
        let event = tokio::select! {
            completion = control_operations.next(), if !control_operations.is_empty() => completion.map(BridgeEvent::Completion),
            completion = data_operations.next(), if !data_operations.is_empty() => completion.map(BridgeEvent::Completion),
            pending = receiver.recv() => pending.map(BridgeEvent::Pending),
        };
        match event {
            Some(BridgeEvent::Pending(request)) => {
                let slot = command_slot(&context, &request.command);
                let capacity = if request.command.is_control() {
                    control_operations.len() < CONTROL_CAPACITY
                } else {
                    data_operations.len() < COMMAND_CAPACITY
                };
                let predecessor = slot.is_some_and(|slot| {
                    pending
                        .iter()
                        .any(|(_, earlier_slot)| *earlier_slot == Some(slot))
                });
                if capacity && !predecessor && slot.is_none_or(|slot| !active_slots.contains(&slot))
                {
                    if let Some(slot) = slot {
                        active_slots.insert(slot);
                    }
                    if request.command.is_control() {
                        control_operations
                            .push(dispatch_pending(accessor, &context, request, slot));
                    } else {
                        data_operations.push(dispatch_pending(accessor, &context, request, slot));
                    }
                } else {
                    pending.push_back((request, slot));
                }
            }
            Some(BridgeEvent::Completion((reply, slot, result))) => {
                if let Some(slot) = slot {
                    active_slots.remove(&slot);
                }
                let failure = result.as_ref().err().and_then(|error| match error {
                    QueueError::Router(_) => None,
                    QueueError::Failure(error) => Some(format!("MMIO router failed: {error:#}")),
                });
                reply.send(result.map(|reply| reply.routed));
                if let Some(reason) = failure {
                    stop_bridge(&context.admission, &mut receiver, &reason);
                    return Err(wasmtime::Error::msg(reason));
                }
                if all_devices_closed(&context) {
                    stop_bridge(&context.admission, &mut receiver, "MMIO bridge stopped");
                    drain_operations(control_operations, data_operations).await;
                    return Ok(());
                }
            }
            None => {
                stop_bridge(&context.admission, &mut receiver, "MMIO bridge closed");
                return Err(wasmtime::Error::msg("MMIO bridge closed"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{BoxRuntime, Reply, ReplySender, enqueue, mpsc};
    use super::*;
    use crate::box_runtime::BoxHost;

    fn access() -> Command {
        Command::Access(0, 4, 0, false)
    }

    #[test]
    fn only_guest_mmio_errors_cross_the_native_queue_as_wit_errors() {
        for error in [
            super::super::Error::Unmapped,
            super::super::Error::BadWidth,
            super::super::Error::Overflow,
        ] {
            assert!(matches!(router_failure(error), QueueError::Router(_)));
        }
        assert!(matches!(
            router_failure(super::super::Error::Device),
            QueueError::Failure(_)
        ));
    }

    #[tokio::test]
    async fn native_queue_keeps_guest_errors_typed_for_the_vmm_client() {
        let admission = Arc::new(Mutex::new(None));
        let failure = Mutex::new(None);
        let (queue, mut receiver) = Queue::new();
        let request = super::super::submit_async(&queue, &admission, &failure, access(), None);
        tokio::pin!(request);
        let pending = tokio::select! {
            result = &mut request => panic!("request completed early: {result:?}"),
            pending = receiver.recv() => pending.unwrap(),
        };
        pending
            .reply
            .send(Err(QueueError::Router(super::super::Error::Unmapped)));
        assert!(matches!(
            request.await,
            Err(QueueError::Router(super::super::Error::Unmapped))
        ));
    }

    #[tokio::test]
    async fn dropping_the_queue_resolves_async_callers_with_the_stop_reason() {
        let admission = Arc::new(Mutex::new(None));
        let (sender, receiver) = Queue::new();
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
    async fn aot_mmio_service_initializes() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
        let artifacts = crate::test_fixtures::trusted_artifacts();
        runtime
            .initialize_mmio_artifact(&artifacts)
            .await
            .expect("AOT MMIO service initializes");

        assert!(runtime.mmio.is_some());
    }

    #[test]
    fn lifecycle_controls_bypass_a_saturated_data_queue() {
        let admission = Arc::new(Mutex::new(None));
        let (queue, mut receiver) = Queue::new();
        for _ in 0..COMMAND_CAPACITY {
            enqueue(&queue, &admission, access()).expect("data queue accepts capacity");
        }
        assert!(enqueue(&queue, &admission, access()).is_err());
        enqueue(&queue, &admission, Command::Control(0, Operation::Reset))
            .expect("reset bypasses data saturation");
        enqueue(&queue, &admission, Command::Control(1, Operation::Close))
            .expect("close bypasses data saturation");

        let commands = std::iter::from_fn(|| receiver.try_recv().ok())
            .map(|pending| pending.command)
            .collect::<Vec<_>>();
        assert!(
            commands
                .iter()
                .any(|command| matches!(command, Command::Control(0, Operation::Reset)))
        );
        assert!(
            commands
                .iter()
                .any(|command| matches!(command, Command::Control(1, Operation::Close)))
        );
    }

    #[test]
    fn fifo_keeps_an_access_ahead_of_a_later_control() {
        let admission = Arc::new(Mutex::new(None));
        let (queue, mut receiver) = Queue::new();
        enqueue(&queue, &admission, access()).expect("access queues");
        enqueue(&queue, &admission, Command::Control(0, Operation::Reset)).expect("reset queues");
        assert!(matches!(
            receiver.try_recv().unwrap().command,
            Command::Access(..)
        ));
        assert!(matches!(
            receiver.try_recv().unwrap().command,
            Command::Control(0, Operation::Reset)
        ));
    }

    #[test]
    fn scheduling_keeps_same_device_controls_behind_an_access() {
        let admission = Arc::new(Mutex::new(None));
        let (queue, mut receiver) = Queue::new();
        enqueue(&queue, &admission, access()).expect("access queues");
        enqueue(&queue, &admission, Command::Control(0, Operation::Reset))
            .expect("same-device reset queues");
        enqueue(&queue, &admission, Command::Control(1, Operation::Reset))
            .expect("other-device reset queues");
        let pending = VecDeque::from([
            (receiver.try_recv().unwrap(), Some(0)),
            (receiver.try_recv().unwrap(), Some(0)),
            (receiver.try_recv().unwrap(), Some(1)),
        ]);

        assert_eq!(next_pending(&pending, &HashSet::new(), 0, 0), Some(0));
        assert_eq!(next_pending(&pending, &HashSet::from([0]), 0, 0), Some(2));
    }

    #[test]
    fn stopping_rejects_new_work_and_completes_queued_callers() {
        let admission = Arc::new(Mutex::new(None));
        let (sender, mut receiver) = Queue::new();
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
        let (sender, mut receiver) = Queue::new();
        let (reply, response) = mpsc::sync_channel(1);
        let reply = ReplyOwner {
            sender: Some(ReplySender::Sync(reply)),
            control: None,
            admission: Arc::clone(&admission),
        };
        let operation: BridgeOperation<'_> = Box::pin(async move {
            std::future::pending::<()>().await;
            (
                reply,
                None,
                Err(QueueError::Failure(wasmtime::Error::msg("unreachable"))),
            )
        });
        stop_bridge(&admission, &mut receiver, "MMIO router failed");
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
                (first_reply, None, Ok(reply(0)))
            }) as BridgeOperation<'_>,
            Box::pin(async move {
                release.send(()).expect("release first operation");
                (second_reply, None, Ok(reply(1)))
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
