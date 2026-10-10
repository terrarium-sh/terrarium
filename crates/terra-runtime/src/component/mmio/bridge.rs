//! Bounded native MMIO routing and shutdown.

use crate::machine::DeviceKind;
use futures_util::future::BoxFuture;
use futures_util::stream::{FuturesUnordered, StreamExt};
use std::collections::{HashSet, VecDeque};

use super::{
    Arc, COMMAND_CAPACITY, CONTROL_CAPACITY, Command, DeviceChannel, Mutex, Operation, Ordering,
    Pending, Queue, QueueError, REQUEST_TIMEOUT, ReplyOwner, RoutedReply,
};

type BridgeOperation<'a> = BoxFuture<'a, Completion>;
type Completion = (
    ReplyOwner,
    Option<(u32, DeviceChannel)>,
    Result<RoutedReply, QueueError>,
);
type Operations<'a> = FuturesUnordered<BridgeOperation<'a>>;

pub(crate) struct BridgeContext {
    pub devices: super::DeviceRegistry,
    pub admission: Arc<Mutex<Option<String>>>,
}

pub(crate) fn create_component_loop(
    context: BridgeContext,
    sender: Queue,
    receiver: tokio::sync::mpsc::Receiver<Pending>,
    channels: Vec<Option<DeviceChannel>>,
) -> crate::box_runtime::ComponentLoop {
    Box::new(move |_| {
        Box::pin(async move {
            let _sender = sender;
            run_bridge(receiver, context, channels).await
        })
    })
}

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
    if let Some(error) = routed.reply.error {
        device.counts.failed.fetch_add(1, Ordering::Relaxed);
        let kind = match device.kind {
            DeviceKind::Block => "block",
            DeviceKind::Fs => "filesystem",
            DeviceKind::Memory => "memory",
            DeviceKind::Vsock => "vsock",
        };
        return Err(wasmtime::Error::msg(format!(
            "MMIO {kind} device error {error:?}"
        )));
    }
    device.counts.completed.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn all_devices_closed(context: &BridgeContext) -> bool {
    context.devices.get().is_some_and(|devices| {
        !devices.is_empty()
            && devices
                .iter()
                .all(|device| device.closed.load(Ordering::Acquire))
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
        super::Error::InvalidSlot | super::Error::Closed | super::Error::Device => {
            QueueError::Failure(super::router_error(error))
        }
    }
}

fn request_fields(
    context: &BridgeContext,
    command: &Command,
    slot: Option<u32>,
) -> Result<(Operation, u64, u8, u64), QueueError> {
    match *command {
        Command::Access(address, width, value, write) => {
            if !matches!(width, 1 | 2 | 4 | 8) {
                return Err(router_failure(super::Error::BadWidth));
            }
            address
                .checked_add(u64::from(width))
                .ok_or_else(|| router_failure(super::Error::Overflow))?;
            let device = slot
                .and_then(|slot| context.devices.get()?.get(slot as usize))
                .filter(|device| !device.closed.load(Ordering::Acquire))
                .ok_or_else(|| router_failure(super::Error::Unmapped))?;
            Ok((
                if write {
                    Operation::Write
                } else {
                    Operation::Read
                },
                address - device.base.load(Ordering::Acquire),
                width,
                value,
            ))
        }
        Command::Control(_, operation) => Ok((operation, 0, 0, 0)),
    }
}

fn dispatch_pending(
    context: &BridgeContext,
    pending: Pending,
    slot: Option<u32>,
    channel: Option<DeviceChannel>,
) -> BridgeOperation<'_> {
    let Pending {
        command,
        reply,
        queue_permit,
    } = pending;
    drop(queue_permit);
    Box::pin(async move {
        let mut channel = slot.zip(channel);
        let result = tokio::time::timeout(REQUEST_TIMEOUT, async {
            let (operation, offset, width, value) = request_fields(context, &command, slot)?;
            let (slot, channel) = channel
                .as_mut()
                .ok_or_else(|| router_failure(super::Error::InvalidSlot))?;
            let sequence = channel.sequence;
            channel.sequence = sequence
                .checked_add(1)
                .ok_or_else(|| router_failure(super::Error::Device))?;
            channel
                .requests
                .send(super::Request {
                    sequence,
                    operation,
                    offset,
                    width,
                    value,
                })
                .await
                .map_err(QueueError::Failure)?;
            let response = channel
                .replies
                .next()
                .await
                .ok_or_else(|| router_failure(super::Error::Closed))?;
            if response.sequence != sequence {
                return Err(router_failure(super::Error::Device));
            }
            let routed = RoutedReply {
                slot: *slot,
                reply: response,
            };
            complete_device(context, &routed).map_err(QueueError::Failure)?;
            Ok(routed)
        })
        .await
        .unwrap_or_else(|_| {
            Err(QueueError::Failure(wasmtime::Error::msg(
                "MMIO request timed out",
            )))
        });
        (reply, channel, result)
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
        reply.send(result);
    }
}

async fn run_bridge(
    mut receiver: tokio::sync::mpsc::Receiver<Pending>,
    context: BridgeContext,
    mut channels: Vec<Option<DeviceChannel>>,
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
            let channel = slot.and_then(|slot| {
                active_slots.insert(slot);
                channels.get_mut(slot as usize)?.take()
            });
            let is_control = request.command.is_control();
            let operation = dispatch_pending(&context, request, slot, channel);
            if is_control {
                control_operations.push(operation);
            } else {
                data_operations.push(operation);
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
                pending.push_back((request, slot));
            }
            Some(BridgeEvent::Completion((reply, channel, result))) => {
                if let Some((slot, channel)) = channel {
                    active_slots.remove(&slot);
                    channels[slot as usize] = Some(channel);
                }
                let failure = result.as_ref().err().and_then(|error| match error {
                    QueueError::Router(_) => None,
                    QueueError::Failure(error) => Some(format!("MMIO router failed: {error:#}")),
                });
                reply.send(result);
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
    use std::assert_matches;

    fn access() -> Command {
        Command::Access(0, 4, 0, false)
    }

    fn native_device(
        device_count: u32,
    ) -> (
        BridgeContext,
        DeviceChannel,
        crate::component::relay::Stream<super::super::Request>,
        crate::component::relay::Sink<Reply>,
    ) {
        use super::super::{
            AtomicBool, AtomicU64, DeviceRegistration, DeviceRequestCounts, OnceLock,
        };
        use crate::component::relay::{MMIO_CAPACITY, channel};

        let devices = Arc::new(OnceLock::new());
        assert!(
            devices
                .set(
                    (0..device_count)
                        .map(|slot| Arc::new(DeviceRegistration {
                            kind: DeviceKind::Block,
                            slot,
                            base: AtomicU64::new(0x1000 * (u64::from(slot) + 1)),
                            size: AtomicU64::new(0x200),
                            closing: AtomicBool::new(false),
                            closed: AtomicBool::new(false),
                            counts: DeviceRequestCounts::default(),
                        }))
                        .collect::<Vec<_>>()
                        .into_boxed_slice()
                )
                .is_ok()
        );
        let (requests, request_stream) = channel(MMIO_CAPACITY);
        let (reply_sink, replies) = channel(MMIO_CAPACITY);
        (
            BridgeContext {
                devices,
                admission: Arc::new(Mutex::new(None)),
            },
            DeviceChannel {
                requests,
                replies,
                sequence: 7,
            },
            request_stream,
            reply_sink,
        )
    }

    #[tokio::test]
    async fn native_dispatch_rejects_stale_and_future_reply_sequences() {
        for sequence in [6, 8] {
            let (context, channel, mut requests, mut replies) = native_device(1);
            let (queue, mut receiver) = Queue::new();
            let response = enqueue(
                &queue,
                &context.admission,
                Command::Access(0x1018, 4, 0, false),
            )
            .unwrap();
            replies
                .send(Reply {
                    sequence,
                    value: 0,
                    error: None,
                })
                .await
                .unwrap();
            let (reply, channel, result) = dispatch_pending(
                &context,
                receiver.try_recv().unwrap(),
                Some(0),
                Some(channel),
            )
            .await;
            assert_eq!(requests.next().await.unwrap().sequence, 7);
            assert_eq!(channel.unwrap().1.sequence, 8);
            assert_matches!(
                &result,
                Err(QueueError::Failure(error)) if error.to_string().contains("Device")
            );
            assert_eq!(
                context.devices.get().unwrap()[0]
                    .counts
                    .completed
                    .load(Ordering::Relaxed),
                0
            );
            reply.send(result);
            assert_matches!(response.recv().unwrap(), Err(QueueError::Failure(_)));
        }
    }

    #[tokio::test]
    async fn native_dispatch_preserves_typed_device_errors_and_failed_counts() {
        let (context, channel, mut requests, mut replies) = native_device(1);
        let (queue, mut receiver) = Queue::new();
        let response = enqueue(
            &queue,
            &context.admission,
            Command::Control(0, Operation::Reset),
        )
        .unwrap();
        replies
            .send(Reply {
                sequence: 7,
                value: 0,
                error: Some(super::super::DeviceError::BadLen),
            })
            .await
            .unwrap();
        let (reply, _, result) = dispatch_pending(
            &context,
            receiver.try_recv().unwrap(),
            Some(0),
            Some(channel),
        )
        .await;
        assert_eq!(requests.next().await.unwrap().operation, Operation::Reset);
        assert_matches!(
            &result,
            Err(QueueError::Failure(error)) if error.to_string() == format!("MMIO block device error {:?}", super::super::DeviceError::BadLen)
        );
        let counts = &context.devices.get().unwrap()[0].counts;
        assert_eq!(counts.completed.load(Ordering::Relaxed), 0);
        assert_eq!(counts.failed.load(Ordering::Relaxed), 1);
        reply.send(result);
        assert_matches!(response.recv().unwrap(), Err(QueueError::Failure(_)));
    }

    #[tokio::test]
    async fn invalid_guest_accesses_leave_native_routing_and_device_sequence_available() {
        use super::super::{Error, submit_async};
        use futures_util::FutureExt;

        let (context, channel, mut requests, mut replies) = native_device(1);
        let devices = Arc::clone(&context.devices);
        let admission = Arc::clone(&context.admission);
        let failure = Mutex::new(None);
        let (queue, receiver) = Queue::new();
        let bridge = tokio::spawn(run_bridge(receiver, context, vec![Some(channel)]));
        for (command, expected) in [
            (Command::Access(0x1000, 3, 0, false), Error::BadWidth),
            (Command::Access(u64::MAX, 8, 0, false), Error::Overflow),
            (Command::Access(0x1200, 4, 0, false), Error::Unmapped),
        ] {
            assert_matches!(submit_async(&queue, &admission, &failure, command, None).await,
                Err(QueueError::Router(error)) if error == expected
            );
            assert!(requests.next().now_or_never().is_none());
            assert!(admission.lock().unwrap().is_none());
        }
        let routed = {
            let access = submit_async(
                &queue,
                &admission,
                &failure,
                Command::Access(0x1018, 4, 0xa5, true),
                None,
            );
            tokio::pin!(access);
            let request = tokio::select! {
                result = &mut access => panic!("access completed before device reply: {result:?}"),
                request = requests.next() => request.unwrap(),
            };
            assert_eq!(
                (
                    request.sequence,
                    request.operation,
                    request.offset,
                    request.width,
                    request.value
                ),
                (7, Operation::Write, 0x18, 4, 0xa5)
            );
            replies
                .send(Reply {
                    sequence: 7,
                    value: 0x42,
                    error: None,
                })
                .await
                .unwrap();
            access.await.unwrap()
        };
        assert_eq!(routed.slot, 0);
        assert_eq!(routed.reply.value, 0x42);
        assert_eq!(
            devices.get().unwrap()[0]
                .counts
                .completed
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            devices.get().unwrap()[0]
                .counts
                .failed
                .load(Ordering::Relaxed),
            0
        );
        drop(queue);
        assert_eq!(
            bridge.await.unwrap().unwrap_err().to_string(),
            "MMIO bridge closed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    /// A vCPU thread reaches the device without the VMM component: routed accesses return the
    /// device's value, unmapped ones read as zero without reaching any device, and a recorded
    /// bridge failure is an error.
    async fn vcpu_accesses_reach_the_device_directly_and_unmapped_ones_read_zero() {
        use super::super::Client;
        use futures_util::FutureExt;

        let (context, channel, mut requests, mut replies) = native_device(1);
        let admission = Arc::clone(&context.admission);
        let devices = Arc::clone(&context.devices);
        let (queue, receiver) = Queue::new();
        let bridge = tokio::spawn(run_bridge(receiver, context, vec![Some(channel)]));
        let client = Client {
            sender: queue,
            admission,
            failure: Arc::new(Mutex::new(None)),
            devices,
        };
        let unmapped = client.clone();
        assert_eq!(
            tokio::task::spawn_blocking(move || unmapped.access_from_vcpu(0x1200, 4, 0, false))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(requests.next().now_or_never().is_none());
        let routed = client.clone();
        let access =
            tokio::task::spawn_blocking(move || routed.access_from_vcpu(0x1018, 4, 0xa5, true));
        let request = requests.next().await.unwrap();
        assert_eq!(
            (request.operation, request.offset, request.value),
            (Operation::Write, 0x18, 0xa5)
        );
        replies
            .send(Reply {
                sequence: request.sequence,
                value: 0x42,
                error: None,
            })
            .await
            .unwrap();
        assert_eq!(access.await.unwrap().unwrap(), 0x42);
        *client.failure.lock().unwrap() = Some("device failed".to_owned());
        assert_eq!(
            client
                .access_from_vcpu(0x1018, 4, 0, false)
                .unwrap_err()
                .to_string(),
            "device failed"
        );
        drop(client);
        assert!(bridge.await.unwrap().is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    /// Only a 4-byte write to a device's `QueueNotify` register is posted; the vCPU continues
    /// at once and collects the device's outcome when it settles the write.
    async fn only_queue_kicks_are_posted_and_settle_with_the_device_outcome() {
        use super::super::Client;

        let (context, channel, mut requests, mut replies) = native_device(1);
        let admission = Arc::clone(&context.admission);
        let devices = Arc::clone(&context.devices);
        let (queue, receiver) = Queue::new();
        let bridge = tokio::spawn(run_bridge(receiver, context, vec![Some(channel)]));
        let client = Client {
            sender: queue,
            admission,
            failure: Arc::new(Mutex::new(None)),
            devices,
        };
        for (address, width) in [(0x1018, 4), (0x1050, 2), (0x3050, 4)] {
            assert!(
                client
                    .post_queue_notify(address, width, 1)
                    .unwrap()
                    .is_none()
            );
        }
        let posted = client.post_queue_notify(0x1050, 4, 1).unwrap().unwrap();
        let request = requests.next().await.unwrap();
        assert_eq!(
            (request.operation, request.offset, request.value),
            (Operation::Write, 0x50, 1)
        );
        replies
            .send(Reply {
                sequence: request.sequence,
                value: 0,
                error: None,
            })
            .await
            .unwrap();
        let settling = client.clone();
        tokio::task::spawn_blocking(move || settling.settle(&posted))
            .await
            .unwrap()
            .unwrap();
        drop(client);
        assert!(bridge.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn closed_device_accesses_are_unmapped_even_when_the_slot_was_already_selected() {
        use futures_util::FutureExt;

        let (context, channel, mut requests, _replies) = native_device(2);
        let command = Command::Access(0x1018, 4, 0, false);
        let queued_slot = command_slot(&context, &command);
        assert_eq!(queued_slot, Some(0));
        context.devices.get().unwrap()[0]
            .closed
            .store(true, Ordering::Release);
        assert!(!all_devices_closed(&context));
        assert_eq!(command_slot(&context, &command), None);
        assert_eq!(
            command_slot(&context, &Command::Access(0x2018, 4, 0, false)),
            Some(1)
        );
        let (queue, mut receiver) = Queue::new();
        let mut channel = Some(channel);
        for slot in [None, queued_slot] {
            let response = enqueue(
                &queue,
                &context.admission,
                Command::Access(0x1018, 4, 0, false),
            )
            .unwrap();
            let selected_channel = if slot.is_some() { channel.take() } else { None };
            let (reply, returned_channel, result) = dispatch_pending(
                &context,
                receiver.try_recv().unwrap(),
                slot,
                selected_channel,
            )
            .await;
            assert_matches!(
                &result,
                Err(QueueError::Router(super::super::Error::Unmapped))
            );
            assert!(requests.next().now_or_never().is_none());
            if let Some((_, returned_channel)) = returned_channel {
                channel = Some(returned_channel);
            }
            reply.send(result);
            assert_matches!(
                response.recv().unwrap(),
                Err(QueueError::Router(super::super::Error::Unmapped))
            );
        }
    }

    #[test]
    fn only_guest_mmio_errors_cross_the_native_queue_as_wit_errors() {
        for error in [
            super::super::Error::Unmapped,
            super::super::Error::BadWidth,
            super::super::Error::Overflow,
        ] {
            assert_matches!(router_failure(error), QueueError::Router(_));
        }
        assert_matches!(
            router_failure(super::super::Error::Device),
            QueueError::Failure(_)
        );
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
        assert_matches!(
            request.await,
            Err(QueueError::Router(super::super::Error::Unmapped))
        );
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
    async fn native_mmio_service_initializes() {
        let engine = crate::engine::device_engine().expect("engine");
        let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
        runtime
            .initialize_mmio()
            .expect("native MMIO service initializes");

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
        let reply = |slot| RoutedReply {
            slot,
            reply: Reply {
                sequence: 0,
                value: 0,
                error: None,
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
