//! Routes MMIO requests between the VMM and device components.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({ world: "mmio", path: "wit", generate_all });
}

use std::sync::{Arc, LazyLock, Mutex};

use bindings::{exports, wit_stream};
use futures_util::lock::Mutex as AsyncMutex;
use wit_bindgen::rt::async_support::{StreamReader, StreamResult, StreamWriter};

use exports::terra::mmio::router::{
    ControlReply, Error, Guest, Operation, Reply, Request, RoutedReply,
};

mod scheduler;

const MAX_DEVICES: usize = terra_limits::MAX_DEVICES;
const MAX_STALE_REPLIES: usize = 16;

enum DeviceState {
    AwaitingReplies {
        writer: StreamWriter<Request>,
    },
    Ready {
        next_sequence: u64,
        writer: StreamWriter<Request>,
        replies: StreamReader<Reply>,
    },
    Closed,
}

struct Device {
    base: u64,
    size: u64,
    state: Arc<AsyncMutex<DeviceState>>,
}

#[derive(Default)]
struct Router {
    devices: Vec<Option<Device>>,
    started: bool,
}

static ROUTER: LazyLock<Mutex<Router>> = LazyLock::new(|| Mutex::new(Router::default()));

fn router() -> std::sync::MutexGuard<'static, Router> {
    ROUTER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn valid_width(width: u8) -> bool {
    matches!(width, 1 | 2 | 4 | 8)
}

fn range_end(base: u64, size: u64) -> Result<u64, Error> {
    base.checked_add(size).ok_or(Error::Overflow)
}

fn device_range_overlaps(
    router: &Router,
    ignored_slot: Option<usize>,
    base: u64,
    end: u64,
) -> bool {
    router
        .devices
        .iter()
        .enumerate()
        .filter(|(slot, _)| Some(*slot) != ignored_slot)
        .filter_map(|(_, device)| device.as_ref())
        .any(|device| {
            device
                .base
                .checked_add(device.size)
                .is_some_and(|device_end| base < device_end && device.base < end)
        })
}

fn device_for_address(router: &Router, address: u64, width: u8) -> Result<(usize, u64), Error> {
    if !valid_width(width) {
        return Err(Error::BadWidth);
    }
    let end = address
        .checked_add(u64::from(width))
        .ok_or(Error::Overflow)?;
    router
        .devices
        .iter()
        .enumerate()
        .find_map(|(slot, device)| {
            let device = device.as_ref()?;
            let device_end = device.base.checked_add(device.size)?;
            (address >= device.base && end <= device_end).then(|| (slot, address - device.base))
        })
        .ok_or(Error::Unmapped)
}

fn device_state(slot: usize) -> Result<Arc<AsyncMutex<DeviceState>>, Error> {
    router()
        .devices
        .get(slot)
        .and_then(Option::as_ref)
        .map(|device| Arc::clone(&device.state))
        .ok_or(Error::InvalidSlot)
}

fn mark_closed(state: &mut DeviceState) {
    *state = DeviceState::Closed;
}

enum ReplySequence {
    Stale,
    Current,
    Future,
}

fn reply_sequence(reply: &Reply, sequence: u64) -> ReplySequence {
    match reply.sequence.cmp(&sequence) {
        std::cmp::Ordering::Less => ReplySequence::Stale,
        std::cmp::Ordering::Equal => ReplySequence::Current,
        std::cmp::Ordering::Greater => ReplySequence::Future,
    }
}

async fn dispatch(
    slot: usize,
    class: scheduler::Class,
    operation: Operation,
    offset: u64,
    width: u8,
    value: u64,
) -> Result<Reply, Error> {
    let state = device_state(slot)?;
    let mut state = state.lock().await;
    let _permit = scheduler::acquire(class).await?;
    dispatch_state(&mut state, operation, offset, width, value).await
}

async fn dispatch_state(
    state: &mut DeviceState,
    operation: Operation,
    offset: u64,
    width: u8,
    value: u64,
) -> Result<Reply, Error> {
    let (sequence, writer, replies) = match state {
        DeviceState::AwaitingReplies { .. } => return Err(Error::Busy),
        DeviceState::Ready {
            next_sequence,
            writer,
            replies,
        } => {
            let sequence = *next_sequence;
            *next_sequence = next_sequence.wrapping_add(1);
            (sequence, writer, replies)
        }
        DeviceState::Closed => return Err(Error::Closed),
    };
    let request = Request {
        sequence,
        operation,
        offset,
        width,
        value,
    };
    if !writer.write_all(vec![request]).await.is_empty() {
        mark_closed(state);
        return Err(Error::Closed);
    }
    for stale_replies in 0..=MAX_STALE_REPLIES {
        let (result, replies) = replies.read(Vec::with_capacity(1)).await;
        let reply = match result {
            StreamResult::Complete(1) => {
                if let Some(reply) = replies.into_iter().next() {
                    reply
                } else {
                    mark_closed(state);
                    return Err(Error::Device);
                }
            }
            StreamResult::Complete(_) | StreamResult::Dropped | StreamResult::Cancelled => {
                mark_closed(state);
                return Err(Error::Closed);
            }
        };
        match reply_sequence(&reply, sequence) {
            ReplySequence::Current => return Ok(reply),
            ReplySequence::Stale if stale_replies < MAX_STALE_REPLIES => {}
            ReplySequence::Stale | ReplySequence::Future => {
                mark_closed(state);
                return Err(Error::Device);
            }
        }
    }
    unreachable!()
}

async fn route_access(
    address: u64,
    width: u8,
    value: u64,
    write: bool,
) -> Result<RoutedReply, Error> {
    let (slot, offset) = {
        let mut router = router();
        router.started = true;
        device_for_address(&router, address, width)?
    };
    let reply = dispatch(
        slot,
        scheduler::Class::Data,
        if write {
            Operation::Write
        } else {
            Operation::Read
        },
        offset,
        width,
        value,
    )
    .await?;
    Ok(RoutedReply {
        slot: u32::try_from(slot).map_err(|_| Error::InvalidSlot)?,
        reply,
    })
}

fn open_device(slot: u32, base: u64, size: u64) -> Result<StreamReader<Request>, Error> {
    let slot = usize::try_from(slot).map_err(|_| Error::InvalidSlot)?;
    if slot >= MAX_DEVICES || size == 0 {
        return Err(Error::InvalidSlot);
    }
    let end = range_end(base, size)?;
    let mut router = router();
    if router.devices.len() <= slot {
        router.devices.resize_with(slot + 1, || None);
    }
    if router.devices[slot].is_some() || device_range_overlaps(&router, None, base, end) {
        return Err(Error::Overlap);
    }
    let (writer, reader) = wit_stream::new();
    router.devices[slot] = Some(Device {
        base,
        size,
        state: Arc::new(AsyncMutex::new(DeviceState::AwaitingReplies { writer })),
    });
    Ok(reader)
}

async fn attach_replies(slot: u32, replies: StreamReader<Reply>) -> Result<(), Error> {
    let slot = usize::try_from(slot).map_err(|_| Error::InvalidSlot)?;
    let state = device_state(slot)?;
    let mut state = state.lock().await;
    match std::mem::replace(&mut *state, DeviceState::Closed) {
        DeviceState::AwaitingReplies { writer } => {
            *state = DeviceState::Ready {
                next_sequence: 0,
                writer,
                replies,
            };
            Ok(())
        }
        ready @ DeviceState::Ready { .. } => {
            *state = ready;
            Err(Error::Busy)
        }
        DeviceState::Closed => Err(Error::Closed),
    }
}

struct Dispatcher;

#[allow(unsafe_code)]
mod component_exports {
    use super::{Dispatcher, bindings};
    bindings::export!(Dispatcher with_types_in bindings);
}

impl Guest for Dispatcher {
    fn open_device(slot: u32, base: u64, size: u64) -> Result<StreamReader<Request>, Error> {
        open_device(slot, base, size)
    }
    async fn attach_replies(slot: u32, replies: StreamReader<Reply>) -> Result<(), Error> {
        attach_replies(slot, replies).await
    }
    fn remap_device(slot: u32, base: u64, size: u64) -> Result<(), Error> {
        let slot = usize::try_from(slot).map_err(|_| Error::InvalidSlot)?;
        if size == 0 {
            return Err(Error::InvalidSlot);
        }
        let end = range_end(base, size)?;
        let mut router = router();
        if router.devices.get(slot).and_then(Option::as_ref).is_none() {
            return Err(Error::InvalidSlot);
        }
        if router.started {
            return Err(Error::Busy);
        }
        if device_range_overlaps(&router, Some(slot), base, end) {
            return Err(Error::Overlap);
        }
        let device = router.devices[slot].as_mut().ok_or(Error::InvalidSlot)?;
        device.base = base;
        device.size = size;
        Ok(())
    }
    async fn access(
        address: u64,
        width: u8,
        value: u64,
        write: bool,
    ) -> Result<RoutedReply, Error> {
        route_access(address, width, value, write).await
    }
    async fn control(slot: u32, operation: Operation) -> Result<ControlReply, Error> {
        let slot = usize::try_from(slot).map_err(|_| Error::InvalidSlot)?;
        router().started = true;
        if !matches!(
            operation,
            Operation::Reset | Operation::Close | Operation::InterruptLevel
        ) {
            return Err(Error::Device);
        }
        let closes_device = operation == Operation::Close;
        let result = dispatch(slot, scheduler::Class::Control, operation, 0, 0, 0).await;
        if closes_device && let Some(device) = router().devices.get_mut(slot) {
            *device = None;
        }
        result.map(|reply| ControlReply {
            reply,
            all_closed: closes_device && router().devices.iter().all(Option::is_none),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn device(base: u64, size: u64) -> Device {
        Device {
            base,
            size,
            state: Arc::new(AsyncMutex::new(DeviceState::Closed)),
        }
    }
    #[test]
    fn routing_rejects_invalid_width_and_outside_ranges() {
        let router = Router {
            devices: vec![Some(device(0x1000, 0x200))],
            started: false,
        };
        assert_eq!(device_for_address(&router, 0x1000, 3), Err(Error::BadWidth));
        assert_eq!(device_for_address(&router, 0x1200, 1), Err(Error::Unmapped));
        assert_eq!(device_for_address(&router, 0x11ff, 2), Err(Error::Unmapped));
        assert_eq!(device_for_address(&router, 0x1008, 8), Ok((0, 8)));
    }
    #[test]
    fn routing_skips_devices_above_the_address() {
        let router = Router {
            devices: vec![Some(device(0x2000, 0x200)), Some(device(0x1000, 0x200))],
            started: false,
        };
        assert_eq!(device_for_address(&router, 0x800, 4), Err(Error::Unmapped));
        assert_eq!(device_for_address(&router, 0x1008, 4), Ok((1, 8)));
    }

    #[test]
    fn stale_replies_are_distinct_from_future_replies() {
        let reply = Reply {
            sequence: 7,
            value: 7,
            error: 0,
            interrupt: true,
        };
        assert!(matches!(reply_sequence(&reply, 7), ReplySequence::Current));
        assert!(matches!(reply_sequence(&reply, 8), ReplySequence::Stale));
        assert!(matches!(reply_sequence(&reply, 3), ReplySequence::Future));
    }

    #[test]
    fn remapping_rejects_overlap_and_overflow() {
        let router = Router {
            devices: vec![Some(device(0x1000, 0x200)), Some(device(0x2000, 0x200))],
            started: false,
        };
        assert!(device_range_overlaps(&router, Some(0), 0x1f00, 0x2100));
        assert!(!device_range_overlaps(&router, Some(0), 0x1000, 0x1200));
        assert_eq!(range_end(u64::MAX, 1), Err(Error::Overflow));
    }
}
