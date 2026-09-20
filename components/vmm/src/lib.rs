//! Routes MMIO requests between a trusted hypervisor adapter and device components.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({ world: "vmm", path: "wit", generate_all });
}

use bindings::{exports, terra, wit_stream};

mod ioapic;
mod lifecycle;
mod machine;
mod scheduler;

use std::sync::{Arc, LazyLock, Mutex};

use futures_util::lock::Mutex as AsyncMutex;
use wit_bindgen::rt::async_support::{StreamReader, StreamResult, StreamWriter};

use exports::terra::mmio::router::{
    ControlReply, Error, Guest, Operation, Reply, Request, RoutedReply,
};
use terra::mmio::platform;

const MAX_DEVICES: usize = terra_limits::MAX_DEVICES;
const MAX_VCPUS: usize = terra_limits::MAX_VCPUS as usize;
const PSCI_CPU_OFF: u64 = 0x8400_0002;
const PSCI_CPU_ON: u64 = 0xc400_0003;
const PSCI_32_CPU_ON: u64 = 0x8400_0003;
const PSCI_AFFINITY_INFO: u64 = 0xc400_0004;
const PSCI_32_AFFINITY_INFO: u64 = 0x8400_0004;
const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
const PSCI_VERSION: u64 = 0x8400_0000;
const PSCI_FEATURES: u64 = 0x8400_000a;
const MAX_STALE_REPLIES: usize = 16;

const MSRS: [(u32, u64); 12] = [
    (0x10, 0),
    (0x1A0, 0),
    (0x277, 0x0007_0406_0007_0406),
    (0xC000_0080, 0x500),
    (0xC000_0081, 0),
    (0xC000_0082, 0),
    (0xC000_0083, 0),
    (0xC000_0084, 0),
    (0xC000_0100, 0),
    (0xC000_0101, 0),
    (0xC000_0102, 0),
    (0xC000_0103, 0),
];

struct DeviceState {
    next_sequence: u64,
    writer: Option<StreamWriter<Request>>,
    replies: Option<StreamReader<Reply>>,
    closed: bool,
}

struct Device {
    base: u64,
    size: u64,
    state: Arc<AsyncMutex<DeviceState>>,
}

#[derive(Clone)]
struct MsrBank {
    values: [u64; 12],
}

impl MsrBank {
    fn new() -> Self {
        Self {
            values: MSRS.map(|(_, default)| default),
        }
    }

    fn slot(index: u32) -> Result<usize, Error> {
        MSRS.iter()
            .position(|(candidate, _)| *candidate == index)
            .ok_or(Error::UnsupportedMsr)
    }

    fn read(&self, index: u32) -> Result<u64, Error> {
        Ok(self.values[Self::slot(index)?])
    }

    fn write(&mut self, index: u32, value: u64) -> Result<(), Error> {
        self.values[Self::slot(index)?] = value;
        Ok(())
    }
}

#[derive(Default)]
struct Router {
    devices: Vec<Option<Device>>,
    msrs: Option<Vec<MsrBank>>,
    powered: Option<Vec<bool>>,
    started: bool,
}

static ROUTER: LazyLock<Mutex<Router>> = LazyLock::new(|| Mutex::new(Router::default()));
static IOAPIC: LazyLock<Mutex<ioapic::IoApic>> =
    LazyLock::new(|| Mutex::new(ioapic::IoApic::new()));

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

fn vcpu_bank(router: &mut Router, vcpu: u8) -> Result<&mut MsrBank, Error> {
    router
        .msrs
        .as_mut()
        .and_then(|banks| banks.get_mut(usize::from(vcpu)))
        .ok_or(Error::InvalidVcpu)
}

fn start_vcpu(router: &mut Router, vcpu: u8) -> Result<(), Error> {
    vcpu_bank(router, vcpu)?;
    router.started = true;
    Ok(())
}

fn powered(router: &mut Router, vcpu: u8) -> Result<&mut bool, Error> {
    router
        .powered
        .as_mut()
        .and_then(|cpus| cpus.get_mut(usize::from(vcpu)))
        .ok_or(Error::InvalidVcpu)
}

fn psci_features(function: u64) -> i64 {
    match function {
        PSCI_VERSION
        | PSCI_FEATURES
        | PSCI_CPU_OFF
        | PSCI_CPU_ON
        | PSCI_32_CPU_ON
        | PSCI_AFFINITY_INFO
        | PSCI_32_AFFINITY_INFO
        | PSCI_SYSTEM_OFF
        | PSCI_SYSTEM_RESET => 0,
        _ => -1,
    }
}

fn psci_hvc(id: u8, hvc: Hvc) -> Result<platform::Completion, Error> {
    let mut router = router();
    psci_hvc_for(&mut router, id, &hvc)
}

fn psci_hvc_for(router: &mut Router, id: u8, hvc: &Hvc) -> Result<platform::Completion, Error> {
    let status = match hvc.function {
        PSCI_VERSION => return Ok(platform::Completion::HvcReturn(0x0001_0000)),
        PSCI_FEATURES => {
            return Ok(platform::Completion::HvcReturn(psci_features(
                hvc.argument0,
            )));
        }
        PSCI_AFFINITY_INFO | PSCI_32_AFFINITY_INFO => {
            if hvc.argument1 != 0 {
                -2
            } else {
                let Ok(target) = u8::try_from(hvc.argument0) else {
                    return Ok(platform::Completion::HvcReturn(-3));
                };
                let Some(powered) = router
                    .powered
                    .as_mut()
                    .and_then(|cpus| cpus.get_mut(usize::from(target)))
                else {
                    return Ok(platform::Completion::HvcReturn(-3));
                };
                i64::from(!*powered)
            }
        }
        PSCI_CPU_ON | PSCI_32_CPU_ON => {
            let Ok(target) = u8::try_from(hvc.argument0) else {
                return Ok(platform::Completion::HvcReturn(-3));
            };
            let Some(powered) = router
                .powered
                .as_mut()
                .and_then(|cpus| cpus.get_mut(usize::from(target)))
            else {
                return Ok(platform::Completion::HvcReturn(-3));
            };
            if target == 0 || *powered {
                -4
            } else {
                return Ok(platform::Completion::CpuStart(platform::CpuStart {
                    target,
                    entry: hvc.argument1,
                    context: hvc.argument2,
                }));
            }
        }
        PSCI_CPU_OFF => {
            *powered(router, id)? = false;
            return Ok(platform::Completion::CpuOff);
        }
        PSCI_SYSTEM_OFF | PSCI_SYSTEM_RESET => return Ok(platform::Completion::SystemStop),
        _ => -1,
    };
    Ok(platform::Completion::HvcReturn(status))
}

fn psci_start_result(result: platform::HvcResult) -> Result<platform::Completion, Error> {
    let mut router = router();
    psci_start_result_for(&mut router, result)
}

fn psci_start_result_for(
    router: &mut Router,
    result: platform::HvcResult,
) -> Result<platform::Completion, Error> {
    if result.status == 0 {
        *powered(router, result.target)? = true;
    }
    Ok(platform::Completion::HvcReturn(result.status))
}

fn mark_closed(state: &mut DeviceState) {
    state.closed = true;
    state.writer = None;
    state.replies = None;
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
    operation: Operation,
    offset: u64,
    width: u8,
    value: u64,
) -> Result<Reply, Error> {
    let state = device_state(slot)?;
    let mut state = state.lock().await;
    if state.closed {
        return Err(Error::Closed);
    }
    let sequence = state.next_sequence;
    state.next_sequence = state.next_sequence.wrapping_add(1);
    let request = Request {
        sequence,
        operation,
        offset,
        width,
        value,
    };
    let unwritten = match state.writer.as_mut() {
        Some(writer) => writer.write_all(vec![request]).await,
        None => return Err(Error::Closed),
    };
    if !unwritten.is_empty() {
        mark_closed(&mut state);
        return Err(Error::Closed);
    }
    for stale_replies in 0..=MAX_STALE_REPLIES {
        let (result, replies) = match state.replies.as_mut() {
            Some(replies) => replies.read(Vec::with_capacity(1)).await,
            None => return Err(Error::Busy),
        };
        let reply = match result {
            StreamResult::Complete(1) => {
                let Some(reply) = replies.into_iter().next() else {
                    mark_closed(&mut state);
                    return Err(Error::Device);
                };
                reply
            }
            StreamResult::Complete(_) | StreamResult::Dropped | StreamResult::Cancelled => {
                mark_closed(&mut state);
                return Err(Error::Closed);
            }
        };
        match reply_sequence(&reply, sequence) {
            ReplySequence::Current => return Ok(reply),
            ReplySequence::Stale if stale_replies < MAX_STALE_REPLIES => {}
            ReplySequence::Stale | ReplySequence::Future => {
                mark_closed(&mut state);
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
    let _permit = scheduler::acquire(scheduler::Class::Data).await?;
    let (slot, offset) = {
        let mut router = router();
        router.started = true;
        device_for_address(&router, address, width)?
    };
    let reply = dispatch(
        slot,
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

fn complete_routed(routed: &RoutedReply) -> Result<(), Error> {
    platform::completed(routed.slot, routed.reply.error != 0).map_err(|_| Error::Device)?;
    Ok(())
}

async fn vcpu_access(address: u64, width: u8, value: u64, write: bool) -> Result<u64, Error> {
    let routed = match route_access(address, width, value, write).await {
        Ok(routed) => routed,
        Err(Error::Unmapped | Error::BadWidth | Error::Overflow) => return Ok(0),
        Err(error) => return Err(error),
    };
    complete_routed(&routed)?;
    Ok(if routed.reply.error == 0 {
        routed.reply.value
    } else {
        0
    })
}

fn ioapic_error(error: ioapic::IoApicError) -> Error {
    match error {
        ioapic::IoApicError::Unconfigured => Error::Busy,
        ioapic::IoApicError::InvalidSlot => Error::InvalidSlot,
        ioapic::IoApicError::BadOffset => Error::Unmapped,
        ioapic::IoApicError::BadWidth => Error::BadWidth,
    }
}

fn interrupt(interrupt: ioapic::X86Interrupt) -> exports::terra::mmio::interrupts::X86Interrupt {
    exports::terra::mmio::interrupts::X86Interrupt {
        vector: interrupt.vector,
        destination: interrupt.destination,
        level_triggered: interrupt.level_triggered,
    }
}

#[derive(Clone, Copy)]
struct Hvc {
    function: u64,
    argument0: u64,
    argument1: u64,
    argument2: u64,
}

async fn read_arm_register(cpu: &platform::Vcpu, register: u8) -> Result<u64, Error> {
    if register == 31 {
        return Ok(0);
    }
    match cpu
        .resume(platform::Completion::ArmRegister(register))
        .await
    {
        Ok(platform::Exit::ArmRegisterValue(value)) => Ok(value),
        Ok(platform::Exit::Stopped) | Err(platform::Error::Cancelled) => Err(Error::Closed),
        Ok(
            platform::Exit::Halt
            | platform::Exit::Shutdown
            | platform::Exit::Interrupted
            | platform::Exit::MmioRead(_)
            | platform::Exit::MmioWrite(_)
            | platform::Exit::PioRead(_)
            | platform::Exit::PioWrite(_)
            | platform::Exit::Rdmsr(_)
            | platform::Exit::Wrmsr(_)
            | platform::Exit::ArmException(_)
            | platform::Exit::HvcResult(_),
        )
        | Err(platform::Error::Unavailable | platform::Error::BadExit) => Err(Error::BadArmExit),
    }
}

async fn handle_arm_exception(
    cpu: &platform::Vcpu,
    id: u8,
    request: platform::ArmException,
) -> Result<platform::Completion, Error> {
    const HVC64: u64 = 0x16;
    if request.syndrome >> 26 == HVC64 {
        let hvc = Hvc {
            function: read_arm_register(cpu, 0).await?,
            argument0: read_arm_register(cpu, 1).await?,
            argument1: read_arm_register(cpu, 2).await?,
            argument2: read_arm_register(cpu, 3).await?,
        };
        return psci_hvc(id, hvc);
    }
    let fields = arm_mmio_fields(request.syndrome)?;
    let value = if fields.write {
        read_arm_register(cpu, fields.register).await?
            & (u64::MAX >> (64 - u32::from(fields.width) * 8))
    } else {
        0
    };
    let value = vcpu_access(request.address, fields.width, value, fields.write).await?;
    let read = if fields.write || fields.register == 31 {
        platform::ArmRead {
            register: None,
            value: 0,
        }
    } else {
        platform::ArmRead {
            register: Some(fields.register),
            value: arm_load_value(value, fields.width, fields.sign_extend, fields.sf),
        }
    };
    Ok(platform::Completion::ArmRead(read))
}

async fn run_vcpu(cpu: platform::Vcpu, id: u8) -> Result<(), Error> {
    {
        let mut router = router();
        start_vcpu(&mut router, id)?;
    }
    let mut completion = platform::Completion::Start;
    loop {
        let exit = match cpu.resume(completion).await {
            Ok(exit) => exit,
            Err(platform::Error::Cancelled) => {
                lifecycle::vcpu_finished();
                return Ok(());
            }
            Err(platform::Error::Unavailable | platform::Error::BadExit) => {
                return Err(Error::Device);
            }
        };
        completion = match exit {
            platform::Exit::Halt | platform::Exit::Interrupted | platform::Exit::PioWrite(_) => {
                platform::Completion::Reenter
            }
            platform::Exit::Shutdown | platform::Exit::Stopped => {
                lifecycle::vcpu_finished();
                return Ok(());
            }
            platform::Exit::MmioRead(request) => platform::Completion::MmioRead(
                vcpu_access(request.address, request.width, 0, false).await?,
            ),
            platform::Exit::MmioWrite(request) => {
                vcpu_access(request.address, request.width, request.value, true).await?;
                platform::Completion::Reenter
            }
            platform::Exit::PioRead(_) => platform::Completion::PioZero,
            platform::Exit::Rdmsr(request) => {
                let mut router = router();
                match vcpu_bank(&mut router, id)?.read(request.index) {
                    Ok(value) => platform::Completion::Rdmsr(value),
                    Err(Error::UnsupportedMsr) => platform::Completion::MsrFault,
                    Err(error) => return Err(error),
                }
            }
            platform::Exit::Wrmsr(request) => {
                let mut router = router();
                match vcpu_bank(&mut router, id)?.write(request.index, request.value) {
                    Ok(()) => platform::Completion::Wrmsr,
                    Err(Error::UnsupportedMsr) => platform::Completion::MsrFault,
                    Err(error) => return Err(error),
                }
            }
            platform::Exit::ArmException(request) => {
                match handle_arm_exception(&cpu, id, request).await {
                    Ok(completion) => completion,
                    Err(Error::Closed) => {
                        lifecycle::vcpu_finished();
                        return Ok(());
                    }
                    Err(Error::BadArmExit) => platform::Completion::ArmRead(platform::ArmRead {
                        register: None,
                        value: 0,
                    }),
                    Err(error) => return Err(error),
                }
            }
            platform::Exit::ArmRegisterValue(_) => return Err(Error::BadArmExit),
            platform::Exit::HvcResult(result) => psci_start_result(result)?,
        };
        wit_bindgen::rt::async_support::yield_async().await;
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ArmMmioFields {
    width: u8,
    register: u8,
    write: bool,
    sign_extend: bool,
    sf: bool,
}

fn arm_mmio_fields(syndrome: u64) -> Result<ArmMmioFields, Error> {
    const EC: u64 = 0b11_1111 << 26;
    const DATA_ABORT_LOWER: u64 = 0x24 << 26;
    const DATA_ABORT_SAME: u64 = 0x25 << 26;
    const ISV: u64 = 1 << 24;
    const SAS: u64 = 0b11 << 22;
    const SSE: u64 = 1 << 21;
    const SRT: u64 = 0b1_1111 << 16;
    const SF: u64 = 1 << 15;
    const WNR: u64 = 1 << 6;

    if !matches!(syndrome & EC, DATA_ABORT_LOWER | DATA_ABORT_SAME) || syndrome & ISV == 0 {
        return Err(Error::BadArmExit);
    }
    let width = 1_u8 << u8::try_from((syndrome & SAS) >> 22).map_err(|_| Error::BadArmExit)?;
    let register = u8::try_from((syndrome & SRT) >> 16).map_err(|_| Error::BadArmExit)?;
    let write = syndrome & WNR != 0;
    let sf = syndrome & SF != 0;
    if !sf && width == 8 {
        return Err(Error::BadArmExit);
    }
    Ok(ArmMmioFields {
        width,
        register,
        write,
        sign_extend: syndrome & SSE != 0,
        sf,
    })
}

fn arm_load_value(value: u64, width: u8, sign_extend: bool, sf: bool) -> u64 {
    let bits = u32::from(width) * 8;
    let value = value & (u64::MAX >> (64 - bits));
    let value = if sign_extend {
        let shift = 64 - bits;
        ((value << shift).cast_signed() >> shift).cast_unsigned()
    } else {
        value
    };
    if sf {
        value
    } else {
        value & u64::from(u32::MAX)
    }
}

struct Dispatcher;

#[allow(unsafe_code)]
mod component_exports {
    use super::{Dispatcher, bindings};
    bindings::export!(Dispatcher with_types_in bindings);
}

impl exports::terra::mmio::interrupts::Guest for Dispatcher {
    fn stage_irq_lines() -> Result<(), Error> {
        machine::stage_irq_lines().map_err(|_| Error::Device)
    }

    fn clear_irq_lines() -> Result<Vec<exports::terra::mmio::interrupts::IrqLevel>, Error> {
        machine::clear_irq_lines().map_err(|_| Error::Device)
    }

    fn device_irq_line(
        kind: terra::mmio::machine_types::DeviceKind,
        ordinal: u32,
        asserted: bool,
    ) -> Result<Option<exports::terra::mmio::interrupts::IrqLevel>, Error> {
        machine::device_irq_line(kind, ordinal, asserted).map_err(|_| Error::Device)
    }

    fn stage_ioapic() -> Result<(), Error> {
        machine::stage_ioapic().map_err(|_| Error::Device)
    }

    fn ioapic_access(
        offset: u8,
        width: u8,
        write: bool,
        value: u32,
    ) -> Result<exports::terra::mmio::interrupts::IoapicReply, Error> {
        router().started = true;
        let access = IOAPIC
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .access(offset, width, write, value)
            .map_err(ioapic_error)?;
        Ok(exports::terra::mmio::interrupts::IoapicReply {
            value: access.value,
            interrupts: access.interrupts.into_iter().map(interrupt).collect(),
        })
    }

    fn ioapic_line(
        slot: u8,
        asserted: bool,
    ) -> Result<Vec<exports::terra::mmio::interrupts::X86Interrupt>, Error> {
        IOAPIC
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .set_line(slot, asserted)
            .map(|interrupts| interrupts.into_iter().map(interrupt).collect())
            .map_err(ioapic_error)
    }

    fn ioapic_device_line(
        kind: terra::mmio::machine_types::DeviceKind,
        ordinal: u32,
        asserted: bool,
    ) -> Result<Vec<exports::terra::mmio::interrupts::X86Interrupt>, Error> {
        let slot = machine::device_slot(kind, ordinal).ok_or(Error::InvalidSlot)?;
        <Self as exports::terra::mmio::interrupts::Guest>::ioapic_line(slot, asserted)
    }

    fn ioapic_eoi(
        vector: u8,
    ) -> Result<Vec<exports::terra::mmio::interrupts::X86Interrupt>, Error> {
        Ok(IOAPIC
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .eoi(vector)
            .into_iter()
            .map(interrupt)
            .collect())
    }
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
        state: Arc::new(AsyncMutex::new(DeviceState {
            next_sequence: 0,
            writer: Some(writer),
            replies: None,
            closed: false,
        })),
    });
    Ok(reader)
}

async fn attach_replies(slot: u32, replies: StreamReader<Reply>) -> Result<(), Error> {
    let slot = usize::try_from(slot).map_err(|_| Error::InvalidSlot)?;
    let state = device_state(slot)?;
    let mut state = state.lock().await;
    if state.closed {
        return Err(Error::Closed);
    }
    if state.replies.is_some() {
        return Err(Error::Busy);
    }
    state.replies = Some(replies);
    Ok(())
}

impl Guest for Dispatcher {
    fn configure_vcpus(count: u8) -> Result<(), Error> {
        let count = usize::from(count);
        if count == 0 || count > MAX_VCPUS {
            return Err(Error::InvalidVcpu);
        }
        let mut router = router();
        if router.started || router.msrs.is_some() {
            return Err(Error::Busy);
        }
        router.msrs = Some(vec![MsrBank::new(); count]);
        let mut powered = vec![false; count];
        powered[0] = true;
        router.powered = Some(powered);
        lifecycle::configure_vcpus(u8::try_from(count).map_err(|_| Error::InvalidVcpu)?);
        Ok(())
    }

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
        let _permit = scheduler::acquire(scheduler::Class::Control).await?;
        let slot = usize::try_from(slot).map_err(|_| Error::InvalidSlot)?;
        router().started = true;
        if !matches!(
            operation,
            Operation::Reset | Operation::Close | Operation::InterruptLevel
        ) {
            return Err(Error::Device);
        }
        let closes_device = operation == Operation::Close;
        let result = dispatch(slot, operation, 0, 0, 0).await;
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
            state: Arc::new(AsyncMutex::new(DeviceState {
                next_sequence: 0,
                writer: None,
                replies: None,
                closed: false,
            })),
        }
    }

    #[test]
    fn routing_rejects_invalid_width_and_outside_ranges() {
        let router = Router {
            devices: vec![Some(device(0x1000, 0x200))],
            msrs: None,
            powered: None,
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
            msrs: None,
            powered: None,
            started: false,
        };
        assert_eq!(device_for_address(&router, 0x800, 4), Err(Error::Unmapped));
        assert_eq!(device_for_address(&router, 0x1008, 4), Ok((1, 8)));
    }

    #[test]
    fn remapping_rejects_overlap_and_overflow() {
        let router = Router {
            devices: vec![Some(device(0x1000, 0x200)), Some(device(0x2000, 0x200))],
            msrs: None,
            powered: None,
            started: false,
        };
        assert!(device_range_overlaps(&router, Some(0), 0x1f00, 0x2100));
        assert!(!device_range_overlaps(&router, Some(0), 0x1000, 0x1200));
        assert_eq!(range_end(u64::MAX, 1), Err(Error::Overflow));
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
    fn msr_banks_are_fixed_and_independent() {
        let mut first = MsrBank::new();
        let second = MsrBank::new();
        assert_eq!(first.read(0x277), Ok(0x0007_0406_0007_0406));
        assert_eq!(first.write(0xC000_0103, 7), Ok(()));
        assert_eq!(first.read(0xC000_0103), Ok(7));
        assert_eq!(second.read(0xC000_0103), Ok(0));
        assert_eq!(first.read(0), Err(Error::UnsupportedMsr));
        assert_eq!(first.write(0, 1), Err(Error::UnsupportedMsr));
    }

    #[test]
    fn arm_loads_follow_the_destination_register_width() {
        assert_eq!(arm_load_value(0x80, 1, true, true), u64::MAX - 0x7f);
        assert_eq!(
            arm_load_value(0x80, 1, true, false),
            u64::from(u32::MAX - 0x7f)
        );
        assert_eq!(
            arm_load_value(0x1234_5678_9abc_def0, 4, false, false),
            0x9abc_def0
        );
    }

    #[test]
    fn arm_syndrome_requires_a_valid_data_abort() {
        const EC: u64 = 0x24 << 26;
        const ISV: u64 = 1 << 24;
        const SF: u64 = 1 << 15;
        const WNR: u64 = 1 << 6;
        let read = EC | ISV | SF | (4 << 16);
        assert_eq!(
            arm_mmio_fields(read),
            Ok(ArmMmioFields {
                width: 1,
                register: 4,
                write: false,
                sign_extend: false,
                sf: true,
            })
        );
        assert_eq!(
            arm_mmio_fields(read | WNR),
            Ok(ArmMmioFields {
                width: 1,
                register: 4,
                write: true,
                sign_extend: false,
                sf: true,
            })
        );
        assert_eq!(arm_mmio_fields(EC | SF), Err(Error::BadArmExit));
        assert_eq!(arm_mmio_fields(ISV | SF), Err(Error::BadArmExit));
        assert_eq!(
            arm_mmio_fields(EC | ISV | (3 << 22)),
            Err(Error::BadArmExit)
        );
        assert_eq!(
            arm_mmio_fields(EC | ISV | (3 << 22) | WNR),
            Err(Error::BadArmExit)
        );
    }

    #[test]
    fn psci_updates_cpu_state_only_after_native_start_succeeds() {
        let mut router = Router {
            devices: Vec::new(),
            msrs: Some(vec![MsrBank::new(), MsrBank::new()]),
            powered: Some(vec![true, false]),
            started: true,
        };
        let start = psci_hvc_for(
            &mut router,
            0,
            &Hvc {
                function: PSCI_CPU_ON,
                argument0: 1,
                argument1: 0x8000,
                argument2: 7,
            },
        )
        .expect("PSCI CPU on");
        let platform::Completion::CpuStart(start) = start else {
            panic!("expected CPU start");
        };
        assert_eq!((start.target, start.entry, start.context), (1, 0x8000, 7));
        assert!(!router.powered.as_ref().expect("CPU state")[1]);
        assert!(matches!(
            psci_start_result_for(
                &mut router,
                platform::HvcResult {
                    target: 1,
                    status: -3,
                },
            ),
            Ok(platform::Completion::HvcReturn(-3))
        ));
        assert!(!router.powered.as_ref().expect("CPU state")[1]);
        assert!(matches!(
            psci_start_result_for(
                &mut router,
                platform::HvcResult {
                    target: 1,
                    status: 0,
                },
            ),
            Ok(platform::Completion::HvcReturn(0))
        ));
        assert!(router.powered.as_ref().expect("CPU state")[1]);
    }

    #[test]
    fn psci_rejects_an_invalid_cpu_without_failing_the_router() {
        let mut router = Router {
            devices: Vec::new(),
            msrs: Some(vec![MsrBank::new()]),
            powered: Some(vec![true]),
            started: true,
        };
        let completion = psci_hvc_for(
            &mut router,
            0,
            &Hvc {
                function: PSCI_CPU_ON,
                argument0: 1,
                argument1: 0x8000,
                argument2: 0,
            },
        );
        assert!(matches!(
            completion,
            Ok(platform::Completion::HvcReturn(-3))
        ));
    }
}
