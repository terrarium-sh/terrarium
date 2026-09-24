#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({ world: "device", path: "wit", generate_all });
}
use bindings::{exports, terra, wasi, wit_stream};

mod carrier;
mod lifecycle;
mod mmio;
mod transport;
mod worker;

use futures_util::{future::poll_fn, task::AtomicWaker};
use std::sync::{
    LazyLock, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::task::Poll;

use exports::terra::vsock::api::{Connection, Error, Reply};
use terra_vsock_device::{VsockError, VsockHeader, VsockSwitch};

static SWITCH: LazyLock<Mutex<VsockSwitch>> = LazyLock::new(|| Mutex::new(VsockSwitch::new()));
#[cfg(test)]
static SWITCH_TEST_LOCK: Mutex<()> = Mutex::new(());
pub(crate) static CLOSED: AtomicBool = AtomicBool::new(false);
static WORK_PENDING: AtomicBool = AtomicBool::new(false);
static WORK_WAKER: AtomicWaker = AtomicWaker::new();
static LAST_CLOCK_SAMPLE: LazyLock<Mutex<Option<(u64, i128)>>> = LazyLock::new(|| Mutex::new(None));

fn clock_update_due(previous: (u64, i128), now: (u64, i128)) -> bool {
    let Some(elapsed) = now.0.checked_sub(previous.0) else {
        return true;
    };
    elapsed >= 60_000_000_000 || (now.1 - previous.1).abs_diff(i128::from(elapsed)) >= 5_000_000_000
}

pub(crate) fn sample_clock() -> Option<(i64, u32)> {
    let monotonic = wasi::clocks::monotonic_clock::now();
    let instant = wasi::clocks::system_clock::now();
    let sample = (
        monotonic,
        i128::from(instant.seconds) * 1_000_000_000 + i128::from(instant.nanoseconds),
    );
    let mut last = LAST_CLOCK_SAMPLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if last.is_some_and(|previous| !clock_update_due(previous, sample)) {
        return None;
    }
    *last = Some(sample);
    Some((instant.seconds, instant.nanoseconds))
}

pub(crate) fn switch() -> std::sync::MutexGuard<'static, VsockSwitch> {
    SWITCH
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) fn wake_worker() {
    WORK_PENDING.store(true, Ordering::Release);
    WORK_WAKER.wake();
}

pub(crate) async fn wait_for_work() {
    poll_fn(|context| {
        WORK_WAKER.register(context.waker());
        if CLOSED.load(Ordering::Acquire) || WORK_PENDING.swap(false, Ordering::AcqRel) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

fn error(error: VsockError) -> Error {
    match error {
        VsockError::TableFull => Error::TableFull,
        VsockError::Backpressure => Error::Backpressure,
        VsockError::UnknownConnection => Error::UnknownConnection,
    }
}

struct Vsock;

impl exports::terra::mmio::device::Guest for Vsock {
    async fn serve(
        requests: wit_bindgen::rt::async_support::StreamReader<terra::mmio::types::Request>,
    ) -> wit_bindgen::rt::async_support::StreamReader<terra::mmio::types::Reply> {
        mmio::serve(requests).await
    }
}

impl exports::terra::vsock::api::Guest for Vsock {
    fn configure_device() -> Result<(), terra::mmio::types::DeviceError> {
        transport::configure()
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn events()
    -> wit_bindgen::rt::async_support::StreamReader<exports::terra::vsock::api::Event> {
        worker::events()
    }

    async fn run() -> Result<(), Error> {
        worker::run().await
    }

    fn decode_control(bytes: Vec<u8>) -> Result<exports::terra::vsock::api::ControlResult, Error> {
        lifecycle::decode_control(&bytes)
    }

    fn decode_diagnostics(
        bytes: Vec<u8>,
    ) -> Result<exports::terra::vsock::api::DiagnosticResult, Error> {
        lifecycle::decode_diagnostics(&bytes)
    }
    fn receive(packet: Vec<u8>) -> Result<(), Error> {
        if CLOSED.load(Ordering::Acquire) {
            return Err(Error::Backpressure);
        }
        let (header, data) = VsockHeader::parse(&packet).map_err(|_| Error::Malformed)?;
        switch().rx(&header, data);
        carrier::wake();
        worker::schedule_receive_queue();
        Ok(())
    }

    fn take_replies(max_items: u32, max_bytes: u32) -> Vec<Reply> {
        switch()
            .take_replies_up_to(max_items as usize, max_bytes as usize)
            .into_iter()
            .map(|reply| Reply {
                header: reply.header.encode().to_vec(),
                payload: reply.payload,
            })
            .collect()
    }

    fn deliver(guest_port: u32, host_port: u32, data: Vec<u8>) -> Result<(), Error> {
        if CLOSED.load(Ordering::Acquire) {
            return Err(Error::Backpressure);
        }
        let result = switch().deliver(guest_port, host_port, &data);
        if result.is_ok() {
            worker::schedule_receive_queue();
        }
        result.map_err(error)
    }

    fn shutdown(guest_port: u32, host_port: u32) -> Result<(), Error> {
        if CLOSED.load(Ordering::Acquire) {
            return Err(Error::Backpressure);
        }
        let result = switch().shutdown(guest_port, host_port);
        if result.is_ok() {
            worker::schedule_receive_queue();
        }
        result.map_err(error)
    }

    fn reset_connection(guest_port: u32, host_port: u32) -> Result<(), Error> {
        if CLOSED.load(Ordering::Acquire) {
            return Err(Error::Backpressure);
        }
        let result = switch().reset_connection(guest_port, host_port);
        if result.is_ok() {
            worker::schedule_receive_queue();
        }
        result.map_err(error)
    }

    fn consume_upstream(guest_port: u32, host_port: u32, max_bytes: u32) -> Vec<u8> {
        switch()
            .take_upstream_for_up_to(guest_port, host_port, max_bytes as usize)
            .into_iter()
            .flat_map(|item| item.data)
            .collect()
    }

    fn connection_count() -> u32 {
        u32::try_from(switch().connection_count()).unwrap_or(u32::MAX)
    }

    fn connection_exists(guest_port: u32, host_port: u32) -> bool {
        switch().connection_exists(guest_port, host_port)
    }

    fn connections(max_items: u32) -> Vec<Connection> {
        switch()
            .connections_up_to(max_items as usize)
            .into_iter()
            .map(|(guest_port, host_port)| Connection {
                guest_port,
                host_port,
            })
            .collect()
    }

    fn reset() {
        if !CLOSED.load(Ordering::Acquire) {
            *LAST_CLOCK_SAMPLE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            transport::reset();
            carrier::wake();
            wake_worker();
        }
    }

    async fn close() {
        CLOSED.store(true, Ordering::Release);
        *LAST_CLOCK_SAMPLE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        transport::close();
        carrier::wake();
        wake_worker();
        worker::finish().await;
    }
}

#[allow(unsafe_code)]
mod component_exports {
    use super::{Vsock, bindings};
    bindings::export!(Vsock with_types_in bindings);
}

#[cfg(test)]
mod clock_tests {
    use super::clock_update_due;

    #[test]
    fn clock_updates_cover_interval_suspend_and_wall_clock_steps() {
        const SECOND: u64 = 1_000_000_000;
        let before = (10 * SECOND, 100 * i128::from(SECOND));
        assert!(!clock_update_due(
            before,
            (20 * SECOND, 110 * i128::from(SECOND))
        ));
        assert!(clock_update_due(
            before,
            (70 * SECOND, 160 * i128::from(SECOND))
        ));
        assert!(clock_update_due(
            before,
            (20 * SECOND, 710 * i128::from(SECOND))
        ));
        assert!(clock_update_due(
            before,
            (20 * SECOND, 90 * i128::from(SECOND))
        ));
        assert!(clock_update_due(before, (0, 100 * i128::from(SECOND))));
    }
}
