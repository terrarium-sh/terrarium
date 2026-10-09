#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({ world: "role", path: "wit", generate_all });
}
use bindings::{exports, terra, wasi, wit_stream};

mod byte_stream;
mod lifecycle;
mod worker;

#[cfg(feature = "fuzzing")]
#[must_use]
pub fn read_lifecycle_frames_for_fuzzing(
    mut bytes: &[u8],
) -> Vec<terra_protocol::control::LifecycleEvent> {
    use futures_util::FutureExt as _;
    std::iter::from_fn(|| {
        lifecycle::read_event(&mut bytes, lifecycle::MAX_DIAGNOSTIC_PAYLOAD_BYTES)
            .now_or_never()
            .flatten()
    })
    .collect()
}

static CLOSED: terra_device_transport::Doorbell = terra_device_transport::Doorbell::new();

fn clock_update_due(previous: (u64, i128), now: (u64, i128)) -> bool {
    let Some(elapsed) = now.0.checked_sub(previous.0) else {
        return true;
    };
    elapsed >= 60_000_000_000 || (now.1 - previous.1).abs_diff(i128::from(elapsed)) >= 5_000_000_000
}

pub(crate) fn is_closed() -> bool {
    CLOSED.is_closed()
}

pub(crate) async fn wait_closed() {
    CLOSED.wait().await;
}

pub struct Agent;

impl exports::terra::agent::api::Guest for Agent {
    #[allow(clippy::unused_async_trait_impl)]
    async fn events()
    -> wit_bindgen::rt::async_support::StreamReader<exports::terra::agent::api::Event> {
        worker::events()
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn close() {
        CLOSED.close();
    }
}

#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)]
mod component_exports {
    use super::{Agent, bindings};
    bindings::export!(Agent with_types_in bindings);
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
