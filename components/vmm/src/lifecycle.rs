use std::future::poll_fn;
use std::sync::{LazyLock, Mutex};
use std::task::{Poll, Waker};

use futures_util::future::{Either, select};

use super::exports::terra::mmio::lifecycle::Guest;
use super::terra::mmio::lifecycle_platform::{self, Event};

#[derive(Default)]
struct State {
    expected_vcpus: u8,
    finished_vcpus: u8,
    terminal: bool,
    waker: Option<Waker>,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| Mutex::new(State::default()));

pub fn configure_vcpus(count: u8) {
    let mut state = STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.expected_vcpus = count;
    state.finished_vcpus = 0;
    state.terminal = false;
    state.waker = None;
}

pub fn vcpu_finished() {
    let waker = {
        let mut state = STATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mark_vcpu_finished(&mut state);
        state.waker.take()
    };
    if let Some(waker) = waker {
        waker.wake();
    }
}

fn mark_vcpu_finished(state: &mut State) {
    state.finished_vcpus = state.finished_vcpus.saturating_add(1);
    state.terminal = state.finished_vcpus >= state.expected_vcpus;
}

async fn wait_for_vcpu() -> Event {
    poll_fn(|context| {
        let mut state = STATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.terminal {
            Poll::Ready(Event::VcpuFinished)
        } else {
            state.waker = Some(context.waker().clone());
            Poll::Pending
        }
    })
    .await
}

impl Guest for super::Dispatcher {
    async fn run() -> Result<Event, lifecycle_platform::Error> {
        <Self as Guest>::wait().await
    }

    async fn wait() -> Result<Event, lifecycle_platform::Error> {
        let outcome = wait_for_shutdown().await;
        let released = super::machine::release().map_err(|_| lifecycle_platform::Error::Closed);
        let event = outcome?;
        released?;
        Ok(event)
    }
}

async fn wait_for_shutdown() -> Result<Event, lifecycle_platform::Error> {
    let (event, running) = match select(
        Box::pin(super::machine::run_vcpus()),
        Box::pin(wait_for_event()),
    )
    .await
    {
        Either::Left((result, waiting)) => {
            let event = if result.is_err() {
                Event::ComponentFailed
            } else {
                waiting.await?
            };
            let outcome = finish_shutdown(event).await?;
            result.map_err(|_| lifecycle_platform::Error::Closed)?;
            return Ok(outcome);
        }
        Either::Right((event, running)) => (event?, running),
    };
    match select(running, Box::pin(finish_shutdown(event))).await {
        Either::Left((result, stopping)) => {
            let outcome = stopping.await?;
            result.map_err(|_| lifecycle_platform::Error::Closed)?;
            Ok(outcome)
        }
        Either::Right((outcome, _)) => outcome,
    }
}

async fn wait_for_event() -> Result<Event, lifecycle_platform::Error> {
    let event = match select(
        Box::pin(lifecycle_platform::next_event()),
        Box::pin(wait_for_vcpu()),
    )
    .await
    {
        Either::Left((event, _)) => event?,
        Either::Right((event, _)) => event,
    };
    Ok(event)
}

async fn finish_shutdown(event: Event) -> Result<Event, lifecycle_platform::Error> {
    super::machine::request_stop().map_err(|_| lifecycle_platform::Error::Closed)?;
    lifecycle_platform::shutdown().await?;
    super::machine::mark_stopped();
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::{State, mark_vcpu_finished};

    #[test]
    fn waits_for_every_configured_vcpu() {
        let mut state = State {
            expected_vcpus: 2,
            ..State::default()
        };
        mark_vcpu_finished(&mut state);
        assert!(!state.terminal);
        mark_vcpu_finished(&mut state);
        assert!(state.terminal);
    }
}
