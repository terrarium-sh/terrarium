use futures_util::{
    FutureExt,
    future::{Either, select},
};

use super::exports::terra::mmio::lifecycle::Guest;
use super::terra::mmio::lifecycle_platform::{self, Event};

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
        Box::pin(lifecycle_platform::next_event()),
    )
    .await
    {
        Either::Left((result, waiting)) => {
            let event = completed_vcpus_event(result.is_err(), waiting.now_or_never())?;
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

fn completed_vcpus_event(
    failed: bool,
    external: Option<Result<Event, lifecycle_platform::Error>>,
) -> Result<Event, lifecycle_platform::Error> {
    if failed {
        Ok(Event::ComponentFailed)
    } else {
        external
            .transpose()
            .map(|event| event.unwrap_or(Event::VcpuFinished))
    }
}

async fn finish_shutdown(event: Event) -> Result<Event, lifecycle_platform::Error> {
    super::machine::request_stop().map_err(|_| lifecycle_platform::Error::Closed)?;
    lifecycle_platform::shutdown().await?;
    super::machine::mark_stopped();
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_vcpus_keep_an_already_ready_external_event() {
        assert!(matches!(
            completed_vcpus_event(false, Some(Ok(Event::Deadline))),
            Ok(Event::Deadline)
        ));
        assert!(matches!(
            completed_vcpus_event(false, None),
            Ok(Event::VcpuFinished)
        ));
        assert!(matches!(
            completed_vcpus_event(true, Some(Ok(Event::Deadline))),
            Ok(Event::ComponentFailed)
        ));
    }
}
