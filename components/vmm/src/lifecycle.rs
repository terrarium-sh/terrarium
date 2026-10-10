use futures_util::{
    FutureExt,
    future::{Either, select},
};

use super::exports::terra::vmm::lifecycle::Guest;
use super::terra::vmm::lifecycle_platform::{self, Event};

impl Guest for super::Dispatcher {
    async fn run() -> Result<Event, lifecycle_platform::Error> {
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
            let event = completed_vcpus_event(result, waiting.now_or_never())?;
            return finish_shutdown(event).await;
        }
        Either::Right((event, running)) => (event?, running),
    };
    match select(running, Box::pin(finish_shutdown(event))).await {
        Either::Left((result, stopping)) => {
            let outcome = stopping.await?;
            completed_vcpus_event(result, Some(Ok(outcome)))
        }
        Either::Right((outcome, _)) => outcome,
    }
}

fn completed_vcpus_event(
    result: Result<(), super::Error>,
    external: Option<Result<Event, lifecycle_platform::Error>>,
) -> Result<Event, lifecycle_platform::Error> {
    if let Err(error) = result {
        Ok(Event::ComponentFailed(format!("vCPU exit: {error:?}")))
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
    use std::assert_matches;

    #[test]
    fn completed_vcpus_keep_an_already_ready_external_event() {
        assert_matches!(
            completed_vcpus_event(Ok(()), Some(Ok(Event::Deadline))),
            Ok(Event::Deadline)
        );
        assert_matches!(completed_vcpus_event(Ok(()), None), Ok(Event::VcpuFinished));
        assert_matches!(
            completed_vcpus_event(Err(super::super::Error::BadArmExit), Some(Ok(Event::Deadline))),
            Ok(Event::ComponentFailed(error)) if error.contains("BadArmExit")
        );
    }
}
