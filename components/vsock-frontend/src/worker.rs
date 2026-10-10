use crate::bindings::wasi::clocks::monotonic_clock;
use crate::{WORK, agent, network, switch, terra, transport, wait_for_work};
use futures_util::future::{Either, select};
use terra::mmio::types::DeviceError;

const MAX_DEVICE_STEPS: usize = 32;
static RUN: futures_util::lock::Mutex<()> = futures_util::lock::Mutex::new(());

fn retire_connections() -> bool {
    let mut progressed = false;
    let mut offset = 0;
    loop {
        let connection = {
            let device = switch();
            device
                .retirements()
                .filter(|connection| !device.has_pending_replies_for(*connection))
                .nth(offset)
        };
        let Some(connection) = connection else {
            break;
        };
        if !transport::has_pending_reply_for(connection) && switch().retire_connection(connection) {
            network::notify_connection(connection);
            network::notify_admission();
            progressed = true;
        } else {
            offset += 1;
        }
    }
    progressed
}

pub async fn run() -> Result<(), DeviceError> {
    let _guard = RUN.try_lock().ok_or(DeviceError::NotReady)?;
    let mut relay = None;
    let result = async {
        while !WORK.is_closed() {
            transport::suppress_transmit_notifications()?;
            let mut progressed = retire_connections();
            progressed |= transport::process_pending(MAX_DEVICE_STEPS)?;
            progressed |= retire_connections();
            progressed |= agent::service(&mut relay);
            progressed |= network::service();
            if progressed {
                wit_bindgen::yield_async().await;
            } else if !transport::rearm_transmit_notifications()? {
                wait_for_work_or_flush_held_interrupt().await?;
            }
        }
        Ok(())
    }
    .await;
    switch().reset_connections();
    retire_connections();
    network::close();
    drop(relay);
    result
}

/// Idles until new work arrives; a held TX interrupt is raised if none comes in time.
async fn wait_for_work_or_flush_held_interrupt() -> Result<(), DeviceError> {
    if !transport::has_held_interrupt() {
        wait_for_work().await;
        return Ok(());
    }
    let work = std::pin::pin!(wait_for_work());
    let timer = std::pin::pin!(monotonic_clock::wait_for(
        transport::HELD_TX_INTERRUPT_NANOS
    ));
    if let Either::Right(_) = select(work, timer).await {
        transport::flush_held_interrupt()?;
    }
    Ok(())
}

pub async fn finish() {
    let _guard = RUN.lock().await;
}
