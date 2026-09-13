use super::{Vsock, transport};
use crate::exports::terra::vsock::api::Guest;
use crate::terra::mmio::types::DeviceError;

terra_device_transport::mmio_device!(
    DeviceError,
    transport::mmio_read,
    write,
    Vsock::reset,
    close,
    transport::interrupt_level
);

async fn write(offset: u64, bytes: Vec<u8>) -> Result<(), DeviceError> {
    if transport::mmio_write(offset, &bytes)? {
        queue_bell(&bytes, transport::queue_notify)?;
    }
    Ok(())
}

async fn close() -> Result<(), DeviceError> {
    Vsock::close().await;
    Ok(())
}

fn queue_bell(
    bytes: &[u8],
    queue_notify: impl FnOnce(u32) -> Result<bool, DeviceError>,
) -> Result<(), DeviceError> {
    let queue = u32::from_le_bytes(bytes.try_into().map_err(|_| DeviceError::BadLen)?);
    queue_notify(queue)?;
    super::wake_worker();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn queue_bell_notifies_the_queue_and_wakes_the_worker() {
        super::super::WORK_PENDING.store(false, Ordering::Release);
        let mut notified = None;
        queue_bell(&1_u32.to_le_bytes(), |queue| {
            notified = Some(queue);
            Ok(false)
        })
        .expect("queue bell");
        assert_eq!(notified, Some(1));
        assert!(super::super::WORK_PENDING.swap(false, Ordering::AcqRel));
    }

    #[test]
    fn queue_bell_rejects_a_non_word_queue_value() {
        assert!(queue_bell(&[0], |_| Ok(false)).is_err());
    }
}
