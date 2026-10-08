use super::{Frontend, transport};
use crate::exports::terra::vsock_frontend::api::Guest;
use crate::terra::mmio::types::DeviceError;

terra_device_transport::mmio_device!(
    DeviceError,
    transport::mmio_read,
    write,
    super::reset_device,
    close,
    transport::interrupt_level
);

async fn write(offset: u64, width: u8, value: u64) -> Result<(), DeviceError> {
    transport::mmio_write(offset, width, value)
}

async fn close() -> Result<(), DeviceError> {
    Frontend::close().await;
    Ok(())
}
