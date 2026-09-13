use super::transport;
use crate::terra::mmio::types::DeviceError;

terra_device_transport::mmio_device!(
    DeviceError,
    transport::mmio_read,
    write,
    transport::reset,
    close,
    transport::interrupt_level
);

async fn write(offset: u64, bytes: Vec<u8>) -> Result<(), DeviceError> {
    transport::mmio_write(offset, &bytes).map(|_| ())
}

async fn close() -> Result<(), DeviceError> {
    transport::close()
}
