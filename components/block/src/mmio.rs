use super::{Block, DeviceError};

terra_device_transport::mmio_device!(
    DeviceError,
    Block::mmio_read,
    Block::mmio_write,
    Block::reset,
    Block::close,
    Block::interrupt_level
);
