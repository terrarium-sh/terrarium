//! Guest-driver side of the virtio-MMIO handshake that self-tests play against devices.

pub use crate::component::mmio::QUEUE_NOTIFY;

use crate::component::MmioDevice;

pub const MAGIC_VALUE: u64 = 0x00;
const DRIVER_FEATURES: u64 = 0x20;
const DRIVER_FEATURES_SELECT: u64 = 0x24;
const QUEUE_SELECT: u64 = 0x30;
const QUEUE_SIZE: u64 = 0x38;
const QUEUE_READY: u64 = 0x44;
pub const INTERRUPT_STATUS: u64 = 0x60;
pub const INTERRUPT_ACK: u64 = 0x64;
pub const STATUS: u64 = 0x70;
const QUEUE_DESCRIPTORS: u64 = 0x80;
const QUEUE_AVAILABLE: u64 = 0x90;
const QUEUE_USED: u64 = 0xa0;

/// `"virt"` in little-endian, read back from [`MAGIC_VALUE`].
pub const MAGIC: u32 = 0x7472_6976;

pub const STATUS_RESET: u32 = 0;
const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;

const VIRTIO_F_VERSION_1: u32 = 1;

/// Guest-physical placement of one split virtqueue.
#[derive(Clone, Copy)]
pub struct QueueLayout {
    pub size: u16,
    pub descriptors: u64,
    pub available: u64,
    pub used: u64,
}

/// Acknowledges the device and accepts `VIRTIO_F_VERSION_1` plus the low feature word `features`.
pub fn negotiate_features(device: &MmioDevice, features: u32) -> wasmtime::Result<()> {
    write_registers(
        device,
        &[
            (STATUS, STATUS_ACKNOWLEDGE),
            (STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER),
            (DRIVER_FEATURES_SELECT, 0),
            (DRIVER_FEATURES, features),
            (DRIVER_FEATURES_SELECT, 1),
            (DRIVER_FEATURES, VIRTIO_F_VERSION_1),
            (
                STATUS,
                STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
            ),
        ],
    )
}

pub fn enable_queue(device: &MmioDevice, queue: u32, layout: QueueLayout) -> wasmtime::Result<()> {
    write_registers(
        device,
        &[
            (QUEUE_SELECT, queue),
            (QUEUE_SIZE, u32::from(layout.size)),
            (QUEUE_DESCRIPTORS, u32::try_from(layout.descriptors)?),
            (QUEUE_AVAILABLE, u32::try_from(layout.available)?),
            (QUEUE_USED, u32::try_from(layout.used)?),
            (QUEUE_READY, 1),
        ],
    )
}

pub fn set_driver_ok(device: &MmioDevice) -> wasmtime::Result<()> {
    write_registers(
        device,
        &[(
            STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        )],
    )
}

pub fn start_single_queue(
    device: &MmioDevice,
    features: u32,
    queue: u32,
    layout: QueueLayout,
) -> wasmtime::Result<()> {
    negotiate_features(device, features)?;
    enable_queue(device, queue, layout)?;
    set_driver_ok(device)
}

fn write_registers(device: &MmioDevice, registers: &[(u64, u32)]) -> wasmtime::Result<()> {
    for &(offset, value) in registers {
        device.write(offset, &value.to_le_bytes())?;
    }
    Ok(())
}
