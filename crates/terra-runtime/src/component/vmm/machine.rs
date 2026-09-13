pub use crate::component::vmm::mmio::terra::mmio::machine_types::{DeviceKind, Error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Device {
    pub kind: DeviceKind,
    pub mmio_base: u64,
    pub irq: u32,
}
