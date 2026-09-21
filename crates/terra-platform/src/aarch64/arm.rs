//! Fixed ARM machine layout.

/// Guest RAM begins at this fixed physical address.
pub const RAM_BASE: u64 = terra_limits::ARM_RAM_BASE;
/// `GICv3` distributor base.
pub const GIC_DIST_BASE: u64 = terra_limits::ARM_GIC_DIST_BASE;
/// `GICv3` distributor size.
pub const GIC_DIST_SIZE: u64 = terra_limits::ARM_GIC_DIST_SIZE;
/// `GICv3` redistributor base.
pub const GIC_REDIST_BASE: u64 = terra_limits::ARM_GIC_REDIST_BASE;
/// `GICv3` redistributor size.
pub const GIC_REDIST_SIZE: u64 = terra_limits::ARM_GIC_REDIST_SIZE;
/// First virtio-MMIO device base.
pub const VIRTIO_MMIO_BASE: u64 = terra_limits::ARM_VIRTIO_MMIO_BASE;
/// Space between virtio-MMIO devices.
pub const VIRTIO_MMIO_STRIDE: u64 = terra_limits::ARM_VIRTIO_MMIO_STRIDE;
/// First virtio SPI number, encoded without the GIC's 32 interrupt offset.
pub const VIRTIO_IRQ_BASE: u32 = terra_limits::ARM_VIRTIO_IRQ_BASE;
/// Maximum number of fixed virtio-MMIO devices.
pub const MAX_DEVICES: usize = terra_limits::ARM_MAX_DEVICES;
/// Maximum number of fixed vCPUs.
pub const MAX_VCPUS: usize = terra_limits::ARM_MAX_VCPUS as usize;

/// GIC address ranges described to the fixed Linux guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GicLayout {
    pub distributor_base: u64,
    pub distributor_size: u64,
    pub redistributor_base: u64,
    pub redistributor_size: u64,
}

pub const GIC_LAYOUT: GicLayout = GicLayout {
    distributor_base: GIC_DIST_BASE,
    distributor_size: GIC_DIST_SIZE,
    redistributor_base: GIC_REDIST_BASE,
    redistributor_size: GIC_REDIST_SIZE,
};

pub use terra_runtime::component::vmm::{Device, DeviceKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    ram_size: u64,
    devices: Vec<Device>,
}

impl Layout {
    #[must_use]
    pub fn ram_size(&self) -> u64 {
        self.ram_size
    }

    #[must_use]
    pub fn devices(&self) -> &[Device] {
        &self.devices
    }

    pub fn machine_config(
        &self,
        vcpus: usize,
    ) -> wasmtime::Result<terra_runtime::component::vmm::MachineConfig> {
        use terra_runtime::component::vmm;
        vmm::MachineConfig::new(
            vmm::Architecture::Arm,
            self.ram_size,
            u8::try_from(vcpus)?,
            self.devices.clone(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    Unaligned,
    ZeroSized,
    RamOverflow,
    TooManyDevices,
}

pub fn build_machine_layout(
    ram_size: u64,
    block_count: usize,
    share_count: usize,
) -> Result<Layout, LayoutError> {
    if ram_size == 0 {
        return Err(LayoutError::ZeroSized);
    }
    if !ram_size.is_multiple_of(4096) {
        return Err(LayoutError::Unaligned);
    }
    if RAM_BASE.checked_add(ram_size).is_none() {
        return Err(LayoutError::RamOverflow);
    }
    let count = block_count
        .checked_add(share_count)
        .and_then(|count| count.checked_add(3))
        .filter(|count| *count <= MAX_DEVICES)
        .ok_or(LayoutError::TooManyDevices)?;
    let devices = (0..count)
        .map(|slot| {
            Ok(Device {
                kind: if slot < block_count {
                    DeviceKind::Block
                } else if slot < block_count + share_count {
                    DeviceKind::Fs
                } else if slot == block_count + share_count {
                    DeviceKind::Memory
                } else if slot == block_count + share_count + 1 {
                    DeviceKind::Net
                } else {
                    DeviceKind::Vsock
                },
                mmio_base: VIRTIO_MMIO_BASE
                    + u64::try_from(slot).map_err(|_| LayoutError::TooManyDevices)?
                        * VIRTIO_MMIO_STRIDE,
                irq: VIRTIO_IRQ_BASE
                    + u32::try_from(slot).map_err(|_| LayoutError::TooManyDevices)?,
            })
        })
        .collect::<Result<_, LayoutError>>()?;
    Ok(Layout { ram_size, devices })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm_machine_has_fixed_devices() {
        let layout = build_machine_layout(4096, 1, 1).unwrap();
        assert_eq!(layout.ram_size(), 4096);
        assert_eq!(
            layout
                .devices()
                .iter()
                .map(|device| device.kind)
                .collect::<Vec<_>>(),
            vec![
                DeviceKind::Block,
                DeviceKind::Fs,
                DeviceKind::Memory,
                DeviceKind::Net,
                DeviceKind::Vsock
            ]
        );
        assert_eq!(layout.devices()[0].mmio_base, VIRTIO_MMIO_BASE);
        assert_eq!(layout.devices()[4].irq, VIRTIO_IRQ_BASE + 4);
        assert_eq!(build_machine_layout(0, 0, 0), Err(LayoutError::ZeroSized));
        assert_eq!(build_machine_layout(1, 0, 0), Err(LayoutError::Unaligned));
        assert_eq!(
            build_machine_layout(4096, MAX_DEVICES, 0),
            Err(LayoutError::TooManyDevices)
        );
    }
}
