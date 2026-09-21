//! Fixed x86 machine layouts.

pub const PAGE_SIZE: u64 = 4096;
pub const RAM_BASE: u64 = 0;
pub const MMIO_BASE: u64 = 0xD000_0000;
pub const MMIO_STRIDE: u64 = 0x1000;
pub const MAX_IO_DEVICES: usize = terra_limits::X86_MAX_DEVICES - 1;
pub const MAX_DEVICES: usize = terra_limits::X86_MAX_DEVICES;
const BOOT_IRQ: u32 = 11;
const ROOT_IRQ: u32 = 12;
const NET_IRQ: u32 = 13;
const VSOCK_IRQ: u32 = 14;
const MEMORY_IRQ: u32 = 15;
const MOUNT_IRQS: [u32; 3] = [17, 18, 19];
const VOLUME_IRQS: [u32; 3] = [20, 21, 22];
pub const IRQ_BASE: u32 = BOOT_IRQ;
pub const MAX_VCPUS: usize = terra_limits::X86_MAX_VCPUS as usize;

pub use terra_runtime::component::vmm::bindings::machine::{Device, DeviceKind};

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
    ) -> wasmtime::Result<terra_runtime::component::vmm::virtualization::MachineConfig> {
        use terra_runtime::component::vmm::virtualization;
        virtualization::MachineConfig::new(
            virtualization::Architecture::X86,
            self.ram_size,
            u8::try_from(vcpus)?,
            self.devices.clone(),
        )
    }
}

fn device_irq(kind: DeviceKind, slot: usize, base_count: usize) -> u32 {
    match kind {
        DeviceKind::Block => match slot {
            0 => BOOT_IRQ,
            1 => ROOT_IRQ,
            _ => VOLUME_IRQS[(slot - 2) % VOLUME_IRQS.len()],
        },
        DeviceKind::Net => NET_IRQ,
        DeviceKind::Vsock => VSOCK_IRQ,
        DeviceKind::Fs => MOUNT_IRQS[(slot - base_count) % MOUNT_IRQS.len()],
        DeviceKind::Memory => MEMORY_IRQ,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    Unaligned,
    ZeroSized,
    Overlap,
    TooManyDevices,
}

/// Build Terra's fixed x86 machine layout.
pub fn build_machine_layout(
    ram_size: u64,
    block_count: usize,
    share_count: usize,
) -> Result<Layout, LayoutError> {
    if ram_size == 0 {
        return Err(LayoutError::ZeroSized);
    }
    if !ram_size.is_multiple_of(PAGE_SIZE) {
        return Err(LayoutError::Unaligned);
    }
    if ram_size > MMIO_BASE - RAM_BASE {
        return Err(LayoutError::Overlap);
    }
    let base_count = block_count
        .checked_add(2)
        .ok_or(LayoutError::TooManyDevices)?;
    let device_count = base_count
        .checked_add(share_count)
        .and_then(|count| count.checked_add(1))
        .filter(|count| *count <= MAX_DEVICES)
        .ok_or(LayoutError::TooManyDevices)?;
    const {
        assert!(MAX_DEVICES as u64 <= (u64::MAX - MMIO_BASE) / MMIO_STRIDE);
    }
    let mut devices = Vec::with_capacity(device_count);
    for slot in 0..device_count {
        let kind = if slot < block_count {
            DeviceKind::Block
        } else if slot == block_count {
            DeviceKind::Net
        } else if slot == block_count + 1 {
            DeviceKind::Vsock
        } else if slot < base_count + share_count {
            DeviceKind::Fs
        } else {
            DeviceKind::Memory
        };
        devices.push(Device {
            kind,
            mmio_base: MMIO_BASE + slot as u64 * MMIO_STRIDE,
            irq: device_irq(kind, slot, base_count),
        });
    }
    Ok(Layout { ram_size, devices })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_machine_layout_has_fixed_device_grants() {
        let layout = build_machine_layout(512 << 20, 2, 1).unwrap();
        assert_eq!(
            layout
                .devices()
                .iter()
                .map(|device| device.kind)
                .collect::<Vec<_>>(),
            vec![
                DeviceKind::Block,
                DeviceKind::Block,
                DeviceKind::Net,
                DeviceKind::Vsock,
                DeviceKind::Fs,
                DeviceKind::Memory,
            ]
        );
        assert_eq!(layout.devices()[0].mmio_base, MMIO_BASE);
        assert_eq!(layout.devices()[5].irq, MEMORY_IRQ);
    }

    #[test]
    fn fixed_layout_preserves_volume_and_share_capacity() {
        let volumes = build_machine_layout(512 << 20, 34, 0).unwrap();
        assert_eq!(volumes.devices().len(), MAX_DEVICES);
        assert_eq!(volumes.devices()[2].irq, VOLUME_IRQS[0]);
        assert_eq!(volumes.devices()[33].irq, VOLUME_IRQS[1]);
        assert_eq!(volumes.devices()[34].kind, DeviceKind::Net);
        assert_eq!(volumes.devices()[36].kind, DeviceKind::Memory);

        let shares = build_machine_layout(512 << 20, 2, 32).unwrap();
        assert_eq!(shares.devices().len(), MAX_DEVICES);
        assert_eq!(shares.devices()[4].irq, MOUNT_IRQS[0]);
        assert_eq!(shares.devices()[35].irq, MOUNT_IRQS[1]);
        assert_eq!(shares.devices()[36].kind, DeviceKind::Memory);
    }

    #[test]
    fn fixed_layout_rejects_invalid_dimensions() {
        assert_eq!(build_machine_layout(0, 1, 0), Err(LayoutError::ZeroSized));
        assert_eq!(
            build_machine_layout(1000, 1, 0),
            Err(LayoutError::Unaligned)
        );
        assert_eq!(
            build_machine_layout(MMIO_BASE + PAGE_SIZE, 1, 0),
            Err(LayoutError::Overlap)
        );
        assert_eq!(
            build_machine_layout(512 << 20, usize::MAX, 0),
            Err(LayoutError::TooManyDevices)
        );
    }
}
