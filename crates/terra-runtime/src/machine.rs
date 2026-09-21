//! Guest machine layouts, validated configuration, and native VM configuration.

pub use crate::component::vmm::bindings::machine::{Device, DeviceKind};
pub use crate::component::vmm::bindings::virtualization::Architecture;
use crate::component::vmm::bindings::virtualization::Config;

#[derive(Clone)]
pub struct MachineConfig {
    config: Config,
}

impl MachineConfig {
    pub fn new(
        architecture: Architecture,
        ram_bytes: u64,
        vcpus: u8,
        devices: Vec<Device>,
    ) -> wasmtime::Result<Self> {
        wasmtime::ensure!(
            vcpus != 0
                && usize::from(vcpus)
                    <= match architecture {
                        Architecture::X86 => terra_limits::X86_MAX_VCPUS as usize,
                        Architecture::Arm => terra_limits::ARM_MAX_VCPUS as usize,
                    },
            "vCPU count outside VM grant"
        );
        wasmtime::ensure!(
            ram_bytes != 0 && ram_bytes.is_multiple_of(4096),
            "RAM size outside VM grant"
        );
        wasmtime::ensure!(
            devices.len()
                <= match architecture {
                    Architecture::X86 => terra_limits::X86_MAX_DEVICES,
                    Architecture::Arm => terra_limits::ARM_MAX_DEVICES,
                },
            "device count outside VM grant"
        );
        Ok(Self {
            config: Config {
                architecture,
                ram_bytes,
                vcpus,
                devices,
            },
        })
    }

    #[must_use]
    pub fn architecture(&self) -> Architecture {
        self.config.architecture
    }

    #[must_use]
    pub fn ram_bytes(&self) -> u64 {
        self.config.ram_bytes
    }

    #[must_use]
    pub fn vcpus(&self) -> u8 {
        self.config.vcpus
    }

    #[must_use]
    pub fn devices(&self) -> &[Device] {
        &self.config.devices
    }

    #[must_use]
    pub(crate) fn is_valid_cpu(&self, id: u8) -> bool {
        id < self.config.vcpus
    }

    pub(crate) fn device_slot(&self, kind: DeviceKind, ordinal: usize) -> wasmtime::Result<u8> {
        self.devices()
            .iter()
            .enumerate()
            .filter(|(_, device)| device.kind == kind)
            .nth(ordinal)
            .map(|(slot, _)| u8::try_from(slot))
            .transpose()?
            .ok_or_else(|| wasmtime::Error::msg("interrupt device outside VM grant"))
    }

    #[must_use]
    pub(crate) fn to_native_config(&self) -> terra_platform::vm::VmConfig {
        use terra_platform::vm::{GicConfig, InterruptControllerConfig, VmConfig};

        VmConfig {
            ram_base: match self.architecture() {
                Architecture::X86 => 0,
                Architecture::Arm => terra_limits::ARM_RAM_BASE,
            },
            ram_bytes: self.ram_bytes(),
            vcpus: self.vcpus(),
            interrupt_controller: match self.architecture() {
                Architecture::X86 => InterruptControllerConfig::X86,
                Architecture::Arm => InterruptControllerConfig::Arm(GicConfig {
                    distributor_base: terra_limits::ARM_GIC_DIST_BASE,
                    distributor_size: terra_limits::ARM_GIC_DIST_SIZE,
                    redistributor_base: terra_limits::ARM_GIC_REDIST_BASE,
                    redistributor_size: terra_limits::ARM_GIC_REDIST_SIZE,
                }),
            },
            irq_routes: self.devices().iter().map(|device| device.irq).collect(),
        }
    }

    pub(crate) fn into_component_config(self) -> Config {
        self.config
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    architecture: Architecture,
    ram_size: u64,
    devices: Vec<Device>,
}

impl Layout {
    #[must_use]
    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    #[must_use]
    pub fn ram_size(&self) -> u64 {
        self.ram_size
    }

    #[must_use]
    pub fn devices(&self) -> &[Device] {
        &self.devices
    }

    pub fn to_machine_config(&self, vcpus: usize) -> wasmtime::Result<MachineConfig> {
        MachineConfig::new(
            self.architecture,
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
    Overlap,
}

pub const MAX_VCPUS: usize = if cfg!(target_arch = "aarch64") {
    terra_limits::ARM_MAX_VCPUS as usize
} else {
    terra_limits::X86_MAX_VCPUS as usize
};

#[cfg(target_arch = "x86_64")]
pub const MAX_GUEST_STORAGE_DEVICES: usize = terra_limits::X86_MAX_DEVICES - 5;
#[cfg(target_arch = "aarch64")]
pub const MAX_GUEST_STORAGE_DEVICES: usize = terra_limits::ARM_MAX_DEVICES - 5;

const PAGE_SIZE: u64 = 4096;

pub fn build_machine_layout(
    ram_size: u64,
    block_count: usize,
    share_count: usize,
) -> Result<Layout, LayoutError> {
    build_machine_layout_for(host_architecture(), ram_size, block_count, share_count)
}

const fn host_architecture() -> Architecture {
    #[cfg(target_arch = "x86_64")]
    return Architecture::X86;
    #[cfg(target_arch = "aarch64")]
    return Architecture::Arm;
}

pub(crate) fn build_machine_layout_for(
    architecture: Architecture,
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
    match architecture {
        Architecture::X86 => x86_layout(ram_size, block_count, share_count),
        Architecture::Arm => arm_layout(ram_size, block_count, share_count),
    }
}

fn x86_layout(
    ram_size: u64,
    block_count: usize,
    share_count: usize,
) -> Result<Layout, LayoutError> {
    const MMIO_BASE: u64 = 0xd000_0000;
    const MMIO_STRIDE: u64 = 0x1000;
    const MOUNT_IRQS: [u32; 3] = [17, 18, 19];
    const VOLUME_IRQS: [u32; 3] = [20, 21, 22];
    if ram_size > MMIO_BASE {
        return Err(LayoutError::Overlap);
    }
    let base_count = block_count
        .checked_add(2)
        .ok_or(LayoutError::TooManyDevices)?;
    let count = base_count
        .checked_add(share_count)
        .and_then(|count| count.checked_add(1))
        .filter(|count| *count <= terra_limits::X86_MAX_DEVICES)
        .ok_or(LayoutError::TooManyDevices)?;
    let devices = (0..count)
        .map(|slot| -> Result<_, LayoutError> {
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
            let irq = match kind {
                DeviceKind::Block => match slot {
                    0 => 11,
                    1 => 12,
                    _ => VOLUME_IRQS[(slot - 2) % VOLUME_IRQS.len()],
                },
                DeviceKind::Net => 13,
                DeviceKind::Vsock => 14,
                DeviceKind::Memory => 15,
                DeviceKind::Fs => MOUNT_IRQS[(slot - base_count) % MOUNT_IRQS.len()],
            };
            Ok(Device {
                kind,
                mmio_base: MMIO_BASE
                    + u64::try_from(slot).map_err(|_| LayoutError::TooManyDevices)? * MMIO_STRIDE,
                irq,
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(Layout {
        architecture: Architecture::X86,
        ram_size,
        devices,
    })
}

fn arm_layout(
    ram_size: u64,
    block_count: usize,
    share_count: usize,
) -> Result<Layout, LayoutError> {
    let count = block_count
        .checked_add(share_count)
        .and_then(|count| count.checked_add(3))
        .filter(|count| *count <= terra_limits::ARM_MAX_DEVICES)
        .ok_or(LayoutError::TooManyDevices)?;
    if terra_limits::ARM_RAM_BASE.checked_add(ram_size).is_none() {
        return Err(LayoutError::RamOverflow);
    }
    let devices = (0..count)
        .map(|slot| -> Result<_, LayoutError> {
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
                mmio_base: terra_limits::ARM_VIRTIO_MMIO_BASE
                    + u64::try_from(slot).map_err(|_| LayoutError::TooManyDevices)?
                        * terra_limits::ARM_VIRTIO_MMIO_STRIDE,
                irq: terra_limits::ARM_VIRTIO_IRQ_BASE
                    + u32::try_from(slot).map_err(|_| LayoutError::TooManyDevices)?,
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(Layout {
        architecture: Architecture::Arm,
        ram_size,
        devices,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_configuration_preserves_the_machine_layout() {
        use terra_platform::vm::{GicConfig, InterruptControllerConfig, VmConfig};

        for architecture in [Architecture::X86, Architecture::Arm] {
            let layout = build_machine_layout_for(architecture, 8 << 20, 2, 1).unwrap();
            let config = layout.to_machine_config(2).unwrap();
            let expected = VmConfig {
                ram_base: match architecture {
                    Architecture::X86 => 0,
                    Architecture::Arm => terra_limits::ARM_RAM_BASE,
                },
                ram_bytes: 8 << 20,
                vcpus: 2,
                interrupt_controller: match architecture {
                    Architecture::X86 => InterruptControllerConfig::X86,
                    Architecture::Arm => InterruptControllerConfig::Arm(GicConfig {
                        distributor_base: terra_limits::ARM_GIC_DIST_BASE,
                        distributor_size: terra_limits::ARM_GIC_DIST_SIZE,
                        redistributor_base: terra_limits::ARM_GIC_REDIST_BASE,
                        redistributor_size: terra_limits::ARM_GIC_REDIST_SIZE,
                    }),
                },
                irq_routes: layout.devices().iter().map(|device| device.irq).collect(),
            };
            assert_eq!(config.to_native_config(), expected);
            let component = config.into_component_config();
            assert_eq!(component.architecture, architecture);
            assert_eq!(component.ram_bytes, expected.ram_bytes);
            assert_eq!(component.vcpus, expected.vcpus);
            assert_eq!(component.devices, layout.devices());
        }
    }

    #[test]
    fn arm_machine_has_fixed_devices() {
        let layout = build_machine_layout_for(Architecture::Arm, 4096, 1, 1).unwrap();
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
                DeviceKind::Vsock,
            ]
        );
        assert_eq!(
            layout.devices()[0].mmio_base,
            terra_limits::ARM_VIRTIO_MMIO_BASE
        );
        assert_eq!(
            layout.devices()[4].irq,
            terra_limits::ARM_VIRTIO_IRQ_BASE + 4
        );
        assert_eq!(
            build_machine_layout_for(Architecture::Arm, 0, 0, 0),
            Err(LayoutError::ZeroSized)
        );
        assert_eq!(
            build_machine_layout_for(Architecture::Arm, 1, 0, 0),
            Err(LayoutError::Unaligned)
        );
        assert_eq!(
            build_machine_layout_for(Architecture::Arm, 4096, terra_limits::ARM_MAX_DEVICES, 0),
            Err(LayoutError::TooManyDevices)
        );
    }

    #[test]
    fn native_machine_layout_has_fixed_device_grants() {
        let layout = build_machine_layout_for(Architecture::X86, 512 << 20, 2, 1).unwrap();
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
        assert_eq!(layout.devices()[0].mmio_base, 0xd000_0000);
        assert_eq!(layout.devices()[5].irq, 15);
    }

    #[test]
    fn fixed_layout_preserves_volume_and_share_capacity() {
        let volumes = build_machine_layout_for(Architecture::X86, 512 << 20, 34, 0).unwrap();
        assert_eq!(volumes.devices().len(), terra_limits::X86_MAX_DEVICES);
        assert_eq!(volumes.devices()[2].irq, 20);
        assert_eq!(volumes.devices()[33].irq, 21);
        assert_eq!(volumes.devices()[34].kind, DeviceKind::Net);
        assert_eq!(volumes.devices()[36].kind, DeviceKind::Memory);

        let shares = build_machine_layout_for(Architecture::X86, 512 << 20, 2, 32).unwrap();
        assert_eq!(shares.devices().len(), terra_limits::X86_MAX_DEVICES);
        assert_eq!(shares.devices()[4].irq, 17);
        assert_eq!(shares.devices()[35].irq, 18);
        assert_eq!(shares.devices()[36].kind, DeviceKind::Memory);
    }

    #[test]
    fn fixed_layout_rejects_invalid_dimensions() {
        assert_eq!(
            build_machine_layout_for(Architecture::X86, 0, 1, 0),
            Err(LayoutError::ZeroSized)
        );
        assert_eq!(
            build_machine_layout_for(Architecture::X86, 1000, 1, 0),
            Err(LayoutError::Unaligned)
        );
        assert_eq!(
            build_machine_layout_for(Architecture::X86, 0xd000_0000 + PAGE_SIZE, 1, 0),
            Err(LayoutError::Overlap)
        );
        assert_eq!(
            build_machine_layout_for(Architecture::X86, 512 << 20, usize::MAX, 0),
            Err(LayoutError::TooManyDevices)
        );
    }

    #[test]
    fn volume_blocks_precede_network_and_vsock() {
        let layout = build_machine_layout_for(Architecture::X86, 512 << 20, 10, 0).unwrap();
        let kinds = layout
            .devices()
            .iter()
            .map(|device| device.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            [
                vec![DeviceKind::Block; 10],
                vec![DeviceKind::Net, DeviceKind::Vsock, DeviceKind::Memory],
            ]
            .concat()
        );
    }
}
