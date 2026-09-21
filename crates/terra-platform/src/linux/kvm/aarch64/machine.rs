#![allow(unsafe_code)]

use super::worker::ArmWorkerError;
use crate::aarch64::arm::{GIC_DIST_BASE, GIC_REDIST_BASE, MAX_VCPUS, RAM_BASE};
use kvm_bindings::{
    KVM_ARM_IRQ_TYPE_SHIFT, KVM_ARM_IRQ_TYPE_SPI, KVM_ARM_VCPU_POWER_OFF, KVM_ARM_VCPU_PSCI_0_2,
    KVM_DEV_ARM_VGIC_CTRL_INIT, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_DEV_ARM_VGIC_GRP_CTRL,
    KVM_DEV_ARM_VGIC_GRP_NR_IRQS, KVM_VGIC_V3_ADDR_TYPE_DIST, KVM_VGIC_V3_ADDR_TYPE_REDIST,
    kvm_create_device, kvm_device_attr, kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
    kvm_userspace_memory_region, kvm_vcpu_init,
};
use kvm_ioctls::{DeviceFd, Kvm, VcpuFd, VmFd};
use std::sync::Arc;
use terra_runtime::memory::GuestRam;
use vm_memory::{GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

const GIC_SPI_OFFSET: u32 = 32;
const VGIC_IRQS: u32 = 128;

pub(super) struct Machine {
    vgic: DeviceFd,
    vm: Arc<VmFd>,
    ram: Arc<GuestMemoryMmap<()>>,
    irqs: Vec<u32>,
}

impl terra_runtime::component::vmm::virtualization::VirtualMachine for Machine {
    fn memory(&self) -> wasmtime::Result<GuestRam> {
        GuestRam::from_shared(self.ram())
            .ok_or_else(|| wasmtime::Error::msg("aliasing ARM KVM RAM"))
    }
}

impl Machine {
    pub(super) fn new(
        kvm: &Kvm,
        config: &terra_runtime::component::vmm::virtualization::MachineConfig,
    ) -> Result<Self, ArmWorkerError> {
        let ram_bytes = config.ram_bytes();
        let ram_size = usize::try_from(ram_bytes).map_err(|_| ArmWorkerError::Memory)?;
        if ram_size == 0 || !ram_bytes.is_multiple_of(4096) {
            return Err(ArmWorkerError::Memory);
        }
        let vm = Arc::new(kvm.create_vm()?);
        let ram = Arc::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(RAM_BASE), ram_size)])
                .map_err(|_| ArmWorkerError::Memory)?,
        );
        let host_address = ram
            .get_host_address(GuestAddress(RAM_BASE))
            .map_err(|_| ArmWorkerError::Memory)?;
        let region = kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            guest_phys_addr: RAM_BASE,
            memory_size: ram_bytes,
            userspace_addr: host_address as u64,
        };
        // SAFETY: this machine owns the mapped RAM for the VM lifetime.
        unsafe { vm.set_user_memory_region(region)? };
        let mut device = kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
            fd: 0,
            flags: 0,
        };
        let vgic = vm.create_device(&mut device)?;
        set_vgic_address(&vgic, KVM_VGIC_V3_ADDR_TYPE_DIST, GIC_DIST_BASE)?;
        set_vgic_address(&vgic, KVM_VGIC_V3_ADDR_TYPE_REDIST, GIC_REDIST_BASE)?;
        vgic.set_device_attr(&kvm_device_attr {
            group: KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            attr: 0,
            addr: std::ptr::from_ref(&VGIC_IRQS) as u64,
            flags: 0,
        })?;
        Ok(Self {
            vgic,
            vm,
            ram,
            irqs: config.devices().iter().map(|device| device.irq).collect(),
        })
    }

    pub(super) fn prepare_vcpus(&self, count: usize) -> Result<Vec<VcpuFd>, ArmWorkerError> {
        if count == 0 || count > MAX_VCPUS {
            return Err(ArmWorkerError::BadVcpuCount(count));
        }
        let mut vcpus = Vec::with_capacity(count);
        for id in 0..count {
            let vcpu = self
                .vm
                .create_vcpu(u64::try_from(id).map_err(|_| ArmWorkerError::Memory)?)?;
            let mut init = kvm_vcpu_init::default();
            self.vm.get_preferred_target(&mut init)?;
            init.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
            if id != 0 {
                init.features[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
            }
            vcpu.vcpu_init(&init)?;
            vcpus.push(vcpu);
        }
        self.vgic.set_device_attr(&kvm_device_attr {
            group: KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT),
            addr: 0,
            flags: 0,
        })?;
        Ok(vcpus)
    }

    pub(super) fn ram(&self) -> Arc<GuestMemoryMmap<()>> {
        Arc::clone(&self.ram)
    }

    pub(super) fn clear_interrupts(&self) -> Result<(), ArmWorkerError> {
        self.irqs
            .iter()
            .try_for_each(|irq| self.interrupt(*irq, false))
    }

    pub(super) fn interrupt(&self, irq: u32, level: bool) -> Result<(), ArmWorkerError> {
        let irq = GIC_SPI_OFFSET
            .checked_add(irq)
            .ok_or(ArmWorkerError::TooManyDevices)?;
        self.vm.set_irq_line(
            (KVM_ARM_IRQ_TYPE_SPI << KVM_ARM_IRQ_TYPE_SHIFT) | irq,
            level,
        )?;
        Ok(())
    }
}

fn set_vgic_address(vgic: &DeviceFd, kind: u32, address: u64) -> Result<(), ArmWorkerError> {
    vgic.set_device_attr(&kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_ADDR,
        attr: u64::from(kind),
        addr: std::ptr::from_ref(&address) as u64,
        flags: 0,
    })?;
    Ok(())
}
