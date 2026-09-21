#![allow(unsafe_code)]

use super::ArmWorkerError;
use crate::aarch64::arm::MAX_VCPUS;
use crate::memory::GuestMemory;
use crate::vm::VmConfig;
use kvm_bindings::{
    KVM_ARM_IRQ_TYPE_SHIFT, KVM_ARM_IRQ_TYPE_SPI, KVM_ARM_VCPU_POWER_OFF, KVM_ARM_VCPU_PSCI_0_2,
    KVM_DEV_ARM_VGIC_CTRL_INIT, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_DEV_ARM_VGIC_GRP_CTRL,
    KVM_DEV_ARM_VGIC_GRP_NR_IRQS, KVM_VGIC_V3_ADDR_TYPE_DIST, KVM_VGIC_V3_ADDR_TYPE_REDIST,
    kvm_create_device, kvm_device_attr, kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
    kvm_userspace_memory_region, kvm_vcpu_init,
};
use kvm_ioctls::{DeviceFd, Kvm, VcpuFd, VmFd};
use std::sync::Arc;

const GIC_SPI_OFFSET: u32 = 32;
const VGIC_IRQS: u32 = 128;

pub(crate) struct Machine {
    vgic: DeviceFd,
    vm: Arc<VmFd>,
    ram: GuestMemory,
    irqs: Vec<u32>,
}

impl Machine {
    pub(super) fn new(kvm: &Kvm, config: &VmConfig) -> Result<Self, ArmWorkerError> {
        let ram_size = usize::try_from(config.ram_bytes).map_err(|_| ArmWorkerError::Memory)?;
        if ram_size == 0 || !config.ram_bytes.is_multiple_of(4096) {
            return Err(ArmWorkerError::Memory);
        }
        let crate::vm::InterruptControllerConfig::Arm(gic) = &config.interrupt_controller else {
            return Err(ArmWorkerError::Memory);
        };
        if gic.distributor_size == 0
            || gic.redistributor_size == 0
            || gic
                .distributor_base
                .checked_add(gic.distributor_size)
                .is_none()
            || gic
                .redistributor_base
                .checked_add(gic.redistributor_size)
                .is_none()
        {
            return Err(ArmWorkerError::Memory);
        }
        let vm = Arc::new(kvm.create_vm()?);
        let ram = GuestMemory::allocate_at(config.ram_base, config.ram_bytes)
            .ok_or(ArmWorkerError::Memory)?;
        let host_address = ram
            .host_address(config.ram_base)
            .ok_or(ArmWorkerError::Memory)?;
        let region = kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            guest_phys_addr: config.ram_base,
            memory_size: config.ram_bytes,
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
        set_vgic_address(&vgic, KVM_VGIC_V3_ADDR_TYPE_DIST, gic.distributor_base)?;
        set_vgic_address(&vgic, KVM_VGIC_V3_ADDR_TYPE_REDIST, gic.redistributor_base)?;
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
            irqs: config.irq_routes.clone(),
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

    pub(crate) fn memory(&self) -> GuestMemory {
        self.ram.clone()
    }

    pub(crate) fn clear_interrupts(&self) -> Result<(), ArmWorkerError> {
        self.irqs
            .iter()
            .try_for_each(|irq| self.set_irq_line(*irq, false))
    }

    pub(crate) fn inject_interrupt(&self, irq: u32, level: bool) -> Result<(), String> {
        self.set_irq_line(irq, level)
            .map_err(|error| format!("ARM interrupt: {error:?}"))
    }

    fn set_irq_line(&self, irq: u32, level: bool) -> Result<(), ArmWorkerError> {
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
