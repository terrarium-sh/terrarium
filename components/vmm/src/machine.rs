use super::exports::terra::mmio::machine::Guest;
use super::terra::mmio::machine_types::{Device, Error};
use super::terra::mmio::virtualization::{Architecture, Config, Vm};
use std::sync::{Arc, Mutex};

#[derive(PartialEq)]
enum VcpuState {
    Prepared,
    Running,
    Stopped,
}

struct Machine {
    vm: Arc<Vm>,
    config: Config,
    interrupt_mode: InterruptMode,
    vcpu_state: VcpuState,
    vcpus: Option<Vec<super::terra::mmio::platform::Vcpu>>,
}

enum InterruptMode {
    Unconfigured,
    IrqLines(Vec<bool>),
    Ioapic,
}

static VM: Mutex<Option<Machine>> = Mutex::new(None);

impl Guest for super::Dispatcher {
    fn initialize(
        config: Config,
        vm: Vm,
        vcpus: Vec<super::terra::mmio::platform::Vcpu>,
    ) -> Result<(), Error> {
        let mut machine = VM.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if machine.is_some() {
            return Err(Error::AlreadyCreated);
        }
        if vcpus.len() != usize::from(config.vcpus) {
            return Err(Error::InvalidVcpus);
        }
        let max_devices = match config.architecture {
            Architecture::X86 => terra_limits::X86_MAX_DEVICES,
            Architecture::Arm => terra_limits::ARM_MAX_DEVICES,
        };
        let max_vcpus = match config.architecture {
            Architecture::X86 => terra_limits::X86_MAX_VCPUS,
            Architecture::Arm => terra_limits::ARM_MAX_VCPUS,
        };
        if config.devices.len() > max_devices || config.vcpus > max_vcpus {
            return Err(Error::InvalidVcpus);
        }
        <super::Dispatcher as super::exports::terra::mmio::router::Guest>::configure_vcpus(
            config.vcpus,
        )
        .map_err(|_| Error::Platform)?;
        *machine = Some(Machine {
            vm: Arc::new(vm),
            interrupt_mode: InterruptMode::Unconfigured,
            config,
            vcpu_state: VcpuState::Prepared,
            vcpus: Some(vcpus),
        });
        Ok(())
    }

    fn compose() -> Result<(), Error> {
        {
            let machine = VM.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if machine
                .as_ref()
                .is_none_or(|machine| machine.vcpu_state != VcpuState::Prepared)
            {
                return Err(Error::InvalidState);
            }
        }
        let mut machine = VM.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        machine.as_mut().ok_or(Error::InvalidState)?.vcpu_state = VcpuState::Running;
        Ok(())
    }
}

pub fn stage_ioapic() -> Result<(), Error> {
    stage_interrupts(true)
}

pub fn stage_irq_lines() -> Result<(), Error> {
    stage_interrupts(false)
}

fn stage_interrupts(uses_ioapic: bool) -> Result<(), Error> {
    let mut machine = VM.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let machine = machine.as_mut().ok_or(Error::InvalidState)?;
    if machine.vcpu_state != VcpuState::Prepared
        || !matches!(machine.interrupt_mode, InterruptMode::Unconfigured)
        || machine.config.architecture != Architecture::X86
    {
        return Err(Error::InvalidState);
    }
    if uses_ioapic {
        super::IOAPIC
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .configure(
                machine
                    .config
                    .devices
                    .iter()
                    .map(|device| device.irq)
                    .collect(),
            )
            .map_err(|_| Error::Platform)?;
    }
    machine.interrupt_mode = if uses_ioapic {
        InterruptMode::Ioapic
    } else {
        InterruptMode::IrqLines(vec![false; machine.config.devices.len()])
    };
    Ok(())
}

pub fn clear_irq_lines() -> Result<Vec<super::exports::terra::mmio::interrupts::IrqLevel>, Error> {
    let mut machine = VM.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let machine = machine.as_mut().ok_or(Error::InvalidState)?;
    let InterruptMode::IrqLines(levels) = &mut machine.interrupt_mode else {
        return Err(Error::InvalidState);
    };
    let mut changes = Vec::new();
    for (device, level) in machine.config.devices.iter().zip(levels) {
        if std::mem::take(level)
            && !changes.iter().any(
                |change: &super::exports::terra::mmio::interrupts::IrqLevel| {
                    change.gsi == device.irq
                },
            )
        {
            changes.push(super::exports::terra::mmio::interrupts::IrqLevel {
                gsi: device.irq,
                asserted: false,
            });
        }
    }
    Ok(changes)
}

pub fn device_irq_line(
    slot: u8,
    asserted: bool,
) -> Result<Option<super::exports::terra::mmio::interrupts::IrqLevel>, Error> {
    let mut machine = VM.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let machine = machine.as_mut().ok_or(Error::InvalidState)?;
    let InterruptMode::IrqLines(levels) = &mut machine.interrupt_mode else {
        return Err(Error::InvalidState);
    };
    update_irq_level(&machine.config.devices, levels, usize::from(slot), asserted)
}

fn update_irq_level(
    devices: &[Device],
    levels: &mut [bool],
    slot: usize,
    asserted: bool,
) -> Result<Option<super::exports::terra::mmio::interrupts::IrqLevel>, Error> {
    if devices.len() != levels.len() {
        return Err(Error::InvalidState);
    }
    let device = devices.get(slot).ok_or(Error::InvalidState)?;
    let gsi = device.irq;
    let previous = devices
        .iter()
        .zip(levels.iter())
        .any(|(device, level)| device.irq == gsi && *level);
    levels[slot] = asserted;
    let next = devices
        .iter()
        .zip(levels.iter())
        .any(|(device, level)| device.irq == gsi && *level);
    Ok(
        (previous != next).then_some(super::exports::terra::mmio::interrupts::IrqLevel {
            gsi,
            asserted: next,
        }),
    )
}

pub fn request_stop() -> Result<(), Error> {
    let machine = VM.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(machine) = machine
        .as_ref()
        .filter(|machine| machine.vcpu_state == VcpuState::Running)
    {
        machine.vm.request_stop().map_err(|_| Error::Platform)?;
    }
    Ok(())
}

pub fn mark_stopped() {
    if let Some(machine) = VM
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
        .filter(|machine| machine.vcpu_state == VcpuState::Running)
    {
        machine.vcpu_state = VcpuState::Stopped;
    }
}

pub fn release() -> Result<(), Error> {
    let mut machine = VM.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if machine
        .as_ref()
        .is_some_and(|machine| machine.vcpu_state == VcpuState::Running)
    {
        return Err(Error::InvalidState);
    }
    if let Some(Machine { vm, vcpus, .. }) = machine.take() {
        drop(vcpus);
        drop(vm);
    }
    Ok(())
}

pub async fn run_vcpus() -> Result<(), Error> {
    let vcpus = {
        let mut machine = VM.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        machine
            .as_mut()
            .and_then(|machine| machine.vcpus.take())
            .ok_or(Error::InvalidState)?
    };
    futures_util::future::try_join_all(
        vcpus
            .into_iter()
            .zip(0_u8..)
            .map(|(cpu, id)| super::run_vcpu(cpu, id)),
    )
    .await
    .map_err(|_| Error::Platform)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::terra::mmio::machine_types::DeviceKind;
    use super::*;
    #[test]
    fn shared_irq_levels_follow_device_identity_and_only_publish_transitions() {
        let devices = [
            (DeviceKind::Block, 11),
            (DeviceKind::Block, 12),
            (DeviceKind::Block, 20),
            (DeviceKind::Block, 21),
            (DeviceKind::Block, 22),
            (DeviceKind::Block, 20),
            (DeviceKind::Fs, 17),
            (DeviceKind::Fs, 18),
            (DeviceKind::Fs, 19),
            (DeviceKind::Fs, 17),
        ]
        .into_iter()
        .map(|(kind, irq)| Device {
            kind,
            irq,
            mmio_base: 0,
        })
        .collect::<Vec<_>>();
        let mut levels = vec![false; devices.len()];
        let mut update = |slot, level| {
            update_irq_level(&devices, &mut levels, slot, level)
                .unwrap()
                .map(|change| (change.gsi, change.asserted))
        };
        assert_eq!(update(2, true), Some((20, true)));
        assert_eq!(update(5, true), None);
        assert_eq!(update(2, false), None);
        assert_eq!(update(6, true), Some((17, true)));
        assert_eq!(update(9, true), None);
        assert_eq!(update(6, false), None);
        assert_eq!(update(5, false), Some((20, false)));
        assert_eq!(update(5, false), None);
        assert_eq!(update(9, false), Some((17, false)));
        let previous = levels.clone();
        assert!(update_irq_level(&devices, &mut levels, devices.len(), true).is_err());
        assert_eq!(levels, previous);
        assert!(update_irq_level(&devices, &mut [], 0, true).is_err());
    }
}
