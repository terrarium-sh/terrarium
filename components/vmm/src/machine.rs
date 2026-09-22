use super::exports::terra::mmio::machine::Guest;
use super::terra::mmio::machine_types::Error;
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
    vcpu_state: VcpuState,
    vcpus: Option<Vec<super::terra::mmio::platform::Vcpu>>,
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
        let (max_devices, max_vcpus) = match config.architecture {
            Architecture::X86 => (terra_limits::X86_MAX_DEVICES, terra_limits::X86_MAX_VCPUS),
            Architecture::Arm => (terra_limits::ARM_MAX_DEVICES, terra_limits::ARM_MAX_VCPUS),
        };
        if config.devices.len() > max_devices || config.vcpus == 0 || config.vcpus > max_vcpus {
            return Err(Error::InvalidVcpus);
        }
        super::configure_vcpus(config.vcpus).map_err(|_| Error::Platform)?;
        *machine = Some(Machine {
            vm: Arc::new(vm),
            vcpu_state: VcpuState::Prepared,
            vcpus: Some(vcpus),
        });
        Ok(())
    }

    fn compose() -> Result<(), Error> {
        let mut machine = VM.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let machine = machine.as_mut().ok_or(Error::InvalidState)?;
        if machine.vcpu_state != VcpuState::Prepared {
            return Err(Error::InvalidState);
        }
        machine.vcpu_state = VcpuState::Running;
        Ok(())
    }
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
    let vcpus = VM
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
        .and_then(|machine| machine.vcpus.take())
        .ok_or(Error::InvalidState)?;
    futures_util::future::try_join_all(
        vcpus
            .into_iter()
            .zip(0_u8..)
            .map(|(cpu, id)| super::run_vcpu(cpu, id)),
    )
    .await
    .map(|_| ())
    .map_err(|_| Error::Platform)
}
