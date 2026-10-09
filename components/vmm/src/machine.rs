use super::exports::terra::vmm::machine::Guest;
use super::terra::vmm::machine_types::Error;
use super::terra::vmm::virtualization::{Architecture, Vm};
use std::sync::{Mutex, MutexGuard};

struct Machine {
    vm: Vm,
    is_running: bool,
    vcpus: Option<Vec<super::terra::vmm::platform::Vcpu>>,
    powered_cpus: Vec<bool>,
}

static VM: Mutex<Option<Machine>> = Mutex::new(None);

fn lock_machine() -> MutexGuard<'static, Option<Machine>> {
    VM.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Guest for super::Dispatcher {
    fn initialize(
        architecture: Architecture,
        vm: Vm,
        vcpus: Vec<super::terra::vmm::platform::Vcpu>,
    ) -> Result<(), Error> {
        let mut machine = lock_machine();
        if machine.is_some() {
            return Err(Error::AlreadyCreated);
        }
        let max_vcpus = match architecture {
            Architecture::X86 => terra_limits::X86_MAX_VCPUS,
            Architecture::Arm => terra_limits::ARM_MAX_VCPUS,
        };
        if vcpus.is_empty() || vcpus.len() > usize::from(max_vcpus) {
            return Err(Error::InvalidVcpus);
        }
        let mut powered_cpus = vec![false; vcpus.len()];
        powered_cpus[0] = true;
        *machine = Some(Machine {
            vm,
            is_running: false,
            vcpus: Some(vcpus),
            powered_cpus,
        });
        Ok(())
    }
}

pub(super) fn with_powered_cpus<T>(
    apply: impl FnOnce(&mut [bool]) -> T,
) -> Result<T, super::Error> {
    let mut machine = lock_machine();
    let machine = machine.as_mut().ok_or(super::Error::InvalidVcpu)?;
    Ok(apply(&mut machine.powered_cpus))
}

pub fn request_stop() -> Result<(), Error> {
    let machine = lock_machine();
    if let Some(machine) = machine.as_ref().filter(|machine| machine.is_running) {
        machine.vm.request_stop().map_err(|_| Error::Platform)?;
    }
    Ok(())
}

pub fn mark_stopped() {
    if let Some(machine) = lock_machine().as_mut() {
        machine.is_running = false;
    }
}

pub fn release() -> Result<(), Error> {
    let mut machine = lock_machine();
    if machine.as_ref().is_some_and(|machine| machine.is_running) {
        return Err(Error::InvalidState);
    }
    if let Some(Machine { vm, vcpus, .. }) = machine.take() {
        drop(vcpus);
        drop(vm);
    }
    Ok(())
}

pub async fn run_vcpus() -> Result<(), super::Error> {
    let vcpus = {
        let mut machine = lock_machine();
        let machine = machine.as_mut().ok_or(super::Error::InvalidVcpu)?;
        let vcpus = machine.vcpus.take().ok_or(super::Error::InvalidVcpu)?;
        machine.is_running = true;
        vcpus
    };
    futures_util::future::try_join_all(
        vcpus
            .into_iter()
            .zip(0_u8..)
            .map(|(cpu, id)| super::run_vcpu(cpu, id)),
    )
    .await
    .map(|_| ())
}
