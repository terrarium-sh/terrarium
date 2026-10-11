//! WHP `x86_64` VM preparation, vCPU run loops, and the software IOAPIC window.

mod boot;
mod emulator;
mod machine;

use super::{Machine, MachineError, RunExit};
use crate::memory::GuestMemory;
use crate::vcpus::{Stop, Vcpus};
use crate::vm::{
    BootState, InterruptControllerConfig, InterruptMode, IoApicAccess, VcpuAction, VcpuExit,
    VcpuHandler, VcpuOutcome, VmCapabilities, VmConfig, VmHandle, report_vcpu_failure,
};
use machine::query_tsc_frequency;
use std::sync::Arc;
use terra_limits::X86_MAX_VCPUS;

const IOAPIC_BASE: u64 = 0xFEC0_0000;
const IOAPIC_SIZE: u64 = 0x20;

pub struct Vm {
    machine: Arc<Machine>,
    vcpus: Vcpus,
}

impl Vm {
    pub fn create(config: &VmConfig, hard_stop: Option<fn() -> !>) -> Result<Self, String> {
        if config.interrupt_controller != InterruptControllerConfig::X86
            || config.vcpus == 0
            || usize::from(config.vcpus) > X86_MAX_VCPUS as usize
        {
            return Err("invalid Windows x64 VM dimensions".to_owned());
        }
        if config.ram_base != terra_limits::X86_RAM_BASE {
            return Err("invalid Windows x64 RAM base".to_owned());
        }
        let memory = terra_limits::x86_ram_layout(config.ram_bytes)
            .and_then(GuestMemory::from_layout)
            .ok_or("allocating WHP guest RAM")?;
        let machine = Arc::new(
            Machine::new(memory, u32::from(config.vcpus), None)
                .map_err(|error| format!("creating WHP VM: {error}"))?,
        );
        let mut vcpus = Vcpus::new(usize::from(config.vcpus), machine.clone(), hard_stop);
        for id in 0..config.vcpus {
            machine
                .create_vcpu(u32::from(id))
                .map_err(|error| error.to_string())?;
            let machine = Arc::clone(&machine);
            let stop = vcpus.stop();
            vcpus.spawn(move |startup| {
                let Some((mut handler, _)) = startup.wait() else {
                    return Ok(());
                };
                let outcome = run_vcpu(&machine, u32::from(id), handler.as_mut(), &stop);
                report_vcpu_failure(id, handler.as_mut(), outcome)
            })?;
        }
        Ok(Self { machine, vcpus })
    }

    pub fn capabilities() -> Result<VmCapabilities, String> {
        Ok(VmCapabilities {
            interrupt_mode: InterruptMode::SoftwareIoapic,
            tsc_frequency: Some(query_tsc_frequency().map_err(|error| error.to_string())?),
        })
    }

    #[must_use]
    pub fn handle(&self) -> VmHandle {
        VmHandle::new(Arc::clone(&self.machine))
    }

    pub fn start(
        mut self,
        boot: BootState,
        handlers: Vec<Box<dyn VcpuHandler>>,
    ) -> Result<Vcpus, String> {
        boot::configure_planned_boot(&self.machine, boot.entry, boot.boot_argument)
            .map_err(|error| format!("configuring boot: {error:?}"))?;
        log::info!(
            "Windows x64 boot: entry={:#x}, boot argument={:#x}",
            boot.entry,
            boot.boot_argument
        );
        self.vcpus.start(boot, handlers)?;
        Ok(self.vcpus)
    }
}

fn run_vcpu(
    machine: &Machine,
    vcpu: u32,
    handler: &mut dyn VcpuHandler,
    stop: &Stop,
) -> Result<(), String> {
    let emulator = emulator::Emulator::new().map_err(|error| error.to_string())?;
    while !stop.is_requested() {
        let raw = machine
            .run_vcpu_context(vcpu)
            .map_err(|error| error.to_string())?;
        match RunExit::from(raw) {
            RunExit::MemoryAccess { .. } => {
                let handler = std::cell::RefCell::new(&mut *handler);
                let mut access =
                    |address: u64, write: bool, data: &mut [u8]| -> Result<(), MachineError> {
                        access_memory(machine, &mut **handler.borrow_mut(), address, write, data)
                    };
                let mut io = |port, write, length, value: &mut u32| -> Result<_, MachineError> {
                    pio_access(&mut **handler.borrow_mut(), port, write, length, value)
                };
                let mut context =
                    emulator::EmulationContext::new(machine, vcpu, &mut access, &mut io);
                emulator
                    .emulate_mmio(&mut context, &raw)
                    .map_err(|error| error.to_string())?;
            }
            RunExit::IoPortAccess => {
                let mut memory = |address, write, data: &mut [u8]| {
                    if machine.contains_guest_memory(address, data.len()) {
                        machine.access_guest_memory(address, write, data)
                    } else {
                        if !write {
                            data.fill(0);
                        }
                        Ok(())
                    }
                };
                let mut io = |port, write, length, value: &mut u32| -> Result<_, MachineError> {
                    pio_access(handler, port, write, length, value)
                };
                let mut context =
                    emulator::EmulationContext::new(machine, vcpu, &mut memory, &mut io);
                emulator
                    .emulate_io(&mut context, &raw)
                    .map_err(|error| error.to_string())?;
            }
            RunExit::ApicEoi(vector) => {
                require_reentry(handler, VcpuExit::IoApicEoi(vector))?;
            }
            RunExit::Halt => {
                require_reentry(handler, VcpuExit::Halt)?;
            }
            RunExit::Canceled => {
                handler.finished(VcpuOutcome::Stopped);
                return Ok(());
            }
            RunExit::Other(reason) => {
                return Err(format!("unexpected WHP exit {reason}"));
            }
        }
    }
    machine
        .cancel_vcpu(vcpu)
        .map_err(|error| error.to_string())?;
    handler.finished(VcpuOutcome::Stopped);
    Ok(())
}

fn require_reentry(handler: &mut dyn VcpuHandler, exit: VcpuExit) -> Result<(), String> {
    matches!(handler.exchange(exit)?, VcpuAction::Reenter)
        .ok_or("unexpected Windows x64 VMM completion".to_owned())
}

fn access_memory(
    machine: &Machine,
    handler: &mut dyn VcpuHandler,
    address: u64,
    write: bool,
    data: &mut [u8],
) -> Result<(), MachineError> {
    if machine.contains_guest_memory(address, data.len()) {
        return machine.access_guest_memory(address, write, data);
    }
    if (IOAPIC_BASE..IOAPIC_BASE + IOAPIC_SIZE).contains(&address) {
        return ioapic_access(handler, address, write, data);
    }
    mmio_access(handler, address, write, data)
}

fn mmio_access(
    handler: &mut dyn VcpuHandler,
    address: u64,
    write: bool,
    data: &mut [u8],
) -> Result<(), MachineError> {
    let Some(width) = valid_mmio_width(data.len()) else {
        if !write {
            data.fill(0);
        }
        return Ok(());
    };
    if write {
        let mut value = [0; 8];
        let Some(destination) = value.get_mut(..data.len()) else {
            return Ok(());
        };
        destination.copy_from_slice(data);
        return require_reentry(
            handler,
            VcpuExit::MmioWrite(crate::vm::MmioWrite {
                address,
                width,
                value: u64::from_le_bytes(value),
            }),
        )
        .map_err(|_| MachineError::Transport);
    }
    let action = handler
        .exchange(VcpuExit::MmioRead(crate::vm::MmioRead { address, width }))
        .map_err(|_| MachineError::Transport)?;
    let VcpuAction::MmioRead(value) = action else {
        return Err(MachineError::Transport);
    };
    data.copy_from_slice(&value.to_le_bytes()[..usize::from(width)]);
    Ok(())
}

fn pio_access(
    handler: &mut dyn VcpuHandler,
    port: u16,
    write: bool,
    length: u8,
    value: &mut u32,
) -> Result<(), MachineError> {
    if write {
        return require_reentry(
            handler,
            VcpuExit::PioWrite(crate::vm::PioWrite {
                port,
                length: u32::from(length),
            }),
        )
        .map_err(|_| MachineError::Transport);
    }
    let action = handler
        .exchange(VcpuExit::PioRead(crate::vm::PioRead {
            port,
            length: u32::from(length),
        }))
        .map_err(|_| MachineError::Transport)?;
    if !matches!(action, VcpuAction::PioZero) {
        return Err(MachineError::Transport);
    }
    *value = 0;
    Ok(())
}

fn ioapic_access(
    handler: &mut dyn VcpuHandler,
    address: u64,
    write: bool,
    data: &mut [u8],
) -> Result<(), MachineError> {
    let Some(offset) = address
        .checked_sub(IOAPIC_BASE)
        .and_then(|offset| u8::try_from(offset).ok())
    else {
        if !write {
            data.fill(0);
        }
        return Ok(());
    };
    let Some(width) = valid_mmio_width(data.len()).filter(|_| data.len() <= 4) else {
        if !write {
            data.fill(0);
        }
        return Ok(());
    };
    let value = if write {
        let mut bytes = [0; 4];
        let Some(destination) = bytes.get_mut(..data.len()) else {
            return Ok(());
        };
        destination.copy_from_slice(data);
        u32::from_le_bytes(bytes)
    } else {
        0
    };
    let action = handler
        .exchange(VcpuExit::IoApicAccess(IoApicAccess {
            offset,
            width,
            write,
            value,
        }))
        .map_err(|_| MachineError::Transport)?;
    let VcpuAction::IoApicValue(value) = action else {
        return Err(MachineError::Transport);
    };
    if !write {
        let Some(destination) = data.get_mut(..4) else {
            data.fill(0);
            return Ok(());
        };
        destination.copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

fn valid_mmio_width(length: usize) -> Option<u8> {
    match length {
        1 | 2 | 4 | 8 => u8::try_from(length).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod width_tests {
    #[test]
    fn whp_mmio_widths_match_the_native_dispatcher() {
        for width in [1, 2, 4, 8] {
            assert_eq!(super::valid_mmio_width(width), u8::try_from(width).ok());
        }
        for width in [0, 3, 5, 6, 7, 9, 16] {
            assert_eq!(super::valid_mmio_width(width), None);
        }
    }
}
