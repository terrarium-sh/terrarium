use crate::memory::GuestMemory;
use crate::vm::{
    BootState, InterruptControllerConfig, InterruptMode, IoApicAccess, VcpuAction, VcpuExit,
    VcpuHandler, VcpuOutcome, VmCapabilities, VmConfig, VmHandle,
};
use crate::windows::worker::VcpuGroup;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use terra_limits::X86_MAX_VCPUS;

pub struct WindowsVm {
    partition: Arc<crate::windows::whp::Partition>,
    hard_stop: Option<fn() -> !>,
}

impl WindowsVm {
    pub fn create(config: &VmConfig, hard_stop: Option<fn() -> !>) -> Result<Self, String> {
        if config.interrupt_controller != InterruptControllerConfig::X86
            || config.vcpus == 0
            || usize::from(config.vcpus) > X86_MAX_VCPUS as usize
        {
            return Err("invalid Windows x64 VM dimensions".to_owned());
        }
        let memory = if config.ram_base == terra_limits::X86_RAM_BASE {
            GuestMemory::allocate_x86_ram(config.ram_bytes)
        } else {
            GuestMemory::allocate_at(config.ram_base, config.ram_bytes)
        }
        .ok_or("allocating WHP guest RAM")?;
        let partition = Arc::new(
            crate::windows::whp::Partition::new(memory, u32::from(config.vcpus), None)
                .map_err(|error| format!("creating WHP VM: {error}"))?,
        );
        for id in 0..u32::from(config.vcpus) {
            partition
                .create_vcpu(id)
                .map_err(|error| error.to_string())?;
        }
        Ok(Self {
            partition,
            hard_stop,
        })
    }

    pub fn capabilities() -> Result<VmCapabilities, String> {
        Ok(VmCapabilities {
            interrupt_mode: InterruptMode::SoftwareIoapic,
            tsc_frequency: Some(
                crate::windows::whp::amd64::query_tsc_frequency()
                    .map_err(|error| error.to_string())?,
            ),
        })
    }

    #[must_use]
    pub fn handle(&self) -> VmHandle {
        VmHandle::new(Arc::clone(&self.partition))
    }

    pub fn start(
        self,
        boot: BootState,
        handlers: Vec<Box<dyn VcpuHandler>>,
    ) -> Result<VcpuGroup, String> {
        if handlers.len() != usize::try_from(self.partition.vcpu_count()).unwrap_or(usize::MAX) {
            return Err("vCPU handler count changed during startup".to_owned());
        }
        let partition = self.partition;
        crate::windows::amd64::configure_planned_boot(&partition, boot.entry, boot.boot_argument)
            .map_err(|error| format!("configuring boot: {error:?}"))?;
        log::info!(
            "Windows x64 boot: entry={:#x}, boot argument={:#x}",
            boot.entry,
            boot.boot_argument
        );
        let mut group = VcpuGroup::new(partition, self.hard_stop);
        for (id, handler) in (0_u32..).zip(handlers) {
            let partition = Arc::clone(&group.partition);
            let stop = Arc::clone(&group.stop);
            group.spawn(move || run_x64_vcpu(&partition, id, handler, &stop))?;
        }
        Ok(group)
    }
}

fn run_x64_vcpu(
    partition: &Arc<crate::windows::whp::Partition>,
    vcpu: u32,
    mut handler: Box<dyn VcpuHandler>,
    stop: &Arc<AtomicBool>,
) -> Result<(), String> {
    let emulator =
        crate::windows::whp::amd64::emulator::Emulator::new().map_err(|error| error.to_string())?;
    while !stop.load(Ordering::Relaxed) {
        let raw = partition
            .run_vcpu_context(vcpu)
            .map_err(|error| error.to_string())?;
        match crate::windows::whp::RunExit::from(raw) {
            crate::windows::whp::RunExit::MemoryAccess { .. } => {
                let handler = std::cell::RefCell::new(handler.as_mut());
                let mut access =
                    |address: u64,
                     write: bool,
                     data: &mut [u8]|
                     -> Result<(), crate::windows::whp::PartitionError> {
                        access_x64_memory(
                            partition,
                            &mut **handler.borrow_mut(),
                            address,
                            write,
                            data,
                        )
                    };
                let mut io = |port,
                              write,
                              length,
                              value: &mut u32|
                 -> Result<_, crate::windows::whp::PartitionError> {
                    pio_access(&mut **handler.borrow_mut(), port, write, length, value)
                };
                let mut context = crate::windows::whp::amd64::emulator::EmulationContext::new(
                    partition,
                    vcpu,
                    &mut access,
                    &mut io,
                );
                emulator
                    .emulate_mmio(&mut context, &raw)
                    .map_err(|error| error.to_string())?;
            }
            crate::windows::whp::RunExit::IoPortAccess => {
                let mut memory = |address, write, data: &mut [u8]| {
                    if partition.contains_guest_memory(address, data.len()) {
                        partition.access_guest_memory(address, write, data)
                    } else {
                        if !write {
                            data.fill(0);
                        }
                        Ok(())
                    }
                };
                let mut io = |port,
                              write,
                              length,
                              value: &mut u32|
                 -> Result<_, crate::windows::whp::PartitionError> {
                    pio_access(handler.as_mut(), port, write, length, value)
                };
                let mut context = crate::windows::whp::amd64::emulator::EmulationContext::new(
                    partition,
                    vcpu,
                    &mut memory,
                    &mut io,
                );
                emulator
                    .emulate_io(&mut context, &raw)
                    .map_err(|error| error.to_string())?;
            }
            crate::windows::whp::RunExit::ApicEoi(vector) => {
                require_reentry(handler.as_mut(), VcpuExit::IoApicEoi(vector))?;
            }
            crate::windows::whp::RunExit::Halt => {
                require_reentry(handler.as_mut(), VcpuExit::Halt)?;
            }
            crate::windows::whp::RunExit::Canceled => {
                handler.finished(VcpuOutcome::Stopped);
                return Ok(());
            }
            crate::windows::whp::RunExit::Other(reason) => {
                return Err(format!("unexpected WHP exit {reason}"));
            }
        }
    }
    handler.finished(VcpuOutcome::Stopped);
    partition
        .cancel_vcpu(vcpu)
        .map_err(|error| error.to_string())
}

fn require_reentry(handler: &mut dyn VcpuHandler, exit: VcpuExit) -> Result<(), String> {
    matches!(handler.exchange(exit)?, VcpuAction::Reenter)
        .then_some(())
        .ok_or("unexpected Windows x64 VMM completion".to_owned())
}

fn access_x64_memory(
    partition: &crate::windows::whp::Partition,
    handler: &mut dyn VcpuHandler,
    address: u64,
    write: bool,
    data: &mut [u8],
) -> Result<(), crate::windows::whp::PartitionError> {
    if partition.contains_guest_memory(address, data.len()) {
        return partition.access_guest_memory(address, write, data);
    }
    if (crate::windows::amd64::IOAPIC_BASE
        ..crate::windows::amd64::IOAPIC_BASE + crate::windows::amd64::IOAPIC_SIZE)
        .contains(&address)
    {
        return ioapic_access(handler, address, write, data);
    }
    mmio_access(handler, address, write, data)
}

fn mmio_access(
    handler: &mut dyn VcpuHandler,
    address: u64,
    write: bool,
    data: &mut [u8],
) -> Result<(), crate::windows::whp::PartitionError> {
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
        .map_err(|_| crate::windows::whp::PartitionError::Transport);
    }
    let action = handler
        .exchange(VcpuExit::MmioRead(crate::vm::MmioRead { address, width }))
        .map_err(|_| crate::windows::whp::PartitionError::Transport)?;
    let VcpuAction::MmioRead(value) = action else {
        return Err(crate::windows::whp::PartitionError::Transport);
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
) -> Result<(), crate::windows::whp::PartitionError> {
    if write {
        return require_reentry(
            handler,
            VcpuExit::PioWrite(crate::vm::PioWrite {
                port,
                length: u32::from(length),
            }),
        )
        .map_err(|_| crate::windows::whp::PartitionError::Transport);
    }
    let action = handler
        .exchange(VcpuExit::PioRead(crate::vm::PioRead {
            port,
            length: u32::from(length),
        }))
        .map_err(|_| crate::windows::whp::PartitionError::Transport)?;
    if !matches!(action, VcpuAction::PioZero) {
        return Err(crate::windows::whp::PartitionError::Transport);
    }
    *value = 0;
    Ok(())
}

fn ioapic_access(
    handler: &mut dyn VcpuHandler,
    address: u64,
    write: bool,
    data: &mut [u8],
) -> Result<(), crate::windows::whp::PartitionError> {
    let Some(offset) = address
        .checked_sub(crate::windows::amd64::IOAPIC_BASE)
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
        .map_err(|_| crate::windows::whp::PartitionError::Transport)?;
    let VcpuAction::IoApicValue(value) = action else {
        return Err(crate::windows::whp::PartitionError::Transport);
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
