use crate::machine::MAX_VCPUS;
use crate::windows::worker::VcpuGroup;
use crate::worker::{self, PreparedVmm, WorkerInput};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use terra_runtime::component::vmm::interrupts::{IoApicHandle, X86Interrupt};
use terra_runtime::component::vmm::{
    Completion, Exit, NativeVcpu, PreparedMachine, StartedVcpus, platform,
};
use terra_runtime::memory::WindowsRam;

fn launch_vcpus(
    partition: Arc<crate::windows::whp::Partition>,
    controls: Vec<NativeVcpu>,
    boot: terra_runtime::component::vmm::BootEntry,
    ioapic: &IoApicHandle,
    hard_stop: Option<fn() -> !>,
) -> Result<StartedVcpus, String> {
    crate::windows::amd64::configure_planned_boot(&partition, boot.entry, boot.boot_argument)
        .map_err(|error| format!("configuring boot: {error:?}"))?;
    log::info!(
        "Windows x64 boot: entry={:#x}, boot argument={:#x}",
        boot.entry,
        boot.boot_argument
    );
    let mut group = VcpuGroup::new(partition, hard_stop);
    for (id, control) in (0_u32..).zip(controls) {
        let partition = Arc::clone(&group.partition);
        let stop = Arc::clone(&group.stop);
        let ioapic = ioapic.clone();
        group.spawn(move || run_x64_vcpu(&partition, id, &ioapic, &control, &stop))?;
    }
    Ok(group.into_started())
}

#[allow(clippy::too_many_lines)]
pub async fn prepare(mut input: WorkerInput) -> Result<PreparedVmm, String> {
    if input.vcpus == 0 || input.vcpus > MAX_VCPUS {
        return Err("invalid Windows x64 VM dimensions".to_owned());
    }
    let component_runtime =
        crate::worker::create_runtime(&input).map_err(|error| error.to_string())?;
    let disks = crate::worker::devices::disk_paths(&input);
    let block_count = 1 + disks.len();
    let share_count = input.shares.len();
    let layout = crate::machine::build_machine_layout(input.ram_bytes, block_count, share_count)
        .map_err(|error| format!("invalid WHP layout: {error:?}"))?;
    let config = layout
        .machine_config(input.vcpus)
        .map_err(|error| error.to_string())?;
    let vcpus = u32::from(config.vcpus());
    let ram = WindowsRam::allocate(config.ram_bytes()).ok_or("allocating WHP guest RAM")?;
    let partition = crate::windows::whp::Partition::new(ram, u32::from(config.vcpus()))
        .map_err(|error| format!("creating WHP VM: {error}"))?;
    for id in 0..u32::from(config.vcpus()) {
        partition
            .create_vcpu(id)
            .map_err(|error| error.to_string())?;
    }
    let prepared = PreparedMachine::new(config, partition);
    let (mut component_runtime, partition) =
        crate::worker::boot_prepared(component_runtime, prepared, &mut input)
            .await
            .map_err(|error| error.to_string())?;
    let ram_alias = partition.ram();
    let ioapic = component_runtime
        .grant_ioapic(Arc::new({
            let interrupt_partition = partition.clone();
            move |interrupt: X86Interrupt| {
                if interrupt.vector < 32
                    || (u32::from(interrupt.destination) >= vcpus
                        && interrupt.destination != u8::MAX)
                {
                    return Err(wasmtime::Error::msg("invalid IOAPIC interrupt"));
                }
                let partition = interrupt_partition.machine();
                partition
                    .request_x64_interrupt(
                        interrupt.vector,
                        interrupt.destination,
                        interrupt.level_triggered,
                    )
                    .map_err(|error| wasmtime::Error::msg(error.to_string()))
            }
        }))
        .await
        .map_err(|error| error.to_string())?;
    worker::devices::assemble_devices(
        &mut component_runtime,
        &mut input,
        ram_alias.clone(),
        &disks,
        |kind, index| {
            ioapic
                .bind_interrupt(kind, index)
                .map_err(|error| error.to_string())
        },
    )?;
    let interrupt_handle = ioapic.clone();
    component_runtime
        .grant_interrupt_shutdown(async move {
            interrupt_handle
                .close()
                .await
                .map_err(|error| error.to_string())
        })
        .map_err(|error| error.to_string())?;
    let launch_ioapic = ioapic.clone();
    let hard_stop = input.hard_stop;
    crate::worker::finish_preparation(component_runtime, input.deadline, move |controls, boot| {
        launch_vcpus(
            partition.machine(),
            controls,
            boot,
            &launch_ioapic,
            hard_stop,
        )
        .map_err(wasmtime::Error::msg)
    })
    .await
    .map_err(|error| error.to_string())
}

fn run_x64_vcpu(
    partition: &Arc<crate::windows::whp::Partition>,
    vcpu: u32,
    ioapic: &IoApicHandle,
    worker: &NativeVcpu,
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
                let mut access =
                    |address: u64,
                     write: bool,
                     data: &mut [u8]|
                     -> Result<(), crate::windows::whp::PartitionError> {
                        access_x64_memory(partition, worker, ioapic, address, write, data)
                    };
                let mut io = |port,
                              write,
                              length,
                              value: &mut u32|
                 -> Result<_, crate::windows::whp::PartitionError> {
                    pio_access(worker, port, write, length, value)
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
                    pio_access(worker, port, write, length, value)
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
                ioapic.eoi(vector).map_err(|error| error.to_string())?;
            }
            crate::windows::whp::RunExit::Halt => require_reentry(worker, Exit::Halt)?,
            crate::windows::whp::RunExit::Canceled => return Ok(()),
            crate::windows::whp::RunExit::Reset { reboot } => {
                return Err(format!("unexpected x64 reset exit (reboot: {reboot})"));
            }
            crate::windows::whp::RunExit::Other(reason) => {
                return Err(format!("unexpected WHP exit {reason}"));
            }
        }
    }
    partition
        .cancel_vcpu(vcpu)
        .map_err(|error| error.to_string())
}

fn require_reentry(worker: &NativeVcpu, exit: Exit) -> Result<(), String> {
    matches!(
        worker.exchange(exit).map_err(|error| error.to_string())?,
        Completion::Reenter
    )
    .then_some(())
    .ok_or("unexpected Windows x64 VMM completion".to_owned())
}

fn access_x64_memory(
    partition: &crate::windows::whp::Partition,
    worker: &NativeVcpu,
    ioapic: &IoApicHandle,
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
        return ioapic_access(ioapic, address, write, data);
    }
    mmio_access(worker, address, write, data)
}

fn mmio_access(
    worker: &NativeVcpu,
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
            worker,
            Exit::MmioWrite(platform::MmioWrite {
                address,
                width,
                value: u64::from_le_bytes(value),
            }),
        )
        .map_err(|_| crate::windows::whp::PartitionError::Transport);
    }
    let completion = worker
        .exchange(Exit::MmioRead(platform::MmioRead { address, width }))
        .map_err(|_| crate::windows::whp::PartitionError::Transport)?;
    let Completion::MmioRead(value) = completion else {
        return Err(crate::windows::whp::PartitionError::Transport);
    };
    data.copy_from_slice(&value.to_le_bytes()[..usize::from(width)]);
    Ok(())
}

fn pio_access(
    worker: &NativeVcpu,
    port: u16,
    write: bool,
    length: u8,
    value: &mut u32,
) -> Result<(), crate::windows::whp::PartitionError> {
    if write {
        return require_reentry(
            worker,
            Exit::PioWrite(platform::PioWrite {
                port,
                length: u32::from(length),
            }),
        )
        .map_err(|_| crate::windows::whp::PartitionError::Transport);
    }
    let completion = worker
        .exchange(Exit::PioRead(platform::PioRead {
            port,
            length: u32::from(length),
        }))
        .map_err(|_| crate::windows::whp::PartitionError::Transport)?;
    if !matches!(completion, Completion::PioZero) {
        return Err(crate::windows::whp::PartitionError::Transport);
    }
    *value = 0;
    Ok(())
}

fn ioapic_access(
    ioapic: &IoApicHandle,
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
    let value = ioapic
        .access(offset, width, write, value)
        .map_err(|_| crate::windows::whp::PartitionError::Transport)?;
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
