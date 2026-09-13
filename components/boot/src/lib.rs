//! Prepares guest boot memory through fixed host capabilities.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({ world: "boot-component", path: "wit" });
}
use bindings::{exports, terra};

mod boot;

use exports::terra::boot::boot::{BootEntry, Error};
use terra::boot::{host, types};

const MAX_TRANSFER_BYTES: u64 = terra_limits::MAX_SINGLE_GUEST_COPY_BYTES;

fn error(error: boot::Error) -> Error {
    match error {
        boot::Error::InvalidRam => Error::InvalidRam,
        boot::Error::InvalidVcpus => Error::InvalidVcpus,
        boot::Error::InvalidDevice => Error::InvalidDevice,
        boot::Error::CommandLineTooLong => Error::CommandLineTooLong,
        boot::Error::InvalidKernel => Error::InvalidKernel,
        boot::Error::KernelArchitecture => Error::KernelArchitecture,
        boot::Error::KernelLayout => Error::KernelLayout,
        boot::Error::KernelTooLarge => Error::KernelTooLarge,
        boot::Error::BootDataTooLarge => Error::BootDataTooLarge,
    }
}

fn copy_kernel(plan: &boot::Plan) -> Result<(), Error> {
    for segment in &plan.kernel_segments {
        let mut offset = 0;
        while offset < segment.file_length {
            let length = (segment.file_length - offset).min(MAX_TRANSFER_BYTES);
            host::copy_kernel(
                segment
                    .source_offset
                    .checked_add(offset)
                    .ok_or(Error::Bounds)?,
                segment
                    .guest_address
                    .checked_add(offset)
                    .ok_or(Error::Bounds)?,
                u32::try_from(length).map_err(|_| Error::Bounds)?,
            )?;
            offset = offset.checked_add(length).ok_or(Error::Bounds)?;
        }
    }
    Ok(())
}

fn write_ram(plan: &boot::Plan) -> Result<(), Error> {
    for write in &plan.writes {
        for (offset, bytes) in write
            .bytes
            .chunks(usize::try_from(MAX_TRANSFER_BYTES).map_err(|_| Error::Bounds)?)
            .enumerate()
        {
            let offset = u64::try_from(offset)
                .ok()
                .and_then(|offset| offset.checked_mul(MAX_TRANSFER_BYTES))
                .ok_or(Error::Bounds)?;
            host::write_ram(
                write.address.checked_add(offset).ok_or(Error::Bounds)?,
                bytes,
            )?;
        }
    }
    Ok(())
}

struct Component;

impl exports::terra::boot::boot::Guest for Component {
    fn stage(kernel_command_line: String) -> Result<BootEntry, Error> {
        let machine = host::machine_config();
        let prefix = host::kernel_prefix()?;
        let devices = machine
            .devices
            .into_iter()
            .map(|device| boot::Device {
                kind: match device.kind {
                    types::DeviceKind::Block => boot::DeviceKind::Block,
                    types::DeviceKind::Net => boot::DeviceKind::Net,
                    types::DeviceKind::Vsock => boot::DeviceKind::Vsock,
                    types::DeviceKind::Fs => boot::DeviceKind::Fs,
                    types::DeviceKind::Memory => boot::DeviceKind::Memory,
                },
                mmio_base: device.mmio_base,
                irq: device.irq,
            })
            .collect::<Vec<_>>();
        let plan = match machine.architecture {
            types::Architecture::X86 => boot::plan_x86(
                &prefix,
                host::kernel_size(),
                machine.ram_bytes,
                machine.vcpus,
                &kernel_command_line,
                &devices,
            ),
            types::Architecture::Arm => boot::plan_arm(
                &prefix,
                host::kernel_size(),
                machine.ram_bytes,
                machine.vcpus,
                &kernel_command_line,
                &devices,
            ),
        }
        .map_err(error)?;
        boot::validate_copy_budget(&plan, host::kernel_size()).map_err(error)?;
        copy_kernel(&plan)?;
        write_ram(&plan)?;
        Ok(BootEntry {
            entry: plan.entry,
            boot_argument: plan.boot_argument,
        })
    }
}

#[allow(unsafe_code)]
mod component_exports {
    use super::{Component, bindings};
    bindings::export!(Component with_types_in bindings);
}
