use vm_fdt::FdtWriter;

use crate::exports::terra::boot::boot::{
    Device, DeviceKind, Error, GuestWrite, KernelSegment, Plan,
};

use terra_limits::{
    ARM_GIC_DIST_BASE, ARM_GIC_DIST_SIZE, ARM_GIC_REDIST_BASE, ARM_GIC_REDIST_SIZE,
    ARM_MAX_DEVICES, ARM_RAM_BASE, ARM_VIRTIO_IRQ_BASE, ARM_VIRTIO_MMIO_BASE,
    ARM_VIRTIO_MMIO_STRIDE, MAX_BOOT_COMMAND_LINE_BYTES, MAX_BOOT_KERNEL_BYTES,
    MAX_BOOT_KERNEL_PREFIX_BYTES, MAX_BOOT_WRITE_BYTES, RAM_PAGE_SIZE, X86_GDT_ADDR,
    X86_MAX_DEVICES, X86_MAX_VCPUS, X86_MMIO_BASE, X86_MMIO_STRIDE, X86_PML4_ADDR, X86_ZERO_PAGE,
};

const X86_HIMEM_START: u64 = 0x10_0000;
const X86_CMDLINE: u64 = terra_limits::X86_RAM_BASE + 0x20_000;
const X86_MP_TABLE: u64 = 0x9fc00;
const X86_PDPT: u64 = terra_limits::X86_RAM_BASE + 0xa000;
const X86_PAGE_DIRECTORY: u64 = terra_limits::X86_RAM_BASE + 0xb000;
const X86_MMIO_SIZE: u64 = 0x200;
const X86_IRQ_BASE: u8 = 11;
const X86_VOLUME_IRQS: [u32; 3] = [20, 21, 22];
const X86_MOUNT_IRQS: [u32; 3] = [17, 18, 19];
const X86_PAGE_2M: u64 = 2 * 1024 * 1024;
const X86_ENTRIES_PER_TABLE: u64 = 512;
const X86_PAGE_TABLE_ENTRY: u64 = 0x03;
const X86_PAGE_2M_ENTRY: u64 = 0x83;
const X86_GDT_CODE: u64 = 0x00af_9b00_0000_ffff;
const X86_GDT_DATA: u64 = 0x00cf_9300_0000_ffff;
const ARM_FDT_ALIGNMENT: u64 = 0x0020_0000;

const _: () = assert!(ARM_GIC_DIST_BASE + ARM_GIC_DIST_SIZE <= ARM_GIC_REDIST_BASE);
const _: () = assert!(ARM_GIC_REDIST_BASE + ARM_GIC_REDIST_SIZE <= ARM_VIRTIO_MMIO_BASE);
const _: () =
    assert!(ARM_VIRTIO_MMIO_BASE + ARM_MAX_DEVICES as u64 * ARM_VIRTIO_MMIO_STRIDE <= ARM_RAM_BASE);
const _: () = assert!(MAX_BOOT_WRITE_BYTES as u64 <= ARM_FDT_ALIGNMENT);

fn end(base: u64, size: u64) -> Result<u64, Error> {
    base.checked_add(size).ok_or(Error::KernelLayout)
}

fn x86_ram_regions(ram_bytes: u64) -> Result<Vec<(u64, u64)>, Error> {
    terra_limits::x86_ram_layout(ram_bytes)
        .map(|layout| {
            layout
                .regions()
                .map(|region| (region.base, region.size))
                .collect()
        })
        .ok_or(Error::InvalidRam)
}

fn range_in_regions(base: u64, size: u64, regions: &[(u64, u64)]) -> Result<(), Error> {
    let end = end(base, size)?;
    regions
        .iter()
        .any(|&(region_base, region_size)| {
            region_base <= base
                && region_base
                    .checked_add(region_size)
                    .is_some_and(|region_end| end <= region_end)
        })
        .ok_or(Error::KernelLayout)
}

fn checked_source(kernel_bytes: u64, offset: u64, len: u64) -> Result<(), Error> {
    let end = end(offset, len)?;
    (end <= kernel_bytes).ok_or(Error::InvalidKernel)
}

fn validate_kernel_prefix(prefix: &[u8], kernel_bytes: u64) -> Result<(), Error> {
    if prefix.len() > MAX_BOOT_KERNEL_PREFIX_BYTES
        || kernel_bytes > MAX_BOOT_KERNEL_BYTES
        || kernel_bytes < u64::try_from(prefix.len()).map_err(|_| Error::InvalidKernel)?
    {
        return Err(Error::KernelTooLarge);
    }
    Ok(())
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn command_line(kernel_command_line: &str, devices: &[Device]) -> Result<String, Error> {
    use std::fmt::Write as _;
    let mut command_line = format!(
        "{kernel_command_line} init_on_alloc=1 init_on_free=0 initcall_blacklist=print_s5_reset_status_mmio"
    )
    .split_ascii_whitespace()
    .collect::<Vec<_>>()
    .join(" ");
    for device in devices {
        let _ = write!(
            command_line,
            " virtio_mmio.device={X86_MMIO_SIZE:#x}@{:#x}:{}",
            device.mmio_base, device.irq
        );
    }
    if command_line.len() >= MAX_BOOT_COMMAND_LINE_BYTES {
        return Err(Error::CommandLineTooLong);
    }
    Ok(command_line)
}

fn x86_irq(kind: DeviceKind, ordinal: usize) -> u32 {
    match kind {
        DeviceKind::Block => match ordinal {
            0 => u32::from(X86_IRQ_BASE),
            1 => u32::from(X86_IRQ_BASE) + 1,
            _ => X86_VOLUME_IRQS[(ordinal - 2) % X86_VOLUME_IRQS.len()],
        },
        DeviceKind::Vsock => 13,
        DeviceKind::Fs => X86_MOUNT_IRQS[ordinal % X86_MOUNT_IRQS.len()],
        DeviceKind::Memory => 15,
    }
}

fn validate_device_order(devices: &[Device], rank: fn(DeviceKind) -> u8) -> Result<(), Error> {
    let count_of = |kind| devices.iter().filter(|device| device.kind == kind).count();
    let is_ordered = devices
        .windows(2)
        .all(|pair| rank(pair[0].kind) <= rank(pair[1].kind));
    (is_ordered && count_of(DeviceKind::Vsock) == 1 && count_of(DeviceKind::Memory) == 1)
        .ok_or(Error::InvalidDevice)
}

fn x86_rank(kind: DeviceKind) -> u8 {
    match kind {
        DeviceKind::Block => 0,
        DeviceKind::Vsock => 1,
        DeviceKind::Fs => 2,
        DeviceKind::Memory => 3,
    }
}

fn validate_x86_devices(devices: &[Device]) -> Result<(), Error> {
    if devices.len() > X86_MAX_DEVICES {
        return Err(Error::InvalidDevice);
    }
    validate_device_order(devices, x86_rank)?;
    for (slot, device) in devices.iter().enumerate() {
        let ordinal = devices[..slot]
            .iter()
            .filter(|earlier| earlier.kind == device.kind)
            .count();
        let expected_base = X86_MMIO_BASE
            .checked_add(u64::try_from(slot).map_err(|_| Error::InvalidDevice)? * X86_MMIO_STRIDE)
            .ok_or(Error::InvalidDevice)?;
        if device.mmio_base != expected_base || device.irq != x86_irq(device.kind, ordinal) {
            return Err(Error::InvalidDevice);
        }
    }
    Ok(())
}

fn x86_zero_page(regions: &[(u64, u64)], command_line_len: usize) -> Result<Vec<u8>, Error> {
    let command_line_len =
        u32::try_from(command_line_len).map_err(|_| Error::CommandLineTooLong)?;
    let mut page = vec![0; usize::try_from(RAM_PAGE_SIZE).map_err(|_| Error::BootDataTooLarge)?];
    let low_end = end(regions[0].0, regions[0].1)?;
    let e820 = [
        (regions[0].0, X86_MP_TABLE - regions[0].0),
        (X86_HIMEM_START, low_end - X86_HIMEM_START),
    ]
    .into_iter()
    .chain(regions.iter().skip(1).copied())
    .collect::<Vec<_>>();
    page[0x1e8] = u8::try_from(e820.len()).map_err(|_| Error::BootDataTooLarge)?;
    page[0x1fe..0x200].copy_from_slice(&0xaa55_u16.to_le_bytes());
    page[0x202..0x206].copy_from_slice(&0x5372_6448_u32.to_le_bytes());
    page[0x210] = 0xff;
    page[0x228..0x22c].copy_from_slice(
        &u32::try_from(X86_CMDLINE)
            .map_err(|_| Error::BootDataTooLarge)?
            .to_le_bytes(),
    );
    page[0x238..0x23c].copy_from_slice(&command_line_len.to_le_bytes());
    for (index, (base, size)) in e820.into_iter().enumerate() {
        let offset = 0x2d0 + index * 20;
        page[offset..offset + 8].copy_from_slice(&base.to_le_bytes());
        page[offset + 8..offset + 16].copy_from_slice(&size.to_le_bytes());
        page[offset + 16..offset + 20].copy_from_slice(&1_u32.to_le_bytes());
    }
    Ok(page)
}

fn x86_page_tables() -> Vec<GuestWrite> {
    const PAGE: usize = 4096;
    let mut pml4 = vec![0; PAGE];
    pml4[..8].copy_from_slice(&(X86_PDPT | X86_PAGE_TABLE_ENTRY).to_le_bytes());
    let mut pdpt = vec![0; PAGE];
    let mut directories = Vec::with_capacity(4);
    for (directory, slot) in (0..4_u64).zip(pdpt.as_chunks_mut::<8>().0) {
        let address = X86_PAGE_DIRECTORY + directory * RAM_PAGE_SIZE;
        *slot = (address | X86_PAGE_TABLE_ENTRY).to_le_bytes();
        let mut entries = vec![0; PAGE];
        for (page, entry) in (0..X86_ENTRIES_PER_TABLE).zip(entries.as_chunks_mut::<8>().0) {
            let page_address = (directory * X86_ENTRIES_PER_TABLE + page) * X86_PAGE_2M;
            *entry = (page_address | X86_PAGE_2M_ENTRY).to_le_bytes();
        }
        directories.push(GuestWrite {
            address,
            bytes: entries,
        });
    }
    let mut gdt = Vec::with_capacity(16);
    gdt.extend_from_slice(&X86_GDT_CODE.to_le_bytes());
    gdt.extend_from_slice(&X86_GDT_DATA.to_le_bytes());
    let mut writes = vec![
        GuestWrite {
            address: X86_GDT_ADDR + 8,
            bytes: gdt,
        },
        GuestWrite {
            address: X86_PML4_ADDR,
            bytes: pml4,
        },
        GuestWrite {
            address: X86_PDPT,
            bytes: pdpt,
        },
    ];
    writes.extend(directories);
    writes
}

fn validate_x86_writes(writes: &[GuestWrite], low_ram: &[(u64, u64)]) -> Result<(), Error> {
    if writes.iter().any(|write| {
        u64::try_from(write.bytes.len())
            .ok()
            .and_then(|size| range_in_regions(write.address, size, low_ram).ok())
            .is_none()
    }) {
        return Err(Error::KernelLayout);
    }
    range_in_regions(
        terra_limits::X86_STACK_TOP - RAM_PAGE_SIZE,
        RAM_PAGE_SIZE,
        low_ram,
    )
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
        .wrapping_neg()
}

fn mp_table(vcpus: u8) -> Result<Vec<u8>, Error> {
    if vcpus == 0 || vcpus > X86_MAX_VCPUS {
        return Err(Error::InvalidVcpus);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"_MP_");
    bytes.extend_from_slice(
        &u32::try_from(X86_MP_TABLE + 16)
            .map_err(|_| Error::BootDataTooLarge)?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&[1, 4, 0, 0, 0, 0, 0, 0]);
    let base = bytes.len();
    bytes.extend_from_slice(b"PCMP");
    let length = bytes.len();
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(&[4, 0]);
    bytes.extend_from_slice(b"TERRA   TERRA-VM    ");
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&(u16::from(vcpus) + 28).to_le_bytes());
    bytes.extend_from_slice(&0xfee0_0000_u32.to_le_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    for cpu in 0..vcpus {
        bytes.extend_from_slice(&[0, cpu, 0x14, if cpu == 0 { 3 } else { 1 }]);
        bytes.extend_from_slice(&0x600_u32.to_le_bytes());
        bytes.extend_from_slice(&[0; 12]);
    }
    bytes.extend_from_slice(&[1, 0]);
    bytes.extend_from_slice(b"ISA   ");
    bytes.extend_from_slice(&[2, vcpus, 0x11, 1]);
    bytes.extend_from_slice(&0xfec0_0000_u32.to_le_bytes());
    for irq in 0..X86_IRQ_BASE {
        bytes.extend_from_slice(&[3, 0, 0, 0, 0, irq, 0xff, irq]);
    }
    for irq in u32::from(X86_IRQ_BASE)..24 {
        let irq = u8::try_from(irq).map_err(|_| Error::BootDataTooLarge)?;
        bytes.extend_from_slice(&[3, 0, 0x0d, 0, 0, irq, 0xff, irq]);
    }
    for (kind, irq) in [(3, 0), (1, 1)] {
        bytes.extend_from_slice(&[4, kind, 0, 0, 0, irq, 0xff, irq]);
    }
    let length_value = u16::try_from(bytes.len() - base).map_err(|_| Error::BootDataTooLarge)?;
    bytes[length..length + 2].copy_from_slice(&length_value.to_le_bytes());
    bytes[base + 7] = checksum(&bytes[base..]);
    bytes[10] = checksum(&bytes[..16]);
    Ok(bytes)
}

pub(crate) fn plan_x86(
    kernel_prefix: &[u8],
    kernel_bytes: u64,
    ram_bytes: u64,
    vcpus: u8,
    kernel_command_line: &str,
    devices: &[Device],
) -> Result<Plan, Error> {
    let ram_regions = x86_ram_regions(ram_bytes)?;
    validate_kernel_prefix(kernel_prefix, kernel_bytes)?;
    validate_x86_devices(devices)?;
    if kernel_prefix.len() < 64
        || kernel_prefix[..4] != [0x7f, b'E', b'L', b'F']
        || kernel_prefix[4] != 2
        || kernel_prefix[5] != 1
    {
        return Err(Error::InvalidKernel);
    }
    if u16_at(kernel_prefix, 18) != Some(62) {
        return Err(Error::KernelArchitecture);
    }
    let entry = u64_at(kernel_prefix, 24).ok_or(Error::InvalidKernel)?;
    let program_headers = usize::try_from(u64_at(kernel_prefix, 32).ok_or(Error::InvalidKernel)?)
        .map_err(|_| Error::InvalidKernel)?;
    let count = usize::from(u16_at(kernel_prefix, 56).ok_or(Error::InvalidKernel)?);
    let mut segments = Vec::new();
    for index in 0..count {
        let offset = program_headers
            .checked_add(index.checked_mul(56).ok_or(Error::InvalidKernel)?)
            .ok_or(Error::InvalidKernel)?;
        let header = kernel_prefix
            .get(offset..offset + 56)
            .ok_or(Error::InvalidKernel)?;
        if u32_at(header, 0) != Some(1) {
            continue;
        }
        let source_offset = u64_at(header, 8).ok_or(Error::InvalidKernel)?;
        let guest_address = u64_at(header, 24).ok_or(Error::InvalidKernel)?;
        let file_length = u64_at(header, 32).ok_or(Error::InvalidKernel)?;
        let memory_length = u64_at(header, 40).ok_or(Error::InvalidKernel)?;
        if file_length == 0 {
            continue;
        }
        if guest_address < X86_HIMEM_START || memory_length < file_length {
            return Err(Error::KernelLayout);
        }
        checked_source(kernel_bytes, source_offset, file_length)?;
        range_in_regions(guest_address, memory_length, &ram_regions[..1])?;
        segments.push(KernelSegment {
            source_offset,
            guest_address,
            file_length,
            memory_length,
        });
    }
    if !segments.iter().any(|segment| {
        end(segment.guest_address, segment.memory_length)
            .is_ok_and(|segment_end| segment.guest_address <= entry && entry < segment_end)
    }) {
        return Err(Error::KernelLayout);
    }
    for (index, segment) in segments.iter().enumerate() {
        if segments[index + 1..].iter().any(|other| {
            segment.guest_address < other.guest_address + other.memory_length
                && other.guest_address < segment.guest_address + segment.memory_length
        }) {
            return Err(Error::KernelLayout);
        }
    }
    let mut command_line = command_line(kernel_command_line, devices)?.into_bytes();
    command_line.push(0);
    let mp_table = mp_table(vcpus)?;
    let zero_page = x86_zero_page(&ram_regions, command_line.len())?;
    let mut writes = x86_page_tables();
    writes.extend([
        GuestWrite {
            address: X86_CMDLINE,
            bytes: command_line,
        },
        GuestWrite {
            address: X86_ZERO_PAGE,
            bytes: zero_page,
        },
        GuestWrite {
            address: X86_MP_TABLE,
            bytes: mp_table,
        },
    ]);
    validate_x86_writes(&writes, &ram_regions[..1])?;
    Ok(Plan {
        entry,
        boot_argument: X86_ZERO_PAGE,
        kernel_segments: segments,
        writes,
    })
}

fn arm_rank(kind: DeviceKind) -> u8 {
    match kind {
        DeviceKind::Block => 0,
        DeviceKind::Fs => 1,
        DeviceKind::Memory => 2,
        DeviceKind::Vsock => 3,
    }
}

fn validate_arm_devices(devices: &[Device]) -> Result<(), Error> {
    if devices.len() > ARM_MAX_DEVICES {
        return Err(Error::InvalidDevice);
    }
    validate_device_order(devices, arm_rank)?;
    for (slot, device) in devices.iter().enumerate() {
        let expected_base = ARM_VIRTIO_MMIO_BASE
            .checked_add(
                u64::try_from(slot).map_err(|_| Error::InvalidDevice)? * ARM_VIRTIO_MMIO_STRIDE,
            )
            .ok_or(Error::InvalidDevice)?;
        let expected_irq = ARM_VIRTIO_IRQ_BASE
            .checked_add(u32::try_from(slot).map_err(|_| Error::InvalidDevice)?)
            .ok_or(Error::InvalidDevice)?;
        if device.mmio_base != expected_base || device.irq != expected_irq {
            return Err(Error::InvalidDevice);
        }
    }
    Ok(())
}

fn arm_fdt(
    ram_bytes: u64,
    vcpus: u8,
    devices: &[Device],
    bootargs: &str,
) -> Result<Vec<u8>, vm_fdt::Error> {
    let mut fdt = FdtWriter::new()?;
    let root = fdt.begin_node("")?;
    fdt.property_string("compatible", "terra,arm64-virt")?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_u32("interrupt-parent", 1)?;
    let chosen = fdt.begin_node("chosen")?;
    fdt.property_string("bootargs", bootargs)?;
    fdt.end_node(chosen)?;
    let cpus = fdt.begin_node("cpus")?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 0)?;
    for cpu in 0..vcpus {
        let node = fdt.begin_node(&format!("cpu@{cpu:x}"))?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "arm,arm-v8")?;
        if vcpus > 1 {
            fdt.property_string("enable-method", "psci")?;
        }
        fdt.property_u64("reg", u64::from(cpu))?;
        fdt.end_node(node)?;
    }
    fdt.end_node(cpus)?;
    let memory = fdt.begin_node(&format!("memory@{ARM_RAM_BASE:x}"))?;
    fdt.property_string("device_type", "memory")?;
    fdt.property_array_u64("reg", &[ARM_RAM_BASE, ram_bytes])?;
    fdt.end_node(memory)?;
    let gic = fdt.begin_node(&format!("intc@{ARM_GIC_DIST_BASE:x}"))?;
    fdt.property_string("compatible", "arm,gic-v3")?;
    fdt.property_null("interrupt-controller")?;
    fdt.property_u32("#interrupt-cells", 3)?;
    fdt.property_array_u64(
        "reg",
        &[
            ARM_GIC_DIST_BASE,
            ARM_GIC_DIST_SIZE,
            ARM_GIC_REDIST_BASE,
            ARM_GIC_REDIST_SIZE,
        ],
    )?;
    fdt.property_phandle(1)?;
    fdt.end_node(gic)?;
    let timer = fdt.begin_node("timer")?;
    fdt.property_string("compatible", "arm,armv8-timer")?;
    fdt.property_null("always-on")?;
    fdt.property_array_u32("interrupts", &[1, 13, 4, 1, 14, 4, 1, 11, 4, 1, 10, 4])?;
    fdt.end_node(timer)?;
    let psci = fdt.begin_node("psci")?;
    fdt.property_string("compatible", "arm,psci-0.2")?;
    fdt.property_string("method", "hvc")?;
    fdt.end_node(psci)?;
    for device in devices {
        let node = fdt.begin_node(&format!("virtio_mmio@{:x}", device.mmio_base))?;
        fdt.property_string("compatible", "virtio,mmio")?;
        fdt.property_array_u64("reg", &[device.mmio_base, ARM_VIRTIO_MMIO_STRIDE])?;
        fdt.property_array_u32("interrupts", &[0, device.irq, 4])?;
        fdt.end_node(node)?;
    }
    fdt.end_node(root)?;
    fdt.finish()
}

pub(crate) fn plan_arm(
    kernel_prefix: &[u8],
    kernel_bytes: u64,
    ram_bytes: u64,
    vcpus: u8,
    kernel_command_line: &str,
    devices: &[Device],
) -> Result<Plan, Error> {
    let ram = terra_limits::arm_ram_layout(ram_bytes).ok_or(Error::InvalidRam)?;
    let ram = ram.regions().next().ok_or(Error::InvalidRam)?;
    if ram.size < ARM_FDT_ALIGNMENT {
        return Err(Error::InvalidRam);
    }
    if vcpus == 0 || vcpus > terra_limits::ARM_MAX_VCPUS {
        return Err(Error::InvalidVcpus);
    }
    validate_kernel_prefix(kernel_prefix, kernel_bytes)?;
    validate_arm_devices(devices)?;
    if kernel_prefix.len() < 64 || kernel_prefix[56..60] != *b"ARMd" {
        return Err(Error::InvalidKernel);
    }
    let text_offset = u64_at(kernel_prefix, 8).ok_or(Error::InvalidKernel)?;
    let memory_length = u64_at(kernel_prefix, 16).ok_or(Error::InvalidKernel)?;
    let file_length = kernel_bytes;
    if memory_length == 0 || memory_length < file_length {
        return Err(Error::KernelLayout);
    }
    let guest_address = ram
        .base
        .checked_add(text_offset)
        .ok_or(Error::KernelLayout)?;
    let ram_end = ram.base.checked_add(ram.size).ok_or(Error::InvalidRam)?;
    let fdt_address = ram_end
        .checked_sub(ARM_FDT_ALIGNMENT)
        .map(|address| address & !(ARM_FDT_ALIGNMENT - 1))
        .ok_or(Error::InvalidRam)?;
    if end(guest_address, memory_length)? > fdt_address {
        return Err(Error::KernelLayout);
    }
    let command_line = command_line(kernel_command_line, &[])?;
    let fdt =
        arm_fdt(ram_bytes, vcpus, devices, &command_line).map_err(|_| Error::BootDataTooLarge)?;
    if fdt.len() > MAX_BOOT_WRITE_BYTES {
        return Err(Error::BootDataTooLarge);
    }
    Ok(Plan {
        entry: guest_address,
        boot_argument: fdt_address,
        kernel_segments: vec![KernelSegment {
            source_offset: 0,
            guest_address,
            file_length,
            memory_length,
        }],
        writes: vec![GuestWrite {
            address: fdt_address,
            bytes: fdt,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    fn x86_kernel() -> Vec<u8> {
        let mut kernel = vec![0; 0x200];
        kernel[..4].copy_from_slice(b"\x7fELF");
        kernel[4] = 2;
        kernel[5] = 1;
        kernel[18..20].copy_from_slice(&62_u16.to_le_bytes());
        kernel[24..32].copy_from_slice(&0x10_0000_u64.to_le_bytes());
        kernel[32..40].copy_from_slice(&64_u64.to_le_bytes());
        kernel[56..58].copy_from_slice(&1_u16.to_le_bytes());
        kernel[64..68].copy_from_slice(&1_u32.to_le_bytes());
        kernel[72..80].copy_from_slice(&0x100_u64.to_le_bytes());
        kernel[88..96].copy_from_slice(&0x10_0000_u64.to_le_bytes());
        kernel[96..104].copy_from_slice(&16_u64.to_le_bytes());
        kernel[104..112].copy_from_slice(&32_u64.to_le_bytes());
        kernel
    }

    fn x86_devices() -> [Device; 3] {
        [
            Device {
                kind: DeviceKind::Block,
                mmio_base: X86_MMIO_BASE,
                irq: 11,
            },
            Device {
                kind: DeviceKind::Vsock,
                mmio_base: X86_MMIO_BASE + X86_MMIO_STRIDE,
                irq: 13,
            },
            Device {
                kind: DeviceKind::Memory,
                mmio_base: X86_MMIO_BASE + 2 * X86_MMIO_STRIDE,
                irq: 15,
            },
        ]
    }

    fn arm_devices() -> [Device; 3] {
        let kinds = [DeviceKind::Block, DeviceKind::Memory, DeviceKind::Vsock];
        core::array::from_fn(|slot| Device {
            kind: kinds[slot],
            mmio_base: ARM_VIRTIO_MMIO_BASE + u64::try_from(slot).unwrap() * ARM_VIRTIO_MMIO_STRIDE,
            irq: ARM_VIRTIO_IRQ_BASE + u32::try_from(slot).unwrap(),
        })
    }

    #[test]
    fn arm_devices_require_ordered_storage_memory_and_one_vsock() {
        use DeviceKind::{Block, Fs, Memory, Vsock};
        for kinds in [
            &[][..],
            &[Block][..],
            &[Block, Vsock][..],
            &[Block, Memory][..],
            &[Block, Vsock, Memory][..],
            &[Block, Memory, Memory, Vsock][..],
            &[Block, Memory, Vsock, Vsock][..],
            &[Fs, Block, Memory, Vsock][..],
        ] {
            let devices = kinds
                .iter()
                .enumerate()
                .map(|(slot, &kind)| Device {
                    kind,
                    mmio_base: ARM_VIRTIO_MMIO_BASE
                        + u64::try_from(slot).unwrap() * ARM_VIRTIO_MMIO_STRIDE,
                    irq: ARM_VIRTIO_IRQ_BASE + u32::try_from(slot).unwrap(),
                })
                .collect::<Vec<_>>();
            assert!(validate_arm_devices(&devices).is_err());
        }
        assert!(validate_arm_devices(&arm_devices()).is_ok());
    }

    #[test]
    fn x86_plan_copies_segments_by_reference_and_writes_boot_data() {
        let plan = plan_x86(
            &x86_kernel(),
            0x200,
            64 << 20,
            2,
            "root=/dev/vda",
            &x86_devices(),
        )
        .expect("x86 plan");
        assert_eq!(plan.entry, 0x10_0000);
        assert_eq!(plan.boot_argument, X86_ZERO_PAGE);
        assert_eq!(plan.kernel_segments.len(), 1);
        assert_eq!(plan.kernel_segments[0].source_offset, 0x100);
        assert!(plan.writes.len() >= 7);
        let command_line = plan
            .writes
            .iter()
            .find(|write| write.address == X86_CMDLINE)
            .expect("command line");
        assert!(command_line.bytes.ends_with(&[0]));
        assert!(
            command_line
                .bytes
                .windows(b"virtio_mmio.device=0x200@0xd0000000:11".len())
                .any(|bytes| bytes == b"virtio_mmio.device=0x200@0xd0000000:11")
        );
        assert!(
            command_line
                .bytes
                .windows(b"init_on_alloc=1 init_on_free=0".len())
                .any(|word| word == b"init_on_alloc=1 init_on_free=0")
        );
        let zero_page = plan
            .writes
            .iter()
            .find(|write| write.address == X86_ZERO_PAGE)
            .expect("zero page");
        assert_eq!(
            u32::from_le_bytes(zero_page.bytes[0x228..0x22c].try_into().unwrap()),
            u32::try_from(X86_CMDLINE).unwrap()
        );
    }

    #[test]
    fn x86_ram_above_the_device_hole_is_described_as_high_memory() {
        let ram_bytes = terra_limits::X86_RAM_LOW_END - terra_limits::X86_RAM_BASE + (2 << 20);
        let regions = x86_ram_regions(ram_bytes).expect("RAM regions");
        assert_eq!(
            regions,
            [
                (
                    terra_limits::X86_RAM_BASE,
                    terra_limits::X86_RAM_LOW_END - terra_limits::X86_RAM_BASE,
                ),
                (terra_limits::X86_HIGH_RAM_BASE, 2 << 20),
            ]
        );
        assert!(range_in_regions(terra_limits::X86_RAM_LOW_END, 4096, &regions).is_err());
        assert!(range_in_regions(terra_limits::X86_HIGH_RAM_BASE, 4096, &regions).is_ok());

        let page = x86_zero_page(&regions, 1).expect("zero page");
        assert_eq!(page[0x1e8], 3);
        let high = 0x2d0 + 2 * 20;
        assert_eq!(
            u64::from_le_bytes(page[high..high + 8].try_into().unwrap()),
            terra_limits::X86_HIGH_RAM_BASE
        );
        assert_eq!(
            u64::from_le_bytes(page[high + 8..high + 16].try_into().unwrap()),
            2 << 20
        );
    }

    #[test]
    fn x86_kernel_cannot_start_in_high_memory() {
        let mut kernel = x86_kernel();
        kernel[24..32].copy_from_slice(&terra_limits::X86_HIGH_RAM_BASE.to_le_bytes());
        kernel[88..96].copy_from_slice(&terra_limits::X86_HIGH_RAM_BASE.to_le_bytes());
        assert_matches!(
            plan_x86(
                &kernel,
                0x200,
                terra_limits::X86_RAM_LOW_END - terra_limits::X86_RAM_BASE + (2 << 20),
                1,
                "",
                &x86_devices(),
            ),
            Err(Error::KernelLayout)
        );
    }

    #[test]
    fn x86_page_tables_map_the_first_four_gib() {
        let writes = x86_page_tables();
        let pml4 = writes
            .iter()
            .find(|write| write.address == X86_PML4_ADDR)
            .expect("PML4");
        assert_eq!(
            u64::from_le_bytes(pml4.bytes[..8].try_into().unwrap()),
            X86_PDPT | X86_PAGE_TABLE_ENTRY
        );
        let pdpt = writes
            .iter()
            .find(|write| write.address == X86_PDPT)
            .expect("PDPT");
        for directory in 0..4_u64 {
            let address = X86_PAGE_DIRECTORY + directory * RAM_PAGE_SIZE;
            let offset = usize::try_from(directory * 8).unwrap();
            assert_eq!(
                u64::from_le_bytes(pdpt.bytes[offset..offset + 8].try_into().unwrap()),
                address | X86_PAGE_TABLE_ENTRY
            );
            let entries = writes
                .iter()
                .find(|write| write.address == address)
                .expect("page directory");
            assert_eq!(
                u64::from_le_bytes(entries.bytes[..8].try_into().unwrap()),
                (directory * 1024 * 1024 * 1024) | X86_PAGE_2M_ENTRY
            );
            assert_eq!(
                u64::from_le_bytes(entries.bytes[4088..].try_into().unwrap()),
                (directory * 1024 * 1024 * 1024 + 1022 * 1024 * 1024) | X86_PAGE_2M_ENTRY
            );
        }
    }

    #[test]
    fn x86_devices_match_the_native_layout() {
        let mut devices = vec![
            Device {
                kind: DeviceKind::Block,
                mmio_base: X86_MMIO_BASE,
                irq: 11,
            },
            Device {
                kind: DeviceKind::Block,
                mmio_base: X86_MMIO_BASE + X86_MMIO_STRIDE,
                irq: 12,
            },
            Device {
                kind: DeviceKind::Vsock,
                mmio_base: X86_MMIO_BASE + 2 * X86_MMIO_STRIDE,
                irq: 13,
            },
            Device {
                kind: DeviceKind::Fs,
                mmio_base: X86_MMIO_BASE + 3 * X86_MMIO_STRIDE,
                irq: 17,
            },
            Device {
                kind: DeviceKind::Memory,
                mmio_base: X86_MMIO_BASE + 4 * X86_MMIO_STRIDE,
                irq: 15,
            },
        ];
        assert!(validate_x86_devices(&devices).is_ok());
        devices[3].irq = 18;
        assert_matches!(validate_x86_devices(&devices), Err(Error::InvalidDevice));
        devices[3].irq = 17;
        devices[3].mmio_base += X86_MMIO_STRIDE;
        assert_matches!(validate_x86_devices(&devices), Err(Error::InvalidDevice));
    }

    #[test]
    fn x86_devices_require_ordered_storage_one_vsock_and_one_memory() {
        use DeviceKind::{Block, Fs, Memory, Vsock};
        let build = |kinds: &[DeviceKind]| {
            let mut counts = [0; 4];
            kinds
                .iter()
                .enumerate()
                .map(|(slot, &kind)| {
                    let ordinal = &mut counts[usize::from(x86_rank(kind))];
                    let irq = x86_irq(kind, *ordinal);
                    *ordinal += 1;
                    Device {
                        kind,
                        mmio_base: X86_MMIO_BASE + u64::try_from(slot).unwrap() * X86_MMIO_STRIDE,
                        irq,
                    }
                })
                .collect::<Vec<_>>()
        };
        for kinds in [
            &[][..],
            &[Block][..],
            &[Block, Vsock][..],
            &[Block, Memory][..],
            &[Memory, Vsock][..],
            &[Block, Memory, Vsock][..],
            &[Block, Vsock, Vsock, Memory][..],
            &[Block, Vsock, Memory, Memory][..],
            &[Block, Vsock, Memory, Fs][..],
            &[Vsock, Block, Memory][..],
        ] {
            assert!(validate_x86_devices(&build(kinds)).is_err(), "{kinds:?}");
        }
        assert!(validate_x86_devices(&build(&[Block, Vsock, Fs, Fs, Memory])).is_ok());
    }

    #[test]
    fn x86_irq_assignment_preserves_native_cycles() {
        assert_eq!(x86_irq(DeviceKind::Block, 2), 20);
        assert_eq!(x86_irq(DeviceKind::Block, 5), 20);
        assert_eq!(x86_irq(DeviceKind::Fs, 0), 17);
        assert_eq!(x86_irq(DeviceKind::Fs, 3), 17);
    }

    #[test]
    fn vsock_requires_the_contiguous_fixed_device_slot() {
        let mut x86 = x86_devices();
        assert!(validate_x86_devices(&x86).is_ok());
        x86[1].mmio_base += X86_MMIO_STRIDE;
        assert!(validate_x86_devices(&x86).is_err());
        let mut arm = arm_devices();
        assert!(validate_arm_devices(&arm).is_ok());
        arm[2].irq += 1;
        assert!(validate_arm_devices(&arm).is_err());
    }

    #[test]
    fn malformed_x86_kernel_is_rejected() {
        assert_matches!(
            plan_x86(&[0; 64], 64, 64 << 20, 1, "", &x86_devices()),
            Err(Error::InvalidKernel)
        );
    }

    #[test]
    fn arm_fdt_describes_the_planned_machine() {
        let devices = arm_devices();
        let fdt = arm_fdt(512 << 20, 2, &devices, "console=hvc0").unwrap();
        let word = |offset| u32::from_be_bytes(fdt[offset..offset + 4].try_into().unwrap());
        assert_eq!(word(0), 0xd00d_feed);
        assert_eq!(word(4) as usize, fdt.len());
        assert!((word(8) as usize) < fdt.len());
        assert!((word(12) as usize) < fdt.len());
        let timer_interrupts = [1_u32, 13, 4, 1, 14, 4, 1, 11, 4, 1, 10, 4]
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .collect::<Vec<_>>();
        assert!(
            fdt.windows(timer_interrupts.len())
                .any(|bytes| bytes == timer_interrupts)
        );
        for name in [
            "memory@40000000",
            "intc@8000000",
            "timer",
            "psci",
            "virtio_mmio@a000000",
            "virtio_mmio@a000200",
            "virtio_mmio@a000400",
            "cpu@0",
            "cpu@1",
            "arm,gic-v3",
            "arm,armv8-timer",
            "arm,psci-0.2",
            "virtio,mmio",
            "console=hvc0",
        ] {
            let terminated = format!("{name}\0");
            assert!(
                fdt.windows(terminated.len())
                    .any(|bytes| bytes == terminated.as_bytes()),
                "missing {name}"
            );
        }
        for value in [
            ARM_RAM_BASE,
            512 << 20,
            ARM_GIC_DIST_BASE,
            ARM_GIC_DIST_SIZE,
            ARM_GIC_REDIST_BASE,
            ARM_GIC_REDIST_SIZE,
        ] {
            assert!(fdt.windows(8).any(|bytes| bytes == value.to_be_bytes()));
        }
        for device in devices {
            assert!(
                fdt.windows(4)
                    .any(|bytes| bytes == device.irq.to_be_bytes())
            );
        }
        assert!(fdt.windows(12).any(|bytes| {
            bytes
                == [0_u32, ARM_VIRTIO_IRQ_BASE, 4]
                    .into_iter()
                    .flat_map(u32::to_be_bytes)
                    .collect::<Vec<_>>()
        }));
    }

    #[test]
    fn arm_plan_places_fdt_after_the_kernel() {
        let mut kernel = vec![0; 64];
        kernel[8..16].copy_from_slice(&0x80_000_u64.to_le_bytes());
        kernel[16..24].copy_from_slice(&0x20_0000_u64.to_le_bytes());
        kernel[56..60].copy_from_slice(b"ARMd");
        let plan = plan_arm(
            &kernel,
            64,
            128 << 20,
            1,
            "console=hvc0 root=/dev/vda",
            &arm_devices(),
        )
        .expect("arm plan");
        assert_eq!(plan.entry, ARM_RAM_BASE + 0x80_000);
        assert_eq!(plan.writes.len(), 1);
        assert!(
            !plan.writes[0]
                .bytes
                .windows(b"virtio_mmio.device=".len())
                .any(|bytes| bytes == b"virtio_mmio.device=")
        );
        assert!(
            plan.writes[0]
                .bytes
                .starts_with(&0xd00d_feed_u32.to_be_bytes())
        );
        assert!(
            plan.writes[0]
                .bytes
                .windows(b"init_on_alloc=1 init_on_free=0".len())
                .any(|word| word == b"init_on_alloc=1 init_on_free=0")
        );
    }
}
