//! Validates and applies import-free Wasm boot plans.

use std::time::Duration;

use terra_protocol::packed_image::{ChunkCache, PackedImage};
use wasmtime::component::Component;

use crate::box_runtime::BoxRuntime;
#[cfg(test)]
use crate::box_runtime::store::BoxHost;
use crate::machine::{Architecture, DeviceKind, MachineConfig};
use crate::memory::{BoundedMemory, GuestRam};
use terra_limits::{
    MAX_BOOT_COMMAND_LINE_BYTES, MAX_BOOT_KERNEL_BYTES, MAX_BOOT_KERNEL_PREFIX_BYTES,
    MAX_BOOT_KERNEL_SEGMENTS, MAX_BOOT_WRITE_BYTES, MAX_BOOT_WRITES,
};

wasmtime::component::bindgen!({
    world: "boot-component", path: "../../components/boot/wit",
    exports: { default: async },
});

const BOOT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
pub struct BootEntry {
    pub entry: u64,
    pub boot_argument: u64,
}

pub struct BootHost;

fn render_machine_config(config: &MachineConfig) -> exports::terra::boot::boot::Machine {
    exports::terra::boot::boot::Machine {
        architecture: match config.architecture() {
            Architecture::X86 => exports::terra::boot::boot::Architecture::X86,
            Architecture::Arm => exports::terra::boot::boot::Architecture::Arm,
        },
        ram_bytes: config.ram_bytes(),
        vcpus: config.vcpus(),
        devices: config
            .devices()
            .iter()
            .map(|device| exports::terra::boot::boot::Device {
                kind: match device.kind {
                    DeviceKind::Block => exports::terra::boot::boot::DeviceKind::Block,
                    DeviceKind::Vsock => exports::terra::boot::boot::DeviceKind::Vsock,
                    DeviceKind::Fs => exports::terra::boot::boot::DeviceKind::Fs,
                    DeviceKind::Memory => exports::terra::boot::boot::DeviceKind::Memory,
                },
                mmio_base: device.mmio_base,
                irq: device.irq,
            })
            .collect(),
    }
}

fn validate_plan(
    plan: &exports::terra::boot::boot::Plan,
    ram: &GuestRam,
    kernel_bytes: u64,
) -> wasmtime::Result<()> {
    wasmtime::ensure!(
        !plan.kernel_segments.is_empty() && plan.kernel_segments.len() <= MAX_BOOT_KERNEL_SEGMENTS,
        "boot plan exceeds kernel segment limit"
    );
    wasmtime::ensure!(
        plan.writes.len() <= MAX_BOOT_WRITES,
        "boot plan exceeds write limit"
    );
    let mut copied = 0_u64;
    for segment in &plan.kernel_segments {
        wasmtime::ensure!(
            segment.file_length <= segment.memory_length,
            "boot segment exceeds its memory range"
        );
        let source_end = segment
            .source_offset
            .checked_add(segment.file_length)
            .ok_or_else(|| wasmtime::Error::msg("boot kernel source range overflows"))?;
        wasmtime::ensure!(
            source_end <= kernel_bytes,
            "boot kernel source range exceeds image"
        );
        copied = copied
            .checked_add(segment.file_length)
            .ok_or_else(|| wasmtime::Error::msg("boot kernel copy budget overflows"))?;
        wasmtime::ensure!(
            copied <= kernel_bytes,
            "boot kernel copies exceed image budget"
        );
        ram.memory()
            .validate_range(segment.guest_address, segment.memory_length)
            .map_err(|error| wasmtime::Error::msg(format!("boot segment: {error:?}")))?;
    }
    for write in &plan.writes {
        wasmtime::ensure!(
            write.bytes.len() <= MAX_BOOT_WRITE_BYTES,
            "boot data exceeds write budget"
        );
        ram.memory()
            .validate_range(write.address, u64::try_from(write.bytes.len())?)
            .map_err(|error| wasmtime::Error::msg(format!("boot write: {error:?}")))?;
    }
    wasmtime::ensure!(
        plan.kernel_segments.iter().any(|segment| {
            segment.guest_address <= plan.entry
                && segment
                    .guest_address
                    .checked_add(segment.memory_length)
                    .is_some_and(|end| plan.entry < end)
        }),
        "boot entry is outside kernel segments"
    );
    ram.memory()
        .validate_range(plan.boot_argument, 1)
        .map_err(|error| wasmtime::Error::msg(format!("boot argument: {error:?}")))?;
    Ok(())
}

fn write_boot_bytes(ram: &GuestRam, address: u64, bytes: &[u8]) -> wasmtime::Result<()> {
    let memory = BoundedMemory::new(ram);
    let chunk_bytes = usize::try_from(terra_limits::MAX_SINGLE_GUEST_COPY_BYTES)?;
    for (offset, chunk) in bytes.chunks(chunk_bytes).enumerate() {
        let address = address
            .checked_add(u64::try_from(offset * chunk_bytes)?)
            .ok_or_else(|| wasmtime::Error::msg("boot write address overflows"))?;
        memory
            .write(address, chunk)
            .map_err(|error| wasmtime::Error::msg(format!("boot memory copy: {error:?}")))?;
    }
    Ok(())
}

fn describe_read_error(error: &std::io::Error) -> wasmtime::Error {
    wasmtime::Error::msg(format!("reading kernel image: {error}"))
}

fn apply_plan(
    plan: &exports::terra::boot::boot::Plan,
    ram: &GuestRam,
    kernel: &PackedImage<'_>,
    cache: &mut ChunkCache,
) -> wasmtime::Result<BootEntry> {
    validate_plan(plan, ram, kernel.image_bytes())?;
    let mut buffer = vec![0; usize::try_from(terra_limits::MAX_SINGLE_GUEST_COPY_BYTES)?];
    for segment in &plan.kernel_segments {
        let mut copied = 0;
        while copied < segment.file_length {
            let len = (segment.file_length - copied).min(terra_limits::MAX_SINGLE_GUEST_COPY_BYTES);
            let piece = &mut buffer[..usize::try_from(len)?];
            kernel
                .read_at(segment.source_offset + copied, piece, cache)
                .map_err(|error| describe_read_error(&error))?;
            write_boot_bytes(ram, segment.guest_address + copied, piece)?;
            copied += len;
        }
    }
    for write in &plan.writes {
        write_boot_bytes(ram, write.address, &write.bytes)?;
    }
    Ok(BootEntry {
        entry: plan.entry,
        boot_argument: plan.boot_argument,
    })
}

impl BoxRuntime {
    pub async fn boot_prepared_machine(
        &self,
        component: &Component,
        config: &MachineConfig,
        ram: GuestRam,
        kernel: PackedImage<'static>,
        command_line: &str,
    ) -> wasmtime::Result<BootEntry> {
        let kernel_bytes = kernel.image_bytes();
        wasmtime::ensure!(
            (1..=MAX_BOOT_KERNEL_BYTES).contains(&kernel_bytes),
            "kernel image must be between 1 byte and {} MiB",
            MAX_BOOT_KERNEL_BYTES >> 20
        );
        wasmtime::ensure!(
            command_line.len() <= MAX_BOOT_COMMAND_LINE_BYTES,
            "kernel command line exceeds boot limit"
        );
        let mut cache = ChunkCache::new(&kernel);
        let mut prefix = vec![0; usize::try_from(kernel_bytes)?.min(MAX_BOOT_KERNEL_PREFIX_BYTES)];
        kernel
            .read_at(0, &mut prefix, &mut cache)
            .map_err(|error| describe_read_error(&error))?;
        let mut boot_store = self.new_child(BootHost);
        let linker = wasmtime::component::Linker::new(self.store.engine());
        let machine = render_machine_config(config);
        let plan = tokio::time::timeout(BOOT_TIMEOUT, async {
            let boot =
                BootComponent::instantiate_async(&mut boot_store.store, component, &linker).await?;
            boot.terra_boot_boot()
                .call_stage(
                    &mut boot_store.store,
                    &machine,
                    &prefix,
                    kernel_bytes,
                    command_line,
                )
                .await
        })
        .await??;
        let plan = plan.map_err(|error| wasmtime::Error::msg(format!("Wasm boot: {error:?}")))?;
        drop(boot_store);
        apply_plan(&plan, &ram, &kernel, &mut cache)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use terra_protocol::guest_image::GuestImage;
    use terra_protocol::packed_image::{chunk_bytes, compress_fast, pack, pack_fast_leaked};

    fn hostile_component(engine: &wasmtime::Engine, body: &str) -> Component {
        Component::new(
            engine,
            format!(
                r#"
                (component
                    (type $architecture (enum "x86" "arm"))
                    (type $device-kind (enum "block" "vsock" "fs" "memory"))
                    (type $device (record (field "kind" $device-kind) (field "mmio-base" u64) (field "irq" u32)))
                    (type $devices (list $device))
                    (type $machine (record (field "architecture" $architecture) (field "ram-bytes" u64) (field "vcpus" u8) (field "devices" $devices)))
                    (type $segment (record (field "source-offset" u64) (field "guest-address" u64) (field "file-length" u64) (field "memory-length" u64)))
                    (type $segments (list $segment))
                    (type $write (record (field "address" u64) (field "bytes" (list u8))))
                    (type $writes (list $write))
                    (type $plan (record (field "entry" u64) (field "boot-argument" u64) (field "kernel-segments" $segments) (field "writes" $writes)))
                    (type $error (enum "invalid-ram" "invalid-vcpus" "invalid-device" "command-line-too-long" "invalid-kernel" "kernel-architecture" "kernel-layout" "kernel-too-large" "boot-data-too-large"))
                    (type $stage-type (func (param "machine" $machine) (param "kernel-prefix" (list u8)) (param "kernel-size" u64) (param "kernel-command-line" string) (result (result $plan (error $error)))))
                    (core module $module
                        (memory (export "memory") 1)
                        (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) i32.const 64)
                        (func (export "stage") (param i32 i64 i32 i32 i32 i32 i32 i64 i32 i32) (result i32) {body} i32.const 0)
                    )
                    (core instance $instance (instantiate $module))
                    (alias core export $instance "memory" (core memory $memory))
                    (alias core export $instance "cabi_realloc" (core func $realloc))
                    (alias core export $instance "stage" (core func $stage-core))
                    (func $stage (type $stage-type)
                        (canon lift (core func $stage-core) (memory $memory) (realloc $realloc)))
                    (instance $boot
                        (export "architecture" (type $architecture))
                        (export "device-kind" (type $device-kind))
                        (export "device" (type $device))
                        (export "machine" (type $machine))
                        (export "kernel-segment" (type $segment))
                        (export "guest-write" (type $write))
                        (export "plan" (type $plan))
                        (export "error" (type $error)) (export "stage" (func $stage)))
                    (export "terra:boot/boot@0.1.0" (instance $boot))
                )
                "#
            ),
        )
        .expect("hostile boot component")
    }

    #[tokio::test]
    async fn boot_component_traps_are_reported() {
        let engine = crate::engine::device_engine().expect("engine");
        let runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
        let component = hostile_component(&engine, "unreachable");
        let ram = GuestRam::new(2 << 20).expect("test RAM");
        let config = MachineConfig::new(Architecture::X86, ram.mapped_bytes(), 1, Vec::new())
            .expect("test machine configuration");

        assert!(
            runtime
                .boot_prepared_machine(&component, &config, ram, kernel_image(&[1]), "")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn boot_component_infinite_loop_reaches_deadline() {
        let engine = crate::engine::device_engine().expect("engine");
        let runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
        let component = hostile_component(&engine, "(loop br 0)");
        let ram = GuestRam::new(2 << 20).expect("test RAM");
        let config = MachineConfig::new(Architecture::X86, ram.mapped_bytes(), 1, Vec::new())
            .expect("test machine configuration");

        assert!(
            runtime
                .boot_prepared_machine(&component, &config, ram, kernel_image(&[1]), "")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn boot_component_rejects_a_malformed_kernel() {
        let engine = crate::engine::device_engine().expect("engine");
        let runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
        let component =
            Component::new(&engine, crate::test_fixtures::wasm::BOOT).expect("boot component");
        let ram = GuestRam::new(2 << 20).expect("test RAM");
        let config =
            crate::machine::build_machine_layout_for(Architecture::X86, ram.mapped_bytes(), 1, 0)
                .expect("test machine layout")
                .to_machine_config(1)
                .expect("test machine configuration");

        assert!(
            runtime
                .boot_prepared_machine(&component, &config, ram, kernel_image(&[1]), "")
                .await
                .is_err()
        );
    }

    fn kernel_image(bytes: &[u8]) -> PackedImage<'static> {
        pack_fast_leaked(bytes, GuestImage::Kernel).unwrap()
    }

    fn apply_bytes(
        plan: &exports::terra::boot::boot::Plan,
        ram: &GuestRam,
        kernel: &[u8],
    ) -> wasmtime::Result<BootEntry> {
        let image = kernel_image(kernel);
        apply_plan(plan, ram, &image, &mut ChunkCache::new(&image))
    }

    fn plan() -> exports::terra::boot::boot::Plan {
        exports::terra::boot::boot::Plan {
            entry: 0,
            boot_argument: 16,
            kernel_segments: vec![exports::terra::boot::boot::KernelSegment {
                source_offset: 0,
                guest_address: 0,
                file_length: 3,
                memory_length: 4,
            }],
            writes: vec![exports::terra::boot::boot::GuestWrite {
                address: 16,
                bytes: vec![9; 2],
            }],
        }
    }

    #[test]
    fn kernel_copies_are_bounded_and_cannot_exceed_the_image_budget() {
        let ram = GuestRam::new(4096).expect("test RAM");
        let mut plan = plan();
        apply_bytes(&plan, &ram, &[7; 4]).unwrap();
        assert_eq!(BoundedMemory::new(&ram).read(0, 4).unwrap(), [7, 7, 7, 0]);
        assert_eq!(BoundedMemory::new(&ram).read(16, 2).unwrap(), [9, 9]);
        plan.kernel_segments
            .push(exports::terra::boot::boot::KernelSegment {
                source_offset: 0,
                guest_address: 4,
                file_length: 2,
                memory_length: 2,
            });
        assert!(apply_bytes(&plan, &ram, &[7; 4]).is_err());
        plan.kernel_segments.pop();
        plan.kernel_segments[0].source_offset = u64::MAX;
        assert!(apply_bytes(&plan, &ram, &[7; 4]).is_err());
    }

    /// The entire hostile plan is rejected before an earlier valid write mutates guest RAM.
    #[test]
    fn invalid_boot_plans_do_not_mutate_ram() {
        let ram = GuestRam::new(4096).unwrap();
        let mut cases = Vec::new();
        let mut invalid = plan();
        invalid.writes.push(exports::terra::boot::boot::GuestWrite {
            address: 4096,
            bytes: vec![1],
        });
        cases.push(invalid);
        let mut invalid = plan();
        invalid.writes[0].bytes = vec![1; MAX_BOOT_WRITE_BYTES + 1];
        cases.push(invalid);
        let mut invalid = plan();
        invalid.writes = (0..=MAX_BOOT_WRITES)
            .map(|_| exports::terra::boot::boot::GuestWrite {
                address: 16,
                bytes: vec![1],
            })
            .collect();
        cases.push(invalid);
        let mut invalid = plan();
        invalid.kernel_segments = (0..=MAX_BOOT_KERNEL_SEGMENTS)
            .map(|_| exports::terra::boot::boot::KernelSegment {
                source_offset: 0,
                guest_address: 0,
                file_length: 0,
                memory_length: 1,
            })
            .collect();
        cases.push(invalid);
        let mut invalid = plan();
        invalid.kernel_segments[0].guest_address = u64::MAX;
        cases.push(invalid);
        let mut invalid = plan();
        invalid.kernel_segments[0].memory_length = 2;
        cases.push(invalid);
        let mut invalid = plan();
        invalid.entry = 4096;
        cases.push(invalid);
        let mut invalid = plan();
        invalid.boot_argument = 4096;
        cases.push(invalid);
        for invalid in cases {
            assert!(apply_bytes(&invalid, &ram, &[7; 4]).is_err());
            assert_eq!(BoundedMemory::new(&ram).read(0, 18).unwrap(), [0; 18]);
        }
    }

    #[test]
    fn boot_copies_large_images_and_data_through_bounded_memory() {
        let ram = GuestRam::new(128 << 10).unwrap();
        let kernel = vec![7; 64 << 10];
        let mut plan = plan();
        plan.kernel_segments[0].file_length = u64::try_from(kernel.len()).unwrap();
        plan.kernel_segments[0].memory_length = u64::try_from(kernel.len()).unwrap();
        plan.writes[0].address = 64 << 10;
        plan.writes[0].bytes = vec![9; 32 << 10];
        plan.boot_argument = plan.writes[0].address;
        apply_bytes(&plan, &ram, &kernel).unwrap();
        assert_eq!(
            BoundedMemory::new(&ram).read(48 << 10, 16 << 10).unwrap(),
            vec![7; 16 << 10]
        );
        assert_eq!(
            BoundedMemory::new(&ram).read(80 << 10, 16 << 10).unwrap(),
            vec![9; 16 << 10]
        );
    }

    /// A segment is copied from its source offset, and a corrupt chunk inside a later segment
    /// fails the boot after the earlier segment was already written.
    #[test]
    fn corrupt_chunk_inside_a_segment_fails_the_boot() {
        let chunk = chunk_bytes(GuestImage::Kernel) as usize;
        let kernel: Vec<u8> = (0..=255).cycle().take(chunk + 64).collect();
        let mut chunk_index = 0;
        let packed = pack(&kernel, GuestImage::Kernel, |bytes| {
            let mut bytes = bytes.to_vec();
            if chunk_index == 1 {
                bytes[0] ^= 1;
            }
            chunk_index += 1;
            compress_fast(&bytes)
        })
        .unwrap();
        let image = PackedImage::parse(&packed, GuestImage::Kernel).unwrap();
        let ram = GuestRam::new(4096).unwrap();
        let mut plan = plan();
        plan.kernel_segments = vec![
            exports::terra::boot::boot::KernelSegment {
                source_offset: 8,
                guest_address: 100,
                file_length: 4,
                memory_length: 4,
            },
            exports::terra::boot::boot::KernelSegment {
                source_offset: chunk as u64,
                guest_address: 200,
                file_length: 4,
                memory_length: 4,
            },
        ];
        plan.entry = 100;
        assert!(apply_plan(&plan, &ram, &image, &mut ChunkCache::new(&image)).is_err());
        assert_eq!(
            BoundedMemory::new(&ram).read(100, 4).unwrap(),
            [8, 9, 10, 11]
        );
        assert_eq!(BoundedMemory::new(&ram).read(200, 4).unwrap(), [0; 4]);
    }
}
