//! Exercise boot planning and bounded staging without virtualization.

use crate::TrustedArtifacts;
use crate::box_runtime::{BoxHost, BoxRuntime};
use crate::machine::{Architecture, build_machine_layout_for};
use crate::memory::GuestRam;
use terra_platform::memory::GuestMemory;

pub(super) async fn run(
    artifacts: &TrustedArtifacts,
    engine: &wasmtime::Engine,
) -> wasmtime::Result<()> {
    let component = artifacts.boot().deserialize(engine)?;
    let runtime = BoxRuntime::new(engine, BoxHost::new())?;
    for architecture in [Architecture::X86, Architecture::Arm] {
        let layout = build_machine_layout_for(architecture, 8 << 20, 1, 0)
            .map_err(|error| wasmtime::Error::msg(format!("boot self-test layout: {error:?}")))?;
        let config = layout.to_machine_config(1)?;
        let ram_base = match architecture {
            Architecture::X86 => terra_limits::X86_RAM_BASE,
            Architecture::Arm => terra_limits::ARM_RAM_BASE,
        };
        let ram = GuestRam::from_memory(
            GuestMemory::from_ranges(&[(ram_base, usize::try_from(config.ram_bytes())?)])
                .ok_or_else(|| wasmtime::Error::msg("boot self-test RAM allocation"))?,
        );
        let kernel = kernel_image(architecture);
        let entry = runtime
            .boot_prepared_machine(&component, &config, ram.clone(), kernel, "console=hvc0")
            .await?;
        let payload_offset = match architecture {
            Architecture::X86 => 0,
            Architecture::Arm => 64,
        };
        wasmtime::ensure!(
            super::read_memory(&ram, entry.entry + payload_offset, 4)? == [42; 4],
            "boot self-test kernel payload was not staged"
        );
        let boot_data = super::read_memory(&ram, entry.boot_argument, 4096)?;
        match architecture {
            Architecture::X86 => wasmtime::ensure!(
                boot_data[0x202..0x206] == 0x5372_6448_u32.to_le_bytes(),
                "boot self-test x86 zero page is missing"
            ),
            Architecture::Arm => {
                wasmtime::ensure!(
                    boot_data.starts_with(&0xd00d_feed_u32.to_be_bytes()),
                    "boot self-test ARM device tree is missing"
                );
                wasmtime::ensure!(
                    !boot_data
                        .windows(b"virtio_mmio.device=".len())
                        .any(|bytes| bytes == b"virtio_mmio.device="),
                    "boot self-test ARM command line duplicates device tree MMIO devices"
                );
            }
        }
        wasmtime::ensure!(
            runtime
                .boot_prepared_machine(&component, &config, ram, vec![0; 64], "")
                .await
                .is_err(),
            "boot self-test accepted a malformed kernel"
        );
    }
    Ok(())
}

fn kernel_image(architecture: Architecture) -> Vec<u8> {
    let mut kernel = vec![42; 64 << 10];
    kernel[..256].fill(0);
    match architecture {
        Architecture::X86 => {
            kernel[..4].copy_from_slice(b"\x7fELF");
            kernel[4] = 2;
            kernel[5] = 1;
            kernel[18..20].copy_from_slice(&62_u16.to_le_bytes());
            kernel[24..32].copy_from_slice(&0x10_0000_u64.to_le_bytes());
            kernel[32..40].copy_from_slice(&64_u64.to_le_bytes());
            kernel[56..58].copy_from_slice(&1_u16.to_le_bytes());
            kernel[64..68].copy_from_slice(&1_u32.to_le_bytes());
            kernel[72..80].copy_from_slice(&256_u64.to_le_bytes());
            kernel[88..96].copy_from_slice(&0x10_0000_u64.to_le_bytes());
            let payload_bytes = (64_u64 << 10) - 256;
            kernel[96..104].copy_from_slice(&payload_bytes.to_le_bytes());
            kernel[104..112].copy_from_slice(&(64_u64 << 10).to_le_bytes());
        }
        Architecture::Arm => {
            kernel[8..16].copy_from_slice(&0x80_000_u64.to_le_bytes());
            kernel[16..24].copy_from_slice(&(2_u64 << 20).to_le_bytes());
            kernel[56..60].copy_from_slice(b"ARMd");
            kernel[64..256].fill(42);
        }
    }
    kernel
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn stages_both_architectures_without_virtualization() {
        let engine = crate::engine::device_engine().unwrap();
        super::run(&crate::test_fixtures::trusted_artifacts(), &engine)
            .await
            .unwrap();
    }
}
