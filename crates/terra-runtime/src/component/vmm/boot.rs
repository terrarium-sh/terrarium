//! Isolated Wasm boot preparation for a fixed native machine.

use std::time::Duration;

use wasmtime::component::Component;

use crate::box_runtime::BoxRuntime;
#[cfg(test)]
use crate::box_runtime::store::BoxHost;
use crate::box_runtime::store::StoreState;
use crate::component::vmm::machine::Device;
use crate::component::vmm::virtualization::{Architecture, MachineConfig};
use crate::memory::{BoundedMemory, GuestRam};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

wasmtime::component::bindgen!({
    world: "boot-component", path: "../../components/boot/wit",
    imports: { default: trappable },
    exports: { default: async },
});

const BOOT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_KERNEL_BYTES: usize = 64 * 1024 * 1024;
const MAX_KERNEL_PREFIX_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct BootEntry {
    pub entry: u64,
    pub boot_argument: u64,
}

struct BootGrant {
    config: MachineConfig,
    ram: GuestRam,
    kernel: Vec<u8>,
    remaining_kernel_copy_bytes: u64,
}

pub struct BootHost {
    grant: Option<BootGrant>,
    ctx: WasiCtx,
    table: ResourceTable,
}
impl Default for BootHost {
    fn default() -> Self {
        let mut table = ResourceTable::new();
        table.set_max_capacity(crate::component::context::MAX_DEVICE_RESOURCES);
        Self {
            grant: None,
            table,
            ctx: WasiCtxBuilder::new()
                .max_random_size(crate::MAX_SINGLE_BYTES)
                .allow_tcp(false)
                .allow_udp(false)
                .allow_ip_name_lookup(false)
                .build(),
        }
    }
}
impl WasiView for BootHost {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

fn bounds() -> terra::boot::types::Error {
    terra::boot::types::Error::Bounds
}

impl BootHost {
    fn grant(
        &mut self,
        config: MachineConfig,
        ram: GuestRam,
        kernel: Vec<u8>,
    ) -> wasmtime::Result<()> {
        wasmtime::ensure!(self.grant.is_none(), "boot capabilities already granted");
        let remaining_kernel_copy_bytes = u64::try_from(kernel.len())?;
        self.grant = Some(BootGrant {
            config,
            ram,
            kernel,
            remaining_kernel_copy_bytes,
        });
        Ok(())
    }

    fn get(&mut self) -> Result<&mut BootGrant, terra::boot::types::Error> {
        self.grant.as_mut().ok_or_else(bounds)
    }
}

impl terra::boot::host::Host for BootHost {
    fn machine_config(&mut self) -> wasmtime::Result<terra::boot::types::Machine> {
        let Some(grant) = self.grant.as_ref() else {
            return Ok(terra::boot::types::Machine {
                architecture: terra::boot::types::Architecture::X86,
                ram_bytes: 0,
                vcpus: 0,
                devices: Vec::new(),
            });
        };
        Ok(terra::boot::types::Machine {
            architecture: match grant.config.architecture() {
                Architecture::X86 => terra::boot::types::Architecture::X86,
                Architecture::Arm => terra::boot::types::Architecture::Arm,
            },
            ram_bytes: grant.config.ram_bytes(),
            vcpus: grant.config.vcpus(),
            devices: grant
                .config
                .devices()
                .iter()
                .map(|device: &Device| terra::boot::types::Device {
                    kind: match device.kind {
                        super::machine::DeviceKind::Block => terra::boot::types::DeviceKind::Block,
                        super::machine::DeviceKind::Net => terra::boot::types::DeviceKind::Net,
                        super::machine::DeviceKind::Vsock => terra::boot::types::DeviceKind::Vsock,
                        super::machine::DeviceKind::Fs => terra::boot::types::DeviceKind::Fs,
                        super::machine::DeviceKind::Memory => {
                            terra::boot::types::DeviceKind::Memory
                        }
                    },
                    mmio_base: device.mmio_base,
                    irq: device.irq,
                })
                .collect(),
        })
    }

    fn kernel_size(&mut self) -> wasmtime::Result<u64> {
        Ok(self
            .grant
            .as_ref()
            .and_then(|grant| u64::try_from(grant.kernel.len()).ok())
            .unwrap_or(0))
    }

    fn kernel_prefix(&mut self) -> wasmtime::Result<Result<Vec<u8>, terra::boot::types::Error>> {
        let grant = self.get()?;
        Ok(Ok(grant.kernel
            [..grant.kernel.len().min(MAX_KERNEL_PREFIX_BYTES)]
            .to_vec()))
    }

    fn copy_kernel(
        &mut self,
        source_offset: u64,
        guest_address: u64,
        length: u32,
    ) -> wasmtime::Result<Result<(), terra::boot::types::Error>> {
        Ok((|| {
            let grant = self.get()?;
            let length = usize::try_from(length).map_err(|_| bounds())?;
            let source_offset = usize::try_from(source_offset).map_err(|_| bounds())?;
            let source_end = source_offset.checked_add(length).ok_or_else(bounds)?;
            let bytes = grant
                .kernel
                .get(source_offset..source_end)
                .ok_or_else(bounds)?;
            let copied = u64::try_from(length).map_err(|_| bounds())?;
            if copied > grant.remaining_kernel_copy_bytes {
                return Err(bounds());
            }
            BoundedMemory::new(&grant.ram)
                .write(guest_address, bytes)
                .map_err(|_| bounds())?;
            grant.remaining_kernel_copy_bytes -= copied;
            Ok(())
        })())
    }

    fn write_ram(
        &mut self,
        address: u64,
        bytes: Vec<u8>,
    ) -> wasmtime::Result<Result<(), terra::boot::types::Error>> {
        Ok(BoundedMemory::new(&self.get()?.ram)
            .write(address, &bytes)
            .map_err(|_| bounds()))
    }
}

impl BoxRuntime {
    pub async fn boot_prepared_machine(
        &self,
        component: &Component,
        config: &MachineConfig,
        ram: GuestRam,
        kernel: Vec<u8>,
        command_line: &str,
    ) -> wasmtime::Result<BootEntry> {
        wasmtime::ensure!(
            !kernel.is_empty() && kernel.len() <= MAX_KERNEL_BYTES,
            "kernel image must be between 1 byte and 64 MiB"
        );
        wasmtime::ensure!(
            command_line.len() <= 2048,
            "kernel command line exceeds boot limit"
        );
        let mut boot_store = self.new_child(BootHost::default());
        boot_store
            .store
            .data_mut()
            .grant(config.clone(), ram.clone(), kernel)?;
        let mut linker = crate::component::context::device_component_linker(self.store.engine())?;
        terra::boot::host::add_to_linker::<
            StoreState<BootHost>,
            wasmtime::component::HasSelf<BootHost>,
        >(&mut linker, AsMut::as_mut)?;
        let entry = tokio::time::timeout(BOOT_TIMEOUT, async {
            let boot =
                BootComponent::instantiate_async(&mut boot_store.store, component, &linker).await?;
            let entry = boot
                .terra_boot_boot()
                .call_stage(&mut boot_store.store, command_line)
                .await?;
            Ok::<_, wasmtime::Error>(entry)
        })
        .await??;
        let entry = entry.map_err(|error| wasmtime::Error::msg(format!("Wasm boot: {error:?}")))?;
        drop(boot_store);
        Ok(BootEntry {
            entry: entry.entry,
            boot_argument: entry.boot_argument,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::terra::boot::host::Host as _;
    use super::*;

    fn hostile_component(engine: &wasmtime::Engine, body: &str) -> Component {
        Component::new(
            engine,
            format!(
                r#"
                (component
                    (type $entry (record (field "entry" u64) (field "boot-argument" u64)))
                    (type $error (enum "invalid-ram" "invalid-vcpus" "invalid-device" "command-line-too-long" "invalid-kernel" "kernel-architecture" "kernel-layout" "kernel-too-large" "boot-data-too-large" "unavailable" "bounds"))
                    (type $stage-type (func (param "kernel-command-line" string) (result (result $entry (error $error)))))
                    (core module $module
                        (memory (export "memory") 1)
                        (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) i32.const 64)
                        (func (export "stage") (param i32 i32) (result i32) {body} i32.const 0)
                    )
                    (core instance $instance (instantiate $module))
                    (alias core export $instance "memory" (core memory $memory))
                    (alias core export $instance "cabi_realloc" (core func $realloc))
                    (alias core export $instance "stage" (core func $stage-core))
                    (func $stage (type $stage-type)
                        (canon lift (core func $stage-core) (memory $memory) (realloc $realloc)))
                    (instance $boot (export "boot-entry" (type $entry)) (export "error" (type $error)) (export "stage" (func $stage)))
                    (export "terra:boot/boot@0.1.0" (instance $boot))
                )
                "#
            ),
        )
        .expect("hostile boot component")
    }

    #[tokio::test]
    async fn boot_traps_and_releases_the_isolated_store() {
        let engine = crate::engine::device_engine().expect("engine");
        let runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
        let component = hostile_component(&engine, "unreachable");
        let ram = GuestRam::new(2 << 20).expect("test RAM");
        let config = MachineConfig::new(Architecture::X86, ram.size(), 1, Vec::new())
            .expect("test machine configuration");

        assert!(
            runtime
                .boot_prepared_machine(&component, &config, ram, vec![1], "")
                .await
                .is_err()
        );
        assert_eq!(runtime.reserved_component_memory(), 0);
    }

    #[tokio::test]
    async fn boot_deadline_releases_the_isolated_store() {
        let engine = crate::engine::device_engine().expect("engine");
        let runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
        let component = hostile_component(&engine, "(loop br 0)");
        let ram = GuestRam::new(2 << 20).expect("test RAM");
        let config = MachineConfig::new(Architecture::X86, ram.size(), 1, Vec::new())
            .expect("test machine configuration");

        assert!(
            runtime
                .boot_prepared_machine(&component, &config, ram, vec![1], "")
                .await
                .is_err()
        );
        assert_eq!(runtime.reserved_component_memory(), 0);
    }

    #[tokio::test]
    async fn boot_component_rejects_a_malformed_kernel_without_retaining_a_store() {
        let engine = crate::engine::device_engine().expect("engine");
        let runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
        let component = Component::new(
            &engine,
            include_bytes!(
                "../../../../../components/target/wasm32-wasip3/release/terra_boot_component.wasm"
            ),
        )
        .expect("boot component");
        let ram = GuestRam::new(2 << 20).expect("test RAM");
        let config = MachineConfig::new(Architecture::X86, ram.size(), 1, Vec::new())
            .expect("test machine configuration");

        assert!(
            runtime
                .boot_prepared_machine(&component, &config, ram, vec![1], "")
                .await
                .is_err()
        );
        assert_eq!(runtime.reserved_component_memory(), 0);
    }

    #[test]
    fn kernel_copies_are_bounded_and_cannot_exceed_the_image_budget() {
        let ram = GuestRam::new(4096).expect("test RAM");
        let config = MachineConfig::new(Architecture::X86, 4096, 1, Vec::new())
            .expect("test machine configuration");
        let mut host = BootHost::default();
        host.grant(config, ram.clone(), vec![7; 4])
            .expect("boot grant");

        assert_eq!(host.copy_kernel(0, 0, 3).expect("host call"), Ok(()));
        assert!(matches!(
            host.copy_kernel(0, 3, 2),
            Ok(Err(terra::boot::types::Error::Bounds))
        ));
        assert!(matches!(
            host.copy_kernel(u64::MAX, 0, 1),
            Ok(Err(terra::boot::types::Error::Bounds))
        ));
        assert!(matches!(
            host.write_ram(0, vec![0; 16 * 1024 + 1]),
            Ok(Err(terra::boot::types::Error::Bounds))
        ));
        assert_eq!(
            BoundedMemory::new(&ram).read(0, 4).expect("bounded read"),
            [7, 7, 7, 0]
        );
    }
}
