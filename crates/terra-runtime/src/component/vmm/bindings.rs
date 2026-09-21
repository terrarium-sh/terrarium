//! Generated VMM interfaces.

wasmtime::component::bindgen!({
    world: "vmm", path: "../../components/vmm/wit",
    additional_derives: [PartialEq, Eq],
    imports: { default: trappable },
    exports: { default: async },
    with: {
        "terra:mmio/platform.vcpu": crate::component::vmm::Vcpu,
        "terra:mmio/virtualization.vm": crate::component::vmm::virtualization::Vm,
    },
});

pub use exports::terra::mmio::interrupts;
pub use terra::mmio::{
    lifecycle_platform, machine_types as machine, platform, types, virtualization,
};
