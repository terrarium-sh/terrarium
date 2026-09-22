//! Generated VMM interfaces.

wasmtime::component::bindgen!({
    world: "vmm", path: "../../components/vmm/wit",
    additional_derives: [PartialEq, Eq],
    imports: { default: trappable },
    exports: { default: async },
    with: {
        "terra:mmio/types@0.1.0": crate::component::mmio::bindings::canonical::types,
        "terra:mmio/platform.vcpu": crate::component::vmm::Vcpu,
        "terra:mmio/virtualization.vm": crate::component::vmm::virtualization::Vm,
    },
});

pub use terra::mmio::{
    lifecycle_platform, machine_types as machine, platform, virtualization, vmm_mmio_client,
};
