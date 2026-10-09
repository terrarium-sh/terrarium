//! Generated VMM interfaces.

wasmtime::component::bindgen!({
    world: "vmm", path: "../../components/vmm/wit",
    additional_derives: [PartialEq, Eq],
    imports: { default: trappable },
    exports: { default: async },
    with: {
        "terra:vmm/platform.vcpu": crate::component::vmm::Vcpu,
        "terra:vmm/virtualization.vm": crate::component::vmm::virtualization::Vm,
    },
});

pub use terra::vmm::{
    lifecycle_platform, machine_types as machine, platform, virtualization, vmm_mmio_client,
};
