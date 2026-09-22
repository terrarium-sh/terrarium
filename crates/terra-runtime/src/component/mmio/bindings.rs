//! Generated MMIO interfaces.

pub(crate) mod canonical {
    wasmtime::component::bindgen!({
        world: "mmio-types", path: "../../components/wit/mmio",
        additional_derives: [PartialEq, Eq],
    });

    pub use terra::mmio::types;
}

wasmtime::component::bindgen!({
    world: "mmio", path: "../../components/wit/mmio",
    additional_derives: [PartialEq, Eq],
    exports: { default: async },
    with: {
        "terra:mmio/types@0.1.0": crate::component::mmio::bindings::canonical::types,
    },
});

pub use canonical::types;
pub use exports::terra::mmio::router;
