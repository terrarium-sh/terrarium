//! Generated MMIO interfaces.

pub(crate) mod canonical {
    wasmtime::component::bindgen!({
        world: "mmio-types", path: "../../components/wit/mmio",
        additional_derives: [PartialEq, Eq],
    });

    pub use terra::mmio::types;
}

pub use canonical::types;
