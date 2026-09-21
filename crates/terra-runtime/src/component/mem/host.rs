use wasmtime::component::HasSelf;

use crate::engine::DeviceContext;
use crate::memory::{ReclaimError, ReclaimRange};

wasmtime::component::bindgen!({
    world: "device",
    path: "../../components/mem/wit",
    debug: false,
    exports: { default: async },
    with: {
        "terra:host/memory@0.1.0": crate::component::block::host::terra::host::memory,
        "terra:host/interrupt@0.1.0": crate::component::block::host::terra::host::interrupt,
        "terra:mmio/types@0.1.0": crate::component::vmm::mmio::terra::mmio::types,
    },
});

pub(crate) use Device as MemComponent;
pub use terra::mmio::types::DeviceError as MemDeviceError;

fn reclaim_error(error: ReclaimError) -> terra::mem::host::Error {
    match error {
        ReclaimError::Invalid => terra::mem::host::Error::Invalid,
        ReclaimError::TooLarge => terra::mem::host::Error::TooLarge,
        ReclaimError::Io | ReclaimError::Unsupported => terra::mem::host::Error::Io,
    }
}

impl terra::mem::host::Host for DeviceContext {
    fn discard(
        &mut self,
        ranges: Vec<terra::mem::host::Range>,
    ) -> Result<(), terra::mem::host::Error> {
        let ranges = ranges
            .into_iter()
            .map(|range| ReclaimRange {
                addr: range.addr,
                len: range.len,
            })
            .collect::<Vec<_>>();
        self.guest_ram().discard(&ranges).map_err(reclaim_error)
    }
}

pub fn mem_component_linker<T: crate::engine::DeviceHost>(
    engine: &wasmtime::Engine,
) -> wasmtime::Result<wasmtime::component::Linker<T>> {
    let mut linker = crate::engine::device_component_linker(engine)?;
    crate::engine::add_device_imports(&mut linker, T::context)?;
    terra::mem::host::add_to_linker::<T, HasSelf<DeviceContext>>(&mut linker, T::context)?;
    Ok(linker)
}
