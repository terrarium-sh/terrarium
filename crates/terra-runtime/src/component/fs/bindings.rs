//! Filesystem component bindings.

wasmtime::component::bindgen!({
    world: "device",
    path: "../../components/fs/wit",
    exports: { default: async },
    imports: {
 "terra:fs/host.file-events": store | trappable,
 "terra:fs/host.open-metadata-at": async | store,
 "terra:fs/host.set-mode": async | store,
 "terra:fs/host.get-mode": async | store,
 "terra:fs/host.get-mode-at": async | store,
 "terra:fs/host.set-mode-at": async | store,
 "terra:fs/host.statfs": async | store,
 },
    with: {
        "terra:host/memory@0.1.0": crate::component::bindings::memory,
        "terra:host/interrupt@0.1.0": crate::component::bindings::interrupt,
        "terra:mmio/types@0.1.0": crate::component::mmio::bindings::canonical::types,
        "wasi:filesystem/types.descriptor": wasmtime_wasi::filesystem::Descriptor,
    },
});

pub(crate) use Device as FsComponent;
pub(crate) use terra as wit;
pub use terra::fs::host::{Error as FsError, FilesystemStat};
pub use terra::mmio::types::DeviceError as FsDeviceError;
