use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::{TrustedArtifact, TrustedArtifacts};

pub mod wasm {
    pub const BLOCK: &[u8] = include_bytes!(
        "../../../components/target/wasm-components/release/terra_block_component.wasm"
    );
    pub const AGENT: &[u8] = include_bytes!(
        "../../../components/target/wasm-components/release/terra_agent_component.wasm"
    );
    pub const VSOCK: &[u8] = include_bytes!(
        "../../../components/target/wasm-components/release/terra_vsock_frontend_component.wasm"
    );
    pub const FS: &[u8] = include_bytes!(
        "../../../components/target/wasm-components/release/terra_fs_component.wasm"
    );
    pub const MEM: &[u8] = include_bytes!(
        "../../../components/target/wasm-components/release/terra_mem_component.wasm"
    );
    pub const BOOT: &[u8] = include_bytes!(
        "../../../components/target/wasm-components/release/terra_boot_component.wasm"
    );
    pub const VMM: &[u8] = include_bytes!(
        "../../../components/target/wasm-components/release/terra_vmm_component.wasm"
    );
    pub const INTERRUPT_CONTROLLER: &[u8] = include_bytes!(
        "../../../components/target/wasm-components/release/terra_interrupt_controller_component.wasm"
    );
}

#[must_use]
pub fn boot_assets_dir() -> PathBuf {
    std::env::var_os("TERRA_BOOT_ASSETS_DIR").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build"),
        PathBuf::from,
    )
}

#[must_use]
pub fn trusted_artifacts() -> TrustedArtifacts {
    static ARTIFACTS: OnceLock<TrustedArtifacts> = OnceLock::new();
    *ARTIFACTS.get_or_init(|| {
        let directory = boot_assets_dir();
        let load = |component: &str| {
            let path = directory.join(format!("terra-{component}-component.cwasm"));
            let bytes = std::fs::read(&path).unwrap_or_else(|error| {
                panic!("{}: {error}; run `make build` first", path.display())
            });
            // SAFETY: boot_assets_dir holds trusted AOT output of this Wasmtime build.
            #[allow(unsafe_code)]
            unsafe {
                TrustedArtifact::from_trusted_bytes(Box::leak(bytes.into_boxed_slice()))
            }
        };
        TrustedArtifacts {
            block: load("block"),
            agent: load("agent"),
            vsock_frontend: load("vsock-frontend"),
            fs: load("fs"),
            mem: load("mem"),
            boot: load("boot"),
            vmm: load("vmm"),
            interrupt_controller: load("interrupt-controller"),
        }
    })
}
