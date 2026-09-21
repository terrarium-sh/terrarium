pub mod wasm {
    pub const BLOCK: &[u8] = include_bytes!(
        "../../../components/target/wasm32-wasip3/release/terra_block_component.wasm"
    );
    pub const VSOCK: &[u8] = include_bytes!(
        "../../../components/target/wasm32-wasip3/release/terra_vsock_component.wasm"
    );
    pub const NETWORK: &[u8] = include_bytes!(
        "../../../components/target/wasm32-wasip3/release/terra_network_component.wasm"
    );
    pub const FS: &[u8] =
        include_bytes!("../../../components/target/wasm32-wasip3/release/terra_fs_component.wasm");
    pub const MEM: &[u8] =
        include_bytes!("../../../components/target/wasm32-wasip3/release/terra_mem_component.wasm");
    pub const BOOT: &[u8] = include_bytes!(
        "../../../components/target/wasm32-wasip3/release/terra_boot_component.wasm"
    );
    pub const VMM: &[u8] =
        include_bytes!("../../../components/target/wasm32-wasip3/release/terra_vmm_component.wasm");
    pub const POLICY: &[u8] = include_bytes!(
        "../../../components/target/wasm32-wasip3/release/terra_policy_component.wasm"
    );
}

#[must_use]
#[allow(unsafe_code)]
pub fn trusted_artifacts() -> super::TrustedArtifacts {
    // SAFETY: these build-tree artifacts are trusted AOT output for this Wasmtime build.
    unsafe {
        super::TrustedArtifacts::new(
            include_bytes!("../../../build/terra-block-component.cwasm"),
            include_bytes!("../../../build/terra-vsock-component.cwasm"),
            include_bytes!("../../../build/terra-network-component.cwasm"),
            include_bytes!("../../../build/terra-fs-component.cwasm"),
            include_bytes!("../../../build/terra-mem-component.cwasm"),
            include_bytes!("../../../build/terra-boot-component.cwasm"),
            include_bytes!("../../../build/terra-vmm-component.cwasm"),
        )
    }
}
