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
#[allow(unsafe_code, clippy::expect_used)]
pub fn trusted_artifacts() -> super::TrustedArtifacts {
    if let Some(directory) = std::env::var_os("TERRA_BOOT_ASSETS_DIR") {
        let directory = std::path::PathBuf::from(directory);
        let artifact = |name| -> &'static [u8] {
            Box::leak(
                std::fs::read(directory.join(name))
                    .expect("read preserved trusted boot-test AOT fixture")
                    .into_boxed_slice(),
            )
        };
        // SAFETY: this manual test fixture selects preserved trusted AOT from the matching build.
        return unsafe {
            super::TrustedArtifacts::new(
                artifact("terra-block-component.cwasm"),
                artifact("terra-agent-component.cwasm"),
                artifact("terra-vsock-frontend-component.cwasm"),
                artifact("terra-fs-component.cwasm"),
                artifact("terra-mem-component.cwasm"),
                artifact("terra-boot-component.cwasm"),
                artifact("terra-vmm-component.cwasm"),
                artifact("terra-interrupt-controller-component.cwasm"),
            )
        };
    }
    // SAFETY: these build-tree artifacts are trusted AOT output for this Wasmtime build.
    unsafe {
        trusted_artifacts_with_frontend(include_bytes!(
            "../../../build/terra-vsock-frontend-component.cwasm"
        ))
    }
}

/// # Safety
/// `frontend` must be preserved trusted AOT output for this exact Wasmtime build.
#[allow(unsafe_code)]
pub unsafe fn trusted_artifacts_with_frontend(frontend: &'static [u8]) -> super::TrustedArtifacts {
    // SAFETY: the caller establishes frontend provenance; remaining artifacts come from this build.
    unsafe {
        super::TrustedArtifacts::new(
            include_bytes!("../../../build/terra-block-component.cwasm"),
            include_bytes!("../../../build/terra-agent-component.cwasm"),
            frontend,
            include_bytes!("../../../build/terra-fs-component.cwasm"),
            include_bytes!("../../../build/terra-mem-component.cwasm"),
            include_bytes!("../../../build/terra-boot-component.cwasm"),
            include_bytes!("../../../build/terra-vmm-component.cwasm"),
            include_bytes!("../../../build/terra-interrupt-controller-component.cwasm"),
        )
    }
}

#[must_use]
pub fn create_boot_plan() -> terra_protocol::Plan {
    terra_protocol::Plan {
        mode: terra_protocol::PlanMode::Run,
        workdir: None,
        shares: Vec::new(),
        volumes: Vec::new(),
        net: terra_protocol::Net::Tsi,
        published_ports: Vec::new(),
        published_udp_ports: Vec::new(),
        env: std::collections::BTreeMap::new(),
        root: false,
        sudo: Vec::new(),
        on_create: Vec::new(),
        on_start: Vec::new(),
        pre_stop: Vec::new(),
        daemons: Vec::new(),
        workload: vec!["/bin/sh".into()],
        sandbox_info: String::new(),
        await_initial_session: false,
        host_tz: None,
        host_time: None,
        host_seed: None,
    }
}
