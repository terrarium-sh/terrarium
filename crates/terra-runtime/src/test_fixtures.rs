pub mod wasm {
    pub const BLOCK: &[u8] = include_bytes!(
        "../../../components/target/wasm-components/release/terra_block_component.wasm"
    );
    pub const VSOCK: &[u8] = include_bytes!(
        "../../../components/target/wasm-components/release/terra_vsock_component.wasm"
    );
    pub const NETWORK: &[u8] = include_bytes!(
        "../../../components/target/wasm-components/release/terra_network_component.wasm"
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
    pub const MMIO: &[u8] = include_bytes!(
        "../../../components/target/wasm-components/release/terra_mmio_component.wasm"
    );
    pub const INTERRUPT_CONTROLLER: &[u8] = include_bytes!(
        "../../../components/target/wasm-components/release/terra_interrupt_controller_component.wasm"
    );
    pub const POLICY: &[u8] = include_bytes!(
        "../../../components/target/wasm-components/release/terra_policy_component.wasm"
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
            include_bytes!("../../../build/terra-mmio-component.cwasm"),
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
        net: terra_protocol::Net {
            guest_ip: std::net::Ipv4Addr::new(100, 96, 0, 2).into(),
            prefix: 30,
            gateway: std::net::Ipv4Addr::new(100, 96, 0, 1).into(),
            dns: std::net::Ipv4Addr::new(100, 96, 0, 1).into(),
        },
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
