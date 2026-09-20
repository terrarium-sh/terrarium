#![allow(clippy::expect_used)]

use terra_runtime::component::fs::host::fs_component_linker;
use terra_runtime::component::mem::host::mem_component_linker;
use terra_runtime::component::network::host::network_component_linker;
use terra_runtime::engine::{block_component_linker, device_engine, vsock_component_linker};
use wasmtime::component::{Component, Linker};

fn assert_resource<T: 'static>(
    linker: &Linker<T>,
    engine: &wasmtime::Engine,
    interface: &str,
    resource: &str,
    allowed: bool,
) {
    let component = Component::new(
        engine,
        format!(
            r#"
        (component
            (import "{interface}" (instance $api (export "{resource}" (type (sub resource)))))
            (alias export $api "{resource}" (type $resource))
            (export "resource" (type $resource))
            (core func $drop (canon resource.drop $resource))
            (func (export "drop") (param "value" (own $resource))
                (canon lift (core func $drop))))
    "#
        ),
    )
    .expect("resource import probe compiles");
    let result = linker.instantiate_pre(&component);
    assert_eq!(result.is_ok(), allowed, "{interface}: {:?}", result.err());
}

fn assert_ram_import_denied<T: 'static>(linker: &Linker<T>, engine: &wasmtime::Engine) {
    let component = Component::new(
        engine,
        r#"
        (component
            (type $memory (instance (export "ram-bytes" (func (result u64)))))
            (import "terra:host/memory@0.1.0" (instance $memory (type $memory))))
        "#,
    )
    .expect("RAM import probe compiles");
    assert!(
        linker.instantiate_pre(&component).is_err(),
        "VMM component gets no guest RAM import"
    );
}

#[test]
fn wasi_filesystem_and_socket_resources_are_device_specific() {
    let engine = device_engine().expect("device engine");
    for (interface, resource) in [
        ("wasi:filesystem/types@0.3.1", "descriptor"),
        ("wasi:sockets/types@0.3.1", "tcp-socket"),
        ("wasi:sockets/types@0.3.1", "udp-socket"),
    ] {
        assert_resource(
            &block_component_linker::<terra_runtime::engine::BlockHost>(&engine)
                .expect("component linker"),
            &engine,
            interface,
            resource,
            false,
        );
        assert_resource(
            &vsock_component_linker::<terra_runtime::engine::VsockDeviceHost>(&engine)
                .expect("component linker"),
            &engine,
            interface,
            resource,
            false,
        );
        assert_resource(
            &mem_component_linker::<terra_runtime::engine::DeviceContext>(&engine)
                .expect("component linker"),
            &engine,
            interface,
            resource,
            false,
        );
        assert_resource(
            &fs_component_linker::<terra_runtime::component::fs::host::FsHost>(&engine)
                .expect("component linker"),
            &engine,
            interface,
            resource,
            resource == "descriptor",
        );
        assert_resource(
            &network_component_linker::<terra_runtime::engine::NetworkHost>(&engine)
                .expect("component linker"),
            &engine,
            interface,
            resource,
            resource != "descriptor",
        );
    }
}

#[test]
fn host_service_clients_are_exclusive_to_vsock() {
    let engine = device_engine().expect("device engine");
    let interface = "terra:vsock/host-service@0.1.0";
    assert_resource(
        &vsock_component_linker::<terra_runtime::engine::VsockDeviceHost>(&engine)
            .expect("vsock linker"),
        &engine,
        interface,
        "client",
        true,
    );
    assert_resource(
        &block_component_linker::<terra_runtime::engine::BlockHost>(&engine).expect("block linker"),
        &engine,
        interface,
        "client",
        false,
    );
    assert_resource(
        &fs_component_linker::<terra_runtime::component::fs::host::FsHost>(&engine)
            .expect("filesystem linker"),
        &engine,
        interface,
        "client",
        false,
    );
    assert_resource(
        &network_component_linker::<terra_runtime::engine::NetworkHost>(&engine)
            .expect("network linker"),
        &engine,
        interface,
        "client",
        false,
    );
    assert_resource(
        &mem_component_linker::<terra_runtime::engine::DeviceContext>(&engine)
            .expect("memory linker"),
        &engine,
        interface,
        "client",
        false,
    );
}

fn assert_components<T: 'static>(linker: &Linker<T>, engine: &wasmtime::Engine, device: &str) {
    for (name, bytes) in [
        ("block", include_bytes!("../../../components/block/target/wasm32-wasip3/release/terra_block_component.wasm").as_slice()),
        ("network", include_bytes!("../../../components/network/target/wasm32-wasip3/release/terra_network_component.wasm").as_slice()),
        ("fs", include_bytes!("../../../components/fs/target/wasm32-wasip3/release/terra_fs_component.wasm").as_slice()),
        ("mem", include_bytes!("../../../components/mem/target/wasm32-wasip3/release/terra_mem_component.wasm").as_slice()),
        ("boot", include_bytes!("../../../components/boot/target/wasm32-wasip3/release/terra_boot_component.wasm").as_slice()),
        ("vsock", include_bytes!("../../../components/vsock/target/wasm32-wasip3/release/terra_vsock_component.wasm").as_slice()),
    ] {
        let component = Component::new(engine, bytes).expect("component compiles");
        let result = linker.instantiate_pre(&component);
        assert_eq!(result.is_ok(), name == device,
            "{device} linker, {name} component: {:?}", result.err());
    }
}

#[test]
fn component_linkers_exclude_ungranted_interfaces() {
    let engine = device_engine().expect("device engine");
    assert_components(
        &block_component_linker::<terra_runtime::engine::BlockHost>(&engine)
            .expect("component linker"),
        &engine,
        "block",
    );
    assert_components(
        &network_component_linker::<terra_runtime::engine::NetworkHost>(&engine)
            .expect("component linker"),
        &engine,
        "network",
    );
    assert_components(
        &fs_component_linker::<terra_runtime::component::fs::host::FsHost>(&engine)
            .expect("component linker"),
        &engine,
        "fs",
    );
    assert_components(
        &mem_component_linker::<terra_runtime::engine::DeviceContext>(&engine)
            .expect("component linker"),
        &engine,
        "mem",
    );
    assert_components(
        &vsock_component_linker::<terra_runtime::engine::VsockDeviceHost>(&engine)
            .expect("component linker"),
        &engine,
        "vsock",
    );
}

#[test]
fn mmio_dispatcher_requires_no_device_capabilities() {
    let engine = device_engine().expect("device engine");
    let linker =
        terra_runtime::component::vmm::mmio::mmio_component_linker(&engine).expect("VMM linker");
    let component = Component::new(
        &engine,
        include_bytes!(
            "../../../components/vmm/target/wasm32-wasip3/release/terra_vmm_component.wasm"
        ),
    )
    .expect("MMIO component compiles");
    linker
        .instantiate_pre(&component)
        .expect("VMM component receives only its scoped platform imports");

    for (interface, resource) in [
        ("wasi:filesystem/types@0.3.1", "descriptor"),
        ("wasi:sockets/types@0.3.1", "tcp-socket"),
        ("wasi:sockets/types@0.3.1", "udp-socket"),
    ] {
        assert_resource(&linker, &engine, interface, resource, false);
    }
    assert_ram_import_denied(&linker, &engine);
    assert_components(&linker, &engine, "router");
}

#[test]
fn only_vmm_receives_virtual_machine_and_vcpu_resources() {
    let engine = device_engine().expect("device engine");
    let vmm =
        terra_runtime::component::vmm::mmio::mmio_component_linker(&engine).expect("VMM linker");
    for (interface, resource) in [
        ("terra:mmio/virtualization@0.1.0", "vm"),
        ("terra:mmio/platform@0.1.0", "vcpu"),
    ] {
        assert_resource(&vmm, &engine, interface, resource, true);
        assert_resource(
            &block_component_linker::<terra_runtime::engine::BlockHost>(&engine)
                .expect("block linker"),
            &engine,
            interface,
            resource,
            false,
        );
        assert_resource(
            &network_component_linker::<terra_runtime::engine::NetworkHost>(&engine)
                .expect("network linker"),
            &engine,
            interface,
            resource,
            false,
        );
        assert_resource(
            &fs_component_linker::<terra_runtime::component::fs::host::FsHost>(&engine)
                .expect("filesystem linker"),
            &engine,
            interface,
            resource,
            false,
        );
        assert_resource(
            &mem_component_linker::<terra_runtime::engine::DeviceContext>(&engine)
                .expect("memory linker"),
            &engine,
            interface,
            resource,
            false,
        );
        assert_resource(
            &vsock_component_linker::<terra_runtime::engine::VsockDeviceHost>(&engine)
                .expect("vsock linker"),
            &engine,
            interface,
            resource,
            false,
        );
    }
}

fn assert_random_grants<T: 'static>(
    linker: &Linker<T>,
    engine: &wasmtime::Engine,
    secure_random_allowed: bool,
) {
    for (interface, function, result, allowed) in [
        ("random", "get-random-u64", "u64", secure_random_allowed),
        ("insecure", "get-insecure-random-u64", "u64", false),
        (
            "insecure-seed",
            "get-insecure-seed",
            "(tuple u64 u64)",
            false,
        ),
    ] {
        let component = Component::new(
            engine,
            format!(
                r#"(component
                    (import "wasi:random/{interface}@0.3.1"
                        (instance (export "{function}" (func (result {result}))))))"#
            ),
        )
        .expect("random import probe compiles");
        let result = linker.instantiate_pre(&component);
        assert_eq!(result.is_ok(), allowed, "{interface}: {:?}", result.err());
    }
}

#[test]
fn only_vsock_receives_secure_random_and_no_component_receives_insecure_random() {
    use terra_runtime::box_runtime::StoreState;
    use terra_runtime::engine::VsockDeviceHost;

    let engine = device_engine().expect("device engine");
    assert_random_grants(
        &block_component_linker::<terra_runtime::engine::BlockHost>(&engine).expect("block linker"),
        &engine,
        false,
    );
    assert_random_grants(
        &network_component_linker::<terra_runtime::engine::NetworkHost>(&engine)
            .expect("network linker"),
        &engine,
        false,
    );
    assert_random_grants(
        &fs_component_linker::<terra_runtime::component::fs::host::FsHost>(&engine)
            .expect("filesystem linker"),
        &engine,
        false,
    );
    assert_random_grants(
        &mem_component_linker::<terra_runtime::engine::DeviceContext>(&engine)
            .expect("memory linker"),
        &engine,
        false,
    );
    assert_random_grants(
        &terra_runtime::component::vmm::mmio::mmio_component_linker(&engine).expect("VMM linker"),
        &engine,
        false,
    );
    assert_random_grants(
        &vsock_component_linker::<terra_runtime::engine::VsockDeviceHost>(&engine)
            .expect("vsock linker"),
        &engine,
        true,
    );
    let shared_vsock = vsock_component_linker::<StoreState<VsockDeviceHost>>(&engine)
        .expect("shared vsock linker");
    assert_random_grants(&shared_vsock, &engine, true);
    assert_components(&shared_vsock, &engine, "vsock");
    for (interface, resource) in [
        ("wasi:filesystem/types@0.3.1", "descriptor"),
        ("wasi:sockets/types@0.3.1", "tcp-socket"),
        ("wasi:sockets/types@0.3.1", "udp-socket"),
    ] {
        assert_resource(&shared_vsock, &engine, interface, resource, false);
    }
}

#[test]
fn device_cli_context_has_no_host_data_or_terminal_streams() {
    use terra_runtime::engine::DeviceContext;
    use wasmtime_wasi::{
        cli::WasiCliView,
        p3::bindings::cli::{
            environment::Host as EnvironmentHost, terminal_stderr::Host as TerminalStderrHost,
            terminal_stdin::Host as TerminalStdinHost, terminal_stdout::Host as TerminalStdoutHost,
        },
    };

    let mut device = DeviceContext::new(4096).expect("device host");
    let mut cli = WasiCliView::cli(&mut device);
    assert!(
        EnvironmentHost::get_environment(&mut cli)
            .expect("environment")
            .is_empty()
    );
    assert!(
        EnvironmentHost::get_arguments(&mut cli)
            .expect("arguments")
            .is_empty()
    );
    assert_eq!(
        EnvironmentHost::get_initial_cwd(&mut cli).expect("initial directory"),
        None
    );
    assert!(
        TerminalStdinHost::get_terminal_stdin(&mut cli)
            .expect("terminal stdin")
            .is_none()
    );
    assert!(
        TerminalStdoutHost::get_terminal_stdout(&mut cli)
            .expect("terminal stdout")
            .is_none()
    );
    assert!(
        TerminalStderrHost::get_terminal_stderr(&mut cli)
            .expect("terminal stderr")
            .is_none()
    );
}

#[test]
fn runtime_vmm_cannot_import_boot_resources_or_vm_memory_methods() {
    let engine = device_engine().expect("engine");
    let linker =
        terra_runtime::component::vmm::mmio::mmio_component_linker(&engine).expect("VMM linker");
    assert_resource(
        &linker,
        &engine,
        "terra:mmio/virtualization@0.1.0",
        "kernel-image",
        false,
    );
    for (method, parameters, result) in [
        (
            "read-ram",
            "(param \"address\" u64) (param \"length\" u32)",
            "(result (result (list u8) (error $error)))",
        ),
        (
            "write-ram",
            "(param \"address\" u64) (param \"bytes\" (list u8))",
            "(result (result (error $error)))",
        ),
        (
            "finish-boot",
            "(param \"entry\" u64) (param \"boot-argument\" u64)",
            "(result (result (error $error)))",
        ),
        ("start-vcpus", "", "(result (result (error $error)))"),
    ] {
        let component = Component::new(
            &engine,
            format!(
                r#"
            (component
                (import "terra:mmio/virtualization@0.1.0" (instance
                    (export "vm" (type $vm (sub resource)))
                    (type $error-type (enum "unavailable" "invalid-config" "bounds"))
                    (export "error" (type $error (eq $error-type)))
                    (export "[method]vm.{method}" (func
                        (param "self" (borrow $vm)) {parameters} {result})))))
        "#
            ),
        )
        .expect("old VM method probe compiles");
        assert!(
            linker.instantiate_pre(&component).is_err(),
            "runtime exposed {method}"
        );
    }
}
