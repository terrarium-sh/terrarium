#![allow(clippy::expect_used)]

#[path = "support/artifacts.rs"]
mod support;

use terra_runtime::component::block::{BlockHost, block_component_linker};
use terra_runtime::component::fs::fs_component_linker;
use terra_runtime::component::mem::mem_component_linker;
use terra_runtime::component::network::{NetworkHost, network_component_linker};
use terra_runtime::component::vsock::{VsockDeviceHost, vsock_component_linker};
use terra_runtime::engine::device_engine;
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

fn assert_function_denied<T: 'static>(
    linker: &Linker<T>,
    engine: &wasmtime::Engine,
    interface: &str,
    function: &str,
    signature: &str,
) {
    let component = Component::new(
        engine,
        format!(
            r#"(component
                (import "{interface}" (instance (export "{function}" (func {signature}))))
            )"#
        ),
    )
    .expect("function import probe compiles");
    assert!(
        linker.instantiate_pre(&component).is_err(),
        "{interface}.{function} must not be linked"
    );
}

fn assert_unused_clock_functions<T: 'static>(linker: &Linker<T>, engine: &wasmtime::Engine) {
    assert_function_denied(
        linker,
        engine,
        "wasi:clocks/monotonic-clock@0.3.1",
        "get-resolution",
        "(result u64)",
    );
    assert_function_denied(
        linker,
        engine,
        "wasi:clocks/monotonic-clock@0.3.1",
        "wait-until",
        "(param \"when\" u64)",
    );
}

fn assert_system_clock_now_denied<T: 'static>(linker: &Linker<T>, engine: &wasmtime::Engine) {
    let component = Component::new(
        engine,
        r#"(component
            (type $api (instance
                (type (record (field "seconds" s64) (field "nanoseconds" u32)))
                (export "instant" (type (eq 0)))
                (type (func (result 1)))
                (export "now" (func (type 2)))))
            (import "wasi:clocks/system-clock@0.3.1" (instance $api (type $api))))"#,
    )
    .expect("system clock probe compiles");
    assert!(
        linker.instantiate_pre(&component).is_err(),
        "wasi:clocks/system-clock.now must not be linked"
    );
}

#[test]
fn clock_linkers_exclude_unused_methods() {
    let engine = device_engine().expect("device engine");
    let fs = fs_component_linker::<terra_runtime::component::fs::FsHost>(&engine)
        .expect("filesystem linker");
    let network = network_component_linker::<NetworkHost>(&engine).expect("network linker");
    let vsock = vsock_component_linker::<VsockDeviceHost>(&engine).expect("vsock linker");
    assert_unused_clock_functions(&fs, &engine);
    assert_unused_clock_functions(&network, &engine);
    assert_unused_clock_functions(&vsock, &engine);
    assert_function_denied(
        &fs,
        &engine,
        "wasi:clocks/monotonic-clock@0.3.1",
        "now",
        "(result u64)",
    );
    assert_system_clock_now_denied(&fs, &engine);
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
            &block_component_linker::<BlockHost>(&engine).expect("component linker"),
            &engine,
            interface,
            resource,
            false,
        );
        assert_resource(
            &vsock_component_linker::<VsockDeviceHost>(&engine).expect("component linker"),
            &engine,
            interface,
            resource,
            false,
        );
        assert_resource(
            &mem_component_linker::<terra_runtime::component::context::DeviceContext>(&engine)
                .expect("component linker"),
            &engine,
            interface,
            resource,
            false,
        );
        assert_resource(
            &fs_component_linker::<terra_runtime::component::fs::FsHost>(&engine)
                .expect("component linker"),
            &engine,
            interface,
            resource,
            resource == "descriptor",
        );
        assert_resource(
            &network_component_linker::<NetworkHost>(&engine).expect("component linker"),
            &engine,
            interface,
            resource,
            resource != "descriptor",
        );
    }
}

fn assert_method_unregistered<T: 'static>(linker: &Linker<T>, interface_name: &str, method: &str) {
    let mut linker = linker.clone();
    let mut interface = linker.instance(interface_name).expect("interface exists");
    assert!(
        interface
            .func_wrap(method, |_, (): ()| -> wasmtime::Result<()> { Ok(()) })
            .is_ok(),
        "linker exposed {method}"
    );
}

#[test]
fn filesystem_and_socket_linkers_exclude_unused_resource_methods() {
    let engine = device_engine().expect("device engine");
    let filesystem = fs_component_linker::<terra_runtime::component::fs::FsHost>(&engine)
        .expect("filesystem linker");
    for method in [
        "[method]descriptor.append-via-stream",
        "[method]descriptor.advise",
        "[method]descriptor.is-same-object",
    ] {
        assert_method_unregistered(&filesystem, "wasi:filesystem/types@0.3.0", method);
    }
    let network = network_component_linker::<NetworkHost>(&engine).expect("network linker");
    for method in [
        "[method]tcp-socket.get-address-family",
        "[method]tcp-socket.get-local-address",
        "[method]udp-socket.get-send-buffer-size",
        "[method]tcp-socket.set-listen-backlog-size",
    ] {
        assert_method_unregistered(&network, "wasi:sockets/types@0.3.0", method);
    }
}

#[test]
fn host_service_clients_are_exclusive_to_vsock() {
    let engine = device_engine().expect("device engine");
    let interface = "terra:vsock/host-service@0.1.0";
    assert_resource(
        &vsock_component_linker::<VsockDeviceHost>(&engine).expect("vsock linker"),
        &engine,
        interface,
        "client",
        true,
    );
    assert_resource(
        &block_component_linker::<BlockHost>(&engine).expect("block linker"),
        &engine,
        interface,
        "client",
        false,
    );
    assert_resource(
        &fs_component_linker::<terra_runtime::component::fs::FsHost>(&engine)
            .expect("filesystem linker"),
        &engine,
        interface,
        "client",
        false,
    );
    assert_resource(
        &network_component_linker::<NetworkHost>(&engine).expect("network linker"),
        &engine,
        interface,
        "client",
        false,
    );
    assert_resource(
        &mem_component_linker::<terra_runtime::component::context::DeviceContext>(&engine)
            .expect("memory linker"),
        &engine,
        interface,
        "client",
        false,
    );
}

fn assert_components<T: 'static>(linker: &Linker<T>, engine: &wasmtime::Engine, device: &str) {
    for (name, bytes) in [
        ("block", support::artifacts::wasm::BLOCK),
        ("network", support::artifacts::wasm::NETWORK),
        ("fs", support::artifacts::wasm::FS),
        ("mem", support::artifacts::wasm::MEM),
        ("boot", support::artifacts::wasm::BOOT),
        ("vsock", support::artifacts::wasm::VSOCK),
    ] {
        let component = Component::new(engine, bytes).expect("component compiles");
        let result = linker.instantiate_pre(&component);
        assert_eq!(
            result.is_ok(),
            name == device,
            "{device} linker, {name} component: {:?}",
            result.err()
        );
    }
}

#[test]
fn component_linkers_exclude_ungranted_interfaces() {
    let engine = device_engine().expect("device engine");
    assert_components(
        &block_component_linker::<BlockHost>(&engine).expect("component linker"),
        &engine,
        "block",
    );
    assert_components(
        &network_component_linker::<NetworkHost>(&engine).expect("component linker"),
        &engine,
        "network",
    );
    assert_components(
        &fs_component_linker::<terra_runtime::component::fs::FsHost>(&engine)
            .expect("component linker"),
        &engine,
        "fs",
    );
    assert_components(
        &mem_component_linker::<terra_runtime::component::context::DeviceContext>(&engine)
            .expect("component linker"),
        &engine,
        "mem",
    );
    assert_components(
        &vsock_component_linker::<VsockDeviceHost>(&engine).expect("component linker"),
        &engine,
        "vsock",
    );
}

#[test]
fn service_components_receive_no_host_resources() {
    let engine = device_engine().expect("device engine");
    let linker = Linker::<()>::new(&engine);
    for (name, bytes) in [
        ("MMIO", support::artifacts::wasm::MMIO),
        (
            "interrupt controller",
            support::artifacts::wasm::INTERRUPT_CONTROLLER,
        ),
    ] {
        let component = Component::new(&engine, bytes).expect("service component compiles");
        linker
            .instantiate_pre(&component)
            .map_err(|error| format!("{name} requested host authority: {error:#}"))
            .expect("service links without host authority");
    }

    for (interface, resource) in [
        ("wasi:filesystem/types@0.3.1", "descriptor"),
        ("wasi:sockets/types@0.3.1", "tcp-socket"),
        ("wasi:sockets/types@0.3.1", "udp-socket"),
        ("terra:mmio/virtualization@0.1.0", "vm"),
        ("terra:mmio/platform@0.1.0", "vcpu"),
    ] {
        assert_resource(&linker, &engine, interface, resource, false);
    }
    assert_ram_import_denied(&linker, &engine);
}

#[test]
fn only_vmm_receives_virtual_machine_and_vcpu_resources() {
    let engine = device_engine().expect("device engine");
    let vmm = terra_runtime::component::vmm::vmm_component_linker(&engine).expect("VMM linker");
    for (interface, resource) in [
        ("terra:mmio/virtualization@0.1.0", "vm"),
        ("terra:mmio/platform@0.1.0", "vcpu"),
    ] {
        assert_resource(&vmm, &engine, interface, resource, true);
        assert_resource(
            &block_component_linker::<BlockHost>(&engine).expect("block linker"),
            &engine,
            interface,
            resource,
            false,
        );
        assert_resource(
            &network_component_linker::<NetworkHost>(&engine).expect("network linker"),
            &engine,
            interface,
            resource,
            false,
        );
        assert_resource(
            &fs_component_linker::<terra_runtime::component::fs::FsHost>(&engine)
                .expect("filesystem linker"),
            &engine,
            interface,
            resource,
            false,
        );
        assert_resource(
            &mem_component_linker::<terra_runtime::component::context::DeviceContext>(&engine)
                .expect("memory linker"),
            &engine,
            interface,
            resource,
            false,
        );
        assert_resource(
            &vsock_component_linker::<VsockDeviceHost>(&engine).expect("vsock linker"),
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
        ("random", "get-random-bytes", "(list u8)", false),
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

    let engine = device_engine().expect("device engine");
    assert_random_grants(
        &block_component_linker::<BlockHost>(&engine).expect("block linker"),
        &engine,
        false,
    );
    assert_random_grants(
        &network_component_linker::<NetworkHost>(&engine).expect("network linker"),
        &engine,
        false,
    );
    assert_random_grants(
        &fs_component_linker::<terra_runtime::component::fs::FsHost>(&engine)
            .expect("filesystem linker"),
        &engine,
        false,
    );
    assert_random_grants(
        &mem_component_linker::<terra_runtime::component::context::DeviceContext>(&engine)
            .expect("memory linker"),
        &engine,
        false,
    );
    assert_random_grants(
        &terra_runtime::component::vmm::vmm_component_linker(&engine).expect("VMM linker"),
        &engine,
        false,
    );
    assert_random_grants(
        &vsock_component_linker::<VsockDeviceHost>(&engine).expect("vsock linker"),
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
    use terra_runtime::component::context::DeviceContext;
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
    let linker = terra_runtime::component::vmm::vmm_component_linker(&engine).expect("VMM linker");
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
