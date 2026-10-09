use crate::support;

use terra_runtime::component::agent::{AgentHost, agent_component_linker};
use terra_runtime::component::block::{BlockHost, block_component_linker};
use terra_runtime::component::fs::fs_component_linker;
use terra_runtime::component::mem::mem_component_linker;
use terra_runtime::component::vsock::vsock_component_linker;
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
    let frontend = vsock_component_linker(&engine).expect("vsock linker");
    let agent = agent_component_linker::<AgentHost>(&engine).expect("agent linker");
    assert_unused_clock_functions(&fs, &engine);
    assert_unused_clock_functions(&frontend, &engine);
    assert_unused_clock_functions(&agent, &engine);
    assert_function_denied(
        &frontend,
        &engine,
        "wasi:clocks/monotonic-clock@0.3.1",
        "now",
        "(result u64)",
    );
    assert_function_denied(
        &fs,
        &engine,
        "wasi:clocks/monotonic-clock@0.3.1",
        "now",
        "(result u64)",
    );
    assert_system_clock_now_denied(&fs, &engine);
    assert_system_clock_now_denied(&frontend, &engine);
}

fn assert_ram_import_denied<T: 'static>(linker: &Linker<T>, engine: &wasmtime::Engine) {
    let component = Component::new(
        engine,
        r#"
        (component
            (type $memory (instance (export "address-limit" (func (result u64)))))
            (import "terra:host/memory@0.1.0" (instance $memory (type $memory))))
        "#,
    )
    .expect("RAM import probe compiles");
    assert!(
        linker.instantiate_pre(&component).is_err(),
        "component gets no guest RAM import"
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
            &agent_component_linker::<AgentHost>(&engine).expect("component linker"),
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
            &vsock_component_linker(&engine).expect("component linker"),
            &engine,
            interface,
            resource,
            false,
        );
    }
}

#[test]
fn broker_resources_are_exclusive_to_vsock_frontend() {
    let engine = device_engine().expect("device engine");
    let interface = "terra:network/broker@0.1.0";
    for resource in ["tcp", "udp", "listener"] {
        assert_resource(
            &vsock_component_linker(&engine).expect("vsock linker"),
            &engine,
            interface,
            resource,
            true,
        );
        assert_resource(
            &block_component_linker::<BlockHost>(&engine).expect("block linker"),
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
            &agent_component_linker::<AgentHost>(&engine).expect("agent linker"),
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
            &terra_runtime::component::vmm::vmm_component_linker(&engine).expect("VMM linker"),
            &engine,
            interface,
            resource,
            false,
        );
        assert_resource(
            &Linker::<()>::new(&engine),
            &engine,
            interface,
            resource,
            false,
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
fn filesystem_linker_excludes_unused_resource_methods() {
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
}

#[test]
fn host_service_clients_are_exclusive_to_agent() {
    let engine = device_engine().expect("device engine");
    let interface = "terra:agent/host-service@0.1.0";
    assert_resource(
        &agent_component_linker::<AgentHost>(&engine).expect("agent linker"),
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
        &vsock_component_linker(&engine).expect("vsock linker"),
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
        ("fs", support::artifacts::wasm::FS),
        ("mem", support::artifacts::wasm::MEM),
        ("agent", support::artifacts::wasm::AGENT),
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
        &agent_component_linker::<AgentHost>(&engine).expect("component linker"),
        &engine,
        "agent",
    );
    assert_components(
        &vsock_component_linker(&engine).expect("vsock linker"),
        &engine,
        "vsock",
    );
}

#[test]
fn service_components_receive_no_host_resources() {
    let engine = device_engine().expect("device engine");
    let linker = Linker::<()>::new(&engine);
    for (name, bytes) in [
        ("boot", support::artifacts::wasm::BOOT),
        (
            "interrupt controller",
            support::artifacts::wasm::INTERRUPT_CONTROLLER,
        ),
    ] {
        let component = Component::new(&engine, bytes).expect("service component compiles");
        if name == "boot" {
            assert!(component.component_type().imports(&engine).next().is_none());
        }
        linker
            .instantiate_pre(&component)
            .map_err(|error| format!("{name} requested host authority: {error:#}"))
            .expect("service links without host authority");
    }

    for (interface, resource) in [
        ("wasi:filesystem/types@0.3.1", "descriptor"),
        ("wasi:sockets/types@0.3.1", "tcp-socket"),
        ("wasi:sockets/types@0.3.1", "udp-socket"),
        ("terra:vmm/virtualization@0.1.0", "vm"),
        ("terra:vmm/platform@0.1.0", "vcpu"),
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
        ("terra:vmm/virtualization@0.1.0", "vm"),
        ("terra:vmm/platform@0.1.0", "vcpu"),
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
            &vsock_component_linker(&engine).expect("vsock linker"),
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
            &agent_component_linker::<AgentHost>(&engine).expect("agent linker"),
            &engine,
            interface,
            resource,
            false,
        );
    }
}

fn assert_random_imports_denied<T: 'static>(linker: &Linker<T>, engine: &wasmtime::Engine) {
    for (interface, function, result) in [
        ("random", "get-random-u64", "u64"),
        ("random", "get-random-bytes", "(list u8)"),
        ("insecure", "get-insecure-random-u64", "u64"),
        ("insecure-seed", "get-insecure-seed", "(tuple u64 u64)"),
    ] {
        assert_function_denied(
            linker,
            engine,
            &format!("wasi:random/{interface}@0.3.1"),
            function,
            &format!("(result {result})"),
        );
    }
}

#[test]
fn no_component_receives_random_authority() {
    use terra_runtime::box_runtime::StoreState;

    let engine = device_engine().expect("device engine");
    assert_random_imports_denied(
        &block_component_linker::<BlockHost>(&engine).expect("block linker"),
        &engine,
    );
    assert_random_imports_denied(
        &vsock_component_linker(&engine).expect("vsock linker"),
        &engine,
    );
    assert_random_imports_denied(
        &fs_component_linker::<terra_runtime::component::fs::FsHost>(&engine)
            .expect("filesystem linker"),
        &engine,
    );
    assert_random_imports_denied(
        &mem_component_linker::<terra_runtime::component::context::DeviceContext>(&engine)
            .expect("memory linker"),
        &engine,
    );
    assert_random_imports_denied(
        &terra_runtime::component::vmm::vmm_component_linker(&engine).expect("VMM linker"),
        &engine,
    );
    assert_random_imports_denied(
        &agent_component_linker::<AgentHost>(&engine).expect("agent linker"),
        &engine,
    );
    let shared_agent =
        agent_component_linker::<StoreState<AgentHost>>(&engine).expect("shared agent linker");
    assert_random_imports_denied(&shared_agent, &engine);
    assert_components(&shared_agent, &engine, "agent");
    for (interface, resource) in [
        ("wasi:filesystem/types@0.3.1", "descriptor"),
        ("wasi:sockets/types@0.3.1", "tcp-socket"),
        ("wasi:sockets/types@0.3.1", "udp-socket"),
    ] {
        assert_resource(&shared_agent, &engine, interface, resource, false);
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
        "terra:vmm/virtualization@0.1.0",
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
                (import "terra:vmm/virtualization@0.1.0" (instance
                    (export "vm" (type $vm (sub resource)))
                    (type $error-type (enum "unavailable"))
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

#[test]
fn agent_has_no_guest_memory_or_interrupt_authority() {
    let engine = device_engine().expect("device engine");
    let agent = agent_component_linker::<AgentHost>(&engine).expect("agent linker");
    assert_ram_import_denied(&agent, &engine);
    for (interface, function) in [
        ("terra:host/interrupt@0.1.0", "signal"),
        ("terra:host/interrupt@0.1.0", "set-level"),
    ] {
        let signature = if function == "set-level" {
            "(param \"level\" bool)"
        } else {
            ""
        };
        assert_function_denied(&agent, &engine, interface, function, signature);
    }
}

#[test]
fn vsock_frontend_has_no_filesystem_or_agent_service_authority() {
    let engine = device_engine().expect("device engine");
    let frontend = vsock_component_linker(&engine).expect("vsock linker");
    for (interface, resource) in [
        ("wasi:filesystem/types@0.3.1", "descriptor"),
        ("wasi:sockets/types@0.3.1", "tcp-socket"),
        ("wasi:sockets/types@0.3.1", "udp-socket"),
        ("terra:agent/host-service@0.1.0", "client"),
    ] {
        assert_resource(&frontend, &engine, interface, resource, false);
    }
    for (function, result) in [("plan", "(list u8)"), ("stop", "(stream u8)")] {
        assert_function_denied(
            &frontend,
            &engine,
            "terra:agent/host-service@0.1.0",
            function,
            &format!("(result {result})"),
        );
    }
    assert_function_denied(
        &frontend,
        &engine,
        "terra:vsock/role-stream@0.1.0",
        "accept",
        "async (param \"output\" (stream u8)) (result (option (stream u8)))",
    );
}

#[test]
fn agent_and_frontend_exports_match_their_single_setup_flow() {
    use wasmtime::component::types::ComponentItem;

    let engine = device_engine().expect("device engine");
    for (bytes, interface_name, expected) in [
        (
            support::artifacts::wasm::AGENT,
            "terra:agent/api@0.1.0",
            &[("close", true), ("events", true)][..],
        ),
        (
            support::artifacts::wasm::VSOCK,
            "terra:vsock-frontend/api@0.1.0",
            &[("close", true), ("configure-device", false), ("run", true)][..],
        ),
    ] {
        let component = Component::new(&engine, bytes).expect("component compiles");
        let component_type = component.component_type();
        let interface = component_type
            .get_export(&engine, interface_name)
            .expect("API export");
        assert!(matches!(&interface.ty, ComponentItem::ComponentInstance(_)));
        if let ComponentItem::ComponentInstance(interface) = interface.ty {
            let mut functions = Vec::new();
            for (name, export) in interface.exports(&engine) {
                if let ComponentItem::ComponentFunc(function) = export.ty {
                    functions.push((name, function.async_()));
                    if name == "configure-device" {
                        let parameters = function.params().collect::<Vec<_>>();
                        assert_eq!(parameters.len(), 1);
                        assert_eq!(parameters[0].0, "network");
                        assert!(matches!(
                            parameters[0].1,
                            wasmtime::component::types::Type::Option(_)
                        ));
                    }
                }
            }
            functions.sort_unstable();
            assert_eq!(functions, expected);
        }
        assert!(
            component_type
                .get_export(&engine, "terra:network/api@0.1.0")
                .is_none()
        );
    }
}
