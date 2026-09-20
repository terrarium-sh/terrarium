#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use terra_runtime::engine::device_engine;
use wasmtime::component::Component;

// Rust's wasm32-wasip3 standard library imports these even when the world omits them.
const RUST_IMPORTS: &[&str] = &[
    "wasi:cli/environment",
    "wasi:cli/exit",
    "wasi:cli/types",
    "wasi:cli/stdin",
    "wasi:cli/stdout",
    "wasi:cli/stderr",
    "wasi:cli/terminal-input",
    "wasi:cli/terminal-output",
    "wasi:cli/terminal-stdin",
    "wasi:cli/terminal-stdout",
    "wasi:cli/terminal-stderr",
    "wasi:clocks/types",
    "wasi:clocks/monotonic-clock",
    "wasi:clocks/system-clock",
];

#[test]
fn compiled_components_import_only_their_declared_capabilities() {
    let engine = device_engine().expect("engine");
    let components: &[(&str, &[&str])] = &[
        (
            "block",
            &[
                "terra:host/memory",
                "terra:host/interrupt",
                "terra:host/disk",
                "terra:mmio/types",
            ],
        ),
        (
            "mem",
            &[
                "terra:host/memory",
                "terra:host/interrupt",
                "terra:mem/host",
                "terra:mmio/types",
            ],
        ),
        (
            "fs",
            &[
                "terra:host/memory",
                "terra:host/interrupt",
                "terra:fs/host",
                "wasi:filesystem/types",
                "wasi:filesystem/preopens",
                "terra:mmio/types",
            ],
        ),
        (
            "network",
            &[
                "terra:host/memory",
                "terra:host/interrupt",
                "terra:host/diagnostics",
                "wasi:sockets/types",
                "wasi:sockets/ip-name-lookup",
                "terra:mmio/types",
            ],
        ),
        (
            "vsock",
            &[
                "terra:host/memory",
                "terra:host/interrupt",
                "terra:vsock/host-service",
                "wasi:random/random",
                "terra:mmio/types",
            ],
        ),
        ("boot", &["terra:boot/types", "terra:boot/host"]),
        ("policy", &[]),
        (
            "vmm",
            &[
                "terra:mmio/types",
                "terra:mmio/machine-types",
                "terra:mmio/platform",
                "terra:mmio/virtualization",
                "terra:mmio/lifecycle-platform",
            ],
        ),
    ];
    for (name, capabilities) in components {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../components/{name}/target/wasm32-wasip3/release/terra_{name}_component.wasm"
        ));
        let component = Component::from_file(&engine, path).expect("built component");
        let actual = component
            .component_type()
            .imports(&engine)
            .map(|(interface, _)| {
                interface
                    .split('@')
                    .next()
                    .expect("interface name")
                    .to_owned()
            })
            .collect::<BTreeSet<_>>();
        let expected = RUST_IMPORTS
            .iter()
            .chain(capabilities.iter())
            .map(|interface| (*interface).to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected, "{name} capability imports changed");
    }
}
