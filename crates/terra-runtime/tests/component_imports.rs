#![allow(clippy::expect_used)]

use std::path::Path;
use terra_runtime::engine::device_engine;
use wasmtime::component::Component;

#[test]
fn service_components_link_without_host_authority() {
    let engine = device_engine().expect("engine");
    let linker = wasmtime::component::Linker::<()>::new(&engine);
    let artifacts = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/target/wasm-components/release");
    for (package, artifact) in [
        ("terra-mmio-component", "terra_mmio_component.wasm"),
        (
            "terra-interrupt-controller-component",
            "terra_interrupt_controller_component.wasm",
        ),
    ] {
        let component = Component::from_file(&engine, artifacts.join(artifact))
            .expect("built service component");
        linker
            .instantiate_pre(&component)
            .map_err(|error| format!("{package} requested host authority: {error:#}"))
            .expect("service links without host authority");
    }
}
