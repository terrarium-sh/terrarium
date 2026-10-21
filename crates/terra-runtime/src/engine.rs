//! Wasmtime engine configuration and component precompilation.

use std::sync::Arc;
use wasmtime::{Config, Engine, Store};

/// Fuel a store burns before yielding to the async executor, so long-running wasm cannot
/// starve the stores and host tasks that share its thread.
const FUEL_YIELD_INTERVAL: u64 = 10_000_000;

/// Engine for device stores with fuel-driven yielding and async components.
pub fn device_engine() -> wasmtime::Result<Engine> {
    let mut config = Config::new();
    apply_device_settings(&mut config)?;
    Engine::new(&config)
}

fn apply_device_settings(config: &mut Config) -> wasmtime::Result<()> {
    // An explicit host triple disables Wasmtime's CPU feature inference, so
    // embedded AOT components load on any host of the build architecture
    // instead of only hosts matching the build machine's CPU.
    config.target(&target_lexicon::Triple::host().to_string())?;
    config
        .consume_fuel(true)
        .shared_memory(false)
        .wasm_memory64(false)
        .wasm_component_model_threading(false)
        .wasm_component_model_memory64(false)
        .wasm_component_model_async(true)
        .concurrency_support(true)
        .with_custom_code_memory(Some(Arc::new(crate::artifacts::CodeProtection)));
    Ok(())
}

/// A store on the device engine with unlimited fuel that yields to the executor at a fixed
/// fuel interval.
///
/// # Panics
///
/// If `engine` does not consume fuel; every [`device_engine`] does.
#[must_use]
#[allow(clippy::expect_used)]
pub fn device_store<T: 'static>(engine: &Engine, data: T) -> Store<T> {
    let mut store = Store::new(engine, data);
    store
        .set_fuel(u64::MAX)
        .expect("the device engine consumes fuel");
    store
        .fuel_async_yield_interval(Some(FUEL_YIELD_INTERVAL))
        .expect("the device engine consumes fuel");
    store
}

/// Precompile a trusted component build into an AOT artifact for
/// embedding. The shipped runtime deserializes these bytes without
/// invoking the compiler.
#[cfg(any(test, feature = "compiler"))]
pub fn precompile_component(engine: &Engine, bytes: &[u8]) -> wasmtime::Result<Vec<u8>> {
    engine.precompile_component(bytes)
}

#[cfg(test)]
mod tests {
    #[test]
    fn device_engine_rejects_unused_memory_models() {
        let engine = super::device_engine().expect("engine");
        for module in ["(module (memory i64 1))", "(module (memory 1 1 shared))"] {
            assert!(wasmtime::Module::new(&engine, module).is_err());
        }
        wasmtime::Module::new(&engine, "(module (memory 1))").expect("ordinary memory");
    }

    /// [`crate::artifacts::CodeProtection`] publishes code without `PROT_BTI`,
    /// which is sound only while device artifacts are compiled without branch
    /// target identification.
    #[test]
    fn precompiled_artifacts_do_not_request_branch_protection() {
        use object::{Object as _, ObjectSection as _};
        let engine = super::device_engine().expect("engine");
        let artifact = super::precompile_component(&engine, b"(component)").expect("compiles");
        let elf = object::File::parse(artifact.as_slice()).expect("ELF artifact");
        let bti = elf.section_by_name(".wasmtime.bti").expect("BTI section");
        assert_eq!(bti.data().expect("BTI flag"), [0]);
    }

    /// A precompiled artifact must not enable CPU features of the machine that
    /// produced it, or it fails to load on older hosts of the same architecture.
    #[test]
    #[allow(unsafe_code)]
    fn precompiled_artifacts_do_not_require_build_machine_cpu_features() {
        let producer = super::device_engine().expect("engine");
        let artifact = super::precompile_component(&producer, b"(component)").expect("compiles");
        let mut config = wasmtime::Config::new();
        super::apply_device_settings(&mut config).expect("settings");
        // SAFETY: the probe only gates ISA flags recorded in the artifact, and
        // denying every feature is exactly a host weaker than the producer's.
        unsafe {
            config.detect_host_feature(|_| Some(false));
        }
        let consumer = wasmtime::Engine::new(&config).expect("engine");
        // SAFETY: the artifact was produced by the trusted engine above.
        unsafe { wasmtime::component::Component::deserialize(&consumer, &artifact) }
            .expect("artifact is host-feature-free");
    }
}
