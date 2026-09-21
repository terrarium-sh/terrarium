//! Wasmtime engine configuration and component precompilation.

use wasmtime::{Config, Engine};

/// Engine for device stores with epoch interruption and async components.
pub fn device_engine() -> wasmtime::Result<Engine> {
    configured_device_engine(false)
}

pub fn policy_engine() -> wasmtime::Result<Engine> {
    configured_device_engine(true)
}

fn configured_device_engine(fuel: bool) -> wasmtime::Result<Engine> {
    let mut config = Config::new();
    apply_device_settings(&mut config, fuel)?;
    Engine::new(&config)
}

fn apply_device_settings(config: &mut Config, fuel: bool) -> wasmtime::Result<()> {
    // An explicit host triple disables Wasmtime's CPU feature inference, so
    // embedded AOT components load on any host of the build architecture
    // instead of only hosts matching the build machine's CPU.
    config.target(&target_lexicon::Triple::host().to_string())?;
    #[cfg(feature = "thread-experiments")]
    config.wasm_threads(false);
    config
        .consume_fuel(fuel)
        .epoch_interruption(true)
        .shared_memory(false)
        .wasm_memory64(false)
        .wasm_component_model_threading(false)
        .wasm_component_model_memory64(false)
        .wasm_component_model_async(true)
        .concurrency_support(true);
    Ok(())
}

/// Precompile a trusted component build into an AOT artifact for
/// embedding. The shipped runtime deserializes these bytes without
/// invoking the compiler.
#[cfg(any(test, feature = "compiler", feature = "test-support"))]
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

    /// A precompiled artifact must not enable CPU features of the machine that
    /// produced it, or it fails to load on older hosts of the same architecture.
    #[test]
    #[allow(unsafe_code)]
    fn precompiled_artifacts_do_not_require_build_machine_cpu_features() {
        let producer = super::device_engine().expect("engine");
        let artifact = super::precompile_component(&producer, b"(component)").expect("compiles");
        let mut config = wasmtime::Config::new();
        super::apply_device_settings(&mut config, false).expect("settings");
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
