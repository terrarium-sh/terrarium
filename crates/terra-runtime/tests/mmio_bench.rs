#![allow(clippy::expect_used)]

use std::time::{Duration, Instant};

use terra_runtime::{
    SyntheticRam,
    box_runtime::{BoxHost, BoxRuntime, BoxRuntimeHandle},
    component::Interrupt,
    engine::{DeviceContext, device_engine, trusted_component},
};

const WARMUP_SAMPLES: usize = 128;
const SEQUENTIAL_SAMPLES: usize = 2048;
const CONCURRENT_CALLERS: usize = 4;
const CONCURRENT_SAMPLES_PER_CALLER: usize = 512;
const SATURATION_ATTEMPTS: usize = 2048;
const MAGIC: [u8; 4] = 0x7472_6976_u32.to_le_bytes();

struct RunningMemory {
    channel: terra_runtime::component::DeviceChannel,
    runtime: BoxRuntimeHandle,
}

fn percentile(samples: &mut [Duration], numerator: usize, denominator: usize) -> Duration {
    samples.sort_unstable();
    samples[(samples.len() * numerator).div_ceil(denominator) - 1]
}

fn print_samples(scenario: &str, samples: &mut [Duration]) {
    println!(
        "terra_mmio_bench scenario={scenario} samples={} p50_ns={} p95_ns={} p99_ns={}",
        samples.len(),
        percentile(samples, 1, 2).as_nanos(),
        percentile(samples, 95, 100).as_nanos(),
        percentile(samples, 99, 100).as_nanos(),
    );
}

fn read_magic(channel: &terra_runtime::component::DeviceChannel) -> wasmtime::Result<()> {
    let bytes = channel.read(0, 4)?;
    (bytes == MAGIC)
        .then_some(())
        .ok_or_else(|| wasmtime::Error::msg("MMIO magic changed"))
}

fn read_error(
    channel: &terra_runtime::component::DeviceChannel,
    scenario: &str,
    error: &wasmtime::Error,
) -> wasmtime::Error {
    let (completed, failed) = channel.request_counts();
    wasmtime::Error::msg(format!(
        "{scenario} MMIO read failed: {error}; completed={completed} failed={failed} failure={:?}",
        channel.failure()
    ))
}

fn read_samples(
    channel: &terra_runtime::component::DeviceChannel,
    count: usize,
    scenario: &str,
) -> wasmtime::Result<Vec<Duration>> {
    (0..count)
        .map(|_| {
            let start = Instant::now();
            read_magic(channel).map_err(|error| read_error(channel, scenario, &error))?;
            Ok(start.elapsed())
        })
        .collect()
}

async fn saturation_probe() -> wasmtime::Result<()> {
    let (_, memory) = start_memory().await;
    for attempted in 1..=SATURATION_ATTEMPTS {
        if let Err(error) = read_magic(&memory.channel) {
            let (completed, failed) = memory.channel.request_counts();
            println!(
                "terra_mmio_bench scenario=saturation attempts={attempted} completed={completed} failed={failed} outcome=failed error={error:?}"
            );
            memory.runtime.abort_and_join().await;
            return Err(error);
        }
    }
    let (completed, failed) = memory.channel.request_counts();
    println!(
        "terra_mmio_bench scenario=saturation attempts={SATURATION_ATTEMPTS} completed={completed} failed={failed} outcome=completed cause=none"
    );
    memory.channel.close().expect("saturation close");
    memory.runtime.join().await.expect("saturation shutdown");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sustained_aot_memory_mmio_reads_complete() {
    saturation_probe().await.expect("sustained MMIO reads");
}

async fn start_memory() -> (Duration, RunningMemory) {
    let start = Instant::now();
    let engine = device_engine().expect("engine");
    // SAFETY: these build-embedded artifacts are trusted AOT output for this Wasmtime build.
    #[allow(unsafe_code)]
    let router = unsafe {
        trusted_component(
            &engine,
            include_bytes!("../../../build/terra-vmm-component.cwasm"),
        )
    }
    .expect("MMIO artifact");
    // SAFETY: this build-embedded artifact is trusted AOT output for this Wasmtime build.
    #[allow(unsafe_code)]
    let component = unsafe {
        trusted_component(
            &engine,
            include_bytes!("../../../build/terra-mem-component.cwasm"),
        )
    }
    .expect("memory artifact");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime.initialize_mmio(&router).await.expect("MMIO router");
    let interrupt: Interrupt = std::sync::Arc::new(|_| Ok(()));
    let channel = terra_runtime::component::mem::instantiate_shared(
        &mut runtime,
        DeviceContext::with_ram(SyntheticRam::new(64 * 1024).expect("RAM")),
        &component,
        interrupt,
    )
    .expect("memory device");
    let runtime = runtime.prepare().await.expect("runtime prepared").start();
    (start.elapsed(), RunningMemory { channel, runtime })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "microbenchmark: run with --release --ignored --nocapture"]
async fn warmed_aot_memory_mmio_reads() {
    saturation_probe().await.expect("sustained MMIO reads");
    let (setup, memory) = start_memory().await;
    println!(
        "terra_mmio_bench scenario=setup samples=1 elapsed_ns={}",
        setup.as_nanos()
    );

    let _ = read_samples(&memory.channel, WARMUP_SAMPLES, "warmup").expect("warmup MMIO reads");

    let mut sequential = read_samples(&memory.channel, SEQUENTIAL_SAMPLES, "sequential")
        .expect("sequential MMIO reads");
    print_samples("sequential", &mut sequential);

    let mut concurrent = Vec::with_capacity(CONCURRENT_CALLERS * CONCURRENT_SAMPLES_PER_CALLER);
    let mut callers = Vec::with_capacity(CONCURRENT_CALLERS);
    for _ in 0..CONCURRENT_CALLERS {
        let channel = memory.channel.clone();
        callers.push(tokio::task::spawn_blocking(move || {
            read_samples(&channel, CONCURRENT_SAMPLES_PER_CALLER, "concurrent")
                .expect("concurrent MMIO reads")
        }));
    }
    for caller in callers {
        concurrent.extend(caller.await.expect("MMIO caller"));
    }
    print_samples("concurrent", &mut concurrent);

    memory.channel.close().expect("memory close");
    memory.runtime.join().await.expect("runtime shutdown");
}
