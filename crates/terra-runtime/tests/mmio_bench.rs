#![allow(clippy::expect_used)]

#[path = "support/artifacts.rs"]
mod support;

use std::time::{Duration, Instant};

use terra_runtime::box_runtime::{BoxHost, BoxRuntime, BoxRuntimeHandle};
use terra_runtime::component::InterruptCallback;
use terra_runtime::component::block::BlockHost;
use terra_runtime::component::block::backing::{BoundedDisk, DiskGrant};
use terra_runtime::component::context::DeviceContext;
use terra_runtime::engine::device_engine;
use terra_runtime::memory::GuestRam;

const WARMUP_SAMPLES: usize = 128;
const SEQUENTIAL_SAMPLES: usize = 2048;
const CONCURRENT_CALLERS: usize = 4;
const CONCURRENT_SAMPLES_PER_CALLER: usize = 512;
const SUSTAINED_ATTEMPTS: usize = 2048;
const MAGIC: [u8; 4] = 0x7472_6976_u32.to_le_bytes();

struct RunningMemory {
    channel: terra_runtime::component::MmioDevice,
    runtime: BoxRuntimeHandle,
}

struct RunningDevices {
    channels: [terra_runtime::component::MmioDevice; 2],
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

fn print_throughput(scenario: &str, requests: usize, elapsed: Duration) {
    println!(
        "terra_mmio_bench scenario={scenario} requests={requests} elapsed_ns={} throughput_ops_per_s={}",
        elapsed.as_nanos(),
        u128::from(requests as u64) * 1_000_000_000 / elapsed.as_nanos(),
    );
}

fn print_idle_runtime(scenario: &str) {
    #[cfg(not(target_os = "linux"))]
    let _ = scenario;

    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").expect("process status");
        let value = |name| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .expect("process status field")
                .split_whitespace()
                .next()
                .expect("process status value")
        };
        println!(
            "terra_mmio_bench scenario={scenario} process_rss_kib={} process_threads={}",
            value("VmRSS:"),
            value("Threads:"),
        );
    }
}

fn read_magic(channel: &terra_runtime::component::MmioDevice) -> wasmtime::Result<()> {
    let bytes = channel.read(0, 4)?;
    (bytes == MAGIC)
        .then_some(())
        .ok_or_else(|| wasmtime::Error::msg("MMIO magic changed"))
}

fn read_error(
    channel: &terra_runtime::component::MmioDevice,
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
    channel: &terra_runtime::component::MmioDevice,
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

async fn sustained_probe() -> wasmtime::Result<()> {
    let (_, memory) = start_memory().await;
    for attempted in 1..=SUSTAINED_ATTEMPTS {
        if let Err(error) = read_magic(&memory.channel) {
            let (completed, failed) = memory.channel.request_counts();
            println!(
                "terra_mmio_bench scenario=sustained attempts={attempted} completed={completed} failed={failed} outcome=failed error={error:?}"
            );
            memory.runtime.abort_and_join().await;
            return Err(error);
        }
    }
    let (completed, failed) = memory.channel.request_counts();
    println!(
        "terra_mmio_bench scenario=sustained attempts={SUSTAINED_ATTEMPTS} completed={completed} failed={failed} outcome=completed cause=none"
    );
    memory.channel.close().expect("sustained close");
    memory.runtime.join().await.expect("sustained shutdown");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sustained_aot_memory_mmio_reads_complete() {
    sustained_probe().await.expect("sustained MMIO reads");
}

async fn start_memory() -> (Duration, RunningMemory) {
    let start = Instant::now();
    let engine = device_engine().expect("engine");
    let mmio = support::artifacts::trusted_artifacts()
        .mmio()
        .deserialize(&engine)
        .expect("MMIO service artifact");
    let component = support::artifacts::trusted_artifacts()
        .mem()
        .deserialize(&engine)
        .expect("memory artifact");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime.initialize_mmio(&mmio).await.expect("MMIO service");
    let interrupt: InterruptCallback = std::sync::Arc::new(|_| Ok(()));
    let channel = terra_runtime::component::mem::register_device(
        &mut runtime,
        DeviceContext::with_ram(GuestRam::new(64 * 1024).expect("RAM")),
        &component,
        interrupt,
    )
    .expect("memory device");
    let runtime = runtime.prepare().await.expect("runtime prepared").start();
    (start.elapsed(), RunningMemory { channel, runtime })
}

async fn shutdown_memory(memory: RunningMemory, scenario: &str) {
    let start = Instant::now();
    memory.channel.close().expect("memory close");
    memory.runtime.join().await.expect("runtime shutdown");
    println!(
        "terra_mmio_bench scenario={scenario} samples=1 elapsed_ns={}",
        start.elapsed().as_nanos()
    );
}

async fn start_memory_and_block() -> RunningDevices {
    let engine = device_engine().expect("engine");
    let mmio = support::artifacts::trusted_artifacts()
        .mmio()
        .deserialize(&engine)
        .expect("MMIO service artifact");
    let memory_component = support::artifacts::trusted_artifacts()
        .mem()
        .deserialize(&engine)
        .expect("memory artifact");
    let block_component = support::artifacts::trusted_artifacts()
        .block()
        .deserialize(&engine)
        .expect("block artifact");
    let ram = GuestRam::new(64 * 1024).expect("RAM");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime.initialize_mmio(&mmio).await.expect("MMIO service");
    let interrupt: InterruptCallback = std::sync::Arc::new(|_| Ok(()));
    let block = terra_runtime::component::block::register_device(
        &mut runtime,
        BlockHost::new(ram.clone(), DiskGrant::Mem(BoundedDisk::new(4096, false))),
        &block_component,
        false,
        std::sync::Arc::clone(&interrupt),
    )
    .expect("block device");
    let memory = terra_runtime::component::mem::register_device(
        &mut runtime,
        DeviceContext::with_ram(ram),
        &memory_component,
        interrupt,
    )
    .expect("memory device");
    RunningDevices {
        channels: [block, memory],
        runtime: runtime.prepare().await.expect("runtime prepared").start(),
    }
}

async fn shutdown_devices(devices: RunningDevices) {
    let start = Instant::now();
    for channel in &devices.channels {
        channel.close().expect("device close");
    }
    devices.runtime.join().await.expect("runtime shutdown");
    println!(
        "terra_mmio_bench scenario=concurrent_devices_shutdown samples=1 elapsed_ns={}",
        start.elapsed().as_nanos()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "microbenchmark: run with --release --ignored --nocapture"]
async fn warmed_aot_memory_mmio_reads() {
    sustained_probe().await.expect("sustained MMIO reads");
    let (setup, memory) = start_memory().await;
    println!(
        "terra_mmio_bench scenario=setup samples=1 elapsed_ns={}",
        setup.as_nanos()
    );
    print_idle_runtime("idle_one_device");

    let _ = read_samples(&memory.channel, WARMUP_SAMPLES, "warmup").expect("warmup MMIO reads");

    let start = Instant::now();
    let mut sequential = read_samples(&memory.channel, SEQUENTIAL_SAMPLES, "sequential")
        .expect("sequential MMIO reads");
    print_samples("sequential", &mut sequential);
    print_throughput("sequential", SEQUENTIAL_SAMPLES, start.elapsed());

    let mut concurrent = Vec::with_capacity(CONCURRENT_CALLERS * CONCURRENT_SAMPLES_PER_CALLER);
    let mut callers = Vec::with_capacity(CONCURRENT_CALLERS);
    let start = Instant::now();
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
    print_throughput(
        "concurrent",
        CONCURRENT_CALLERS * CONCURRENT_SAMPLES_PER_CALLER,
        start.elapsed(),
    );

    shutdown_memory(memory, "shutdown").await;

    let devices = start_memory_and_block().await;
    print_idle_runtime("idle_two_devices");
    let start = Instant::now();
    let mut callers = Vec::with_capacity(devices.channels.len());
    for channel in &devices.channels {
        let channel = channel.clone();
        callers.push(tokio::task::spawn_blocking(move || {
            read_samples(
                &channel,
                CONCURRENT_SAMPLES_PER_CALLER,
                "concurrent_devices",
            )
            .expect("concurrent device MMIO reads")
        }));
    }
    let mut concurrent_devices =
        Vec::with_capacity(devices.channels.len() * CONCURRENT_SAMPLES_PER_CALLER);
    for caller in callers {
        concurrent_devices.extend(caller.await.expect("concurrent device caller"));
    }
    print_samples("concurrent_devices", &mut concurrent_devices);
    print_throughput(
        "concurrent_devices",
        devices.channels.len() * CONCURRENT_SAMPLES_PER_CALLER,
        start.elapsed(),
    );
    shutdown_devices(devices).await;
}
