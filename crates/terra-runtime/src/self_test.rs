//! Exercise the production device runtime without starting a virtual machine.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::TrustedArtifacts;
use crate::box_runtime::{BoxHost, BoxRuntime};
use crate::component::MmioDevice;
use crate::component::block::backing::{DiskGrant, FileDisk};
use crate::component::context::DeviceContext;
use crate::memory::{BoundedMemory, GuestRam};

mod agent;
mod boot;
mod filesystem;
pub mod network;
pub mod network_stream;
mod vsock;

const FIXTURE_STARTUP_WAIT: Duration = Duration::from_secs(120);

pub struct AgentListeners {
    pub control: terra_platform::io::local::LocalListener,
    pub agent: terra_platform::io::local::LocalListener,
}

pub async fn run_self_test(artifacts: TrustedArtifacts, directory: &Path) -> wasmtime::Result<()> {
    let engine = crate::engine::device_engine()?;
    boot::run(&artifacts, &engine)
        .await
        .map_err(|error| error.context("boot self-test"))?;
    vsock::run(&artifacts, &engine)
        .await
        .map_err(|error| error.context("vsock frontend self-test"))?;
    exercise_storage_and_memory(&artifacts, &engine, directory)
        .await
        .map_err(|error| error.context("storage and memory self-test"))?;
    filesystem::run(&artifacts, &engine, directory)
        .await
        .map_err(|error| error.context("filesystem self-test"))?;
    network::run(&artifacts, &engine)
        .await
        .map_err(|error| error.context("network self-test"))?;
    agent::run(&artifacts, &engine, directory)
        .await
        .map_err(|error| error.context("agent self-test"))?;
    Ok(())
}

pub async fn run_self_test_with_network(
    artifacts: TrustedArtifacts,
    directory: &Path,
    backend: crate::component::network::NetworkBackend,
    endpoints: network::Endpoints,
    agent_listeners: Option<AgentListeners>,
) -> wasmtime::Result<()> {
    let engine = crate::engine::device_engine()?;
    boot::run(&artifacts, &engine)
        .await
        .map_err(|error| error.context("boot self-test"))?;
    vsock::run(&artifacts, &engine)
        .await
        .map_err(|error| error.context("vsock frontend self-test"))?;
    exercise_storage_and_memory(&artifacts, &engine, directory)
        .await
        .map_err(|error| error.context("storage and memory self-test"))?;
    filesystem::run(&artifacts, &engine, directory)
        .await
        .map_err(|error| error.context("filesystem self-test"))?;
    network::run_with_backend(&artifacts, &engine, backend, endpoints)
        .await
        .map_err(|error| error.context("network self-test"))?;
    agent::run_with_external_clients(&artifacts, &engine, directory, agent_listeners)
        .await
        .map_err(|error| error.context("agent self-test"))
}

pub fn run_agent_clients(directory: &Path) -> wasmtime::Result<()> {
    agent::run_clients(directory)
}

pub async fn run_self_test_local_only(
    artifacts: TrustedArtifacts,
    directory: &Path,
    agent_listeners: Option<AgentListeners>,
) -> wasmtime::Result<()> {
    let engine = crate::engine::device_engine()?;
    boot::run(&artifacts, &engine)
        .await
        .map_err(|error| error.context("boot self-test"))?;
    vsock::run(&artifacts, &engine)
        .await
        .map_err(|error| error.context("vsock frontend self-test"))?;
    exercise_storage_and_memory(&artifacts, &engine, directory).await?;
    filesystem::run(&artifacts, &engine, directory).await?;
    agent::run_with_external_clients(&artifacts, &engine, directory, agent_listeners).await
}

const DESCRIPTORS: u64 = 0x1000;
const AVAILABLE: u64 = 0x2000;
const USED: u64 = 0x3000;
const HEADER: u64 = 0x4000;
const DATA: u64 = 0x5000;
const STATUS: u64 = 0x6000;
const QUEUE_SIZE: u16 = 8;
const RECLAIM_ADDRESS: u64 = 64 * 1024;
const RECLAIM_BYTES: u32 = 64 * 1024;

fn write_memory(ram: &GuestRam, address: u64, bytes: &[u8]) -> wasmtime::Result<()> {
    BoundedMemory::new(ram)
        .write(address, bytes)
        .map_err(|error| wasmtime::Error::msg(format!("self-test memory write: {error:?}")))
}

fn read_memory(ram: &GuestRam, address: u64, length: u64) -> wasmtime::Result<Vec<u8>> {
    BoundedMemory::new(ram)
        .read(address, length)
        .map_err(|error| wasmtime::Error::msg(format!("self-test memory read: {error:?}")))
}

fn configure_queue(device: &MmioDevice, queue: u32, features: u32) -> wasmtime::Result<()> {
    for (offset, value) in [
        (0x70, 1),
        (0x70, 3),
        (0x24, 0),
        (0x20, features),
        (0x24, 1),
        (0x20, 1),
        (0x70, 11),
        (0x30, queue),
        (0x38, u32::from(QUEUE_SIZE)),
        (0x80, u32::try_from(DESCRIPTORS)?),
        (0x90, u32::try_from(AVAILABLE)?),
        (0xa0, u32::try_from(USED)?),
        (0x44, 1),
        (0x70, 15),
    ] {
        device.write(offset, &value.to_le_bytes())?;
    }
    Ok(())
}

async fn submit_descriptors(
    device: &MmioDevice,
    ram: &GuestRam,
    queue: u32,
    index: u16,
    descriptors: &[(u64, u32, u16)],
) -> wasmtime::Result<()> {
    for (slot, &(address, length, flags)) in descriptors.iter().enumerate() {
        let mut descriptor = [0; 16];
        descriptor[..8].copy_from_slice(&address.to_le_bytes());
        descriptor[8..12].copy_from_slice(&length.to_le_bytes());
        descriptor[12..14].copy_from_slice(&flags.to_le_bytes());
        descriptor[14..].copy_from_slice(&u16::try_from(slot + 1)?.to_le_bytes());
        write_memory(ram, DESCRIPTORS + u64::try_from(slot)? * 16, &descriptor)?;
    }
    write_memory(
        ram,
        AVAILABLE + 4 + u64::from(index % QUEUE_SIZE) * 2,
        &[0; 2],
    )?;
    write_memory(ram, AVAILABLE + 2, &index.wrapping_add(1).to_le_bytes())?;
    device.write(0x50, &queue.to_le_bytes())?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while read_memory(ram, USED + 2, 2)? != index.wrapping_add(1).to_le_bytes() {
            if let Some(error) = device.failure() {
                wasmtime::bail!("self-test device failed: {error}");
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        wasmtime::Result::Ok(())
    })
    .await??;
    device.write(0x64, &1_u32.to_le_bytes())?;
    Ok(())
}

async fn submit_block(
    device: &MmioDevice,
    ram: &GuestRam,
    index: u16,
    operation: u32,
    data: &[u8],
) -> wasmtime::Result<Vec<u8>> {
    let mut header = [0; 16];
    header[..4].copy_from_slice(&operation.to_le_bytes());
    write_memory(ram, HEADER, &header)?;
    write_memory(ram, DATA, data)?;
    write_memory(ram, STATUS, &[0xff])?;
    let mut descriptors = vec![(HEADER, 16, 1)];
    if !data.is_empty() {
        descriptors.push((
            DATA,
            u32::try_from(data.len())?,
            if operation == 1 || operation == 11 {
                1
            } else {
                3
            },
        ));
    }
    descriptors.push((STATUS, 1, 2));
    submit_descriptors(device, ram, 0, index, &descriptors).await?;
    let status = read_memory(ram, STATUS, 1)?;
    wasmtime::ensure!(
        status == [0],
        "block self-test request {index} (operation {operation}) failed with status {}",
        status[0]
    );
    read_memory(ram, DATA, u64::try_from(data.len())?)
}

async fn exercise_storage_and_memory(
    artifacts: &TrustedArtifacts,
    engine: &wasmtime::Engine,
    directory: &Path,
) -> wasmtime::Result<()> {
    let disk_path = directory.join("disk.img");
    std::fs::File::create(&disk_path)?.set_len(64 * 1024)?;
    let block_ram = GuestRam::new(64 * 1024)
        .ok_or_else(|| wasmtime::Error::msg("allocating block self-test memory"))?;
    let memory_ram = GuestRam::new(128 * 1024)
        .ok_or_else(|| wasmtime::Error::msg("allocating memory self-test memory"))?;
    let mut runtime = BoxRuntime::new(engine, BoxHost::new())?;
    runtime.initialize_mmio()?;
    let block = crate::component::block::register_device(
        &mut runtime,
        crate::component::block::BlockHost::new(
            block_ram.clone(),
            DiskGrant::File(FileDisk::open(&disk_path, false)?),
        ),
        &artifacts.block().deserialize(engine)?,
        false,
        Arc::new(|_| Ok(())),
    )?;
    let memory = crate::component::mem::register_device(
        &mut runtime,
        DeviceContext::with_ram(memory_ram.clone()),
        &artifacts.mem().deserialize(engine)?,
        Arc::new(|_| Ok(())),
    )?;
    let runtime = runtime.prepare().await?.start();
    let result = async {
        configure_queue(&block, 0, (1 << 9) | (1 << 13))?;
        let bytes = [0xa5; 512];
        submit_block(&block, &block_ram, 0, 1, &bytes).await?;
        submit_block(&block, &block_ram, 1, 4, &[]).await?;
        wasmtime::ensure!(
            submit_block(&block, &block_ram, 2, 0, &[0; 512]).await? == bytes,
            "block self-test read disagrees with its write"
        );
        wasmtime::ensure!(
            std::fs::read(&disk_path)?[..512] == bytes,
            "block self-test flush did not persist"
        );
        let mut discard = [0; 16];
        discard[8..12].copy_from_slice(&8_u32.to_le_bytes());
        submit_block(&block, &block_ram, 3, 11, &discard).await?;
        configure_queue(&memory, 2, (1 << 4) | (1 << 5))?;
        for offset in (0..u64::from(RECLAIM_BYTES)).step_by(4096) {
            write_memory(&memory_ram, RECLAIM_ADDRESS + offset, &[0x5a; 4096])?;
        }
        tokio::time::sleep(Duration::from_millis(1200)).await;
        submit_descriptors(
            &memory,
            &memory_ram,
            2,
            0,
            &[(RECLAIM_ADDRESS, RECLAIM_BYTES, 2)],
        )
        .await?;
        #[cfg(target_os = "linux")]
        for offset in (0..u64::from(RECLAIM_BYTES)).step_by(4096) {
            wasmtime::ensure!(
                read_memory(&memory_ram, RECLAIM_ADDRESS + offset, 4096)? == [0; 4096],
                "memory self-test did not reclaim the reported page"
            );
        }
        for device in [&block, &memory] {
            device.write(0x70, &0_u32.to_le_bytes())?;
            wasmtime::ensure!(
                device.read(0, 4)? == 0x7472_6976_u32.to_le_bytes(),
                "self-test device reset failed"
            );
        }
        wasmtime::Result::Ok(())
    }
    .await;
    block.close()?;
    memory.close()?;
    runtime.join().await?;
    result
}

#[cfg(test)]
mod tests {
    #[tokio::test(flavor = "multi_thread")]
    async fn production_devices_run_without_virtualization() {
        let directory = tempfile::tempdir().unwrap();
        super::run_self_test(crate::test_fixtures::trusted_artifacts(), directory.path())
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn agent_uses_trusted_listeners_without_binding_in_the_vm() {
        use terra_platform::io::local::LocalListener;

        let directory = tempfile::tempdir().unwrap();
        let listeners = super::AgentListeners {
            control: LocalListener::bind(directory.path().join("agent-control.sock")).unwrap(),
            agent: LocalListener::bind(directory.path().join("agent-agent.sock")).unwrap(),
        };
        let client_directory = directory.path().to_owned();
        let clients =
            tokio::task::spawn_blocking(move || super::run_agent_clients(&client_directory));
        super::agent::run_with_external_clients(
            &crate::test_fixtures::trusted_artifacts(),
            &crate::engine::device_engine().unwrap(),
            &directory.path().join("absent-directory"),
            Some(listeners),
        )
        .await
        .unwrap();
        clients.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn local_only_devices_run_without_a_network_backend() {
        use terra_platform::io::local::LocalListener;

        let directory = tempfile::tempdir().unwrap();
        let listeners = super::AgentListeners {
            control: LocalListener::bind(directory.path().join("agent-control.sock")).unwrap(),
            agent: LocalListener::bind(directory.path().join("agent-agent.sock")).unwrap(),
        };
        let client_directory = directory.path().to_owned();
        let clients =
            tokio::task::spawn_blocking(move || super::run_agent_clients(&client_directory));
        super::run_self_test_local_only(
            crate::test_fixtures::trusted_artifacts(),
            directory.path(),
            Some(listeners),
        )
        .await
        .unwrap();
        clients.await.unwrap().unwrap();
    }
}
