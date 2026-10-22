use crate::support;
use std::sync::Arc;
use terra_runtime::box_runtime::{BoxHost, BoxRuntime};
use terra_runtime::component::AccessMode;
use terra_runtime::component::block::BlockHost;
use terra_runtime::component::block::backing::{BoundedDisk, DiskGrant};
use terra_runtime::engine::device_engine;
use terra_runtime::memory::{BoundedMemory, GuestRam};
use terra_runtime::test_support::virtio;
use wasmtime::component::Component;

const RAM_BYTES: u64 = 128 * 1024;
const DESC: u64 = 0x1000;
const AVAIL: u64 = 0x2000;
const USED: u64 = 0x3000;
const HEADER: u64 = 0x4000;
const DATA: u64 = 0x5000;
const STATUS: u64 = 0x6000;
const T_IN: u32 = 0;
const NEXT: u16 = 1;
const WRITE: u16 = 2;

fn descriptor(addr: u64, len: u32, flags: u16, next: u16) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&addr.to_le_bytes());
    bytes[8..12].copy_from_slice(&len.to_le_bytes());
    bytes[12..14].copy_from_slice(&flags.to_le_bytes());
    bytes[14..16].copy_from_slice(&next.to_le_bytes());
    bytes
}

/// Publishes `chain` as available entry `index` and waits for the device to use it.
async fn submit(
    channel: &terra_runtime::component::MmioDevice,
    memory: &BoundedMemory<'_>,
    index: u16,
    chain: &[[u8; 16]],
) {
    memory.write(DESC, &chain.concat()).expect("descriptors");
    memory
        .write(AVAIL + 4 + u64::from(index % 8) * 2, &0_u16.to_le_bytes())
        .expect("available entry");
    memory
        .write(AVAIL + 2, &index.wrapping_add(1).to_le_bytes())
        .expect("available index");
    channel
        .write(virtio::QUEUE_NOTIFY, &0_u32.to_le_bytes())
        .expect("queue bell");
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while memory.read(USED + 2, 2).expect("used index") != index.wrapping_add(1).to_le_bytes() {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("block request completion");
}

/// A malformed header whose status byte points outside guest memory cannot be answered; the
/// request must still be used, or the device would retry it forever and stall the guest's disk.
#[tokio::test(flavor = "multi_thread")]
async fn unanswerable_requests_are_used_and_the_queue_keeps_serving() {
    let ram = GuestRam::new(RAM_BYTES).expect("ram");
    let engine = device_engine().expect("engine");
    let component = Component::new(&engine, support::artifacts::wasm::BLOCK).expect("component");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime.initialize_mmio().expect("MMIO service");
    let channel = terra_runtime::component::block::register_device(
        &mut runtime,
        BlockHost::new(
            ram.clone(),
            DiskGrant::Mem(BoundedDisk::new(4096, AccessMode::ReadWrite)),
        ),
        &component,
        Arc::new(|_| Ok(())),
    )
    .expect("channel");
    let _runtime = runtime.prepare().await.expect("runtime prepared").start();
    virtio::start_single_queue(
        &channel,
        0,
        0,
        virtio::QueueLayout {
            size: 8,
            descriptors: DESC,
            available: AVAIL,
            used: USED,
        },
    )
    .expect("MMIO setup");
    let memory = BoundedMemory::new(&ram);
    submit(
        &channel,
        &memory,
        0,
        &[
            descriptor(HEADER, 8, NEXT, 1),
            descriptor(RAM_BYTES + 0x1000, 1, WRITE, 0),
        ],
    )
    .await;
    let mut header = [0; 16];
    header[..4].copy_from_slice(&T_IN.to_le_bytes());
    memory.write(HEADER, &header).expect("header");
    memory.write(STATUS, &[0xff]).expect("status");
    submit(
        &channel,
        &memory,
        1,
        &[
            descriptor(HEADER, 16, NEXT, 1),
            descriptor(DATA, 512, NEXT | WRITE, 2),
            descriptor(STATUS, 1, WRITE, 0),
        ],
    )
    .await;
    assert_eq!(memory.read(STATUS, 1).expect("status"), [0]);
    channel.close().expect("close");
}
