#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/artifacts.rs"]
mod support;

use std::sync::Arc;
use std::time::Duration;

use terra_runtime::box_runtime::BoxRuntime;
use terra_runtime::box_runtime::store::BoxHost;
use terra_runtime::component::Interrupt;
use terra_runtime::component::vsock::VsockChannel;
use terra_runtime::engine::device_engine;
use terra_runtime::memory::{BoundedMemory, GuestRam};
use terra_vsock_device::{
    CONTROL_VSOCK_PORT, GUEST_CID, HOST_CID, VSOCK_HEADER_BYTES, VsockHeader,
};
use wasmtime::component::Component;

const QUEUE_SIZE: u32 = 16;
const RX_BUFFERS: u16 = 16;
const RX_DESC: u64 = 0x1000;
const RX_AVAIL: u64 = 0x2000;
const RX_USED: u64 = 0x3000;
const RX_DATA: u64 = 0x4000;
const TX_DESC: u64 = 0x1_5000;
const TX_AVAIL: u64 = 0x1_6000;
const TX_USED: u64 = 0x1_7000;
const TX_DATA: u64 = 0x1_8000;
const PACKET_BYTES: usize = 4096;
const EXPECTED_REPLIES: u16 = 9;

fn no_interrupt() -> Interrupt {
    Arc::new(|_| Ok(()))
}

fn write_memory(memory: &BoundedMemory<'_>, address: u64, bytes: &[u8]) {
    memory.write(address, bytes).expect("guest memory write");
}

fn read_memory(memory: &BoundedMemory<'_>, address: u64, len: usize) -> Vec<u8> {
    memory
        .read(address, u64::try_from(len).expect("memory length"))
        .expect("guest memory read")
}

fn write_word(channel: &VsockChannel, offset: u64, value: u32) {
    channel
        .write_mmio(offset, &value.to_le_bytes())
        .expect("MMIO write");
}

fn configure_queue(channel: &VsockChannel, queue: u32, desc: u64, avail: u64, used: u64) {
    write_word(channel, 0x30, queue);
    write_word(channel, 0x38, QUEUE_SIZE);
    write_word(
        channel,
        0x80,
        u32::try_from(desc).expect("descriptor address"),
    );
    write_word(
        channel,
        0x90,
        u32::try_from(avail).expect("available address"),
    );
    write_word(channel, 0xa0, u32::try_from(used).expect("used address"));
    write_word(channel, 0x44, 1);
}

fn configure_transport(channel: &VsockChannel) {
    for (offset, value) in [(0x70, 1), (0x70, 3), (0x24, 1), (0x20, 1), (0x70, 11)] {
        write_word(channel, offset, value);
    }
    configure_queue(channel, 0, RX_DESC, RX_AVAIL, RX_USED);
    configure_queue(channel, 1, TX_DESC, TX_AVAIL, TX_USED);
    write_word(channel, 0x70, 15);
}

fn descriptor(address: u64, len: u32, flags: u16) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&address.to_le_bytes());
    bytes[8..12].copy_from_slice(&len.to_le_bytes());
    bytes[12..14].copy_from_slice(&flags.to_le_bytes());
    bytes
}

fn post_receive_buffers(memory: &BoundedMemory<'_>) {
    for index in 0..RX_BUFFERS {
        let descriptor_offset = RX_DESC + u64::from(index) * 16;
        let packet_offset = RX_DATA + u64::from(index) * PACKET_BYTES as u64;
        write_memory(
            memory,
            descriptor_offset,
            &descriptor(
                packet_offset,
                u32::try_from(PACKET_BYTES).expect("packet size"),
                2,
            ),
        );
        write_memory(
            memory,
            RX_AVAIL + 4 + u64::from(index) * 2,
            &index.to_le_bytes(),
        );
    }
    write_memory(memory, RX_AVAIL + 2, &RX_BUFFERS.to_le_bytes());
}

fn post_request(memory: &BoundedMemory<'_>) {
    let header = VsockHeader {
        src_cid: GUEST_CID,
        dst_cid: HOST_CID,
        src_port: 7000,
        dst_port: CONTROL_VSOCK_PORT,
        len: 0,
        type_: 1,
        op: 1,
        flags: 0,
        buf_alloc: 65536,
        fwd_cnt: 0,
    };
    write_memory(memory, TX_DATA, &header.encode());
    write_memory(
        memory,
        TX_DESC,
        &descriptor(
            TX_DATA,
            u32::try_from(VSOCK_HEADER_BYTES).expect("header size"),
            0,
        ),
    );
    write_memory(memory, TX_AVAIL + 2, &1_u16.to_le_bytes());
}

fn used_index(memory: &BoundedMemory<'_>) -> u16 {
    u16::from_le_bytes(
        read_memory(memory, RX_USED + 2, 2)
            .try_into()
            .expect("used index"),
    )
}

async fn wait_for_replies(memory: &BoundedMemory<'_>) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while used_index(memory) < EXPECTED_REPLIES {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("host replies drain without another receive bell");
}

fn replies(memory: &BoundedMemory<'_>) -> Vec<(VsockHeader, Vec<u8>)> {
    (0..used_index(memory))
        .map(|slot| {
            let entry = read_memory(memory, RX_USED + 4 + u64::from(slot) * 8, 8);
            let head = u32::from_le_bytes(entry[..4].try_into().expect("used head"));
            let len = u32::from_le_bytes(entry[4..].try_into().expect("used length"));
            let packet_address = RX_DATA + u64::from(head) * PACKET_BYTES as u64;
            let packet = read_memory(memory, packet_address, len as usize);
            let (header, payload) = VsockHeader::parse(&packet).expect("vsock response header");
            (header, payload.to_vec())
        })
        .collect()
}

fn plan_frame() -> Vec<u8> {
    let payload = format!(r#"{{"pad":"{}"}}"#, "x".repeat(20 * 1024)).into_bytes();
    let mut frame = u32::try_from(payload.len())
        .expect("plan length")
        .to_le_bytes()
        .to_vec();
    frame.extend_from_slice(&payload);
    frame
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn posted_receive_queue_drains_handshake_and_plan_without_a_second_bell() {
    let engine = device_engine().expect("engine");
    let router = Component::new(&engine, support::artifacts::wasm::VMM).expect("MMIO router");
    let ram = GuestRam::new(256 * 1024).expect("RAM");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime.initialize_mmio(&router).await.expect("MMIO router");
    let artifact = support::artifacts::trusted_artifacts().vsock();
    let channel = VsockChannel::from_trusted_artifact(
        &mut runtime,
        ram.clone(),
        artifact,
        plan_frame(),
        None,
        None,
        None,
        no_interrupt(),
    )
    .expect("vsock");
    let runtime = runtime.prepare().await.expect("runtime prepared").start();
    let memory = BoundedMemory::new(&ram);

    configure_transport(&channel);
    post_receive_buffers(&memory);
    write_word(&channel, 0x50, 0);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(used_index(&memory), 0, "empty receive queue stays posted");

    post_request(&memory);
    write_word(&channel, 0x50, 1);
    wait_for_replies(&memory).await;

    let delivered = replies(&memory);
    assert!(
        delivered.iter().any(|(header, _)| header.op == 2),
        "handshake response reaches the already-posted receive queue"
    );
    assert!(
        delivered
            .iter()
            .any(|(header, payload)| header.op == 5 && !payload.is_empty()),
        "plan packets reach the already-posted receive queue"
    );

    channel.close_async().await.expect("vsock close");
    tokio::time::timeout(Duration::from_secs(5), runtime.join())
        .await
        .expect("runtime shutdown deadline")
        .expect("runtime shutdown");
}
