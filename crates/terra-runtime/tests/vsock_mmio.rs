#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/artifacts.rs"]
mod support;

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::future::poll_fn;
use futures_util::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use terra_runtime::box_runtime::{BoxHost, BoxRuntime};
use terra_runtime::component::InterruptCallback;
use terra_runtime::component::vsock::VsockChannel;
use terra_runtime::engine::device_engine;
use terra_runtime::memory::{BoundedMemory, GuestRam};
use terra_vsock_device::{GUEST_CID, HOST_CID, MUX_VSOCK_PORT, VSOCK_HEADER_BYTES, VsockHeader};
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
const TX_CARRIER_DESC: u16 = 0;
const TX_SYN_DESC: u16 = 1;
const TX_SYN_PAYLOAD_DESC: u16 = 2;
const TX_SYN_HEADER_DATA: u64 = TX_DATA + 0x100;
const TX_SYN_PAYLOAD_DATA: u64 = TX_DATA + 0x200;

fn no_interrupt() -> InterruptCallback {
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

fn descriptor(address: u64, len: u32, flags: u16, next: u16) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&address.to_le_bytes());
    bytes[8..12].copy_from_slice(&len.to_le_bytes());
    bytes[12..14].copy_from_slice(&flags.to_le_bytes());
    bytes[14..16].copy_from_slice(&next.to_le_bytes());
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
                0,
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

fn guest_header(op: u16, len: u32) -> VsockHeader {
    VsockHeader {
        src_cid: GUEST_CID,
        dst_cid: HOST_CID,
        src_port: 7000,
        dst_port: MUX_VSOCK_PORT,
        len,
        type_: 1,
        op,
        flags: 0,
        buf_alloc: 65536,
        fwd_cnt: 0,
    }
}

fn post_carrier_and_syns(memory: &BoundedMemory<'_>, syns: &[u8]) {
    write_memory(memory, TX_DATA, &guest_header(1, 0).encode());
    write_memory(
        memory,
        TX_DESC,
        &descriptor(
            TX_DATA,
            u32::try_from(VSOCK_HEADER_BYTES).expect("header size"),
            0,
            0,
        ),
    );
    write_memory(
        memory,
        TX_SYN_HEADER_DATA,
        &guest_header(5, u32::try_from(syns.len()).expect("SYN size")).encode(),
    );
    write_memory(memory, TX_SYN_PAYLOAD_DATA, syns);
    write_memory(
        memory,
        TX_DESC + u64::from(TX_SYN_DESC) * 16,
        &descriptor(
            TX_SYN_HEADER_DATA,
            u32::try_from(VSOCK_HEADER_BYTES).expect("header size"),
            1,
            TX_SYN_PAYLOAD_DESC,
        ),
    );
    write_memory(
        memory,
        TX_DESC + u64::from(TX_SYN_PAYLOAD_DESC) * 16,
        &descriptor(
            TX_SYN_PAYLOAD_DATA,
            u32::try_from(syns.len()).expect("SYN size"),
            0,
            0,
        ),
    );
    write_memory(memory, TX_AVAIL + 4, &TX_CARRIER_DESC.to_le_bytes());
    write_memory(memory, TX_AVAIL + 6, &TX_SYN_DESC.to_le_bytes());
    write_memory(memory, TX_AVAIL + 2, &2_u16.to_le_bytes());
}

fn used_index(memory: &BoundedMemory<'_>) -> u16 {
    u16::from_le_bytes(
        read_memory(memory, RX_USED + 2, 2)
            .try_into()
            .expect("used index"),
    )
}

async fn wait_for_plan(memory: &BoundedMemory<'_>, plan_bytes: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while replies(memory)
            .iter()
            .filter(|(header, _)| header.op == 5)
            .map(|(_, payload)| payload.len())
            .sum::<usize>()
            < plan_bytes
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("host replies drain without another receive bell");
}

#[derive(Clone, Debug, Default)]
struct CapturedCarrier(Arc<Mutex<Vec<u8>>>);

impl CapturedCarrier {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().expect("captured carrier").clone()
    }
}

impl AsyncRead for CapturedCarrier {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _bytes: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }
}

impl AsyncWrite for CapturedCarrier {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.lock().expect("captured carrier").extend(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn guest_syns() -> Vec<u8> {
    let carrier = CapturedCarrier::default();
    let mut connection = yamux::Connection::new(
        carrier.clone(),
        terra_protocol::mux::yamux_config(),
        yamux::Mode::Client,
    );
    let mut control = poll_fn(|context| connection.poll_new_outbound(context))
        .await
        .expect("control stream");
    let mut diagnostics = poll_fn(|context| connection.poll_new_outbound(context))
        .await
        .expect("diagnostic stream");
    assert_eq!(control.write(&[]).await.expect("control SYN"), 0);
    assert_eq!(diagnostics.write(&[]).await.expect("diagnostic SYN"), 0);
    poll_fn(|context| {
        let status = connection.poll_next_inbound(context);
        assert!(status.is_pending(), "Yamux carrier: {status:?}");
        if carrier.bytes().is_empty() {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    carrier.bytes()
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
    let mut plan = support::artifacts::create_boot_plan();
    plan.sandbox_info = "x".repeat(20 * 1024);
    terra_protocol::encode_frame(&plan).expect("plan encodes")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn posted_receive_queue_drains_handshake_and_plan_without_a_second_bell() {
    let engine = device_engine().expect("engine");
    let mmio = Component::new(&engine, support::artifacts::wasm::MMIO).expect("MMIO service");
    let ram = GuestRam::new(256 * 1024).expect("RAM");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime.initialize_mmio(&mmio).await.expect("MMIO service");
    let artifact = support::artifacts::trusted_artifacts().vsock();
    let plan = plan_frame();
    let channel = VsockChannel::from_trusted_artifact(
        &mut runtime,
        ram.clone(),
        artifact,
        plan.clone(),
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

    let syns = guest_syns().await;
    post_carrier_and_syns(&memory, &syns);
    write_word(&channel, 0x50, 1);
    wait_for_plan(&memory, plan.len()).await;

    let delivered = replies(&memory);
    assert!(
        delivered.iter().any(|(header, _)| header.op == 2),
        "handshake response reaches the already-posted receive queue"
    );
    assert!(
        delivered
            .iter()
            .filter(|(header, _)| header.op == 5)
            .map(|(_, payload)| payload.len())
            .sum::<usize>()
            >= plan.len(),
        "plan packets reach the already-posted receive queue"
    );

    channel.close_async().await.expect("vsock close");
    tokio::time::timeout(Duration::from_secs(5), runtime.join())
        .await
        .expect("runtime shutdown deadline")
        .expect("runtime shutdown");
}
