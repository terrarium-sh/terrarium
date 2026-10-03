use std::io::{Read as _, Write as _};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use terra_platform::io::local::{LocalListener, LocalStream};

use crate::box_runtime::{BoxHost, BoxRuntime};
use crate::component::vsock::VsockChannel;
use crate::memory::GuestRam;

use super::{read_memory, write_memory};

const QUEUE_SIZE: u16 = 16;
const RX_DESC: u64 = 0x1000;
const RX_AVAIL: u64 = 0x2000;
const RX_USED: u64 = 0x3000;
const RX_DATA: u64 = 0x4000;
const TX_DESC: u64 = 0x1_5000;
const TX_AVAIL: u64 = 0x1_6000;
const TX_USED: u64 = 0x1_7000;
const TX_DATA: u64 = 0x1_8000;
const PACKET_BYTES: u32 = 4096;
const VSOCK_HEADER_BYTES: usize = 44;
const YAMUX_HEADER_BYTES: usize = 12;
const GUEST_PORT: u32 = 7000;

struct GuestTransport {
    channel: VsockChannel,
    ram: GuestRam,
    transmitted: u16,
    received: u16,
    carrier_bytes: Vec<u8>,
    is_connected: bool,
}

fn write_word(channel: &VsockChannel, offset: u64, value: u32) -> wasmtime::Result<()> {
    channel.write_mmio(offset, &value.to_le_bytes())
}

fn descriptor(address: u64, length: u32, flags: u16, next: u16) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&address.to_le_bytes());
    bytes[8..12].copy_from_slice(&length.to_le_bytes());
    bytes[12..14].copy_from_slice(&flags.to_le_bytes());
    bytes[14..].copy_from_slice(&next.to_le_bytes());
    bytes
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> wasmtime::Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .ok_or_else(|| wasmtime::Error::msg("short vsock self-test packet"))?
        .try_into()
        .map_err(wasmtime::Error::from)
}

fn yamux_frame(kind: u8, flags: u16, stream: u32, payload: &[u8]) -> wasmtime::Result<Vec<u8>> {
    let mut bytes = vec![0, kind];
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes.extend_from_slice(&stream.to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(payload.len())?.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

impl GuestTransport {
    fn configure(&self) -> wasmtime::Result<()> {
        for index in 0..QUEUE_SIZE {
            write_memory(
                &self.ram,
                RX_DESC + u64::from(index) * 16,
                &descriptor(
                    RX_DATA + u64::from(index) * u64::from(PACKET_BYTES),
                    PACKET_BYTES,
                    2,
                    0,
                ),
            )?;
            write_memory(
                &self.ram,
                RX_AVAIL + 4 + u64::from(index) * 2,
                &index.to_le_bytes(),
            )?;
        }
        write_memory(&self.ram, RX_AVAIL + 2, &QUEUE_SIZE.to_le_bytes())?;
        for (offset, value) in [(0x70, 1), (0x70, 3), (0x24, 1), (0x20, 1), (0x70, 11)] {
            write_word(&self.channel, offset, value)?;
        }
        for (queue, desc, avail, used) in [
            (0, RX_DESC, RX_AVAIL, RX_USED),
            (1, TX_DESC, TX_AVAIL, TX_USED),
        ] {
            for (offset, value) in [
                (0x30, queue),
                (0x38, u32::from(QUEUE_SIZE)),
                (0x80, u32::try_from(desc)?),
                (0x90, u32::try_from(avail)?),
                (0xa0, u32::try_from(used)?),
                (0x44, 1),
            ] {
                write_word(&self.channel, offset, value)?;
            }
        }
        write_word(&self.channel, 0x70, 15)?;
        write_word(&self.channel, 0x50, 0)
    }

    async fn send_packet(&mut self, operation: u16, payload: &[u8]) -> wasmtime::Result<()> {
        let mut packet = Vec::with_capacity(VSOCK_HEADER_BYTES + payload.len());
        packet.extend_from_slice(&3_u64.to_le_bytes());
        packet.extend_from_slice(&2_u64.to_le_bytes());
        packet.extend_from_slice(&GUEST_PORT.to_le_bytes());
        packet.extend_from_slice(&terra_protocol::mux::MUX_VSOCK_PORT.to_le_bytes());
        packet.extend_from_slice(&u32::try_from(payload.len())?.to_le_bytes());
        packet.extend_from_slice(&1_u16.to_le_bytes());
        packet.extend_from_slice(&operation.to_le_bytes());
        packet.extend_from_slice(&0_u32.to_le_bytes());
        packet.extend_from_slice(&65536_u32.to_le_bytes());
        packet.extend_from_slice(&0_u32.to_le_bytes());
        packet.extend_from_slice(payload);
        wasmtime::ensure!(
            packet.len() <= usize::try_from(PACKET_BYTES)?,
            "vsock self-test packet limit"
        );
        write_memory(&self.ram, TX_DATA, &packet)?;
        write_memory(
            &self.ram,
            TX_DESC,
            &descriptor(
                TX_DATA,
                u32::try_from(VSOCK_HEADER_BYTES)?,
                u16::from(!payload.is_empty()),
                1,
            ),
        )?;
        if !payload.is_empty() {
            write_memory(
                &self.ram,
                TX_DESC + 16,
                &descriptor(
                    TX_DATA + u64::try_from(VSOCK_HEADER_BYTES)?,
                    u32::try_from(payload.len())?,
                    0,
                    0,
                ),
            )?;
        }
        write_memory(
            &self.ram,
            TX_AVAIL + 4 + u64::from(self.transmitted % QUEUE_SIZE) * 2,
            &0_u16.to_le_bytes(),
        )?;
        self.transmitted = self.transmitted.wrapping_add(1);
        write_memory(&self.ram, TX_AVAIL + 2, &self.transmitted.to_le_bytes())?;
        write_word(&self.channel, 0x50, 1)?;
        while read_memory(&self.ram, TX_USED + 2, 2)? != self.transmitted.to_le_bytes() {
            self.check_failure()?;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok(())
    }

    fn check_failure(&self) -> wasmtime::Result<()> {
        match self.channel.failure() {
            Some(error) => Err(wasmtime::Error::msg(error)),
            None => Ok(()),
        }
    }

    fn receive_packets(&mut self) -> wasmtime::Result<()> {
        let used = u16::from_le_bytes(field(&read_memory(&self.ram, RX_USED + 2, 2)?, 0)?);
        let received_before = self.received;
        while self.received != used {
            let entry = read_memory(
                &self.ram,
                RX_USED + 4 + u64::from(self.received % QUEUE_SIZE) * 8,
                8,
            )?;
            let head = u32::from_le_bytes(field(&entry, 0)?);
            let length = u32::from_le_bytes(field(&entry, 4)?);
            wasmtime::ensure!(
                head < u32::from(QUEUE_SIZE) && length <= PACKET_BYTES,
                "invalid vsock self-test reply"
            );
            let packet = read_memory(
                &self.ram,
                RX_DATA + u64::from(head) * u64::from(PACKET_BYTES),
                u64::from(length),
            )?;
            wasmtime::ensure!(
                u32::from_le_bytes(field(&packet, 16)?) == terra_protocol::mux::MUX_VSOCK_PORT
                    && u32::from_le_bytes(field(&packet, 20)?) == GUEST_PORT,
                "vsock self-test reply ports"
            );
            match u16::from_le_bytes(field(&packet, 30)?) {
                2 => self.is_connected = true,
                3 => wasmtime::bail!("vsock self-test carrier reset"),
                5 => {
                    let payload = packet
                        .get(VSOCK_HEADER_BYTES..)
                        .ok_or_else(|| wasmtime::Error::msg("short vsock self-test reply"))?;
                    wasmtime::ensure!(
                        payload.len() == usize::try_from(u32::from_le_bytes(field(&packet, 24)?))?,
                        "vsock self-test reply length"
                    );
                    self.carrier_bytes.extend_from_slice(payload);
                }
                _ => {}
            }
            write_memory(
                &self.ram,
                RX_AVAIL + 4 + u64::from(self.received % QUEUE_SIZE) * 2,
                &u16::try_from(head)?.to_le_bytes(),
            )?;
            self.received = self.received.wrapping_add(1);
        }
        if self.received != received_before {
            write_memory(
                &self.ram,
                RX_AVAIL + 2,
                &self.received.wrapping_add(QUEUE_SIZE).to_le_bytes(),
            )?;
            write_word(&self.channel, 0x50, 0)?;
        }
        Ok(())
    }

    async fn read_data(&mut self, stream: u32) -> wasmtime::Result<Vec<u8>> {
        let result =
            tokio::time::timeout(Duration::from_secs(2), self.read_data_inner(stream)).await;
        result.map_err(|_| {
            wasmtime::Error::msg(format!(
                "vsock self-test stream {stream} timed out (connected={}, receive_packets={}, carrier_bytes={})",
                self.is_connected,
                self.received,
                self.carrier_bytes.len(),
            ))
        })?
    }

    async fn read_data_inner(&mut self, stream: u32) -> wasmtime::Result<Vec<u8>> {
        loop {
            self.check_failure()?;
            self.receive_packets()?;
            if self.carrier_bytes.len() < YAMUX_HEADER_BYTES {
                tokio::time::sleep(Duration::from_millis(1)).await;
                continue;
            }
            let kind = self.carrier_bytes[1];
            let flags = u16::from_be_bytes(field(&self.carrier_bytes, 2)?);
            let id = u32::from_be_bytes(field(&self.carrier_bytes, 4)?);
            let length = if kind == 0 {
                usize::try_from(u32::from_be_bytes(field(&self.carrier_bytes, 8)?))?
            } else {
                0
            };
            wasmtime::ensure!(
                length <= usize::try_from(PACKET_BYTES)?,
                "vsock self-test Yamux frame limit"
            );
            let end = YAMUX_HEADER_BYTES + length;
            if self.carrier_bytes.len() < end {
                tokio::time::sleep(Duration::from_millis(1)).await;
                continue;
            }
            let payload = self.carrier_bytes[YAMUX_HEADER_BYTES..end].to_vec();
            self.carrier_bytes.drain(..end);
            if flags & 1 != 0 {
                self.send_packet(5, &yamux_frame(1, 2, id, &[])?).await?;
            }
            if id == stream && !payload.is_empty() {
                return Ok(payload);
            }
        }
    }

    async fn read_stream_bytes(&mut self, stream: u32, length: usize) -> wasmtime::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        while bytes.len() < length {
            bytes.extend(self.read_data(stream).await?);
        }
        wasmtime::ensure!(bytes.len() == length, "vsock self-test stream length");
        Ok(bytes)
    }
}

fn encode_plan() -> wasmtime::Result<Vec<u8>> {
    let gateway = std::net::Ipv4Addr::new(100, 96, 0, 1).into();
    Ok(terra_protocol::encode_frame(&terra_protocol::Plan {
        mode: terra_protocol::PlanMode::Run,
        workdir: None,
        shares: Vec::new(),
        volumes: Vec::new(),
        net: terra_protocol::Net {
            guest_ip: std::net::Ipv4Addr::new(100, 96, 0, 2).into(),
            prefix: 30,
            gateway,
            dns: gateway,
        },
        env: std::collections::BTreeMap::new(),
        root: false,
        sudo: Vec::new(),
        on_create: Vec::new(),
        on_start: Vec::new(),
        pre_stop: Vec::new(),
        daemons: Vec::new(),
        workload: vec!["/bin/true".into()],
        sandbox_info: String::new(),
        await_initial_session: false,
        host_tz: None,
        host_time: None,
        host_seed: None,
    })?)
}

pub(super) async fn run(
    artifacts: &crate::TrustedArtifacts,
    engine: &wasmtime::Engine,
    directory: &Path,
) -> wasmtime::Result<()> {
    let control_path = directory.join("vsock-control.sock");
    let control_listener = LocalListener::bind(&control_path)?;
    let mut control = LocalStream::connect(&control_path)?;
    let (control_grant, _) = control_listener.accept()?;
    drop(control_listener);
    let client_path = directory.join("vsock-agent.sock");
    let listener = LocalListener::bind(&client_path)?;
    let ram = GuestRam::new(256 * 1024)
        .ok_or_else(|| wasmtime::Error::msg("allocating vsock self-test memory"))?;
    let mut runtime = BoxRuntime::new(engine, BoxHost::new())?;
    runtime.initialize_mmio_artifact(artifacts).await?;
    let channel = VsockChannel::from_trusted_artifact(
        &mut runtime,
        ram.clone(),
        artifacts.vsock(),
        encode_plan()?,
        Some(listener),
        Some(control_grant),
        None,
        Arc::new(|_| Ok(())),
    )?;
    let runtime = runtime.prepare().await?.start();
    let mut guest = GuestTransport {
        channel: channel.clone(),
        ram,
        transmitted: 0,
        received: 0,
        carrier_bytes: Vec::new(),
        is_connected: false,
    };
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        exercise_transport(&mut guest, &mut control, &client_path),
    )
    .await
    .map_err(wasmtime::Error::from)
    .and_then(std::convert::identity);
    let closed = channel.close_async().await;
    let joined = runtime.join().await;
    result?;
    closed?;
    joined
}

async fn exercise_transport(
    guest: &mut GuestTransport,
    control: &mut LocalStream,
    client_path: &Path,
) -> wasmtime::Result<()> {
    wasmtime::ensure!(
        guest.channel.read_mmio(0, 4)? == 0x7472_6976_u32.to_le_bytes(),
        "vsock self-test MMIO magic"
    );
    wasmtime::ensure!(
        guest.channel.read_mmio(8, 4)? == 19_u32.to_le_bytes(),
        "vsock self-test device ID"
    );
    guest.configure()?;
    guest.send_packet(1, &[]).await?;
    let mut syns = yamux_frame(0, 1, terra_protocol::mux::CONTROL_STREAM_ID, &[])?;
    syns.extend(yamux_frame(
        0,
        1,
        terra_protocol::mux::DIAGNOSTIC_STREAM_ID,
        &[],
    )?);
    guest.send_packet(5, &syns).await?;
    let plan = guest
        .read_data(terra_protocol::mux::CONTROL_STREAM_ID)
        .await?;
    wasmtime::ensure!(guest.is_connected, "vsock self-test handshake response");
    let decoded: terra_protocol::Plan = terra_protocol::decode_frame_payload(
        plan.get(4..)
            .ok_or_else(|| wasmtime::Error::msg("short vsock self-test plan"))?,
    )?;
    wasmtime::ensure!(
        decoded.host_time.is_some() && decoded.host_seed.is_some(),
        "vsock self-test host plan enrichment"
    );
    let mut client = LocalStream::connect(client_path)?;
    client.write_all(b"guestless input")?;
    client.set_nonblocking(true)?;
    let input = guest.read_stream_bytes(2, b"guestless input".len()).await?;
    wasmtime::ensure!(input == b"guestless input", "vsock self-test local input");
    guest
        .send_packet(5, &yamux_frame(0, 0, 2, b"guestless output")?)
        .await?;
    let mut output = Vec::new();
    while output.len() < b"guestless output".len() {
        let mut bytes = [0; 32];
        match client.read(&mut bytes) {
            Ok(0) => wasmtime::bail!("vsock self-test client closed early"),
            Ok(length) => output.extend_from_slice(&bytes[..length]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    wasmtime::ensure!(
        output == b"guestless output",
        "vsock self-test local output"
    );
    control.write_all(&[terra_protocol::STOP_SIGNAL])?;
    while guest
        .read_data(terra_protocol::mux::CONTROL_STREAM_ID)
        .await?
        != [terra_protocol::STOP_SIGNAL]
    {}
    write_word(&guest.channel, 0x70, 0)?;
    wasmtime::ensure!(
        guest.channel.read_mmio(0x70, 4)? == [0; 4],
        "vsock self-test reset status"
    );
    Ok(())
}
