//! Exercise virtio-vsock descriptors, local-only routing, and physical reset.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use terra_protocol::vsock::{AGENT_PORT, CONTROL_PORT, GUEST_CID, HOST_CID, UDP_PORT};

use crate::TrustedArtifacts;
use crate::box_runtime::{BoxHost, BoxRuntime};
use crate::component::MmioDevice;
use crate::component::vsock::streams::{FrontendStreams, StreamEndpoint};
use crate::memory::GuestRam;

use super::{read_memory, write_memory};

const WAIT: Duration = Duration::from_secs(5);
const HEADER_BYTES: usize = 44;
const QUEUE_SIZE: u16 = 16;
const RECEIVE_DESCRIPTOR: u64 = 0x1000;
const RECEIVE_AVAILABLE: u64 = 0x2000;
const RECEIVE_USED: u64 = 0x3000;
const TRANSMIT_DESCRIPTOR: u64 = 0x5000;
const TRANSMIT_AVAILABLE: u64 = 0x6000;
const TRANSMIT_USED: u64 = 0x7000;
const TRANSMIT_HEADER: u64 = 0x8000;
const TRANSMIT_PAYLOAD: u64 = 0x9000;
const RECEIVE_DATA: u64 = 0x20000;
const RECEIVE_BYTES: u32 = 512;

pub(super) async fn run(
    artifacts: &TrustedArtifacts,
    engine: &wasmtime::Engine,
) -> wasmtime::Result<()> {
    let ram = GuestRam::new(2 * 1024 * 1024)
        .ok_or_else(|| wasmtime::Error::msg("vsock self-test RAM allocation"))?;
    let mut runtime = BoxRuntime::new(engine, BoxHost::new())?;
    runtime.initialize_mmio()?;
    let (streams, mut agent) = FrontendStreams::new();
    let (interrupt, events) = create_interrupt();
    let device = crate::component::vsock::register_device(
        &mut runtime,
        ram.clone(),
        artifacts.vsock(),
        streams,
        None,
        Vec::new(),
        interrupt,
    )?;
    let running = runtime.prepare().await?.start();
    let mut guest = GuestVsock::new(device.clone(), ram, events);
    let exercised = async {
        guest.configure()?;
        for (source, destination) in [
            (AGENT_PORT, CONTROL_PORT),
            (CONTROL_PORT, AGENT_PORT),
            (7000, 7000),
            (CONTROL_PORT, CONTROL_PORT),
            (7000, terra_protocol::vsock::TCP_PORT),
            (7001, UDP_PORT),
        ] {
            guest.send(source, destination, 1, 0, &[]).await?;
        }
        guest.send(AGENT_PORT, AGENT_PORT, 1, 65536, &[]).await?;
        let generation = wait_connected(&mut agent)
            .await
            .map_err(|error| error.context("initial agent transport admission"))?;
        let replies = guest.receive()?;
        wasmtime::ensure!(
            replies.iter().filter(|reply| reply.op == 3).count() >= 6,
            "local-only vsock rejects network and cross-endpoint tuples"
        );
        for bytes in [b"split-".as_slice(), b"agent-request"] {
            guest.send(AGENT_PORT, AGENT_PORT, 5, 65536, bytes).await?;
        }
        wasmtime::ensure!(
            read_stream(&mut agent, generation, 19)
                .await
                .map_err(|error| error.context("fragmented agent input"))?
                == b"split-agent-request",
            "vsock preserves fragmented agent bytes"
        );
        let payload = vec![91; 5000];
        agent
            .try_write(generation, &payload)
            .map_err(stream_error)?;
        wasmtime::ensure!(
            guest
                .read_payload(AGENT_PORT, payload.len())
                .await
                .map_err(|error| error.context("agent output through small receive descriptors"))?
                == payload,
            "small receive descriptors preserve partially delivered vsock payloads"
        );
        exercise_ready_receive_without_notification(&mut guest, &mut agent, generation).await?;
        guest.device.write(0x70, &0_u32.to_le_bytes())?;
        wait_disconnected(&mut agent)
            .await
            .map_err(|error| error.context("agent retirement after physical reset"))?;
        wasmtime::ensure!(
            agent.try_write(generation, &[1]).is_err(),
            "physical reset rejects retired agent generation"
        );
        guest.configure()?;
        guest.send(AGENT_PORT, AGENT_PORT, 1, 65536, &[]).await?;
        let replacement = wait_connected(&mut agent)
            .await
            .map_err(|error| error.context("agent admission after physical reset"))?;
        wasmtime::ensure!(
            replacement > generation,
            "physical reset admits a fresh agent generation"
        );
        exercise_stream_half_closes(&mut guest, &mut agent, replacement).await?;
        Ok(())
    }
    .await;
    let closed = device.close_async().await;
    let joined = running.join().await;
    exercised?;
    closed?;
    joined
}

async fn exercise_stream_half_closes(
    guest: &mut GuestVsock,
    agent: &mut StreamEndpoint,
    generation: u64,
) -> wasmtime::Result<()> {
    guest
        .send_with_flags(AGENT_PORT, AGENT_PORT, 4, 1, 65536, &[])
        .await?;
    tokio::time::timeout(WAIT, async {
        while agent.try_write(generation, &[]).is_ok() {
            agent.wait().await;
        }
    })
    .await?;
    guest
        .send(AGENT_PORT, AGENT_PORT, 5, 65536, b"half-open")
        .await?;
    wasmtime::ensure!(
        read_stream(agent, generation, 9).await? == b"half-open",
        "dropping frontend output preserves guest input"
    );
    guest
        .send_with_flags(AGENT_PORT, AGENT_PORT, 4, 2, 65536, &[])
        .await?;
    wait_disconnected(agent).await?;
    tokio::time::timeout(WAIT, async {
        loop {
            if guest
                .receive()?
                .iter()
                .any(|packet| packet.port == AGENT_PORT && packet.op == 3)
            {
                return Ok::<(), wasmtime::Error>(());
            }
            guest.wait_for_receive_work().await?;
        }
    })
    .await??;
    guest.set_receive_window(AGENT_PORT, AGENT_PORT, 0);
    guest.send(AGENT_PORT, AGENT_PORT, 1, 0, &[]).await?;
    let generation = wait_connected(agent).await?;
    agent.close(generation);
    tokio::time::timeout(WAIT, async {
        loop {
            if guest
                .receive()?
                .iter()
                .any(|packet| packet.port == AGENT_PORT && packet.op == 4 && packet.flags & 2 != 0)
            {
                return Ok::<(), wasmtime::Error>(());
            }
            guest.wait_for_receive_work().await?;
        }
    })
    .await??;
    guest
        .send(AGENT_PORT, AGENT_PORT, 5, 0, b"after-eof")
        .await?;
    wasmtime::ensure!(
        read_stream(agent, generation, 9).await? == b"after-eof",
        "role EOF ignores guest output credit and preserves guest input"
    );
    guest
        .send_with_flags(AGENT_PORT, AGENT_PORT, 4, 2, 0, &[])
        .await?;
    wait_disconnected(agent).await
}

async fn exercise_ready_receive_without_notification(
    guest: &mut GuestVsock,
    agent: &mut StreamEndpoint,
    generation: u64,
) -> wasmtime::Result<()> {
    guest.device.write(0x64, &3_u32.to_le_bytes())?;
    agent
        .try_write(generation, b"queued")
        .map_err(stream_error)?;
    tokio::time::timeout(WAIT, async {
        while guest.used_index(RECEIVE_USED)? == guest.received {
            guest.events.changed().await?;
        }
        Ok::<(), wasmtime::Error>(())
    })
    .await??;
    let (notification, quiet_events) = tokio::sync::watch::channel(0);
    let events = std::mem::replace(&mut guest.events, quiet_events);
    let ready = tokio::time::timeout(WAIT, guest.wait_for_receive_work()).await;
    guest.events = events;
    drop(notification);
    ready??;
    wasmtime::ensure!(
        guest.read_payload(AGENT_PORT, 6).await? == b"queued",
        "a consumed interrupt notification cannot hide available receive descriptors"
    );
    Ok(())
}

pub(super) struct GuestVsock {
    pub(super) device: MmioDevice,
    ram: GuestRam,
    transmitted: u16,
    received: u16,
    forwarded: BTreeMap<(u32, u32), u32>,
    receive_windows: BTreeMap<(u32, u32), u32>,
    events: tokio::sync::watch::Receiver<u64>,
}

pub(super) struct Packet {
    pub(super) port: u32,
    pub(super) guest_port: u32,
    pub(super) op: u16,
    pub(super) flags: u32,
    pub(super) forwarded: u32,
    pub(super) window: u32,
    pub(super) payload: Vec<u8>,
}

fn descriptor(address: u64, length: u32, flags: u16, next: u16) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&address.to_le_bytes());
    bytes[8..12].copy_from_slice(&length.to_le_bytes());
    bytes[12..14].copy_from_slice(&flags.to_le_bytes());
    bytes[14..].copy_from_slice(&next.to_le_bytes());
    bytes
}

pub(super) fn create_interrupt() -> (
    crate::component::InterruptCallback,
    tokio::sync::watch::Receiver<u64>,
) {
    let (interrupt, events) = tokio::sync::watch::channel(0_u64);
    (
        Arc::new(move |_| {
            interrupt.send_modify(|revision| *revision = revision.wrapping_add(1));
            Ok(())
        }),
        events,
    )
}

impl GuestVsock {
    pub(super) fn new(
        device: MmioDevice,
        ram: GuestRam,
        events: tokio::sync::watch::Receiver<u64>,
    ) -> Self {
        Self {
            device,
            ram,
            transmitted: 0,
            received: 0,
            forwarded: BTreeMap::new(),
            receive_windows: BTreeMap::new(),
            events,
        }
    }

    pub(super) fn set_receive_window(&mut self, guest_port: u32, host_port: u32, window: u32) {
        self.receive_windows.insert((guest_port, host_port), window);
    }

    pub(super) fn receive_window(&self, guest_port: u32, host_port: u32) -> u32 {
        self.receive_windows
            .get(&(guest_port, host_port))
            .copied()
            .unwrap_or(65536)
    }

    pub(super) async fn wait_for_receive_work(&mut self) -> wasmtime::Result<()> {
        if self.used_index(RECEIVE_USED)? == self.received {
            self.events.changed().await?;
        }
        Ok(())
    }

    pub(super) async fn acknowledge(
        &mut self,
        guest_port: u32,
        host_port: u32,
        count: usize,
    ) -> wasmtime::Result<()> {
        let forwarded = self.forwarded.entry((guest_port, host_port)).or_default();
        *forwarded = forwarded.wrapping_add(u32::try_from(count)?);
        self.send(
            guest_port,
            host_port,
            6,
            self.receive_window(guest_port, host_port),
            &[],
        )
        .await
    }

    pub(super) fn configure(&mut self) -> wasmtime::Result<()> {
        self.transmitted = 0;
        self.received = 0;
        self.forwarded.clear();
        self.receive_windows.clear();
        wasmtime::ensure!(
            self.device.read(8, 4)? == 19_u32.to_le_bytes(),
            "vsock device ID"
        );
        wasmtime::ensure!(
            self.device.read(0x100, 4)? == GUEST_CID.to_le_bytes()
                && self.device.read(0x104, 4)? == 0_u32.to_le_bytes(),
            "fixed guest CID"
        );
        for (offset, value) in [(0x70, 1_u32), (0x70, 3), (0x24, 1), (0x20, 1), (0x70, 11)] {
            self.device.write(offset, &value.to_le_bytes())?;
        }
        for (queue, descriptors, available, used) in [
            (0_u32, RECEIVE_DESCRIPTOR, RECEIVE_AVAILABLE, RECEIVE_USED),
            (1, TRANSMIT_DESCRIPTOR, TRANSMIT_AVAILABLE, TRANSMIT_USED),
        ] {
            write_memory(&self.ram, available, &[0; 4])?;
            write_memory(&self.ram, used, &[0; 4])?;
            for (offset, value) in [
                (0x30, queue),
                (0x38, u32::from(QUEUE_SIZE)),
                (0x80, u32::try_from(descriptors)?),
                (0x90, u32::try_from(available)?),
                (0xa0, u32::try_from(used)?),
                (0x44, 1),
            ] {
                self.device.write(offset, &value.to_le_bytes())?;
            }
        }
        for index in 0..QUEUE_SIZE {
            write_memory(
                &self.ram,
                RECEIVE_DESCRIPTOR + u64::from(index) * 16,
                &descriptor(
                    RECEIVE_DATA + u64::from(index) * u64::from(RECEIVE_BYTES),
                    RECEIVE_BYTES,
                    2,
                    0,
                ),
            )?;
            write_memory(
                &self.ram,
                RECEIVE_AVAILABLE + 4 + u64::from(index) * 2,
                &index.to_le_bytes(),
            )?;
        }
        write_memory(&self.ram, RECEIVE_AVAILABLE + 2, &QUEUE_SIZE.to_le_bytes())?;
        self.device.write(0x70, &15_u32.to_le_bytes())?;
        self.device.write(0x50, &0_u32.to_le_bytes())
    }

    fn used_index(&self, address: u64) -> wasmtime::Result<u16> {
        Ok(u16::from_le_bytes(
            read_memory(&self.ram, address + 2, 2)?
                .as_slice()
                .try_into()?,
        ))
    }

    pub(super) async fn send(
        &mut self,
        source: u32,
        destination: u32,
        op: u16,
        credit: u32,
        bytes: &[u8],
    ) -> wasmtime::Result<()> {
        self.send_with_flags(source, destination, op, 0, credit, bytes)
            .await
    }

    pub(super) async fn send_with_flags(
        &mut self,
        source: u32,
        destination: u32,
        op: u16,
        flags: u32,
        credit: u32,
        bytes: &[u8],
    ) -> wasmtime::Result<()> {
        if op == 1 || op == 2 {
            self.forwarded.remove(&(source, destination));
        }
        let mut header = [0; HEADER_BYTES];
        header[..8].copy_from_slice(&u64::from(GUEST_CID).to_le_bytes());
        header[8..16].copy_from_slice(&u64::from(HOST_CID).to_le_bytes());
        header[16..20].copy_from_slice(&source.to_le_bytes());
        header[20..24].copy_from_slice(&destination.to_le_bytes());
        header[24..28].copy_from_slice(&u32::try_from(bytes.len())?.to_le_bytes());
        header[28..30].copy_from_slice(&1_u16.to_le_bytes());
        header[30..32].copy_from_slice(&op.to_le_bytes());
        header[32..36].copy_from_slice(&flags.to_le_bytes());
        header[36..40].copy_from_slice(&credit.to_le_bytes());
        header[40..44].copy_from_slice(
            &self
                .forwarded
                .get(&(source, destination))
                .copied()
                .unwrap_or(0)
                .to_le_bytes(),
        );
        write_memory(&self.ram, TRANSMIT_HEADER, &header)?;
        for (index, chunk) in bytes
            .chunks(usize::try_from(crate::MAX_SINGLE_BYTES)?)
            .enumerate()
        {
            write_memory(
                &self.ram,
                TRANSMIT_PAYLOAD + u64::try_from(index)? * crate::MAX_SINGLE_BYTES,
                chunk,
            )?;
        }
        write_memory(
            &self.ram,
            TRANSMIT_DESCRIPTOR,
            &descriptor(
                TRANSMIT_HEADER,
                u32::try_from(HEADER_BYTES)?,
                u16::from(!bytes.is_empty()),
                1,
            ),
        )?;
        if !bytes.is_empty() {
            write_memory(
                &self.ram,
                TRANSMIT_DESCRIPTOR + 16,
                &descriptor(TRANSMIT_PAYLOAD, u32::try_from(bytes.len())?, 0, 0),
            )?;
        }
        write_memory(
            &self.ram,
            TRANSMIT_AVAILABLE + 4 + u64::from(self.transmitted % QUEUE_SIZE) * 2,
            &0_u16.to_le_bytes(),
        )?;
        self.transmitted = self.transmitted.wrapping_add(1);
        write_memory(
            &self.ram,
            TRANSMIT_AVAILABLE + 2,
            &self.transmitted.to_le_bytes(),
        )?;
        self.device.write(0x64, &3_u32.to_le_bytes())?;
        self.device.write(0x50, &1_u32.to_le_bytes())?;
        tokio::time::timeout(WAIT, async {
            while self.used_index(TRANSMIT_USED)? != self.transmitted {
                self.device.write(0x64, &3_u32.to_le_bytes())?;
                self.events.changed().await?;
            }
            wasmtime::Result::Ok(())
        })
        .await
        .map_err(|error| {
            wasmtime::Error::msg(format!(
                "vsock transmit {source}:{destination} operation {op}: {error}"
            ))
        })?
    }

    pub(super) fn receive(&mut self) -> wasmtime::Result<Vec<Packet>> {
        self.device.write(0x64, &3_u32.to_le_bytes())?;
        let used = self.used_index(RECEIVE_USED)?;
        let mut packets = Vec::new();
        while self.received != used {
            let slot = self.received % QUEUE_SIZE;
            let entry = read_memory(&self.ram, RECEIVE_USED + 4 + u64::from(slot) * 8, 8)?;
            let head = u32::from_le_bytes(entry[..4].try_into()?);
            let length = u32::from_le_bytes(entry[4..].try_into()?);
            wasmtime::ensure!(
                head < u32::from(QUEUE_SIZE) && length <= RECEIVE_BYTES,
                "vsock receive descriptor bounds"
            );
            if length != 0 {
                wasmtime::ensure!(
                    usize::try_from(length)? >= HEADER_BYTES,
                    "vsock receive header length"
                );
                let bytes = read_memory(
                    &self.ram,
                    RECEIVE_DATA + u64::from(head) * u64::from(RECEIVE_BYTES),
                    u64::from(length),
                )?;
                wasmtime::ensure!(
                    bytes[..8] == u64::from(HOST_CID).to_le_bytes()
                        && bytes[8..16] == u64::from(GUEST_CID).to_le_bytes(),
                    "vsock response CIDs"
                );
                let payload_len = u32::from_le_bytes(bytes[24..28].try_into()?);
                wasmtime::ensure!(
                    u64::from(payload_len) + u64::try_from(HEADER_BYTES)? == u64::from(length),
                    "vsock receive payload length"
                );
                packets.push(Packet {
                    port: u32::from_le_bytes(bytes[16..20].try_into()?),
                    guest_port: u32::from_le_bytes(bytes[20..24].try_into()?),
                    op: u16::from_le_bytes(bytes[30..32].try_into()?),
                    flags: u32::from_le_bytes(bytes[32..36].try_into()?),
                    forwarded: u32::from_le_bytes(bytes[40..44].try_into()?),
                    window: u32::from_le_bytes(bytes[36..40].try_into()?),
                    payload: bytes[HEADER_BYTES..].to_vec(),
                });
            }
            write_memory(
                &self.ram,
                RECEIVE_AVAILABLE + 4 + u64::from(slot) * 2,
                &u16::try_from(head)?.to_le_bytes(),
            )?;
            self.received = self.received.wrapping_add(1);
        }
        write_memory(
            &self.ram,
            RECEIVE_AVAILABLE + 2,
            &self.received.wrapping_add(QUEUE_SIZE).to_le_bytes(),
        )?;
        self.device.write(0x50, &0_u32.to_le_bytes())?;
        Ok(packets)
    }

    pub(super) async fn read_payload(
        &mut self,
        port: u32,
        length: usize,
    ) -> wasmtime::Result<Vec<u8>> {
        tokio::time::timeout(WAIT, async {
            let mut bytes = Vec::new();
            while bytes.len() < length {
                for packet in self.receive()? {
                    if packet.op == 5 {
                        wasmtime::ensure!(
                            packet.port == port,
                            "stalled connection emitted unexpected payload"
                        );
                        let count = packet.payload.len();
                        bytes.extend(packet.payload);
                        self.acknowledge(packet.guest_port, packet.port, count)
                            .await?;
                    }
                }
                wasmtime::ensure!(bytes.len() <= length, "vsock returned excess stream bytes");
                if bytes.len() < length {
                    self.device.write(0x64, &3_u32.to_le_bytes())?;
                    self.wait_for_receive_work().await?;
                }
            }
            Ok(bytes)
        })
        .await?
    }
}

fn stream_error(
    error: crate::component::vsock::streams::stream_types::StreamError,
) -> wasmtime::Error {
    wasmtime::Error::msg(format!("vsock self-test stream: {error:?}"))
}

pub(super) async fn wait_connected(endpoint: &mut StreamEndpoint) -> wasmtime::Result<u64> {
    tokio::time::timeout(WAIT, async {
        loop {
            if let Some(generation) = endpoint.current() {
                return generation;
            }
            endpoint.wait().await;
        }
    })
    .await
    .map_err(wasmtime::Error::from)
}

async fn wait_disconnected(endpoint: &mut StreamEndpoint) -> wasmtime::Result<()> {
    tokio::time::timeout(WAIT, async {
        while endpoint.current().is_some() {
            endpoint.wait().await;
        }
    })
    .await?;
    Ok(())
}

pub(super) async fn read_stream(
    endpoint: &mut StreamEndpoint,
    generation: u64,
    length: usize,
) -> wasmtime::Result<Vec<u8>> {
    tokio::time::timeout(WAIT, async {
        let mut bytes = Vec::new();
        while bytes.len() < length {
            let chunk = endpoint
                .try_read(generation, u32::try_from(length - bytes.len())?)
                .map_err(stream_error)?;
            if chunk.is_empty() {
                endpoint.wait().await;
            } else {
                bytes.extend(chunk);
            }
        }
        Ok(bytes)
    })
    .await?
}

#[cfg(test)]
mod tests {
    /// Receive readiness remains observable after another wait consumes the interrupt notification.
    #[tokio::test(flavor = "multi_thread")]
    async fn frontend_exercises_agent_descriptors_local_only_and_physical_reset() {
        super::run(
            &crate::test_fixtures::trusted_artifacts(),
            &crate::engine::device_engine().unwrap(),
        )
        .await
        .unwrap();
    }
}
