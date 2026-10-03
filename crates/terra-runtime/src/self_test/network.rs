use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::TrustedArtifacts;
use crate::box_runtime::{BoxHost, BoxRuntime};
use crate::component::MmioDevice;
use crate::component::context::DeviceContext;
use crate::component::network::{GuestNetworkConfig, NameLookup, Policy, PortMapping};
use crate::memory::GuestRam;

const WAIT: Duration = Duration::from_secs(5);
const GUEST_MAC: [u8; 6] = [2, 0x53, 0x4d, 0, 0, 2];
const GUEST_IP: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 2);
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 1);
const GATEWAY_MAC: [u8; 6] = [2, 0x53, 0x4d, 0, 0, 1];

struct LoopbackPolicy;

impl Policy for LoopbackPolicy {
    fn allows(&self, address: IpAddr, _: Option<u16>) -> bool {
        address.is_loopback()
    }

    fn host_service_ports(&self) -> &[Option<u16>] {
        &[None]
    }

    fn lookup_name(&self, name: &str) -> NameLookup {
        if name == "localhost" {
            NameLookup::Resolve(name.into())
        } else {
            NameLookup::Denied
        }
    }

    fn accept_resolved(&self, _: &str, addresses: &[IpAddr]) -> Vec<IpAddr> {
        addresses
            .iter()
            .copied()
            .filter(IpAddr::is_loopback)
            .collect()
    }
}

pub(super) async fn run(
    artifacts: &TrustedArtifacts,
    engine: &wasmtime::Engine,
) -> wasmtime::Result<()> {
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    tcp.set_nonblocking(true)?;
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    udp.set_read_timeout(Some(WAIT))?;
    udp.set_write_timeout(Some(WAIT))?;
    let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let published = reserved.local_addr()?.port();
    drop(reserved);
    let ram = GuestRam::new(64 * 1024)
        .ok_or_else(|| wasmtime::Error::msg("network self-test RAM allocation"))?;
    let mut runtime = BoxRuntime::new(engine, BoxHost::new())?;
    runtime.initialize_mmio_artifact(artifacts).await?;
    let network = artifacts.network().deserialize(engine)?;
    let device = crate::component::network::register_device(
        &mut runtime,
        DeviceContext::with_ram(ram.clone()),
        &network,
        Arc::new(LoopbackPolicy),
        vec![PortMapping::new(published, 8080)],
        GuestNetworkConfig::default(),
        Arc::new(|_| Ok(())),
    )?;
    let running = runtime.prepare().await?.start();
    let driver = device.clone();
    let result = tokio::task::spawn_blocking(move || {
        let mut guest = GuestNetwork::new(driver, ram)?;
        guest.learn_gateway()?;
        guest.exchange_udp(&udp)?;
        guest.resolve_localhost()?;
        guest.exchange_tcp(&tcp)?;
        guest.exchange_published(published)
    })
    .await
    .map_err(|error| wasmtime::Error::msg(format!("network self-test driver: {error}")))
    .and_then(std::convert::identity);
    let closed = device.close_async().await;
    let stopped = running.join().await;
    result?;
    closed?;
    stopped
}

struct GuestNetwork {
    device: MmioDevice,
    ram: GuestRam,
    tx_index: u16,
    rx_index: u16,
}

impl GuestNetwork {
    fn new(device: MmioDevice, ram: GuestRam) -> wasmtime::Result<Self> {
        let guest = Self {
            device,
            ram,
            tx_index: 0,
            rx_index: 0,
        };
        wasmtime::ensure!(
            guest.device.read(8, 4)? == 1_u32.to_le_bytes(),
            "network device identity"
        );
        for (offset, value) in [(0x70, 1), (0x70, 3), (0x24, 1), (0x20, 1), (0x70, 11)] {
            guest.write_register(offset, value)?;
        }
        for (queue, base) in [(0, 0x1000), (1, 0x6000)] {
            for (offset, value) in [
                (0x30, queue),
                (0x38, 256),
                (0x80, base),
                (0x90, base + 0x1000),
                (0xa0, base + 0x2000),
                (0x44, 1),
            ] {
                guest.write_register(offset, value)?;
            }
        }
        let mut descriptor = [0; 16];
        descriptor[..8].copy_from_slice(&0x4000_u64.to_le_bytes());
        descriptor[8..12].copy_from_slice(&2048_u32.to_le_bytes());
        descriptor[12..14].copy_from_slice(&2_u16.to_le_bytes());
        guest.write_memory(0x1000, &descriptor)?;
        guest.write_memory(0x2002, &1_u16.to_le_bytes())?;
        guest.write_register(0x70, 15)?;
        guest.write_register(0x50, 0)?;
        Ok(guest)
    }

    fn write_register(&self, offset: u64, value: u32) -> wasmtime::Result<()> {
        self.device.write(offset, &value.to_le_bytes())
    }

    fn write_memory(&self, offset: u64, bytes: &[u8]) -> wasmtime::Result<()> {
        super::write_memory(&self.ram, offset, bytes)
    }

    fn read_memory(&self, offset: u64, length: u64) -> wasmtime::Result<Vec<u8>> {
        super::read_memory(&self.ram, offset, length)
    }

    fn wait_for_index(&self, offset: u64, expected: u16) -> wasmtime::Result<()> {
        let deadline = Instant::now() + WAIT;
        while self.read_memory(offset, 2)? != expected.to_le_bytes() {
            wasmtime::ensure!(
                self.device.failure().is_none(),
                "network component failed: {:?}",
                self.device.failure()
            );
            wasmtime::ensure!(
                Instant::now() < deadline,
                "network self-test virtqueue timed out at {offset:#x}"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }

    fn send(&mut self, frame: &[u8]) -> wasmtime::Result<()> {
        wasmtime::ensure!(frame.len() <= 1500, "network self-test frame too large");
        let mut bytes = vec![0; 12];
        bytes.extend_from_slice(frame);
        self.write_memory(0x9000, &bytes)?;
        let mut descriptor = [0; 16];
        descriptor[..8].copy_from_slice(&0x9000_u64.to_le_bytes());
        descriptor[8..12].copy_from_slice(&u32::try_from(bytes.len())?.to_le_bytes());
        self.write_memory(0x6000, &descriptor)?;
        self.write_memory(
            0x7004 + 2 * u64::from(self.tx_index % 256),
            &0_u16.to_le_bytes(),
        )?;
        self.tx_index = self.tx_index.wrapping_add(1);
        self.write_memory(0x7002, &self.tx_index.to_le_bytes())?;
        self.write_register(0x50, 1)?;
        self.wait_for_index(0x8002, self.tx_index)
    }

    fn receive(&mut self) -> wasmtime::Result<Vec<u8>> {
        let next = self.rx_index.wrapping_add(1);
        self.wait_for_index(0x3002, next)?;
        let entry = self.read_memory(0x3004 + 8 * u64::from(self.rx_index % 256), 8)?;
        let length = u32::from_le_bytes(entry[4..8].try_into()?);
        wasmtime::ensure!(
            (26..=2048).contains(&length),
            "network self-test received invalid frame length"
        );
        let frame = self.read_memory(0x400c, u64::from(length - 12))?;
        self.rx_index = next;
        self.write_memory(0x2004 + 2 * u64::from(next % 256), &0_u16.to_le_bytes())?;
        self.write_memory(0x2002, &next.wrapping_add(1).to_le_bytes())?;
        self.write_register(0x50, 0)?;
        Ok(frame)
    }

    fn learn_gateway(&mut self) -> wasmtime::Result<()> {
        let mut arp = vec![0; 42];
        arp[..6].fill(255);
        arp[6..12].copy_from_slice(&GUEST_MAC);
        arp[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
        arp[22..28].copy_from_slice(&GUEST_MAC);
        arp[28..32].copy_from_slice(&GUEST_IP.octets());
        arp[38..42].copy_from_slice(&GATEWAY_IP.octets());
        self.send(&arp)?;
        let reply = self.receive()?;
        wasmtime::ensure!(
            reply.len() >= 42 && reply[12..14] == [8, 6] && reply[20..22] == [0, 2],
            "network self-test ARP reply"
        );
        Ok(())
    }

    fn receive_transport(
        &mut self,
        protocol: u8,
        destination_port: u16,
    ) -> wasmtime::Result<Vec<u8>> {
        let deadline = Instant::now() + WAIT;
        loop {
            wasmtime::ensure!(
                Instant::now() < deadline,
                "network self-test transport reply timed out"
            );
            let frame = self.receive()?;
            if frame.len() < 34 || frame[12..14] != [8, 0] || frame[23] != protocol {
                continue;
            }
            let start = 14 + usize::from(frame[14] & 15) * 4;
            let end = 14 + usize::from(u16::from_be_bytes([frame[16], frame[17]]));
            wasmtime::ensure!(
                start + 4 <= end && end <= frame.len(),
                "network self-test invalid IP reply"
            );
            if frame[start + 2..start + 4] == destination_port.to_be_bytes() {
                return Ok(frame[start..end].to_vec());
            }
        }
    }

    fn exchange_udp(&mut self, socket: &UdpSocket) -> wasmtime::Result<()> {
        let port = socket.local_addr()?.port();
        self.send(&udp_frame(port, b"terra-udp")?)?;
        let mut bytes = [0; 64];
        let (length, peer) = socket.recv_from(&mut bytes)?;
        wasmtime::ensure!(
            &bytes[..length] == b"terra-udp" && peer.ip().is_loopback(),
            "network self-test UDP request"
        );
        socket.send_to(b"udp-reply", peer)?;
        let reply = self.receive_transport(17, 40000)?;
        wasmtime::ensure!(
            reply.len() >= 8 && &reply[8..] == b"udp-reply",
            "network self-test UDP response"
        );
        Ok(())
    }

    fn resolve_localhost(&mut self) -> wasmtime::Result<()> {
        let query =
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09localhost\x00\x00\x01\x00\x01";
        self.send(&udp_frame(53, query)?)?;
        let reply = self.receive_transport(17, 40000)?;
        wasmtime::ensure!(
            reply.len() >= 20
                && reply[8..10] == [0x12, 0x34]
                && reply[11].trailing_zeros() >= 4
                && reply[14..16] != [0, 0],
            "network self-test DNS answer"
        );
        wasmtime::ensure!(
            reply.ends_with(&Ipv4Addr::LOCALHOST.octets()),
            "network self-test DNS loopback address"
        );
        Ok(())
    }

    fn exchange_tcp(&mut self, listener: &TcpListener) -> wasmtime::Result<()> {
        let port = listener.local_addr()?.port();
        self.send(&tcp_frame(port, 40001, 1, 0, 2, &[])?)?;
        let syn_ack = self.receive_transport(6, 40001)?;
        wasmtime::ensure!(
            syn_ack.len() >= 20 && syn_ack[13] & 0x12 == 0x12,
            "network self-test TCP SYN ACK"
        );
        let peer_sequence = read_sequence(&syn_ack)?.wrapping_add(1);
        self.send(&tcp_frame(port, 40001, 2, peer_sequence, 16, &[])?)?;
        let deadline = Instant::now() + WAIT;
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    wasmtime::ensure!(
                        Instant::now() < deadline,
                        "network self-test TCP accept timed out"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(error.into()),
            }
        };
        configure_stream(&stream)?;
        self.send(&tcp_frame(port, 40001, 2, peer_sequence, 24, b"terra-tcp")?)?;
        let mut request = [0; 9];
        stream.read_exact(&mut request)?;
        wasmtime::ensure!(&request == b"terra-tcp", "network self-test TCP request");
        stream.write_all(b"tcp-reply")?;
        let received = self.receive_tcp_payload(40001, b"tcp-reply")?;
        self.send(&tcp_frame(port, 40001, 11, received, 17, &[])?)?;
        let mut eof = [0];
        wasmtime::ensure!(stream.read(&mut eof)? == 0, "network self-test TCP EOF");
        stream.shutdown(Shutdown::Write)?;
        Ok(())
    }

    fn receive_tcp_payload(&mut self, port: u16, expected: &[u8]) -> wasmtime::Result<u32> {
        let deadline = Instant::now() + WAIT;
        let mut bytes = Vec::new();
        loop {
            wasmtime::ensure!(
                Instant::now() < deadline,
                "network self-test TCP payload timed out"
            );
            let reply = self.receive_transport(6, port)?;
            wasmtime::ensure!(reply.len() >= 20, "network self-test short TCP reply");
            let header = usize::from(reply[12] >> 4) * 4;
            wasmtime::ensure!(
                (20..=reply.len()).contains(&header),
                "network self-test invalid TCP header"
            );
            bytes.extend_from_slice(&reply[header..]);
            wasmtime::ensure!(
                expected.starts_with(&bytes),
                "network self-test unexpected TCP response"
            );
            if bytes == expected {
                return Ok(
                    read_sequence(&reply)?.wrapping_add(u32::try_from(reply.len() - header)?)
                );
            }
        }
    }

    fn exchange_published(&mut self, host_port: u16) -> wasmtime::Result<()> {
        let deadline = Instant::now() + WAIT;
        let mut stream = loop {
            match TcpStream::connect_timeout(
                &(Ipv4Addr::LOCALHOST, host_port).into(),
                Duration::from_millis(100),
            ) {
                Ok(stream) => break stream,
                Err(error) => {
                    wasmtime::ensure!(
                        Instant::now() < deadline,
                        "network self-test published connect: {error}"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        configure_stream(&stream)?;
        let syn = self.receive_transport(6, 8080)?;
        wasmtime::ensure!(
            syn.len() >= 20 && syn[13] & 2 != 0,
            "network self-test published SYN"
        );
        let gateway_port = u16::from_be_bytes([syn[0], syn[1]]);
        let peer_sequence = read_sequence(&syn)?.wrapping_add(1);
        self.send(&tcp_frame(gateway_port, 8080, 1, peer_sequence, 18, &[])?)?;
        stream.write_all(b"published-request")?;
        let received = self.receive_tcp_payload(8080, b"published-request")?;
        self.send(&tcp_frame(
            gateway_port,
            8080,
            2,
            received,
            24,
            b"published-reply",
        )?)?;
        let mut reply = [0; 15];
        stream.read_exact(&mut reply)?;
        wasmtime::ensure!(
            &reply == b"published-reply",
            "network self-test published response"
        );
        self.send(&tcp_frame(gateway_port, 8080, 17, received, 17, &[])?)?;
        let mut eof = [0];
        wasmtime::ensure!(
            stream.read(&mut eof)? == 0,
            "network self-test published EOF"
        );
        stream.shutdown(Shutdown::Write)?;
        Ok(())
    }
}

fn configure_stream(stream: &TcpStream) -> wasmtime::Result<()> {
    stream.set_read_timeout(Some(WAIT))?;
    stream.set_write_timeout(Some(WAIT))?;
    stream.set_nodelay(true)?;
    Ok(())
}

fn read_sequence(tcp: &[u8]) -> wasmtime::Result<u32> {
    Ok(u32::from_be_bytes(tcp[4..8].try_into()?))
}

fn udp_frame(port: u16, payload: &[u8]) -> wasmtime::Result<Vec<u8>> {
    let mut udp = vec![0; 8];
    udp[..2].copy_from_slice(&40000_u16.to_be_bytes());
    udp[2..4].copy_from_slice(&port.to_be_bytes());
    udp[4..6].copy_from_slice(&u16::try_from(8 + payload.len())?.to_be_bytes());
    udp.extend_from_slice(payload);
    ip_frame(17, udp)
}

fn tcp_frame(
    port: u16,
    guest_port: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: &[u8],
) -> wasmtime::Result<Vec<u8>> {
    let mut tcp = vec![0; 20];
    tcp[..2].copy_from_slice(&guest_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&port.to_be_bytes());
    tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
    tcp[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&65535_u16.to_be_bytes());
    tcp.extend_from_slice(payload);
    let mut pseudo_header = Vec::from(GUEST_IP.octets());
    pseudo_header.extend_from_slice(&GATEWAY_IP.octets());
    pseudo_header.extend_from_slice(&[0, 6]);
    pseudo_header.extend_from_slice(&u16::try_from(tcp.len())?.to_be_bytes());
    pseudo_header.extend_from_slice(&tcp);
    tcp[16..18].copy_from_slice(&checksum(&pseudo_header).to_be_bytes());
    ip_frame(6, tcp)
}

fn ip_frame(protocol: u8, transport: Vec<u8>) -> wasmtime::Result<Vec<u8>> {
    let mut frame = vec![0; 34];
    frame[..6].copy_from_slice(&GATEWAY_MAC);
    frame[6..12].copy_from_slice(&GUEST_MAC);
    frame[12..14].copy_from_slice(&[8, 0]);
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&u16::try_from(20 + transport.len())?.to_be_bytes());
    frame[22] = 64;
    frame[23] = protocol;
    frame[26..30].copy_from_slice(&GUEST_IP.octets());
    frame[30..34].copy_from_slice(&GATEWAY_IP.octets());
    let ip_checksum = checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
    frame.extend(transport);
    Ok(frame)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes.chunks(2).fold(0_u32, |sum, pair| {
        sum + u32::from(u16::from_be_bytes([
            pair[0],
            pair.get(1).copied().unwrap_or(0),
        ]))
    });
    while sum > u32::from(u16::MAX) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(0)
}
