#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({ world: "device", path: "wit", generate_all });
}
use bindings::{exports, terra, wasi, wit_stream};
use wasi::sockets::types::{
    IpAddressFamily, IpSocketAddress, Ipv4SocketAddress, Ipv6SocketAddress, TcpSocket,
    UdpSocket as WasiUdpSocket,
};
use wit_bindgen::rt::async_support::StreamResult;

mod dns;
mod icmp;
mod mmio;
mod published;
mod transport;

use std::collections::VecDeque;
use std::future::IntoFuture;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{
    LazyLock, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::task::Poll;

use exports::terra::network::api::{Config, Error, Guest, PublishedPort};
use exports::terra::network::transport::Guest as TransportGuest;
use futures::channel::mpsc::{Sender, channel};
use futures::{
    FutureExt, StreamExt,
    future::poll_fn,
    future::{AbortHandle, AbortRegistration, Abortable},
    stream::FuturesUnordered,
};
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{self, SocketBuffer};
use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket, UdpMetadata};
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, IpAddress, IpCidr,
    IpListenEndpoint, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket, UdpRepr,
};
use terra::mmio::types::DeviceError;

const MAX_FRAME_BYTES: usize = 65_536;
const MAX_QUEUED_FRAMES: usize = 128;
const MAX_QUEUED_BYTES: usize = 512 * 1024;
const MAX_WORK_PER_WAKE: usize = 8;
const TCP_BUFFER_BYTES: usize = terra_limits::NETWORK_TCP_BUFFER_BYTES;
const TCP_CHUNK_BYTES: usize = terra_limits::NETWORK_TCP_CHUNK_BYTES;
const TCP_FLOW_TIMEOUT_SECS: u64 = 30;
const DNS_PORT: u16 = 53;
const LEARNED_DNS_TTL_SECS: u32 = 60;
const MAX_UDP_PACKET_BYTES: usize = 4096;
const UDP_RECEIVE_TIMEOUT: u64 = 5_000_000_000;
const PUBLISHED_LISTENER_RETRY_DELAY: u64 = 1_000_000_000;

#[derive(Clone)]
struct GatewayConfig {
    mac: EthernetAddress,
    ip: Ipv4Addr,
    ip6: Ipv6Addr,
    host_service_ports: Vec<Option<u16>>,
    published_ports: Vec<PublishedPort>,
    mtu: usize,
    flow_capacity: usize,
}

struct DeviceFrame {
    input: Option<Vec<u8>>,
    output: Vec<Vec<u8>>,
    mtu: usize,
}
struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Vec<Vec<u8>>);

impl DeviceFrame {
    fn new(input: Option<Vec<u8>>, mtu: usize) -> Self {
        Self {
            input,
            output: Vec::new(),
            mtu,
        }
    }
}
impl Device for DeviceFrame {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        Some((Rx(self.input.take()?), Tx(&mut self.output)))
    }
    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.output))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = self.mtu + 14;
        capabilities
    }
}
impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        self.0.push(frame);
        result
    }
}

struct Flow {
    id: u32,
    guest: TcpFlow,
    socket: Option<SocketHandle>,
    outgoing: Sender<Vec<u8>>,
    pending_guest_data: Option<Vec<u8>>,
    abort: AbortHandle,
}
impl Drop for Flow {
    fn drop(&mut self) {
        self.abort.abort();
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TcpFlow {
    source: IpAddr,
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
}
struct HostFlowStart {
    generation: u64,
    id: u32,
    destination: IpAddr,
    port: u16,
    outgoing: futures::channel::mpsc::Receiver<Vec<u8>>,
    registration: AbortRegistration,
}
struct UdpFlow {
    id: u32,
    abort: AbortHandle,
}
struct UdpFlowStart {
    generation: u64,
    id: u32,
    destination: IpAddr,
    request: UdpRequest,
    registration: AbortRegistration,
}
struct Background {
    generation: u64,
    id: u32,
    abort: AbortHandle,
}
struct PublishedFlow {
    id: u32,
    outgoing: Sender<Vec<u8>>,
    abort: AbortHandle,
}
struct PublishedFlowStart {
    generation: u64,
    id: u32,
    socket: wasi::sockets::types::TcpSocket,
    outgoing: futures::channel::mpsc::Receiver<Vec<u8>>,
    registration: AbortRegistration,
}

enum AddPublishedFlowError {
    Full(wasi::sockets::types::TcpSocket),
    Failed,
}
impl Drop for PublishedFlow {
    fn drop(&mut self) {
        self.abort.abort();
    }
}
impl Drop for Background {
    fn drop(&mut self) {
        self.abort.abort();
    }
}
impl Drop for UdpFlow {
    fn drop(&mut self) {
        self.abort.abort();
    }
}
#[derive(Clone)]
struct UdpRequest {
    source_mac: EthernetAddress,
    destination_mac: EthernetAddress,
    source: IpAddr,
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
    data: Vec<u8>,
}
impl UdpRequest {
    fn reply(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() > MAX_UDP_PACKET_BYTES {
            return None;
        }
        let header = match self.source {
            IpAddr::V4(_) => 20,
            IpAddr::V6(_) => 40,
        };
        let mut frame = vec![0; 14 + header + 8 + data.len()];
        let mut ethernet = EthernetFrame::new_unchecked(&mut frame);
        ethernet.set_dst_addr(self.source_mac);
        ethernet.set_src_addr(self.destination_mac);
        match (self.source, self.destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                ethernet.set_ethertype(EthernetProtocol::Ipv4);
                let mut ip = Ipv4Packet::new_unchecked(ethernet.payload_mut());
                ip.set_version(4);
                ip.set_hop_limit(64);
                ip.set_header_len(20);
                ip.set_total_len(u16::try_from(20 + 8 + data.len()).ok()?);
                ip.set_next_header(IpProtocol::Udp);
                ip.set_src_addr(destination);
                ip.set_dst_addr(source);
                let source = IpAddress::Ipv4(ip.src_addr());
                let destination = IpAddress::Ipv4(ip.dst_addr());
                UdpRepr {
                    src_port: self.destination_port,
                    dst_port: self.source_port,
                }
                .emit(
                    &mut UdpPacket::new_unchecked(ip.payload_mut()),
                    &source,
                    &destination,
                    data.len(),
                    |payload| payload.copy_from_slice(data),
                    &smoltcp::phy::ChecksumCapabilities::default(),
                );
                ip.fill_checksum();
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                ethernet.set_ethertype(EthernetProtocol::Ipv6);
                let mut ip = Ipv6Packet::new_unchecked(ethernet.payload_mut());
                ip.set_version(6);
                ip.set_next_header(IpProtocol::Udp);
                ip.set_hop_limit(64);
                ip.set_payload_len(u16::try_from(8 + data.len()).ok()?);
                ip.set_src_addr(destination);
                ip.set_dst_addr(source);
                let source = IpAddress::Ipv6(ip.src_addr());
                let destination = IpAddress::Ipv6(ip.dst_addr());
                UdpRepr {
                    src_port: self.destination_port,
                    dst_port: self.source_port,
                }
                .emit(
                    &mut UdpPacket::new_unchecked(ip.payload_mut()),
                    &source,
                    &destination,
                    data.len(),
                    |payload| payload.copy_from_slice(data),
                    &smoltcp::phy::ChecksumCapabilities::default(),
                );
            }
            _ => return None,
        }
        Some(frame)
    }
}
struct Gateway {
    config: Option<GatewayConfig>,
    interface: Option<Interface>,
    sockets: SocketSet<'static>,
    dns_socket: Option<SocketHandle>,
    flows: Vec<Flow>,
    finished_flows: VecDeque<u32>,
    udp_flows: Vec<UdpFlow>,
    background: Vec<Background>,
    published_flows: Vec<PublishedFlow>,
    published: published::PublishedTable,
    frames: VecDeque<Vec<u8>>,
    frame_bytes: usize,
    started: u64,
    next_flow: u32,
    next_background: u32,
    published_listeners_started: bool,
}

impl Gateway {
    fn new() -> Self {
        Self {
            config: None,
            interface: None,
            sockets: SocketSet::new(vec![]),
            dns_socket: None,
            flows: Vec::new(),
            finished_flows: VecDeque::new(),
            udp_flows: Vec::new(),
            background: Vec::new(),
            published_flows: Vec::new(),
            published: published::PublishedTable::new(),
            frames: VecDeque::new(),
            frame_bytes: 0,
            started: monotonic_now(),
            next_flow: 0,
            next_background: 0,
            published_listeners_started: false,
        }
    }
    fn configure(&mut self, config: GatewayConfig) {
        let mut device = DeviceFrame::new(None, config.mtu);
        let mut interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ethernet(config.mac)),
            &mut device,
            Instant::ZERO,
        );
        interface.update_ip_addrs(|addresses| {
            let _ = addresses.push(IpCidr::new(IpAddress::Ipv4(config.ip), 30));
            let _ = addresses.push(IpCidr::new(IpAddress::Ipv6(config.ip6), 64));
        });
        interface.set_any_ip(true);
        self.config = Some(config);
        self.interface = Some(interface);
        self.sockets = SocketSet::new(vec![]);
        let mut dns = UdpSocket::new(
            PacketBuffer::new(vec![PacketMetadata::EMPTY; 8], vec![0; 8192]),
            PacketBuffer::new(vec![PacketMetadata::EMPTY; 8], vec![0; 8192]),
        );
        let _ = dns.bind(IpListenEndpoint {
            addr: None,
            port: DNS_PORT,
        });
        self.dns_socket = Some(self.sockets.add(dns));
        self.flows.clear();
        self.finished_flows.clear();
        self.udp_flows.clear();
        self.background.clear();
        self.published_flows.clear();
        self.published = published::PublishedTable::new();
        self.frames.clear();
        self.frame_bytes = 0;
        self.started = monotonic_now();
        self.next_flow = 0;
        self.next_background = 0;
        self.published_listeners_started = false;
    }
    fn validate(&self, frame: &[u8]) -> Result<(), Error> {
        let config = self.config.as_ref().ok_or(Error::NotReady)?;
        (frame.len() >= 14 && frame.len() <= MAX_FRAME_BYTES && frame.len() - 14 <= config.mtu)
            .then_some(())
            .ok_or(Error::Malformed)
    }
    fn flow_capacity(&self) -> usize {
        self.config
            .as_ref()
            .map_or(0, |config| config.flow_capacity)
    }
    fn has_flow_capacity(&self, slots: usize) -> bool {
        self.flows.len()
            + self.udp_flows.len()
            + self.background.len()
            + 2 * self.published_flows.len()
            + slots
            <= self.flow_capacity()
    }
    fn add_flow(&mut self, guest: TcpFlow) -> Result<Option<HostFlowStart>, Error> {
        if self.flows.iter().any(|flow| flow.guest == guest) {
            return Ok(None);
        }
        let connect_destination =
            self.socket_destination(guest.destination, guest.destination_port);
        let Some(connect_destination) = connect_destination else {
            return Err(Error::NotReady);
        };
        if !self.has_flow_capacity(1) {
            return Err(Error::Backpressure);
        }
        let id = self.next_flow;
        self.next_flow = self.next_flow.wrapping_add(1);
        let (outgoing, incoming) = channel(1);
        let (abort, registration) = AbortHandle::new_pair();
        self.flows.push(Flow {
            id,
            guest,
            socket: None,
            outgoing,
            pending_guest_data: None,
            abort: abort.clone(),
        });
        Ok(Some(HostFlowStart {
            generation: GENERATION.load(Ordering::Acquire),
            id,
            destination: connect_destination,
            port: guest.destination_port,
            outgoing: incoming,
            registration,
        }))
    }
    fn activate_flow(&mut self, generation: u64, id: u32) -> Result<(), Error> {
        if generation != GENERATION.load(Ordering::Acquire) {
            return Err(Error::NotReady);
        }
        let flow = self
            .flows
            .iter_mut()
            .find(|flow| flow.id == id)
            .ok_or(Error::NotReady)?;
        if flow.socket.is_some() {
            return Ok(());
        }
        let guest = flow.guest;
        let mut socket = tcp::Socket::new(
            SocketBuffer::new(vec![0; TCP_BUFFER_BYTES]),
            SocketBuffer::new(vec![0; TCP_BUFFER_BYTES]),
        );
        socket.set_timeout(Some(smoltcp::time::Duration::from_secs(
            TCP_FLOW_TIMEOUT_SECS,
        )));
        socket
            .listen(IpListenEndpoint {
                addr: Some(guest.destination.into()),
                port: guest.destination_port,
            })
            .map_err(|_| Error::Backpressure)?;
        let socket = self.sockets.add(socket);
        flow.socket = Some(socket);
        Ok(())
    }

    #[cfg(test)]
    fn add_connected_flow(&mut self, guest: TcpFlow) -> Result<Option<HostFlowStart>, Error> {
        let flow = self.add_flow(guest)?;
        if let Some(flow) = &flow {
            self.activate_flow(flow.generation, flow.id)?;
        }
        Ok(flow)
    }

    fn add_udp_flow(&mut self, request: UdpRequest) -> Result<UdpFlowStart, Error> {
        let destination = self.socket_destination(request.destination, request.destination_port);
        let Some(destination) = destination else {
            return Err(Error::NotReady);
        };
        if !self.has_flow_capacity(1) {
            return Err(Error::Backpressure);
        }
        let id = self.next_flow;
        self.next_flow = self.next_flow.wrapping_add(1);
        let (abort, registration) = AbortHandle::new_pair();
        self.udp_flows.push(UdpFlow { id, abort });
        Ok(UdpFlowStart {
            generation: GENERATION.load(Ordering::Acquire),
            id,
            destination,
            request,
            registration,
        })
    }
    fn finish_udp_flow(&mut self, generation: u64, id: u32) {
        if GENERATION.load(Ordering::Acquire) != generation {
            return;
        }
        self.udp_flows.retain(|flow| flow.id != id);
        PUBLISHED_FLOW_WAKER.wake();
    }
    fn reject_pending_flow(&mut self, generation: u64, id: u32, syn_frame: &[u8]) {
        if generation != GENERATION.load(Ordering::Acquire)
            || !self
                .flows
                .iter()
                .any(|flow| flow.id == id && flow.socket.is_none())
        {
            return;
        }
        self.finish_flow(generation, id);
        if let Some(reset) = tcp_reset(syn_frame) {
            let _ = self.enqueue(reset);
        }
    }
    fn finish_flow(&mut self, generation: u64, id: u32) {
        if GENERATION.load(Ordering::Acquire) != generation {
            return;
        }
        let Some(index) = self.flows.iter().position(|flow| flow.id == id) else {
            return;
        };
        let Some(socket) = self.flows[index].socket else {
            self.flows.swap_remove(index);
            PUBLISHED_FLOW_WAKER.wake();
            return;
        };
        self.sockets.get_mut::<tcp::Socket>(socket).abort();
        if !self.finished_flows.contains(&id) {
            self.finished_flows.push_back(id);
        }
        WORK_WAKER.wake();
    }
    fn close_host_input(&mut self, generation: u64, id: u32) {
        if GENERATION.load(Ordering::Acquire) != generation {
            return;
        }
        if let Some(socket) = self
            .flows
            .iter()
            .find(|flow| flow.id == id)
            .and_then(|flow| flow.socket)
        {
            self.sockets.get_mut::<tcp::Socket>(socket).close();
            let _ = self.pump(None);
            WORK_WAKER.wake();
        }
    }
    fn reap_finished_flows(&mut self) {
        let generation = GENERATION.load(Ordering::Acquire);
        let timed_out = self
            .flows
            .iter()
            .filter(|flow| {
                flow.socket
                    .is_some_and(|socket| !self.sockets.get::<tcp::Socket>(socket).is_open())
            })
            .map(|flow| flow.id)
            .collect::<Vec<_>>();
        for id in timed_out {
            self.finish_flow(generation, id);
        }
        for _ in 0..MAX_WORK_PER_WAKE {
            let Some(id) = self.finished_flows.pop_front() else {
                return;
            };
            let Some(index) = self.flows.iter().position(|flow| flow.id == id) else {
                continue;
            };
            let Some(socket) = self.flows[index].socket else {
                continue;
            };
            if self.sockets.get::<tcp::Socket>(socket).state() != tcp::State::Closed {
                self.finished_flows.push_back(id);
                continue;
            }
            self.flows.swap_remove(index);
            self.sockets.remove(socket);
            PUBLISHED_FLOW_WAKER.wake();
        }
    }
    fn add_background(&mut self) -> Result<(u64, u32, AbortRegistration), Error> {
        if !self.has_flow_capacity(1) {
            return Err(Error::Backpressure);
        }
        let id = self.next_background;
        self.next_background = self.next_background.wrapping_add(1);
        let (abort, registration) = AbortHandle::new_pair();
        let generation = GENERATION.load(Ordering::Acquire);
        self.background.push(Background {
            generation,
            id,
            abort,
        });
        Ok((generation, id, registration))
    }
    fn finish_background(&mut self, generation: u64, id: u32) {
        if GENERATION.load(Ordering::Acquire) == generation {
            self.background
                .retain(|task| task.generation != generation || task.id != id);
            PUBLISHED_FLOW_WAKER.wake();
        }
    }
    fn add_published_flow(
        &mut self,
        guest_port: u16,
        socket: wasi::sockets::types::TcpSocket,
    ) -> Result<PublishedFlowStart, AddPublishedFlowError> {
        if !self.has_flow_capacity(2) {
            return Err(AddPublishedFlowError::Full(socket));
        }
        let config = self.config.as_ref().ok_or(AddPublishedFlowError::Failed)?;
        let guest_ip = Ipv4Addr::from(u32::from(config.ip).saturating_add(1));
        let id = self.next_flow;
        self.next_flow = self.next_flow.wrapping_add(1);
        let Some(interface) = self.interface.as_mut() else {
            return Err(AddPublishedFlowError::Failed);
        };
        match self.published.accept(
            id,
            guest_ip,
            guest_port,
            config.ip,
            interface,
            &mut self.sockets,
        ) {
            Ok(()) => {}
            Err(published::Error::Full) => return Err(AddPublishedFlowError::Full(socket)),
            Err(published::Error::Unknown | published::Error::Backpressure) => {
                return Err(AddPublishedFlowError::Failed);
            }
        }
        let _ = self.pump(None);
        let (outgoing, incoming) = channel(1);
        let (abort, registration) = AbortHandle::new_pair();
        self.published_flows.push(PublishedFlow {
            id,
            outgoing,
            abort,
        });
        Ok(PublishedFlowStart {
            generation: GENERATION.load(Ordering::Acquire),
            id,
            socket,
            outgoing: incoming,
            registration,
        })
    }
    fn finish_published_flow(&mut self, generation: u64, id: u32) {
        if GENERATION.load(Ordering::Acquire) != generation {
            return;
        }
        if let Some(index) = self.published_flows.iter().position(|flow| flow.id == id) {
            self.published_flows.swap_remove(index);
            let _ = self.published.abort(id, &mut self.sockets);
            PUBLISHED_FLOW_WAKER.wake();
        }
    }
    fn deliver_published(&mut self, id: u32, data: &[u8]) -> Result<(), Error> {
        match self.published.deliver(id, data) {
            Ok(()) => {}
            Err(published::Error::Unknown) => return Err(Error::NotReady),
            Err(published::Error::Full | published::Error::Backpressure) => {
                return Err(Error::Backpressure);
            }
        }
        let _ = self.pump(None);
        Ok(())
    }
    fn finish_published_input(&mut self, id: u32) -> Result<(), Error> {
        self.published
            .host_eof(id)
            .map_err(|_| Error::Backpressure)?;
        self.pump(None)
    }
    fn pump(&mut self, input: Option<Vec<u8>>) -> Result<(), Error> {
        let config = self.config.as_ref().ok_or(Error::NotReady)?;
        let mut device = DeviceFrame::new(input, config.mtu);
        self.published.pump(&mut self.sockets);
        let now = protocol_now(self.started);
        self.interface
            .as_mut()
            .ok_or(Error::NotReady)?
            .poll(now, &mut device, &mut self.sockets);
        self.published.pump(&mut self.sockets);
        let mut terminal = Vec::new();
        let mut guest_eof = Vec::new();
        for flow in &mut self.published_flows {
            for data in self
                .published
                .take_upstream(flow.id, TCP_CHUNK_BYTES)
                .map_err(|_| Error::Backpressure)?
            {
                if let Err(error) = flow.outgoing.try_send(data) {
                    self.published
                        .restore_upstream(flow.id, error.into_inner())
                        .map_err(|_| Error::Backpressure)?;
                    break;
                }
            }
            if self
                .published
                .is_terminal(flow.id, &self.sockets)
                .map_err(|_| Error::Backpressure)?
            {
                terminal.push(flow.id);
            }
            if self
                .published
                .guest_eof(flow.id, &self.sockets)
                .map_err(|_| Error::Backpressure)?
            {
                guest_eof.push(flow.id);
            }
        }
        for id in terminal.into_iter().chain(guest_eof) {
            if let Some(flow) = self.published_flows.iter_mut().find(|flow| flow.id == id) {
                flow.outgoing.close_channel();
            }
        }
        for frame in device.output {
            self.enqueue(frame)?;
        }
        Ok(())
    }
    fn enqueue(&mut self, frame: Vec<u8>) -> Result<(), Error> {
        if self.frames.len() == MAX_QUEUED_FRAMES
            || self.frame_bytes.saturating_add(frame.len()) > MAX_QUEUED_BYTES
        {
            return Err(Error::Backpressure);
        }
        self.frame_bytes += frame.len();
        self.frames.push_back(frame);
        TICK.store(true, Ordering::Release);
        WORK_WAKER.wake();
        Ok(())
    }
    fn socket_destination(&self, destination: IpAddr, port: u16) -> Option<IpAddr> {
        let config = self.config.as_ref()?;
        if destination != IpAddr::V4(config.ip) && destination != IpAddr::V6(config.ip6) {
            return Some(destination);
        }
        config
            .host_service_ports
            .iter()
            .any(|grant| grant.is_none_or(|grant| grant == port))
            .then_some(match destination {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            })
    }
    fn protocol_delay(&mut self) -> Option<u64> {
        self.interface
            .as_mut()?
            .poll_delay(protocol_now(self.started), &self.sockets)
            .map(|delay| delay.total_micros().saturating_mul(1_000))
    }
    fn take_frames(&mut self, max_items: usize, max_bytes: usize) -> Vec<Vec<u8>> {
        let mut bytes: usize = 0;
        let mut frames = Vec::new();
        while frames.len() < max_items {
            let Some(frame) = self.frames.front() else {
                break;
            };
            if bytes.saturating_add(frame.len()) > max_bytes {
                break;
            }
            let Some(frame) = self.frames.pop_front() else {
                break;
            };
            bytes += frame.len();
            self.frame_bytes -= frame.len();
            frames.push(frame);
        }
        frames
    }
    fn guest_data(&mut self) {
        for flow in &mut self.flows {
            let Some(socket) = flow.socket else {
                continue;
            };
            if let Some(data) = flow.pending_guest_data.take()
                && let Err(error) = flow.outgoing.try_send(data)
            {
                flow.pending_guest_data = Some(error.into_inner());
                continue;
            }
            let socket = self.sockets.get_mut::<tcp::Socket>(socket);
            while socket.can_recv() {
                let mut data = vec![0; socket.recv_queue().min(TCP_CHUNK_BYTES)];
                match socket.recv_slice(&mut data) {
                    Ok(size) if size > 0 => {
                        data.truncate(size);
                        if let Err(error) = flow.outgoing.try_send(data) {
                            flow.pending_guest_data = Some(error.into_inner());
                            break;
                        }
                    }
                    _ => break,
                }
            }
            if matches!(
                socket.state(),
                tcp::State::CloseWait
                    | tcp::State::Closing
                    | tcp::State::LastAck
                    | tcp::State::TimeWait
                    | tcp::State::Closed
            ) && socket.recv_queue() == 0
                && flow.pending_guest_data.is_none()
            {
                flow.outgoing.close_channel();
            }
        }
    }
    fn send_tcp(&mut self, id: u32, data: &[u8]) -> Result<usize, Error> {
        let socket = self
            .flows
            .iter()
            .find(|flow| flow.id == id)
            .and_then(|flow| flow.socket)
            .ok_or(Error::Malformed)?;
        let size = self
            .sockets
            .get_mut::<tcp::Socket>(socket)
            .send_slice(data)
            .map_err(|_| Error::Backpressure)?;
        let _ = self.pump(None);
        Ok(size)
    }
    fn send_current_tcp(&mut self, generation: u64, id: u32, data: &[u8]) -> Result<usize, Error> {
        if GENERATION.load(Ordering::Acquire) != generation {
            return Err(Error::NotReady);
        }
        self.send_tcp(id, data)
    }
    fn register_tcp_send_waker(&mut self, id: u32, waker: &std::task::Waker) {
        if let Some(socket) = self
            .flows
            .iter()
            .find(|flow| flow.id == id)
            .and_then(|flow| flow.socket)
        {
            self.sockets
                .get_mut::<tcp::Socket>(socket)
                .register_send_waker(waker);
        }
    }
    fn register_published_send_waker(&mut self, id: u32, waker: &std::task::Waker) -> bool {
        self.published
            .register_send_waker(id, &mut self.sockets, waker)
            .is_ok()
    }
    fn dns_queries(&mut self) -> Vec<(Vec<u8>, UdpMetadata)> {
        let mut queries = Vec::new();
        let Some(handle) = self.dns_socket else {
            return queries;
        };
        let socket = self.sockets.get_mut::<UdpSocket>(handle);
        while socket.can_recv() {
            match socket.recv() {
                Ok((data, meta)) => queries.push((data.to_vec(), meta)),
                Err(_) => break,
            }
        }
        queries
    }
    fn dns_reply(&mut self, data: &[u8], meta: UdpMetadata) -> Result<(), Error> {
        let handle = self.dns_socket.ok_or(Error::NotReady)?;
        self.sockets
            .get_mut::<UdpSocket>(handle)
            .send_slice(data, meta)
            .map_err(|_| Error::Backpressure)?;
        self.pump(None)
    }
}

fn tcp_syn(frame: &[u8]) -> Option<TcpFlow> {
    let ethernet = EthernetFrame::new_checked(frame).ok()?;
    match ethernet.ethertype() {
        EthernetProtocol::Ipv4 => {
            let ip = Ipv4Packet::new_checked(ethernet.payload()).ok()?;
            ip.verify_checksum().then_some(())?;
            let tcp = (ip.next_header() == IpProtocol::Tcp)
                .then(|| TcpPacket::new_checked(ip.payload()).ok())??;
            let source = IpAddress::Ipv4(ip.src_addr());
            let destination = IpAddress::Ipv4(ip.dst_addr());
            tcp.verify_checksum(&source, &destination).then_some(())?;
            (tcp.syn() && !tcp.ack()).then(|| TcpFlow {
                source: source.into(),
                source_port: tcp.src_port(),
                destination: destination.into(),
                destination_port: tcp.dst_port(),
            })
        }
        EthernetProtocol::Ipv6 => {
            let ip = Ipv6Packet::new_checked(ethernet.payload()).ok()?;
            let tcp = (ip.next_header() == IpProtocol::Tcp)
                .then(|| TcpPacket::new_checked(ip.payload()).ok())??;
            let source = IpAddress::Ipv6(ip.src_addr());
            let destination = IpAddress::Ipv6(ip.dst_addr());
            tcp.verify_checksum(&source, &destination).then_some(())?;
            (tcp.syn() && !tcp.ack()).then(|| TcpFlow {
                source: source.into(),
                source_port: tcp.src_port(),
                destination: destination.into(),
                destination_port: tcp.dst_port(),
            })
        }
        _ => None,
    }
}
fn tcp_reset(frame: &[u8]) -> Option<Vec<u8>> {
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{IpRepr, TcpControl, TcpRepr, TcpSeqNumber};

    let flow = tcp_syn(frame)?;
    let ethernet = EthernetFrame::new_checked(frame).ok()?;
    let acknowledgement = match ethernet.ethertype() {
        EthernetProtocol::Ipv4 => {
            let ip = Ipv4Packet::new_checked(ethernet.payload()).ok()?;
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            tcp.seq_number() + tcp.segment_len()
        }
        EthernetProtocol::Ipv6 => {
            let ip = Ipv6Packet::new_checked(ethernet.payload()).ok()?;
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            tcp.seq_number() + tcp.segment_len()
        }
        _ => return None,
    };
    let reset = TcpRepr {
        src_port: flow.destination_port,
        dst_port: flow.source_port,
        control: TcpControl::Rst,
        seq_number: TcpSeqNumber(0),
        ack_number: Some(acknowledgement),
        window_len: 0,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    let ip = IpRepr::new(
        flow.destination.into(),
        flow.source.into(),
        IpProtocol::Tcp,
        reset.buffer_len(),
        64,
    );
    let mut frame = vec![0; 14 + ip.buffer_len()];
    let mut reply = EthernetFrame::new_unchecked(&mut frame);
    reply.set_src_addr(ethernet.dst_addr());
    reply.set_dst_addr(ethernet.src_addr());
    reply.set_ethertype(ethernet.ethertype());
    let checksums = ChecksumCapabilities::default();
    ip.emit(reply.payload_mut(), &checksums);
    reset.emit(
        &mut TcpPacket::new_unchecked(&mut reply.payload_mut()[ip.header_len()..]),
        &ip.src_addr(),
        &ip.dst_addr(),
        &checksums,
    );
    Some(frame)
}

fn udp_request(frame: &[u8]) -> Option<UdpRequest> {
    let ethernet = EthernetFrame::new_checked(frame).ok()?;
    let (source, destination, payload) = match ethernet.ethertype() {
        EthernetProtocol::Ipv4 => {
            let ip = Ipv4Packet::new_checked(ethernet.payload()).ok()?;
            ip.verify_checksum().then_some(())?;
            (ip.next_header() == IpProtocol::Udp).then_some((
                IpAddr::V4(ip.src_addr()),
                IpAddr::V4(ip.dst_addr()),
                ip.payload(),
            ))?
        }
        EthernetProtocol::Ipv6 => {
            let ip = Ipv6Packet::new_checked(ethernet.payload()).ok()?;
            (ip.next_header() == IpProtocol::Udp).then_some((
                IpAddr::V6(ip.src_addr()),
                IpAddr::V6(ip.dst_addr()),
                ip.payload(),
            ))?
        }
        _ => return None,
    };
    let udp = UdpPacket::new_checked(payload).ok()?;
    (!source.is_ipv6() || udp.checksum() != 0).then_some(())?;
    udp.verify_checksum(&source.into(), &destination.into())
        .then_some(())?;
    (udp.dst_port() != DNS_PORT && udp.payload().len() <= MAX_UDP_PACKET_BYTES).then(|| {
        UdpRequest {
            source_mac: ethernet.src_addr(),
            destination_mac: ethernet.dst_addr(),
            source,
            source_port: udp.src_port(),
            destination,
            destination_port: udp.dst_port(),
            data: udp.payload().to_vec(),
        }
    })
}
static GATEWAY: LazyLock<Mutex<Gateway>> = LazyLock::new(|| Mutex::new(Gateway::new()));
static GENERATION: AtomicU64 = AtomicU64::new(0);
static RUNNING: AtomicBool = AtomicBool::new(false);
static TICK: AtomicBool = AtomicBool::new(false);
static WORK: LazyLock<Mutex<VecDeque<Vec<u8>>>> = LazyLock::new(|| Mutex::new(VecDeque::new()));
static WORK_WAKER: futures::task::AtomicWaker = futures::task::AtomicWaker::new();
static PUBLISHED_FLOW_WAKER: futures::task::AtomicWaker = futures::task::AtomicWaker::new();
fn gateway() -> std::sync::MutexGuard<'static, Gateway> {
    GATEWAY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn queue_frame(frame: Vec<u8>) -> Result<(), Error> {
    gateway().validate(&frame)?;
    let mut work = WORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if work.len() == MAX_QUEUED_FRAMES
        || work
            .iter()
            .map(Vec::len)
            .sum::<usize>()
            .saturating_add(frame.len())
            > MAX_QUEUED_BYTES
    {
        return Err(Error::Backpressure);
    }
    work.push_back(frame);
    WORK_WAKER.wake();
    Ok(())
}
fn take_work() -> Option<Vec<u8>> {
    WORK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .pop_front()
}
pub(crate) fn tick() {
    TICK.store(true, Ordering::Release);
    WORK_WAKER.wake();
}
async fn wait_for_work() {
    poll_fn(|context| {
        WORK_WAKER.register(context.waker());
        if RUNNING.load(Ordering::Acquire)
            && WORK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
            && !TICK.load(Ordering::Acquire)
        {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
}

fn protocol_delay() -> Option<u64> {
    gateway().protocol_delay()
}

fn monotonic_now() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        wasi::clocks::monotonic_clock::now()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::sync::OnceLock;
        use std::time::Instant as MonotonicInstant;

        static STARTED: OnceLock<MonotonicInstant> = OnceLock::new();
        u64::try_from(
            STARTED
                .get_or_init(MonotonicInstant::now)
                .elapsed()
                .as_nanos(),
        )
        .unwrap_or(u64::MAX)
    }
}

fn protocol_now(started: u64) -> Instant {
    let elapsed = monotonic_now().wrapping_sub(started) / 1_000_000;
    Instant::from_millis(i64::try_from(elapsed).unwrap_or(i64::MAX))
}

async fn wait_for_activity() -> bool {
    let Some(delay) = protocol_delay() else {
        wait_for_work().await;
        return false;
    };
    let work = wait_for_work().fuse();
    let timer = wasi::clocks::monotonic_clock::wait_for(delay).fuse();
    futures::pin_mut!(work, timer);
    futures::select! {
        () = work => false,
        () = timer => true,
    }
}

fn config(config: Config) -> Result<GatewayConfig, Error> {
    let mac: [u8; 6] = config
        .gateway_mac
        .try_into()
        .map_err(|_| Error::Malformed)?;
    let ip: [u8; 4] = config.gateway_ip.try_into().map_err(|_| Error::Malformed)?;
    let ip6: [u8; 16] = config
        .gateway_ip6
        .try_into()
        .map_err(|_| Error::Malformed)?;
    let mtu = usize::try_from(config.mtu).map_err(|_| Error::Malformed)?;
    (576..=MAX_FRAME_BYTES - 14)
        .contains(&mtu)
        .then_some(GatewayConfig {
            mac: EthernetAddress(mac),
            ip: Ipv4Addr::from(ip),
            ip6: Ipv6Addr::from(ip6),
            host_service_ports: config.host_service_ports,
            published_ports: config.published_ports,
            mtu,
            flow_capacity: usize::try_from(config.flow_capacity).map_err(|_| Error::Malformed)?,
        })
        .ok_or(Error::Malformed)
}
fn start_dns(query: Vec<u8>, meta: UdpMetadata) -> Result<(), Error> {
    let Some(name) = dns::question_name(&query) else {
        return gateway().dns_reply(&dns::error_response(&query, dns::DNS_RCODE_SERVFAIL), meta);
    };
    let (generation, id, registration) = gateway().add_background()?;
    wit_bindgen::rt::async_support::spawn_local(async move {
        let response = Abortable::new(resolve_dns(name, query), registration).await;
        if let Ok(response) = response
            && GENERATION.load(Ordering::Relaxed) == generation
        {
            let _ = gateway().dns_reply(&response, meta);
        }
        gateway().finish_background(generation, id);
    });
    Ok(())
}

async fn resolve_dns(name: String, query: Vec<u8>) -> Vec<u8> {
    match wasi::sockets::ip_name_lookup::resolve_addresses(name).await {
        Ok(addresses) => dns::build_ip_response(
            &query,
            &addresses
                .into_iter()
                .map(host_ip_address)
                .collect::<Vec<_>>(),
            LEARNED_DNS_TTL_SECS,
        ),
        Err(wasi::sockets::ip_name_lookup::ErrorCode::AccessDenied) => {
            dns::error_response(&query, dns::DNS_RCODE_NXDOMAIN)
        }
        Err(_) => dns::error_response(&query, dns::DNS_RCODE_SERVFAIL),
    }
}

fn host_ip_address(address: wasi::sockets::types::IpAddress) -> IpAddr {
    match address {
        wasi::sockets::types::IpAddress::Ipv4((a, b, c, d)) => {
            IpAddr::V4(Ipv4Addr::new(a, b, c, d))
        }
        wasi::sockets::types::IpAddress::Ipv6(segments) => {
            IpAddr::V6(Ipv6Addr::from(<[u16; 8]>::from(segments)))
        }
    }
}
async fn run_published_listener(host_port: u16, guest_port: u16, ipv6: bool) -> Result<(), Error> {
    loop {
        let result = run_published_listener_inner(host_port, guest_port, ipv6).await;
        if let Err(error) = result {
            terra::host::diagnostics::event(&format!(
                "published {} listener on port {host_port} stopped: {error:?}",
                if ipv6 { "IPv6" } else { "IPv4" },
            ));
        }
        if !RUNNING.load(Ordering::Acquire) {
            return result;
        }
        wasi::clocks::monotonic_clock::wait_for(PUBLISHED_LISTENER_RETRY_DELAY).await;
    }
}

async fn run_published_listener_inner(
    host_port: u16,
    guest_port: u16,
    ipv6: bool,
) -> Result<(), Error> {
    let socket = TcpSocket::create(if ipv6 {
        IpAddressFamily::Ipv6
    } else {
        IpAddressFamily::Ipv4
    })
    .map_err(|_| Error::Backpressure)?;
    socket
        .bind(if ipv6 {
            IpSocketAddress::Ipv6(Ipv6SocketAddress {
                address: (0, 0, 0, 0, 0, 0, 0, 1),
                port: host_port,
                flow_info: 0,
                scope_id: 0,
            })
        } else {
            IpSocketAddress::Ipv4(Ipv4SocketAddress {
                address: (127, 0, 0, 1),
                port: host_port,
            })
        })
        .map_err(|_| Error::Backpressure)?;
    let mut listener = socket.listen().map_err(|_| Error::Backpressure)?;
    loop {
        match listener.read(Vec::with_capacity(1)).await {
            (wit_bindgen::rt::async_support::StreamResult::Complete(count), sockets)
                if count > 0 =>
            {
                for socket in sockets.into_iter().take(count) {
                    if !add_published_flow(guest_port, socket).await {
                        return Ok(());
                    }
                }
            }
            _ => return Err(Error::NotReady),
        }
    }
}
async fn add_published_flow(guest_port: u16, socket: wasi::sockets::types::TcpSocket) -> bool {
    let mut pending_socket = Some(socket);
    poll_fn(|context| {
        let Some(socket) = pending_socket.take() else {
            return Poll::Ready(false);
        };
        let result = { gateway().add_published_flow(guest_port, socket) };
        match result {
            Ok(flow) => {
                start_published_flow(flow);
                Poll::Ready(true)
            }
            Err(AddPublishedFlowError::Full(socket)) => {
                pending_socket = Some(socket);
                PUBLISHED_FLOW_WAKER.register(context.waker());
                if gateway().has_flow_capacity(2) {
                    context.waker().wake_by_ref();
                }
                Poll::Pending
            }
            Err(AddPublishedFlowError::Failed) => Poll::Ready(true),
        }
    })
    .await
}
async fn next_host_chunk(
    outgoing: &mut (impl futures::Stream<Item = Vec<u8>> + Unpin),
) -> Option<Vec<u8>> {
    let chunk = outgoing.next().await?;
    tick();
    Some(chunk)
}

fn start_published_flow(flow: PublishedFlowStart) {
    let PublishedFlowStart {
        generation,
        id,
        socket,
        outgoing,
        registration,
    } = flow;
    wit_bindgen::rt::async_support::spawn_local(async move {
        let _ = Abortable::new(
            async move {
                let (mut writer, outgoing_stream) = wit_stream::new();
                let send = socket.send(outgoing_stream).into_future().fuse();
                let (mut incoming_stream, receive) = socket.receive();
                let receive = receive.into_future().fuse();
                let mut outgoing = outgoing.fuse();
                let input = async {
                    loop {
                        match incoming_stream
                            .read(Vec::with_capacity(TCP_CHUNK_BYTES))
                            .await
                        {
                            (
                                wit_bindgen::rt::async_support::StreamResult::Complete(size),
                                data,
                            ) if size > 0 => {
                                if !deliver_published(generation, id, &data[..size]).await {
                                    return false;
                                }
                            }
                            _ => return gateway().finish_published_input(id).is_ok(),
                        }
                    }
                }
                .fuse();
                let output = async move {
                    while let Some(data) = next_host_chunk(&mut outgoing).await {
                        if !writer.write_all(data).await.is_empty() {
                            return false;
                        }
                    }
                    true
                }
                .fuse();
                futures::pin_mut!(send, receive, input, output);
                loop {
                    futures::select! {
                        result = send => if result.is_err() { return; },
                        result = receive => if result.is_err() { return; },
                        input_ok = input => if !input_ok { return; },
                        output_ok = output => if !output_ok { return; },
                        complete => return,
                    }
                }
            },
            registration,
        )
        .await;
        gateway().finish_published_flow(generation, id);
    });
}

async fn deliver_published(generation: u64, id: u32, data: &[u8]) -> bool {
    poll_fn(|context| {
        let mut state = gateway();
        if GENERATION.load(Ordering::Acquire) != generation {
            return Poll::Ready(false);
        }
        match state.deliver_published(id, data) {
            Ok(()) => Poll::Ready(true),
            Err(Error::Backpressure) => {
                if state.register_published_send_waker(id, context.waker()) {
                    Poll::Pending
                } else {
                    Poll::Ready(false)
                }
            }
            Err(Error::Malformed | Error::NotReady) => Poll::Ready(false),
        }
    })
    .await
}

async fn deliver_host_tcp(generation: u64, id: u32, mut data: Vec<u8>) -> bool {
    while !data.is_empty() {
        let sent = poll_fn(|context| {
            let mut state = gateway();
            match state.send_current_tcp(generation, id, &data) {
                Ok(size) if size > 0 => Poll::Ready(Ok(size)),
                Ok(_) | Err(Error::Backpressure) => {
                    state.register_tcp_send_waker(id, context.waker());
                    Poll::Pending
                }
                Err(error) => Poll::Ready(Err(error)),
            }
        })
        .await;
        let Ok(sent) = sent else {
            return false;
        };
        data = data.split_off(sent);
    }
    true
}

async fn connect_host_tcp(socket: &TcpSocket, destination: IpAddr, port: u16) -> bool {
    let address = match destination {
        IpAddr::V4(address) => IpSocketAddress::Ipv4(Ipv4SocketAddress {
            address: address.octets().into(),
            port,
        }),
        IpAddr::V6(address) => IpSocketAddress::Ipv6(Ipv6SocketAddress {
            address: address.segments().into(),
            port,
            flow_info: 0,
            scope_id: 0,
        }),
    };
    let connect = socket.connect(address).fuse();
    let timeout =
        wasi::clocks::monotonic_clock::wait_for(TCP_FLOW_TIMEOUT_SECS * 1_000_000_000).fuse();
    futures::pin_mut!(connect, timeout);
    futures::select! {
        result = connect => result.is_ok(),
        () = timeout => false,
    }
}

fn start_host_flow(flow: HostFlowStart, syn_frame: Vec<u8>) {
    let HostFlowStart {
        generation,
        id,
        destination,
        port,
        outgoing,
        registration,
    } = flow;
    wit_bindgen::rt::async_support::spawn_local(async move {
        let outcome = Abortable::new(
            async move {
                let Ok(socket) = TcpSocket::create(match destination {
                    IpAddr::V4(_) => IpAddressFamily::Ipv4,
                    IpAddr::V6(_) => IpAddressFamily::Ipv6,
                }) else {
                    gateway().reject_pending_flow(generation, id, &syn_frame);
                    return false;
                };
                if !connect_host_tcp(&socket, destination, port).await {
                    gateway().reject_pending_flow(generation, id, &syn_frame);
                    return false;
                }
                {
                    let mut state = gateway();
                    if state
                        .activate_flow(generation, id)
                        .and_then(|()| state.pump(Some(syn_frame)))
                        .is_err()
                    {
                        return false;
                    }
                }
                let (mut writer, outgoing_stream) = wit_stream::new();
                let send = socket.send(outgoing_stream).into_future().fuse();
                let (mut incoming_stream, receive) = socket.receive();
                let receive = receive.into_future().fuse();
                let mut outgoing = outgoing.fuse();
                let forward = async move {
                    while let Some(data) = next_host_chunk(&mut outgoing).await {
                        if !writer.write_all(data).await.is_empty() {
                            return;
                        }
                    }
                }
                .fuse();
                let incoming = async {
                    loop {
                        match incoming_stream
                            .read(Vec::with_capacity(TCP_CHUNK_BYTES))
                            .await
                        {
                            (StreamResult::Complete(size), data) if size > 0 => {
                                if !deliver_host_tcp(generation, id, data[..size].to_vec()).await {
                                    return false;
                                }
                            }
                            (StreamResult::Dropped | StreamResult::Complete(0), _) => {
                                return true;
                            }
                            (StreamResult::Complete(_) | StreamResult::Cancelled, _) => {
                                return false;
                            }
                        }
                    }
                }
                .fuse();
                futures::pin_mut!(send, receive, forward, incoming);
                loop {
                    futures::select! {
                        result = send => if result.is_err() { return false; },
                        result = receive => if result.is_err() { return false; },
                        () = forward => {}
                        complete_input = incoming => {
                            if !complete_input { return false; }
                            gateway().close_host_input(generation, id);
                        },
                        complete => return true,
                    }
                }
            },
            registration,
        )
        .await;
        if outcome != Ok(true) {
            gateway().finish_flow(generation, id);
        }
    });
}
fn start_udp_flow(flow: UdpFlowStart) {
    let UdpFlowStart {
        generation,
        id,
        destination,
        request,
        registration,
    } = flow;
    wit_bindgen::rt::async_support::spawn_local(async move {
        let reply = Abortable::new(
            async move {
                let socket = WasiUdpSocket::create(match destination {
                    IpAddr::V4(_) => IpAddressFamily::Ipv4,
                    IpAddr::V6(_) => IpAddressFamily::Ipv6,
                })
                .ok()?;
                socket
                    .connect(match destination {
                        IpAddr::V4(address) => IpSocketAddress::Ipv4(Ipv4SocketAddress {
                            address: (
                                address.octets()[0],
                                address.octets()[1],
                                address.octets()[2],
                                address.octets()[3],
                            ),
                            port: request.destination_port,
                        }),
                        IpAddr::V6(address) => IpSocketAddress::Ipv6(Ipv6SocketAddress {
                            address: address.segments().into(),
                            port: request.destination_port,
                            flow_info: 0,
                            scope_id: 0,
                        }),
                    })
                    .ok()?;
                socket.send(request.data.clone(), None).await.ok()?;
                let receive = socket.receive().fuse();
                let timeout = wasi::clocks::monotonic_clock::wait_for(UDP_RECEIVE_TIMEOUT).fuse();
                futures::pin_mut!(receive, timeout);
                futures::select! {
                    received = receive => request.reply(&received.ok()?.0),
                    () = timeout => None,
                }
            },
            registration,
        )
        .await;
        if GENERATION.load(Ordering::Acquire) == generation
            && let Ok(Some(frame)) = reply
        {
            let _ = gateway().enqueue(frame);
        }
        gateway().finish_udp_flow(generation, id);
    });
}
struct Network;

impl exports::terra::mmio::device::Guest for Network {
    async fn serve(
        requests: wit_bindgen::rt::async_support::StreamReader<terra::mmio::types::Request>,
    ) -> wit_bindgen::rt::async_support::StreamReader<terra::mmio::types::Reply> {
        mmio::serve(requests).await
    }
}
impl Guest for Network {
    fn configure(value: Config) -> Result<(), Error> {
        GENERATION.fetch_add(1, Ordering::Relaxed);
        WORK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        TICK.store(false, Ordering::Release);
        RUNNING.store(true, Ordering::Release);
        let config = config(value)?;
        gateway().configure(config);
        Ok(())
    }
    #[allow(clippy::unused_async_trait_impl)]
    async fn receive(frame: Vec<u8>) -> Result<(), Error> {
        queue_frame(frame)
    }
    async fn run() -> Result<(), Error> {
        let published_ports = {
            let mut state = gateway();
            if state.published_listeners_started {
                Vec::new()
            } else {
                state.published_listeners_started = true;
                state
                    .config
                    .as_ref()
                    .ok_or(Error::NotReady)?
                    .published_ports
                    .clone()
            }
        };
        let mut published_listeners = FuturesUnordered::new();
        for port in published_ports {
            published_listeners.push(run_published_listener(
                port.host_port,
                port.guest_port,
                false,
            ));
            published_listeners.push(run_published_listener(
                port.host_port,
                port.guest_port,
                true,
            ));
        }
        while RUNNING.load(Ordering::Acquire) {
            let timer_elapsed = if published_listeners.is_empty() {
                wait_for_activity().await
            } else {
                let work = wait_for_activity().fuse();
                futures::pin_mut!(work);
                futures::select! {
                    listener = published_listeners.next() => {
                        let _ = listener;
                        false
                    },
                    timer_elapsed = work => timer_elapsed,
                }
            };
            gateway().reap_finished_flows();
            let mut processed = 0;
            while processed < MAX_WORK_PER_WAKE {
                let Some(frame) = take_work() else {
                    break;
                };
                let _ = receive_frame(frame);
                processed += 1;
            }
            let signalled = TICK.swap(false, Ordering::AcqRel);
            if signalled || timer_elapsed {
                let _ = gateway().pump(None);
                gateway().guest_data();
                gateway().reap_finished_flows();
            }
            let queue_work = signalled || TICK.swap(false, Ordering::AcqRel);
            if (processed != 0 || queue_work) && transport::is_configured() {
                // An unaddressable ring cannot be completed; wait for reset or another doorbell.
                let _ = transport::service_queues().await;
            }
            if processed == MAX_WORK_PER_WAKE {
                wit_bindgen::rt::async_support::yield_async().await;
            }
        }
        Ok(())
    }
    fn take_frames(max_items: u32, max_bytes: u32) -> Vec<Vec<u8>> {
        gateway().take_frames(max_items as usize, max_bytes as usize)
    }
    fn reset() {
        GENERATION.fetch_add(1, Ordering::Relaxed);
        WORK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        TICK.store(false, Ordering::Release);
        *gateway() = Gateway::new();
    }
}

pub(crate) fn receive_frame(frame: Vec<u8>) -> Result<(), Error> {
    gateway().validate(&frame)?;
    let config = gateway().config.clone().ok_or(Error::NotReady)?;
    if let Some(reply) = icmp::reply(&frame, IpAddr::V4(config.ip), IpAddr::V6(config.ip6))? {
        gateway().enqueue(reply)?;
        return Ok(());
    }
    if let Some(guest) = tcp_syn(&frame) {
        let host_flow = gateway().add_flow(guest)?;
        if let Some(flow) = host_flow {
            start_host_flow(flow, frame);
            return Ok(());
        }
        if gateway()
            .flows
            .iter()
            .any(|flow| flow.guest == guest && flow.socket.is_none())
        {
            return Ok(());
        }
    }
    let udp_request = udp_request(&frame);
    let is_udp = udp_request.is_some();
    let udp_flow = udp_request
        .map(|request| gateway().add_udp_flow(request))
        .transpose()?;
    let queries = {
        let mut state = gateway();
        state.pump((!is_udp).then_some(frame))?;
        state.guest_data();
        state.dns_queries()
    };
    for (query, meta) in queries {
        start_dns(query, meta)?;
    }
    if let Some(flow) = udp_flow {
        start_udp_flow(flow);
    }
    Ok(())
}

pub(crate) fn reset_protocol() {
    GENERATION.fetch_add(1, Ordering::Relaxed);
    WORK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    TICK.store(false, Ordering::Release);
    let config = gateway().config.clone();
    if let Some(config) = config {
        gateway().configure(config);
    }
}

impl TransportGuest for Network {
    fn configure() -> Result<(), DeviceError> {
        transport::configure()
    }
}

impl Network {
    fn reset() {
        reset_protocol();
        transport::reset();
    }

    fn close() {
        GENERATION.fetch_add(1, Ordering::Relaxed);
        RUNNING.store(false, Ordering::Release);
        WORK_WAKER.wake();
        WORK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        TICK.store(false, Ordering::Release);
        *gateway() = Gateway::new();
        transport::close();
    }
}
#[allow(unsafe_code)]
mod component_exports {
    use super::{Network, bindings};
    bindings::export!(Network with_types_in bindings);
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        ArpOperation, ArpPacket, ArpRepr, TcpControl, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
    };
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    fn gateway() -> Gateway {
        let mut gateway = Gateway::new();
        gateway.configure(GatewayConfig {
            mac: EthernetAddress([2, 0, 0, 0, 0, 1]),
            ip: Ipv4Addr::new(100, 96, 0, 1),
            ip6: "fd53:4d00::1".parse().unwrap(),
            host_service_ports: Vec::new(),
            published_ports: Vec::new(),
            mtu: 1500,
            flow_capacity: 448,
        });
        gateway
    }

    #[test]
    fn run_drains_a_full_batch_without_waiting_for_another_tick() {
        <Network as Guest>::configure(Config {
            gateway_mac: vec![2, 0, 0, 0, 0, 1],
            gateway_ip: vec![100, 96, 0, 1],
            gateway_ip6: "fd53:4d00::1"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
            host_service_ports: Vec::new(),
            published_ports: Vec::new(),
            mtu: 1500,
            flow_capacity: 448,
        })
        .expect("network configures");
        for _ in 0..=MAX_WORK_PER_WAKE {
            queue_frame(vec![0; 14]).expect("frame queues");
        }

        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut run = std::pin::pin!(<Network as Guest>::run());
        assert!(matches!(run.as_mut().poll(&mut context), Poll::Pending));
        assert_eq!(WORK.lock().expect("work lock").len(), 1);
        assert!(matches!(run.as_mut().poll(&mut context), Poll::Pending));
        assert!(WORK.lock().expect("work lock").is_empty());
        RUNNING.store(false, Ordering::Release);
        draining_host_queue_wakes_pending_guest_data();
    }

    fn draining_host_queue_wakes_pending_guest_data() {
        struct WakeFlag(AtomicBool);
        impl std::task::Wake for WakeFlag {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.store(true, Ordering::Release);
            }
        }
        let flag = std::sync::Arc::new(WakeFlag(AtomicBool::new(false)));
        let waker = Waker::from(std::sync::Arc::clone(&flag));
        let mut gateway = gateway();
        let mut flow = gateway
            .add_connected_flow(tcp_syn(&syn()).unwrap())
            .unwrap()
            .unwrap();
        gateway.flows[0].outgoing.try_send(vec![1]).unwrap();
        gateway.flows[0].outgoing.try_send(vec![2]).unwrap();
        gateway.flows[0].pending_guest_data = Some(vec![3]);
        gateway.guest_data();
        assert_eq!(gateway.flows[0].pending_guest_data, Some(vec![3]));
        WORK_WAKER.register(&waker);
        assert_eq!(
            next_host_chunk(&mut flow.outgoing).now_or_never(),
            Some(Some(vec![1]))
        );
        assert!(flag.0.load(Ordering::Acquire));
        gateway.guest_data();
        assert!(gateway.flows[0].pending_guest_data.is_none());
        assert_eq!(flow.outgoing.next().now_or_never(), Some(Some(vec![2])));
        assert_eq!(flow.outgoing.next().now_or_never(), Some(Some(vec![3])));
    }

    fn syn() -> Vec<u8> {
        syn_to(Ipv4Addr::new(1, 1, 1, 1), 443)
    }
    fn syn_to(destination: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut frame = vec![0; 58];
        let mut ethernet = EthernetFrame::new_unchecked(&mut frame);
        ethernet.set_dst_addr(EthernetAddress([2, 0, 0, 0, 0, 1]));
        ethernet.set_src_addr(EthernetAddress([2, 0, 0, 0, 0, 2]));
        ethernet.set_ethertype(EthernetProtocol::Ipv4);
        let mut ip = Ipv4Packet::new_unchecked(ethernet.payload_mut());
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len(44);
        ip.set_next_header(IpProtocol::Tcp);
        ip.set_src_addr(Ipv4Addr::new(100, 96, 0, 2));
        ip.set_dst_addr(destination);
        let source = IpAddress::Ipv4(ip.src_addr());
        let destination = IpAddress::Ipv4(ip.dst_addr());
        TcpRepr {
            src_port: 40000,
            dst_port: port,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(1),
            ack_number: None,
            window_len: 65535,
            window_scale: None,
            max_seg_size: Some(1460),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        }
        .emit(
            &mut TcpPacket::new_unchecked(ip.payload_mut()),
            &source,
            &destination,
            &ChecksumCapabilities::default(),
        );
        ip.fill_checksum();
        frame
    }
    fn flow(destination: IpAddr, port: u16) -> TcpFlow {
        TcpFlow {
            source: IpAddr::V4(Ipv4Addr::new(100, 96, 0, 2)),
            source_port: 40000,
            destination,
            destination_port: port,
        }
    }
    fn arp_request() -> Vec<u8> {
        let mut frame = vec![0; 42];
        let mut ethernet = EthernetFrame::new_unchecked(&mut frame);
        ethernet.set_dst_addr(EthernetAddress([255; 6]));
        ethernet.set_src_addr(EthernetAddress([2, 0, 0, 0, 0, 2]));
        ethernet.set_ethertype(EthernetProtocol::Arp);
        ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: EthernetAddress([2, 0, 0, 0, 0, 2]),
            source_protocol_addr: Ipv4Addr::new(100, 96, 0, 2),
            target_hardware_addr: EthernetAddress([0; 6]),
            target_protocol_addr: Ipv4Addr::new(100, 96, 0, 1),
        }
        .emit(&mut ArpPacket::new_unchecked(ethernet.payload_mut()));
        frame
    }
    fn tcp_reply(syn_ack: &[u8], control: TcpControl) -> Vec<u8> {
        let ethernet = EthernetFrame::new_checked(syn_ack).unwrap();
        let ip = Ipv4Packet::new_checked(ethernet.payload()).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let mut frame = vec![0; 54];
        let mut ethernet = EthernetFrame::new_unchecked(&mut frame);
        ethernet.set_dst_addr(EthernetAddress([2, 0, 0, 0, 0, 1]));
        ethernet.set_src_addr(EthernetAddress([2, 0, 0, 0, 0, 2]));
        ethernet.set_ethertype(EthernetProtocol::Ipv4);
        let mut ip = Ipv4Packet::new_unchecked(ethernet.payload_mut());
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len(40);
        ip.set_next_header(IpProtocol::Tcp);
        ip.set_src_addr(Ipv4Addr::new(100, 96, 0, 2));
        ip.set_dst_addr(Ipv4Addr::new(1, 1, 1, 1));
        let source = IpAddress::Ipv4(ip.src_addr());
        let destination = IpAddress::Ipv4(ip.dst_addr());
        TcpRepr {
            src_port: 40000,
            dst_port: 443,
            control,
            seq_number: TcpSeqNumber(2),
            ack_number: Some(tcp.seq_number() + tcp.segment_len()),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        }
        .emit(
            &mut TcpPacket::new_unchecked(ip.payload_mut()),
            &source,
            &destination,
            &ChecksumCapabilities::default(),
        );
        ip.fill_checksum();
        frame
    }
    fn ack(syn_ack: &[u8]) -> Vec<u8> {
        tcp_reply(syn_ack, TcpControl::None)
    }
    fn fin(syn_ack: &[u8]) -> Vec<u8> {
        tcp_reply(syn_ack, TcpControl::Fin)
    }
    fn dns_query() -> Vec<u8> {
        let payload = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let mut frame = vec![0; 14 + 20 + 8 + payload.len()];
        let mut ethernet = EthernetFrame::new_unchecked(&mut frame);
        ethernet.set_dst_addr(EthernetAddress([2, 0, 0, 0, 0, 1]));
        ethernet.set_src_addr(EthernetAddress([2, 0, 0, 0, 0, 2]));
        ethernet.set_ethertype(EthernetProtocol::Ipv4);
        let mut ip = Ipv4Packet::new_unchecked(ethernet.payload_mut());
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len((20 + 8 + payload.len()) as u16);
        ip.set_next_header(IpProtocol::Udp);
        ip.set_src_addr(Ipv4Addr::new(100, 96, 0, 2));
        ip.set_dst_addr(Ipv4Addr::new(1, 1, 1, 1));
        let source = IpAddress::Ipv4(ip.src_addr());
        let destination = IpAddress::Ipv4(ip.dst_addr());
        UdpRepr {
            src_port: 40000,
            dst_port: DNS_PORT,
        }
        .emit(
            &mut UdpPacket::new_unchecked(ip.payload_mut()),
            &source,
            &destination,
            payload.len(),
            |data| data.copy_from_slice(&payload),
            &ChecksumCapabilities::default(),
        );
        ip.fill_checksum();
        frame
    }
    fn syn6() -> Vec<u8> {
        let source = "fd53:4d00::2".parse::<Ipv6Addr>().unwrap();
        let destination = "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap();
        let mut frame = vec![0; 14 + 40 + 24];
        let mut ethernet = EthernetFrame::new_unchecked(&mut frame);
        ethernet.set_dst_addr(EthernetAddress([2, 0, 0, 0, 0, 1]));
        ethernet.set_src_addr(EthernetAddress([2, 0, 0, 0, 0, 2]));
        ethernet.set_ethertype(EthernetProtocol::Ipv6);
        let mut ip = Ipv6Packet::new_unchecked(ethernet.payload_mut());
        ip.set_version(6);
        ip.set_next_header(IpProtocol::Tcp);
        ip.set_hop_limit(64);
        ip.set_payload_len(24);
        ip.set_src_addr(source);
        ip.set_dst_addr(destination);
        TcpRepr {
            src_port: 40000,
            dst_port: 443,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(1),
            ack_number: None,
            window_len: 65535,
            window_scale: None,
            max_seg_size: Some(1460),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        }
        .emit(
            &mut TcpPacket::new_unchecked(ip.payload_mut()),
            &IpAddress::Ipv6(source),
            &IpAddress::Ipv6(destination),
            &ChecksumCapabilities::default(),
        );
        frame
    }
    fn udp6() -> Vec<u8> {
        let source = "fd53:4d00::2".parse::<Ipv6Addr>().unwrap();
        let destination = "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap();
        let payload = b"udp6";
        let mut frame = vec![0; 14 + 40 + 8 + payload.len()];
        let mut ethernet = EthernetFrame::new_unchecked(&mut frame);
        ethernet.set_dst_addr(EthernetAddress([2, 0, 0, 0, 0, 1]));
        ethernet.set_src_addr(EthernetAddress([2, 0, 0, 0, 0, 2]));
        ethernet.set_ethertype(EthernetProtocol::Ipv6);
        let mut ip = Ipv6Packet::new_unchecked(ethernet.payload_mut());
        ip.set_version(6);
        ip.set_next_header(IpProtocol::Udp);
        ip.set_hop_limit(64);
        ip.set_payload_len((8 + payload.len()) as u16);
        ip.set_src_addr(source);
        ip.set_dst_addr(destination);
        UdpRepr {
            src_port: 40000,
            dst_port: 9999,
        }
        .emit(
            &mut UdpPacket::new_unchecked(ip.payload_mut()),
            &IpAddress::Ipv6(source),
            &IpAddress::Ipv6(destination),
            payload.len(),
            |data| data.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
        frame
    }
    #[test]
    fn raw_syn_gets_a_syn_ack_after_host_flow_registration() {
        let mut gateway = gateway();
        gateway.pump(Some(arp_request())).unwrap();
        gateway.take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES);
        let frame = syn();
        assert_eq!(
            tcp_syn(&frame),
            Some(flow(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443))
        );
        gateway
            .add_connected_flow(tcp_syn(&frame).unwrap())
            .unwrap()
            .unwrap();
        gateway.pump(Some(frame)).unwrap();
        assert_eq!(
            gateway
                .sockets
                .get::<tcp::Socket>(gateway.flows[0].socket.unwrap())
                .state(),
            tcp::State::SynReceived
        );
        let reply = gateway
            .take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES)
            .into_iter()
            .find(|frame| {
                EthernetFrame::new_checked(frame)
                    .is_ok_and(|ethernet| ethernet.ethertype() == EthernetProtocol::Ipv4)
            })
            .expect("SYN-ACK");
        let ethernet = EthernetFrame::new_checked(&reply).unwrap();
        let ip = Ipv4Packet::new_checked(ethernet.payload()).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.syn() && tcp.ack());
        gateway.pump(Some(ack(&reply))).unwrap();
        gateway.take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES);
        assert_eq!(
            gateway.send_tcp(0, b"host reply").unwrap(),
            b"host reply".len()
        );
        let reply = gateway
            .take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES)
            .into_iter()
            .find(|frame| {
                EthernetFrame::new_checked(frame).is_ok_and(|ethernet| {
                    ethernet.ethertype() == EthernetProtocol::Ipv4
                        && Ipv4Packet::new_checked(ethernet.payload()).is_ok_and(|ip| {
                            TcpPacket::new_checked(ip.payload())
                                .is_ok_and(|tcp| tcp.payload() == b"host reply")
                        })
                })
            })
            .expect("host TCP payload");
        assert_eq!(
            TcpPacket::new_checked(
                Ipv4Packet::new_checked(EthernetFrame::new_checked(&reply).unwrap().payload())
                    .unwrap()
                    .payload()
            )
            .unwrap()
            .payload(),
            b"host reply"
        );
    }

    #[test]
    fn host_service_syn_uses_the_gateway_listener_and_loopback_connect_target() {
        let mut gateway = gateway();
        gateway
            .config
            .as_mut()
            .expect("configured gateway")
            .host_service_ports = vec![Some(5432)];
        gateway.pump(Some(arp_request())).unwrap();
        gateway.take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES);
        let destination = Ipv4Addr::new(100, 96, 0, 1);
        let frame = syn_to(destination, 5432);
        let flow = gateway
            .add_connected_flow(tcp_syn(&frame).unwrap())
            .expect("host service flow")
            .unwrap();
        assert_eq!(flow.destination, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(gateway.flows.len(), 1);
        gateway.pump(Some(frame)).unwrap();
        assert_eq!(
            gateway
                .sockets
                .get::<tcp::Socket>(gateway.flows[0].socket.unwrap())
                .state(),
            tcp::State::SynReceived
        );
    }

    #[test]
    fn dropped_syn_ack_retries_at_the_protocol_deadline() {
        let mut gateway = gateway();
        gateway.pump(Some(arp_request())).unwrap();
        gateway.take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES);
        gateway
            .add_connected_flow(tcp_syn(&syn()).unwrap())
            .unwrap()
            .unwrap();
        gateway.pump(Some(syn())).unwrap();
        gateway.take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES);
        let delay = gateway.protocol_delay().expect("TCP retry deadline");
        gateway.started = monotonic_now().wrapping_sub(delay.saturating_add(1));
        gateway.pump(None).unwrap();
        assert!(
            gateway
                .take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES)
                .into_iter()
                .any(
                    |frame| EthernetFrame::new_checked(&frame).is_ok_and(|ethernet| {
                        ethernet.ethertype() == EthernetProtocol::Ipv4
                            && Ipv4Packet::new_checked(ethernet.payload()).is_ok_and(|ip| {
                                TcpPacket::new_checked(ip.payload())
                                    .is_ok_and(|tcp| tcp.syn() && tcp.ack())
                            })
                    })
                )
        );
    }

    #[test]
    fn failed_pending_connections_send_a_reset_without_allocating_tcp_buffers() {
        for syn_frame in [syn(), syn6()] {
            let mut gateway = gateway();
            let guest = tcp_syn(&syn_frame).unwrap();
            let pending = gateway.add_flow(guest).unwrap().unwrap();
            let sockets = gateway.sockets.iter().count();
            gateway.reject_pending_flow(pending.generation.wrapping_add(1), pending.id, &syn_frame);
            assert_eq!(gateway.flows.len(), 1);
            gateway.reject_pending_flow(pending.generation, pending.id, &syn_frame);
            assert!(gateway.flows.is_empty());
            assert_eq!(gateway.sockets.iter().count(), sockets);
            let frames = gateway.take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES);
            let frame = frames.last().expect("TCP reset");
            let ethernet = EthernetFrame::new_checked(frame).unwrap();
            let (source, destination, payload) = match ethernet.ethertype() {
                EthernetProtocol::Ipv4 => {
                    let ip = Ipv4Packet::new_checked(ethernet.payload()).unwrap();
                    assert!(ip.verify_checksum());
                    (
                        IpAddress::Ipv4(ip.src_addr()),
                        IpAddress::Ipv4(ip.dst_addr()),
                        &ethernet.payload()[20..],
                    )
                }
                EthernetProtocol::Ipv6 => {
                    let ip = Ipv6Packet::new_checked(ethernet.payload()).unwrap();
                    (
                        IpAddress::Ipv6(ip.src_addr()),
                        IpAddress::Ipv6(ip.dst_addr()),
                        &ethernet.payload()[40..],
                    )
                }
                _ => panic!("expected TCP reset"),
            };
            let tcp = TcpPacket::new_checked(payload).unwrap();
            assert_eq!(IpAddr::from(source), guest.destination);
            assert_eq!(IpAddr::from(destination), guest.source);
            assert_eq!(tcp.src_port(), guest.destination_port);
            assert_eq!(tcp.dst_port(), guest.source_port);
            assert!(tcp.rst() && tcp.ack());
            assert_eq!(tcp.ack_number(), TcpSeqNumber(2));
            assert!(tcp.verify_checksum(&source, &destination));
        }
    }

    #[test]
    fn pending_connections_allocate_socket_buffers_only_after_connecting() {
        let mut gateway = gateway();
        let initial_sockets = gateway.sockets.iter().count();
        let guest = flow(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
        let pending = gateway.add_flow(guest).unwrap().unwrap();
        assert_eq!(gateway.sockets.iter().count(), initial_sockets);
        assert!(gateway.flows[0].socket.is_none());
        assert!(gateway.add_flow(guest).unwrap().is_none());
        gateway.finish_flow(pending.generation, pending.id);
        assert!(gateway.flows.is_empty());
        assert!(
            gateway
                .activate_flow(pending.generation, pending.id)
                .is_err()
        );
        let connected = gateway.add_flow(guest).unwrap().unwrap();
        gateway
            .activate_flow(connected.generation, connected.id)
            .unwrap();
        let socket = gateway
            .sockets
            .get::<tcp::Socket>(gateway.flows[0].socket.unwrap());
        assert_eq!(socket.recv_capacity(), TCP_BUFFER_BYTES);
        assert_eq!(socket.send_capacity(), TCP_BUFFER_BYTES);
        assert_eq!(gateway.sockets.iter().count(), initial_sockets + 1);
        gateway.pump(Some(syn())).unwrap();
        gateway
            .take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES)
            .pop()
            .expect("handshake reply");
    }

    #[test]
    fn configured_flow_capacity_releases_closed_flows() {
        for expected_capacity in [128_u16, 448] {
            let mut gateway = gateway();
            gateway.config.as_mut().unwrap().flow_capacity = usize::from(expected_capacity);
            let destination = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
            for port in 0..expected_capacity {
                gateway
                    .add_connected_flow(TcpFlow {
                        source_port: port,
                        ..flow(destination, 443)
                    })
                    .unwrap()
                    .unwrap();
            }
            assert!(matches!(
                gateway.add_connected_flow(flow(destination, 443)),
                Err(Error::Backpressure)
            ));
            assert_eq!(gateway.flows.len(), usize::from(expected_capacity));
            let closed = gateway.flows[0].id;
            gateway.finish_flow(GENERATION.load(Ordering::Acquire), closed);
            gateway.reap_finished_flows();
            gateway
                .add_connected_flow(flow(destination, 443))
                .expect("closed flow frees a slot")
                .unwrap();
        }
    }

    #[test]
    fn dns_and_socket_work_share_capacity_and_release_slots() {
        let mut gateway = gateway();
        gateway.config.as_mut().unwrap().flow_capacity = 2;
        let pending = gateway.add_flow(tcp_syn(&syn()).unwrap()).unwrap().unwrap();
        let (generation, id, _registration) = gateway.add_background().unwrap();
        assert!(!gateway.has_flow_capacity(1));
        assert!(matches!(gateway.add_background(), Err(Error::Backpressure)));
        assert!(matches!(
            gateway.add_flow(flow(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 443)),
            Err(Error::Backpressure)
        ));
        gateway.finish_background(generation.wrapping_add(1), id);
        assert!(!gateway.has_flow_capacity(1));
        gateway.finish_background(generation, id);
        assert!(gateway.has_flow_capacity(1));
        gateway.finish_flow(pending.generation, pending.id);
        assert!(gateway.has_flow_capacity(2));
    }

    #[test]
    fn published_flows_share_the_memory_budget_with_outbound_flows() {
        let mut gateway = gateway();
        gateway.config.as_mut().unwrap().flow_capacity = 2;
        let (outgoing, _) = channel(1);
        let (abort, _) = AbortHandle::new_pair();
        gateway.published_flows.push(PublishedFlow {
            id: 7,
            outgoing,
            abort,
        });
        assert!(!gateway.has_flow_capacity(1));
        assert!(!gateway.has_flow_capacity(2));
        let destination = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        assert!(matches!(
            gateway.add_connected_flow(flow(destination, 443)),
            Err(Error::Backpressure)
        ));
        gateway.finish_published_flow(GENERATION.load(Ordering::Acquire), 7);
        assert!(gateway.has_flow_capacity(2));
        gateway
            .add_connected_flow(flow(destination, 443))
            .unwrap()
            .unwrap();
        assert!(gateway.has_flow_capacity(1));
        assert!(!gateway.has_flow_capacity(2));
    }

    #[test]
    fn outbound_flow_has_a_timeout() {
        let mut gateway = gateway();
        gateway
            .add_connected_flow(flow(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443))
            .expect("flow starts")
            .unwrap();
        assert_eq!(
            gateway
                .sockets
                .get::<tcp::Socket>(gateway.flows[0].socket.unwrap())
                .timeout(),
            Some(smoltcp::time::Duration::from_secs(TCP_FLOW_TIMEOUT_SECS))
        );
    }

    #[test]
    fn retransmitted_syn_reuses_its_flow() {
        let mut gateway = gateway();
        let flow = tcp_syn(&syn()).unwrap();
        assert!(gateway.add_connected_flow(flow).unwrap().is_some());
        assert!(gateway.add_connected_flow(flow).unwrap().is_none());
        assert_eq!(gateway.flows.len(), 1);
    }

    #[test]
    fn closed_flow_reaps_pending_guest_data_without_a_host_task_exit() {
        let mut gateway = gateway();
        let _host_flow = gateway
            .add_connected_flow(tcp_syn(&syn()).unwrap())
            .unwrap()
            .unwrap();
        let socket = gateway.flows[0].socket.unwrap();
        gateway.flows[0].pending_guest_data = Some(vec![1]);
        gateway.flows[0].outgoing.try_send(vec![2]).unwrap();
        gateway.sockets.get_mut::<tcp::Socket>(socket).abort();
        gateway.reap_finished_flows();
        assert!(gateway.flows.is_empty());
    }

    #[test]
    fn invalid_transport_checksums_do_not_start_flows() {
        let mut tcp = syn();
        tcp[14 + 20 + 4] ^= 1;
        assert_eq!(tcp_syn(&tcp), None);

        let mut udp = udp6();
        *udp.last_mut().unwrap() ^= 1;
        assert!(udp_request(&udp).is_none());

        let mut udp = udp6();
        let mut ethernet = EthernetFrame::new_unchecked(&mut udp);
        let mut ip = Ipv6Packet::new_unchecked(ethernet.payload_mut());
        UdpPacket::new_unchecked(ip.payload_mut()).set_checksum(0);
        assert!(udp_request(&udp).is_none());
    }

    #[test]
    fn host_eof_preserves_unacknowledged_response_bytes() {
        let mut gateway = gateway();
        gateway.pump(Some(arp_request())).unwrap();
        gateway.take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES);
        let flow = gateway
            .add_connected_flow(tcp_syn(&syn()).unwrap())
            .unwrap()
            .unwrap();
        gateway.pump(Some(syn())).unwrap();
        let syn_ack = gateway
            .take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES)
            .pop()
            .unwrap();
        gateway.pump(Some(ack(&syn_ack))).unwrap();
        assert_eq!(gateway.send_tcp(flow.id, b"response").unwrap(), 8);
        gateway.close_host_input(GENERATION.load(Ordering::Acquire), flow.id);
        gateway.reap_finished_flows();
        assert_eq!(gateway.flows.len(), 1);
        let socket = gateway
            .sockets
            .get::<tcp::Socket>(gateway.flows[0].socket.unwrap());
        assert_eq!(socket.state(), tcp::State::FinWait1);
        assert_eq!(socket.send_queue(), 8);
    }

    #[test]
    fn small_tcp_buffers_resume_after_acknowledgement() {
        let mut gateway = gateway();
        gateway.pump(Some(arp_request())).unwrap();
        gateway.take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES);
        let flow = gateway
            .add_connected_flow(tcp_syn(&syn()).unwrap())
            .unwrap()
            .unwrap();
        gateway.pump(Some(syn())).unwrap();
        let syn_ack = gateway
            .take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES)
            .pop()
            .unwrap();
        gateway.pump(Some(ack(&syn_ack))).unwrap();
        let payload = vec![42; TCP_BUFFER_BYTES * 4];
        let mut sent = 0;
        let mut received = Vec::new();
        for iteration in 0..64 {
            sent += gateway.send_tcp(flow.id, &payload[sent..]).unwrap();
            if iteration == 0 {
                assert_eq!(gateway.send_tcp(flow.id, &[1]).unwrap(), 0);
            }
            let frames = gateway.take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES);
            for frame in frames {
                let ethernet = EthernetFrame::new_checked(&frame).unwrap();
                let ip = Ipv4Packet::new_checked(ethernet.payload()).unwrap();
                let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
                received.extend_from_slice(tcp.payload());
                gateway.pump(Some(ack(&frame))).unwrap();
            }
        }
        assert_eq!(received.len(), payload.len());
        assert_eq!(received, payload);
    }

    #[test]
    fn guest_fin_closes_the_host_input_stream() {
        for host_closes_first in [false, true] {
            let mut gateway = gateway();
            gateway.pump(Some(arp_request())).expect("guest ARP");
            gateway.take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES);
            let mut flow = gateway
                .add_connected_flow(tcp_syn(&syn()).unwrap())
                .expect("flow starts")
                .unwrap();
            gateway.pump(Some(syn())).expect("guest SYN");
            let syn_ack = gateway
                .take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES)
                .pop()
                .expect("SYN-ACK");
            gateway.pump(Some(ack(&syn_ack))).expect("guest ACK");
            if host_closes_first {
                gateway.close_host_input(GENERATION.load(Ordering::Acquire), flow.id);
            }
            gateway.pump(Some(fin(&syn_ack))).expect("guest FIN");
            gateway.guest_data();
            assert_eq!(flow.outgoing.next().now_or_never(), Some(None));
        }
    }

    #[test]
    fn published_accept_emits_a_guest_syn() {
        let mut gateway = gateway();
        gateway.pump(Some(arp_request())).expect("guest ARP");
        gateway.take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES);
        let config = gateway.config.clone().expect("configured gateway");
        assert!(
            gateway
                .published
                .accept(
                    7,
                    Ipv4Addr::new(100, 96, 0, 2),
                    8080,
                    config.ip,
                    gateway.interface.as_mut().expect("interface"),
                    &mut gateway.sockets,
                )
                .is_ok()
        );
        gateway.pump(None).expect("published SYN");
        let frame = gateway
            .take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES)
            .into_iter()
            .find(|frame| {
                EthernetFrame::new_checked(frame).is_ok_and(|ethernet| {
                    Ipv4Packet::new_checked(ethernet.payload()).is_ok_and(|ip| {
                        TcpPacket::new_checked(ip.payload()).is_ok_and(|tcp| {
                            ip.dst_addr() == Ipv4Addr::new(100, 96, 0, 2)
                                && tcp.dst_port() == 8080
                                && tcp.syn()
                        })
                    })
                })
            })
            .expect("published SYN frame");
        assert_eq!(
            Ipv4Packet::new_checked(EthernetFrame::new_checked(&frame).unwrap().payload())
                .unwrap()
                .src_addr(),
            Ipv4Addr::new(100, 96, 0, 1)
        );
    }
    #[test]
    fn raw_udp_dns_reaches_the_gateway_socket() {
        let mut gateway = gateway();
        gateway.pump(Some(arp_request())).unwrap();
        gateway.take_frames(MAX_QUEUED_FRAMES, MAX_FRAME_BYTES);
        gateway.pump(Some(dns_query())).unwrap();
        assert_eq!(gateway.dns_queries().len(), 1);
    }
    #[test]
    fn raw_udp_packet_builds_a_guest_reply() {
        let mut frame = dns_query();
        let mut ethernet = EthernetFrame::new_unchecked(&mut frame);
        let mut ip = Ipv4Packet::new_unchecked(ethernet.payload_mut());
        let source = IpAddress::Ipv4(ip.src_addr());
        let destination = IpAddress::Ipv4(ip.dst_addr());
        UdpPacket::new_unchecked(ip.payload_mut()).set_dst_port(9999);
        UdpPacket::new_unchecked(ip.payload_mut()).fill_checksum(&source, &destination);
        ip.fill_checksum();
        UdpPacket::new_unchecked(ip.payload_mut()).set_checksum(0);
        let request = udp_request(&frame).expect("guest UDP request");
        assert_eq!(request.destination, Ipv4Addr::new(1, 1, 1, 1));
        let reply = request.reply(b"reply").expect("bounded reply");
        let ethernet = EthernetFrame::new_checked(&reply).unwrap();
        let ip = Ipv4Packet::new_checked(ethernet.payload()).unwrap();
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!(ip.version(), 4);
        assert_eq!(ip.hop_limit(), 64);
        assert_eq!(ip.src_addr(), Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(ip.dst_addr(), Ipv4Addr::new(100, 96, 0, 2));
        assert_eq!(udp.src_port(), 9999);
        assert_eq!(udp.dst_port(), 40000);
        assert_eq!(udp.payload(), b"reply");
    }
    #[test]
    fn raw_ipv6_syn_gets_a_syn_ack() {
        let mut gateway = gateway();
        let frame = syn6();
        let destination = "2606:4700:4700::1111".parse().unwrap();
        assert_eq!(
            tcp_syn(&frame),
            Some(TcpFlow {
                source: IpAddr::V6("fd53:4d00::2".parse().unwrap()),
                source_port: 40000,
                destination: IpAddr::V6(destination),
                destination_port: 443,
            })
        );
        gateway
            .add_connected_flow(tcp_syn(&frame).unwrap())
            .unwrap()
            .unwrap();
        gateway.pump(Some(frame)).unwrap();
        assert_eq!(
            gateway
                .sockets
                .get::<tcp::Socket>(gateway.flows[0].socket.unwrap())
                .state(),
            tcp::State::SynReceived
        );
    }
    #[test]
    fn raw_ipv6_udp_packet_builds_a_guest_reply() {
        let request = udp_request(&udp6()).expect("guest IPv6 UDP request");
        let reply = request.reply(b"reply").expect("bounded reply");
        let ethernet = EthernetFrame::new_checked(&reply).unwrap();
        assert_eq!(ethernet.ethertype(), EthernetProtocol::Ipv6);
        let ip = Ipv6Packet::new_checked(ethernet.payload()).unwrap();
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!(ip.version(), 6);
        assert_eq!(ip.hop_limit(), 64);
        assert_eq!(
            ip.src_addr(),
            "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(ip.dst_addr(), "fd53:4d00::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            (udp.src_port(), udp.dst_port(), udp.payload()),
            (9999, 40000, b"reply".as_slice())
        );
    }

    #[test]
    fn host_service_redirect_needs_the_matching_grant() {
        let mut gateway = gateway();
        gateway
            .config
            .as_mut()
            .expect("configured gateway")
            .host_service_ports = vec![Some(5432)];

        assert_eq!(
            gateway.socket_destination(IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1)), 5432),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            gateway.socket_destination(IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1)), 22),
            None
        );
        assert_eq!(
            gateway.socket_destination(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
    }

    #[test]
    fn ungranted_gateway_requests_do_not_reserve_flow_slots() {
        let mut gateway = gateway();
        let request = UdpRequest {
            source_mac: EthernetAddress([2, 0, 0, 0, 0, 2]),
            destination_mac: EthernetAddress([2, 0, 0, 0, 0, 1]),
            source: IpAddr::V4(Ipv4Addr::new(100, 96, 0, 2)),
            source_port: 40000,
            destination: IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1)),
            destination_port: 22,
            data: Vec::new(),
        };
        for _ in 0..gateway.flow_capacity() {
            assert!(matches!(
                gateway.add_connected_flow(flow(request.destination, request.destination_port)),
                Err(Error::NotReady)
            ));
            assert!(matches!(
                gateway.add_udp_flow(request.clone()),
                Err(Error::NotReady)
            ));
        }
        assert!(gateway.flows.is_empty());
        assert!(gateway.udp_flows.is_empty());
    }

    #[test]
    fn finished_udp_flows_free_slots() {
        let mut gateway = gateway();
        let request = UdpRequest {
            source_mac: EthernetAddress([2, 0, 0, 0, 0, 2]),
            destination_mac: EthernetAddress([2, 0, 0, 0, 0, 1]),
            source: IpAddr::V4(Ipv4Addr::new(100, 96, 0, 2)),
            source_port: 40000,
            destination: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            destination_port: 443,
            data: Vec::new(),
        };
        let generation = GENERATION.load(Ordering::Acquire);
        let first = gateway.add_udp_flow(request.clone()).unwrap().id;
        for _ in 1..gateway.flow_capacity() {
            gateway.add_udp_flow(request.clone()).unwrap();
        }
        assert!(matches!(
            gateway.add_udp_flow(request.clone()),
            Err(Error::Backpressure)
        ));

        gateway.finish_udp_flow(generation, first);

        gateway
            .add_udp_flow(request)
            .expect("finished UDP flow frees a slot");
    }
}
