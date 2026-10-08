use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use super::network_stream::GuestStream;
use super::network_stream::Stream;
use super::vsock::{GuestVsock, create_interrupt, read_stream, wait_connected};
use crate::TrustedArtifacts;
use crate::box_runtime::{BoxHost, BoxRuntime};
use crate::component::network::{NetworkBackend, PortMapping};
use crate::component::vsock::streams::{FrontendStreams, StreamEndpoint};
use crate::memory::GuestRam;
use terra_protocol::application::{Message, TcpTarget};
use terra_protocol::socket::{self, Error};
use terra_protocol::vsock::{
    AGENT_PORT, CONTROL_PORT, FLOW_REPLY_BYTES, PUBLICATION_PORT, TCP_PORT, UDP_PORT,
};

const WAIT: Duration = Duration::from_secs(5);
const STALLED_TCP_COUNT: usize = 8;
const UDP_BURST_DATAGRAMS: usize = terra_protocol::network::MAX_NETWORK_DATAGRAMS + 1;

pub(super) async fn run(
    artifacts: &TrustedArtifacts,
    engine: &wasmtime::Engine,
) -> wasmtime::Result<()> {
    let servers = TestServers::start()?;
    let (backend, broker) = create_backend(servers.endpoints)?;
    let client = backend.client.clone();
    let result = run_with_backend(artifacts, engine, backend, servers.endpoints).await;
    let served = servers.finish();
    client.disconnect();
    let stopped = tokio::time::timeout(WAIT, broker).await;
    result?;
    served?;
    require_broker_peer_shutdown(stopped??)?;
    Ok(())
}

pub fn create_backend(
    endpoints: Endpoints,
) -> wasmtime::Result<(NetworkBackend, tokio::task::JoinHandle<std::io::Result<()>>)> {
    use terra_network::config::{Config, Limits, Network, PublishedListener, StaticDnsRecord};
    use terra_platform::io::local::{AsyncLocalStream, create_local_pair};
    let listeners = vec![
        PublishedListener {
            grant: 1,
            address: (Ipv4Addr::LOCALHOST, endpoints.published).into(),
            transport: terra_network::ResourceKind::Tcp,
        },
        PublishedListener {
            grant: 2,
            address: (std::net::Ipv6Addr::LOCALHOST, endpoints.published).into(),
            transport: terra_network::ResourceKind::Tcp,
        },
        PublishedListener {
            grant: 3,
            address: (Ipv4Addr::LOCALHOST, endpoints.published).into(),
            transport: terra_network::ResourceKind::Udp,
        },
        PublishedListener {
            grant: 4,
            address: (std::net::Ipv6Addr::LOCALHOST, endpoints.published).into(),
            transport: terra_network::ResourceKind::Udp,
        },
    ];
    let broker = terra_network::Broker::bind(Config {
        policy: Network {
            allow: vec![
                format!("HOST_LOOPBACK:{}", endpoints.tcp),
                format!("HOST_LOOPBACK:{}", endpoints.udp),
                "localhost".into(),
            ],
            hosts: vec![StaticDnsRecord {
                name: "loopback.test".into(),
                addr: "127.0.0.1".into(),
            }],
            ..Network::default()
        },
        gateways: [
            crate::component::network::HostServiceAddresses::default()
                .gateway_ip
                .into(),
            crate::component::network::HostServiceAddresses::default()
                .gateway_ip6
                .into(),
        ],
        listeners: listeners.clone(),
        limits: Limits::default(),
    })?;
    let ready = broker.ready();
    let (worker, endpoint) = create_local_pair()?;
    worker.set_nonblocking(true)?;
    endpoint.set_nonblocking(true)?;
    let client = terra_network::Client::new(AsyncLocalStream::from_std(worker)?);
    let broker = tokio::spawn(broker.serve(AsyncLocalStream::from_std(endpoint)?));
    Ok((
        NetworkBackend {
            client,
            ready,
            listeners,
        },
        broker,
    ))
}

#[derive(Clone, Copy)]
pub struct Endpoints {
    pub tcp: u16,
    pub udp: u16,
    pub published: u16,
}

pub struct TestServers {
    pub endpoints: Endpoints,
    tcp: std::thread::JoinHandle<wasmtime::Result<()>>,
    udp: std::thread::JoinHandle<wasmtime::Result<()>>,
    tcp_ipv6: std::thread::JoinHandle<wasmtime::Result<()>>,
    udp_ipv6: std::thread::JoinHandle<wasmtime::Result<()>>,
}

/// Server sockets bound before any server thread starts, so a port collision can retry cleanly.
struct BoundServers {
    tcp: TcpListener,
    udp: UdpSocket,
    tcp6: TcpListener,
    udp6: UdpSocket,
    published: u16,
}

const PORT_ATTEMPTS: usize = 16;

/// Each IPv6 server reuses its IPv4 port number, and the broker later binds the published port on
/// both families and protocols, but the kernel picked each number for one socket only.
fn bind_servers() -> std::io::Result<BoundServers> {
    use std::net::Ipv6Addr;
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let tcp6 = TcpListener::bind((Ipv6Addr::LOCALHOST, tcp.local_addr()?.port()))?;
    let udp6 = UdpSocket::bind((Ipv6Addr::LOCALHOST, udp.local_addr()?.port()))?;
    let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let published = reserved.local_addr()?.port();
    // ponytail: the broker binds `published` in another process after these drop; the window is
    // narrow, so a collision there still fails the self-test.
    let _free_on_every_family = (
        TcpListener::bind((Ipv6Addr::LOCALHOST, published))?,
        UdpSocket::bind((Ipv4Addr::LOCALHOST, published))?,
        UdpSocket::bind((Ipv6Addr::LOCALHOST, published))?,
    );
    Ok(BoundServers {
        tcp,
        udp,
        tcp6,
        udp6,
        published,
    })
}

impl TestServers {
    pub fn start() -> wasmtime::Result<Self> {
        let mut attempts = 1;
        let BoundServers {
            tcp,
            udp,
            tcp6,
            udp6,
            published,
        } = loop {
            match bind_servers() {
                Err(error)
                    if error.kind() == std::io::ErrorKind::AddrInUse
                        && attempts < PORT_ATTEMPTS =>
                {
                    attempts += 1;
                }
                result => break result?,
            }
        };
        tcp.set_nonblocking(true)?;
        udp.set_read_timeout(Some(super::FIXTURE_STARTUP_WAIT))?;
        udp.set_write_timeout(Some(WAIT))?;
        let endpoints = Endpoints {
            tcp: tcp.local_addr()?.port(),
            udp: udp.local_addr()?.port(),
            published,
        };
        tcp6.set_nonblocking(true)?;
        udp6.set_read_timeout(Some(super::FIXTURE_STARTUP_WAIT))?;
        udp6.set_write_timeout(Some(WAIT))?;
        let tcp_ipv6 = std::thread::spawn(move || {
            let mut stream = accept_stream(&tcp6, super::FIXTURE_STARTUP_WAIT)?;
            wasmtime::ensure!(
                stream.peer_addr()?.ip() == std::net::Ipv6Addr::LOCALHOST,
                "network self-test IPv6 TCP source"
            );
            let mut bytes = [0; 10];
            stream.read_exact(&mut bytes)?;
            wasmtime::ensure!(
                &bytes == b"terra-ipv6",
                "network self-test IPv6 TCP request"
            );
            let mut extra = [0];
            wasmtime::ensure!(
                stream.read(&mut extra)? == 0,
                "network self-test IPv6 TCP FIN"
            );
            stream.write_all(&bytes)?;
            stream.shutdown(Shutdown::Write)?;
            Ok(())
        });
        let udp_ipv6 = std::thread::spawn(move || {
            let mut bytes = [0; 32];
            let (length, peer) = udp6.recv_from(&mut bytes)?;
            wasmtime::ensure!(
                &bytes[..length] == b"terra-ipv6" && peer.ip() == std::net::Ipv6Addr::LOCALHOST,
                "network self-test IPv6 UDP request"
            );
            udp6.send_to(&bytes[..length], peer)?;
            Ok(())
        });
        let tcp = std::thread::spawn(move || serve_tcp(&tcp, published));
        let udp = std::thread::spawn(move || serve_udp(&udp));
        Ok(Self {
            endpoints,
            tcp,
            udp,
            tcp_ipv6,
            udp_ipv6,
        })
    }

    pub fn finish(self) -> wasmtime::Result<()> {
        let results = [self.tcp, self.udp, self.tcp_ipv6, self.udp_ipv6].map(|server| {
            server
                .join()
                .map_err(|_| wasmtime::Error::msg("network self-test server failed"))
        });
        for result in results {
            result??;
        }
        Ok(())
    }
}

#[must_use]
pub(crate) fn create_dns_fallback_backend() -> (
    NetworkBackend,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<wasmtime::Result<()>>,
) {
    use terra_protocol::network::{MAX_NETWORK_FRAME_BYTES, Request, Response};
    use tokio::io::AsyncWriteExt;

    let (worker, mut endpoint) = tokio::io::duplex(MAX_NETWORK_FRAME_BYTES);
    let client = terra_network::Client::new(worker);
    let backend = NetworkBackend {
        client,
        ready: terra_network::config::Ready {
            version: terra_network::config::PROTOCOL_VERSION,
            host_service_ports: Vec::new(),
            blocks_direct_dns: true,
        },
        listeners: Vec::new(),
    };
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let broker_task = tokio::spawn(async move {
        for _ in 0..2 {
            let request = terra_protocol::read_frame_async_with_limit::<Request>(
                &mut endpoint,
                MAX_NETWORK_FRAME_BYTES,
            )
            .await?
            .ok_or_else(|| wasmtime::Error::msg("DNS fallback broker request EOF"))?;
            wasmtime::ensure!(
                request.operation == terra_network::Operation::Resolve("many.test".into()),
                "DNS fallback broker resolves only the configured fixture"
            );
            let response = Response {
                id: request.id,
                result: Ok(terra_network::Reply::Resolved(
                    (1..=32)
                        .map(|last| Ipv4Addr::new(192, 0, 2, last).into())
                        .collect(),
                )),
            };
            endpoint
                .write_all(&terra_protocol::encode_frame_with_limit(
                    &response,
                    MAX_NETWORK_FRAME_BYTES,
                )?)
                .await?;
        }
        let _ = stopped.await;
        wasmtime::Result::Ok(())
    });
    (backend, stop, broker_task)
}

fn require_broker_peer_shutdown(result: std::io::Result<()>) -> wasmtime::Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn dns_query(name: &str) -> wasmtime::Result<Vec<u8>> {
    let mut query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00".to_vec();
    for label in name.split('.') {
        query.push(u8::try_from(label.len())?);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(b"\x00\x00\x01\x00\x01");
    Ok(query)
}

fn build_tcp_payload() -> Vec<u8> {
    (0..251)
        .cycle()
        .take(2 * terra_protocol::network::MAX_NETWORK_READ_BYTES + 1)
        .collect()
}

fn serve_udp(udp: &UdpSocket) -> wasmtime::Result<()> {
    let mut bytes = [0; 4096];
    let mut socket_peer = None;
    for payload in [b"terra-udp".as_slice(), &[37; 3072], &[]] {
        let (length, peer) = udp.recv_from(&mut bytes)?;
        wasmtime::ensure!(
            &bytes[..length] == payload && peer.ip().is_loopback(),
            "network self-test UDP request"
        );
        wasmtime::ensure!(
            socket_peer.is_none_or(|previous| previous == peer),
            "one UDP stream keeps the same native socket across datagrams"
        );
        if socket_peer.is_none() {
            let unsolicited_sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
            unsolicited_sender.set_write_timeout(Some(WAIT))?;
            for _ in 0..UDP_BURST_DATAGRAMS {
                unsolicited_sender.send_to(b"unsolicited", peer)?;
            }
        }
        socket_peer = Some(peer);
        udp.set_read_timeout(Some(WAIT))?;
        udp.send_to(payload, peer)?;
    }
    let mut burst = Vec::new();
    for index in 0..u8::try_from(UDP_BURST_DATAGRAMS)? {
        let (length, peer) = udp.recv_from(&mut bytes)?;
        wasmtime::ensure!(
            bytes[..length] == vec![index; usize::from(index) + 1] && Some(peer) == socket_peer,
            "UDP burst retains datagram boundaries and its native socket"
        );
        burst.push((bytes[..length].to_vec(), peer));
    }
    for (payload, peer) in burst {
        udp.send_to(&payload, peer)?;
    }
    Ok(())
}

fn serve_tcp(listener: &TcpListener, published: u16) -> wasmtime::Result<()> {
    let mut stalled = accept_stream(listener, super::FIXTURE_STARTUP_WAIT)?;
    stalled.write_all(&vec![37; 24 * 1024])?;
    let mut stream = accept_stream(listener, WAIT)?;
    let expected = build_tcp_payload();
    let mut request = vec![0; expected.len()];
    stream.read_exact(&mut request)?;
    wasmtime::ensure!(request == expected, "network self-test TCP request");
    let mut eof = [0];
    wasmtime::ensure!(stream.read(&mut eof)? == 0, "network self-test TCP EOF");
    stream.write_all(&expected)?;
    stream.shutdown(Shutdown::Write)?;
    for _ in 0..2 {
        let mut stream =
            TcpStream::connect_timeout(&(Ipv4Addr::LOCALHOST, published).into(), WAIT)?;
        configure_stream(&stream)?;
        stream.write_all(&expected)?;
        stream.shutdown(Shutdown::Write)?;
        let mut reply = [0; 15];
        stream.read_exact(&mut reply)?;
        wasmtime::ensure!(
            &reply == b"published-reply",
            "network self-test published response"
        );
        wasmtime::ensure!(
            stream.read(&mut eof)? == 0,
            "network self-test published EOF"
        );
    }
    let retired_udp_peer = serve_published_udp(published)?;
    let reset = stalled.read(&mut eof);
    wasmtime::ensure!(
        matches!(reset, Ok(0))
            || reset.is_err_and(|error| { error.kind() == std::io::ErrorKind::ConnectionReset }),
        "network self-test reset left a stalled TCP resource open"
    );
    serve_reopened_published_udp(published)?;
    drop(retired_udp_peer);
    let mut stream = accept_stream(listener, WAIT)?;
    stream.write_all(b"reset-reply")?;
    wasmtime::ensure!(
        stream.read(&mut eof)? == 0,
        "network self-test connection after reset EOF"
    );
    stream.shutdown(Shutdown::Write)?;
    serve_tcp_half_closes(listener)?;
    serve_stalled_streams(listener)
}

fn serve_tcp_half_closes(listener: &TcpListener) -> wasmtime::Result<()> {
    let mut stream = accept_stream(listener, WAIT)?;
    stream.shutdown(Shutdown::Write)?;
    let mut observed_fin = [0];
    stream.read_exact(&mut observed_fin)?;
    wasmtime::ensure!(
        &observed_fin == b"R",
        "guest reports remote FIN before native reset"
    );
    let stream = tokio::net::TcpSocket::from_std_stream(stream);
    stream.set_zero_linger()?;
    drop(stream);
    let mut stream = accept_stream(listener, WAIT)?;
    stream.write_all(&vec![
        83;
        2 * terra_protocol::network::MAX_NETWORK_READ_BYTES + 1
    ])?;
    stream.read_exact(&mut observed_fin)?;
    wasmtime::ensure!(
        &observed_fin == b"R",
        "guest writes after closing its receive half"
    );
    wasmtime::ensure!(
        stream.read(&mut observed_fin)? == 0,
        "guest receive close preserves native write FIN"
    );
    Ok(())
}

fn serve_published_udp(port: u16) -> wasmtime::Result<UdpSocket> {
    let clients = [
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?,
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?,
        UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0))?,
    ];
    let payloads = [
        b"published-one".to_vec(),
        vec![61; 4096],
        b"published-ipv6".to_vec(),
    ];
    for (client, payload) in clients.iter().zip(&payloads) {
        client.set_read_timeout(Some(WAIT))?;
        client.set_write_timeout(Some(WAIT))?;
        client.send_to(
            payload,
            std::net::SocketAddr::new(client.local_addr()?.ip(), port),
        )?;
    }
    let mut bytes = [0; 4097];
    for (client, payload) in clients.iter().zip(&payloads) {
        let (length, sender) = client.recv_from(&mut bytes)?;
        wasmtime::ensure!(
            &bytes[..length] == payload && sender.port() == port,
            "published UDP retains payloads and the public sender port"
        );
    }
    let client = &clients[0];
    let destination = (Ipv4Addr::LOCALHOST, port);
    for payload in [b"".as_slice(), b"after-oversize"] {
        if !payload.is_empty() {
            client.send_to(&[71; 4097], destination)?;
        }
        client.send_to(payload, destination)?;
        let (length, _) = client.recv_from(&mut bytes)?;
        wasmtime::ensure!(
            &bytes[..length] == payload,
            "published UDP empty and bounded datagrams"
        );
    }
    let [first_peer, _, _] = clients;
    Ok(first_peer)
}

fn serve_reopened_published_udp(port: u16) -> wasmtime::Result<()> {
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    client.set_read_timeout(Some(WAIT))?;
    client.send_to(b"publication-reopened", (Ipv4Addr::LOCALHOST, port))?;
    let mut bytes = [0; 32];
    let (length, sender) = client.recv_from(&mut bytes)?;
    wasmtime::ensure!(
        &bytes[..length] == b"publication-reopened" && sender.port() == port,
        "a publication stream reset permits a fresh host datagram"
    );
    Ok(())
}

fn serve_stalled_streams(listener: &TcpListener) -> wasmtime::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener.try_clone()?)?;
            let payload = vec![
                47;
                terra_protocol::vsock::FLOW_REPLY_BYTES
                    + terra_protocol::vsock::FLOW_UPSTREAM_BYTES
            ];
            let mut streams = Vec::with_capacity(STALLED_TCP_COUNT);
            for _ in 0..STALLED_TCP_COUNT {
                let admission_wait = if streams.is_empty() {
                    super::FIXTURE_STARTUP_WAIT
                } else {
                    WAIT
                };
                let (mut stream, _) =
                    tokio::time::timeout(admission_wait, listener.accept()).await??;
                tokio::time::timeout(WAIT, stream.write_all(&payload)).await??;
                streams.push(stream);
            }
            for mut stream in streams {
                let mut byte = [0];
                let closed = tokio::time::timeout(WAIT, stream.read(&mut byte)).await?;
                wasmtime::ensure!(
                    matches!(closed, Ok(0))
                        || closed.is_err_and(|error| {
                            error.kind() == std::io::ErrorKind::ConnectionReset
                        }),
                    "broker loss retires every stalled native TCP socket"
                );
            }
            wasmtime::Result::Ok(())
        })
}

/// `wait` is `FIXTURE_STARTUP_WAIT` for a server's first client: servers start before the
/// guest, whose earlier self-test stages can take longer than `WAIT` under tracing or load.
fn accept_stream(listener: &TcpListener, wait: Duration) -> wasmtime::Result<TcpStream> {
    let deadline = Instant::now() + wait;
    let stream = loop {
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
    Ok(stream)
}

fn configure_stream(stream: &TcpStream) -> wasmtime::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(WAIT))?;
    stream.set_write_timeout(Some(WAIT))?;
    stream.set_nodelay(true)?;
    Ok(())
}

pub async fn run_with_backend(
    artifacts: &TrustedArtifacts,
    engine: &wasmtime::Engine,
    backend: NetworkBackend,
    endpoints: Endpoints,
) -> wasmtime::Result<()> {
    let (mut guest, mut agent, running) =
        start_guest(artifacts, engine, backend.clone(), Vec::new()).await?;
    let result = async {
        exercise_control_failure(&mut guest, &mut agent).await?;
        run_socket_streams(artifacts, engine, backend, endpoints).await
    }
    .await;
    let closed = guest.stream.guest.device.close_async().await;
    let stopped = running.join().await;
    result?;
    closed?;
    stopped?;
    run_dns_fallback(artifacts, engine).await
}

async fn run_socket_streams(
    artifacts: &TrustedArtifacts,
    engine: &wasmtime::Engine,
    backend: NetworkBackend,
    endpoints: Endpoints,
) -> wasmtime::Result<()> {
    let requests = (0..8).map(|_| {
        backend
            .client
            .request(terra_network::Operation::Resolve("loopback.test".into()))
    });
    for reply in futures_util::future::join_all(requests).await {
        wasmtime::ensure!(
            reply
                == Ok(terra_network::Reply::Resolved(vec![
                    Ipv4Addr::LOCALHOST.into()
                ])),
            "network self-test concurrent broker replies"
        );
    }
    let broker_client = backend.client.clone();
    let (mut guest, mut agent, running) = start_guest(
        artifacts,
        engine,
        backend,
        vec![
            PortMapping::new(endpoints.published, 8080),
            PortMapping {
                host: endpoints.published,
                guest: 8081,
                transport: terra_network::ResourceKind::Udp,
            },
        ],
    )
    .await?;
    let result = async {
        exercise_socket_stream(&mut guest, &mut agent, endpoints).await?;
        let generation = agent
            .current()
            .ok_or_else(|| wasmtime::Error::msg("agent lost before broker failure"))?;
        let (stalled, udp) = exercise_admission_pressure(&mut guest, &mut agent, endpoints.tcp)
            .await
            .map_err(|error| error.context("full flow capacity and eight stalled TCP windows"))?;
        broker_client.disconnect();
        guest.stream.require_reset(CONTROL).await?;
        for stream in stalled
            .into_iter()
            .chain(udp)
            .chain(guest.udp_publications.clone())
        {
            guest.stream.require_reset(stream).await?;
        }
        guest
            .stream
            .guest
            .send(19001, TCP_PORT, 1, 65536, &[])
            .await?;
        guest.stream.require_reset((19001, TCP_PORT)).await?;
        guest
            .stream
            .guest
            .send(AGENT_PORT, AGENT_PORT, 5, 65536, b"stop")
            .await?;
        wasmtime::ensure!(
            read_stream(&mut agent, generation, 4).await? == b"stop",
            "broker loss preserves agent stop progress"
        );
        Ok(())
    }
    .await;
    let closed = guest.stream.guest.device.close_async().await;
    let stopped = running.join().await;
    result?;
    closed?;
    stopped
}

const CONTROL: Stream = (CONTROL_PORT, CONTROL_PORT);
/// Fills every flow slot left after the stalled TCP flows and both UDP publication families.
#[allow(clippy::cast_possible_truncation)]
const STALLED_UDP_COUNT: u32 =
    (terra_protocol::vsock::MAX_NETWORK_SOCKETS - STALLED_TCP_COUNT - 2) as u32;

async fn exercise_admission_pressure(
    guest: &mut GuestNetwork,
    agent: &mut StreamEndpoint,
    tcp_port: u16,
) -> wasmtime::Result<(Vec<Stream>, Vec<Stream>)> {
    let mut udp = Vec::new();
    for offset in 0..STALLED_UDP_COUNT {
        udp.push(guest.open_udp(20000 + offset).await?);
    }
    let mut stalled = Vec::with_capacity(STALLED_TCP_COUNT);
    for _ in 0..STALLED_TCP_COUNT {
        stalled.push(guest.open_tcp(TcpTarget::HostService(tcp_port)).await?);
    }
    for &stream in &stalled {
        guest.stream.wait_buffered(stream, FLOW_REPLY_BYTES).await?;
    }
    for refused in [(19000, TCP_PORT), (19000, UDP_PORT)] {
        guest
            .stream
            .guest
            .send(refused.0, refused.1, 1, 24576, &[])
            .await?;
        guest.stream.require_reset(refused).await?;
    }
    let generation = agent
        .current()
        .ok_or_else(|| wasmtime::Error::msg("agent under pressure"))?;
    guest
        .stream
        .guest
        .send(AGENT_PORT, AGENT_PORT, 5, 65536, b"cancel")
        .await?;
    wasmtime::ensure!(
        read_stream(agent, generation, 6).await? == b"cancel",
        "agent cancellation progresses at full combined network capacity"
    );
    agent
        .try_write(generation, b"pressure-reply")
        .map_err(|error| wasmtime::Error::msg(format!("agent pressure output: {error:?}")))?;
    wasmtime::ensure!(
        guest
            .stream
            .read_bytes((AGENT_PORT, AGENT_PORT), 14)
            .await?
            == b"pressure-reply",
        "agent replies progress while all eight TCP receive windows are full"
    );
    guest.exercise_dns().await?;
    for &stream in &stalled {
        wasmtime::ensure!(
            !guest.stream.is_reset(stream),
            "capacity denial preserves admitted TCP flows"
        );
        wasmtime::ensure!(
            guest.stream.buffered_bytes(stream) == FLOW_REPLY_BYTES,
            "unread TCP payload stays within the advertised guest receive window"
        );
        wasmtime::ensure!(
            guest.stream.credit_requests(stream) <= 3,
            "unchanged credit replies cannot create a credit request storm"
        );
    }
    Ok((stalled, udp))
}

async fn start_guest(
    artifacts: &TrustedArtifacts,
    engine: &wasmtime::Engine,
    backend: NetworkBackend,
    mappings: Vec<PortMapping>,
) -> wasmtime::Result<(
    GuestNetwork,
    StreamEndpoint,
    crate::box_runtime::BoxRuntimeHandle,
)> {
    let ram = GuestRam::new(2 * 1024 * 1024)
        .ok_or_else(|| wasmtime::Error::msg("network self-test RAM allocation"))?;
    let mut runtime = BoxRuntime::new(engine, BoxHost::new())?;
    runtime.initialize_mmio()?;
    let (streams, agent) = FrontendStreams::new();
    let (interrupt, events) = create_interrupt();
    let device = crate::component::vsock::register_device(
        &mut runtime,
        ram.clone(),
        artifacts.vsock(),
        streams,
        Some(backend),
        mappings,
        interrupt,
    )?;
    let running = runtime.prepare().await?.start();
    let mut transport = GuestVsock::new(device.clone(), ram, events);
    let result = async {
        transport.configure()?;
        let mut guest = GuestNetwork::new(GuestStream::new(transport))
            .await
            .map_err(|error| error.context("network control admission and ABI readiness"))?;
        guest
            .stream
            .guest
            .send(AGENT_PORT, AGENT_PORT, 1, 65536, &[])
            .await?;
        Ok(guest)
    }
    .await;
    match result {
        Ok(guest) => Ok((guest, agent, running)),
        Err(error) => {
            let _ = device.close_async().await;
            let _ = running.join().await;
            Err(error)
        }
    }
}

async fn run_dns_fallback(
    artifacts: &TrustedArtifacts,
    engine: &wasmtime::Engine,
) -> wasmtime::Result<()> {
    let (backend, stop, broker_task) = create_dns_fallback_backend();
    let client = backend.client.clone();
    let result = async {
        let (mut guest, _, running) = start_guest(artifacts, engine, backend, Vec::new()).await?;
        let exercised = guest.exercise_dns_fallback().await;
        let closed = guest.stream.guest.device.close_async().await;
        let joined = running.join().await;
        exercised?;
        closed?;
        joined
    }
    .await;
    let _ = stop.send(());
    client.disconnect();
    let served = tokio::time::timeout(WAIT, broker_task).await??;
    result?;
    served
}

/// A malformed control frame retires the control stream and disables networking; agent services remain.
async fn exercise_control_failure(
    guest: &mut GuestNetwork,
    agent: &mut StreamEndpoint,
) -> wasmtime::Result<()> {
    let generation = wait_connected(agent).await?;
    let udp = [guest.open_udp(19003).await?, guest.open_udp(19004).await?];
    guest
        .stream
        .submit_raw(CONTROL, &[0; terra_protocol::application::HEADER_BYTES])
        .await?;
    guest.stream.require_reset(CONTROL).await?;
    for stream in udp {
        guest.stream.require_reset(stream).await?;
    }
    for refused in [(19002, TCP_PORT), (19002, UDP_PORT), CONTROL] {
        guest
            .stream
            .guest
            .send(refused.0, refused.1, 1, 24576, &[])
            .await?;
        guest.stream.require_reset(refused).await?;
    }
    wasmtime::ensure!(
        agent.current() == Some(generation),
        "control loss preserves agent services"
    );
    guest
        .stream
        .guest
        .send(AGENT_PORT, AGENT_PORT, 5, 65536, b"after")
        .await?;
    wasmtime::ensure!(
        read_stream(agent, generation, 5).await? == b"after",
        "agent input progresses after network control loss"
    );
    agent.try_write(generation, b"reply").map_err(|error| {
        wasmtime::Error::msg(format!("agent output after control loss: {error:?}"))
    })?;
    wasmtime::ensure!(
        guest.stream.read_bytes((AGENT_PORT, AGENT_PORT), 5).await? == b"reply",
        "agent output progresses after network control loss"
    );
    Ok(())
}

async fn exercise_socket_stream(
    guest: &mut GuestNetwork,
    agent: &mut StreamEndpoint,
    endpoints: Endpoints,
) -> wasmtime::Result<()> {
    let agent_generation = wait_connected(agent)
        .await
        .map_err(|error| error.context("agent admission with networking enabled"))?;
    guest.exercise_opening_errors().await?;
    let stalled = guest
        .open_tcp(TcpTarget::HostService(endpoints.tcp))
        .await?;
    guest
        .stream
        .guest
        .set_receive_window(stalled.0, stalled.1, 0);
    guest
        .stream
        .guest
        .send(stalled.0, stalled.1, 6, 0, &[])
        .await?;
    guest
        .stream
        .guest
        .send(AGENT_PORT, AGENT_PORT, 5, 65536, b"cancel")
        .await?;
    wasmtime::ensure!(
        read_stream(agent, agent_generation, 6).await? == b"cancel",
        "agent cancellation input progresses while a TCP peer stalls"
    );
    agent
        .try_write(agent_generation, b"control-reply")
        .map_err(|error| wasmtime::Error::msg(format!("agent output: {error:?}")))?;
    wasmtime::ensure!(
        guest
            .stream
            .read_bytes((AGENT_PORT, AGENT_PORT), 13)
            .await?
            == b"control-reply",
        "agent output progresses while a TCP peer stalls"
    );
    guest
        .exercise_dns()
        .await
        .map_err(|error| error.context("concurrent DNS and name policy"))?;
    guest.exercise_udp(endpoints.udp).await.map_err(|error| {
        error.context("UDP per-datagram peers, socket loss and asynchronous denial")
    })?;
    guest
        .exchange_tcp(TcpTarget::HostService(endpoints.tcp), &build_tcp_payload())
        .await?;
    guest
        .exchange_tcp(
            TcpTarget::Peer((socket::HOST_SERVICE_IPV6, endpoints.tcp).into()),
            b"terra-ipv6",
        )
        .await?;
    for _ in 0..2 {
        guest.exchange_published().await.map_err(|error| {
            error.context("successive frontend-initiated TCP publication streams")
        })?;
    }
    let (publication, prior_peer) = guest
        .exchange_published_udp()
        .await
        .map_err(|error| error.context("frontend-initiated UDP publication streams"))?;
    guest.stream.reset(publication).await?;
    let (_, denied) = guest
        .open_tcp_result(TcpTarget::Peer(
            (Ipv4Addr::new(192, 0, 2, 23), endpoints.tcp).into(),
        ))
        .await?;
    wasmtime::ensure!(
        denied == Message::TcpOpened(Err(Error::AccessDenied)),
        "TCP opening reports broker authorization failure before raw data"
    );
    guest.stream.reset(stalled).await?;
    guest
        .exchange_reopened_publication_udp(publication, prior_peer)
        .await?;
    let replacement = guest
        .open_tcp_on(stalled.0, TcpTarget::HostService(endpoints.tcp))
        .await?;
    wasmtime::ensure!(
        guest.stream.read_bytes(replacement, 11).await? == b"reset-reply",
        "a reused source port after reset carries only fresh raw bytes"
    );
    guest.stream.finish_input(replacement).await?;
    guest.stream.require_eof(replacement).await?;
    guest
        .exercise_tcp_half_closes(endpoints.tcp)
        .await
        .map_err(|error| error.context("TCP half closes and reset after FIN"))
}

struct GuestNetwork {
    stream: GuestStream,
    next_guest_port: u32,
    next_query: u32,
    udp_publications: Vec<Stream>,
}

impl GuestNetwork {
    async fn new(stream: GuestStream) -> wasmtime::Result<Self> {
        let mut guest = Self {
            stream,
            next_guest_port: 10000,
            next_query: 1,
            udp_publications: Vec::new(),
        };
        guest.stream.connect(CONTROL).await?;
        guest.stream.send_message(CONTROL, &Message::Hello).await?;
        wasmtime::ensure!(
            guest.stream.read_message(CONTROL).await? == Message::Ready,
            "network ABI readiness precedes socket operations"
        );
        Ok(guest)
    }

    async fn exercise_opening_errors(&mut self) -> wasmtime::Result<()> {
        let tcp = Message::TcpOpen {
            target: TcpTarget::HostService(80),
            inline_urgent: false,
        };
        for (host_port, opening, wrong_class, expected) in [
            (
                TCP_PORT,
                tcp.clone(),
                Message::UdpOpen,
                Message::TcpOpened(Err(Error::Protocol)),
            ),
            (
                UDP_PORT,
                Message::UdpOpen,
                tcp,
                Message::UdpOpened(Err(Error::Protocol)),
            ),
        ] {
            let mut wrong_version = opening.encode()?;
            let version_start = terra_protocol::application::HEADER_BYTES;
            wrong_version[version_start..version_start + 2]
                .copy_from_slice(&(terra_protocol::application::VERSION + 1).to_le_bytes());
            for bytes in [wrong_version, wrong_class.encode()?] {
                let stream = (self.allocate_guest_port(), host_port);
                self.stream.connect(stream).await?;
                self.stream.submit_raw(stream, &bytes).await?;
                wasmtime::ensure!(
                    self.stream.read_message(stream).await? == expected,
                    "invalid socket openings report a protocol error before EOF"
                );
                self.stream.require_eof(stream).await?;
                self.stream.reset(stream).await?;
            }
        }
        let refused = (self.allocate_guest_port(), PUBLICATION_PORT);
        self.stream
            .guest
            .send(refused.0, refused.1, 1, 24576, &[])
            .await?;
        self.stream.require_reset(refused).await
    }

    async fn open_tcp_on(
        &mut self,
        guest_port: u32,
        target: TcpTarget,
    ) -> wasmtime::Result<Stream> {
        let (stream, result) = self.open_tcp_result_on(guest_port, target).await?;
        wasmtime::ensure!(
            matches!(result, Message::TcpOpened(Ok(_))),
            "network self-test TCP opening: {result:?}"
        );
        Ok(stream)
    }

    async fn open_tcp_result_on(
        &mut self,
        guest_port: u32,
        target: TcpTarget,
    ) -> wasmtime::Result<(Stream, Message)> {
        let stream = (guest_port, TCP_PORT);
        self.stream.connect(stream).await?;
        let opening = Message::TcpOpen {
            target,
            inline_urgent: true,
        }
        .encode()?;
        self.stream.submit_raw(stream, &opening[..5]).await?;
        self.stream.submit_raw(stream, &opening[5..]).await?;
        let result = self.stream.read_message(stream).await?;
        Ok((stream, result))
    }

    fn allocate_guest_port(&mut self) -> u32 {
        let port = self.next_guest_port;
        self.next_guest_port += 1;
        port
    }

    async fn open_tcp_result(&mut self, target: TcpTarget) -> wasmtime::Result<(Stream, Message)> {
        let port = self.allocate_guest_port();
        self.open_tcp_result_on(port, target).await
    }

    async fn open_tcp(&mut self, target: TcpTarget) -> wasmtime::Result<Stream> {
        let port = self.allocate_guest_port();
        self.open_tcp_on(port, target).await
    }

    async fn open_udp(&mut self, guest_port: u32) -> wasmtime::Result<Stream> {
        let stream = (guest_port, UDP_PORT);
        self.stream.connect(stream).await?;
        self.stream.send_message(stream, &Message::UdpOpen).await?;
        let reply = self.stream.read_message(stream).await?;
        wasmtime::ensure!(
            reply == Message::UdpOpened(Ok(())),
            "UDP socket admission on {guest_port}: {reply:?}"
        );
        Ok(stream)
    }

    async fn exercise_tcp_half_closes(&mut self, port: u16) -> wasmtime::Result<()> {
        let reset_after_fin = self.open_tcp(TcpTarget::HostService(port)).await?;
        self.stream.require_eof(reset_after_fin).await?;
        self.stream.submit_raw(reset_after_fin, b"R").await?;
        self.stream.require_reset(reset_after_fin).await?;
        let receive_closed = self.open_tcp(TcpTarget::HostService(port)).await?;
        wasmtime::ensure!(
            self.stream.read_bytes(receive_closed, 16 * 1024).await? == vec![83; 16 * 1024],
            "guest receive close follows the prefetched raw payload"
        );
        self.stream
            .guest
            .send_with_flags(receive_closed.0, receive_closed.1, 4, 1, 24576, &[])
            .await?;
        self.stream.submit_raw(receive_closed, b"R").await?;
        self.stream.finish_input(receive_closed).await?;
        self.exercise_dns().await
    }

    async fn exchange_tcp(&mut self, target: TcpTarget, payload: &[u8]) -> wasmtime::Result<()> {
        let stream = self.open_tcp(target).await?;
        self.stream.submit_raw(stream, payload).await?;
        self.stream.finish_input(stream).await?;
        wasmtime::ensure!(
            self.stream.read_bytes(stream, payload.len()).await? == payload,
            "raw TCP bytes retain content through broker queues and FIN"
        );
        self.stream.require_eof(stream).await?;
        self.stream
            .guest
            .send_with_flags(stream.0, stream.1, 4, 3, 0, &[])
            .await?;
        self.stream.reset(stream).await?;
        let bytes = self.resolve(false, dns_query("loopback.test")?).await?;
        wasmtime::ensure!(
            bytes.ends_with(&Ipv4Addr::LOCALHOST.octets()),
            "the frontend keeps serving after a guest closes and resets a TCP stream"
        );
        Ok(())
    }

    async fn exchange_published(&mut self) -> wasmtime::Result<()> {
        let (stream, guest_port, peer) = loop {
            let stream = self.stream.accept().await?;
            match self.stream.read_message(stream).await? {
                Message::Publication { guest_port, peer } => break (stream, guest_port, peer),
                Message::PublicationUdp { guest_port: 8081 } => self.udp_publications.push(stream),
                other => wasmtime::bail!("network self-test publication header: {other:?}"),
            }
        };
        wasmtime::ensure!(
            guest_port == 8080 && peer.ip().is_loopback(),
            "publication header names the configured port and its host peer"
        );
        let payload = build_tcp_payload();
        wasmtime::ensure!(
            self.stream.read_bytes(stream, payload.len()).await? == payload,
            "published raw TCP request"
        );
        self.stream.require_eof(stream).await?;
        self.stream.submit_raw(stream, b"published-reply").await?;
        self.stream.finish_input(stream).await
    }

    async fn exchange_published_udp(&mut self) -> wasmtime::Result<(Stream, std::net::SocketAddr)> {
        while self.udp_publications.len() < 2 {
            let stream = self.stream.accept().await?;
            wasmtime::ensure!(
                self.stream.read_message(stream).await?
                    == Message::PublicationUdp { guest_port: 8081 },
                "UDP publication names only the authorized guest port"
            );
            self.udp_publications.push(stream);
        }
        let mut ipv4 = None;
        for stream in self.udp_publications.clone() {
            let Message::UdpDatagram { peer, bytes } = self.stream.read_message(stream).await?
            else {
                wasmtime::bail!("published UDP requires datagram framing");
            };
            wasmtime::ensure!(
                peer.ip().is_loopback(),
                "published UDP retains the external host peer"
            );
            wasmtime::ensure!(
                bytes
                    == if peer.is_ipv4() {
                        b"published-one".as_slice()
                    } else {
                        b"published-ipv6".as_slice()
                    },
                "published UDP family and payload"
            );
            self.stream
                .send_message(stream, &Message::UdpSend { peer, bytes })
                .await?;
            if peer.is_ipv4() {
                ipv4 = Some((stream, peer));
                let Message::UdpDatagram {
                    peer: second,
                    bytes,
                } = self.stream.read_message(stream).await?
                else {
                    wasmtime::bail!("published UDP second peer datagram");
                };
                wasmtime::ensure!(
                    second != peer && bytes == vec![61; 4096],
                    "UDP publication admits distinct host peers and maximum datagrams"
                );
                self.stream
                    .send_message(
                        stream,
                        &Message::UdpSend {
                            peer: second,
                            bytes,
                        },
                    )
                    .await?;
            }
        }
        let (stream, first_peer) =
            ipv4.ok_or_else(|| wasmtime::Error::msg("missing IPv4 UDP publication"))?;
        for expected in [b"".as_slice(), b"after-oversize"] {
            let Message::UdpDatagram { peer, bytes } = self.stream.read_message(stream).await?
            else {
                wasmtime::bail!("published UDP datagram after oversized drop");
            };
            wasmtime::ensure!(
                bytes == expected,
                "UDP publication drops oversized input without truncating it"
            );
            self.stream
                .send_message(stream, &Message::UdpSend { peer, bytes })
                .await?;
        }
        let peer = (Ipv4Addr::LOCALHOST, 9).into();
        self.stream
            .send_message(
                stream,
                &Message::UdpSend {
                    peer,
                    bytes: vec![1],
                },
            )
            .await?;
        wasmtime::ensure!(
            self.stream.read_message(stream).await?
                == Message::UdpError {
                    peer,
                    error: Error::AccessDenied
                },
            "UDP publication cannot send to a host peer that never contacted the listener"
        );
        Ok((stream, first_peer))
    }

    async fn exchange_reopened_publication_udp(
        &mut self,
        retired: Stream,
        prior_peer: std::net::SocketAddr,
    ) -> wasmtime::Result<()> {
        let stream = self.stream.accept().await?;
        wasmtime::ensure!(
            stream != retired,
            "replacement UDP publication has a fresh transport tuple"
        );
        wasmtime::ensure!(
            self.stream.read_message(stream).await? == Message::PublicationUdp { guest_port: 8081 },
            "replacement UDP publication validates its guest port again"
        );
        let Message::UdpDatagram { peer, bytes } = self.stream.read_message(stream).await? else {
            wasmtime::bail!("replacement UDP publication first datagram");
        };
        wasmtime::ensure!(
            peer != prior_peer && bytes == b"publication-reopened",
            "replacement UDP publication contains only the fresh host peer and datagram"
        );
        self.stream
            .send_message(
                stream,
                &Message::UdpSend {
                    peer: prior_peer,
                    bytes: vec![1],
                },
            )
            .await?;
        wasmtime::ensure!(
            self.stream.read_message(stream).await?
                == Message::UdpError {
                    peer: prior_peer,
                    error: Error::AccessDenied
                },
            "a retired UDP publication peer cannot authorize replies in the replacement"
        );
        self.stream
            .send_message(stream, &Message::UdpSend { peer, bytes })
            .await?;
        self.udp_publications
            .retain(|publication| *publication != retired);
        self.udp_publications.push(stream);
        Ok(())
    }

    async fn exercise_udp(&mut self, port: u16) -> wasmtime::Result<()> {
        let retired_port = self.allocate_guest_port();
        let retired = self.open_udp(retired_port).await?;
        let guest_port = self.allocate_guest_port();
        let stream = self.open_udp(guest_port).await?;
        self.stream.reset(retired).await?;
        let replacement = self.open_udp(retired_port).await?;
        let ipv4 = (socket::HOST_SERVICE_IPV4, port).into();
        let ipv6 = (socket::HOST_SERVICE_IPV6, port).into();
        for (index, (peer, payload)) in [
            (ipv4, b"terra-udp".to_vec()),
            (ipv6, b"terra-ipv6".to_vec()),
            (ipv4, vec![37; 3072]),
            (ipv4, Vec::new()),
        ]
        .into_iter()
        .enumerate()
        {
            self.stream
                .send_message(
                    stream,
                    &Message::UdpSend {
                        peer,
                        bytes: payload.clone(),
                    },
                )
                .await?;
            wasmtime::ensure!(
                self.stream.read_message(stream).await?
                    == Message::UdpDatagram {
                        peer,
                        bytes: payload
                    },
                "UDP preserves the guest-visible sender address and datagram boundaries"
            );
            if index == 0 {
                let denied = (Ipv4Addr::new(192, 0, 2, 23), port).into();
                self.stream
                    .send_message(
                        stream,
                        &Message::UdpSend {
                            peer: denied,
                            bytes: vec![1],
                        },
                    )
                    .await?;
                wasmtime::ensure!(
                    self.stream.read_message(stream).await?
                        == Message::UdpError {
                            peer: denied,
                            error: Error::AccessDenied
                        },
                    "a denied UDP send is reported asynchronously and leaves the socket usable"
                );
            }
        }
        let mut burst = Vec::new();
        for index in 0..u8::try_from(UDP_BURST_DATAGRAMS)? {
            burst.extend(
                Message::UdpSend {
                    peer: ipv4,
                    bytes: vec![index; usize::from(index) + 1],
                }
                .encode()?,
            );
        }
        self.stream.submit_raw(stream, &burst).await?;
        for index in 0..u8::try_from(UDP_BURST_DATAGRAMS)? {
            wasmtime::ensure!(
                self.stream.read_message(stream).await?
                    == Message::UdpDatagram {
                        peer: ipv4,
                        bytes: vec![index; usize::from(index) + 1]
                    },
                "UDP receive streams retain every datagram across a broker batch boundary"
            );
        }
        self.stream.finish_input(stream).await?;
        self.stream.require_eof(stream).await?;
        self.stream
            .send_message(replacement, &Message::Hello)
            .await?;
        self.stream.require_reset(replacement).await?;
        self.exercise_dns().await
    }

    async fn query_dns(&mut self, stream: bool, bytes: Vec<u8>) -> wasmtime::Result<u32> {
        let id = self.next_query;
        self.next_query += 1;
        self.stream
            .send_message(CONTROL, &Message::DnsQuery { id, stream, bytes })
            .await?;
        Ok(id)
    }

    async fn read_dns(&mut self) -> wasmtime::Result<(u32, bool, Vec<u8>)> {
        match self.stream.read_message(CONTROL).await? {
            Message::DnsResult { id, stream, bytes } => Ok((id, stream, bytes)),
            other => wasmtime::bail!("unexpected control message {other:?}"),
        }
    }

    async fn resolve(&mut self, stream: bool, bytes: Vec<u8>) -> wasmtime::Result<Vec<u8>> {
        let id = self.query_dns(stream, bytes).await?;
        let (answered, answered_stream, bytes) = self.read_dns().await?;
        wasmtime::ensure!(
            answered == id && answered_stream == stream,
            "DNS result identity"
        );
        Ok(bytes)
    }

    async fn exercise_dns(&mut self) -> wasmtime::Result<()> {
        let mut pending = VecDeque::new();
        for _ in 0..6 {
            pending.push_back(self.query_dns(false, dns_query("loopback.test")?).await?);
        }
        while !pending.is_empty() {
            let (id, stream, bytes) = self.read_dns().await?;
            let position = pending
                .iter()
                .position(|query| *query == id)
                .ok_or_else(|| wasmtime::Error::msg("unknown DNS result identity"))?;
            pending.remove(position);
            wasmtime::ensure!(
                !stream && bytes.ends_with(&Ipv4Addr::LOCALHOST.octets()),
                "concurrent DNS broker result"
            );
        }
        for (name, code) in [("loopback.test", 0), ("localhost", 2), ("denied.test", 3)] {
            let bytes = self.resolve(false, dns_query(name)?).await?;
            wasmtime::ensure!(
                bytes.len() >= 12 && bytes[..2] == [0x12, 0x34] && bytes[3] & 15 == code,
                "broker-authorized DNS response for {name}"
            );
        }
        let query = dns_query("loopback.test")?;
        let mut bytes = u16::try_from(query.len())?.to_be_bytes().to_vec();
        bytes.extend(query);
        let bytes = self.resolve(true, bytes).await?;
        wasmtime::ensure!(
            usize::from(u16::from_be_bytes(bytes[..2].try_into()?)) == bytes.len() - 2
                && bytes.ends_with(&Ipv4Addr::LOCALHOST.octets()),
            "DNS TCP framing"
        );
        Ok(())
    }

    async fn exercise_dns_fallback(&mut self) -> wasmtime::Result<()> {
        let query = dns_query("many.test")?;
        let bytes = self.resolve(false, query.clone()).await?;
        wasmtime::ensure!(
            bytes.len() == query.len() && bytes[2] & 2 != 0 && bytes[6..12] == [0; 6],
            "DNS truncation requests TCP fallback"
        );
        let mut framed = u16::try_from(query.len())?.to_be_bytes().to_vec();
        framed.extend(&query);
        let bytes = self.resolve(true, framed).await?;
        wasmtime::ensure!(
            bytes.len() == 2 + query.len() + 32 * 16
                && bytes[8..10] == 32_u16.to_be_bytes()
                && bytes[4] & 2 == 0,
            "DNS TCP fallback retains every broker-authorized address"
        );
        for (answer, last) in bytes[2 + query.len()..]
            .as_chunks::<16>()
            .0
            .iter()
            .zip(1..=32)
        {
            wasmtime::ensure!(
                answer[12..] == Ipv4Addr::new(192, 0, 2, last).octets(),
                "DNS fallback answer integrity"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Accepted sockets inherit nonblocking mode on macOS; fixture reads must wait for delayed input.
    #[test]
    fn configured_fixture_stream_waits_for_delayed_input() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut stream = listener.accept().unwrap().0;
        stream.set_nonblocking(true).unwrap();
        let mut bytes = [0];
        assert_eq!(
            stream.read(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        configure_stream(&stream).unwrap();
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            client.write_all(b"R").unwrap();
        });
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"R");
        sender.join().unwrap();
    }

    /// The host self-test starts these servers before its boot, vsock, storage and filesystem
    /// stages; a server that gave up after `WAIT` refused the guest's later connection under
    /// tracing or load.
    #[test]
    fn test_servers_outlive_earlier_self_test_stages() {
        let servers = TestServers::start().unwrap();
        std::thread::sleep(WAIT + Duration::from_secs(1));
        let endpoints = servers.endpoints;
        TcpStream::connect((Ipv4Addr::LOCALHOST, endpoints.tcp)).unwrap();
        TcpStream::connect((std::net::Ipv6Addr::LOCALHOST, endpoints.tcp)).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "UDP throughput: run with --release --ignored --nocapture"]
    async fn broker_backed_udp_throughput_without_virtualization() {
        const PAYLOAD_BYTES: usize = 1200;
        const DATAGRAMS: usize = 4096;
        const SAMPLES: usize = 5;
        const WINDOWS: [usize; 2] = [1, 32];

        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.set_read_timeout(Some(WAIT)).unwrap();
        socket.set_write_timeout(Some(WAIT)).unwrap();
        let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let endpoints = Endpoints {
            tcp: 9,
            udp: socket.local_addr().unwrap().port(),
            published: reserved.local_addr().unwrap().port(),
        };
        drop(reserved);
        let server = std::thread::spawn(move || {
            let mut bytes = [0; PAYLOAD_BYTES + 1];
            for _ in 0..WINDOWS.len() * (SAMPLES + 1) * DATAGRAMS {
                let (length, peer) = socket.recv_from(&mut bytes).unwrap();
                assert_eq!(length, PAYLOAD_BYTES);
                assert!(bytes[..length].iter().all(|byte| *byte == 37));
                assert_eq!(socket.send_to(&bytes[..length], peer).unwrap(), length);
            }
        });
        let (backend, broker_task) = create_backend(endpoints).unwrap();
        let client = backend.client.clone();
        let (mut guest, _, running) = start_guest(
            &crate::test_fixtures::trusted_artifacts(),
            &crate::engine::device_engine().unwrap(),
            backend,
            Vec::new(),
        )
        .await
        .unwrap();
        let guest_port = guest.allocate_guest_port();
        let stream = guest.open_udp(guest_port).await.unwrap();
        let peer = (socket::HOST_SERVICE_IPV4, endpoints.udp).into();
        let payload = vec![37; PAYLOAD_BYTES];
        let request = Message::UdpSend {
            peer,
            bytes: payload.clone(),
        }
        .encode()
        .unwrap();
        let expected = Message::UdpDatagram {
            peer,
            bytes: payload,
        };
        let payload_mib =
            f64::from(u32::try_from(PAYLOAD_BYTES * DATAGRAMS).unwrap()) / 1024.0 / 1024.0;
        println!(
            "native UDP echo + broker + production frontend/virtqueues; excludes VM and setup; one warmup per window"
        );
        for window in WINDOWS {
            let burst = request.repeat(window);
            for sample in 0..=SAMPLES {
                let started = Instant::now();
                for _ in 0..DATAGRAMS / window {
                    guest.stream.submit_raw(stream, &burst).await.unwrap();
                    for _ in 0..window {
                        assert_eq!(guest.stream.read_message(stream).await.unwrap(), expected);
                    }
                }
                let elapsed = started.elapsed().as_secs_f64();
                if sample != 0 {
                    println!(
                        "window={window} sample={sample} echo_mib_per_second={:.3} mean_echo_us={:.3}",
                        payload_mib / elapsed,
                        elapsed * 1_000_000.0 / f64::from(u32::try_from(DATAGRAMS).unwrap()),
                    );
                }
            }
        }
        guest.stream.reset(stream).await.unwrap();
        guest.stream.guest.device.close_async().await.unwrap();
        running.join().await.unwrap();
        server.join().unwrap();
        client.disconnect();
        require_broker_peer_shutdown(
            tokio::time::timeout(WAIT, broker_task)
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "TCP throughput: run with --release --ignored --nocapture"]
    async fn broker_backed_tcp_throughput_without_virtualization() {
        const PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
        const SAMPLES: usize = 5;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let endpoints = Endpoints {
            tcp: listener.local_addr().unwrap().port(),
            udp: 9,
            published: reserved.local_addr().unwrap().port(),
        };
        drop(reserved);
        let server = std::thread::spawn(move || {
            let expected = vec![37; PAYLOAD_BYTES];
            for _ in 0..=SAMPLES {
                let mut stream =
                    accept_stream(&listener, super::super::FIXTURE_STARTUP_WAIT).unwrap();
                let mut request = vec![0; PAYLOAD_BYTES];
                stream.read_exact(&mut request).unwrap();
                assert_eq!(request, expected);
                let mut eof = [0];
                assert_eq!(stream.read(&mut eof).unwrap(), 0);
                stream.write_all(&expected).unwrap();
                stream.shutdown(Shutdown::Write).unwrap();
            }
        });
        let (backend, broker_task) = create_backend(endpoints).unwrap();
        let client = backend.client.clone();
        let (mut guest, _, running) = start_guest(
            &crate::test_fixtures::trusted_artifacts(),
            &crate::engine::device_engine().unwrap(),
            backend,
            Vec::new(),
        )
        .await
        .unwrap();
        let payload = vec![37; PAYLOAD_BYTES];
        let payload_mib = f64::from(u32::try_from(payload.len()).unwrap()) / 1024.0 / 1024.0;
        println!(
            "native TCP + broker + production frontend/virtqueues; excludes VM and setup; one warmup"
        );
        for sample in 0..=SAMPLES {
            let stream = guest
                .open_tcp(TcpTarget::HostService(endpoints.tcp))
                .await
                .unwrap();
            let started = Instant::now();
            guest.stream.submit_raw(stream, &payload).await.unwrap();
            guest.stream.finish_input(stream).await.unwrap();
            let upload = started.elapsed();
            let started = Instant::now();
            assert_eq!(
                guest
                    .stream
                    .read_bytes(stream, PAYLOAD_BYTES)
                    .await
                    .unwrap(),
                payload
            );
            guest.stream.require_eof(stream).await.unwrap();
            let download = started.elapsed();
            guest.stream.reset(stream).await.unwrap();
            if sample != 0 {
                println!(
                    "sample={sample} upload_mib_per_second={:.3} download_mib_per_second={:.3}",
                    payload_mib / upload.as_secs_f64(),
                    payload_mib / download.as_secs_f64(),
                );
            }
        }
        guest.stream.guest.device.close_async().await.unwrap();
        running.join().await.unwrap();
        server.join().unwrap();
        client.disconnect();
        require_broker_peer_shutdown(
            tokio::time::timeout(WAIT, broker_task)
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn broker_backed_socket_stream_exercises_dns_tcp_udp_published_and_reconnect() {
        let servers = TestServers::start().unwrap();
        let endpoints = servers.endpoints;
        let (backend, broker_task) = create_backend(endpoints).unwrap();
        let client = backend.client.clone();
        let result = run_with_backend(
            &crate::test_fixtures::trusted_artifacts(),
            &crate::engine::device_engine().unwrap(),
            backend,
            endpoints,
        )
        .await;
        let served = servers.finish();
        result.unwrap();
        served.unwrap();
        client.disconnect();
        require_broker_peer_shutdown(
            tokio::time::timeout(WAIT, broker_task)
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, endpoints.published)).is_err());
        assert!(UdpSocket::bind((Ipv4Addr::LOCALHOST, endpoints.published)).is_ok());
    }
}
