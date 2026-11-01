//! Guest DNS and publication services over the agent's own network control and publication vsock endpoints.

use crate::diagnostics::Diagnostics;
use anyhow::{Context as _, Result, ensure};
use futures_util::{StreamExt as _, stream::FuturesUnordered};
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use terra_protocol::application::{HostFrame, LentFrame, StreamDecoder, UdpRun};
use terra_protocol::network_control::{
    AgentControl, DnsPayload, DnsTransport, FrontendControl, MAX_DNS_QUERIES, Publication,
};
use terra_protocol::vsock::{CONTROL_PORT, GUEST_CID, PUBLICATION_PORT};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore, SemaphorePermit, oneshot};
use tokio::time::Instant;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub(crate) const RELAY_SOURCE: Ipv4Addr = Ipv4Addr::new(169, 254, 96, 1);
pub(crate) const PUBLISHED_DESTINATION: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 2);
const DNS_IPV4: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 53);
const DNS_ADDRESS: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(DNS_IPV4), 53);
const MAX_DNS_CLIENTS: usize = 16;
const MAX_TCP_PUBLICATION_CLIENTS: usize = 32;
const MAX_UDP_PUBLICATION_CLIENTS: usize = 2 * terra_protocol::MAX_PUBLISHED_PORTS;
const MAX_PUBLICATION_CARRIERS: usize = 128;
const BASE_AGENT_OPEN_FILES: usize = 1024;
// A TCP carrier holds its vsock stream and the published service socket.
const _: () = assert!(2 * MAX_PUBLICATION_CARRIERS <= BASE_AGENT_OPEN_FILES);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const PUBLICATION_TIMEOUT: Duration =
    Duration::from_secs(terra_protocol::application::OPEN_TIMEOUT_SECS);
const UDP_PEER_TTL: Duration = Duration::from_secs(terra_protocol::network::UDP_PEER_TTL_SECS);

type Writer = AsyncMutex<Pin<Box<dyn AsyncWrite + Send>>>;
type PendingQueries = Mutex<BTreeMap<u32, oneshot::Sender<DnsPayload>>>;

struct PublicationGrants {
    tcp: PortGrant,
    udp: PortGrant,
}

impl PublicationGrants {
    fn new(tcp_ports: Vec<u16>, udp_ports: Vec<u16>) -> Self {
        Self {
            tcp: PortGrant {
                ports: tcp_ports,
                slots: Semaphore::new(MAX_TCP_PUBLICATION_CLIENTS),
            },
            udp: PortGrant {
                ports: udp_ports,
                slots: Semaphore::new(MAX_UDP_PUBLICATION_CLIENTS),
            },
        }
    }
}

/// The guest ports one protocol may publish, and how many relays may run at once.
struct PortGrant {
    ports: Vec<u16>,
    slots: Semaphore,
}

impl PortGrant {
    fn admit(&self, guest_port: u16) -> io::Result<SemaphorePermit<'_>> {
        if !self.ports.contains(&guest_port) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "publication names an unconfigured guest port",
            ));
        }
        self.slots.try_acquire().map_err(io::Error::other)
    }
}

struct UdpPublicationPeer {
    peer: SocketAddr,
    socket: UdpSocket,
    expires: Instant,
}

struct NetworkClient {
    writer: Writer,
    pending: PendingQueries,
    next_id: AtomicU32,
    queries: Semaphore,
    shutdown: CancellationToken,
}

impl NetworkClient {
    fn new(writer: impl AsyncWrite + Send + 'static, shutdown: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            writer: AsyncMutex::new(Box::pin(writer)),
            pending: Mutex::default(),
            next_id: AtomicU32::new(1),
            queries: Semaphore::new(MAX_DNS_QUERIES),
            shutdown,
        })
    }

    async fn send(&self, message: &AgentControl) -> io::Result<()> {
        let bytes = terra_protocol::encode_frame(message)?;
        let mut writer = self.writer.lock().await;
        if self.shutdown.is_cancelled() {
            return Err(io::Error::from(rustix::io::Errno::NETDOWN));
        }
        let partial_write = self.shutdown.drop_guard_ref();
        writer.write_all(&bytes).await?;
        writer.flush().await?;
        partial_write.disarm();
        Ok(())
    }

    async fn query(&self, transport: DnsTransport, bytes: Vec<u8>) -> io::Result<Vec<u8>> {
        tokio::time::timeout(DNS_TIMEOUT, async {
            let _permit = self.queries.acquire().await.map_err(io::Error::other)?;
            let id = self
                .next_id
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
                .map_err(|_| io::Error::other("DNS query identifiers exhausted"))?;
            let (sender, reply) = oneshot::channel();
            crate::lock_or_abort(&self.pending).insert(id, sender);
            let _pending = PendingQuery {
                id,
                pending: &self.pending,
            };
            self.send(&AgentControl::DnsQuery(DnsPayload {
                id,
                transport,
                bytes,
            }))
            .await?;
            match reply.await {
                Ok(DnsPayload {
                    transport: answered,
                    bytes,
                    ..
                }) if answered == transport => Ok(bytes),
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected DNS response",
                )),
                Err(_) => Err(io::Error::from(rustix::io::Errno::NETDOWN)),
            }
        })
        .await?
    }
}

struct PendingQuery<'a> {
    id: u32,
    pending: &'a PendingQueries,
}

impl Drop for PendingQuery<'_> {
    fn drop(&mut self) {
        crate::lock_or_abort(self.pending).remove(&self.id);
    }
}

/// A vsock stream whose shutdown half-closes the connection, unlike a plain async file.
struct VsockStream(crate::AsyncFile);

impl VsockStream {
    fn new(socket: rustix::fd::OwnedFd) -> io::Result<Self> {
        crate::into_async_file(socket).map(Self)
    }
}

impl AsyncRead for VsockStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(context, buffer)
    }
}

impl AsyncWrite for VsockStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(
            rustix::net::shutdown(self.0.get_ref(), rustix::net::Shutdown::Write)
                .map_err(io::Error::from),
        )
    }
}

#[allow(unsafe_code)]
fn limit_vsock_buffer_bytes(socket: impl AsFd, buffer_bytes: usize) -> io::Result<()> {
    let bytes = u64::try_from(buffer_bytes).map_err(io::Error::other)?;
    let length =
        libc::socklen_t::try_from(std::mem::size_of_val(&bytes)).map_err(io::Error::other)?;
    for option in [
        linux_raw_sys::vm_sockets::SO_VM_SOCKETS_BUFFER_MAX_SIZE,
        linux_raw_sys::vm_sockets::SO_VM_SOCKETS_BUFFER_SIZE,
    ] {
        let option = i32::try_from(option).map_err(io::Error::other)?;
        // SAFETY: the borrowed socket stays live and setsockopt reads the initialized u64 of the specified length.
        if unsafe {
            libc::setsockopt(
                socket.as_fd().as_raw_fd(),
                libc::AF_VSOCK,
                option,
                std::ptr::from_ref(&bytes).cast(),
                length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut actual = 0_u64;
        let mut actual_length = length;
        // SAFETY: getsockopt writes only to the initialized u64 and socklen_t of the supplied length.
        if unsafe {
            libc::getsockopt(
                socket.as_fd().as_raw_fd(),
                libc::AF_VSOCK,
                option,
                std::ptr::from_mut(&mut actual).cast(),
                std::ptr::from_mut(&mut actual_length),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if actual_length != length || actual != bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vsock buffer limit changed; rebuild the guest kernel",
            ));
        }
    }
    Ok(())
}

fn connect_control() -> Result<VsockStream> {
    let socket = crate::mux::connect_vsock(CONTROL_PORT, "network control", |socket| {
        limit_vsock_buffer_bytes(socket, terra_protocol::vsock::CONTROL_REPLY_BYTES)
    })?;
    Ok(VsockStream::new(socket)?)
}

fn listen_publications() -> Result<tokio::io::unix::AsyncFd<File>> {
    let socket =
        crate::mux::create_vsock_socket().context("creating the publication vsock listener")?;
    limit_vsock_buffer_bytes(&socket, terra_protocol::vsock::FLOW_REPLY_BYTES)
        .context("configuring the publication vsock listener")?;
    rustix::net::bind(
        &socket,
        &crate::mux::vsock_address(GUEST_CID, PUBLICATION_PORT),
    )
    .context("binding the guest publication endpoint")?;
    rustix::net::listen(&socket, i32::try_from(MAX_PUBLICATION_CARRIERS)?)
        .context("listening for publication streams")?;
    rustix::io::ioctl_fionbio(&socket, true)?;
    Ok(crate::into_async_fd(socket)?)
}

/// Reads once into `decoder`; `false` at a clean end of the stream.
async fn read_into_decoder(
    reader: &mut (impl AsyncRead + Unpin),
    decoder: &mut StreamDecoder,
) -> io::Result<bool> {
    let count = reader.read(decoder.read_buffer()).await?;
    if count == 0 {
        return if decoder.is_empty() {
            Ok(false)
        } else {
            Err(io::Error::from(io::ErrorKind::UnexpectedEof))
        };
    }
    decoder.commit(count);
    Ok(true)
}

/// Delivers DNS results until the control stream ends; any end of the stream means networking is gone.
async fn receive_results(
    mut reader: impl AsyncRead + Unpin,
    client: Arc<NetworkClient>,
) -> io::Error {
    let error = loop {
        match terra_protocol::read_frame_async::<FrontendControl>(&mut reader).await {
            Ok(Some(FrontendControl::DnsResult(payload))) => {
                if let Some(sender) = crate::lock_or_abort(&client.pending).remove(&payload.id) {
                    let _ = sender.send(payload);
                }
            }
            Ok(Some(FrontendControl::Ready)) => {
                break io::Error::new(io::ErrorKind::InvalidData, "unexpected control message");
            }
            Ok(None) | Err(_) => break io::Error::from(rustix::io::Errno::NETDOWN),
        }
    };
    crate::lock_or_abort(&client.pending).clear();
    error
}

fn reserve_udp_publication_files(
    mut limits: rustix::process::Rlimit,
) -> Result<rustix::process::Rlimit> {
    let minimum = u64::try_from(
        BASE_AGENT_OPEN_FILES
            + MAX_UDP_PUBLICATION_CLIENTS
                * (terra_protocol::network::MAX_UDP_PUBLICATION_PEERS + 1),
    )?;
    ensure!(
        limits.maximum.is_none_or(|maximum| maximum >= minimum),
        "UDP publication requires an open-file hard limit of at least {minimum}; raise the guest hard limit"
    );
    if let Some(current) = limits.current {
        limits.current = Some(current.max(minimum));
    }
    Ok(limits)
}

/// Exchanges Hello/Ready on a fresh control stream.
async fn await_network_ready(
    client: &NetworkClient,
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<()> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        client.send(&AgentControl::Hello).await?;
        match terra_protocol::read_frame_async(reader).await? {
            Some(FrontendControl::Ready) => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "network returned an invalid readiness response",
            )),
        }
    })
    .await
    .context("network readiness handshake timed out")??;
    Ok(())
}

pub(crate) fn render_resolv_conf(net: terra_protocol::Net) -> String {
    match net {
        terra_protocol::Net::LocalOnly => "# local_only\n".to_owned(),
        terra_protocol::Net::Tsi => format!("nameserver {}\n", DNS_ADDRESS.ip()),
    }
}

pub(crate) async fn start(
    tasks: &TaskTracker,
    plan: &terra_protocol::Plan,
    shutdown: &CancellationToken,
    diagnostic: &Diagnostics,
) -> Result<()> {
    match plan.net {
        terra_protocol::Net::LocalOnly => {}
        terra_protocol::Net::Tsi => {
            let shutdown = shutdown.child_token();
            if !plan.published_udp_ports.is_empty() {
                let limits = reserve_udp_publication_files(rustix::process::getrlimit(
                    rustix::process::Resource::Nofile,
                ))?;
                rustix::process::setrlimit(rustix::process::Resource::Nofile, limits)
                    .context("reserving guest UDP publication descriptors")?;
            }
            crate::loopback::add_alias_address("lo:terra-dns", DNS_IPV4)?;
            let publications =
                if plan.published_ports.is_empty() && plan.published_udp_ports.is_empty() {
                    None
                } else {
                    crate::loopback::configure_publication_addresses(&shutdown).await?;
                    Some(listen_publications()?)
                };
            let (mut reader, writer) = tokio::io::split(connect_control()?);
            let client = NetworkClient::new(writer, shutdown.clone());
            await_network_ready(&client, &mut reader).await?;
            let results_client = client.clone();
            spawn_network_service(
                tasks,
                "control",
                async move { Err(receive_results(reader, results_client).await) },
                &shutdown,
                diagnostic,
            );
            let udp_dns = UdpSocket::bind(DNS_ADDRESS)
                .await
                .context("binding guest UDP DNS")?;
            let tcp_dns = TcpListener::bind(DNS_ADDRESS)
                .await
                .context("binding guest TCP DNS")?;
            spawn_network_service(
                tasks,
                "UDP DNS",
                serve_udp_dns(tasks.clone(), udp_dns, client.clone(), shutdown.clone()),
                &shutdown,
                diagnostic,
            );
            spawn_network_service(
                tasks,
                "TCP DNS",
                serve_tcp_dns(tasks.clone(), tcp_dns, client, shutdown.clone()),
                &shutdown,
                diagnostic,
            );
            if let Some(listener) = publications {
                spawn_network_service(
                    tasks,
                    "publication",
                    serve_publications(
                        tasks.clone(),
                        listener,
                        plan.published_ports.clone(),
                        plan.published_udp_ports.clone(),
                        shutdown.clone(),
                    ),
                    &shutdown,
                    diagnostic,
                );
            }
            ensure!(
                !shutdown.is_cancelled(),
                "network unavailable during startup"
            );
        }
    }
    Ok(())
}

async fn resolve_dns(
    client: &NetworkClient,
    transport: DnsTransport,
    query: Vec<u8>,
) -> io::Result<Vec<u8>> {
    if let Ok(response) = client.query(transport, query.clone()).await {
        return Ok(response);
    }
    Ok(terra_protocol::dns::error_response(
        &query,
        terra_protocol::dns::Rcode::ServFail,
    ))
}

fn spawn_network_service(
    tasks: &TaskTracker,
    name: &'static str,
    service: impl std::future::Future<Output = io::Result<()>> + Send + 'static,
    shutdown: &CancellationToken,
    diagnostic: &Diagnostics,
) {
    let shutdown = shutdown.clone();
    let diagnostic = diagnostic.clone();
    tasks.spawn(async move { run_network_service(name, service, &shutdown, &diagnostic).await });
}

fn spawn_admitted<Client>(
    tasks: &TaskTracker,
    shutdown: &CancellationToken,
    permit: OwnedSemaphorePermit,
    client: Client,
) where
    Client: std::future::Future<Output: Send> + Send + 'static,
{
    let shutdown = shutdown.clone();
    tasks.spawn(async move {
        let _permit = permit;
        shutdown.run_until_cancelled(client).await;
    });
}

async fn run_network_service(
    name: &str,
    service: impl std::future::Future<Output = io::Result<()>>,
    shutdown: &CancellationToken,
    diagnostic: &Diagnostics,
) {
    if let Some(Err(error)) = shutdown.run_until_cancelled(service).await {
        let message = format!("terra-agent: network unavailable: {name}: {error}\n");
        eprint!("{message}");
        diagnostic.record(message.as_bytes());
        shutdown.cancel();
    }
}

async fn serve_udp_dns(
    tasks: TaskTracker,
    socket: UdpSocket,
    client: Arc<NetworkClient>,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let socket = Arc::new(socket);
    let slots = Arc::new(Semaphore::new(MAX_DNS_CLIENTS));
    let mut bytes = vec![0; terra_protocol::socket::MAX_DNS_BYTES + 1];
    loop {
        let (length, peer) = socket.recv_from(&mut bytes).await?;
        if length > terra_protocol::socket::MAX_DNS_BYTES {
            continue;
        }
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let query = bytes[..length].to_vec();
        let client = client.clone();
        let socket = socket.clone();
        spawn_admitted(&tasks, &shutdown, permit, async move {
            if let Ok(response) = resolve_dns(&client, DnsTransport::Datagram, query).await {
                let _ = socket.send_to(&response, peer).await;
            }
        });
    }
}

async fn serve_tcp_dns(
    tasks: TaskTracker,
    listener: TcpListener,
    client: Arc<NetworkClient>,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_DNS_CLIENTS));
    loop {
        let (stream, _peer) = listener.accept().await?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let client = client.clone();
        spawn_admitted(&tasks, &shutdown, permit, async move {
            serve_dns_stream(stream, &client).await
        });
    }
}

async fn serve_dns_stream(mut stream: TcpStream, client: &NetworkClient) -> io::Result<()> {
    loop {
        let Some(query) = tokio::time::timeout(DNS_TIMEOUT, read_dns_query(&mut stream)).await??
        else {
            return Ok(());
        };
        let response = resolve_dns(client, DnsTransport::Stream, query).await?;
        let length = u16::try_from(response.len())
            .map_err(|_| io::Error::other("DNS response exceeds a stream's length prefix"))?;
        let mut framed = length.to_be_bytes().to_vec();
        framed.extend_from_slice(&response);
        tokio::time::timeout(DNS_TIMEOUT, stream.write_all(&framed)).await??;
    }
}

async fn read_dns_query(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
) -> io::Result<Option<Vec<u8>>> {
    let mut prefix = [0; 2];
    if reader.read(&mut prefix[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut prefix[1..]).await?;
    let length = usize::from(u16::from_be_bytes(prefix));
    if length > terra_protocol::socket::MAX_DNS_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS query exceeds its size limit",
        ));
    }
    let mut query = vec![0; length];
    reader.read_exact(&mut query).await?;
    Ok(Some(query))
}

async fn serve_publications(
    tasks: TaskTracker,
    listener: tokio::io::unix::AsyncFd<File>,
    tcp_ports: Vec<u16>,
    udp_ports: Vec<u16>,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_PUBLICATION_CARRIERS));
    let grants = Arc::new(PublicationGrants::new(tcp_ports, udp_ports));
    loop {
        let permit = slots
            .clone()
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        let carrier = listener
            .async_io(tokio::io::Interest::READABLE, |listener| {
                rustix::net::accept_with(listener, rustix::net::SocketFlags::CLOEXEC)
                    .map_err(io::Error::from)
            })
            .await?;
        let carrier = VsockStream::new(carrier)?;
        let grants = grants.clone();
        spawn_admitted(&tasks, &shutdown, permit, async move {
            relay_publication(carrier, &grants).await
        });
    }
}

async fn read_publication_header(
    carrier: &mut (impl AsyncRead + Unpin),
) -> io::Result<Publication> {
    terra_protocol::read_frame_async(carrier)
        .await?
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
}

async fn connect_published_service(guest_port: u16) -> io::Result<TcpStream> {
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::from((RELAY_SOURCE, 0)))?;
    socket
        .connect(SocketAddr::from((PUBLISHED_DESTINATION, guest_port)))
        .await
}

async fn copy_publication_bytes(
    service: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    carrier: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
) -> io::Result<()> {
    tokio::io::copy_bidirectional_with_sizes(
        service,
        carrier,
        terra_protocol::vsock::FLOW_UPSTREAM_BYTES,
        terra_protocol::vsock::FLOW_REPLY_BYTES,
    )
    .await
    .map(|_| ())
}

async fn relay_publication(
    mut carrier: impl AsyncRead + AsyncWrite + Unpin,
    grants: &PublicationGrants,
) -> io::Result<()> {
    let deadline = Instant::now() + PUBLICATION_TIMEOUT;
    match tokio::time::timeout_at(deadline, read_publication_header(&mut carrier)).await?? {
        Publication::Tcp { guest_port } => {
            let guest_port = guest_port.get();
            let _permit = grants.tcp.admit(guest_port)?;
            let mut service =
                tokio::time::timeout_at(deadline, connect_published_service(guest_port)).await??;
            copy_publication_bytes(&mut service, &mut carrier).await
        }
        Publication::Udp { guest_port } => {
            let guest_port = guest_port.get();
            let _permit = grants.udp.admit(guest_port)?;
            relay_udp_publication(
                carrier,
                RELAY_SOURCE,
                SocketAddr::from((PUBLISHED_DESTINATION, guest_port)),
            )
            .await
        }
    }
}

async fn wait_udp_publication_reply(
    peers: &VecDeque<UdpPublicationPeer>,
    next_reply: usize,
) -> (usize, io::Result<()>) {
    let mut readiness: FuturesUnordered<_> = peers
        .iter()
        .enumerate()
        .cycle()
        .skip(next_reply)
        .take(peers.len())
        .map(|(index, entry)| async move { (index, entry.socket.readable().await) })
        .collect();
    if let Some(reply) = readiness.next().await {
        reply
    } else {
        std::future::pending().await
    }
}

async fn connect_published_udp_service(
    source: Ipv4Addr,
    destination: SocketAddr,
) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind((source, 0)).await?;
    rustix::net::sockopt::set_socket_recv_buffer_size(
        &socket,
        terra_protocol::application::MAX_FRAME_BYTES,
    )?;
    rustix::net::sockopt::set_socket_send_buffer_size(
        &socket,
        terra_protocol::application::MAX_FRAME_BYTES,
    )?;
    socket.connect(destination).await?;
    Ok(socket)
}

async fn send_publication_datagrams(
    socket: &UdpSocket,
    segment: u16,
    bytes: &[u8],
) -> io::Result<()> {
    if segment == 0 {
        return socket.send(bytes).await.map(drop);
    }
    for datagram in bytes.chunks(usize::from(segment)) {
        socket.send(datagram).await?;
    }
    Ok(())
}

/// Reusable buffers that turn the replies queued on a publication socket into `UdpSend` frames.
struct ReplyBuffers {
    datagram: [u8; terra_protocol::network::MAX_NETWORK_DATAGRAM_BYTES + 1],
    run: Vec<u8>,
    frames: Vec<u8>,
}

impl ReplyBuffers {
    const fn new() -> Self {
        Self {
            datagram: [0; terra_protocol::network::MAX_NETWORK_DATAGRAM_BYTES + 1],
            run: Vec::new(),
            frames: Vec::new(),
        }
    }
}

/// Frames up to `MAX_DATAGRAM_SEGMENTS` replies already queued on one publication socket into
/// `buffers.frames`, merging equal-size datagrams that end in at most one shorter one into a
/// segmented frame as UDP GRO would.
fn read_publication_replies(
    socket: &UdpSocket,
    peer: SocketAddr,
    buffers: &mut ReplyBuffers,
) -> io::Result<()> {
    fn finish_run(
        frames: &mut Vec<u8>,
        peer: SocketAddr,
        run: &mut Vec<u8>,
        segment: &mut usize,
    ) -> io::Result<()> {
        let lent = UdpRun {
            peer,
            segment: u16::try_from(*segment).unwrap_or(0),
            bytes: run.as_slice(),
        };
        terra_protocol::application::append_udp_send(frames, lent).map_err(io::Error::other)?;
        run.clear();
        *segment = 0;
        Ok(())
    }
    let ReplyBuffers {
        datagram,
        run,
        frames,
    } = buffers;
    run.clear();
    frames.clear();
    let mut segment = 0;
    for _ in 0..terra_protocol::application::MAX_DATAGRAM_SEGMENTS {
        let length = match socket.try_recv(datagram) {
            Ok(length) => length,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if frames.is_empty() && run.is_empty() => return Err(error),
            Err(_) => break,
        };
        if length > terra_protocol::network::MAX_NETWORK_DATAGRAM_BYTES {
            continue;
        }
        if !terra_protocol::application::extends_udp_run(run.len(), segment, length) {
            if segment != 0 {
                finish_run(frames, peer, run, &mut segment)?;
            }
            segment = length;
        }
        run.extend_from_slice(&datagram[..length]);
        if length == 0 || length < segment {
            finish_run(frames, peer, run, &mut segment)?;
        }
    }
    if segment != 0 {
        finish_run(frames, peer, run, &mut segment)?;
    }
    Ok(())
}

async fn relay_udp_publication(
    mut carrier: impl AsyncRead + AsyncWrite + Unpin,
    source: Ipv4Addr,
    destination: SocketAddr,
) -> io::Result<()> {
    let mut decoder = StreamDecoder::default();
    let mut peers: VecDeque<UdpPublicationPeer> = VecDeque::new();
    let mut replies = ReplyBuffers::new();
    let mut next_reply = 0;
    loop {
        let now = Instant::now();
        peers.retain(|entry| entry.expires > now);
        let expires = peers
            .iter()
            .map(|entry| entry.expires)
            .min()
            .unwrap_or(now + UDP_PEER_TTL);
        tokio::select! {
            read = read_into_decoder(&mut carrier, &mut decoder) => {
                if !read? {
                    return Ok(());
                }
                forward_host_frames(&mut decoder, &mut peers, source, destination).await?;
            }
            (index, ready) = wait_udp_publication_reply(&peers, next_reply) => {
                next_reply = (index + 1) % peers.len();
                forward_peer_replies(&mut carrier, &mut peers, index, ready, &mut replies).await?;
            }
            () = tokio::time::sleep_until(expires), if !peers.is_empty() => {}
        }
    }
}

/// Forwards every whole frame `decoder` holds, sending datagram runs straight from its buffer.
async fn forward_host_frames(
    decoder: &mut StreamDecoder,
    peers: &mut VecDeque<UdpPublicationPeer>,
    source: Ipv4Addr,
    destination: SocketAddr,
) -> io::Result<()> {
    loop {
        let frame = decoder
            .next_lent_frame::<HostFrame>()
            .map_err(io::Error::other)?;
        match frame {
            None => return Ok(()),
            Some(LentFrame::UdpRun(run)) => {
                forward_host_datagram(peers, run.peer, run.segment, run.bytes, source, destination)
                    .await?;
            }
            Some(LentFrame::Frame(HostFrame::UdpError { .. })) => {}
            Some(LentFrame::Frame(HostFrame::Opened(_) | HostFrame::UdpDatagram(_))) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected UDP publication message",
                ));
            }
        }
    }
}

/// Sends a host datagram on `peer`'s socket, opening one for a new peer and renewing its grant.
async fn forward_host_datagram(
    peers: &mut VecDeque<UdpPublicationPeer>,
    peer: SocketAddr,
    segment: u16,
    bytes: &[u8],
    source: Ipv4Addr,
    destination: SocketAddr,
) -> io::Result<()> {
    let known = peers
        .iter()
        .position(|entry| entry.peer == peer)
        .and_then(|index| peers.remove(index));
    let socket = if let Some(entry) = known {
        entry.socket
    } else {
        if peers.len() == terra_protocol::network::MAX_UDP_PUBLICATION_PEERS {
            peers.pop_front();
        }
        connect_published_udp_service(source, destination).await?
    };
    if send_publication_datagrams(&socket, segment, bytes)
        .await
        .is_ok()
    {
        peers.push_back(UdpPublicationPeer {
            peer,
            socket,
            expires: Instant::now() + UDP_PEER_TTL,
        });
    }
    Ok(())
}

/// Sends the replies queued on one peer's socket to the host; a socket that failed drops its peer.
async fn forward_peer_replies(
    carrier: &mut (impl AsyncWrite + Unpin),
    peers: &mut VecDeque<UdpPublicationPeer>,
    index: usize,
    ready: io::Result<()>,
    replies: &mut ReplyBuffers,
) -> io::Result<()> {
    let entry = peers
        .get(index)
        .ok_or_else(|| io::Error::other("missing UDP publication peer"))?;
    if entry.expires <= Instant::now() {
        return Ok(());
    }
    match ready.and_then(|()| read_publication_replies(&entry.socket, entry.peer, replies)) {
        Ok(()) if !replies.frames.is_empty() => {
            carrier.write_all(&replies.frames).await?;
            carrier.flush().await?;
        }
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(_) => {
            peers.remove(index);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use std::num::NonZeroU16;
    use terra_protocol::application::{Frame as _, GuestFrame};

    /// A frame other than a datagram, split across reads, makes forwarding return for more bytes;
    /// it would spin forever if the incomplete frame looked like nothing to do. The forwarding
    /// runs on its own thread so a regression fails here instead of hanging the suite.
    #[test]
    fn forwarding_returns_for_the_rest_of_a_split_error_frame() {
        let error = HostFrame::UdpError {
            peer: "192.0.2.1:9".parse().unwrap(),
            error: terra_protocol::socket::Error::Closed,
        }
        .encode()
        .unwrap();
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut decoder = StreamDecoder::default();
            let partial = &error[..error.len() - 1];
            decoder.read_buffer()[..partial.len()].copy_from_slice(partial);
            decoder.commit(partial.len());
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let forwarded = runtime.block_on(forward_host_frames(
                &mut decoder,
                &mut VecDeque::new(),
                Ipv4Addr::LOCALHOST,
                "127.0.0.1:9".parse().unwrap(),
            ));
            done.send((forwarded.is_ok(), decoder.is_empty())).unwrap();
        });
        assert_eq!(
            finished.recv_timeout(Duration::from_secs(10)),
            Ok((true, false)),
            "forwarding must return and keep the partial frame"
        );
    }

    #[tokio::test]
    async fn dns_tcp_framing_bounds_and_strips_the_length_prefix() {
        assert_eq!(
            read_dns_query(&mut &b"\0\x03abc"[..]).await.unwrap(),
            Some(b"abc".to_vec())
        );
        assert_eq!(read_dns_query(&mut &b""[..]).await.unwrap(), None);
        for query in [&b"\0"[..], &b"\0\x03ab"[..], &b"\x10\x01"[..]] {
            assert!(read_dns_query(&mut &query[..]).await.is_err());
        }
    }

    #[test]
    #[ignore = "requires Linux AF_VSOCK socket creation"]
    fn native_vsock_buffers_match_their_network_endpoint_budgets() {
        for bytes in [
            terra_protocol::vsock::FLOW_REPLY_BYTES,
            terra_protocol::vsock::CONTROL_REPLY_BYTES,
        ] {
            limit_vsock_buffer_bytes(crate::mux::create_vsock_socket().unwrap(), bytes).unwrap();
        }
    }

    /// UDP publication keeps the preexisting 1024-FD allowance plus 64 carriers and 16 peer sockets per carrier, without raising the hard limit or lowering larger soft limits.
    #[test]
    fn udp_publication_file_limit_covers_full_capacity() {
        use rustix::process::Rlimit;
        assert_eq!(
            reserve_udp_publication_files(Rlimit {
                current: Some(1024),
                maximum: Some(4096),
            })
            .unwrap(),
            Rlimit {
                current: Some(2112),
                maximum: Some(4096)
            },
        );
        for current in [None, Some(2112), Some(4096)] {
            let limits = Rlimit {
                current,
                maximum: Some(4096),
            };
            assert_eq!(reserve_udp_publication_files(limits).unwrap(), limits);
        }
        assert_eq!(
            reserve_udp_publication_files(Rlimit {
                current: Some(1024),
                maximum: None,
            })
            .unwrap()
            .current,
            Some(2112)
        );
        let error = reserve_udp_publication_files(Rlimit {
            current: Some(1024),
            maximum: Some(2111),
        })
        .unwrap_err();
        assert!(error.to_string().contains("hard limit of at least 2112"));
    }

    struct TestNetwork {
        client: Arc<NetworkClient>,
        host: tokio::io::DuplexStream,
        receiver: tokio::task::JoinHandle<io::Error>,
    }

    fn start_test_network() -> TestNetwork {
        let (guest, host) = tokio::io::duplex(64 * 1024);
        let (reader, writer) = tokio::io::split(guest);
        let client = NetworkClient::new(writer, CancellationToken::new());
        let receiver = tokio::spawn(receive_results(reader, client.clone()));
        TestNetwork {
            client,
            host,
            receiver,
        }
    }

    async fn read_host_message(host: &mut tokio::io::DuplexStream) -> AgentControl {
        terra_protocol::read_frame_async(host)
            .await
            .unwrap()
            .unwrap()
    }

    /// Reads one kernel-layout frame without reading past it.
    async fn read_guest_frame(host: &mut tokio::io::DuplexStream) -> GuestFrame {
        use terra_protocol::application::HEADER_BYTES;
        let mut header = [0; HEADER_BYTES];
        host.read_exact(&mut header).await.unwrap();
        let mut frame = header.to_vec();
        frame.resize(terra_protocol::application::frame_len(header).unwrap(), 0);
        host.read_exact(&mut frame[HEADER_BYTES..]).await.unwrap();
        GuestFrame::decode(&frame).unwrap().unwrap().0
    }

    /// Saturated UDP DNS keeps at most sixteen tracked clients and cancellation releases every query.
    #[tokio::test]
    async fn udp_dns_bounds_clients_and_cancels_pending_queries() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut network = start_test_network();
            let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let address = listener.local_addr().unwrap();
            let requester = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let shutdown = CancellationToken::new();
            let tasks = TaskTracker::new();
            let server = tokio::spawn({
                let client = network.client.clone();
                let shutdown = shutdown.clone();
                let tasks = tasks.clone();
                async move {
                    shutdown
                        .run_until_cancelled(serve_udp_dns(
                            tasks,
                            listener,
                            client,
                            shutdown.clone(),
                        ))
                        .await
                }
            });
            for _ in 0..MAX_DNS_CLIENTS {
                requester.send_to(&[0; 12], address).await.unwrap();
                assert_matches!(
                    read_host_message(&mut network.host).await,
                    AgentControl::DnsQuery(_)
                );
            }
            assert_eq!(tasks.len(), MAX_DNS_CLIENTS);
            for _ in 0..MAX_DNS_CLIENTS {
                requester.send_to(&[0; 12], address).await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert_eq!(tasks.len(), MAX_DNS_CLIENTS);
            shutdown.cancel();
            tasks.close();
            tasks.wait().await;
            assert!(server.await.unwrap().is_none());
            assert!(network.client.pending.lock().unwrap().is_empty());
            drop(network.host);
            network.receiver.await.unwrap();
        })
        .await
        .unwrap();
    }

    /// Concurrent DNS answers are matched by query identity, not arrival order.
    #[tokio::test]
    async fn dns_results_match_their_queries_out_of_order() {
        let mut network = start_test_network();
        let first = tokio::spawn({
            let client = network.client.clone();
            async move { client.query(DnsTransport::Datagram, vec![1; 12]).await }
        });
        let AgentControl::DnsQuery(DnsPayload { id: first_id, .. }) =
            read_host_message(&mut network.host).await
        else {
            panic!("expected a DNS query");
        };
        let second = tokio::spawn({
            let client = network.client.clone();
            async move { client.query(DnsTransport::Datagram, vec![2; 12]).await }
        });
        let AgentControl::DnsQuery(DnsPayload { id: second_id, .. }) =
            read_host_message(&mut network.host).await
        else {
            panic!("expected a DNS query");
        };
        for (id, byte) in [(second_id, 2), (first_id, 1)] {
            let reply = FrontendControl::DnsResult(DnsPayload {
                id,
                transport: DnsTransport::Datagram,
                bytes: vec![byte; 12],
            });
            network
                .host
                .write_all(&terra_protocol::encode_frame(&reply).unwrap())
                .await
                .unwrap();
        }
        assert_eq!(first.await.unwrap().unwrap(), vec![1; 12]);
        assert_eq!(second.await.unwrap().unwrap(), vec![2; 12]);
        assert!(network.client.pending.lock().unwrap().is_empty());
    }

    /// Cancelling a partially written control frame retires networking before another frame can follow it.
    #[tokio::test]
    async fn interrupted_control_write_disables_only_networking() {
        let parent = CancellationToken::new();
        let shutdown = parent.child_token();
        let (guest, mut host) = tokio::io::duplex(1);
        let (_reader, writer) = tokio::io::split(guest);
        let client = NetworkClient::new(writer, shutdown.clone());
        let query = tokio::spawn({
            let client = client.clone();
            async move { client.query(DnsTransport::Datagram, vec![1; 12]).await }
        });
        host.read_exact(&mut [0; 1]).await.unwrap();
        query.abort();
        assert!(query.await.unwrap_err().is_cancelled());
        assert!(shutdown.is_cancelled());
        assert!(!parent.is_cancelled());
        assert_eq!(
            client
                .send(&AgentControl::Hello)
                .await
                .unwrap_err()
                .raw_os_error(),
            Some(rustix::io::Errno::NETDOWN.raw_os_error())
        );
        assert!(client.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn exhausted_dns_query_identifiers_are_never_reused() {
        let network = start_test_network();
        network.client.next_id.store(u32::MAX, Ordering::Relaxed);
        assert!(
            network
                .client
                .query(DnsTransport::Datagram, vec![1; 12])
                .await
                .is_err()
        );
        assert_eq!(network.client.next_id.load(Ordering::Relaxed), u32::MAX);
        assert!(network.client.pending.lock().unwrap().is_empty());
        drop(network.host);
        network.receiver.await.unwrap();
    }

    /// Losing the control stream fails pending queries and reports networking as down.
    #[tokio::test]
    async fn control_loss_releases_queries_and_reports_network_down() {
        let mut network = start_test_network();
        let query = tokio::spawn({
            let client = network.client.clone();
            async move { client.query(DnsTransport::Stream, vec![0, 1, 7]).await }
        });
        read_host_message(&mut network.host).await;
        drop(network.host);
        let error = network.receiver.await.unwrap();
        assert_eq!(
            error.raw_os_error(),
            Some(rustix::io::Errno::NETDOWN.raw_os_error())
        );
        assert!(query.await.unwrap().is_err());
        assert!(network.client.pending.lock().unwrap().is_empty());
    }

    /// Network failures preserve the DNS transaction and question for UDP and TCP clients.
    #[tokio::test]
    async fn unanswered_dns_returns_servfail() {
        let network = start_test_network();
        drop(network.host);
        network.receiver.await.unwrap();
        let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x01a\0\0\x01\0\x01";
        let expected =
            terra_protocol::dns::error_response(query, terra_protocol::dns::Rcode::ServFail);
        for transport in [DnsTransport::Datagram, DnsTransport::Stream] {
            assert_eq!(
                resolve_dns(&network.client, transport, query.to_vec())
                    .await
                    .unwrap(),
                expected
            );
        }
        assert!(network.client.pending.lock().unwrap().is_empty());
    }

    /// A failed helper cancels only network services; normal shutdown emits no failure.
    #[tokio::test]
    async fn network_service_failure_preserves_parent() {
        use std::os::fd::OwnedFd;
        let parent = CancellationToken::new();
        let shutdown = parent.child_token();
        let (diagnostic, host_diagnostic) = std::os::unix::net::UnixStream::pair().unwrap();
        let diagnostic = Diagnostics::new(File::from(OwnedFd::from(diagnostic))).unwrap();
        run_network_service(
            "test",
            std::future::ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
            &shutdown,
            &diagnostic,
        )
        .await;
        assert!(shutdown.is_cancelled());
        assert!(!parent.is_cancelled());
        let mut diagnostics = host_diagnostic.try_clone().unwrap();
        diagnostic.finish().await;
        let Some(terra_protocol::LifecycleEvent::Diagnostic { bytes }) =
            terra_protocol::read_frame(&mut diagnostics).unwrap()
        else {
            panic!("network failure diagnostic missing");
        };
        assert!(
            String::from_utf8(bytes)
                .unwrap()
                .contains("network unavailable: test")
        );
    }

    /// The publication header is consumed exactly; raw bytes behind it stay for the relay.
    #[tokio::test]
    async fn publication_header_leaves_raw_bytes_unread() {
        let header = |publication| terra_protocol::encode_frame(&publication).unwrap();
        let guest_port = NonZeroU16::new(8080).unwrap();
        let mut bytes = header(Publication::Tcp { guest_port });
        bytes.extend_from_slice(b"GET /");
        let mut carrier = &bytes[..];
        assert_eq!(
            read_publication_header(&mut carrier).await.unwrap(),
            Publication::Tcp { guest_port }
        );
        assert_eq!(carrier, b"GET /");
        let datagram = HostFrame::UdpDatagram(UdpRun {
            segment: 0,
            peer: "203.0.113.9:40000".parse().unwrap(),
            bytes: b"udp".to_vec(),
        })
        .encode()
        .unwrap();
        let guest_port = NonZeroU16::new(5353).unwrap();
        let mut bytes = header(Publication::Udp { guest_port });
        bytes.extend_from_slice(&datagram);
        let mut carrier = &bytes[..];
        assert_eq!(
            read_publication_header(&mut carrier).await.unwrap(),
            Publication::Udp { guest_port }
        );
        assert_eq!(carrier, datagram);
        let wrong = terra_protocol::encode_frame(&FrontendControl::Ready).unwrap();
        assert!(read_publication_header(&mut &wrong[..]).await.is_err());
        let oversized =
            u32::try_from(<Publication as terra_protocol::Message>::MAX_PAYLOAD_BYTES + 1)
                .unwrap()
                .to_le_bytes();
        assert_eq!(
            read_publication_header(&mut &oversized[..])
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    /// Each raw publication direction drains accepted bytes before half-close and keeps the reverse direction alive.
    #[tokio::test]
    async fn publication_drains_bytes_and_preserves_half_close() {
        let (mut service, mut guest_client) = tokio::io::duplex(37);
        let (mut carrier, mut host_client) = tokio::io::duplex(41);
        let relay =
            tokio::spawn(async move { copy_publication_bytes(&mut service, &mut carrier).await });
        let service_bytes = vec![0x17; 65 * 1024];
        let host_bytes = vec![0x93; 97 * 1024];
        let guest_expected = host_bytes.clone();
        let host_expected = service_bytes.clone();
        let guest = tokio::spawn(async move {
            guest_client.write_all(&service_bytes).await.unwrap();
            guest_client.shutdown().await.unwrap();
            let mut response = Vec::new();
            guest_client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, guest_expected);
        });
        let host = tokio::spawn(async move {
            let mut request = Vec::new();
            host_client.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, host_expected);
            host_client.write_all(&host_bytes).await.unwrap();
            host_client.shutdown().await.unwrap();
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            guest.await.unwrap();
            host.await.unwrap();
            relay.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    /// TCP and UDP grants are independent, and all 64 UDP family streams retain TCP capacity.
    #[tokio::test]
    async fn publication_admission_reserves_each_protocol() {
        let grants = Arc::new(PublicationGrants::new(vec![8080], vec![5353]));
        for message in [
            Publication::Udp {
                guest_port: NonZeroU16::new(8080).unwrap(),
            },
            Publication::Tcp {
                guest_port: NonZeroU16::new(5353).unwrap(),
            },
        ] {
            let (guest, mut host) = tokio::io::duplex(64);
            host.write_all(&terra_protocol::encode_frame(&message).unwrap())
                .await
                .unwrap();
            assert_eq!(
                relay_publication(guest, &grants).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        let mut hosts = Vec::new();
        let mut workers = Vec::new();
        let tasks = TaskTracker::new();
        let shutdown = CancellationToken::new();
        for _ in 0..2 * terra_protocol::MAX_PUBLISHED_PORTS {
            let (guest, mut host) = tokio::io::duplex(64);
            host.write_all(
                &terra_protocol::encode_frame(&Publication::Udp {
                    guest_port: NonZeroU16::new(5353).unwrap(),
                })
                .unwrap(),
            )
            .await
            .unwrap();
            hosts.push(host);
            let grants = grants.clone();
            let shutdown = shutdown.clone();
            workers.push(tasks.spawn(async move {
                assert!(
                    shutdown
                        .run_until_cancelled(relay_publication(guest, &grants))
                        .await
                        .is_none()
                );
            }));
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while grants.udp.slots.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            grants.tcp.slots.available_permits(),
            MAX_TCP_PUBLICATION_CLIENTS
        );
        assert_eq!(tasks.len(), 2 * terra_protocol::MAX_PUBLISHED_PORTS);
        shutdown.cancel();
        tasks.close();
        tasks.wait().await;
        for worker in workers {
            worker.await.unwrap();
        }
        assert_eq!(
            grants.udp.slots.available_permits(),
            2 * terra_protocol::MAX_PUBLISHED_PORTS
        );
        drop(hosts);
    }

    struct TestUdpPublication {
        host: tokio::io::DuplexStream,
        service: UdpSocket,
        relay: tokio::task::JoinHandle<Option<io::Result<()>>>,
        shutdown: CancellationToken,
    }

    impl TestUdpPublication {
        async fn new() -> Self {
            let service = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let destination = service.local_addr().unwrap();
            let (guest, host) = tokio::io::duplex(73);
            let shutdown = CancellationToken::new();
            let relay = tokio::spawn({
                let shutdown = shutdown.clone();
                async move {
                    shutdown
                        .run_until_cancelled(relay_udp_publication(
                            guest,
                            Ipv4Addr::LOCALHOST,
                            destination,
                        ))
                        .await
                }
            });
            Self {
                host,
                service,
                relay,
                shutdown,
            }
        }

        async fn send(&mut self, peer: SocketAddr, bytes: &[u8]) -> SocketAddr {
            self.host
                .write_all(
                    &HostFrame::UdpDatagram(UdpRun {
                        segment: 0,
                        peer,
                        bytes: bytes.to_vec(),
                    })
                    .encode()
                    .unwrap(),
                )
                .await
                .unwrap();
            let mut received = [0; terra_protocol::network::MAX_NETWORK_DATAGRAM_BYTES + 1];
            let (length, source) = self.service.recv_from(&mut received).await.unwrap();
            assert_eq!(&received[..length], bytes);
            source
        }
    }

    /// Split frames, empty/max datagrams and IPv4/IPv6 peer identities survive the native relay; oversize and unrelated replies do not.
    #[tokio::test]
    async fn udp_publication_preserves_datagrams_and_filters_service_replies() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut publication = TestUdpPublication::new().await;
            let ipv4: SocketAddr = "203.0.113.9:40000".parse().unwrap();
            let ipv6: SocketAddr = "[2001:db8::9]:40001".parse().unwrap();
            let mut coalesced = HostFrame::UdpDatagram(UdpRun {
                segment: 0,
                peer: ipv4,
                bytes: b"\0binary\xff".to_vec(),
            })
            .encode()
            .unwrap();
            coalesced.extend_from_slice(
                &HostFrame::UdpDatagram(UdpRun {
                    segment: 0,
                    peer: ipv6,
                    bytes: Vec::new(),
                })
                .encode()
                .unwrap(),
            );
            publication.host.write_all(&coalesced).await.unwrap();
            let mut request = [0; 32];
            let (length, first) = publication.service.recv_from(&mut request).await.unwrap();
            assert_eq!(&request[..length], b"\0binary\xff");
            let (length, second) = publication.service.recv_from(&mut request).await.unwrap();
            assert_eq!(length, 0);
            assert_ne!(first, second);
            for (peer, source, bytes) in [
                (ipv6, second, Vec::new()),
                (
                    ipv4,
                    first,
                    vec![0x93; terra_protocol::network::MAX_NETWORK_DATAGRAM_BYTES],
                ),
            ] {
                publication.service.send_to(&bytes, source).await.unwrap();
                assert_eq!(
                    read_guest_frame(&mut publication.host).await,
                    GuestFrame::UdpSend(UdpRun {
                        segment: 0,
                        peer,
                        bytes
                    })
                );
            }
            let maximum = vec![0x41; terra_protocol::network::MAX_NETWORK_DATAGRAM_BYTES];
            assert_eq!(publication.send(ipv4, &maximum).await, first);
            let stranger = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            stranger.send_to(b"unrelated", first).await.unwrap();
            publication
                .service
                .send_to(
                    &vec![0; terra_protocol::network::MAX_NETWORK_DATAGRAM_BYTES + 1],
                    first,
                )
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(20),
                    publication.host.read(&mut [0; 1])
                )
                .await
                .is_err()
            );
            publication
                .host
                .write_all(
                    &HostFrame::UdpError {
                        peer: ipv4,
                        error: terra_protocol::socket::Error::AccessDenied,
                    }
                    .encode()
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(publication.send(ipv4, b"still live").await, first);
            publication.service.send_to(b"reply", first).await.unwrap();
            assert_eq!(
                read_guest_frame(&mut publication.host).await,
                GuestFrame::UdpSend(UdpRun {
                    segment: 0,
                    peer: ipv4,
                    bytes: b"reply".to_vec()
                })
            );
            publication.host.shutdown().await.unwrap();
            publication.relay.await.unwrap().unwrap().unwrap();
            assert!(std::net::UdpSocket::bind(first).is_ok());
            assert!(std::net::UdpSocket::bind(second).is_ok());
        })
        .await
        .unwrap();
    }

    /// A segmented host frame reaches the service as separate datagrams, and queued service replies
    /// return as runs of equal-size datagrams ending at most one shorter one; an empty or longer
    /// reply ends the run.
    #[tokio::test]
    async fn udp_publication_carries_datagram_runs_both_ways() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut publication = TestUdpPublication::new().await;
            let peer: SocketAddr = "203.0.113.9:40000".parse().unwrap();
            let run: Vec<u8> = (0..2500_u32).map(|index| (index % 251) as u8).collect();
            publication
                .host
                .write_all(
                    &HostFrame::UdpDatagram(UdpRun {
                        peer,
                        segment: 1000,
                        bytes: run.clone(),
                    })
                    .encode()
                    .unwrap(),
                )
                .await
                .unwrap();
            let mut received = [0; 2000];
            let mut source = None;
            for expected in run.chunks(1000) {
                let (length, from) = publication.service.recv_from(&mut received).await.unwrap();
                assert_eq!(&received[..length], expected);
                source = Some(from);
            }
            let source = source.unwrap();
            for datagram in [
                &run[..1000],
                &run[1000..2000],
                &[],
                &run[..300],
                &run[300..600],
                &run[..400],
                &run[..7],
            ] {
                publication.service.try_send_to(datagram, source).unwrap();
            }
            for expected in [
                GuestFrame::UdpSend(UdpRun {
                    peer,
                    segment: 1000,
                    bytes: run[..2000].to_vec(),
                }),
                GuestFrame::UdpSend(UdpRun {
                    segment: 0,
                    peer,
                    bytes: Vec::new(),
                }),
                GuestFrame::UdpSend(UdpRun {
                    peer,
                    segment: 300,
                    bytes: run[..600].to_vec(),
                }),
                GuestFrame::UdpSend(UdpRun {
                    peer,
                    segment: 400,
                    bytes: [&run[..400], &run[..7]].concat(),
                }),
            ] {
                assert_eq!(read_guest_frame(&mut publication.host).await, expected);
            }
        })
        .await
        .unwrap();
    }

    /// The seventeenth peer retires the oldest inbound mapping; cancellation releases all sixteen native sockets.
    #[tokio::test]
    async fn udp_publication_bounds_peers_and_releases_sockets_on_cancel() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut publication = TestUdpPublication::new().await;
            let mut sources = VecDeque::new();
            for port in
                1..=u16::try_from(terra_protocol::network::MAX_UDP_PUBLICATION_PEERS + 1).unwrap()
            {
                let peer = SocketAddr::from(([203, 0, 113, 9], port));
                let source = publication.send(peer, &port.to_le_bytes()).await;
                if sources.len() == terra_protocol::network::MAX_UDP_PUBLICATION_PEERS {
                    let oldest = sources.pop_front().unwrap();
                    assert!(std::net::UdpSocket::bind(oldest).is_ok());
                }
                assert!(!sources.contains(&source));
                assert!(std::net::UdpSocket::bind(source).is_err());
                sources.push_back(source);
            }
            publication.shutdown.cancel();
            assert!(publication.relay.await.unwrap().is_none());
            for source in sources {
                assert!(std::net::UdpSocket::bind(source).is_ok());
            }
        })
        .await
        .unwrap();
    }

    /// Service replies never extend the 60-second inbound grant, and expiry drops the native socket even while the stream stays open.
    #[tokio::test]
    async fn udp_publication_expires_after_last_inbound_datagram() {
        let mut publication = TestUdpPublication::new().await;
        let peer: SocketAddr = "203.0.113.9:40000".parse().unwrap();
        let source = publication.send(peer, b"first").await;
        tokio::time::pause();
        tokio::time::advance(UDP_PEER_TTL / 2).await;
        tokio::time::resume();
        publication.service.send_to(b"reply", source).await.unwrap();
        assert_eq!(
            read_guest_frame(&mut publication.host).await,
            GuestFrame::UdpSend(UdpRun {
                segment: 0,
                peer,
                bytes: b"reply".to_vec()
            })
        );
        tokio::time::pause();
        tokio::time::advance(UDP_PEER_TTL / 2 + Duration::from_secs(1)).await;
        let mut retired = None;
        for _ in 0..1000 {
            tokio::task::yield_now().await;
            if let Ok(socket) = std::net::UdpSocket::bind(source) {
                retired = Some(socket);
                break;
            }
        }
        let retired = retired.expect("the expired peer kept its native socket");
        tokio::time::resume();
        let replacement = publication.send(peer, b"replacement").await;
        assert_ne!(replacement, retired.local_addr().unwrap());
        publication
            .host
            .write_all(&HostFrame::Opened(Ok(())).encode().unwrap())
            .await
            .unwrap();
        assert_eq!(
            publication
                .relay
                .await
                .unwrap()
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(std::net::UdpSocket::bind(replacement).is_ok());
    }

    #[test]
    #[ignore = "requires Linux user and network namespace creation"]
    fn publication_preserves_distinct_peer_and_excludes_loopback_listener() {
        const CHILD: &str = "TERRA_PUBLICATION_NAMESPACE_TEST";
        if std::env::var_os(CHILD).is_none() {
            let (_crate, test_path) = std::any::type_name_of_val(
                &publication_preserves_distinct_peer_and_excludes_loopback_listener,
            )
            .split_once("::")
            .unwrap();
            let output = std::process::Command::new("unshare")
                .args(["--user", "--map-root-user", "--net"])
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", test_path, "--ignored"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.contains("1 passed"),
                "{stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        crate::loopback::enable().unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                crate::loopback::add_alias_address("lo:terra-dns", DNS_IPV4).unwrap();
                let _dns_udp = UdpSocket::bind(DNS_ADDRESS).await.unwrap();
                let _dns_tcp = TcpListener::bind(DNS_ADDRESS).await.unwrap();
                crate::loopback::configure_publication_addresses(&CancellationToken::new())
                    .await
                    .unwrap();
                let _published_udp = UdpSocket::bind((PUBLISHED_DESTINATION, 53)).await.unwrap();
                let listener = TcpListener::bind((PUBLISHED_DESTINATION, 53))
                    .await
                    .unwrap();
                let port = listener.local_addr().unwrap().port();
                let connection = connect_published_service(port).await.unwrap();
                let (_accepted, peer) = listener.accept().await.unwrap();
                assert_eq!(peer.ip(), std::net::IpAddr::V4(RELAY_SOURCE));
                assert_eq!(connection.local_addr().unwrap().ip(), peer.ip());
                drop(listener);
                let loopback = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
                assert!(
                    connect_published_service(loopback.local_addr().unwrap().port())
                        .await
                        .is_err()
                );
                assert_udp_publication_routes().await;
            });
    }

    async fn assert_udp_publication_routes() {
        let service = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
        let destination =
            SocketAddr::from((PUBLISHED_DESTINATION, service.local_addr().unwrap().port()));
        let peer_socket = connect_published_udp_service(RELAY_SOURCE, destination)
            .await
            .unwrap();
        assert_eq!(
            rustix::net::sockopt::socket_recv_buffer_size(&peer_socket).unwrap(),
            2 * terra_protocol::application::MAX_FRAME_BYTES
        );
        assert_eq!(
            rustix::net::sockopt::socket_send_buffer_size(&peer_socket).unwrap(),
            2 * terra_protocol::application::MAX_FRAME_BYTES
        );
        drop(peer_socket);
        let port = service.local_addr().unwrap().port();
        let (guest, mut host) = tokio::io::duplex(73);
        let relay = tokio::spawn(async move {
            relay_publication(guest, &PublicationGrants::new(Vec::new(), vec![port])).await
        });
        let mut datagrams = terra_protocol::encode_frame(&Publication::Udp {
            guest_port: NonZeroU16::new(port).unwrap(),
        })
        .unwrap();
        for peer in [
            "203.0.113.9:40000".parse().unwrap(),
            "[2001:db8::9]:40001".parse().unwrap(),
        ] {
            datagrams.extend_from_slice(
                &HostFrame::UdpDatagram(UdpRun {
                    segment: 0,
                    peer,
                    bytes: Vec::new(),
                })
                .encode()
                .unwrap(),
            );
        }
        host.write_all(&datagrams).await.unwrap();
        let (_, first) = service.recv_from(&mut [0; 1]).await.unwrap();
        let (_, second) = service.recv_from(&mut [0; 1]).await.unwrap();
        assert_eq!(first.ip(), std::net::IpAddr::V4(RELAY_SOURCE));
        assert_eq!(second.ip(), first.ip());
        assert_ne!(second, first);
        for (peer, source) in [
            ("203.0.113.9:40000".parse().unwrap(), first),
            ("[2001:db8::9]:40001".parse().unwrap(), second),
        ] {
            service.send_to(b"wildcard reply", source).await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), read_guest_frame(&mut host))
                    .await
                    .unwrap(),
                GuestFrame::UdpSend(UdpRun {
                    segment: 0,
                    peer,
                    bytes: b"wildcard reply".to_vec()
                })
            );
        }
        host.shutdown().await.unwrap();
        relay.await.unwrap().unwrap();

        let loopback = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let destination =
            SocketAddr::from((PUBLISHED_DESTINATION, loopback.local_addr().unwrap().port()));
        let excluded = connect_published_udp_service(RELAY_SOURCE, destination)
            .await
            .unwrap();
        excluded.send(b"not loopback").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), loopback.recv_from(&mut [0; 32]))
                .await
                .is_err()
        );
    }
}
