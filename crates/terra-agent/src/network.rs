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
use terra_protocol::application::{Direction, MAX_DNS_QUERIES, Message, StreamDecoder};
use terra_protocol::vsock::{CONTROL_PORT, GUEST_CID, HOST_CID, PUBLICATION_PORT};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{Mutex as AsyncMutex, Semaphore, oneshot};
use tokio::time::Instant;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub(super) const RELAY_SOURCE: Ipv4Addr = Ipv4Addr::new(169, 254, 96, 1);
pub(super) const PUBLISHED_DESTINATION: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 2);
const DNS_IPV4: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 53);
const DNS_ADDRESS: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(DNS_IPV4), 53);
const MAX_DNS_CLIENTS: usize = 16;
const MAX_TCP_PUBLICATION_CLIENTS: usize = 32;
const MAX_UDP_PUBLICATION_CLIENTS: usize = 2 * terra_protocol::MAX_PUBLISHED_PORTS;
/// Fits two descriptors per carrier inside [`BASE_AGENT_OPEN_FILES`].
const MAX_PUBLICATION_CARRIERS: usize = 128;
const BASE_AGENT_OPEN_FILES: usize = 1024;
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const PUBLICATION_TIMEOUT: Duration =
    Duration::from_secs(terra_protocol::application::OPEN_TIMEOUT_SECS);
const UDP_PEER_TTL: Duration = Duration::from_secs(terra_protocol::network::UDP_PEER_TTL_SECS);

type Writer = AsyncMutex<Pin<Box<dyn AsyncWrite + Send>>>;
type PendingQueries = Arc<Mutex<BTreeMap<u32, oneshot::Sender<Message>>>>;

struct PublicationGrants {
    tcp_ports: Vec<u16>,
    udp_ports: Vec<u16>,
    tcp_slots: Semaphore,
    udp_slots: Semaphore,
}

impl PublicationGrants {
    fn new(tcp_ports: Vec<u16>, udp_ports: Vec<u16>) -> Self {
        Self {
            tcp_ports,
            udp_ports,
            tcp_slots: Semaphore::new(MAX_TCP_PUBLICATION_CLIENTS),
            udp_slots: Semaphore::new(MAX_UDP_PUBLICATION_CLIENTS),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PublicationTarget {
    Tcp { guest_port: u16, peer: SocketAddr },
    Udp { guest_port: u16 },
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
            pending: Arc::default(),
            next_id: AtomicU32::new(1),
            queries: Semaphore::new(MAX_DNS_QUERIES),
            shutdown,
        })
    }

    async fn send(&self, message: &Message) -> io::Result<()> {
        let bytes = message.encode().map_err(io::Error::other)?;
        let mut writer = self.writer.lock().await;
        if self.shutdown.is_cancelled() {
            return Err(io::Error::from(rustix::io::Errno::NETDOWN));
        }
        let mut pending = PendingControlWrite {
            shutdown: &self.shutdown,
            complete: false,
        };
        writer.write_all(&bytes).await?;
        writer.flush().await?;
        pending.complete = true;
        Ok(())
    }

    /// Answer one DNS query; `Ok(None)` means the network did not answer within the deadline.
    async fn query(&self, stream: bool, bytes: Vec<u8>) -> io::Result<Option<Vec<u8>>> {
        let Ok(outcome) = tokio::time::timeout(DNS_TIMEOUT, async {
            let _permit = self.queries.acquire().await.map_err(io::Error::other)?;
            let id = self
                .next_id
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
                .map_err(|_| io::Error::other("DNS query identifiers exhausted"))?;
            let (sender, reply) = oneshot::channel();
            self.pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(id, sender);
            let _pending = PendingQuery {
                id,
                pending: self.pending.clone(),
            };
            self.send(&Message::DnsQuery { id, stream, bytes }).await?;
            match reply.await {
                Ok(Message::DnsResult {
                    stream: answered,
                    bytes,
                    ..
                }) if answered == stream => Ok(bytes),
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected DNS response",
                )),
                Err(_) => Err(io::Error::from(rustix::io::Errno::NETDOWN)),
            }
        })
        .await
        else {
            return Ok(None);
        };
        outcome.map(Some)
    }
}

struct PendingControlWrite<'a> {
    shutdown: &'a CancellationToken,
    complete: bool,
}

impl Drop for PendingControlWrite<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.shutdown.cancel();
        }
    }
}

struct PendingQuery {
    id: u32,
    pending: PendingQueries,
}

impl Drop for PendingQuery {
    fn drop(&mut self) {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
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
            rustix::net::shutdown(self.0.get_ref().get_ref(), rustix::net::Shutdown::Write)
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

fn vsock_socket(buffer_bytes: usize) -> io::Result<rustix::fd::OwnedFd> {
    let socket = rustix::net::socket_with(
        rustix::net::AddressFamily::VSOCK,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(io::Error::from)?;
    limit_vsock_buffer_bytes(&socket, buffer_bytes)?;
    Ok(socket)
}

fn connect_control() -> Result<VsockStream> {
    let socket = vsock_socket(terra_protocol::vsock::CONTROL_REPLY_BYTES)
        .context("creating the network control vsock")?;
    rustix::net::bind(&socket, &crate::mux::vsock_address(GUEST_CID, CONTROL_PORT))
        .context("binding the fixed guest network control endpoint")?;
    rustix::net::connect(&socket, &crate::mux::vsock_address(HOST_CID, CONTROL_PORT))
        .context("connecting the host network control endpoint")?;
    Ok(VsockStream::new(socket)?)
}

fn listen_publications() -> Result<async_io::Async<File>> {
    let socket = vsock_socket(terra_protocol::vsock::FLOW_REPLY_BYTES)
        .context("creating the publication vsock listener")?;
    rustix::net::bind(
        &socket,
        &crate::mux::vsock_address(GUEST_CID, PUBLICATION_PORT),
    )
    .context("binding the guest publication endpoint")?;
    rustix::net::listen(&socket, i32::try_from(MAX_PUBLICATION_CARRIERS)?)
        .context("listening for publication streams")?;
    Ok(async_io::Async::new(File::from(socket))?)
}

async fn read_message(
    reader: &mut (impl AsyncRead + Unpin),
    decoder: &mut StreamDecoder,
) -> io::Result<Option<Message>> {
    loop {
        if let Some(message) = decoder
            .next(Direction::HostToGuest)
            .map_err(io::Error::other)?
        {
            return Ok(Some(message));
        }
        let mut bytes = vec![0; decoder.remaining_capacity()];
        let count = reader.read(&mut bytes).await?;
        if count == 0 {
            return if decoder.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::from(io::ErrorKind::UnexpectedEof))
            };
        }
        decoder.push(&bytes[..count]).map_err(io::Error::other)?;
    }
}

/// Deliver DNS results until the control stream ends; any end of the stream means networking is gone.
async fn receive_results(
    mut reader: impl AsyncRead + Unpin,
    mut decoder: StreamDecoder,
    pending: PendingQueries,
) -> io::Error {
    let error = loop {
        match read_message(&mut reader, &mut decoder).await {
            Ok(Some(message @ Message::DnsResult { id, .. })) => {
                if let Some(sender) = pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&id)
                {
                    let _ = sender.send(message);
                }
            }
            Ok(Some(_)) => {
                break io::Error::new(io::ErrorKind::InvalidData, "unexpected control message");
            }
            Ok(None) | Err(_) => break io::Error::from(rustix::io::Errno::NETDOWN),
        }
    };
    pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    error
}

pub(super) fn validate_kernel_socket_version() -> Result<()> {
    let version = std::fs::read_to_string("/sys/kernel/terra_socket_abi")
        .context("reading kernel socket ABI; rebuild the kernel and guest together")?;
    validate_socket_version(
        version
            .trim()
            .parse()
            .context("invalid kernel socket ABI")?,
    )
}

fn reserve_udp_publication_files(
    mut limits: rustix::process::Rlimit,
) -> Result<rustix::process::Rlimit> {
    let minimum = u64::try_from(
        BASE_AGENT_OPEN_FILES
            + MAX_UDP_PUBLICATION_CLIENTS * (terra_protocol::network::MAX_UDP_PEERS + 1),
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

fn validate_socket_version(version: u16) -> Result<()> {
    ensure!(
        version == terra_protocol::socket::VERSION,
        "socket protocol version {version} is incompatible with guest version {}; rebuild the kernel, network component, and guest",
        terra_protocol::socket::VERSION
    );
    Ok(())
}

/// Exchange Hello/Ready on a fresh control stream and return the decoder holding any bytes after Ready.
async fn verify_network_version(
    client: &NetworkClient,
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<StreamDecoder> {
    let mut decoder = StreamDecoder::default();
    tokio::time::timeout(DNS_TIMEOUT, async {
        client.send(&Message::Hello).await?;
        match read_message(reader, &mut decoder).await? {
            Some(Message::Ready) => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "network returned an invalid readiness response",
            )),
        }
    })
    .await
    .context("network version handshake timed out")??;
    Ok(decoder)
}

pub(super) async fn start(
    plan: &terra_protocol::Plan,
    shutdown: &CancellationToken,
    tasks: &TaskTracker,
    diagnostic: &Diagnostics,
) -> Result<()> {
    validate_kernel_socket_version()?;
    match plan.net {
        terra_protocol::Net::LocalOnly => {
            std::fs::write("/etc/resolv.conf", "# local_only\n")
                .context("configuring local-only resolution")?;
        }
        terra_protocol::Net::Tsi => {
            let shutdown = shutdown.child_token();
            if !plan.published_udp_ports.is_empty() {
                let limits = reserve_udp_publication_files(rustix::process::getrlimit(
                    rustix::process::Resource::Nofile,
                ))?;
                rustix::process::setrlimit(rustix::process::Resource::Nofile, limits)
                    .context("reserving guest UDP publication descriptors")?;
            }
            crate::config::configure_loopback_address("lo:terra-dns", DNS_IPV4)?;
            let publications =
                if plan.published_ports.is_empty() && plan.published_udp_ports.is_empty() {
                    None
                } else {
                    crate::config::configure_publication_addresses(&shutdown).await?;
                    Some(listen_publications()?)
                };
            let (mut reader, writer) = tokio::io::split(connect_control()?);
            let client = NetworkClient::new(writer, shutdown.clone());
            let decoder = verify_network_version(&client, &mut reader).await?;
            let pending = client.pending.clone();
            let owner_shutdown = shutdown.clone();
            let owner_diagnostic = diagnostic.clone();
            tasks.spawn(async move {
                if let Some(error) = owner_shutdown
                    .run_until_cancelled(receive_results(reader, decoder, pending))
                    .await
                {
                    report_network_unavailable("owner", &error, &owner_shutdown, &owner_diagnostic);
                }
            });
            start_dns(client, &shutdown, tasks, diagnostic).await?;
            if let Some(listener) = publications {
                let publication_shutdown = shutdown.clone();
                let publication_diagnostic = diagnostic.clone();
                let publication_tasks = tasks.clone();
                let ports = plan.published_ports.clone();
                let udp_ports = plan.published_udp_ports.clone();
                tasks.spawn(async move {
                    run_network_service(
                        "publication",
                        serve_publications(
                            listener,
                            ports,
                            udp_ports,
                            &publication_shutdown,
                            &publication_tasks,
                        ),
                        &publication_shutdown,
                        &publication_diagnostic,
                    )
                    .await;
                });
            }
            std::fs::write(
                "/etc/resolv.conf",
                format!("nameserver {}\n", DNS_ADDRESS.ip()),
            )
            .context("configuring guest DNS")?;
            ensure!(
                !shutdown.is_cancelled(),
                "network unavailable during startup"
            );
        }
    }
    Ok(())
}

async fn start_dns(
    client: Arc<NetworkClient>,
    shutdown: &CancellationToken,
    tasks: &TaskTracker,
    diagnostic: &Diagnostics,
) -> Result<()> {
    let udp = UdpSocket::bind(DNS_ADDRESS)
        .await
        .context("binding guest UDP DNS")?;
    let tcp = TcpListener::bind(DNS_ADDRESS)
        .await
        .context("binding guest TCP DNS")?;
    let udp_client = client.clone();
    let udp_shutdown = shutdown.clone();
    let udp_diagnostic = diagnostic.clone();
    let udp_tasks = tasks.clone();
    tasks.spawn(async move {
        run_network_service(
            "UDP DNS",
            serve_udp_dns(udp, udp_client, &udp_shutdown, &udp_tasks),
            &udp_shutdown,
            &udp_diagnostic,
        )
        .await;
    });
    let tcp_shutdown = shutdown.clone();
    let tcp_diagnostic = diagnostic.clone();
    let tcp_tasks = tasks.clone();
    tasks.spawn(async move {
        run_network_service(
            "TCP DNS",
            serve_tcp_dns(tcp, client, &tcp_shutdown, &tcp_tasks),
            &tcp_shutdown,
            &tcp_diagnostic,
        )
        .await;
    });
    Ok(())
}

async fn resolve_dns(client: &NetworkClient, stream: bool, query: Vec<u8>) -> io::Result<Vec<u8>> {
    if let Ok(Some(response)) = client.query(stream, query.clone()).await {
        return Ok(response);
    }
    let question = if stream {
        query.get(2..).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing DNS stream prefix")
        })?
    } else {
        &query[..]
    };
    let mut response =
        terra_protocol::dns::error_response(question, terra_protocol::dns::DNS_RCODE_SERVFAIL);
    if stream {
        let length = u16::try_from(response.len()).map_err(io::Error::other)?;
        response.splice(..0, length.to_be_bytes());
    }
    Ok(response)
}

async fn run_network_service(
    name: &str,
    service: impl std::future::Future<Output = io::Result<()>>,
    shutdown: &CancellationToken,
    diagnostic: &Diagnostics,
) {
    if let Some(Err(error)) = shutdown.run_until_cancelled(service).await {
        report_network_unavailable(name, &error, shutdown, diagnostic);
    }
}

fn report_network_unavailable(
    name: &str,
    error: &io::Error,
    shutdown: &CancellationToken,
    diagnostic: &Diagnostics,
) {
    let message = format!("terra-agent: network unavailable: {name}: {error}\n");
    eprint!("{message}");
    diagnostic.record(message.as_bytes());
    shutdown.cancel();
}

async fn serve_udp_dns(
    socket: UdpSocket,
    client: Arc<NetworkClient>,
    shutdown: &CancellationToken,
    tasks: &TaskTracker,
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
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            let _permit = permit;
            shutdown
                .run_until_cancelled(async {
                    if let Ok(response) = resolve_dns(&client, false, query).await {
                        let _ = socket.send_to(&response, peer).await;
                    }
                })
                .await;
        });
    }
}

async fn serve_tcp_dns(
    listener: TcpListener,
    client: Arc<NetworkClient>,
    shutdown: &CancellationToken,
    tasks: &TaskTracker,
) -> io::Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_DNS_CLIENTS));
    loop {
        let (stream, _peer) = listener.accept().await?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let client = client.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            let _permit = permit;
            shutdown
                .run_until_cancelled(serve_dns_stream(stream, &client))
                .await;
        });
    }
}

async fn serve_dns_stream(mut stream: TcpStream, client: &NetworkClient) -> io::Result<()> {
    loop {
        let query = tokio::time::timeout(DNS_TIMEOUT, read_dns_query(&mut stream))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS client read timed out"))??;
        let Some(query) = query else {
            return Ok(());
        };
        let response = resolve_dns(client, true, query).await?;
        tokio::time::timeout(DNS_TIMEOUT, stream.write_all(&response))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS client write timed out"))??;
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
    let mut query = vec![0; length + 2];
    query[..2].copy_from_slice(&prefix);
    reader.read_exact(&mut query[2..]).await?;
    Ok(Some(query))
}

async fn serve_publications(
    listener: async_io::Async<File>,
    tcp_ports: Vec<u16>,
    udp_ports: Vec<u16>,
    shutdown: &CancellationToken,
    tasks: &TaskTracker,
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
            .read_with(|listener| {
                rustix::net::accept_with(listener, rustix::net::SocketFlags::CLOEXEC)
                    .map_err(io::Error::from)
            })
            .await?;
        let carrier = VsockStream::new(carrier)?;
        let grants = grants.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            let _permit = permit;
            shutdown
                .run_until_cancelled(relay_publication(carrier, &grants))
                .await;
        });
    }
}

async fn read_publication_header(
    carrier: &mut (impl AsyncRead + Unpin),
) -> io::Result<PublicationTarget> {
    let mut header = [0; terra_protocol::application::HEADER_BYTES];
    carrier.read_exact(&mut header).await?;
    let length = usize::try_from(u32::from_le_bytes([
        header[4], header[5], header[6], header[7],
    ]))
    .map_err(io::Error::other)?;
    if length
        > terra_protocol::application::MAX_OPENING_BYTES - terra_protocol::application::HEADER_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized publication header",
        ));
    }
    let mut frame = header.to_vec();
    frame.resize(header.len() + length, 0);
    carrier.read_exact(&mut frame[header.len()..]).await?;
    match Message::decode(&frame, Direction::HostToGuest).map_err(io::Error::other)? {
        Some((Message::Publication { guest_port, peer }, _)) => {
            Ok(PublicationTarget::Tcp { guest_port, peer })
        }
        Some((Message::PublicationUdp { guest_port }, _)) => {
            Ok(PublicationTarget::Udp { guest_port })
        }
        None
        | Some((
            Message::TcpOpen { .. }
            | Message::TcpOpened(_)
            | Message::UdpOpen
            | Message::UdpOpened(_)
            | Message::UdpSend { .. }
            | Message::UdpDatagram { .. }
            | Message::UdpError { .. }
            | Message::Hello
            | Message::Ready
            | Message::DnsQuery { .. }
            | Message::DnsResult { .. },
            _,
        )) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid publication header",
        )),
    }
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
    let target = tokio::time::timeout_at(deadline, read_publication_header(&mut carrier))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "publication opening timed out"))??;
    let (guest_port, ports, slots) = match target {
        PublicationTarget::Tcp { guest_port, .. } => {
            (guest_port, &grants.tcp_ports, &grants.tcp_slots)
        }
        PublicationTarget::Udp { guest_port } => (guest_port, &grants.udp_ports, &grants.udp_slots),
    };
    if !ports.contains(&guest_port) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "publication names an unconfigured guest port",
        ));
    }
    let _permit = slots.try_acquire().map_err(io::Error::other)?;
    match target {
        PublicationTarget::Tcp { .. } => {
            let mut service =
                tokio::time::timeout_at(deadline, connect_published_service(guest_port))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "publication opening timed out")
                    })??;
            if service.local_addr()?.ip() != std::net::IpAddr::V4(RELAY_SOURCE) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "publication relay source address changed",
                ));
            }
            copy_publication_bytes(&mut service, &mut carrier).await
        }
        PublicationTarget::Udp { .. } => {
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
        terra_protocol::socket::MAX_DATAGRAM_BYTES,
    )?;
    rustix::net::sockopt::set_socket_send_buffer_size(
        &socket,
        terra_protocol::socket::MAX_DATAGRAM_BYTES,
    )?;
    socket.connect(destination).await?;
    Ok(socket)
}

async fn relay_udp_publication(
    mut carrier: impl AsyncRead + AsyncWrite + Unpin,
    source: Ipv4Addr,
    destination: SocketAddr,
) -> io::Result<()> {
    let mut decoder = StreamDecoder::default();
    let mut peers: VecDeque<UdpPublicationPeer> = VecDeque::new();
    let mut reply = [0; terra_protocol::socket::MAX_DATAGRAM_BYTES + 1];
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
            message = read_message(&mut carrier, &mut decoder) => {
                let Some(message) = message? else {
                    return Ok(());
                };
                let (peer, bytes) = match message {
                    Message::UdpDatagram { peer, bytes } => (peer, bytes),
                    Message::UdpError { .. } => continue,
                    Message::TcpOpen { .. }
                    | Message::TcpOpened(_)
                    | Message::UdpOpen
                    | Message::UdpOpened(_)
                    | Message::UdpSend { .. }
                    | Message::Hello
                    | Message::Ready
                    | Message::DnsQuery { .. }
                    | Message::DnsResult { .. }
                    | Message::Publication { .. }
                    | Message::PublicationUdp { .. } => {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected UDP publication message"));
                    }
                };
                let entry = if let Some(index) = peers.iter().position(|entry| entry.peer == peer) {
                    peers.remove(index).ok_or_else(|| io::Error::other("missing UDP publication peer"))?
                } else {
                    if peers.len() == terra_protocol::network::MAX_UDP_PEERS {
                        peers.pop_front();
                    }
                    let socket = connect_published_udp_service(source, destination).await?;
                    UdpPublicationPeer { peer, socket, expires: now + UDP_PEER_TTL }
                };
                if entry.socket.send(&bytes).await.is_ok() {
                    peers.push_back(UdpPublicationPeer { expires: Instant::now() + UDP_PEER_TTL, ..entry });
                }
            }
            (index, ready) = wait_udp_publication_reply(&peers, next_reply) => {
                next_reply = (index + 1) % peers.len();
                let entry = peers.get(index).ok_or_else(|| io::Error::other("missing UDP publication peer"))?;
                if entry.expires <= Instant::now() {
                    continue;
                }
                let received = ready.and_then(|()| entry.socket.try_recv(&mut reply));
                match received {
                    Ok(length) if length <= terra_protocol::socket::MAX_DATAGRAM_BYTES => {
                        let frame = Message::UdpSend { peer: entry.peer, bytes: reply[..length].to_vec() }
                            .encode().map_err(io::Error::other)?;
                        carrier.write_all(&frame).await?;
                        carrier.flush().await?;
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => { peers.remove(index); }
                }
            }
            () = tokio::time::sleep_until(expires), if !peers.is_empty() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[tokio::test]
    async fn dns_tcp_framing_bounds_and_preserves_queries() {
        assert_eq!(
            read_dns_query(&mut &b"\0\x03abc"[..]).await.unwrap(),
            Some(b"\0\x03abc".to_vec())
        );
        assert_eq!(read_dns_query(&mut &b""[..]).await.unwrap(), None);
        for query in [&b"\0"[..], &b"\0\x03ab"[..], &b"\x10\x01"[..]] {
            assert!(read_dns_query(&mut &query[..]).await.is_err());
        }
    }

    #[test]
    fn startup_accepts_only_the_matching_kernel_socket_version() {
        assert!(validate_socket_version(terra_protocol::socket::VERSION).is_ok());
        assert!(validate_socket_version(0).is_err());
        assert!(validate_socket_version(terra_protocol::socket::VERSION + 1).is_err());
    }

    #[test]
    #[ignore = "requires Linux AF_VSOCK socket creation"]
    fn native_vsock_buffers_match_their_network_endpoint_budgets() {
        for bytes in [
            terra_protocol::vsock::FLOW_REPLY_BYTES,
            terra_protocol::vsock::CONTROL_REPLY_BYTES,
        ] {
            vsock_socket(bytes).unwrap();
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
        let receiver = tokio::spawn(receive_results(
            reader,
            StreamDecoder::default(),
            client.pending.clone(),
        ));
        TestNetwork {
            client,
            host,
            receiver,
        }
    }

    async fn read_host_message(host: &mut tokio::io::DuplexStream) -> Message {
        let mut header = [0; 8];
        host.read_exact(&mut header).await.unwrap();
        let length = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
        let mut frame = header.to_vec();
        frame.resize(8 + length, 0);
        host.read_exact(&mut frame[8..]).await.unwrap();
        let mut decoder = StreamDecoder::default();
        decoder.push(&frame).unwrap();
        decoder.next(Direction::GuestToHost).unwrap().unwrap()
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
                        .run_until_cancelled(serve_udp_dns(listener, client, &shutdown, &tasks))
                        .await
                }
            });
            for _ in 0..MAX_DNS_CLIENTS {
                requester.send_to(&[0; 12], address).await.unwrap();
                assert_matches!(
                    read_host_message(&mut network.host).await,
                    Message::DnsQuery { .. }
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
            async move { client.query(false, vec![1; 12]).await }
        });
        let Message::DnsQuery { id: first_id, .. } = read_host_message(&mut network.host).await
        else {
            panic!("expected a DNS query");
        };
        let second = tokio::spawn({
            let client = network.client.clone();
            async move { client.query(false, vec![2; 12]).await }
        });
        let Message::DnsQuery { id: second_id, .. } = read_host_message(&mut network.host).await
        else {
            panic!("expected a DNS query");
        };
        for (id, byte) in [(second_id, 2), (first_id, 1)] {
            let reply = Message::DnsResult {
                id,
                stream: false,
                bytes: vec![byte; 12],
            };
            network
                .host
                .write_all(&reply.encode().unwrap())
                .await
                .unwrap();
        }
        assert_eq!(first.await.unwrap().unwrap(), Some(vec![1; 12]));
        assert_eq!(second.await.unwrap().unwrap(), Some(vec![2; 12]));
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
            async move { client.query(false, vec![1; 12]).await }
        });
        host.read_exact(&mut [0; 1]).await.unwrap();
        query.abort();
        assert!(query.await.unwrap_err().is_cancelled());
        assert!(shutdown.is_cancelled());
        assert!(!parent.is_cancelled());
        assert_eq!(
            client
                .send(&Message::Hello)
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
        assert!(network.client.query(false, vec![1; 12]).await.is_err());
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
            async move { client.query(true, vec![0, 1, 7]).await }
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
        for stream in [false, true] {
            let mut request = query.to_vec();
            let mut expected =
                terra_protocol::dns::error_response(query, terra_protocol::dns::DNS_RCODE_SERVFAIL);
            if stream {
                request.splice(..0, u16::try_from(query.len()).unwrap().to_be_bytes());
                expected.splice(..0, u16::try_from(expected.len()).unwrap().to_be_bytes());
            }
            assert_eq!(
                resolve_dns(&network.client, stream, request).await.unwrap(),
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
        let peer: SocketAddr = "203.0.113.9:40000".parse().unwrap();
        let mut bytes = Message::Publication {
            guest_port: 8080,
            peer,
        }
        .encode()
        .unwrap();
        bytes.extend_from_slice(b"GET /");
        let mut carrier = &bytes[..];
        assert_eq!(
            read_publication_header(&mut carrier).await.unwrap(),
            PublicationTarget::Tcp {
                guest_port: 8080,
                peer
            }
        );
        assert_eq!(carrier, b"GET /");
        let datagram = Message::UdpDatagram {
            peer,
            bytes: b"udp".to_vec(),
        }
        .encode()
        .unwrap();
        let mut bytes = Message::PublicationUdp { guest_port: 5353 }
            .encode()
            .unwrap();
        bytes.extend_from_slice(&datagram);
        let mut carrier = &bytes[..];
        assert_eq!(
            read_publication_header(&mut carrier).await.unwrap(),
            PublicationTarget::Udp { guest_port: 5353 }
        );
        assert_eq!(carrier, datagram);
        let mut wrong = &Message::Ready.encode().unwrap()[..];
        assert!(read_publication_header(&mut wrong).await.is_err());
        let oversized = u32::try_from(
            terra_protocol::application::MAX_OPENING_BYTES
                - terra_protocol::application::HEADER_BYTES
                + 1,
        )
        .unwrap();
        let mut header = [0; terra_protocol::application::HEADER_BYTES];
        header[4..8].copy_from_slice(&oversized.to_le_bytes());
        assert_eq!(
            read_publication_header(&mut &header[..])
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
            Message::PublicationUdp { guest_port: 8080 },
            Message::Publication {
                guest_port: 5353,
                peer: "203.0.113.9:40000".parse().unwrap(),
            },
        ] {
            let (guest, mut host) = tokio::io::duplex(64);
            host.write_all(&message.encode().unwrap()).await.unwrap();
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
                &Message::PublicationUdp { guest_port: 5353 }
                    .encode()
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
            while grants.udp_slots.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            grants.tcp_slots.available_permits(),
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
            grants.udp_slots.available_permits(),
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
                    &Message::UdpDatagram {
                        peer,
                        bytes: bytes.to_vec(),
                    }
                    .encode()
                    .unwrap(),
                )
                .await
                .unwrap();
            let mut received = [0; terra_protocol::socket::MAX_DATAGRAM_BYTES + 1];
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
            let mut coalesced = Message::UdpDatagram {
                peer: ipv4,
                bytes: b"\0binary\xff".to_vec(),
            }
            .encode()
            .unwrap();
            coalesced.extend_from_slice(
                &Message::UdpDatagram {
                    peer: ipv6,
                    bytes: Vec::new(),
                }
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
                    vec![0x93; terra_protocol::socket::MAX_DATAGRAM_BYTES],
                ),
            ] {
                publication.service.send_to(&bytes, source).await.unwrap();
                assert_eq!(
                    read_host_message(&mut publication.host).await,
                    Message::UdpSend { peer, bytes }
                );
            }
            let maximum = vec![0x41; terra_protocol::socket::MAX_DATAGRAM_BYTES];
            assert_eq!(publication.send(ipv4, &maximum).await, first);
            let stranger = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            stranger.send_to(b"unrelated", first).await.unwrap();
            publication
                .service
                .send_to(
                    &vec![0; terra_protocol::socket::MAX_DATAGRAM_BYTES + 1],
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
                    &Message::UdpError {
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
                read_host_message(&mut publication.host).await,
                Message::UdpSend {
                    peer: ipv4,
                    bytes: b"reply".to_vec()
                }
            );
            publication.host.shutdown().await.unwrap();
            publication.relay.await.unwrap().unwrap().unwrap();
            assert!(std::net::UdpSocket::bind(first).is_ok());
            assert!(std::net::UdpSocket::bind(second).is_ok());
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
            for port in 1..=u16::try_from(terra_protocol::network::MAX_UDP_PEERS + 1).unwrap() {
                let peer = SocketAddr::from(([203, 0, 113, 9], port));
                let source = publication.send(peer, &port.to_le_bytes()).await;
                if sources.len() == terra_protocol::network::MAX_UDP_PEERS {
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
            read_host_message(&mut publication.host).await,
            Message::UdpSend {
                peer,
                bytes: b"reply".to_vec()
            }
        );
        tokio::time::pause();
        tokio::time::advance(UDP_PEER_TTL / 2 + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        let retired = std::net::UdpSocket::bind(source).unwrap();
        tokio::time::resume();
        let replacement = publication.send(peer, b"replacement").await;
        assert_ne!(replacement, retired.local_addr().unwrap());
        publication
            .host
            .write_all(&Message::Ready.encode().unwrap())
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
            let output = std::process::Command::new("unshare")
                .args(["--user", "--map-root-user", "--net"])
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", "network::tests::publication_preserves_distinct_peer_and_excludes_loopback_listener", "--ignored"])
                .env(CHILD, "1")
                .output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        crate::config::enable_loopback().unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                crate::config::configure_loopback_address("lo:terra-dns", DNS_IPV4).unwrap();
                let _dns_udp = UdpSocket::bind(DNS_ADDRESS).await.unwrap();
                let _dns_tcp = TcpListener::bind(DNS_ADDRESS).await.unwrap();
                crate::config::configure_publication_addresses(&CancellationToken::new())
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
            2 * terra_protocol::socket::MAX_DATAGRAM_BYTES
        );
        assert_eq!(
            rustix::net::sockopt::socket_send_buffer_size(&peer_socket).unwrap(),
            2 * terra_protocol::socket::MAX_DATAGRAM_BYTES
        );
        drop(peer_socket);
        let port = service.local_addr().unwrap().port();
        let (guest, mut host) = tokio::io::duplex(73);
        let relay = tokio::spawn(async move {
            relay_publication(guest, &PublicationGrants::new(Vec::new(), vec![port])).await
        });
        let mut datagrams = Message::PublicationUdp { guest_port: port }
            .encode()
            .unwrap();
        for peer in [
            "203.0.113.9:40000".parse().unwrap(),
            "[2001:db8::9]:40001".parse().unwrap(),
        ] {
            datagrams.extend_from_slice(
                &Message::UdpDatagram {
                    peer,
                    bytes: Vec::new(),
                }
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
                tokio::time::timeout(Duration::from_secs(1), read_host_message(&mut host))
                    .await
                    .unwrap(),
                Message::UdpSend {
                    peer,
                    bytes: b"wildcard reply".to_vec()
                }
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
