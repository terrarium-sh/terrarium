//! TCP sockets and the relay between one socket and one yamux stream.

use crate::{Error, SocketSource, map_io_error};
use socket2::SockRef;
use std::io;
use std::net::SocketAddr;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use terra_protocol::application::TcpOpenOptions;
use terra_protocol::network::{MAX_NETWORK_CHUNK_BYTES, MAX_NETWORK_READ_BYTES, TcpEvent};
use tokio::io::{AsyncReadExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::Mutex;
use tokio_util::compat::Compat;

type StreamRead = ReadHalf<Compat<yamux::Stream>>;
type StreamWrite = WriteHalf<Compat<yamux::Stream>>;

/// Applies the options every outbound TCP socket carries.
fn configure_outbound(socket: &SockRef<'_>, options: TcpOpenOptions) -> io::Result<()> {
    if options.inline_urgent {
        socket.set_out_of_band_inline(true)?;
    }
    if let Some(keepalive) = options.keepalive {
        socket.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(Duration::from_secs(keepalive.idle_secs().into()))
                .with_interval(Duration::from_secs(keepalive.interval_secs().into()))
                .with_retries(keepalive.probe_count().into()),
        )?;
    }
    bound_socket_buffers(socket)
}

/// Binds one published TCP listener natively; see [`super::bind_listeners`].
pub(super) fn bind_tcp_listener_socket(address: SocketAddr) -> io::Result<socket2::Socket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::STREAM,
        None,
    )?;
    reserve_listener_address(&socket)?;
    bound_socket_buffers(&SockRef::from(&socket))?;
    socket.bind(&address.into())?;
    socket.listen(64)?;
    Ok(socket)
}

/// Unix lets a restarted box rebind its port in `TIME_WAIT`. On Windows `SO_REUSEADDR` would let
/// another local process bind the published port, so the listener claims it exclusively.
fn reserve_listener_address(socket: &socket2::Socket) -> io::Result<()> {
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    #[cfg(windows)]
    {
        use windows_sys::Win32::Networking::WinSock::{SO_EXCLUSIVEADDRUSE, SOL_SOCKET};
        super::udp::set_socket_option(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)?;
    }
    Ok(())
}

pub(super) fn bound_socket_buffers(socket: &SockRef<'_>) -> io::Result<()> {
    socket.set_recv_buffer_size(crate::MAX_SOCKET_BUFFER_BYTES as usize)?;
    socket.set_send_buffer_size(crate::MAX_SOCKET_BUFFER_BYTES as usize)
}

pub(super) async fn connect(
    sockets: &SocketSource,
    peer: SocketAddr,
    options: TcpOpenOptions,
) -> Result<TcpStream, Error> {
    let stream = tokio::time::timeout(Duration::from_secs(30), open_stream(sockets, peer, options))
        .await
        .map_err(|_| Error::TimedOut)?
        .map_err(map_io_error)?;
    stream.set_nodelay(true).map_err(map_io_error)?;
    Ok(stream)
}

async fn open_stream(
    sockets: &SocketSource,
    peer: SocketAddr,
    options: TcpOpenOptions,
) -> io::Result<TcpStream> {
    match sockets {
        SocketSource::Native => {
            let socket = if peer.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            configure_outbound(&SockRef::from(&socket), options)?;
            socket.connect(peer).await
        }
        SocketSource::Delegated(outbound) => {
            let socket = outbound.connect_tcp(peer).await?;
            configure_outbound(&SockRef::from(&socket), options)?;
            socket.set_nonblocking(true)?;
            TcpStream::from_std(socket.into())
        }
    }
}

pub(super) async fn accept(listener: &TcpListener) -> Result<(TcpStream, SocketAddr), Error> {
    let (stream, peer) = listener.accept().await.map_err(map_io_error)?;
    if !peer.ip().is_loopback() {
        return Err(Error::AccessDenied);
    }
    bound_socket_buffers(&SockRef::from(&stream)).map_err(map_io_error)?;
    stream.set_nodelay(true).map_err(map_io_error)?;
    Ok((stream, peer))
}

struct Relay {
    tcp: TcpStream,
    events: Mutex<StreamWrite>,
    #[cfg(windows)]
    write_shutdown_started: AtomicBool,
}

/// Copies bytes both ways until both directions finish or one fails; dropping the stream aborts.
pub(super) async fn relay(stream: Compat<yamux::Stream>, tcp: TcpStream) {
    let (upload_read, events) = tokio::io::split(stream);
    let relay = Relay {
        tcp,
        events: Mutex::new(events),
        #[cfg(windows)]
        write_shutdown_started: AtomicBool::new(false),
    };
    let download = relay.download();
    let upload = relay.upload(upload_read);
    tokio::pin!(download, upload);
    let (mut is_eof_sent, mut is_upload_done) = (false, false);
    while !(is_eof_sent && is_upload_done) {
        tokio::select! {
            is_ok = &mut download, if !is_eof_sent => {
                if !is_ok {
                    return;
                }
                is_eof_sent = true;
            }
            is_ok = &mut upload, if !is_upload_done => {
                if !is_ok {
                    return;
                }
                is_upload_done = true;
            }
            error = relay.wait_tcp_error(), if is_eof_sent && !is_upload_done => {
                relay.send(&TcpEvent::Failed(error)).await;
                return;
            }
        }
    }
}

impl Relay {
    async fn send(&self, event: &TcpEvent) -> bool {
        crate::frames::write_frame(&mut *self.events.lock().await, event)
            .await
            .is_ok()
    }

    async fn read_some(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            self.tcp.readable().await?;
            match self.tcp.try_read(buffer) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => return result,
            }
        }
    }

    async fn write_all(&self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            self.tcp.writable().await?;
            match self.tcp.try_write(bytes) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(length) => bytes = &bytes[length..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Returns whether `Eof` was sent; `false` means the relay must end.
    async fn download(&self) -> bool {
        let mut buffer = vec![0; MAX_NETWORK_READ_BYTES];
        loop {
            let event = match self.read_some(&mut buffer).await {
                Ok(0) => TcpEvent::Eof,
                Ok(length) => TcpEvent::Data(buffer[..length].to_vec()),
                Err(error) => TcpEvent::Failed(map_io_error(error)),
            };
            if !self.send(&event).await {
                return false;
            }
            match event {
                TcpEvent::Data(_) => {}
                TcpEvent::Eof => return true,
                TcpEvent::WriteShutdown(_) | TcpEvent::Failed(_) => return false,
            }
        }
    }

    /// Returns whether `WriteShutdown` was sent; `false` means the relay must end.
    async fn upload(&self, mut stream: StreamRead) -> bool {
        let mut buffer = vec![0; MAX_NETWORK_CHUNK_BYTES];
        loop {
            let length = stream.read(&mut buffer).await.unwrap_or(0);
            if length == 0 {
                let result = self.shutdown_write().map_err(map_io_error);
                return self.send(&TcpEvent::WriteShutdown(result)).await;
            }
            if let Err(error) = self.write_all(&buffer[..length]).await {
                self.send(&TcpEvent::Failed(map_io_error(error))).await;
                return false;
            }
        }
    }

    fn shutdown_write(&self) -> io::Result<()> {
        #[cfg(windows)]
        self.write_shutdown_started.store(true, Ordering::SeqCst);
        let shutdown = SockRef::from(&self.tcp).shutdown(std::net::Shutdown::Write);
        #[cfg(windows)]
        if shutdown.is_err() {
            self.write_shutdown_started.store(false, Ordering::SeqCst);
        }
        shutdown
    }

    #[cfg(not(windows))]
    async fn wait_tcp_error(&self) -> Error {
        if let Err(error) = self.tcp.ready(tokio::io::Interest::ERROR).await {
            return map_io_error(error);
        }
        match self.tcp.take_error() {
            Ok(None) => Error::ConnectionReset,
            Ok(Some(error)) | Err(error) => map_io_error(error),
        }
    }

    #[cfg(windows)]
    async fn wait_tcp_error(&self) -> Error {
        loop {
            tokio::select! {
                ready = self.tcp.ready(tokio::io::Interest::ERROR) => {
                    if let Err(error) = ready {
                        return map_io_error(error);
                    }
                    return match self.tcp.take_error() {
                        Ok(None) => Error::ConnectionReset,
                        Ok(Some(error)) | Err(error) => map_io_error(error),
                    };
                }
                () = tokio::time::sleep(Duration::from_millis(50)) => {
                    match self.tcp.take_error() {
                        Ok(None) => {}
                        Ok(Some(error)) | Err(error) => return map_io_error(error),
                    }
                    match read_windows_tcp_state(&self.tcp) {
                        Ok(windows_sys::Win32::Networking::WinSock::TCPSTATE_CLOSED)
                            if !self.write_shutdown_started.load(Ordering::SeqCst) => return Error::ConnectionReset,
                        Ok(_) => {}
                        Err(error) => return map_io_error(error),
                    }
                }
            }
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn read_windows_tcp_state(socket: &TcpStream) -> io::Result<i32> {
    use windows_sys::Win32::Networking::WinSock::{
        SIO_TCP_INFO, SOCKET_ERROR, TCP_INFO_v0, WSAGetLastError, WSAIoctl,
    };

    let version = 0u32;
    let mut info = TCP_INFO_v0::default();
    let info_bytes = u32::try_from(std::mem::size_of::<TCP_INFO_v0>())
        .map_err(|_| io::Error::other("TCP info size exceeds ioctl limit"))?;
    let raw_socket = usize::try_from(socket.as_raw_socket())
        .map_err(|_| io::Error::other("socket handle exceeds ioctl limit"))?;
    let mut returned = 0u32;
    // SAFETY: WSAIoctl completes synchronously with live input and output buffers.
    let status = unsafe {
        WSAIoctl(
            raw_socket,
            SIO_TCP_INFO,
            (&raw const version).cast(),
            4,
            (&raw mut info).cast(),
            info_bytes,
            &raw mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if status == SOCKET_ERROR {
        // SAFETY: WSAGetLastError reads the calling thread's last Winsock error.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    if returned < info_bytes {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short TCP info"));
    }
    Ok(info.State)
}
