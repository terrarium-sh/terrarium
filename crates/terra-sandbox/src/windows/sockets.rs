//! Outbound sockets the trusted launcher opens for the `AppContainer` broker, whose own sockets
//! network isolation keeps off host loopback. No reply is a socket that can still listen.

use super::Role;
use crate::SocketReply;
use anyhow::{Context, Result, ensure};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::io::{AsRawSocket, FromRawSocket};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use terra_platform::local_socket::{LocalStream, OwnedSocket, encode_sockets, receive_sockets};
use terra_platform::process;
use terra_platform::process::sandbox_env::ROLE;
use windows_sys::Win32::Networking::WinSock::{
    SO_UPDATE_CONNECT_CONTEXT, SOL_SOCKET, WSAEMFILE, setsockopt,
};

pub(super) const LAUNCHER_SOCKETS_ENV: &str = "TERRA_WINDOWS_SANDBOX_SOCKETS";
pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Bounds the launcher threads a broker can hold with connections that never complete.
pub(super) const MAX_PENDING_CONNECTS: usize = 64;

/// One broker request; anything else on the channel ends it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Request {
    ConnectTcp(SocketAddr),
    BindUdp(socket2::Domain),
}

const CONNECT_TCP_V4: u8 = 1;
const CONNECT_TCP_V6: u8 = 2;
const BIND_UDP_V4: u8 = 3;
const BIND_UDP_V6: u8 = 4;

impl Request {
    fn encode(self, id: u32) -> Vec<u8> {
        let mut bytes = id.to_le_bytes().to_vec();
        match self {
            Self::ConnectTcp(SocketAddr::V4(peer)) => {
                bytes.push(CONNECT_TCP_V4);
                bytes.extend(peer.ip().octets());
                bytes.extend(peer.port().to_le_bytes());
            }
            Self::ConnectTcp(SocketAddr::V6(peer)) => {
                bytes.push(CONNECT_TCP_V6);
                bytes.extend(peer.ip().octets());
                bytes.extend(peer.port().to_le_bytes());
            }
            Self::BindUdp(domain) if domain == socket2::Domain::IPV6 => bytes.push(BIND_UDP_V6),
            Self::BindUdp(_) => bytes.push(BIND_UDP_V4),
        }
        bytes
    }

    /// Reads one request and its id; `Ok(None)` is the broker closing the channel.
    fn read(channel: &mut impl Read) -> io::Result<Option<(u32, Self)>> {
        let mut id = [0; 4];
        match channel.read_exact(&mut id) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error),
        }
        let mut kind = [0];
        channel.read_exact(&mut kind)?;
        let request = match kind[0] {
            CONNECT_TCP_V4 => {
                let mut ip = [0; 4];
                channel.read_exact(&mut ip)?;
                Self::ConnectTcp(SocketAddr::new(
                    Ipv4Addr::from(ip).into(),
                    read_port(channel)?,
                ))
            }
            CONNECT_TCP_V6 => {
                let mut ip = [0; 16];
                channel.read_exact(&mut ip)?;
                Self::ConnectTcp(SocketAddr::new(
                    Ipv6Addr::from(ip).into(),
                    read_port(channel)?,
                ))
            }
            BIND_UDP_V4 => Self::BindUdp(socket2::Domain::IPV4),
            BIND_UDP_V6 => Self::BindUdp(socket2::Domain::IPV6),
            _ => return Err(io::ErrorKind::InvalidData.into()),
        };
        Ok(Some((u32::from_le_bytes(id), request)))
    }

    /// A Windows duplicate keeps the connection state its socket had when duplicated, so a
    /// connection completes here before the socket is handed over. A non-blocking connect leaves
    /// that user-mode state unconnected, so `SO_UPDATE_CONNECT_CONTEXT` records the completion.
    fn open(self) -> io::Result<socket2::Socket> {
        match self {
            Self::ConnectTcp(peer) => {
                let socket = socket2::Socket::new(
                    socket2::Domain::for_address(peer),
                    socket2::Type::STREAM,
                    None,
                )?;
                socket.connect_timeout(&peer.into(), CONNECT_TIMEOUT)?;
                let raw = usize::try_from(socket.as_raw_socket()).map_err(io::Error::other)?;
                // SAFETY: socket is live; the option takes no value.
                let status = unsafe {
                    setsockopt(
                        raw,
                        SOL_SOCKET,
                        SO_UPDATE_CONNECT_CONTEXT,
                        std::ptr::null(),
                        0,
                    )
                };
                if status != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(socket)
            }
            Self::BindUdp(domain) => {
                let unspecified = if domain == socket2::Domain::IPV6 {
                    IpAddr::from(Ipv6Addr::UNSPECIFIED)
                } else {
                    IpAddr::from(Ipv4Addr::UNSPECIFIED)
                };
                let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
                if domain == socket2::Domain::IPV6 {
                    socket.set_only_v6(true)?;
                }
                socket.bind(&SocketAddr::new(unspecified, 0).into())?;
                Ok(socket)
            }
        }
    }
}

fn read_port(channel: &mut impl Read) -> io::Result<u16> {
    let mut port = [0; 2];
    channel.read_exact(&mut port)?;
    Ok(u16::from_le_bytes(port))
}

/// The launcher's writing half; each reply is written whole under its lock.
#[derive(Clone)]
struct Replies {
    channel: Arc<Mutex<LocalStream>>,
    worker_pid: u32,
}

impl Replies {
    fn send(&self, id: u32, reply: io::Result<socket2::Socket>) {
        let channel = self.channel.lock().unwrap_or_else(PoisonError::into_inner);
        let mut writer: &LocalStream = &channel;
        let frame =
            reply.and_then(|socket| encode_sockets(&[OwnedSocket::from(socket)], self.worker_pid));
        let status = frame
            .as_ref()
            .map_or_else(|error| error.raw_os_error().unwrap_or(-1), |_| 0);
        let mut message = id.to_le_bytes().to_vec();
        message.extend(status.to_le_bytes());
        message.extend(frame.unwrap_or_default());
        let _ = writer.write_all(&message);
    }
}

/// Answers the worker's requests on `channel` until the worker closes it or misbehaves.
pub(super) fn serve(channel: LocalStream, worker_pid: u32) -> Result<std::thread::JoinHandle<()>> {
    let replies = Replies {
        channel: Arc::new(Mutex::new(channel.try_clone()?)),
        worker_pid,
    };
    let pending_connects = Arc::new(AtomicUsize::new(0));
    let mut requests = channel;
    Ok(std::thread::Builder::new()
        .name("sandbox-launcher-sockets".into())
        .spawn(move || {
            while let Ok(Some((id, request))) = Request::read(&mut requests) {
                if matches!(request, Request::BindUdp(_)) {
                    replies.send(id, request.open());
                    continue;
                }
                if pending_connects.fetch_add(1, Ordering::AcqRel) >= MAX_PENDING_CONNECTS {
                    pending_connects.fetch_sub(1, Ordering::AcqRel);
                    replies.send(id, Err(io::Error::from_raw_os_error(WSAEMFILE)));
                    continue;
                }
                let (replies, pending_connects) = (replies.clone(), pending_connects.clone());
                let spawned = std::thread::Builder::new()
                    .name("sandbox-launcher-connect".into())
                    .spawn(move || {
                        replies.send(id, request.open());
                        pending_connects.fetch_sub(1, Ordering::AcqRel);
                    });
                if spawned.is_err() {
                    return;
                }
            }
        })?)
}

/// The broker's channel to the trusted launcher that opens its outbound sockets.
pub struct LauncherSockets {
    requests: Mutex<LocalStream>,
    pending: Arc<Mutex<HashMap<u32, SocketReply>>>,
    next_id: AtomicU32,
}

impl LauncherSockets {
    /// Takes the channel the Windows sandbox passed this worker; `Ok(None)` means the worker
    /// runs outside the sandbox. A sandboxed broker without one fails here.
    pub fn claim() -> Result<Option<Self>> {
        let Some(handle) = process::inherited_handle(LAUNCHER_SOCKETS_ENV)? else {
            ensure!(
                std::env::var_os(ROLE).is_none_or(|role| role != Role::Network.name()),
                "the Windows sandbox launched the broker without its socket channel"
            );
            return Ok(None);
        };
        process::initialize_winsock()?;
        process::set_inheritable(handle, false)?;
        // SAFETY: the trusted launcher passed this inherited socket to this worker alone.
        let channel = unsafe { LocalStream::from_raw_socket(handle as u64) };
        Self::from_channel(channel).map(Some)
    }

    fn from_channel(channel: LocalStream) -> Result<Self> {
        let pending = Arc::new(Mutex::new(HashMap::<u32, SocketReply>::new()));
        let mut replies = channel.try_clone()?;
        let dispatch = pending.clone();
        std::thread::Builder::new()
            .name("launcher-socket-replies".into())
            .spawn(move || {
                while let Ok((id, reply)) = read_reply(&mut replies) {
                    let waiting = dispatch
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(&id);
                    match waiting {
                        Some(waiting) => waiting(reply),
                        None => break,
                    }
                }
                let abandoned: Vec<_> = dispatch
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .drain()
                    .collect();
                for (_, waiting) in abandoned {
                    waiting(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
                }
            })
            .context("starting the Windows sandbox socket reply reader")?;
        Ok(Self {
            requests: Mutex::new(channel),
            pending,
            next_id: AtomicU32::new(0),
        })
    }

    /// Calls `reply` with a TCP socket connected to `peer`, once the launcher has connected it.
    pub fn connect_tcp(&self, peer: SocketAddr, reply: SocketReply) {
        self.request(Request::ConnectTcp(peer), reply);
    }

    /// Returns a UDP socket bound to an ephemeral port on the unspecified address of `domain`.
    pub fn bind_udp(&self, domain: socket2::Domain) -> io::Result<socket2::Socket> {
        if ![socket2::Domain::IPV4, socket2::Domain::IPV6].contains(&domain) {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let (sender, receiver) = std::sync::mpsc::channel();
        self.request(
            Request::BindUdp(domain),
            Box::new(move |reply| {
                let _ = sender.send(reply);
            }),
        );
        receiver
            .recv()
            .unwrap_or_else(|_| Err(io::ErrorKind::BrokenPipe.into()))
    }

    fn request(&self, request: Request, reply: SocketReply) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, reply);
        let sent = self
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write_all(&request.encode(id));
        if let Err(error) = sent {
            let waiting = self
                .pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&id);
            if let Some(waiting) = waiting {
                waiting(Err(error));
            }
        }
    }
}

/// Reads one reply; a protocol error ends the reader.
fn read_reply(channel: &mut LocalStream) -> io::Result<(u32, io::Result<socket2::Socket>)> {
    let mut header = [0; 8];
    channel.read_exact(&mut header)?;
    let id = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let status = i32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    if status != 0 {
        return Ok((id, Err(io::Error::from_raw_os_error(status))));
    }
    let mut sockets = receive_sockets(channel)?;
    match (sockets.pop(), sockets.is_empty()) {
        (Some(socket), true) => Ok((id, Ok(socket2::Socket::from(socket)))),
        _ => Err(io::Error::other(
            "the Windows sandbox launcher sent no socket",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect_blocking(
        sockets: &LauncherSockets,
        peer: SocketAddr,
    ) -> io::Result<socket2::Socket> {
        let (sender, receiver) = std::sync::mpsc::channel();
        sockets.connect_tcp(
            peer,
            Box::new(move |reply| {
                let _ = sender.send(reply);
            }),
        );
        receiver.recv_timeout(Duration::from_secs(10)).unwrap()
    }

    #[test]
    fn requests_round_trip_and_reject_other_kinds() {
        for request in [
            Request::ConnectTcp("127.0.0.1:80".parse().unwrap()),
            Request::ConnectTcp("[::1]:443".parse().unwrap()),
            Request::BindUdp(socket2::Domain::IPV4),
            Request::BindUdp(socket2::Domain::IPV6),
        ] {
            let bytes = request.encode(7);
            assert_eq!(
                Request::read(&mut bytes.as_slice()).unwrap(),
                Some((7, request))
            );
        }
        assert_eq!(Request::read(&mut [].as_slice()).unwrap(), None);
        assert!(Request::read(&mut [0_u8, 0, 0, 0, 0].as_slice()).is_err());
        assert!(Request::read(&mut [0_u8, 0, 0, 0, CONNECT_TCP_V4, 127].as_slice()).is_err());
    }

    /// Connections the launcher completes reach their peer, replies match their requests while
    /// a slow connection is pending, and no launcher socket can listen.
    #[test]
    fn launcher_sockets_connect_and_never_listen() {
        let (broker, launcher) = terra_platform::local_socket::create_local_pair().unwrap();
        let _serving = serve(launcher, std::process::id()).unwrap();
        let sockets = LauncherSockets::from_channel(broker).unwrap();
        let (slow_sender, slow_receiver) = std::sync::mpsc::channel();
        sockets.connect_tcp(
            "192.0.2.1:9".parse().unwrap(),
            Box::new(move |reply| {
                let _ = slow_sender.send(reply.is_ok());
            }),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let tcp = connect_blocking(&sockets, address).unwrap();
        assert_eq!(tcp.peer_addr().unwrap().as_socket(), Some(address));
        listener.accept().unwrap();
        assert!(tcp.listen(1).is_err());
        assert!(connect_blocking(&sockets, "127.0.0.1:1".parse().unwrap()).is_err());
        let udp = sockets.bind_udp(socket2::Domain::IPV4).unwrap();
        assert_eq!(
            udp.local_addr().unwrap().as_socket().unwrap().ip(),
            IpAddr::from(Ipv4Addr::UNSPECIFIED)
        );
        assert!(sockets.bind_udp(socket2::Domain::UNIX).is_err());
        assert!(slow_receiver.try_recv().is_err());
    }
}
