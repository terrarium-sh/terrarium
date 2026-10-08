use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::Result;

pub(super) struct HostService {
    port: u16,
    requests: Arc<AtomicUsize>,
    datagrams: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl HostService {
    pub(super) fn start() -> Result<Self> {
        let (listener, udp) = loop {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            let port = listener.local_addr()?.port();
            let [ipv4, ipv6] = [
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
            ]
            .map(UdpSocket::bind);
            match (ipv4, ipv6) {
                (Ok(ipv4), Ok(ipv6)) => break (listener, [ipv4, ipv6]),
                (Err(error), _) | (_, Err(error)) if error.kind() == io::ErrorKind::AddrInUse => {}
                (Err(error), _) | (_, Err(error)) => return Err(error.into()),
            }
        };
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        for socket in &udp {
            socket.set_nonblocking(true)?;
        }
        let requests = Arc::new(AtomicUsize::new(0));
        let datagrams = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let server_requests = Arc::clone(&requests);
        let server_datagrams = Arc::clone(&datagrams);
        let server_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("self-test-network".to_owned())
            .spawn(move || {
                serve_requests(
                    &listener,
                    &udp,
                    &server_requests,
                    &server_datagrams,
                    &server_stop,
                )
            })?;
        Ok(Self {
            port,
            requests,
            datagrams,
            stop,
            thread: Some(thread),
        })
    }

    pub(super) fn port(&self) -> u16 {
        self.port
    }

    pub(super) fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    pub(super) fn datagrams(&self) -> usize {
        self.datagrams.load(Ordering::SeqCst)
    }
}

impl Drop for HostService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_requests(
    listener: &TcpListener,
    udp: &[UdpSocket; 2],
    requests: &AtomicUsize,
    datagrams: &AtomicUsize,
    stop: &AtomicBool,
) -> io::Result<()> {
    while !stop.load(Ordering::SeqCst) {
        let mut bytes = [0; 4096];
        for socket in udp {
            match socket.recv_from(&mut bytes) {
                Ok((length, peer)) => {
                    datagrams.fetch_add(1, Ordering::SeqCst);
                    let payload = &bytes[..length];
                    let reply = if payload == b"terra-udp" {
                        b"HOST_DATAGRAM"
                    } else {
                        payload
                    };
                    socket.send_to(reply, peer)?;
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = serve_request(stream, requests);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn serve_request(mut stream: TcpStream, requests: &AtomicUsize) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut reader = BufReader::new(&mut stream).take(16 * 1024);
    let mut request = String::new();
    reader.read_line(&mut request)?;
    if !request.starts_with("GET ") {
        return Err(io::Error::other("expected HTTP GET"));
    }
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            return Err(io::Error::other("incomplete HTTP request"));
        }
        if header == "\r\n" {
            break;
        }
    }
    requests.fetch_add(1, Ordering::SeqCst);
    stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nHOST_NETWORK",
    )
}

fn read_http_body(port: u16) -> io::Result<Vec<u8>> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut reader = BufReader::new(stream).take(64 * 1024);
    let mut status = String::new();
    reader.read_line(&mut status)?;
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(io::Error::other("HTTP response was not successful"));
    }
    let mut length = None;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            return Err(io::Error::other("incomplete HTTP response"));
        }
        if header == "\r\n" {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("Content-Length")
        {
            length = value.trim().parse::<usize>().ok();
        }
    }
    let length = length
        .filter(|length| *length <= 64 * 1024)
        .ok_or_else(|| io::Error::other("missing or invalid HTTP content length"))?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(body)
}

pub(super) fn read_published_port(port: u16) -> bool {
    read_http_body(port).is_ok_and(|body| body == b"GUEST_NETWORK")
}

pub(super) fn read_published_datagram(port: u16) -> bool {
    let result = || -> io::Result<bool> {
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        client.set_read_timeout(Some(Duration::from_secs(2)))?;
        client.send_to(b"published-udp", (Ipv4Addr::LOCALHOST, port))?;
        let mut bytes = [0; 4096];
        let (length, peer) = client.recv_from(&mut bytes)?;
        Ok(peer.port() == port && &bytes[..length] == b"GUEST_DATAGRAM")
    };
    result().unwrap_or(false)
}

pub(super) fn exercise_quic(self_test: &super::SelfTest, allowed: &HostService) -> Result<()> {
    println!("self-test: UDP QUIC options, ECN and GSO");
    std::fs::write(
        self_test.directory.join("writable/socket-probe"),
        include_bytes!(env!("TERRA_SOCKET_PROBE")),
    )?;
    let output = self_test.execute(
        &format!(
            "cp /work/socket-probe /tmp/socket-probe; chmod 755 /tmp/socket-probe; \
             /tmp/socket-probe --quic-socket 100.96.0.1 {}",
            allowed.port()
        ),
        &[],
    )?;
    super::require_output(&output, "SOCKET_QUIC_OK")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_service_counts_gets_and_serves_the_fixture() -> Result<()> {
        let service = HostService::start()?;
        assert_eq!(read_http_body(service.port())?, b"HOST_NETWORK");
        assert_eq!(service.requests(), 1);
        assert!(!read_published_port(service.port()));
        assert_eq!(service.requests(), 2);
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        udp.set_read_timeout(Some(Duration::from_secs(2)))?;
        udp.send_to(b"terra-udp", (Ipv4Addr::LOCALHOST, service.port()))?;
        let mut bytes = [0; 32];
        let (length, peer) = udp.recv_from(&mut bytes)?;
        assert_eq!(&bytes[..length], b"HOST_DATAGRAM");
        assert_eq!(peer.port(), service.port());
        assert_eq!(service.datagrams(), 1);
        assert!(!read_published_datagram(service.port()));
        assert_eq!(service.datagrams(), 2);
        Ok(())
    }

    #[test]
    fn host_service_echoes_datagram_boundaries_and_payloads_on_both_families() -> Result<()> {
        let service = HostService::start()?;
        for address in [
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
        ] {
            let udp = UdpSocket::bind(address)?;
            udp.set_read_timeout(Some(Duration::from_secs(2)))?;
            let peer = SocketAddr::new(address.ip(), service.port());
            for payload in [&[][..], &[1; 1200][..], &[2; 1200][..], &[3; 401][..]] {
                udp.send_to(payload, peer)?;
                let mut bytes = [0; 4096];
                let (length, sender) = udp.recv_from(&mut bytes)?;
                assert_eq!(sender, peer);
                assert_eq!(&bytes[..length], payload);
            }
        }
        assert_eq!(service.datagrams(), 8);
        Ok(())
    }

    #[test]
    fn published_port_requires_success_and_the_exact_body() -> Result<()> {
        for (response, expected) in [
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nGUEST_NETWORK"[..],
                true,
            ),
            (
                &b"HTTP/1.1 403 Forbidden\r\nContent-Length: 13\r\n\r\nGUEST_NETWORK"[..],
                false,
            ),
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nWRONG_NETWORK"[..],
                false,
            ),
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n"[..],
                false,
            ),
        ] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            let port = listener.local_addr()?.port();
            let server = thread::spawn(move || -> io::Result<()> {
                let (mut stream, _) = listener.accept()?;
                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                let mut request = [0; 1024];
                assert!(stream.read(&mut request)? > 0);
                stream.write_all(response)
            });
            assert_eq!(read_published_port(port), expected);
            server
                .join()
                .map_err(|_| io::Error::other("HTTP fixture panicked"))??;
        }
        Ok(())
    }
}
