//! End-to-end tests: a real client and broker over a Unix socket pair, with real local sockets.

use super::dns::resolve_addresses;
use super::udp::{UDP_PEER_TTL, UdpResource, receive_datagrams, send_datagrams};
use super::*;
use crate::config::PublishedListener;
use crate::{Client, TcpDownload, TcpUpload};
use futures_util::FutureExt;
use socket2::SockRef;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use terra_policy::config::{Network, StaticDnsRecord};
use terra_protocol::network::{
    DATAGRAM_FRAME_OVERHEAD_BYTES, Datagram, MAX_NETWORK_DATAGRAM_BATCH_BYTES,
    MAX_NETWORK_DATAGRAM_BYTES, MAX_NETWORK_DATAGRAMS, SendFailure,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("test stalled")
}

fn config() -> Config {
    Config {
        policy: Network {
            allow: vec!["HOST_LOOPBACK".into(), "localhost".into()],
            hosts: vec![StaticDnsRecord {
                name: "static.test".into(),
                addr: "1.1.1.1".into(),
            }],
            ..Network::default()
        },
        gateways: [
            "100.96.0.1".parse().unwrap(),
            "fd53:4d00::1".parse().unwrap(),
        ],
        listeners: vec![],
    }
}

fn start(config: &Config) -> (Client, tokio::task::JoinHandle<io::Result<()>>) {
    start_broker(Broker::bind(config).unwrap())
}

fn start_broker(broker: Broker) -> (Client, tokio::task::JoinHandle<io::Result<()>>) {
    #[cfg(unix)]
    let (worker, endpoint) = {
        let (worker, endpoint) = std::os::unix::net::UnixStream::pair().unwrap();
        worker.set_nonblocking(true).unwrap();
        endpoint.set_nonblocking(true).unwrap();
        (
            tokio::net::UnixStream::from_std(worker).unwrap(),
            tokio::net::UnixStream::from_std(endpoint).unwrap(),
        )
    };
    #[cfg(not(unix))]
    let (worker, endpoint) = tokio::io::duplex(1 << 20);
    (Client::new(worker), tokio::spawn(broker.serve(endpoint)))
}

async fn finish_session(client: Client, broker: tokio::task::JoinHandle<io::Result<()>>) {
    drop(client);
    broker.await.unwrap().unwrap();
}

struct Tcp {
    upload: TcpUpload,
    download: TcpDownload,
    remote: TcpStream,
}

async fn connect_tcp(client: &Client, inline_urgent: bool) -> (Tcp, TcpListener) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (flow, accepted) = tokio::join!(client.open_tcp(address, inline_urgent), listener.accept());
    let flow = flow.unwrap();
    assert_eq!(flow.peer(), address);
    let (upload, download) = flow.split();
    let tcp = Tcp {
        upload,
        download,
        remote: accepted.unwrap().0,
    };
    (tcp, listener)
}

async fn read_download(download: &mut TcpDownload, length: usize) -> Vec<u8> {
    let mut received = Vec::new();
    while received.len() < length {
        received.extend(download.next().await.expect("unexpected eof").unwrap());
    }
    received
}

#[tokio::test]
async fn ipv6_publication_conflicts_preserve_required_ipv4_listeners() {
    bounded(async {
        for transport in [ResourceKind::Tcp, ResourceKind::Udp] {
            let reserved_tcp;
            let reserved_udp;
            let address = match transport {
                ResourceKind::Tcp => {
                    reserved_tcp = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
                    reserved_tcp.local_addr().unwrap()
                }
                ResourceKind::Udp => {
                    reserved_udp = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
                    reserved_udp.local_addr().unwrap()
                }
            };
            let mut setup = config();
            setup.listeners = vec![
                PublishedListener {
                    grant: 1,
                    address: (Ipv4Addr::LOCALHOST, address.port()).into(),
                    transport,
                },
                PublishedListener {
                    grant: 2,
                    address,
                    transport,
                },
            ];
            let broker = Broker::bind(&setup).unwrap();
            match transport {
                ResourceKind::Tcp => {
                    assert!(broker.listeners.contains_key(&1));
                    assert!(!broker.listeners.contains_key(&2));
                }
                ResourceKind::Udp => {
                    assert!(broker.udp_listeners.contains_key(&1));
                    assert!(!broker.udp_listeners.contains_key(&2));
                }
            }
            let (client, session) = start_broker(broker);
            match transport {
                ResourceKind::Tcp => {
                    assert_eq!(client.accept(2).await.err(), Some(Error::AccessDenied));
                }
                ResourceKind::Udp => {
                    assert_eq!(
                        client.open_published_udp(2).await.err(),
                        Some(Error::AccessDenied)
                    );
                }
            }
            finish_session(client, session).await;
            setup.listeners.remove(0);
            assert!(Broker::bind(&setup).is_err());
        }
    })
    .await;
}

#[tokio::test]
async fn tcp_upload_and_download_preserve_order() {
    bounded(async {
        let (client, session) = start(&config());
        let (mut tcp, _listener) = connect_tcp(&client, false).await;
        let upload: Vec<u8> = (0..=255).cycle().take(1 << 20).collect();
        let download: Vec<u8> = (0..=255).rev().cycle().take(1 << 20).collect();
        let (mut remote_read, mut remote_write) = tcp.remote.split();
        let expected_upload = upload.clone();
        let ((), (), received) = tokio::join!(
            async {
                for chunk in upload.chunks(10_000) {
                    tcp.upload.write(chunk).await.unwrap();
                }
            },
            async { remote_write.write_all(&download).await.unwrap() },
            async {
                let mut bytes = vec![0; expected_upload.len()];
                remote_read.read_exact(&mut bytes).await.unwrap();
                assert_eq!(bytes, expected_upload);
                read_download(&mut tcp.download, download.len()).await
            }
        );
        assert_eq!(received, download);
        drop((tcp.upload, tcp.download));
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
async fn client_half_close_reaches_the_peer_while_the_download_continues() {
    bounded(async {
        let (client, session) = start(&config());
        let (mut tcp, _listener) = connect_tcp(&client, false).await;
        tcp.upload.write(b"one").await.unwrap();
        tcp.upload.write(b"two").await.unwrap();
        tcp.upload.finish().await.unwrap();
        let mut received = Vec::new();
        tcp.remote.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"onetwo");
        tcp.remote.write_all(b"after").await.unwrap();
        assert_eq!(read_download(&mut tcp.download, 5).await, b"after");
        tcp.remote.shutdown().await.unwrap();
        assert_eq!(tcp.download.next().await, None);
        drop(tcp.download);
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
async fn peer_fin_ends_the_download_while_the_upload_continues() {
    bounded(async {
        let (client, session) = start(&config());
        let (mut tcp, _listener) = connect_tcp(&client, false).await;
        tcp.remote.write_all(b"last").await.unwrap();
        tcp.remote.shutdown().await.unwrap();
        assert_eq!(read_download(&mut tcp.download, 4).await, b"last");
        assert_eq!(tcp.download.next().await, None);
        tcp.upload.write(b"still").await.unwrap();
        let mut received = [0; 5];
        tcp.remote.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"still");
        tcp.upload.finish().await.unwrap();
        assert_eq!(tcp.remote.read(&mut received).await.unwrap(), 0);
        finish_session(client, session).await;
    })
    .await;
}

/// An unread payload makes a reset after FIN observable to the broker on every host OS.
#[tokio::test]
async fn reset_after_fin_fails_a_later_upload_write() {
    bounded(async {
        let (client, session) = start(&config());
        let (mut tcp, _listener) = connect_tcp(&client, false).await;
        tcp.remote.shutdown().await.unwrap();
        assert_eq!(tcp.download.next().await, None);
        tcp.upload.write(b"RX").await.unwrap();
        let mut received = [0];
        tcp.remote.read_exact(&mut received).await.unwrap();
        assert_eq!(received, [b'R']);
        tcp.remote.peek(&mut received).await.unwrap();
        assert_eq!(received, [b'X']);
        SockRef::from(&tcp.remote)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(tcp.remote);
        loop {
            match tcp.upload.write(b"y").await {
                Ok(()) => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(error) => break assert_eq!(error, Error::ConnectionReset),
            }
        }
        assert_eq!(tcp.upload.finish().await, Err(Error::ConnectionReset));
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
async fn an_idle_upload_learns_of_a_reset_after_fin() {
    bounded(async {
        let (client, session) = start(&config());
        let (mut tcp, _listener) = connect_tcp(&client, false).await;
        tcp.remote.shutdown().await.unwrap();
        assert_eq!(tcp.download.next().await, None);
        tcp.upload.write(b"RX").await.unwrap();
        let mut received = [0];
        tcp.remote.read_exact(&mut received).await.unwrap();
        tcp.remote.peek(&mut received).await.unwrap();
        SockRef::from(&tcp.remote)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(tcp.remote);
        assert_eq!(tcp.upload.wait_failed().await, Error::ConnectionReset);
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
async fn orderly_close_does_not_fail_the_flow() {
    bounded(async {
        let (client, session) = start(&config());
        let (mut tcp, _listener) = connect_tcp(&client, false).await;
        tcp.remote.shutdown().await.unwrap();
        assert_eq!(tcp.download.next().await, None);
        tokio::time::sleep(Duration::from_millis(200)).await;
        tcp.upload.write(b"x").await.unwrap();
        tcp.upload.finish().await.unwrap();
        let mut received = Vec::new();
        tcp.remote.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"x");
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
async fn reset_is_reported_to_the_download_and_to_finish() {
    bounded(async {
        let (client, session) = start(&config());
        let (mut tcp, _listener) = connect_tcp(&client, false).await;
        SockRef::from(&tcp.remote)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(tcp.remote);
        assert_eq!(tcp.download.next().await, Some(Err(Error::ConnectionReset)));
        assert_eq!(tcp.download.next().await, None);
        assert_eq!(tcp.upload.finish().await, Err(Error::ConnectionReset));
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
async fn requested_inline_urgent_data_stays_in_the_tcp_byte_stream() {
    bounded(async {
        let (client, session) = start(&config());
        let (mut tcp, _listener) = connect_tcp(&client, true).await;
        tcp.remote.write_all(b"ab").await.unwrap();
        SockRef::from(&tcp.remote).send_out_of_band(b"!").unwrap();
        tcp.remote.write_all(b"cd").await.unwrap();
        assert_eq!(read_download(&mut tcp.download, 5).await, b"ab!cd");
        drop((tcp.upload, tcp.download));
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
async fn dropping_every_flow_half_closes_the_broker_socket() {
    bounded(async {
        let (client, session) = start(&config());
        let (tcp, _listener) = connect_tcp(&client, false).await;
        let Tcp {
            upload,
            download,
            mut remote,
        } = tcp;
        drop((upload, download));
        let mut bytes = [0; 1];
        assert!(matches!(remote.read(&mut bytes).await, Ok(0) | Err(_)));
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
async fn dropping_the_download_keeps_the_upload_working() {
    bounded(async {
        let (client, session) = start(&config());
        let (mut tcp, _listener) = connect_tcp(&client, false).await;
        drop(tcp.download);
        tcp.remote.write_all(&vec![1; 600_000]).await.unwrap();
        tcp.upload.write(b"up").await.unwrap();
        let mut received = [0; 2];
        tcp.remote.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"up");
        tcp.upload.finish().await.unwrap();
        finish_session(client, session).await;
    })
    .await;
}

/// A client that never reads stalls the peer after the socket buffers and yamux window fill.
#[tokio::test]
async fn a_non_reading_client_back_pressures_the_peer() {
    bounded(async {
        let (client, session) = start(&config());
        let (mut tcp, _listener) = connect_tcp(&client, false).await;
        SockRef::from(&tcp.remote)
            .set_send_buffer_size(64 << 10)
            .unwrap();
        let mut sent = 0;
        while let Ok(written) =
            tokio::time::timeout(Duration::from_millis(500), tcp.remote.write(&[7; 16 << 10])).await
        {
            sent += written.unwrap();
        }
        assert!(sent > 0 && sent < 3 << 20, "peer sent {sent} bytes");
        let mut received = 0;
        while received < sent {
            received += tcp.download.next().await.unwrap().unwrap().len();
        }
        assert_eq!(received, sent);
        drop((tcp.upload, tcp.download));
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
async fn policy_denials_and_invalid_peers_fail_before_any_connect() {
    bounded(async {
        let (client, session) = start(&config());
        for (peer, error) in [
            ("192.0.2.1:443", Error::AccessDenied),
            ("127.0.0.1:0", Error::InvalidArgument),
            ("[::ffff:127.0.0.1]:80", Error::InvalidArgument),
        ] {
            assert_eq!(
                client.open_tcp(peer.parse().unwrap(), false).await.err(),
                Some(error)
            );
        }
        assert_eq!(client.accept(1).await.err(), Some(Error::AccessDenied));
        assert_eq!(
            client.open_published_udp(1).await.err(),
            Some(Error::AccessDenied)
        );
        assert_eq!(
            client.resolve("denied.test".into()).await,
            Err(Error::AccessDenied)
        );
        assert_eq!(
            client.resolve("static.test".into()).await,
            Ok(vec!["1.1.1.1".parse().unwrap()])
        );
        assert!(client.is_available());
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
async fn open_flows_are_limited_and_released_when_dropped() {
    bounded(async {
        let mut limited = Broker::bind(&config()).unwrap();
        limited.max_resources = 1;
        let (client, session) = start_broker(limited);
        let first = client.open_udp().await.unwrap();
        assert_eq!(client.open_udp().await.err(), Some(Error::LimitExceeded));
        drop(first);
        loop {
            match client.open_udp().await {
                Ok(_) => break,
                Err(error) => {
                    assert_eq!(error, Error::LimitExceeded);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
/// A second accept on the same grant waits for the first instead of failing, so a client that
/// reopens a grant it just dropped never loses it; connections still go to one accept at a time.
async fn accepting_requires_a_loopback_peer_and_queues_accepts_per_grant() {
    bounded(async {
        let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);
        let mut setup = config();
        setup.listeners = vec![PublishedListener {
            grant: 1,
            address,
            transport: ResourceKind::Tcp,
        }];
        let (client, session) = start(&setup);
        let waiting = tokio::spawn({
            let client = client.clone();
            async move { client.accept(1).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let queued = tokio::spawn({
            let client = client.clone();
            async move { client.accept(1).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished() && !queued.is_finished());
        let mut connected = TcpStream::connect(address).await.unwrap();
        let flow = waiting.await.unwrap().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!queued.is_finished());
        let second = TcpStream::connect(address).await.unwrap();
        assert_eq!(
            queued.await.unwrap().unwrap().peer(),
            second.local_addr().unwrap()
        );
        assert_eq!(flow.peer(), connected.local_addr().unwrap());
        let (mut upload, mut download) = flow.split();
        connected.write_all(b"in").await.unwrap();
        assert_eq!(read_download(&mut download, 2).await, b"in");
        upload.write(b"out").await.unwrap();
        let mut received = [0; 3];
        connected.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"out");
        drop((upload, download));
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
async fn cancelling_an_accept_releases_the_grant() {
    // A connection that arrives before the broker sees the reset is taken by the cancelled accept.
    bounded(async {
        let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);
        let mut setup = config();
        setup.listeners = vec![PublishedListener {
            grant: 1,
            address,
            transport: ResourceKind::Tcp,
        }];
        let (client, session) = start(&setup);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.accept(1))
                .await
                .is_err()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (accepted, connected) = tokio::join!(client.accept(1), TcpStream::connect(address));
        accepted.unwrap();
        connected.unwrap();
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
async fn dns_answers_while_many_tcp_flows_are_busy() {
    bounded(async {
        let (client, session) = start(&config());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut flows = Vec::new();
        let mut remotes = Vec::new();
        for _ in 0..64 {
            let (flow, accepted) = tokio::join!(client.open_tcp(address, false), listener.accept());
            let mut remote = accepted.unwrap().0;
            remote.write_all(&vec![1; 64 << 10]).await.unwrap();
            flows.push(flow.unwrap().split());
            remotes.push(remote);
        }
        for (upload, _) in &mut flows {
            upload.write(&[2; 4096]).await.unwrap();
        }
        assert_eq!(
            client.resolve("static.test".into()).await,
            Ok(vec!["1.1.1.1".parse().unwrap()])
        );
        client.open_udp().await.unwrap();
        drop((flows, remotes));
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
async fn resolver_admission_is_released_after_a_timeout() {
    struct Slow;
    impl ToSocketAddrs for Slow {
        type Iter = std::vec::IntoIter<SocketAddr>;

        fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
            std::thread::sleep(Duration::from_millis(2300));
            Ok(Vec::new().into_iter())
        }
    }
    bounded(async {
        let resolvers = Arc::new(Semaphore::new(1));
        let permit = resolvers.clone().try_acquire_owned().unwrap();
        assert_eq!(resolve_addresses(Slow, permit).await, Err(Error::TimedOut));
        assert!(resolvers.clone().try_acquire_owned().is_err());
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(resolvers.try_acquire_owned().is_ok());
    })
    .await;
}

fn datagram(peer: SocketAddr, bytes: Vec<u8>) -> Datagram {
    Datagram { peer, bytes }
}

fn denied_at(index: u32) -> SendFailure {
    SendFailure {
        index,
        error: Error::AccessDenied,
    }
}

/// Queued datagrams arrive in ordered batches, and a denied datagram fails alone by index.
#[tokio::test]
async fn udp_batches_preserve_order_and_report_failures_by_index() {
    bounded(async {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let (client, session) = start(&config());
        let flow = client.open_udp().await.unwrap();
        let datagrams = [address, "192.0.2.1:9".parse().unwrap(), address]
            .into_iter()
            .zip(0..)
            .map(|(peer, index)| datagram(peer, vec![index]))
            .collect();
        assert_eq!(flow.send(datagrams).await, Ok(vec![denied_at(1)]));
        let mut bytes = [0; 8];
        let (_, peer) = socket.recv_from(&mut bytes).await.unwrap();
        assert_eq!(bytes[0], 0);
        socket.recv_from(&mut bytes).await.unwrap();
        assert_eq!(bytes[0], 2);
        let count = u8::try_from(MAX_NETWORK_DATAGRAMS + 8).unwrap();
        for index in 0..count {
            socket.send_to(&[index], peer).await.unwrap();
        }
        let mut received = Vec::new();
        while received.len() < usize::from(count) {
            let batch = flow.receive().await.unwrap();
            assert!(batch.len() <= MAX_NETWORK_DATAGRAMS);
            received.extend(batch.into_iter().map(|datagram| datagram.bytes[0]));
        }
        assert_eq!(received, (0..count).collect::<Vec<_>>());
        drop(flow);
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
async fn udp_preserves_messages_and_drops_truncated_or_unsolicited_datagrams() {
    bounded(async {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (client, session) = start(&config());
        let flow = client.open_udp().await.unwrap();
        assert_eq!(flow.send(vec![datagram(address, vec![])]).await, Ok(vec![]));
        let mut bytes = [0; 8];
        let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
        assert_eq!(length, 0);
        socket.send_to(&[], peer).await.unwrap();
        assert_eq!(flow.receive().await, Ok(vec![datagram(address, vec![])]));
        stranger.send_to(b"unsolicited", peer).await.unwrap();
        for size in [
            MAX_NETWORK_DATAGRAM_BYTES + 1,
            MAX_NETWORK_DATAGRAM_BYTES + 2,
        ] {
            socket.send_to(&vec![0; size], peer).await.unwrap();
        }
        socket.send_to(b"ok", peer).await.unwrap();
        assert_eq!(
            flow.receive().await,
            Ok(vec![datagram(address, b"ok".to_vec())])
        );
        drop(flow);
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
async fn a_cancelled_receive_leaves_its_request_for_the_next_call() {
    bounded(async {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let (client, session) = start(&config());
        let flow = client.open_udp().await.unwrap();
        flow.send(vec![datagram(address, vec![1])]).await.unwrap();
        let (_, peer) = socket.recv_from(&mut [0; 8]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), flow.receive())
                .await
                .is_err()
        );
        socket.send_to(b"late", peer).await.unwrap();
        assert_eq!(
            flow.receive().await,
            Ok(vec![datagram(address, b"late".to_vec())])
        );
        assert!(client.is_available());
        drop(flow);
        finish_session(client, session).await;
    })
    .await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn udp_publication_grants_one_owner_and_only_received_peers() {
    bounded(async {
        for address in [
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
        ] {
            let reserved = std::net::UdpSocket::bind(address).unwrap();
            let published_address = reserved.local_addr().unwrap();
            drop(reserved);
            let reserved_tcp = std::net::TcpListener::bind(address).unwrap();
            let tcp_address = reserved_tcp.local_addr().unwrap();
            drop(reserved_tcp);
            let mut setup = config();
            setup.policy.allow.clear();
            setup.listeners = vec![
                PublishedListener {
                    grant: 1,
                    address: published_address,
                    transport: ResourceKind::Udp,
                },
                PublishedListener {
                    grant: 2,
                    address: tcp_address,
                    transport: ResourceKind::Tcp,
                },
            ];
            let (client, session) = start(&setup);
            for grant in [0, 2, 3] {
                assert_eq!(
                    client.open_published_udp(grant).await.err(),
                    Some(Error::AccessDenied)
                );
            }
            assert_eq!(client.accept(1).await.err(), Some(Error::AccessDenied));
            let flow = client.open_published_udp(1).await.unwrap();
            let waiting_owner = tokio::spawn({
                let client = client.clone();
                async move { client.open_published_udp(1).await }
            });
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(
                !waiting_owner.is_finished(),
                "a second owner waits for the first"
            );
            let peer = UdpSocket::bind(address).await.unwrap();
            let peer_address = peer.local_addr().unwrap();
            let stranger = UdpSocket::bind(address).await.unwrap();
            stranger
                .send_to(&vec![0; MAX_NETWORK_DATAGRAM_BYTES + 2], published_address)
                .await
                .unwrap();
            assert_eq!(
                flow.send(vec![datagram(peer_address, b"unsolicited".to_vec())])
                    .await,
                Ok(vec![denied_at(0)])
            );
            for bytes in [Vec::new(), vec![0x37; MAX_NETWORK_DATAGRAM_BYTES]] {
                peer.send_to(&bytes, published_address).await.unwrap();
                assert_eq!(
                    flow.receive().await,
                    Ok(vec![datagram(peer_address, bytes.clone())])
                );
                assert_eq!(
                    flow.send(vec![datagram(peer_address, bytes.clone())]).await,
                    Ok(vec![])
                );
                let mut response = vec![0; MAX_NETWORK_DATAGRAM_BYTES + 1];
                let (length, sender) = peer.recv_from(&mut response).await.unwrap();
                assert_eq!(sender, published_address);
                assert_eq!(&response[..length], &bytes);
            }
            assert_eq!(
                flow.send(vec![datagram(stranger.local_addr().unwrap(), vec![1])])
                    .await,
                Ok(vec![denied_at(0)])
            );
            drop(flow);
            let replacement = waiting_owner.await.unwrap().unwrap();
            assert_eq!(
                replacement
                    .send(vec![datagram(peer_address, vec![1])])
                    .await,
                Ok(vec![denied_at(0)])
            );
            drop(replacement);
            finish_session(client, session).await;
            assert!(std::net::UdpSocket::bind(published_address).is_ok());
        }
    })
    .await;
}

fn bound_resource(publication_grant: Option<u32>) -> UdpResource {
    UdpResource {
        ipv4: Some(super::udp::bind_udp((Ipv4Addr::LOCALHOST, 0).into()).unwrap()),
        ipv6: None,
        peers: Arc::default(),
        publication_grant,
    }
}

fn test_policy() -> Arc<BoxPolicy> {
    Arc::new(BoxPolicy::new(&config().policy, config().gateways).unwrap())
}

#[tokio::test]
async fn udp_peer_filter_refreshes_recent_peers_and_expires_them() {
    tokio::time::pause();
    let udp = UdpResource {
        ipv4: None,
        ipv6: None,
        peers: Arc::default(),
        publication_grant: Some(1),
    };
    let policy = test_policy();
    let first = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
    let second = SocketAddr::from((Ipv4Addr::LOCALHOST, 2));
    let nearly_expired = UDP_PEER_TTL.checked_sub(Duration::from_secs(1)).unwrap();
    assert!(!udp.authorize_send(&policy, first));
    for port in 1..=u16::try_from(crate::MAX_UDP_PEERS).unwrap() {
        udp.remember_peer(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    }
    tokio::time::advance(nearly_expired).await;
    assert!(udp.knows_peer(first));
    assert!(udp.authorize_send(&policy, first));
    udp.remember_peer(first);
    let newest = SocketAddr::from((Ipv4Addr::LOCALHOST, 100));
    udp.remember_peer(newest);
    assert!(udp.knows_peer(first));
    assert!(!udp.knows_peer(second));
    assert_eq!(udp.peers.lock().unwrap().len(), crate::MAX_UDP_PEERS);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(udp.knows_peer(first));
    assert!(udp.knows_peer(newest));
    assert_eq!(udp.peers.lock().unwrap().len(), 2);
    tokio::time::advance(nearly_expired).await;
    assert!(!udp.knows_peer(first));
    assert!(!udp.authorize_send(&policy, first));
    assert!(!udp.knows_peer(newest));
    assert!(udp.peers.lock().unwrap().is_empty());
}

#[tokio::test]
async fn udp_send_rechecks_peer_expiry_after_waiting_for_socket_readiness() {
    let peer_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer = peer_socket.local_addr().unwrap();
    let udp = bound_resource(Some(1));
    tokio::time::pause();
    udp.remember_peer(peer);
    let mut send = Box::pin(send_datagrams(
        udp,
        test_policy(),
        vec![datagram(peer, vec![1])],
    ));
    assert!(send.as_mut().now_or_never().is_none());
    tokio::time::advance(UDP_PEER_TTL).await;
    assert_eq!(send.await, vec![denied_at(0)]);
    assert_eq!(
        peer_socket.try_recv(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn udp_publication_replies_do_not_extend_peer_expiry() {
    let peer_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer = peer_socket.local_addr().unwrap();
    let udp = bound_resource(Some(1));
    tokio::time::pause();
    udp.remember_peer(peer);
    tokio::time::advance(UDP_PEER_TTL.checked_sub(Duration::from_secs(1)).unwrap()).await;
    let policy = test_policy();
    let reply = vec![datagram(peer, vec![1])];
    assert_eq!(
        send_datagrams(udp.clone(), policy.clone(), reply.clone()).await,
        vec![]
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(send_datagrams(udp, policy, reply).await, vec![denied_at(0)]);
}

#[tokio::test]
async fn udp_policy_expiry_is_rechecked_by_peer_authorization() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NOW: AtomicU64 = AtomicU64::new(0);

    let mut network = config().policy;
    network.allow = vec!["api.test:443".into()];
    let policy =
        BoxPolicy::with_clock(&network, config().gateways, || NOW.load(Ordering::Relaxed)).unwrap();
    let peer = "1.1.1.1:443".parse().unwrap();
    policy.accept_resolved("api.test", &["1.1.1.1".parse().unwrap()]);
    assert!(authorize_peer(&policy, peer));
    NOW.store(60_000_000_000, Ordering::Relaxed);
    assert!(!authorize_peer(&policy, peer));
}

/// Queued replies retain only the datagram bytes covered by the broker's batch budget.
#[tokio::test]
async fn udp_receive_retained_bytes_fit_batch_budget() {
    let udp = bound_resource(None);
    let socket = udp.ipv4.clone().unwrap();
    let sender = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    udp.remember_peer(sender.local_addr().unwrap());
    for length in [0, 1] {
        let payload = vec![0x37; length];
        for _ in 0..MAX_NETWORK_DATAGRAMS {
            sender
                .send_to(&payload, socket.local_addr().unwrap())
                .unwrap();
        }
        let batch = tokio::time::timeout(
            Duration::from_secs(1),
            receive_datagrams(udp.clone(), test_policy()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(batch.len(), MAX_NETWORK_DATAGRAMS);
        assert!(batch.iter().all(|datagram| datagram.bytes == payload));
        let retained_bytes: usize = batch
            .iter()
            .map(|datagram| datagram.bytes.capacity() + DATAGRAM_FRAME_OVERHEAD_BYTES)
            .sum();
        assert!(retained_bytes <= MAX_NETWORK_DATAGRAM_BATCH_BYTES);
    }
}

/// Rejected traffic yields even with readable sockets, while accepted datagrams keep their order.
#[tokio::test]
async fn udp_receive_rejections_yield_before_and_after_first_datagram() {
    for (has_prefix, is_oversized) in [(false, false), (true, false), (false, true)] {
        let udp = bound_resource(None);
        let socket = udp.ipv4.clone().unwrap();
        let sender = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let stranger = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let peer = sender.local_addr().unwrap();
        udp.remember_peer(peer);
        let destination = socket.local_addr().unwrap();
        let mut expected = Vec::new();
        if has_prefix {
            sender.send_to(b"first", destination).unwrap();
            socket.peek_from(&mut [0; 5]).await.unwrap();
            expected.push(datagram(peer, b"first".to_vec()));
        }
        for _ in 0..=MAX_NETWORK_DATAGRAMS {
            if is_oversized {
                sender
                    .send_to(&[0; MAX_NETWORK_DATAGRAM_BYTES + 1], destination)
                    .unwrap();
            } else {
                stranger.send_to(b"rejected", destination).unwrap();
            }
        }
        socket.readable().await.unwrap();
        let policy = test_policy();
        let mut receive = Box::pin(receive_datagrams(udp.clone(), policy.clone()));
        let mut received = Vec::new();
        if let Some(completed) = receive.as_mut().now_or_never() {
            let batch = completed.unwrap();
            assert_eq!(batch, expected);
            received.extend(batch);
            receive = Box::pin(receive_datagrams(udp.clone(), policy.clone()));
        }
        let mut rejected = [0; MAX_NETWORK_DATAGRAM_BYTES + 1];
        let (length, rejected_peer) =
            tokio::time::timeout(Duration::from_secs(1), socket.peek_from(&mut rejected))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            rejected_peer,
            if is_oversized {
                peer
            } else {
                stranger.local_addr().unwrap()
            }
        );
        assert_eq!(
            length,
            if is_oversized {
                MAX_NETWORK_DATAGRAM_BYTES + 1
            } else {
                b"rejected".len()
            }
        );
        assert!(receive.as_mut().now_or_never().is_none());
        sender.send_to(b"last", destination).unwrap();
        expected.push(datagram(peer, b"last".to_vec()));
        while received.len() < expected.len() {
            let batch = tokio::time::timeout(Duration::from_secs(1), &mut receive)
                .await
                .unwrap()
                .unwrap();
            assert!(!batch.is_empty() && batch.len() <= MAX_NETWORK_DATAGRAMS);
            received.extend(batch);
            if received.len() < expected.len() {
                receive = Box::pin(receive_datagrams(udp.clone(), policy.clone()));
            }
        }
        assert_eq!(received, expected);
    }
}

#[tokio::test]
async fn a_client_that_leaves_ends_the_session_and_frees_published_sockets() {
    bounded(async {
        let (client, session) = start(&config());
        let (tcp, _listener) = connect_tcp(&client, false).await;
        drop(tcp.remote);
        let waiting = tokio::spawn({
            let client = client.clone();
            async move { client.accept(1).await.err() }
        });
        client.disconnect();
        assert_eq!(waiting.await.unwrap(), Some(Error::Closed));
        drop((tcp.upload, tcp.download));
        assert!(!client.is_available());
        drop(client);
        assert!(session.await.unwrap().is_ok());
    })
    .await;
}

/// Closing a published UDP flow releases its grant at once even while another handle still holds
/// the flow (the runtime's receive stream does), so the frontend's immediate reopen succeeds.
#[tokio::test]
async fn closing_a_shared_udp_publication_lets_it_reopen_at_once() {
    bounded(async {
        let reserved = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let published_address = reserved.local_addr().unwrap();
        drop(reserved);
        let mut setup = config();
        setup.listeners = vec![PublishedListener {
            grant: 1,
            address: published_address,
            transport: ResourceKind::Udp,
        }];
        let (client, session) = start(&setup);
        let flow = client.open_published_udp(1).await.unwrap();
        let still_held = flow.clone();
        let receiving = tokio::spawn(async move { still_held.receive().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        flow.close();
        let reopened = tokio::time::timeout(Duration::from_secs(2), client.open_published_udp(1))
            .await
            .expect("the closed flow released its grant")
            .unwrap();
        assert_eq!(receiving.await.unwrap(), Err(Error::Closed));
        drop((flow, reopened));
        finish_session(client, session).await;
    })
    .await;
}
