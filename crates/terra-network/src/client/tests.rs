//! Client behavior against a hand-driven broker that sends malformed or unexpected frames.

use super::*;
use std::future::poll_fn;
use std::time::Duration;
use terra_protocol::network::{Datagram, SendFailure, TcpEvent, UdpReply, UdpRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

type BrokerStream = Compat<yamux::Stream>;

struct FakeBroker {
    streams: mpsc::UnboundedReceiver<yamux::Stream>,
    outbound: mpsc::Sender<oneshot::Sender<yamux::Stream>>,
}

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("test stalled")
}

fn fake_broker() -> (Client, FakeBroker) {
    let (worker, endpoint) = tokio::io::duplex(1 << 20);
    let (inbound, streams) = mpsc::unbounded_channel();
    let (outbound, mut outbound_requests) = mpsc::channel::<oneshot::Sender<yamux::Stream>>(1);
    tokio::spawn(async move {
        let mut connection = crate::mux::connect(endpoint, yamux::Mode::Server);
        loop {
            tokio::select! {
                stream = poll_fn(|cx| connection.poll_next_inbound(cx)) => match stream {
                    Some(Ok(stream)) => drop(inbound.send(stream)),
                    _ => return,
                },
                Some(reply) = outbound_requests.recv() => {
                    if let Ok(stream) = poll_fn(|cx| connection.poll_new_outbound(cx)).await {
                        drop(reply.send(stream));
                    }
                }
            }
        }
    });
    (Client::new(worker), FakeBroker { streams, outbound })
}

impl FakeBroker {
    /// Accepts the next stream, reads its `Open`, and answers with `reply`.
    async fn answer(&mut self, reply: Result<Opened, Error>) -> (Open, BrokerStream) {
        let mut stream = self.streams.recv().await.unwrap().compat();
        let open = crate::frames::read_frame::<Open>(&mut stream)
            .await
            .unwrap()
            .unwrap();
        crate::frames::write_frame(&mut stream, &reply)
            .await
            .unwrap();
        (open, stream)
    }
}

const PEER: &str = "127.0.0.1:9";

async fn assert_disconnected(client: &Client) {
    bounded(client.wait_closed()).await;
    assert!(!client.is_available());
    assert_eq!(client.open_udp().await.err(), Some(Error::Closed));
}

#[tokio::test]
/// The flow validates each event when it reads it, so reading the flow disconnects the client.
async fn malformed_or_out_of_order_tcp_events_disconnect_the_client() {
    let oversized = u32::MAX.to_le_bytes().to_vec();
    let frame = |event: TcpEvent| terra_protocol::encode_frame(&event).unwrap();
    for events in [
        vec![frame(TcpEvent::Data(vec![]))],
        vec![frame(TcpEvent::Eof), frame(TcpEvent::Eof)],
        vec![frame(TcpEvent::Eof), frame(TcpEvent::Data(vec![1]))],
        vec![frame(TcpEvent::WriteShutdown(Ok(())))],
        vec![oversized],
        vec![vec![1, 0, 0, 0, 0xee]],
    ] {
        bounded(async {
            let (client, mut broker) = fake_broker();
            let peer: SocketAddr = PEER.parse().unwrap();
            let (flow, (_, mut stream)) = tokio::join!(
                async { client.open_tcp(peer, false).await.unwrap() },
                broker.answer(Ok(Opened::Tcp { peer }))
            );
            let (mut upload, mut download) = flow.split();
            for bytes in events {
                stream.write_all(&bytes).await.unwrap();
            }
            while download.next().await.is_some_and(|event| event.is_ok()) {}
            assert_eq!(upload.write(b"x").await, Err(Error::Closed));
            assert_disconnected(&client).await;
        })
        .await;
    }
}

#[tokio::test]
async fn open_replies_that_do_not_match_the_request_disconnect_the_client() {
    let loopback: SocketAddr = PEER.parse().unwrap();
    for (open_reply, is_accept) in [
        (
            Opened::Tcp {
                peer: "127.0.0.1:10".parse().unwrap(),
            },
            false,
        ),
        (Opened::Udp, false),
        (
            Opened::Tcp {
                peer: "192.0.2.1:9".parse().unwrap(),
            },
            true,
        ),
        (
            Opened::Tcp {
                peer: "127.0.0.1:0".parse().unwrap(),
            },
            true,
        ),
    ] {
        bounded(async {
            let (client, mut broker) = fake_broker();
            let (result, _) = tokio::join!(
                async {
                    if is_accept {
                        client.accept(1).await
                    } else {
                        client.open_tcp(loopback, false).await
                    }
                    .err()
                },
                broker.answer(Ok(open_reply.clone()))
            );
            assert_eq!(result, Some(Error::Closed));
            assert_disconnected(&client).await;
        })
        .await;
    }
    bounded(async {
        let (client, mut broker) = fake_broker();
        let (result, _) = tokio::join!(
            client.resolve("a.test".into()),
            broker.answer(Ok(Opened::Resolved(vec![])))
        );
        assert_eq!(result, Err(Error::Closed));
        assert_disconnected(&client).await;
    })
    .await;
}

#[tokio::test]
async fn broker_errors_are_returned_without_disconnecting() {
    bounded(async {
        let (client, mut broker) = fake_broker();
        let (result, (open, _)) = tokio::join!(
            client.open_tcp(PEER.parse().unwrap(), true),
            broker.answer(Err(Error::AccessDenied))
        );
        assert_eq!(result.err(), Some(Error::AccessDenied));
        assert_eq!(
            open,
            Open::Tcp {
                peer: PEER.parse().unwrap(),
                inline_urgent: true
            }
        );
        assert!(client.is_available());
    })
    .await;
}

#[tokio::test]
async fn unrequested_or_empty_udp_replies_disconnect_the_client() {
    let datagram = Datagram {
        peer: PEER.parse().unwrap(),
        bytes: vec![1],
    };
    for reply in [UdpReply::Sent(vec![]), UdpReply::Datagrams(vec![datagram])] {
        bounded(async {
            let (client, mut broker) = fake_broker();
            let (_flow, (_, mut stream)) = tokio::join!(
                async { client.open_udp().await.unwrap() },
                broker.answer(Ok(Opened::Udp))
            );
            crate::frames::write_frame(&mut stream, &reply)
                .await
                .unwrap();
            assert_disconnected(&client).await;
        })
        .await;
    }
    bounded(async {
        let (client, mut broker) = fake_broker();
        let (flow, (_, mut stream)) = tokio::join!(
            async { client.open_udp().await.unwrap() },
            broker.answer(Ok(Opened::Udp))
        );
        let receiving = tokio::spawn(async move { flow.receive().await });
        let request = crate::frames::read_frame::<UdpRequest>(&mut stream)
            .await
            .unwrap();
        assert_eq!(request, Some(UdpRequest::Receive));
        crate::frames::write_frame(&mut stream, &UdpReply::Datagrams(vec![]))
            .await
            .unwrap();
        assert_eq!(receiving.await.unwrap(), Err(Error::Closed));
        assert_disconnected(&client).await;
    })
    .await;
}

#[tokio::test]
async fn out_of_range_send_failures_disconnect_the_client() {
    bounded(async {
        let (client, mut broker) = fake_broker();
        let (flow, (_, mut stream)) = tokio::join!(
            async { client.open_udp().await.unwrap() },
            broker.answer(Ok(Opened::Udp))
        );
        let datagram = Datagram {
            peer: PEER.parse().unwrap(),
            bytes: vec![1],
        };
        let sending = tokio::spawn(async move { flow.send(vec![datagram]).await });
        let request = crate::frames::read_frame::<UdpRequest>(&mut stream)
            .await
            .unwrap();
        assert!(matches!(request, Some(UdpRequest::Send(_))));
        let reply = UdpReply::Sent(vec![SendFailure {
            index: 1,
            error: Error::Io,
        }]);
        crate::frames::write_frame(&mut stream, &reply)
            .await
            .unwrap();
        assert_eq!(sending.await.unwrap(), Err(Error::Closed));
        assert_disconnected(&client).await;
    })
    .await;
}

#[tokio::test]
async fn a_stream_opened_by_the_broker_disconnects_the_client() {
    bounded(async {
        let (client, broker) = fake_broker();
        let (reply, stream) = oneshot::channel();
        broker.outbound.send(reply).await.unwrap();
        let mut stream = stream.await.unwrap().compat();
        stream.write_all(b"x").await.unwrap();
        assert_disconnected(&client).await;
    })
    .await;
}

#[tokio::test]
async fn disconnecting_fails_pending_calls() {
    bounded(async {
        let (client, mut broker) = fake_broker();
        let pending = tokio::spawn({
            let client = client.clone();
            async move { client.resolve("slow.test".into()).await }
        });
        let mut stream = broker.streams.recv().await.unwrap().compat();
        let _ = stream.read(&mut [0; 1]).await.unwrap();
        client.disconnect();
        assert_eq!(pending.await.unwrap(), Err(Error::Closed));
        assert_eq!(
            client.open_tcp(PEER.parse().unwrap(), false).await.err(),
            Some(Error::Closed)
        );
    })
    .await;
}

#[tokio::test]
async fn a_broker_failure_ends_the_udp_flow_with_its_error() {
    bounded(async {
        let (client, mut broker) = fake_broker();
        let (flow, (_, mut stream)) = tokio::join!(
            async { client.open_udp().await.unwrap() },
            broker.answer(Ok(Opened::Udp))
        );
        let receiving = tokio::spawn({
            let flow = flow.clone();
            async move { flow.receive().await }
        });
        let request = crate::frames::read_frame::<UdpRequest>(&mut stream)
            .await
            .unwrap();
        assert_eq!(request, Some(UdpRequest::Receive));
        crate::frames::write_frame(&mut stream, &UdpReply::Failed(Error::Io))
            .await
            .unwrap();
        assert_eq!(receiving.await.unwrap(), Err(Error::Io));
        assert_eq!(flow.receive().await, Err(Error::Io));
        assert_eq!(flow.send(vec![]).await, Err(Error::Io));
        assert!(client.is_available());
    })
    .await;
}
