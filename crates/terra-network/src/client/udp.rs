//! One UDP flow: pull-based send and receive requests with one outstanding of each.

use super::Client;
use crate::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use terra_protocol::network::{
    Datagram, MAX_NETWORK_DATAGRAM_BATCH_BYTES, MAX_NETWORK_DATAGRAM_BYTES, MAX_NETWORK_DATAGRAMS,
    MAX_NETWORK_FRAME_BYTES, SendFailure, UdpReply, UdpRequest,
};
use tokio::io::{AsyncWriteExt, ReadHalf};
use tokio::sync::{Mutex, mpsc};
use tokio_util::compat::Compat;
use tokio_util::sync::CancellationToken;

/// Replies of one request kind. The flag is set from the request until its reply is consumed.
struct Replies<T> {
    queue: Mutex<mpsc::Receiver<T>>,
    is_outstanding: Arc<AtomicBool>,
}

struct Inner {
    client: Client,
    requests: mpsc::Sender<Vec<u8>>,
    closed: CancellationToken,
    failure: Arc<OnceLock<Error>>,
    sent: Replies<Vec<SendFailure>>,
    received: Replies<Vec<Datagram>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.closed.cancel();
    }
}

/// Cloneable handle. Calls of the same kind queue behind each other; a dropped call leaves its
/// request outstanding, and the next call of that kind picks up its reply.
#[derive(Clone)]
pub struct UdpFlow(Arc<Inner>);

struct Routes {
    sent: mpsc::Sender<Vec<SendFailure>>,
    is_send_outstanding: Arc<AtomicBool>,
    received: mpsc::Sender<Vec<Datagram>>,
    is_receive_outstanding: Arc<AtomicBool>,
}

impl UdpFlow {
    pub(super) fn start(client: &Client, stream: Compat<yamux::Stream>) -> Self {
        let (requests, request_queue) = mpsc::channel(2);
        let (sent, sent_queue) = mpsc::channel(1);
        let (received, received_queue) = mpsc::channel(1);
        let is_send_outstanding = Arc::new(AtomicBool::new(false));
        let is_receive_outstanding = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(OnceLock::new());
        let closed = CancellationToken::new();
        tokio::spawn(run(
            client.clone(),
            stream,
            request_queue,
            closed.clone(),
            failure.clone(),
            Routes {
                sent,
                is_send_outstanding: is_send_outstanding.clone(),
                received,
                is_receive_outstanding: is_receive_outstanding.clone(),
            },
        ));
        Self(Arc::new(Inner {
            client: client.clone(),
            requests,
            closed,
            failure,
            sent: Replies {
                queue: Mutex::new(sent_queue),
                is_outstanding: is_send_outstanding,
            },
            received: Replies {
                queue: Mutex::new(received_queue),
                is_outstanding: is_receive_outstanding,
            },
        }))
    }

    /// Resets the flow now, even while other handles or calls still hold it.
    pub fn close(&self) {
        self.0.closed.cancel();
    }

    /// Returns the datagrams that were not sent, by index.
    pub async fn send(&self, datagrams: Vec<Datagram>) -> Result<Vec<SendFailure>, Error> {
        let count = datagrams.len();
        let mut replies = self.0.sent.queue.lock().await;
        if self.0.sent.is_outstanding.load(Ordering::SeqCst) {
            replies.recv().await.ok_or_else(|| self.ended())?;
            self.0.sent.is_outstanding.store(false, Ordering::SeqCst);
        }
        let frame = encode(&UdpRequest::Send(datagrams))?;
        self.0.sent.is_outstanding.store(true, Ordering::SeqCst);
        self.0
            .requests
            .send(frame)
            .await
            .map_err(|_| self.ended())?;
        let failures = replies.recv().await.ok_or_else(|| self.ended())?;
        self.0.sent.is_outstanding.store(false, Ordering::SeqCst);
        if failures
            .windows(2)
            .all(|pair| pair[0].index < pair[1].index)
            && failures
                .last()
                .is_none_or(|failure| (failure.index as usize) < count)
        {
            Ok(failures)
        } else {
            Err(self.0.client.reject_broker())
        }
    }

    pub async fn receive(&self) -> Result<Vec<Datagram>, Error> {
        let mut replies = self.0.received.queue.lock().await;
        if !self.0.received.is_outstanding.swap(true, Ordering::SeqCst) {
            self.0
                .requests
                .send(encode(&UdpRequest::Receive)?)
                .await
                .map_err(|_| self.ended())?;
        }
        let datagrams = replies.recv().await.ok_or_else(|| self.ended())?;
        self.0
            .received
            .is_outstanding
            .store(false, Ordering::SeqCst);
        if is_valid_batch(&datagrams) {
            Ok(datagrams)
        } else {
            Err(self.0.client.reject_broker())
        }
    }

    /// The broker's failure that ended the flow, else `Closed`.
    fn ended(&self) -> Error {
        self.0.failure.get().copied().unwrap_or(Error::Closed)
    }
}

fn encode(request: &UdpRequest) -> Result<Vec<u8>, Error> {
    terra_protocol::encode_frame_with_limit(request, MAX_NETWORK_FRAME_BYTES)
        .map_err(|_| Error::InvalidArgument)
}

fn is_valid_batch(datagrams: &[Datagram]) -> bool {
    !datagrams.is_empty()
        && datagrams.len() <= MAX_NETWORK_DATAGRAMS
        && datagrams.iter().map(Datagram::batch_bytes).sum::<usize>()
            <= MAX_NETWORK_DATAGRAM_BATCH_BYTES
        && datagrams.iter().all(|Datagram { peer, bytes }| {
            bytes.len() <= MAX_NETWORK_DATAGRAM_BYTES
                && peer.port() != 0
                && peer.ip() == peer.ip().to_canonical()
        })
}

type StreamRead = ReadHalf<Compat<yamux::Stream>>;

async fn read_reply(mut read: StreamRead) -> (StreamRead, std::io::Result<Option<UdpReply>>) {
    let reply = crate::frames::read_frame::<UdpReply>(&mut read).await;
    (read, reply)
}

/// Owns the stream: writes queued request frames whole and delivers each reply to the waiting call
/// of its kind. Returning drops the stream, which resets the flow at the broker.
async fn run(
    client: Client,
    stream: Compat<yamux::Stream>,
    mut requests: mpsc::Receiver<Vec<u8>>,
    closed: CancellationToken,
    failure: Arc<OnceLock<Error>>,
    routes: Routes,
) {
    let (read, mut write) = tokio::io::split(stream);
    let mut reply = Box::pin(read_reply(read));
    loop {
        tokio::select! {
            () = client.0.closed.cancelled() => return,
            () = closed.cancelled() => return,
            frame = requests.recv() => {
                let Some(frame) = frame else { return };
                if write.write_all(&frame).await.is_err() {
                    return;
                }
            }
            (read, result) = &mut reply => {
                let is_routed = match result {
                    Ok(Some(UdpReply::Sent(failures))) => {
                        routes.is_send_outstanding.load(Ordering::SeqCst)
                            && routes.sent.try_send(failures).is_ok()
                    }
                    Ok(Some(UdpReply::Datagrams(datagrams))) => {
                        routes.is_receive_outstanding.load(Ordering::SeqCst)
                            && routes.received.try_send(datagrams).is_ok()
                    }
                    Ok(Some(UdpReply::Failed(error))) => {
                        let _ = failure.set(error);
                        return;
                    }
                    Ok(None) => return,
                    Err(error) if error.kind() != std::io::ErrorKind::InvalidData => return,
                    Err(_) => false,
                };
                if !is_routed {
                    client.disconnect();
                    return;
                }
                reply = Box::pin(read_reply(read));
            }
        }
    }
}
