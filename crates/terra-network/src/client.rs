use crate::{Error, Handle, Operation, Reply, ResourceKind};
use futures_util::future::BoxFuture;
use futures_util::stream::{self, StreamExt};
use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use terra_protocol::network::{
    Datagram, MAX_NETWORK_CHUNK_BYTES, MAX_NETWORK_DATAGRAM_BATCH_BYTES,
    MAX_NETWORK_DATAGRAM_BYTES, MAX_NETWORK_DATAGRAMS, MAX_NETWORK_FRAME_BYTES,
    MAX_NETWORK_READ_BYTES, Request, RequestId, Response, UNBOUND_UDP_PEER,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Client(Arc<Connection>);

pub struct WriteAdmission {
    client: Client,
    permit: OwnedSemaphorePermit,
}

impl WriteAdmission {
    /// Accepts an owned chunk; dropping its reply future does not cancel the write.
    pub fn start(
        self,
        handle: Handle,
        bytes: Vec<u8>,
    ) -> Result<BoxFuture<'static, Result<(), Error>>, Error> {
        let Self { client, permit } = self;
        if !client.is_available() {
            return Err(Error::Closed);
        }
        if bytes.len() > MAX_NETWORK_CHUNK_BYTES {
            return Err(Error::InvalidArgument);
        }
        let id = allocate_id(&client.0.ids)?;
        let (response, receiver) = oneshot::channel();
        client
            .0
            .commands
            .try_send(Command {
                request: Request {
                    id,
                    operation: Operation::WriteAll { handle, bytes },
                },
                response: Some(response),
                request_admission: Some(permit),
            })
            .map_err(|_| Error::LimitExceeded)?;
        Ok(Box::pin(async move {
            let delivery = tokio::select! {
                delivery = receiver => delivery.ok(),
                () = client.0.closed.cancelled() => None,
            };
            match delivery.and_then(|mut delivery| delivery.result.take()) {
                Some(Ok(Reply::Written(_))) => Ok(()),
                Some(Err(error)) => Err(error),
                Some(Ok(
                    Reply::Opened { .. }
                    | Reply::Data(_)
                    | Reply::Eof
                    | Reply::Datagrams(_)
                    | Reply::Resolved(_)
                    | Reply::Cancelled(_)
                    | Reply::Done
                    | Reply::Sent(_),
                ))
                | None => Err(Error::Closed),
            }
        }))
    }
}

struct Connection {
    commands: mpsc::Sender<Command>,
    ids: Arc<AtomicU64>,
    admission: Arc<Semaphore>,
    socket_wait_admission: Arc<Semaphore>,
    dns_admission: Arc<Semaphore>,
    closed: CancellationToken,
}

struct Command {
    request: Request,
    response: Option<oneshot::Sender<Delivery>>,
    request_admission: Option<OwnedSemaphorePermit>,
}

struct Waiter {
    expected_reply: ExpectedReply,
    response: Option<oneshot::Sender<Delivery>>,
    _request_admission: Option<OwnedSemaphorePermit>,
}

#[derive(Clone, Copy)]
enum ExpectedReply {
    Opened {
        kind: ResourceKind,
        peer: SocketAddr,
    },
    Accepted,
    Read(u32),
    WrittenAll(usize),
    Datagrams,
    Sent(usize),
    Resolved,
    Done,
    Cancelled,
}

impl From<&Operation> for ExpectedReply {
    fn from(operation: &Operation) -> Self {
        match operation {
            Operation::OpenTcp {
                peer,
                inline_urgent: _,
            } => Self::Opened {
                kind: ResourceKind::Tcp,
                peer: *peer,
            },
            Operation::OpenUdp | Operation::OpenPublishedUdp(_) => Self::Opened {
                kind: ResourceKind::Udp,
                peer: UNBOUND_UDP_PEER,
            },
            Operation::Accept(_) => Self::Accepted,
            Operation::Read { max_bytes, .. } => Self::Read(*max_bytes),
            Operation::WriteAll { bytes, .. } => Self::WrittenAll(bytes.len()),
            Operation::ReceiveDatagram(_) => Self::Datagrams,
            Operation::SendDatagrams { datagrams, .. } => Self::Sent(datagrams.len()),
            Operation::Resolve(_) => Self::Resolved,
            Operation::ShutdownWrite(_) | Operation::Close(_) | Operation::WaitError(_) => {
                Self::Done
            }
            Operation::Cancel(_) => Self::Cancelled,
        }
    }
}

struct Delivery {
    result: Option<Result<Reply, Error>>,
    controls: mpsc::Sender<Command>,
    ids: Arc<AtomicU64>,
    closed: CancellationToken,
}

impl Drop for Delivery {
    fn drop(&mut self) {
        if let Some(Ok(Reply::Opened { handle, .. })) = self.result.take() {
            let result = allocate_id(&self.ids).and_then(|id| {
                self.controls
                    .try_send(Command {
                        request: Request {
                            id,
                            operation: Operation::Close(handle),
                        },
                        response: None,
                        request_admission: None,
                    })
                    .map_err(|_| Error::LimitExceeded)
            });
            if result.is_err() {
                self.closed.cancel();
            }
        }
    }
}

struct CancelOnDrop {
    client: Client,
    id: RequestId,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.id != 0 {
            self.client.send_control(Operation::Cancel(self.id));
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.closed.cancel();
    }
}

impl Client {
    #[must_use]
    pub fn new(channel: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) -> Self {
        let (commands, receiver) = mpsc::channel(crate::MAX_PENDING_REQUESTS);
        let ids = Arc::new(AtomicU64::new(1));
        let closed = CancellationToken::new();
        tokio::spawn(run_connection(
            channel,
            receiver,
            commands.clone(),
            ids.clone(),
            closed.clone(),
        ));
        Self(Arc::new(Connection {
            commands,
            ids,
            admission: Arc::new(Semaphore::new(crate::MAX_NON_DNS_REQUESTS)),
            socket_wait_admission: Arc::new(Semaphore::new(crate::MAX_SOCKET_WAIT_REQUESTS)),
            dns_admission: Arc::new(Semaphore::new(crate::MAX_DNS_REQUESTS)),
            closed,
        }))
    }

    #[must_use]
    pub fn is_available(&self) -> bool {
        !self.0.closed.is_cancelled()
    }

    pub async fn wait_closed(&self) {
        self.0.closed.cancelled().await;
    }

    pub fn disconnect(&self) {
        self.0.closed.cancel();
    }

    /// Dropping the returned future cancels the request at the broker.
    pub async fn request(&self, operation: Operation) -> Result<Reply, Error> {
        if !self.is_available() {
            return Err(Error::Closed);
        }
        let admission = match crate::RequestAdmission::from(&operation) {
            crate::RequestAdmission::SocketWait => &self.0.socket_wait_admission,
            crate::RequestAdmission::Dns => &self.0.dns_admission,
            crate::RequestAdmission::Active => &self.0.admission,
        };
        let permit = if matches!(
            operation,
            Operation::OpenPublishedUdp(_)
                | Operation::Accept(_)
                | Operation::Read { .. }
                | Operation::ReceiveDatagram(_)
                | Operation::WaitError(_)
                | Operation::ShutdownWrite(_)
        ) {
            tokio::select! {
                biased;
                () = self.0.closed.cancelled() => return Err(Error::Closed),
                permit = admission.clone().acquire_owned() => permit.map_err(|_| Error::Closed)?,
            }
        } else {
            admission
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::LimitExceeded)?
        };
        let id = allocate_id(&self.0.ids)?;
        let (response, receiver) = oneshot::channel();
        self.0
            .commands
            .try_send(Command {
                request: Request { id, operation },
                response: Some(response),
                request_admission: Some(permit),
            })
            .map_err(|_| Error::LimitExceeded)?;
        let mut guard = CancelOnDrop {
            client: self.clone(),
            id,
        };
        let result = tokio::select! {
            result = receiver => result.ok(),
            () = self.0.closed.cancelled() => None,
        };
        guard.id = 0;
        result
            .and_then(|mut delivery| delivery.result.take())
            .unwrap_or(Err(Error::Closed))
    }

    pub fn try_reserve_write_all(&self) -> Result<WriteAdmission, Error> {
        if !self.is_available() {
            return Err(Error::Closed);
        }
        let permit = self
            .0
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::LimitExceeded)?;
        Ok(WriteAdmission {
            client: self.clone(),
            permit,
        })
    }

    pub fn reserve_write_all(&self) -> BoxFuture<'static, Result<WriteAdmission, Error>> {
        let client = self.clone();
        Box::pin(async move {
            let permit = tokio::select! {
                permit = client.0.admission.clone().acquire_owned() => {
                    permit.map_err(|_| Error::Closed)?
                }
                () = client.0.closed.cancelled() => return Err(Error::Closed),
            };
            Ok(WriteAdmission { client, permit })
        })
    }

    pub fn close(&self, handle: Handle) {
        self.send_control(Operation::Close(handle));
    }

    fn send_control(&self, operation: Operation) {
        if self.is_available() {
            let result = allocate_id(&self.0.ids).and_then(|id| {
                self.0
                    .commands
                    .try_send(Command {
                        request: Request { id, operation },
                        response: None,
                        request_admission: None,
                    })
                    .map_err(|_| Error::LimitExceeded)
            });
            if result.is_err() {
                self.disconnect();
            }
        }
    }
}

fn allocate_id(ids: &AtomicU64) -> Result<RequestId, Error> {
    ids.try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .map_err(|_| Error::LimitExceeded)
}

async fn run_connection(
    channel: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    mut commands: mpsc::Receiver<Command>,
    controls: mpsc::Sender<Command>,
    ids: Arc<AtomicU64>,
    closed: CancellationToken,
) {
    let (read, mut write) = tokio::io::split(channel);
    let read = tokio::io::BufReader::with_capacity(crate::IPC_READ_BUFFER_BYTES, read);
    let replies = stream::unfold(read, |mut read| async move {
        let response = terra_protocol::read_frame_async_with_limit::<Response>(
            &mut read,
            MAX_NETWORK_FRAME_BYTES,
        )
        .await;
        Some((response, read))
    });
    tokio::pin!(replies);
    let (outgoing, mut frames) = mpsc::channel::<Vec<u8>>(crate::MAX_QUEUED_REQUESTS);
    let writer_closed = closed.clone();
    let writer = tokio::spawn(async move {
        let _ = crate::writer::write_queued_frames(&mut write, &mut frames, Ok).await;
        writer_closed.cancel();
    });
    let mut pending = BTreeMap::<RequestId, Waiter>::new();
    let mut last_handle = 0;
    loop {
        tokio::select! {
            () = closed.cancelled() => break,
            command = commands.recv(), if outgoing.capacity() > 0 => {
                let Some(command) = command else { break; };
                if queue_request(command, &outgoing, &mut pending).is_err() { break; }
            }
            capacity = outgoing.reserve(), if outgoing.capacity() == 0 => {
                if capacity.is_err() { break; }
            }
            reply = replies.next() => {
                let Some(Ok(Some(response))) = reply else { break; };
                let Some(waiter) = pending.remove(&response.id) else { break; };
                if !validate_reply(&waiter.expected_reply, &response.result, &mut last_handle) { break; }
                let delivery = Delivery { result: Some(response.result), controls: controls.clone(), ids: ids.clone(), closed: closed.clone() };
                if let Some(sender) = waiter.response {
                    let _ = sender.send(delivery);
                }
            }
        }
    }
    closed.cancel();
    writer.abort();
    let _ = writer.await;
}

fn queue_request(
    command: Command,
    outgoing: &mpsc::Sender<Vec<u8>>,
    pending: &mut BTreeMap<RequestId, Waiter>,
) -> io::Result<()> {
    if pending.len() == crate::MAX_PENDING_REQUESTS {
        return Err(io::Error::other("broker client pending budget exhausted"));
    }
    let frame = terra_protocol::encode_frame_with_limit(&command.request, MAX_NETWORK_FRAME_BYTES)?;
    outgoing
        .try_send(frame)
        .map_err(|_| io::Error::other("broker client writer queue exhausted"))?;
    pending.insert(
        command.request.id,
        Waiter {
            expected_reply: ExpectedReply::from(&command.request.operation),
            response: command.response,
            _request_admission: command.request_admission,
        },
    );
    Ok(())
}

fn validate_reply(
    expected_reply: &ExpectedReply,
    result: &Result<Reply, Error>,
    last_handle: &mut Handle,
) -> bool {
    let Ok(reply) = result else {
        return true;
    };
    match (expected_reply, reply) {
        (
            ExpectedReply::Opened {
                kind: expected_kind,
                peer: expected_peer,
            },
            Reply::Opened { handle, kind, peer },
        ) => {
            if kind != expected_kind || peer != expected_peer || *handle <= *last_handle {
                return false;
            }
            *last_handle = *handle;
            true
        }
        (
            ExpectedReply::Accepted,
            Reply::Opened {
                handle,
                kind: ResourceKind::Tcp,
                peer,
            },
        ) => {
            if *handle <= *last_handle || !peer.ip().is_loopback() || peer.port() == 0 {
                return false;
            }
            *last_handle = *handle;
            true
        }
        (ExpectedReply::Read(max_bytes), Reply::Data(bytes)) => {
            !bytes.is_empty()
                && bytes.len() <= *max_bytes as usize
                && bytes.len() <= MAX_NETWORK_READ_BYTES
        }
        (ExpectedReply::WrittenAll(expected_bytes), Reply::Written(length)) => {
            *length as usize == *expected_bytes
        }
        (ExpectedReply::Datagrams, Reply::Datagrams(datagrams)) => {
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
        (ExpectedReply::Sent(count), Reply::Sent(failures)) => {
            failures
                .windows(2)
                .all(|pair| pair[0].index < pair[1].index)
                && failures
                    .last()
                    .is_none_or(|failure| (failure.index as usize) < *count)
        }
        (ExpectedReply::Resolved, Reply::Resolved(addresses)) => {
            !addresses.is_empty()
                && addresses.len() <= terra_protocol::network::MAX_NETWORK_ADDRESSES
                && addresses.iter().all(|ip| *ip == ip.to_canonical())
        }
        (ExpectedReply::Done, Reply::Done)
        | (ExpectedReply::Cancelled, Reply::Cancelled(_))
        | (ExpectedReply::Read(_), Reply::Eof) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send_datagram(handle: Handle, peer: SocketAddr, bytes: Vec<u8>) -> Operation {
        Operation::SendDatagrams {
            handle,
            datagrams: vec![Datagram { peer, bytes }],
        }
    }

    fn datagram_reply(peer: SocketAddr, bytes: Vec<u8>) -> Reply {
        Reply::Datagrams(vec![Datagram { peer, bytes }])
    }
    use tokio::io::AsyncWriteExt;

    fn assert_reply_validation(
        operation: &Operation,
        result: &Result<Reply, Error>,
        previous_handle: Handle,
        is_valid: bool,
    ) {
        let mut last_handle = previous_handle;
        assert_eq!(
            validate_reply(&ExpectedReply::from(operation), result, &mut last_handle),
            is_valid,
            "{operation:?}: {result:?}"
        );
        let expected_handle = if let (true, Ok(Reply::Opened { handle, .. })) = (is_valid, result) {
            *handle
        } else {
            previous_handle
        };
        assert_eq!(last_handle, expected_handle);
    }

    #[test]
    fn pending_metadata_has_no_owned_payload_and_preserves_reply_kinds() {
        assert!(!std::mem::needs_drop::<ExpectedReply>());
        let address = "127.0.0.1:1234".parse().unwrap();
        let tcp = Reply::Opened {
            handle: 2,
            kind: ResourceKind::Tcp,
            peer: address,
        };
        let udp = Reply::Opened {
            handle: 2,
            kind: ResourceKind::Udp,
            peer: UNBOUND_UDP_PEER,
        };
        let data = Reply::Data(vec![1]);
        let written = Reply::Written(1);
        let datagram = datagram_reply(address, vec![]);
        let resolved = Reply::Resolved(vec!["1.1.1.1".parse().unwrap()]);
        let cancelled = Reply::Cancelled(true);
        let replies = [
            tcp.clone(),
            udp.clone(),
            data.clone(),
            Reply::Eof,
            written.clone(),
            datagram.clone(),
            resolved.clone(),
            cancelled.clone(),
            Reply::Done,
            Reply::Sent(vec![]),
        ];
        for (operation, valid_replies) in [
            (
                Operation::OpenTcp {
                    peer: address,
                    inline_urgent: false,
                },
                vec![tcp.clone()],
            ),
            (Operation::OpenUdp, vec![udp.clone()]),
            (Operation::OpenPublishedUdp(1), vec![udp]),
            (Operation::Accept(1), vec![tcp]),
            (
                Operation::Read {
                    handle: 1,
                    max_bytes: 1,
                },
                vec![data, Reply::Eof],
            ),
            (
                Operation::WriteAll {
                    handle: 1,
                    bytes: vec![1],
                },
                vec![written],
            ),
            (Operation::ReceiveDatagram(1), vec![datagram]),
            (
                send_datagram(1, address, vec![1]),
                vec![Reply::Sent(vec![])],
            ),
            (Operation::ShutdownWrite(1), vec![Reply::Done]),
            (Operation::WaitError(1), vec![Reply::Done]),
            (Operation::Resolve("example.test".into()), vec![resolved]),
            (Operation::Cancel(1), vec![cancelled]),
            (Operation::Close(1), vec![Reply::Done]),
        ] {
            for reply in &replies {
                assert_reply_validation(
                    &operation,
                    &Ok(reply.clone()),
                    1,
                    valid_replies.contains(reply),
                );
            }
            for error in [Error::Io, Error::Cancelled, Error::WrongKind] {
                assert_reply_validation(&operation, &Err(error), 1, true);
            }
        }
    }

    #[test]
    fn compact_metadata_preserves_handle_validation_boundaries() {
        let address = "127.0.0.1:1234".parse().unwrap();
        for (operation, kind, opened_peer) in [
            (
                Operation::OpenTcp {
                    peer: address,
                    inline_urgent: false,
                },
                ResourceKind::Tcp,
                address,
            ),
            (Operation::OpenUdp, ResourceKind::Udp, UNBOUND_UDP_PEER),
            (
                Operation::OpenPublishedUdp(1),
                ResourceKind::Udp,
                UNBOUND_UDP_PEER,
            ),
            (Operation::Accept(1), ResourceKind::Tcp, address),
        ] {
            for handle in [0, 1, 2, Handle::MAX] {
                assert_reply_validation(
                    &operation,
                    &Ok(Reply::Opened {
                        handle,
                        kind,
                        peer: opened_peer,
                    }),
                    1,
                    handle > 1,
                );
            }
            for peer in ["127.0.0.1:0", "127.0.0.1:4321", "192.0.2.1:1234"] {
                assert_reply_validation(
                    &operation,
                    &Ok(Reply::Opened {
                        handle: 2,
                        kind,
                        peer: peer.parse().unwrap(),
                    }),
                    1,
                    matches!(operation, Operation::Accept(_)) && peer == "127.0.0.1:4321",
                );
            }
        }
    }

    #[test]
    fn compact_metadata_preserves_payload_validation_boundaries() {
        for max_bytes in [0, 1, u32::MAX] {
            for length in [0, 1, 2, MAX_NETWORK_READ_BYTES, MAX_NETWORK_READ_BYTES + 1] {
                assert_reply_validation(
                    &Operation::Read {
                        handle: 1,
                        max_bytes,
                    },
                    &Ok(Reply::Data(vec![0; length])),
                    1,
                    length != 0 && length <= max_bytes as usize && length <= MAX_NETWORK_READ_BYTES,
                );
            }
        }
        for length in [0, 1, 2] {
            for written in [0, 1, 2, 3] {
                assert_reply_validation(
                    &Operation::WriteAll {
                        handle: 1,
                        bytes: vec![0; length],
                    },
                    &Ok(Reply::Written(written)),
                    1,
                    written as usize == length,
                );
            }
        }
        for length in [
            0,
            MAX_NETWORK_DATAGRAM_BYTES,
            MAX_NETWORK_DATAGRAM_BYTES + 1,
        ] {
            assert_reply_validation(
                &Operation::ReceiveDatagram(1),
                &Ok(datagram_reply(
                    "127.0.0.1:9".parse().unwrap(),
                    vec![0; length],
                )),
                1,
                length <= MAX_NETWORK_DATAGRAM_BYTES,
            );
        }
        for (addresses, is_valid) in [
            (vec![], false),
            (vec!["1.1.1.1".parse().unwrap()], true),
            (vec!["::1".parse().unwrap()], true),
            (vec!["::ffff:1.1.1.1".parse().unwrap()], false),
            (
                vec!["1.1.1.1".parse().unwrap(); terra_protocol::network::MAX_NETWORK_ADDRESSES],
                true,
            ),
            (
                vec![
                    "1.1.1.1".parse().unwrap();
                    terra_protocol::network::MAX_NETWORK_ADDRESSES + 1
                ],
                false,
            ),
        ] {
            assert_reply_validation(
                &Operation::Resolve("example.test".into()),
                &Ok(Reply::Resolved(addresses)),
                1,
                is_valid,
            );
        }
        assert_reply_validation(&Operation::Cancel(1), &Ok(Reply::Cancelled(false)), 1, true);
        assert_reply_validation(
            &Operation::Read {
                handle: 1,
                max_bytes: 0,
            },
            &Ok(Reply::Eof),
            1,
            true,
        );
    }

    #[tokio::test]
    async fn write_all_requires_a_full_acknowledgement() {
        for written in [0, 3, 5] {
            let (channel, mut peer) = tokio::io::duplex(8192);
            let client = Client::new(channel);
            let completion = client
                .try_reserve_write_all()
                .unwrap()
                .start(7, vec![1; 4])
                .unwrap();
            let request = terra_protocol::read_frame_async::<Request>(&mut peer)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                request.operation,
                Operation::WriteAll {
                    handle: 7,
                    bytes: vec![1; 4]
                }
            );
            terra_protocol::write_frame_async(
                &mut peer,
                &Response {
                    id: request.id,
                    result: Ok(Reply::Written(written)),
                },
            )
            .await
            .unwrap();
            assert_eq!(completion.await, Err(Error::Closed));
            assert!(!client.is_available());
        }
    }

    #[tokio::test]
    async fn socket_waiters_bound_admission_and_cancel_before_enqueue() {
        use std::future::Future;
        use std::task::Poll;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for (operation, reply) in [
                (
                    Operation::OpenPublishedUdp(1),
                    Reply::Opened {
                        handle: 1,
                        kind: ResourceKind::Udp,
                        peer: UNBOUND_UDP_PEER,
                    },
                ),
                (
                    Operation::ReceiveDatagram(1),
                    datagram_reply("127.0.0.1:9".parse().unwrap(), vec![]),
                ),
                (Operation::WaitError(1), Reply::Done),
                (Operation::ShutdownWrite(1), Reply::Done),
            ] {
                for outcome in [Ok(()), Err(Error::Closed)] {
                    let (channel, mut peer) = tokio::io::duplex(8192);
                    let client = Client::new(channel);
                    let admission = match crate::RequestAdmission::from(&operation) {
                        crate::RequestAdmission::SocketWait => &client.0.socket_wait_admission,
                        crate::RequestAdmission::Active => client.0.admission.as_ref(),
                        crate::RequestAdmission::Dns => &client.0.dns_admission,
                    };
                    let capacity = admission.available_permits();
                    let occupied = admission
                        .acquire_many(u32::try_from(capacity).unwrap())
                        .await
                        .unwrap();
                    let mut waiting = Box::pin(client.request(operation.clone()));
                    std::future::poll_fn(|context| {
                        assert!(waiting.as_mut().poll(context).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    assert_eq!(client.0.commands.capacity(), crate::MAX_PENDING_REQUESTS);
                    assert_eq!(client.0.ids.load(Ordering::Relaxed), 1);
                    assert_eq!(
                        client.try_reserve_write_all().is_ok(),
                        crate::RequestAdmission::from(&operation)
                            == crate::RequestAdmission::SocketWait
                    );
                    if outcome == Err(Error::Closed) {
                        client.disconnect();
                    }
                    match outcome {
                        Ok(()) => {
                            drop(occupied);
                            let response = async {
                                let request =
                                    terra_protocol::read_frame_async::<Request>(&mut peer)
                                        .await
                                        .unwrap()
                                        .unwrap();
                                assert_eq!(request.operation, operation);
                                terra_protocol::write_frame_async(
                                    &mut peer,
                                    &Response {
                                        id: request.id,
                                        result: Ok(reply.clone()),
                                    },
                                )
                                .await
                                .unwrap();
                            };
                            let (result, ()) = tokio::join!(waiting, response);
                            assert_eq!(result, Ok(reply.clone()));
                        }
                        Err(error) => {
                            assert_eq!(waiting.await, Err(error));
                            assert_eq!(client.0.commands.capacity(), crate::MAX_PENDING_REQUESTS);
                            assert_eq!(client.0.ids.load(Ordering::Relaxed), 1);
                            drop(occupied);
                        }
                    }
                    assert_eq!(admission.available_permits(), capacity);
                    client.disconnect();
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelling_every_socket_wait_retains_admission_until_acknowledged() {
        use std::future::Future;
        use std::task::Poll;

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (channel, mut peer) = tokio::io::duplex(8192);
            let client = Client::new(channel);
            let count = crate::MAX_SOCKET_WAIT_REQUESTS;
            let mut waits = (0..count)
                .map(|handle| {
                    Box::pin(
                        client.request(Operation::ReceiveDatagram(u64::try_from(handle).unwrap())),
                    )
                })
                .collect::<Vec<_>>();
            std::future::poll_fn(|context| {
                for wait in &mut waits {
                    assert!(wait.as_mut().poll(context).is_pending());
                }
                if client.0.socket_wait_admission.available_permits() == 0 {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            for _ in 0..count {
                let request = terra_protocol::read_frame_async::<Request>(&mut peer)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(matches!(request.operation, Operation::ReceiveDatagram(_)));
            }
            assert_eq!(client.0.socket_wait_admission.available_permits(), 0);
            drop(waits);
            assert!(client.is_available());
            assert_eq!(client.0.socket_wait_admission.available_permits(), 0);
            for _ in 0..count {
                let request = terra_protocol::read_frame_async::<Request>(&mut peer)
                    .await
                    .unwrap()
                    .unwrap();
                let Operation::Cancel(target) = request.operation else {
                    panic!("expected cancellation");
                };
                for response in [
                    Response {
                        id: request.id,
                        result: Ok(Reply::Cancelled(true)),
                    },
                    Response {
                        id: target,
                        result: Err(Error::Cancelled),
                    },
                ] {
                    terra_protocol::write_frame_async(&mut peer, &response)
                        .await
                        .unwrap();
                }
            }
            while client.0.socket_wait_admission.available_permits() != count {
                tokio::task::yield_now().await;
            }
            assert!(client.is_available());
            client.disconnect();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn dns_requests_keep_a_bounded_reservation_under_bulk_pressure() {
        use std::future::Future;
        use std::task::Poll;

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (channel, mut peer) = tokio::io::duplex(8192);
            let client = Client::new(channel);
            let bulk = (0..crate::MAX_NON_DNS_REQUESTS)
                .map(|_| client.try_reserve_write_all().unwrap())
                .collect::<Vec<_>>();
            assert!(matches!(
                client.try_reserve_write_all(),
                Err(Error::LimitExceeded)
            ));
            assert_eq!(
                client.0.admission.available_permits()
                    + client.0.dns_admission.available_permits()
                    + bulk.len(),
                crate::MAX_QUEUED_REQUESTS / 2
            );
            let mut queries = (0..crate::MAX_DNS_REQUESTS)
                .map(|index| {
                    Box::pin(client.request(Operation::Resolve(format!("reserved-{index}.test"))))
                })
                .collect::<Vec<_>>();
            std::future::poll_fn(|context| {
                for query in &mut queries {
                    assert!(query.as_mut().poll(context).is_pending());
                }
                Poll::Ready(())
            })
            .await;
            assert_eq!(client.0.dns_admission.available_permits(), 0);
            assert_eq!(
                client
                    .request(Operation::Resolve("exhausted.test".into()))
                    .await,
                Err(Error::LimitExceeded)
            );
            let resolved = Reply::Resolved(vec!["1.1.1.1".parse().unwrap()]);
            let response = async {
                for index in 0..crate::MAX_DNS_REQUESTS {
                    let request = terra_protocol::read_frame_async::<Request>(&mut peer)
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(
                        request.operation,
                        Operation::Resolve(format!("reserved-{index}.test"))
                    );
                    terra_protocol::write_frame_async(
                        &mut peer,
                        &Response {
                            id: request.id,
                            result: Ok(resolved.clone()),
                        },
                    )
                    .await
                    .unwrap();
                }
            };
            let completion = async {
                for query in queries {
                    assert_eq!(query.await, Ok(resolved.clone()));
                }
            };
            tokio::join!(response, completion);
            assert_eq!(client.0.admission.available_permits(), 0);
            assert_eq!(
                client.0.dns_admission.available_permits(),
                crate::MAX_DNS_REQUESTS
            );
            drop(bulk);
            assert_eq!(
                client.0.admission.available_permits(),
                crate::MAX_NON_DNS_REQUESTS
            );
            client.disconnect();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn write_admission_waits_for_global_capacity_and_survives_dropped_receivers() {
        let (channel, mut peer) = tokio::io::duplex(8192);
        let client = Client::new(channel);
        let mut permits = (0..crate::MAX_NON_DNS_REQUESTS)
            .map(|_| client.0.admission.clone().try_acquire_owned().unwrap())
            .collect::<Vec<_>>();
        let mut reservation = client.reserve_write_all();
        std::future::poll_fn(|cx| {
            assert!(reservation.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert!(client.is_available());
        drop(permits.pop());
        let admission = reservation.await.unwrap();
        let completion = admission.start(7, b"owned".to_vec()).unwrap();
        drop(completion);
        let request = terra_protocol::read_frame_async::<Request>(&mut peer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            request.operation,
            Operation::WriteAll {
                handle: 7,
                bytes: b"owned".to_vec()
            }
        );
        assert_eq!(client.0.admission.available_permits(), 0);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                terra_protocol::read_frame_async::<Request>(&mut peer)
            )
            .await
            .is_err()
        );
        let reservation = client.reserve_write_all();
        terra_protocol::write_frame_async(
            &mut peer,
            &Response {
                id: request.id,
                result: Ok(Reply::Written(5)),
            },
        )
        .await
        .unwrap();
        let admission = tokio::time::timeout(std::time::Duration::from_secs(2), reservation)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(client.0.admission.available_permits(), 0);
        let reservation = client.reserve_write_all();
        client.disconnect();
        assert!(matches!(reservation.await, Err(Error::Closed)));
        drop(admission);
    }

    #[tokio::test]
    async fn fragmented_replies_survive_outgoing_controls() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for fragmented_header in [true, false] {
                let (channel, peer) = tokio::io::duplex(1);
                let (mut read, mut write) = tokio::io::split(peer);
                let client = Client::new(channel);
                let request = client.request(Operation::Read {
                    handle: 7,
                    max_bytes: 8,
                });
                let peer = async {
                    let original = terra_protocol::read_frame_async::<Request>(&mut read)
                        .await
                        .unwrap()
                        .unwrap();
                    let completion = Response {
                        id: original.id,
                        result: Ok(Reply::Data(b"fragment".to_vec())),
                    };
                    let frame = terra_protocol::encode_frame(&completion).unwrap();
                    let split = if fragmented_header {
                        2
                    } else {
                        frame.len() - 2
                    };
                    write.write_all(&frame[..split]).await.unwrap();
                    client.close(99);
                    let close = terra_protocol::read_frame_async::<Request>(&mut read)
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(close.operation, Operation::Close(99));
                    write.write_all(&frame[split..]).await.unwrap();
                    terra_protocol::write_frame_async(
                        &mut write,
                        &Response {
                            id: close.id,
                            result: Err(Error::StaleHandle),
                        },
                    )
                    .await
                    .unwrap();
                };
                let (result, ()) = tokio::join!(request, peer);
                assert_eq!(result, Ok(Reply::Data(b"fragment".to_vec())));
                assert!(client.is_available());
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn abandoned_open_replies_close_their_resources() {
        use std::future::Future;
        use std::task::Poll;

        for operation in [Operation::OpenUdp, Operation::OpenPublishedUdp(1)] {
            let (channel, mut peer) = tokio::io::duplex(8192);
            let client = Client::new(channel);
            let mut opening = Box::pin(client.request(operation));
            std::future::poll_fn(|context| {
                assert!(opening.as_mut().poll(context).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(opening);
            let original = terra_protocol::read_frame_async::<Request>(&mut peer)
                .await
                .unwrap()
                .unwrap();
            let cancel = terra_protocol::read_frame_async::<Request>(&mut peer)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(cancel.operation, Operation::Cancel(original.id));
            for response in [
                Response {
                    id: original.id,
                    result: Ok(Reply::Opened {
                        handle: 1,
                        kind: ResourceKind::Udp,
                        peer: UNBOUND_UDP_PEER,
                    }),
                },
                Response {
                    id: cancel.id,
                    result: Ok(Reply::Cancelled(false)),
                },
            ] {
                terra_protocol::write_frame_async(&mut peer, &response)
                    .await
                    .unwrap();
            }
            let close = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                terra_protocol::read_frame_async::<Request>(&mut peer),
            )
            .await
            .unwrap()
            .unwrap()
            .unwrap();
            assert_eq!(close.operation, Operation::Close(1));
            terra_protocol::write_frame_async(
                &mut peer,
                &Response {
                    id: close.id,
                    result: Ok(Reply::Done),
                },
            )
            .await
            .unwrap();
            assert!(client.is_available());
        }
    }

    #[tokio::test]
    async fn malformed_replies_fail_the_session_instead_of_attaching_resources() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let client = Client::new(client);
        let request = client.request(Operation::Read {
            handle: 7,
            max_bytes: 1,
        });
        let attack = async {
            let request = terra_protocol::read_frame_async::<Request>(&mut peer)
                .await
                .unwrap()
                .unwrap();
            terra_protocol::write_frame_async(
                &mut peer,
                &Response {
                    id: request.id,
                    result: Ok(Reply::Data(vec![0; 2])),
                },
            )
            .await
            .unwrap();
        };
        let (result, ()) = tokio::join!(request, attack);
        assert_eq!(result, Err(Error::Closed));
        assert!(!client.is_available());
    }
}
