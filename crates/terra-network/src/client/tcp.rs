//! One TCP flow: raw upload bytes out, framed events in. A reader task owns the stream's read half
//! and routes events to the download (data) and to both halves (flow state).

use super::Client;
use crate::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use terra_protocol::network::TcpEvent;
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, watch};
use tokio_util::compat::Compat;
use tokio_util::sync::CancellationToken;

/// Data frames the reader may read ahead for a download that is not reading.
const MAX_QUEUED_FRAMES: usize = 4;

type StreamRead = ReadHalf<Compat<yamux::Stream>>;
type StreamWrite = WriteHalf<Compat<yamux::Stream>>;

pub struct TcpFlow {
    peer: SocketAddr,
    upload: TcpUpload,
    download: TcpDownload,
    close: CancellationToken,
}

/// Uploads fail with the flow's terminal error once the flow has failed, even after the peer's `Eof`.
pub struct TcpUpload {
    stream: StreamWrite,
    state: watch::Receiver<FlowState>,
    is_fin_sent: Arc<AtomicBool>,
}

pub struct TcpDownload {
    data: mpsc::Receiver<Result<Vec<u8>, Error>>,
    /// Keeps the reader running while only the download is alive.
    _state: watch::Receiver<FlowState>,
}

/// What the broker has reported about the flow besides data.
#[derive(Clone, Copy, Default)]
struct FlowState {
    write_shutdown: Option<Result<(), Error>>,
    failure: Option<Error>,
}

struct Reader {
    stream: StreamRead,
    /// Disconnects the client without keeping its connection alive the way a `Client` clone would.
    disconnect: CancellationToken,
    data: Option<mpsc::Sender<Result<Vec<u8>, Error>>>,
    state: watch::Sender<FlowState>,
    is_fin_sent: Arc<AtomicBool>,
}

impl Reader {
    /// Applies events until the flow is finished. A malformed or out-of-order event disconnects the
    /// client.
    async fn run(mut self) {
        loop {
            let event = crate::frames::read_frame::<TcpEvent>(&mut self.stream).await;
            match event {
                Ok(Some(TcpEvent::Data(bytes))) if !bytes.is_empty() && self.data.is_some() => {
                    self.send_data(Ok(bytes)).await;
                }
                Ok(Some(TcpEvent::Eof)) if self.data.is_some() => {
                    self.data = None;
                    if self.state.borrow().write_shutdown.is_some() {
                        return;
                    }
                }
                Ok(Some(TcpEvent::WriteShutdown(result)))
                    if self.state.borrow().write_shutdown.is_none()
                        && self.is_fin_sent.load(Ordering::SeqCst) =>
                {
                    self.state
                        .send_modify(|state| state.write_shutdown = Some(result));
                    if self.data.is_none() {
                        return;
                    }
                }
                Ok(Some(TcpEvent::Failed(error))) => return self.fail(error).await,
                Ok(None) => return self.fail(Error::Closed).await,
                Err(error) if error.kind() != io::ErrorKind::InvalidData => {
                    return self.fail(Error::Closed).await;
                }
                Ok(Some(_)) | Err(_) => {
                    self.disconnect.cancel();
                    return self.fail(Error::Closed).await;
                }
            }
        }
    }

    async fn send_data(&self, item: Result<Vec<u8>, Error>) {
        if let Some(data) = &self.data {
            let _ = data.send(item).await;
        }
    }

    async fn fail(&self, error: Error) {
        self.state.send_modify(|state| state.failure = Some(error));
        self.send_data(Err(error)).await;
    }
}

/// Runs the reader until the flow is closed or both halves are dropped.
async fn run_reader(reader: Reader, close: CancellationToken) {
    let both_halves_dropped = reader.state.clone();
    tokio::select! {
        () = close.cancelled() => {}
        () = both_halves_dropped.closed() => {}
        () = reader.run() => {}
    }
}

impl TcpFlow {
    pub(super) fn start(client: &Client, stream: Compat<yamux::Stream>, peer: SocketAddr) -> Self {
        let (read, write) = tokio::io::split(stream);
        let (data_sender, data) = mpsc::channel(MAX_QUEUED_FRAMES);
        let (state_sender, state) = watch::channel(FlowState::default());
        let is_fin_sent = Arc::new(AtomicBool::new(false));
        let close = CancellationToken::new();
        tokio::spawn(run_reader(
            Reader {
                stream: read,
                disconnect: client.0.closed.clone(),
                data: Some(data_sender),
                state: state_sender,
                is_fin_sent: is_fin_sent.clone(),
            },
            close.clone(),
        ));
        Self {
            peer,
            upload: TcpUpload {
                stream: write,
                state: state.clone(),
                is_fin_sent,
            },
            download: TcpDownload {
                data,
                _state: state,
            },
            close,
        }
    }

    #[must_use]
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Cancelling the token ends the flow's reader task.
    #[must_use]
    pub fn close_token(&self) -> CancellationToken {
        self.close.clone()
    }

    /// Dropping both halves resets the flow; dropping only the download keeps the upload working.
    #[must_use]
    pub fn split(self) -> (TcpUpload, TcpDownload) {
        (self.upload, self.download)
    }
}

/// Resolves with the flow's failure; pends forever if the flow ends without one.
async fn wait_failure(state: &mut watch::Receiver<FlowState>) -> Error {
    if let Ok(state) = state.wait_for(|state| state.failure.is_some()).await
        && let Some(error) = state.failure
    {
        return error;
    }
    std::future::pending().await
}

impl TcpUpload {
    pub async fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if let Some(error) = self.state.borrow().failure {
            return Err(error);
        }
        tokio::select! {
            biased;
            error = wait_failure(&mut self.state) => Err(error),
            result = self.stream.write_all(bytes) => result.map_err(|_| {
                self.state.borrow().failure.unwrap_or(Error::ConnectionReset)
            }),
        }
    }

    /// Resolves with the flow's terminal error; pends forever if the flow ends cleanly.
    pub async fn wait_failed(&mut self) -> Error {
        wait_failure(&mut self.state).await
    }

    /// Sends FIN, then waits until the broker has written every byte and shut the socket down.
    pub async fn finish(mut self) -> Result<(), Error> {
        if let Some(error) = self.state.borrow().failure {
            return Err(error);
        }
        self.is_fin_sent.store(true, Ordering::SeqCst);
        self.stream.shutdown().await.map_err(|_| Error::Closed)?;
        let Ok(state) = self
            .state
            .wait_for(|state| state.write_shutdown.is_some() || state.failure.is_some())
            .await
        else {
            return Err(Error::Closed);
        };
        match (state.write_shutdown, state.failure) {
            (Some(result), _) => result,
            (None, Some(error)) => Err(error),
            (None, None) => Err(Error::Closed),
        }
    }
}

impl TcpDownload {
    /// `None` is the peer's `Eof`.
    pub async fn next(&mut self) -> Option<Result<Vec<u8>, Error>> {
        self.data.recv().await
    }
}
