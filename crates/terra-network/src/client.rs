mod tcp;
#[cfg(test)]
mod tests;
mod udp;

pub use self::tcp::{TcpDownload, TcpFlow, TcpUpload};
pub use self::udp::UdpFlow;

use crate::Error;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::Poll;
use terra_protocol::network::{ListenerGrant, MAX_NETWORK_NAME_BYTES, Open, Opened};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;

type OutboundReply = oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>;

#[derive(Clone)]
pub struct Client(Arc<Connection>);

struct Connection {
    outbound_requests: mpsc::Sender<OutboundReply>,
    closed: CancellationToken,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.closed.cancel();
    }
}

impl Client {
    /// Must run inside a Tokio runtime; the client opens every stream and rejects any the broker opens.
    #[must_use]
    pub fn new(channel: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) -> Self {
        let (outbound_requests, requests) = mpsc::channel(crate::MAX_STREAMS);
        let closed = CancellationToken::new();
        tokio::spawn(drive(channel, requests, closed.clone()));
        Self(Arc::new(Connection {
            outbound_requests,
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

    pub async fn open_tcp(&self, peer: SocketAddr, inline_urgent: bool) -> Result<TcpFlow, Error> {
        let (stream, opened) = self
            .open_stream(&Open::Tcp {
                peer,
                inline_urgent,
            })
            .await?;
        match opened {
            Opened::Tcp { peer: opened_peer } if opened_peer == peer => {
                Ok(TcpFlow::start(self, stream, peer))
            }
            Opened::Tcp { .. } | Opened::Udp | Opened::Resolved(_) => Err(self.reject_broker()),
        }
    }

    /// Waits for one connection to the published listener; the peer is loopback.
    pub async fn accept(&self, grant: ListenerGrant) -> Result<TcpFlow, Error> {
        let (stream, opened) = self.open_stream(&Open::Accept(grant)).await?;
        match opened {
            Opened::Tcp { peer } if peer.ip().is_loopback() && peer.port() != 0 => {
                Ok(TcpFlow::start(self, stream, peer))
            }
            Opened::Tcp { .. } | Opened::Udp | Opened::Resolved(_) => Err(self.reject_broker()),
        }
    }

    pub async fn open_udp(&self) -> Result<UdpFlow, Error> {
        self.open_udp_stream(&Open::Udp).await
    }

    pub async fn open_published_udp(&self, grant: ListenerGrant) -> Result<UdpFlow, Error> {
        self.open_udp_stream(&Open::PublishedUdp(grant)).await
    }

    pub async fn resolve(&self, name: String) -> Result<Vec<IpAddr>, Error> {
        if name.len() > MAX_NETWORK_NAME_BYTES {
            return Err(Error::InvalidArgument);
        }
        match self.open_stream(&Open::Resolve(name)).await?.1 {
            Opened::Resolved(addresses)
                if !addresses.is_empty()
                    && addresses
                        .iter()
                        .all(|address| *address == address.to_canonical()) =>
            {
                Ok(addresses)
            }
            Opened::Resolved(_) | Opened::Tcp { .. } | Opened::Udp => Err(self.reject_broker()),
        }
    }

    async fn open_udp_stream(&self, open: &Open) -> Result<UdpFlow, Error> {
        let (stream, opened) = self.open_stream(open).await?;
        match opened {
            Opened::Udp => Ok(UdpFlow::start(self, stream)),
            Opened::Tcp { .. } | Opened::Resolved(_) => Err(self.reject_broker()),
        }
    }

    /// Opens a stream, sends `open`, and waits for the broker's reply. Dropping the future resets the stream.
    async fn open_stream(&self, open: &Open) -> Result<(Compat<yamux::Stream>, Opened), Error> {
        let opening = async {
            let (reply, stream) = oneshot::channel();
            self.0
                .outbound_requests
                .send(reply)
                .await
                .map_err(|_| Error::Closed)?;
            let mut stream = stream
                .await
                .map_err(|_| Error::Closed)?
                .map_err(|error| match error {
                    yamux::ConnectionError::TooManyStreams => Error::LimitExceeded,
                    _ => Error::Closed,
                })?
                .compat();
            crate::frames::write_frame(&mut stream, open)
                .await
                .map_err(|_| Error::Closed)?;
            let opened = crate::frames::read_frame::<Result<Opened, Error>>(&mut stream)
                .await
                .map_err(|error| self.reject_malformed(&error))?
                .ok_or(Error::Closed)??;
            Ok((stream, opened))
        };
        tokio::select! {
            () = self.0.closed.cancelled() => Err(Error::Closed),
            result = opening => result,
        }
    }

    /// Disconnects after a broker protocol violation.
    fn reject_broker(&self) -> Error {
        self.disconnect();
        Error::Closed
    }

    fn reject_malformed(&self, error: &io::Error) -> Error {
        if error.kind() == io::ErrorKind::InvalidData {
            self.disconnect();
        }
        Error::Closed
    }
}

/// Drives the yamux connection and opens streams on request until it ends or a stream arrives.
async fn drive(
    channel: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    mut requests: mpsc::Receiver<OutboundReply>,
    closed: CancellationToken,
) {
    let mut connection = crate::mux::connect(channel, yamux::Mode::Client);
    let mut waiting: Option<OutboundReply> = None;
    let run = std::future::poll_fn(|cx| {
        loop {
            let reply = match waiting.take() {
                Some(reply) => reply,
                None => match requests.poll_recv(cx) {
                    Poll::Ready(Some(reply)) => reply,
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => break,
                },
            };
            match connection.poll_new_outbound(cx) {
                Poll::Ready(stream) => {
                    let _ = reply.send(stream);
                }
                Poll::Pending => {
                    waiting = Some(reply);
                    break;
                }
            }
        }
        connection.poll_next_inbound(cx).map(|_| ())
    });
    tokio::select! {
        () = closed.cancelled() => {}
        () = run => {}
    }
    closed.cancel();
}
