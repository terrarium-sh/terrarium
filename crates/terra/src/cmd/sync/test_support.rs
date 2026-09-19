use std::io::Read;
use terra_protocol::{SyncEntry, SyncEntryKind, SyncReply, encode_frame};
use tokio::io::{AsyncRead, AsyncWrite};

pub(super) fn entry(path: &str, kind: SyncEntryKind, target: Option<&str>) -> SyncEntry {
    SyncEntry {
        relative_path: path.into(),
        kind,
        size: 0,
        mode: 0o755,
        mtime_secs: 100,
        mtime_nanos: 0,
        link_target: target.map(str::to_owned),
    }
}

pub(super) struct Peer(pub(super) std::io::Cursor<Vec<u8>>);

impl Read for Peer {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        Read::read(&mut self.0, bytes)
    }
}

impl AsyncRead for Peer {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let n = Read::read(&mut self.0, buf.initialize_unfilled())?;
        buf.advance(n);
        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Peer {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

pub(super) struct PendingPeer {
    pub(super) peer: Peer,
    pub(super) blocked: Option<tokio::sync::oneshot::Sender<()>>,
}

impl AsyncRead for PendingPeer {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.peer).poll_read(cx, buf);
        if matches!(result, std::task::Poll::Ready(Ok(()))) && buf.filled().len() == before {
            if let Some(blocked) = self.blocked.take() {
                let _ = blocked.send(());
            }
            std::task::Poll::Pending
        } else {
            result
        }
    }
}

impl AsyncWrite for PendingPeer {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.peer).poll_write(cx, bytes)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.peer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.peer).poll_shutdown(cx)
    }
}

pub(super) fn peer(replies: &[SyncReply]) -> Peer {
    Peer(std::io::Cursor::new(
        replies
            .iter()
            .flat_map(|reply| encode_frame(reply).unwrap())
            .collect(),
    ))
}
