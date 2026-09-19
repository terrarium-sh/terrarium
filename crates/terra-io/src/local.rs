//! Filesystem-addressed local streams for host control channels.

#[cfg(unix)]
pub use std::os::unix::net::{UnixListener as LocalListener, UnixStream as LocalStream};
#[cfg(windows)]
pub use uds_windows::{UnixListener as LocalListener, UnixStream as LocalStream};

#[cfg(all(unix, feature = "tokio"))]
pub use tokio::net::UnixStream as AsyncLocalStream;

#[cfg(all(windows, feature = "tokio"))]
mod asynchronous {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use async_io::Async;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt as _};

    use super::LocalStream;

    struct WindowsLocalStream(LocalStream);

    impl io::Read for WindowsLocalStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.0.read(buffer)
        }
    }

    impl io::Write for WindowsLocalStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.write(buffer)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl std::os::windows::io::AsSocket for WindowsLocalStream {
        fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
            self.0.as_socket()
        }
    }

    // SAFETY: The wrapper owns the socket for the whole async registration.
    #[allow(unsafe_code)]
    unsafe impl async_io::IoSafe for WindowsLocalStream {}

    pub struct AsyncLocalStream(Compat<Async<WindowsLocalStream>>);

    impl AsyncLocalStream {
        pub async fn connect(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
            let path = path.as_ref().to_owned();
            let stream = tokio::task::spawn_blocking(move || LocalStream::connect(path))
                .await
                .map_err(io::Error::other)??;
            Self::from_std(stream)
        }

        pub fn from_std(stream: LocalStream) -> io::Result<Self> {
            Async::new(WindowsLocalStream(stream)).map(|stream| Self(stream.compat()))
        }
    }

    impl AsyncRead for AsyncLocalStream {
        fn poll_read(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for AsyncLocalStream {
        fn poll_write(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(context, buffer)
        }

        fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(context)
        }

        fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            let stream = &mut self.get_mut().0;
            std::task::ready!(Pin::new(&mut *stream).poll_flush(context))?;
            let socket = &stream.get_ref().get_ref().0;
            Poll::Ready(socket.shutdown(std::net::Shutdown::Write))
        }
    }
}

#[cfg(all(windows, feature = "tokio"))]
pub use asynchronous::AsyncLocalStream;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::Shutdown;
    use std::time::Duration;

    #[test]
    fn local_stream_round_trip_timeout_and_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("socket");
        let listener = LocalListener::bind(&path).unwrap();
        let mut client = LocalStream::connect(&path).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buffer = [0; 4];
        let error = server.read(&mut buffer).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        client.write_all(b"ping").unwrap();
        server.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"ping");
        server.write_all(b"pong").unwrap();
        client.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"pong");
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(server.read(&mut buffer).unwrap(), 0);
    }
}

#[cfg(all(test, feature = "tokio"))]
mod asynchronous_tests {
    use std::io::{Read as _, Write as _};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    #[tokio::test]
    async fn asynchronous_local_stream_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("socket");
        let listener = LocalListener::bind(&path).unwrap();
        let client = AsyncLocalStream::connect(path.clone()).await.unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let (mut reader, mut writer) = tokio::io::split(client);

        writer.write_all(b"ping").await.unwrap();
        let mut buffer = [0; 4];
        server.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"ping");
        server.write_all(b"pong").unwrap();
        reader.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"pong");
    }

    #[tokio::test]
    async fn converts_a_nonblocking_local_stream() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("socket");
        let listener = LocalListener::bind(&path).unwrap();
        let stream = LocalStream::connect(&path).unwrap();
        stream.set_nonblocking(true).unwrap();
        let client = AsyncLocalStream::from_std(stream).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        let (mut reader, mut writer) = tokio::io::split(client);
        writer.write_all(b"ping").await.unwrap();
        let mut buffer = [0; 4];
        server.read_exact(&mut buffer).unwrap();
        server.write_all(b"pong").unwrap();
        reader.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"pong");
    }

    #[tokio::test]
    async fn shutdown_closes_the_write_half() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("socket");
        let listener = LocalListener::bind(&path).unwrap();
        let client = AsyncLocalStream::connect(&path).await.unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let (mut reader, mut writer) = tokio::io::split(client);

        writer.write_all(b"ping").await.unwrap();
        writer.shutdown().await.unwrap();
        let mut buffer = [0; 4];
        server.read_exact(&mut buffer).unwrap();
        assert_eq!(server.read(&mut buffer).unwrap(), 0);
        server.write_all(b"pong").unwrap();
        reader.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"pong");
    }
}
