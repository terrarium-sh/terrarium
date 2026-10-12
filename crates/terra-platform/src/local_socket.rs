//! Filesystem-addressed local streams for host control channels.

#[cfg(unix)]
pub use std::os::unix::net::{UnixListener as LocalListener, UnixStream as LocalStream};
#[cfg(windows)]
pub use uds_windows::{UnixListener as LocalListener, UnixStream as LocalStream};

pub fn create_local_pair() -> std::io::Result<(LocalStream, LocalStream)> {
    #[cfg(unix)]
    {
        LocalStream::pair()
    }
    #[cfg(windows)]
    {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("socket");
        let listener = LocalListener::bind(&path)?;
        let client = LocalStream::connect(&path)?;
        let (server, _) = listener.accept()?;
        Ok((client, server))
    }
}

#[cfg(unix)]
pub use tokio::net::UnixStream as AsyncLocalStream;

/// Ends the stream's write direction at once, so the peer reads EOF while this end can still read.
#[cfg(unix)]
pub fn shutdown_write(stream: &AsyncLocalStream) -> std::io::Result<()> {
    rustix::net::shutdown(stream, rustix::net::Shutdown::Write).map_err(std::io::Error::from)
}

#[cfg(unix)]
pub struct AsyncLocalListener(tokio::io::unix::AsyncFd<LocalListener>);

#[cfg(unix)]
impl AsyncLocalListener {
    pub fn from_std(listener: LocalListener) -> std::io::Result<Self> {
        listener.set_nonblocking(true)?;
        tokio::io::unix::AsyncFd::new(listener).map(Self)
    }

    pub async fn accept(&self) -> std::io::Result<LocalStream> {
        self.0
            .async_io(tokio::io::Interest::READABLE, |listener| {
                listener.accept().map(|(stream, _)| stream)
            })
            .await
    }
}

#[cfg(windows)]
mod asynchronous {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use async_io::Async;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt as _};

    use super::{LocalListener, LocalStream};

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

        fn socket(&self) -> &LocalStream {
            &self.0.get_ref().get_ref().0
        }

        /// Reads what is queued without waiting; `WouldBlock` until [`Self::readable`] resolves.
        pub fn try_read(&self, buffer: &mut [u8]) -> io::Result<usize> {
            io::Read::read(&mut self.socket(), buffer)
        }

        /// Writes what fits without waiting; `WouldBlock` until [`Self::writable`] resolves.
        pub fn try_write(&self, bytes: &[u8]) -> io::Result<usize> {
            io::Write::write(&mut self.socket(), bytes)
        }

        pub async fn readable(&self) -> io::Result<()> {
            self.0.get_ref().readable().await
        }

        pub async fn writable(&self) -> io::Result<()> {
            self.0.get_ref().writable().await
        }
    }

    /// Ends the stream's write direction at once, so the peer reads EOF while this end can still read.
    pub fn shutdown_write(stream: &AsyncLocalStream) -> io::Result<()> {
        stream.socket().shutdown(std::net::Shutdown::Write)
    }

    struct WindowsLocalListener(LocalListener);

    impl std::os::windows::io::AsSocket for WindowsLocalListener {
        #[allow(unsafe_code)]
        fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
            use std::os::windows::io::{AsRawSocket, BorrowedSocket};
            // SAFETY: The listener owns this socket for the returned borrow's lifetime.
            unsafe { BorrowedSocket::borrow_raw(self.0.as_raw_socket()) }
        }
    }

    // SAFETY: The wrapper owns the listening socket for the whole async registration.
    #[allow(unsafe_code)]
    unsafe impl async_io::IoSafe for WindowsLocalListener {}

    pub struct AsyncLocalListener(Async<WindowsLocalListener>);

    impl AsyncLocalListener {
        pub fn from_std(listener: LocalListener) -> io::Result<Self> {
            Async::new(WindowsLocalListener(listener)).map(Self)
        }

        pub async fn accept(&self) -> io::Result<LocalStream> {
            self.0
                .read_with(|listener| listener.0.accept().map(|(stream, _)| stream))
                .await
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

#[cfg(windows)]
pub use asynchronous::{AsyncLocalListener, AsyncLocalStream, shutdown_write};

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
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
        assert_matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        );
        client.write_all(b"ping").unwrap();
        server.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"ping");
        server.write_all(b"pong").unwrap();
        client.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"pong");
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(server.read(&mut buffer).unwrap(), 0);
    }

    #[test]
    fn local_stream_pair_round_trip() {
        let (mut left, mut right) = create_local_pair().unwrap();
        left.write_all(b"ping").unwrap();
        let mut buffer = [0; 4];
        right.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"ping");
    }

    #[cfg(windows)]
    #[test]
    fn local_stream_pair_returns_long_temp_path_errors() {
        if std::env::var_os("TERRA_TEST_LONG_PAIR_TEMP").is_some() {
            let directory = std::env::temp_dir();
            assert!(directory.is_dir());
            assert!(directory.to_str().unwrap().len() >= 108);
            assert_eq!(
                create_local_pair().unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput
            );
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let long_directory = directory.path().join("a".repeat(110));
        std::fs::create_dir(&long_directory).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "local_socket::tests::local_stream_pair_returns_long_temp_path_errors",
                "--nocapture",
            ])
            .env("TERRA_TEST_LONG_PAIR_TEMP", "1")
            .env("TMP", &long_directory)
            .env("TEMP", &long_directory)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed;"));
    }
}

#[cfg(test)]
mod asynchronous_tests {
    use std::io::{Read as _, Write as _};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    #[tokio::test]
    async fn cancelled_accept_and_read_leave_the_stream_usable() {
        use std::time::Duration;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("socket");
        let listener = AsyncLocalListener::from_std(LocalListener::bind(&path).unwrap()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        let mut client = AsyncLocalStream::connect(&path).await.unwrap();
        let mut server = listener.accept().await.unwrap();
        let mut bytes = [0; 4];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), client.read_exact(&mut bytes))
                .await
                .is_err()
        );
        server.write_all(b"ping").unwrap();
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ping");
        server.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(client.read(&mut bytes).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn accept_waits_and_preserves_the_connection() {
        use std::time::Duration;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("socket");
        let listener = AsyncLocalListener::from_std(LocalListener::bind(&path).unwrap()).unwrap();
        let mut client = LocalStream::connect(&path).unwrap();
        client.write_all(b"probe").unwrap();
        let mut server = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut buffer = [0; 5];
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        server.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"probe");
    }

    /// Non-blocking I/O reports `WouldBlock` until readiness, and a write shutdown reads as EOF.
    #[tokio::test]
    async fn try_io_waits_for_readiness_and_shutdown_reads_as_eof() {
        let (left, right) = create_local_pair().unwrap();
        for stream in [&left, &right] {
            stream.set_nonblocking(true).unwrap();
        }
        let (left, right) = (
            AsyncLocalStream::from_std(left).unwrap(),
            AsyncLocalStream::from_std(right).unwrap(),
        );
        let mut buffer = [0; 8];
        assert_eq!(
            left.try_read(&mut buffer).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        right.writable().await.unwrap();
        assert_eq!(right.try_write(b"ping").unwrap(), 4);
        left.readable().await.unwrap();
        assert_eq!(left.try_read(&mut buffer).unwrap(), 4);
        assert_eq!(&buffer[..4], b"ping");
        shutdown_write(&right).unwrap();
        left.readable().await.unwrap();
        assert_eq!(left.try_read(&mut buffer).unwrap(), 0);
        assert_eq!(left.try_write(b"back").unwrap(), 4);
    }

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
