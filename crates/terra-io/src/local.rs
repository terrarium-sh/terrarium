//! Filesystem-addressed local streams for host control channels.

#[cfg(unix)]
pub use std::os::unix::net::{UnixListener as LocalListener, UnixStream as LocalStream};
#[cfg(windows)]
pub use uds_windows::{UnixListener as LocalListener, UnixStream as LocalStream};

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
