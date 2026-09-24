//! The guest side of the agent's single vsock carrier.

use anyhow::{Context as _, Result};
use futures_util::{future::poll_fn, io::AsyncWriteExt as _};
use std::{fs::File, os::fd::OwnedFd, os::unix::net::UnixStream, thread};
use tokio::sync::mpsc;

pub(super) struct GuestMux {
    thread: thread::JoinHandle<()>,
}

pub(super) struct Streams {
    pub(super) control: File,
    pub(super) diagnostic: File,
    pub(super) clients: mpsc::Receiver<File>,
    pub(super) driver: GuestMux,
}

impl GuestMux {
    pub(super) fn wait(self) {
        if self.thread.join().is_err() {
            eprintln!("terra-agent: mux thread panicked");
        }
    }

    pub(super) fn connect() -> Result<Streams> {
        let carrier = crate::vsock::connect(
            crate::vsock::VMADDR_CID_HOST,
            terra_protocol::mux::MUX_VSOCK_PORT,
        )
        .context("dialling the host mux port")?;
        Self::start(carrier)
    }

    fn start(carrier: File) -> Result<Streams> {
        let (control, driver_control) = UnixStream::pair().context("creating control bridge")?;
        let (diagnostic, driver_diagnostic) =
            UnixStream::pair().context("creating diagnostic bridge")?;
        let (clients, client_streams) = mpsc::channel(terra_protocol::mux::MAX_CLIENT_STREAMS);
        let driver = thread::Builder::new()
            .name("agent-mux".into())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                if let Err(error) = runtime.block_on(run(
                    carrier,
                    File::from(OwnedFd::from(driver_control)),
                    File::from(OwnedFd::from(driver_diagnostic)),
                    clients,
                )) {
                    eprintln!("terra-agent: mux failed: {error:#}");
                }
            })
            .context("starting mux driver")?;
        Ok(Streams {
            control: File::from(OwnedFd::from(control)),
            diagnostic: File::from(OwnedFd::from(diagnostic)),
            clients: client_streams,
            driver: Self { thread: driver },
        })
    }
}

async fn run(
    carrier: File,
    control: File,
    diagnostic: File,
    clients: mpsc::Sender<File>,
) -> Result<()> {
    let carrier = async_io::Async::new(carrier).context("registering carrier")?;
    let mut connection = yamux::Connection::new(
        carrier,
        terra_protocol::mux::yamux_config(),
        yamux::Mode::Client,
    );
    for (name, local) in [("control", control), ("diagnostic", diagnostic)] {
        let mut stream = poll_fn(|cx| connection.poll_new_outbound(cx))
            .await
            .with_context(|| format!("opening mux {name} stream"))?;
        // Yamux sends the opening SYN on the first write, including an empty write.
        stream
            .write(&[])
            .await
            .with_context(|| format!("sending mux {name} SYN"))?;
        tokio::spawn(bridge(stream, local));
    }

    while let Some(stream) = poll_fn(|cx| connection.poll_next_inbound(cx)).await {
        let stream = stream?;
        anyhow::ensure!(stream.id().is_server(), "unexpected guest-initiated stream");
        let (agent, driver) = UnixStream::pair().context("creating client bridge")?;
        if clients.try_send(File::from(OwnedFd::from(agent))).is_err() {
            continue;
        }
        tokio::spawn(bridge(stream, File::from(OwnedFd::from(driver))));
    }
    Ok(())
}

async fn bridge(stream: yamux::Stream, local: File) {
    let Ok(reader) = local.try_clone().and_then(async_io::Async::new) else {
        return;
    };
    let Ok(mut writer) = async_io::Async::new(local) else {
        return;
    };
    let (mut stream_reader, mut stream_writer) = futures_util::io::AsyncReadExt::split(stream);
    let to_stream = async move {
        let copied = futures_util::io::copy(reader, &mut stream_writer).await;
        let closed = stream_writer.close().await;
        copied?;
        closed
    };
    let to_local = async move {
        futures_util::io::copy(&mut stream_reader, &mut writer).await?;
        rustix::net::shutdown(writer.get_ref(), rustix::net::Shutdown::Write)
            .map_err(std::io::Error::from)
    };
    let (output, input) = tokio::join!(to_stream, to_local);
    if let Err(error) = output.and(input) {
        eprintln!("terra-agent: mux bridge failed: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::io::AsyncReadExt as _;

    struct Carrier {
        control: crate::AsyncFile,
        diagnostic: crate::AsyncFile,
        clients: mpsc::Receiver<File>,
        control_stream: yamux::Stream,
        diagnostic_stream: yamux::Stream,
        client_streams: Vec<yamux::Stream>,
        driver: tokio::task::JoinHandle<()>,
        guest_driver: GuestMux,
    }

    async fn promptly<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(1), future)
            .await
            .expect("mux operation stalled")
    }

    async fn wait_for_guest_driver(driver: GuestMux) {
        promptly(async {
            while !driver.thread.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await;
        driver.wait();
    }

    async fn carrier(client_count: usize) -> Carrier {
        let (host, guest) = UnixStream::pair().unwrap();
        let Streams {
            control,
            diagnostic,
            clients,
            driver: guest_driver,
        } = GuestMux::start(File::from(OwnedFd::from(guest))).unwrap();
        let carrier = async_io::Async::new(File::from(OwnedFd::from(host))).unwrap();
        let mut connection = yamux::Connection::new(
            carrier,
            terra_protocol::mux::yamux_config(),
            yamux::Mode::Server,
        );
        let control_stream = promptly(poll_fn(|cx| connection.poll_next_inbound(cx)))
            .await
            .unwrap()
            .unwrap();
        let diagnostic_stream = promptly(poll_fn(|cx| connection.poll_next_inbound(cx)))
            .await
            .unwrap()
            .unwrap();
        let mut client_streams = Vec::with_capacity(client_count);
        for _ in 0..client_count {
            client_streams.push(
                promptly(poll_fn(|cx| connection.poll_new_outbound(cx)))
                    .await
                    .unwrap(),
            );
        }
        let driver = tokio::spawn(async move {
            while poll_fn(|cx| connection.poll_next_inbound(cx))
                .await
                .is_some()
            {}
        });
        Carrier {
            control: crate::into_async_file(control).unwrap(),
            diagnostic: crate::into_async_file(diagnostic).unwrap(),
            clients,
            control_stream,
            diagnostic_stream,
            client_streams,
            driver,
            guest_driver,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn carrier_loss_cancels_the_workload_and_finishes_the_guest_driver() {
        let Carrier {
            control,
            diagnostic: _diagnostic,
            clients: _clients,
            control_stream: _control_stream,
            diagnostic_stream: _diagnostic_stream,
            client_streams: _client_streams,
            driver,
            guest_driver,
        } = carrier(0).await;
        let stop = tokio_util::sync::CancellationToken::new();
        let watcher = tokio::spawn(crate::watch_control(
            control,
            stop.clone(),
            tokio_util::sync::CancellationToken::new(),
        ));
        driver.abort();
        promptly(stop.cancelled()).await;
        promptly(watcher).await.unwrap();
        wait_for_guest_driver(guest_driver).await;
    }

    async fn client_fin_keeps_the_reply_open(
        client_stream: &mut yamux::Stream,
        clients: &mut mpsc::Receiver<File>,
    ) {
        promptly(client_stream.write_all(b"host")).await.unwrap();
        promptly(client_stream.close()).await.unwrap();
        let guest = tokio::time::timeout(std::time::Duration::from_secs(1), clients.recv())
            .await
            .unwrap()
            .unwrap();
        let mut guest_reader = crate::into_async_file(guest.try_clone().unwrap()).unwrap();
        let mut received = [0; 4];
        promptly(tokio::io::AsyncReadExt::read_exact(
            &mut guest_reader,
            &mut received,
        ))
        .await
        .unwrap();
        assert_eq!(received, *b"host");
        assert_eq!(
            promptly(tokio::io::AsyncReadExt::read(
                &mut guest_reader,
                &mut received
            ))
            .await
            .unwrap(),
            0
        );
        let mut guest = crate::into_async_file(guest).unwrap();
        promptly(tokio::io::AsyncWriteExt::write_all(&mut guest, b"guest"))
            .await
            .unwrap();
        rustix::net::shutdown(guest.get_ref(), rustix::net::Shutdown::Write).unwrap();
        let mut reply = [0; 5];
        promptly(client_stream.read_exact(&mut reply))
            .await
            .unwrap();
        assert_eq!(reply, *b"guest");
        assert_eq!(promptly(client_stream.read(&mut reply)).await.unwrap(), 0);
    }

    /// A finished exec can close stdin before the host's EOF arrives. A failed
    /// input write must not cancel the bridge carrying the exec's final response.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn closed_agent_input_preserves_the_final_response() {
        let mut carrier = carrier(1).await;
        let mut client = carrier.client_streams.pop().unwrap();
        promptly(client.write(&[])).await.unwrap();
        let guest = promptly(carrier.clients.recv()).await.unwrap();
        rustix::net::shutdown(&guest, rustix::net::Shutdown::Read).unwrap();
        promptly(client.write_all(b"late input")).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let response =
            terra_protocol::encode_frame(&terra_protocol::AgentOutput::Exit { code: 7 }).unwrap();
        let mut guest = crate::into_async_file(guest).unwrap();
        promptly(tokio::io::AsyncWriteExt::write_all(&mut guest, &response))
            .await
            .unwrap();
        drop(guest);
        let mut received = vec![0; response.len()];
        promptly(client.read_exact(&mut received)).await.unwrap();
        assert_eq!(received, response);
        assert_eq!(promptly(client.read(&mut received)).await.unwrap(), 0);
        promptly(client.close()).await.unwrap();
        carrier.driver.abort();
        let _ = carrier.driver.await;
        wait_for_guest_driver(carrier.guest_driver).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_client_does_not_delay_control_or_large_client_bytes() {
        let Carrier {
            mut control,
            diagnostic: _diagnostic,
            mut clients,
            mut control_stream,
            diagnostic_stream: _diagnostic_stream,
            client_streams,
            driver,
            guest_driver: _guest_driver,
        } = carrier(2).await;
        let mut client_streams = client_streams.into_iter();
        let mut blocked_client = client_streams.next().unwrap();
        let mut large_client = client_streams.next().unwrap();
        let mut blocked = tokio::spawn(async move {
            let bytes = vec![0; terra_protocol::mux::MAX_STREAM_WINDOW_BYTES * 4];
            blocked_client.write_all(&bytes).await
        });
        let _blocked_agent = promptly(clients.recv()).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut blocked)
                .await
                .is_err()
        );

        promptly(control_stream.write_all(&[terra_protocol::STOP_SIGNAL]))
            .await
            .unwrap();
        let mut stop = [0; 1];
        promptly(tokio::io::AsyncReadExt::read_exact(&mut control, &mut stop))
            .await
            .unwrap();
        assert_eq!(stop, [terra_protocol::STOP_SIGNAL]);
        let ready =
            terra_protocol::encode_frame(&terra_protocol::LifecycleEvent::AgentReady).unwrap();
        promptly(tokio::io::AsyncWriteExt::write_all(&mut control, &ready))
            .await
            .unwrap();
        let mut response = vec![0; ready.len()];
        promptly(control_stream.read_exact(&mut response))
            .await
            .unwrap();
        assert_eq!(response, ready);

        let bytes = vec![0xA5; terra_protocol::mux::MAX_STREAM_FRAME_BYTES + 1];
        promptly(large_client.write_all(&bytes)).await.unwrap();
        let agent = promptly(clients.recv()).await.unwrap();
        let mut reader = crate::into_async_file(agent.try_clone().unwrap()).unwrap();
        let mut received = vec![0; bytes.len()];
        promptly(tokio::io::AsyncReadExt::read_exact(
            &mut reader,
            &mut received,
        ))
        .await
        .unwrap();
        assert_eq!(received, bytes);
        let mut writer = crate::into_async_file(agent).unwrap();
        promptly(tokio::io::AsyncWriteExt::write_all(&mut writer, &received))
            .await
            .unwrap();
        let mut reply = vec![0; received.len()];
        promptly(large_client.read_exact(&mut reply)).await.unwrap();
        assert_eq!(reply, received);
        blocked.abort();
        driver.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn carrier_bridges_reserved_and_host_opened_streams() {
        let Carrier {
            mut control,
            mut diagnostic,
            mut clients,
            mut control_stream,
            mut diagnostic_stream,
            mut client_streams,
            driver,
            guest_driver,
        } = carrier(1).await;
        assert_eq!(
            control_stream.id().val(),
            terra_protocol::mux::CONTROL_STREAM_ID
        );
        assert_eq!(
            diagnostic_stream.id().val(),
            terra_protocol::mux::DIAGNOSTIC_STREAM_ID
        );
        let mut client_stream = client_streams.pop().unwrap();
        promptly(control_stream.write_all(b"plan")).await.unwrap();
        let mut plan = [0; 4];
        promptly(tokio::io::AsyncReadExt::read_exact(&mut control, &mut plan))
            .await
            .unwrap();
        assert_eq!(plan, *b"plan");

        promptly(tokio::io::AsyncWriteExt::write_all(
            &mut diagnostic,
            b"diagnostic",
        ))
        .await
        .unwrap();
        let mut output = [0; 10];
        promptly(diagnostic_stream.read_exact(&mut output))
            .await
            .unwrap();
        assert_eq!(output, *b"diagnostic");

        client_fin_keeps_the_reply_open(&mut client_stream, &mut clients).await;
        drop(control_stream);
        drop(diagnostic_stream);
        drop(client_stream);
        driver.abort();
        let _ = driver.await;
        let mut eof = [0; 1];
        assert_eq!(
            promptly(tokio::io::AsyncReadExt::read(&mut control, &mut eof))
                .await
                .unwrap(),
            0
        );
        wait_for_guest_driver(guest_driver).await;
    }
}
