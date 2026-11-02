use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::{Duration, Instant};

use terra_platform::local_socket::{LocalListener, LocalStream};

use super::yamux;
use crate::box_runtime::{BoxHost, BoxRuntime};
use crate::component::agent::Agent;
use crate::component::vsock::streams::StreamEndpoint;
use std::collections::BTreeMap;
use terra_protocol::AgentCommand;

struct GuestTransport {
    endpoint: StreamEndpoint,
    connection_number: u64,
    carrier_bytes: Vec<u8>,
    stream_bytes: BTreeMap<u32, Vec<u8>>,
}

impl GuestTransport {
    async fn send_bytes(&mut self, bytes: &[u8]) -> wasmtime::Result<()> {
        self.endpoint
            .write_all(self.connection_number, bytes)
            .await
            .map_err(|error| wasmtime::Error::msg(format!("agent device suite write: {error:?}")))
    }

    async fn receive_packets(&mut self) -> wasmtime::Result<()> {
        loop {
            let bytes = self
                .endpoint
                .try_read(self.connection_number, 16384)
                .map_err(|error| {
                    wasmtime::Error::msg(format!("agent device suite read: {error:?}"))
                })?;
            if bytes.is_empty() {
                break;
            }
            self.carrier_bytes.extend(bytes);
        }
        while let Some(frame) = yamux::take_frame(&mut self.carrier_bytes)? {
            if frame.kind == yamux::DATA {
                self.stream_bytes
                    .entry(frame.stream)
                    .or_default()
                    .extend(frame.payload);
            }
            if frame.flags & yamux::SYN != 0 {
                let acknowledgement = if frame.kind == yamux::PING {
                    yamux::encode(yamux::PING, yamux::ACK, frame.stream, frame.value, &[])
                } else {
                    yamux::encode(yamux::WINDOW_UPDATE, yamux::ACK, frame.stream, 0, &[])
                };
                self.send_bytes(&acknowledgement).await?;
            }
            wasmtime::ensure!(
                frame.kind != yamux::GO_AWAY,
                "agent device suite peer sent GoAway"
            );
        }
        Ok(())
    }

    async fn read_stream_bytes(&mut self, stream: u32, length: usize) -> wasmtime::Result<Vec<u8>> {
        loop {
            self.receive_packets().await?;
            let bytes = self.stream_bytes.entry(stream).or_default();
            if bytes.len() >= length {
                return Ok(bytes.drain(..length).collect());
            }
            self.endpoint.wait().await;
        }
    }

    async fn read_control(&mut self, length: usize) -> wasmtime::Result<Vec<u8>> {
        self.read_stream_bytes(terra_protocol::mux::CONTROL_STREAM_ID, length)
            .await
    }

    async fn read_control_message<T: terra_protocol::Message>(&mut self) -> wasmtime::Result<T> {
        let prefix = <[u8; 4]>::try_from(self.read_control(4).await?)
            .map_err(|_| wasmtime::Error::msg("device suite control frame prefix"))?;
        let length = terra_protocol::frame_payload_len::<T>(prefix)?;
        Ok(terra_protocol::decode_frame_payload(
            &self.read_control(length).await?,
        )?)
    }

    async fn send_control(&mut self, bytes: &[u8]) -> wasmtime::Result<()> {
        self.send_bytes(&yamux::data(
            0,
            terra_protocol::mux::CONTROL_STREAM_ID,
            bytes,
        )?)
        .await
    }
}

fn encode_plan() -> wasmtime::Result<Vec<u8>> {
    Ok(terra_protocol::encode_frame(
        &terra_protocol::Plan::bare_run(vec!["/bin/true".into()]),
    )?)
}

pub(super) async fn run(
    artifacts: &crate::TrustedArtifacts,
    engine: &wasmtime::Engine,
    directory: &Path,
) -> wasmtime::Result<()> {
    let client_directory = directory.to_owned();
    let clients = std::thread::spawn(move || run_clients(&client_directory));
    let result = run_with_clients(artifacts, engine, directory).await;
    let served = clients
        .join()
        .map_err(|_| wasmtime::Error::msg("agent device suite clients failed"))?;
    result?;
    served
}

fn run_clients(directory: &Path) -> wasmtime::Result<()> {
    let mut control = connect_client(&directory.join("agent-control.sock"))?;
    let mut client = connect_client(&directory.join("agent-agent.sock"))?;
    client.write_all(b"guestless input")?;
    let mut output = [0; b"guestless output".len()];
    client.set_read_timeout(Some(super::FIXTURE_STARTUP_WAIT))?;
    client.read_exact(&mut output).map_err(|error| {
        wasmtime::Error::msg(format!("agent device suite startup response: {error}"))
    })?;
    wasmtime::ensure!(
        &output == b"guestless output",
        "agent device suite local output"
    );
    control.write_all(&[terra_protocol::STOP_SIGNAL])?;
    Ok(())
}

fn connect_client(path: &Path) -> wasmtime::Result<LocalStream> {
    let deadline = Instant::now() + super::FIXTURE_STARTUP_WAIT;
    let client = loop {
        match LocalStream::connect(path) {
            Ok(client) => break client,
            Err(error) => {
                wasmtime::ensure!(
                    Instant::now() < deadline,
                    "agent device suite client connection: {error}"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    };
    client.set_read_timeout(Some(super::STEP_WAIT))?;
    client.set_write_timeout(Some(super::STEP_WAIT))?;
    Ok(client)
}

async fn run_with_clients(
    artifacts: &crate::TrustedArtifacts,
    engine: &wasmtime::Engine,
    directory: &Path,
) -> wasmtime::Result<()> {
    let control_listener = LocalListener::bind(directory.join("agent-control.sock"))?;
    let listener = LocalListener::bind(directory.join("agent-agent.sock"))?;
    control_listener.set_nonblocking(true)?;
    let control_grant = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match control_listener.accept() {
                Ok((stream, _)) => return Ok(stream),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .map_err(|error| {
        wasmtime::Error::from(error).context("agent device suite control client admission")
    })??;
    drop(control_listener);
    let (mut peer, endpoint) = StreamEndpoint::pair();
    peer.connect(1)
        .map_err(|error| wasmtime::Error::msg(format!("agent device suite connect: {error:?}")))?;
    let mut runtime = BoxRuntime::new(engine, BoxHost::new())?;
    let _agent = Agent::from_trusted_artifact(
        &mut runtime,
        endpoint,
        artifacts.agent,
        encode_plan()?,
        Some(listener),
        Some(control_grant),
        None,
    )?;
    let lifecycle = runtime.lifecycle_notifier();
    let teardown = runtime.native_teardown();
    let (finished, finish) = tokio::sync::oneshot::channel();
    runtime.register_loop(Box::new(move |_| {
        Box::pin(async move {
            finish.await.map_err(wasmtime::Error::from)?;
            Ok(())
        })
    }))?;
    let runtime = runtime.prepare().await?.start();
    let mut guest = GuestTransport {
        endpoint: peer,
        connection_number: 1,
        carrier_bytes: Vec::new(),
        stream_bytes: BTreeMap::new(),
    };
    let result = tokio::time::timeout(super::STEP_WAIT, async {
        exercise_transport(&mut guest).await?;
        lifecycle.wait_for_agent_ready().await;
        Ok(())
    })
    .await
    .map_err(wasmtime::Error::from)
    .and_then(std::convert::identity);
    let closed = teardown
        .wait_until(Instant::now() + super::STEP_WAIT)
        .await
        .map_err(wasmtime::Error::msg);
    let _ = finished.send(());
    let joined = runtime.join().await;
    result?;
    closed?;
    joined
}

async fn exercise_transport(guest: &mut GuestTransport) -> wasmtime::Result<()> {
    for stream in terra_protocol::mux::RESERVED_STREAM_IDS {
        guest
            .send_bytes(&yamux::encode(yamux::DATA, yamux::SYN, stream, 0, &[]))
            .await?;
    }
    let _: terra_protocol::Plan = guest.read_control_message().await?;
    let host_state: terra_protocol::HostState = guest.read_control_message().await?;
    wasmtime::ensure!(
        host_state.time.nanoseconds < 1_000_000_000 && host_state.seed != [0; 32],
        "agent device suite host state follows the plan"
    );
    guest
        .send_control(&terra_protocol::encode_frame(
            &terra_protocol::LifecycleEvent::AgentReady,
        )?)
        .await?;
    let input = guest
        .read_stream_bytes(yamux::FIRST_CLIENT_STREAM_ID, b"guestless input".len())
        .await?;
    wasmtime::ensure!(
        input == b"guestless input",
        "agent device suite local input"
    );
    guest
        .send_bytes(&yamux::data(
            0,
            yamux::FIRST_CLIENT_STREAM_ID,
            b"guestless output",
        )?)
        .await?;
    loop {
        match guest.read_control_message().await? {
            AgentCommand::Stop => break,
            AgentCommand::SyncClock(time) => {
                wasmtime::ensure!(
                    time.nanoseconds < 1_000_000_000,
                    "device suite clock update"
                );
            }
        }
    }
    Ok(())
}
