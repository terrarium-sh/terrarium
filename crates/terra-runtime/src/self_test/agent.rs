use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::{Duration, Instant};

use terra_platform::io::local::{LocalListener, LocalStream};

use crate::box_runtime::{BoxHost, BoxRuntime};
use crate::component::agent::Agent;
use crate::component::vsock::streams::StreamEndpoint;
use std::collections::BTreeMap;

const YAMUX_HEADER_BYTES: usize = 12;

struct GuestTransport {
    endpoint: StreamEndpoint,
    connection_number: u64,
    carrier_bytes: Vec<u8>,
    stream_bytes: BTreeMap<u32, Vec<u8>>,
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> wasmtime::Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .ok_or_else(|| wasmtime::Error::msg("short agent self-test frame"))?
        .try_into()
        .map_err(wasmtime::Error::from)
}

fn yamux_frame(kind: u8, flags: u16, stream: u32, payload: &[u8]) -> wasmtime::Result<Vec<u8>> {
    let mut bytes = vec![0, kind];
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes.extend_from_slice(&stream.to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(payload.len())?.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

impl GuestTransport {
    async fn send_bytes(&mut self, bytes: &[u8]) -> wasmtime::Result<()> {
        let mut sent = 0;
        while sent < bytes.len() {
            let end = bytes
                .len()
                .min(sent + terra_protocol::mux::MAX_STREAM_FRAME_BYTES);
            let count = self
                .endpoint
                .try_write(self.connection_number, &bytes[sent..end])
                .map_err(|error| {
                    wasmtime::Error::msg(format!("agent self-test write: {error:?}"))
                })? as usize;
            if count == 0 {
                self.endpoint.wait().await;
            } else {
                sent += count;
            }
        }
        Ok(())
    }

    async fn receive_packets(&mut self) -> wasmtime::Result<()> {
        loop {
            let bytes = self
                .endpoint
                .try_read(self.connection_number, 16384)
                .map_err(|error| {
                    wasmtime::Error::msg(format!("agent self-test read: {error:?}"))
                })?;
            if bytes.is_empty() {
                break;
            }
            self.carrier_bytes.extend(bytes);
        }
        while self.carrier_bytes.len() >= YAMUX_HEADER_BYTES {
            let kind = self.carrier_bytes[1];
            let flags = u16::from_be_bytes(field(&self.carrier_bytes, 2)?);
            let stream = u32::from_be_bytes(field(&self.carrier_bytes, 4)?);
            let length = if kind == 0 {
                usize::try_from(u32::from_be_bytes(field(&self.carrier_bytes, 8)?))?
            } else {
                0
            };
            wasmtime::ensure!(
                length <= terra_protocol::mux::MAX_STREAM_FRAME_BYTES,
                "agent self-test Yamux frame limit"
            );
            let end = YAMUX_HEADER_BYTES + length;
            if self.carrier_bytes.len() < end {
                break;
            }
            let mut frame: Vec<_> = self.carrier_bytes.drain(..end).collect();
            if kind == 0 {
                self.stream_bytes
                    .entry(stream)
                    .or_default()
                    .extend(&frame[YAMUX_HEADER_BYTES..]);
            }
            if flags & 1 != 0 {
                if kind == 2 {
                    frame[2..4].copy_from_slice(&2_u16.to_be_bytes());
                    self.send_bytes(&frame).await?;
                } else {
                    self.send_bytes(&yamux_frame(1, 2, stream, &[])?).await?;
                }
            }
            wasmtime::ensure!(kind != 3, "agent self-test peer sent GoAway");
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

    async fn send_control(&mut self, bytes: &[u8]) -> wasmtime::Result<()> {
        self.send_bytes(&yamux_frame(
            0,
            0,
            terra_protocol::mux::CONTROL_STREAM_ID,
            bytes,
        )?)
        .await
    }
}

fn encode_plan() -> wasmtime::Result<Vec<u8>> {
    Ok(terra_protocol::encode_frame(
        &terra_protocol::BootPlan::new(terra_protocol::Plan {
            mode: terra_protocol::PlanMode::Run,
            workdir: None,
            shares: Vec::new(),
            volumes: Vec::new(),
            net: terra_protocol::Net::Tsi,
            published_ports: Vec::new(),
            published_udp_ports: Vec::new(),
            env: std::collections::BTreeMap::new(),
            root: false,
            sudo: Vec::new(),
            on_create: Vec::new(),
            on_start: Vec::new(),
            pre_stop: Vec::new(),
            daemons: Vec::new(),
            workload: vec!["/bin/true".into()],
            sandbox_info: String::new(),
            await_initial_session: false,
            host_tz: None,
            host_time: None,
            host_seed: None,
        }),
    )?)
}

pub(super) async fn run(
    artifacts: &crate::TrustedArtifacts,
    engine: &wasmtime::Engine,
    directory: &Path,
) -> wasmtime::Result<()> {
    let client_directory = directory.to_owned();
    let clients = std::thread::spawn(move || run_clients(&client_directory));
    let result = run_with_external_clients(artifacts, engine, directory, None).await;
    let served = clients
        .join()
        .map_err(|_| wasmtime::Error::msg("agent self-test clients failed"))?;
    result?;
    served
}

pub(super) fn run_clients(directory: &Path) -> wasmtime::Result<()> {
    let mut control = connect_client(&directory.join("agent-control.sock"))?;
    let mut client = connect_client(&directory.join("agent-agent.sock"))?;
    client.write_all(b"guestless input")?;
    let mut output = [0; b"guestless output".len()];
    client.set_read_timeout(Some(super::FIXTURE_STARTUP_WAIT))?;
    client.read_exact(&mut output).map_err(|error| {
        wasmtime::Error::msg(format!("agent self-test startup response: {error}"))
    })?;
    wasmtime::ensure!(
        &output == b"guestless output",
        "agent self-test local output"
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
                    "agent self-test client connection: {error}"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    };
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    client.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(client)
}

pub(super) async fn run_with_external_clients(
    artifacts: &crate::TrustedArtifacts,
    engine: &wasmtime::Engine,
    directory: &Path,
    listeners: Option<super::AgentListeners>,
) -> wasmtime::Result<()> {
    let super::AgentListeners {
        control: control_listener,
        agent: listener,
    } = match listeners {
        Some(listeners) => listeners,
        None => super::AgentListeners {
            control: LocalListener::bind(directory.join("agent-control.sock"))?,
            agent: LocalListener::bind(directory.join("agent-agent.sock"))?,
        },
    };
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
        wasmtime::Error::from(error).context("agent self-test control client admission")
    })??;
    drop(control_listener);
    let (mut peer, endpoint) = StreamEndpoint::pair();
    peer.connect(1)
        .map_err(|error| wasmtime::Error::msg(format!("agent self-test connect: {error:?}")))?;
    let mut runtime = BoxRuntime::new(engine, BoxHost::new())?;
    let _agent = Agent::from_trusted_artifact(
        &mut runtime,
        endpoint,
        artifacts.agent(),
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
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        exercise_transport(&mut guest).await?;
        lifecycle.wait_for_agent_ready().await;
        Ok(())
    })
    .await
    .map_err(wasmtime::Error::from)
    .and_then(std::convert::identity);
    let closed = teardown
        .wait_until(Instant::now() + Duration::from_secs(5))
        .await
        .map_err(wasmtime::Error::msg);
    let _ = finished.send(());
    let joined = runtime.join().await;
    result?;
    closed?;
    joined
}

async fn exercise_transport(guest: &mut GuestTransport) -> wasmtime::Result<()> {
    for stream in [
        terra_protocol::mux::CONTROL_STREAM_ID,
        terra_protocol::mux::DIAGNOSTIC_STREAM_ID,
    ] {
        guest.send_bytes(&yamux_frame(0, 1, stream, &[])?).await?;
    }
    let length = u32::from_le_bytes(field(&guest.read_control(4).await?, 0)?);
    let plan = guest.read_control(usize::try_from(length)?).await?;
    let envelope: terra_protocol::BootPlan = terra_protocol::decode_frame_payload(&plan)?;
    envelope.validate_protocol_versions()?;
    let decoded = envelope.plan;
    wasmtime::ensure!(
        decoded.host_time.is_some() && decoded.host_seed.is_some(),
        "agent self-test host plan enrichment"
    );
    guest
        .send_control(&terra_protocol::encode_frame(
            &terra_protocol::LifecycleEvent::AgentReady,
        )?)
        .await?;
    let input = guest.read_stream_bytes(2, b"guestless input".len()).await?;
    wasmtime::ensure!(input == b"guestless input", "agent self-test local input");
    guest
        .send_bytes(&yamux_frame(0, 0, 2, b"guestless output")?)
        .await?;
    loop {
        let command = guest.read_control(1).await?[0];
        if command == terra_protocol::STOP_SIGNAL {
            break;
        }
        wasmtime::ensure!(
            command == terra_protocol::CLOCK_SYNC,
            "unexpected self-test control command"
        );
        let mut update = vec![command];
        update.extend(
            guest
                .read_control(terra_protocol::CLOCK_SYNC_BYTES - 1)
                .await?,
        );
        wasmtime::ensure!(
            terra_protocol::decode_clock_sync(&update).is_some(),
            "self-test clock update"
        );
    }
    Ok(())
}
