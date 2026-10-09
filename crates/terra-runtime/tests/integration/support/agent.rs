#![allow(dead_code)]

use std::collections::VecDeque;
use std::time::Duration;

use terra_platform::io::local::{LocalListener, LocalStream};
use terra_runtime::box_runtime::{BoxHost, BoxRuntime, BoxRuntimeHandle};
use terra_runtime::component::agent::Agent;
use terra_runtime::component::vmm::lifecycle::LifecycleNotifier;
use terra_runtime::component::vsock::streams::{STREAM_BUFFER_BYTES, StreamEndpoint};

pub struct AgentGuest {
    pub endpoint: StreamEndpoint,
    pub agent: Agent,
    pub lifecycle: LifecycleNotifier,
    pub connection_number: u64,
    pub read_limit: u32,
    runtime: BoxRuntimeHandle,
    root_finished: tokio::sync::oneshot::Sender<()>,
    teardown: terra_runtime::component::vmm::teardown::NativeTeardown,
    control_bytes: Vec<u8>,
    session_bytes: Vec<u8>,
    frames: VecDeque<YamuxFrame>,
}

impl AgentGuest {
    pub async fn create(
        plan: Vec<u8>,
        listener: Option<LocalListener>,
        control: Option<LocalStream>,
    ) -> Self {
        let engine = terra_runtime::engine::device_engine().expect("engine");
        let artifacts = super::artifacts::trusted_artifacts();
        let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
        let (endpoint, role_endpoint) = StreamEndpoint::pair();
        let agent = Agent::from_trusted_artifact(
            &mut runtime,
            role_endpoint,
            artifacts.agent(),
            plan,
            listener,
            control,
            None,
        )
        .expect("agent");
        let (root_finished, root_completion) = tokio::sync::oneshot::channel();
        runtime
            .register_loop(Box::new(move |_| {
                Box::pin(async move {
                    let _ = root_completion.await;
                    Ok(())
                })
            }))
            .expect("root loop");
        let teardown = runtime.native_teardown();
        let lifecycle = runtime.lifecycle_notifier();
        let runtime = runtime.prepare().await.expect("prepare").start();
        Self {
            endpoint,
            agent,
            lifecycle,
            connection_number: 1,
            read_limit: u32::try_from(STREAM_BUFFER_BYTES).expect("stream bound"),
            runtime,
            root_finished,
            teardown,
            control_bytes: Vec::new(),
            session_bytes: Vec::new(),
            frames: VecDeque::new(),
        }
    }

    pub async fn negotiate(&mut self) {
        self.endpoint
            .connect(self.connection_number)
            .expect("connect");
        let mut streams = yamux_frame(0, 1, terra_protocol::mux::CONTROL_STREAM_ID, 0, &[]);
        streams.extend(yamux_frame(
            0,
            1,
            terra_protocol::mux::DIAGNOSTIC_STREAM_ID,
            0,
            &[],
        ));
        self.send_session(&streams).await;
    }

    pub fn drain_control(&mut self) {
        while let Ok(bytes) = self
            .endpoint
            .try_read(self.connection_number, self.read_limit)
        {
            if bytes.is_empty() {
                break;
            }
            self.session_bytes.extend(bytes);
        }
        while self.session_bytes.len() >= 12 {
            let bytes = &self.session_bytes;
            let kind = bytes[1];
            let flags = u16::from_be_bytes(bytes[2..4].try_into().expect("flags"));
            let stream = u32::from_be_bytes(bytes[4..8].try_into().expect("stream"));
            let value = u32::from_be_bytes(bytes[8..12].try_into().expect("value"));
            let length = if kind == 0 { value as usize } else { 0 };
            if bytes.len() < 12 + length {
                break;
            }
            let payload = bytes[12..12 + length].to_vec();
            if kind == 0 && stream == terra_protocol::mux::CONTROL_STREAM_ID {
                self.control_bytes.extend(payload);
            } else {
                self.frames.push_back(YamuxFrame {
                    kind,
                    flags,
                    stream,
                    value,
                    payload,
                });
            }
            self.session_bytes.drain(..12 + length);
        }
    }

    pub async fn read_control(&mut self, length: usize) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.control_bytes.len() < length {
                self.drain_control();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            self.control_bytes.drain(..length).collect()
        })
        .await
        .expect("control progress deadline")
    }

    pub async fn read_plan(&mut self) -> terra_protocol::Plan {
        let length =
            u32::from_le_bytes(self.read_control(4).await.try_into().expect("frame length"));
        let envelope: terra_protocol::BootPlan =
            terra_protocol::decode_frame_payload(&self.read_control(length as usize).await)
                .expect("plan");
        envelope
            .validate_protocol_versions()
            .expect("plan versions");
        envelope.plan
    }

    pub async fn send_control(&mut self, bytes: &[u8]) {
        self.send_session(&yamux_frame(
            0,
            0,
            terra_protocol::mux::CONTROL_STREAM_ID,
            u32::try_from(bytes.len()).expect("control frame length"),
            bytes,
        ))
        .await;
    }

    pub async fn wait_for_stop(&mut self) {
        loop {
            let command = self.read_control(1).await[0];
            if command == terra_protocol::STOP_SIGNAL {
                return;
            }
            assert_eq!(command, terra_protocol::CLOCK_SYNC);
            let mut update = vec![command];
            update.extend(
                self.read_control(terra_protocol::CLOCK_SYNC_BYTES - 1)
                    .await,
            );
            assert!(terra_protocol::decode_clock_sync(&update).is_some());
        }
    }

    pub async fn send_session(&mut self, bytes: &[u8]) {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut written = 0;
            while written < bytes.len() {
                let chunk = &bytes[written..bytes.len().min(written + STREAM_BUFFER_BYTES)];
                written += self
                    .endpoint
                    .try_write(self.connection_number, chunk)
                    .expect("session bytes") as usize;
                if written < bytes.len() {
                    self.drain_control();
                    tokio::task::yield_now().await;
                }
            }
        })
        .await
        .expect("guest write deadline");
    }

    pub fn drain_yamux(&mut self) -> Vec<YamuxFrame> {
        self.drain_control();
        self.frames.drain(..).collect()
    }

    pub async fn wait_for_failure(&self) -> String {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(error) = self.agent.failure() {
                    return error;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("agent failure deadline")
    }

    pub async fn close(self) {
        self.agent.close_async().await.expect("close");
        let _ = self.root_finished.send(());
        tokio::time::timeout(Duration::from_secs(5), self.runtime.join())
            .await
            .expect("join deadline")
            .expect("join");
    }

    pub async fn close_disconnected(self) {
        let _ = self.agent.close_async().await;
        let _ = self
            .teardown
            .wait_until(std::time::Instant::now() + Duration::from_secs(3))
            .await;
        let _ = self.root_finished.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), self.runtime.join())
            .await
            .expect("failed runtime shutdown deadline");
    }
}

pub struct YamuxFrame {
    pub kind: u8,
    pub flags: u16,
    pub stream: u32,
    pub value: u32,
    pub payload: Vec<u8>,
}

pub fn yamux_frame(kind: u8, flags: u16, stream: u32, value: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, kind];
    bytes.extend(flags.to_be_bytes());
    bytes.extend(stream.to_be_bytes());
    bytes.extend(value.to_be_bytes());
    bytes.extend(payload);
    bytes
}

pub fn plan_frame() -> Vec<u8> {
    terra_protocol::encode_frame(&terra_protocol::BootPlan::new(
        super::artifacts::create_boot_plan(),
    ))
    .expect("plan encodes")
}
