#![allow(dead_code)]

use std::collections::VecDeque;
use std::time::Duration;

use terra_platform::local_socket::{LocalListener, LocalStream};
use terra_runtime::box_runtime::{BoxHost, BoxRuntime, BoxRuntimeHandle};
use terra_runtime::component::agent::Agent;
use terra_runtime::component::vmm::lifecycle::LifecycleNotifier;
use terra_runtime::component::vsock::streams::{STREAM_BUFFER_BYTES, StreamEndpoint};
use terra_runtime::test_support::yamux;

pub struct AgentGuest {
    pub endpoint: StreamEndpoint,
    pub agent: Agent,
    pub lifecycle: LifecycleNotifier,
    pub connection_number: u64,
    pub read_limit: usize,
    runtime: BoxRuntimeHandle,
    root_finished: tokio::sync::oneshot::Sender<()>,
    teardown: terra_runtime::component::vmm::teardown::NativeTeardown,
    control_bytes: Vec<u8>,
    session_bytes: Vec<u8>,
    frames: VecDeque<yamux::Frame>,
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
            artifacts.agent,
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
            read_limit: STREAM_BUFFER_BYTES,
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
        let streams: Vec<u8> = terra_protocol::mux::RESERVED_STREAM_IDS
            .into_iter()
            .flat_map(|stream| yamux::encode(yamux::DATA, yamux::SYN, stream, 0, &[]))
            .collect();
        self.send_session(&streams).await;
    }

    pub fn drain_session(&mut self) {
        while let Ok(bytes) = self
            .endpoint
            .try_read(self.connection_number, self.read_limit)
        {
            if bytes.is_empty() {
                break;
            }
            self.session_bytes.extend(bytes);
        }
        while let Some(frame) = yamux::take_frame(&mut self.session_bytes).expect("yamux frame") {
            if frame.kind == yamux::DATA && frame.stream == terra_protocol::mux::CONTROL_STREAM_ID {
                self.control_bytes.extend(frame.payload);
            } else {
                self.frames.push_back(frame);
            }
        }
    }

    pub async fn read_control(&mut self, length: usize) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.control_bytes.len() < length {
                self.drain_session();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            self.control_bytes.drain(..length).collect()
        })
        .await
        .expect("control progress deadline")
    }

    /// Reads the boot plan and the host state frame that follows it.
    pub async fn read_plan(&mut self) -> terra_protocol::Plan {
        let plan = self.read_control_message().await;
        let _: terra_protocol::HostState = self.read_control_message().await;
        plan
    }

    async fn read_control_message<T: terra_protocol::Message>(&mut self) -> T {
        let prefix = self.read_control(4).await.try_into().expect("frame length");
        let length = terra_protocol::frame_payload_len::<T>(prefix).expect("frame length");
        terra_protocol::decode_frame_payload(&self.read_control(length).await)
            .expect("control message")
    }

    pub async fn send_control(&mut self, bytes: &[u8]) {
        self.send_session(
            &yamux::data(0, terra_protocol::mux::CONTROL_STREAM_ID, bytes).expect("control frame"),
        )
        .await;
    }

    pub async fn wait_for_stop(&mut self) {
        loop {
            match self.read_control_message().await {
                terra_protocol::AgentCommand::Stop => return,
                terra_protocol::AgentCommand::SyncClock(time) => {
                    assert!(time.nanoseconds < 1_000_000_000);
                }
            }
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
                    .expect("session bytes");
                if written < bytes.len() {
                    self.drain_session();
                    tokio::task::yield_now().await;
                }
            }
        })
        .await
        .expect("guest write deadline");
    }

    pub fn drain_yamux(&mut self) -> Vec<yamux::Frame> {
        self.drain_session();
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

pub fn plan_frame() -> Vec<u8> {
    terra_protocol::encode_frame(&terra_protocol::Plan::bare_run(vec!["/bin/sh".into()]))
        .expect("plan encodes")
}
