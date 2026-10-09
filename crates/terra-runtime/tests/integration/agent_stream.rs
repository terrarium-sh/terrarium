use crate::support::agent as support;

use std::time::Duration;
use support::{AgentGuest, plan_frame, yamux_frame};
use terra_runtime::component::vsock::streams::stream_types::StreamError;

/// Fragmenting every Yamux header and lifecycle frame preserves boot-plan
/// delivery, version validation, and readiness.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fragmented_stream_delivers_plan_and_lifecycle() {
    let mut envelope: terra_protocol::BootPlan =
        terra_protocol::decode_frame_payload(&plan_frame()[4..]).expect("plan");
    envelope.plan.sandbox_info = "x".repeat(4 * 1024);
    let expected = envelope.plan.sandbox_info.clone();
    let mut agent = AgentGuest::create(
        terra_protocol::encode_frame(&envelope).expect("plan"),
        None,
        None,
    )
    .await;
    agent.read_limit = 7;
    agent
        .endpoint
        .connect(agent.connection_number)
        .expect("connect");
    let mut frames = yamux_frame(0, 1, terra_protocol::mux::CONTROL_STREAM_ID, 0, &[]);
    frames.extend(yamux_frame(
        0,
        1,
        terra_protocol::mux::DIAGNOSTIC_STREAM_ID,
        0,
        &[],
    ));
    for byte in frames {
        agent.send_session(&[byte]).await;
    }
    assert_eq!(agent.read_plan().await.sandbox_info, expected);
    let ready =
        terra_protocol::encode_frame(&terra_protocol::LifecycleEvent::AgentReady).expect("ready");
    for byte in ready {
        agent.send_control(&[byte]).await;
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while !agent.lifecycle.is_agent_ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("fragmented lifecycle progresses");
    agent.close().await;
}

/// The guest cannot open a host-owned stream or replace the reserved control
/// stream with a client command stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_direction_stream_cannot_select_agent_services() {
    for stream in [2, 5] {
        let mut agent = AgentGuest::create(plan_frame(), None, None).await;
        agent
            .endpoint
            .connect(agent.connection_number)
            .expect("connect");
        agent.send_session(&yamux_frame(0, 1, stream, 0, &[])).await;
        if stream == 2 {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Some(frame) = agent
                        .drain_yamux()
                        .into_iter()
                        .find(|frame| frame.kind == 3)
                    {
                        assert_eq!(frame.value, 1);
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("wrong-direction stream gets protocol GoAway");
            agent.send_session(&yamux_frame(3, 0, 0, 0, &[])).await;
        }
        let failure = agent.wait_for_failure().await;
        assert!(failure.contains("disconnected"), "{failure}");
        assert!(!agent.lifecycle.is_agent_ready());
        agent.close_disconnected().await;
    }
}

/// Diagnostic payloads cannot impersonate lifecycle events on the reserved
/// control stream and cause the worker to fail before readiness.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn diagnostic_frame_on_control_stream_is_rejected() {
    let mut agent = AgentGuest::create(plan_frame(), None, None).await;
    agent.negotiate().await;
    agent.read_plan().await;
    agent
        .send_control(
            &terra_protocol::encode_frame(&terra_protocol::LifecycleEvent::Diagnostic {
                bytes: b"forged".to_vec(),
            })
            .expect("diagnostic frame"),
        )
        .await;
    let failure = agent.wait_for_failure().await;
    assert!(failure.contains("disconnected"), "{failure}");
    assert!(!agent.lifecycle.is_agent_ready());
    agent.close_disconnected().await;
}

/// Replacement invalidates old endpoint handles and the pinned agent worker;
/// the replacement connection cannot replay the boot plan.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_connection_number_cannot_restart_agent_session() {
    let mut agent = AgentGuest::create(plan_frame(), None, None).await;
    agent.negotiate().await;
    agent.read_plan().await;
    agent
        .send_control(
            &terra_protocol::encode_frame(&terra_protocol::LifecycleEvent::AgentReady)
                .expect("ready"),
        )
        .await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while !agent.lifecycle.is_agent_ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("ready");
    let old_connection_number = agent.connection_number;
    agent.endpoint.disconnect(old_connection_number);
    agent
        .endpoint
        .connect(old_connection_number + 1)
        .expect("replacement");
    assert!(matches!(
        agent.endpoint.try_write(old_connection_number, &[0]),
        Err(StreamError::Stale)
    ));
    assert!(matches!(
        agent.endpoint.try_read(old_connection_number, 1),
        Err(StreamError::Stale)
    ));
    let failure = agent.wait_for_failure().await;
    assert!(failure.contains("disconnected"), "{failure}");
    assert!(!agent.lifecycle.is_agent_ready());
    assert_eq!(
        agent
            .endpoint
            .try_read(old_connection_number + 1, 65536)
            .expect("replacement read"),
        [] as [u8; 0]
    );
    agent.close_disconnected().await;
}

/// Losing the carrier while waiting for the diagnostic stream fails promptly
/// instead of waiting for guest readiness forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_loss_before_diagnostic_stream_terminates_worker() {
    let mut agent = AgentGuest::create(plan_frame(), None, None).await;
    agent
        .endpoint
        .connect(agent.connection_number)
        .expect("connect");
    agent
        .send_session(&yamux_frame(
            0,
            1,
            terra_protocol::mux::CONTROL_STREAM_ID,
            0,
            &[],
        ))
        .await;
    agent.read_plan().await;
    agent.endpoint.close(agent.connection_number);
    let failure = agent.wait_for_failure().await;
    assert!(failure.contains("disconnected"), "{failure}");
    assert!(!agent.lifecycle.is_agent_ready());
    agent.close_disconnected().await;
}
