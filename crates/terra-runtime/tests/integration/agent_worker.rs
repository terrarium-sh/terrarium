use crate::support::agent as support;

use std::io::{self, Read as _, Write as _};
use std::time::Duration;

use terra_platform::io::local::{LocalListener, LocalStream, create_local_pair};
use terra_protocol::mux::MAX_STREAM_WINDOW_BYTES;

use support::{AgentGuest, plan_frame, yamux_frame};

const PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

async fn start_client() -> (tempfile::TempDir, AgentGuest, LocalStream) {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("agent.sock");
    let listener = LocalListener::bind(&path).expect("listener");
    let client = LocalStream::connect(&path).expect("client");
    client.set_nonblocking(true).expect("nonblocking client");
    let mut agent = AgentGuest::create(plan_frame(), Some(listener), None).await;
    agent.negotiate().await;
    agent.read_plan().await;
    (directory, agent, client)
}

/// Both directions transfer more than the carrier buffers and Yamux window;
/// the reserved control stream delivers guest readiness during the exchange.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_round_trip_preserves_large_payloads() {
    let (_directory, mut agent, mut client) = start_client().await;
    agent
        .send_control(
            &terra_protocol::encode_frame(&terra_protocol::LifecycleEvent::AgentReady)
                .expect("ready frame"),
        )
        .await;
    let request = vec![b'q'; PAYLOAD_BYTES];
    let response = vec![b'r'; PAYLOAD_BYTES];
    let mut written = 0;
    let mut received: Vec<u8> = Vec::new();
    let mut response_written = 0;
    let mut client_received: Vec<u8> = Vec::new();
    let mut send_credit = MAX_STREAM_WINDOW_BYTES;
    tokio::time::timeout(Duration::from_secs(20), async {
        while client_received.len() < PAYLOAD_BYTES {
            if written < request.len() {
                match client.write(&request[written..(written + 16 * 1024).min(request.len())]) {
                    Ok(count) => written += count,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("client write: {error}"),
                }
            }
            for frame in agent.drain_yamux() {
                if frame.stream != 2 {
                    continue;
                }
                if frame.flags & 1 != 0 {
                    agent.send_session(&yamux_frame(1, 2, 2, 0, &[])).await;
                }
                if frame.kind == 0 && !frame.payload.is_empty() {
                    received.extend_from_slice(&frame.payload);
                    agent
                        .send_session(&yamux_frame(1, 0, 2, frame.value, &[]))
                        .await;
                } else if frame.kind == 1 {
                    send_credit += frame.value as usize;
                }
            }
            if received.len() == PAYLOAD_BYTES
                && response_written < PAYLOAD_BYTES
                && send_credit != 0
            {
                let length = (PAYLOAD_BYTES - response_written)
                    .min(8192)
                    .min(send_credit);
                agent
                    .send_session(&yamux_frame(
                        0,
                        0,
                        2,
                        u32::try_from(length).expect("bounded frame length"),
                        &response[response_written..response_written + length],
                    ))
                    .await;
                response_written += length;
                send_credit -= length;
            }
            let mut bytes = vec![0; 16 * 1024];
            match client.read(&mut bytes) {
                Ok(0) => panic!("client closed before response"),
                Ok(count) => client_received.extend(&bytes[..count]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("client read: {error}"),
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("large transfer deadline");
    assert_eq!(received, request);
    assert_eq!(client_received, response);
    assert!(agent.lifecycle.is_agent_ready());
    agent.close().await;
}

/// Exhausting a client stream's Yamux credit does not block readiness or stop
/// on the reserved control stream while the guest keeps reading the carrier.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_progress_survives_stalled_bulk_delivery() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("agent.sock");
    let listener = LocalListener::bind(&path).expect("listener");
    let mut client = LocalStream::connect(&path).expect("client");
    client.set_nonblocking(true).expect("nonblocking client");
    let (mut stop_sender, stop_grant) = create_local_pair().expect("control pair");
    let mut agent = AgentGuest::create(plan_frame(), Some(listener), Some(stop_grant)).await;
    agent.negotiate().await;
    agent.read_plan().await;
    wait_for_client_stream(&mut agent).await;
    agent.send_session(&yamux_frame(1, 2, 2, 0, &[])).await;
    let payload = vec![b'x'; PAYLOAD_BYTES];
    let mut written = 0;
    let mut received = 0;
    tokio::time::timeout(Duration::from_secs(3), async {
        while received < MAX_STREAM_WINDOW_BYTES {
            if written < payload.len() {
                match client.write(&payload[written..]) {
                    Ok(count) => written += count,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("bulk input: {error}"),
                }
            }
            received += agent
                .drain_yamux()
                .into_iter()
                .filter(|frame| frame.kind == 0 && frame.stream == 2)
                .map(|frame| frame.payload.len())
                .sum::<usize>();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("client window fills");
    assert_eq!(received, MAX_STREAM_WINDOW_BYTES);
    agent
        .send_control(
            &terra_protocol::encode_frame(&terra_protocol::LifecycleEvent::AgentReady)
                .expect("ready frame"),
        )
        .await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while !agent.lifecycle.is_agent_ready() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("readiness progresses while client credit is exhausted");
    stop_sender
        .write_all(&[terra_protocol::STOP_SIGNAL])
        .expect("stop signal");
    agent.wait_for_stop().await;
    assert!(
        agent
            .drain_yamux()
            .iter()
            .all(|frame| frame.stream != 2 || frame.payload.is_empty())
    );
    agent.endpoint.disconnect(agent.connection_number);
    wait_for_client_eof(&mut client).await;
    let failure = agent.wait_for_failure().await;
    assert!(failure.contains("disconnected"), "{failure}");
    agent.close_disconnected().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reset_releases_the_open_client() {
    let (_directory, mut agent, mut client) = start_client().await;
    wait_for_client_stream(&mut agent).await;
    agent.endpoint.disconnect(agent.connection_number);
    wait_for_client_eof(&mut client).await;
    let failure = agent.wait_for_failure().await;
    assert!(failure.contains("disconnected"), "{failure}");
    assert!(!agent.lifecycle.is_agent_ready());
    agent.close_disconnected().await;
}

/// A malformed lifecycle frame terminates the connection and releases host clients.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_lifecycle_releases_the_open_client() {
    let (_directory, mut agent, mut client) = start_client().await;
    wait_for_client_stream(&mut agent).await;
    agent.send_control(&u32::MAX.to_le_bytes()).await;
    wait_for_client_eof(&mut client).await;
    let failure = agent.wait_for_failure().await;
    assert!(failure.contains("disconnected"), "{failure}");
    agent.close_disconnected().await;
}

/// Resetting one authorized session closes its local client without tearing
/// down the control session or the other reserved streams.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_client_stream_preserves_agent_readiness() {
    let (_directory, mut agent, mut client) = start_client().await;
    wait_for_client_stream(&mut agent).await;
    agent
        .send_control(
            &terra_protocol::encode_frame(&terra_protocol::LifecycleEvent::AgentReady)
                .expect("ready frame"),
        )
        .await;
    agent.send_session(&yamux_frame(0, 8, 2, 0, &[])).await;
    wait_for_client_eof(&mut client).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while !agent.lifecycle.is_agent_ready() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("readiness survives client cancellation");
    assert!(agent.agent.failure().is_none());
    agent.close().await;
}

async fn wait_for_client_stream(agent: &mut AgentGuest) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if agent
                .drain_yamux()
                .iter()
                .any(|frame| frame.stream == 2 && frame.flags & 1 != 0)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("host client SYN");
}

async fn wait_for_client_eof(client: &mut LocalStream) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match client.read(&mut [0; 1]) {
                Ok(0) => break,
                Ok(_) => panic!("closed client received bytes"),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => break,
                Err(error) => panic!("client disconnect: {error}"),
            }
        }
    })
    .await
    .expect("closed session releases client");
}
