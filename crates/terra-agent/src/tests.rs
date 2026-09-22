use super::*;
use crate::diagnostics::write as write_diagnostic;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use terra_protocol::LifecycleEvent;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[test]
fn exit_report_is_framed_before_shutdown() {
    let mut agent = Vec::new();
    write_exit_report(&mut agent, 23).unwrap();
    assert_eq!(
        terra_protocol::read_frame::<LifecycleEvent>(&mut agent.as_slice()).unwrap(),
        Some(LifecycleEvent::Exit { code: 23 })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_exit_report_and_diagnostic_are_framed() {
    let (mut agent, mut host) = UnixStream::pair().unwrap();
    let mut diagnostic =
        crate::into_async_file(File::from(OwnedFd::from(agent.try_clone().unwrap()))).unwrap();
    write_diagnostic(&mut diagnostic, b"hook output")
        .await
        .unwrap();
    drop(diagnostic);
    write_exit_report(&mut agent, 23).unwrap();

    assert_eq!(
        terra_protocol::read_frame(&mut host).unwrap(),
        Some(LifecycleEvent::Diagnostic {
            bytes: b"hook output".to_vec()
        })
    );
    assert_eq!(
        terra_protocol::read_frame(&mut host).unwrap(),
        Some(LifecycleEvent::Exit { code: 23 })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_socket_transfers_more_than_its_buffer_without_blocking() {
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut sender = crate::into_async_file(sender).unwrap();
    let mut receiver = crate::into_async_file(receiver).unwrap();
    let payload = vec![42; 1 << 20];
    let sending = tokio::spawn(async move {
        sender.write_all(&payload).await.unwrap();
        rustix::net::shutdown(sender.get_ref(), rustix::net::Shutdown::Write).unwrap();
    });
    let mut output = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        receiver.read_to_end(&mut output).await.unwrap();
        sending.await.unwrap();
    })
    .await
    .unwrap();
    assert_eq!(output, vec![42; 1 << 20]);
}

#[tokio::test]
async fn agent_readiness_uses_control_without_waiting_for_hooks() {
    let (agent, host) = UnixStream::pair().unwrap();
    let control = File::from(OwnedFd::from(agent));
    let mut host = crate::into_async_file(host).unwrap();
    report_agent_ready(&control).await.unwrap();
    let event = terra_protocol::read_frame_async::<LifecycleEvent>(&mut host)
        .await
        .unwrap();
    assert_eq!(event, Some(LifecycleEvent::AgentReady));
}
