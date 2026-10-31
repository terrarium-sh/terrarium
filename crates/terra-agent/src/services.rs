//! Agent session, file transfer, and exec services.

use crate::AsyncFile;
use crate::term::session::{ClientConn, DetachOutcome, Session};
use std::fs::File;
use std::os::fd::AsFd;
use std::sync::Arc;
use std::time::Duration;
use terra_protocol::{
    AGENT_HELLO, AgentService, ClientInput, ControlReply, ControlRequest, MAX_SERVICE_FRAME_BYTES,
    TermSize, read_frame_async_with_limit,
};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{mpsc, watch};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const STARTUP_WAIT: Duration = Duration::from_mins(5);
const SERVICE_SELECT_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);

/// Whether sync and exec are served; the console session and its control always are.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupState {
    /// Sync and exec wait until the state changes or `STARTUP_WAIT` runs out.
    Pending,
    Ready,
    Refused,
}

/// Changes the [`StartupState`] of a running server; dropping it refuses requests still pending.
pub(crate) struct Server(watch::Sender<StartupState>);

impl Server {
    pub(crate) fn update_state(&self, state: StartupState) {
        self.0.send_replace(state);
    }
}

pub(crate) fn init_server(
    tasks: &TaskTracker,
    session: Arc<Session>,
    mut clients: mpsc::Receiver<File>,
    workload_is_root: bool,
    initial_session: Option<mpsc::Sender<()>>,
    initial_state: StartupState,
    cancellation: &CancellationToken,
) -> Server {
    let (state, startup) = watch::channel(initial_state);
    let services = Services {
        session,
        workload_is_root,
        initial_session,
        startup,
        cancellation: cancellation.clone(),
    };
    let connections = tasks.clone();
    tasks.spawn(async move {
        while let Some(conn) = services
            .cancellation
            .run_until_cancelled(clients.recv())
            .await
            .flatten()
        {
            connections.spawn(services.clone().serve(conn));
        }
    });
    Server(state)
}

async fn wait_until_started(startup: &mut watch::Receiver<StartupState>) -> bool {
    let outcome = tokio::time::timeout(
        STARTUP_WAIT,
        startup.wait_for(|state| match state {
            StartupState::Pending => false,
            StartupState::Ready | StartupState::Refused => true,
        }),
    )
    .await;
    matches!(outcome, Ok(Ok(state)) if *state == StartupState::Ready)
}

/// What each client connection is served with; every connection task owns a copy.
#[derive(Clone)]
struct Services {
    session: Arc<Session>,
    workload_is_root: bool,
    initial_session: Option<mpsc::Sender<()>>,
    startup: watch::Receiver<StartupState>,
    cancellation: CancellationToken,
}

impl Services {
    async fn serve(self, conn: File) {
        let Self {
            session,
            workload_is_root,
            initial_session,
            mut startup,
            cancellation,
        } = self;
        let Ok(mut conn) = crate::into_async_file(conn) else {
            return;
        };
        let service = cancellation
            .run_until_cancelled(async {
                conn.write_all(&AGENT_HELLO).await?;
                conn.flush().await?;
                tokio::time::timeout(
                    SERVICE_SELECT_TIMEOUT,
                    read_frame_async_with_limit::<AgentService>(&mut conn, MAX_SERVICE_FRAME_BYTES),
                )
                .await?
            })
            .await;
        let Some(Ok(Some(service))) = service else {
            return;
        };
        let waits_for_startup = match service {
            AgentService::Session | AgentService::SessionControl => false,
            AgentService::Sync | AgentService::Exec => true,
        };
        if waits_for_startup
            && cancellation
                .run_until_cancelled(wait_until_started(&mut startup))
                .await
                != Some(true)
        {
            return;
        }
        match service {
            AgentService::Session => {
                cancellation
                    .run_until_cancelled(serve_client(&session, conn, initial_session.as_ref()))
                    .await;
            }
            AgentService::SessionControl => {
                cancellation
                    .run_until_cancelled(serve_session_control(&session, conn))
                    .await;
            }
            AgentService::Sync => {
                let Ok(file) = prepare_file_transfer(conn) else {
                    return;
                };
                serve_file_transfer(file, workload_is_root, cancellation).await;
            }
            AgentService::Exec => {
                Box::pin(crate::exec::serve_exec(
                    conn,
                    workload_is_root,
                    cancellation,
                ))
                .await;
            }
        }
    }
}

async fn serve_file_transfer(file: File, workload_is_root: bool, cancellation: CancellationToken) {
    let Ok(shutdown) = file.try_clone() else {
        return;
    };
    let worker_cancellation = cancellation.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        crate::sync::serve_sync_session(file, workload_is_root, &worker_cancellation);
    });
    tokio::select! {
        _ = &mut worker => return,
        () = cancellation.cancelled() => {}
    }
    let _ = rustix::net::shutdown(&shutdown, rustix::net::Shutdown::Both);
    let _ = worker.await;
}

fn prepare_file_transfer(conn: AsyncFile) -> std::io::Result<File> {
    let file = conn.into_inner().into_inner()?;
    let flags = rustix::fs::fcntl_getfl(&file)?;
    rustix::fs::fcntl_setfl(&file, flags & !rustix::fs::OFlags::NONBLOCK)?;
    for kind in [
        rustix::net::sockopt::Timeout::Recv,
        rustix::net::sockopt::Timeout::Send,
    ] {
        rustix::net::sockopt::set_socket_timeout(&file, kind, Some(CONTROL_TIMEOUT))?;
    }
    Ok(file)
}

async fn serve_client(
    session: &Arc<Session>,
    conn: AsyncFile,
    initial_session: Option<&mpsc::Sender<()>>,
) {
    let Ok(mut reader) = conn
        .get_ref()
        .as_fd()
        .try_clone_to_owned()
        .and_then(crate::into_async_file)
    else {
        return;
    };
    let Ok(client) = ClientConn::from_async(conn) else {
        return;
    };
    let Some(id) = session.attach_client(&client).await else {
        return;
    };
    if let Some(initial_session) = initial_session {
        let _ = initial_session.try_send(());
    }
    loop {
        match terra_protocol::read_frame_async::<ClientInput>(&mut reader).await {
            Ok(Some(ClientInput::Keys(bytes))) if session.send_input(&bytes).await.is_err() => {
                break;
            }
            Ok(Some(ClientInput::Keys(_) | ClientInput::Eof)) => {}
            Ok(Some(ClientInput::Resize(TermSize { rows, cols }))) => {
                if rows > 0 && cols > 0 {
                    session.set_client_size(id, rows, cols).await;
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
    session.detach_client(id).await;
}

async fn serve_session_control(session: &Arc<Session>, mut conn: AsyncFile) {
    let request = tokio::time::timeout(
        CONTROL_TIMEOUT,
        terra_protocol::read_frame_async::<ControlRequest>(&mut conn),
    )
    .await;
    let Ok(Ok(Some(request))) = request else {
        return;
    };
    let replies: Vec<ControlReply> = match request {
        ControlRequest::List => session
            .list_clients()
            .await
            .into_iter()
            .map(|(id, size)| ControlReply::Client {
                id,
                size: size.map(|(rows, cols)| TermSize { rows, cols }),
            })
            .chain([ControlReply::Done])
            .collect(),
        ControlRequest::Detach { id } => vec![match session.detach_client(id).await {
            DetachOutcome::Detached { .. } => ControlReply::Detached { id },
            DetachOutcome::Missing => ControlReply::Missing { id },
        }],
        ControlRequest::DetachAll => {
            let (ids, _) = session.detach_all_clients().await;
            ids.into_iter()
                .map(|id| ControlReply::Detached { id })
                .chain([ControlReply::Done])
                .collect()
        }
    };
    for reply in &replies {
        if write_control_reply(&mut conn, reply).await.is_err() {
            return;
        }
    }
}

async fn write_control_reply(conn: &mut AsyncFile, reply: &ControlReply) -> std::io::Result<()> {
    tokio::time::timeout(
        CONTROL_TIMEOUT,
        terra_protocol::write_frame_async(conn, reply),
    )
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use std::os::fd::OwnedFd;
    use terra_protocol::{SyncReply, SyncRequest};

    fn file_connection() -> (AsyncFile, File) {
        let (host, agent) = std::os::unix::net::UnixStream::pair().unwrap();
        (
            crate::into_async_file(host).unwrap(),
            prepare_file_transfer(crate::into_async_file(agent).unwrap()).unwrap(),
        )
    }

    #[tokio::test]
    async fn file_transfer_uses_blocking_io_with_bounded_socket_operations() {
        let (_host, agent) = file_connection();
        assert!(
            !rustix::fs::fcntl_getfl(&agent)
                .unwrap()
                .contains(rustix::fs::OFlags::NONBLOCK)
        );
        for kind in [
            rustix::net::sockopt::Timeout::Recv,
            rustix::net::sockopt::Timeout::Send,
        ] {
            assert_eq!(
                rustix::net::sockopt::socket_timeout(&agent, kind).unwrap(),
                Some(CONTROL_TIMEOUT)
            );
        }
    }

    async fn wait_for_file_transfer(transfer: tokio::task::JoinHandle<()>) {
        tokio::time::timeout(Duration::from_secs(1), transfer)
            .await
            .expect("file transfer worker did not stop")
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn requests_wait_for_startup_or_are_refused() {
        let (state, mut startup) = watch::channel(StartupState::Pending);
        let server = Server(state);
        let waiting = tokio::spawn(async move { wait_until_started(&mut startup).await });
        tokio::task::yield_now().await;
        server.update_state(StartupState::Ready);
        assert!(waiting.await.unwrap());

        let (_, mut startup) = watch::channel(StartupState::Refused);
        assert!(!wait_until_started(&mut startup).await);

        let (state, mut startup) = watch::channel(StartupState::Pending);
        drop(Server(state));
        assert!(!wait_until_started(&mut startup).await);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn named_control_service_selection_lists_attached_clients() {
        let (input, _sink) = std::os::unix::net::UnixStream::pair().unwrap();
        let cancellation = CancellationToken::new();
        let tasks = TaskTracker::new();
        let session = Session::new(
            &tasks,
            crate::into_async_file(input).unwrap(),
            &cancellation,
        )
        .unwrap();
        let (client, client_sink) = std::os::unix::net::UnixStream::pair().unwrap();
        let client = ClientConn::from_file(File::from(OwnedFd::from(client))).unwrap();
        session.attach_client(&client).await.unwrap();
        drop(client_sink);

        let (host, agent) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut host = crate::into_async_file(host).unwrap();
        let serving = {
            let session = session.clone();
            tokio::spawn(async move {
                Services {
                    session,
                    workload_is_root: false,
                    initial_session: None,
                    startup: watch::channel(StartupState::Pending).1,
                    cancellation,
                }
                .serve(File::from(OwnedFd::from(agent)))
                .await;
            })
        };
        let mut hello = [0; AGENT_HELLO.len()];
        tokio::io::AsyncReadExt::read_exact(&mut host, &mut hello)
            .await
            .unwrap();
        assert_eq!(hello, AGENT_HELLO);
        terra_protocol::write_frame_async(&mut host, &AgentService::SessionControl)
            .await
            .unwrap();
        terra_protocol::write_frame_async(&mut host, &ControlRequest::List)
            .await
            .unwrap();
        assert_eq!(
            terra_protocol::read_frame_async::<ControlReply>(&mut host)
                .await
                .unwrap(),
            Some(ControlReply::Client { id: 0, size: None })
        );
        assert_eq!(
            terra_protocol::read_frame_async::<ControlReply>(&mut host)
                .await
                .unwrap(),
            Some(ControlReply::Done)
        );
        serving.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_an_idle_file_connection_joins_the_file_worker() {
        let (_host, agent) = file_connection();
        let cancellation = CancellationToken::new();
        let transfer = tokio::spawn(serve_file_transfer(agent, true, cancellation.clone()));

        cancellation.cancel();
        wait_for_file_transfer(transfer).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_an_incomplete_request_joins_the_file_worker() {
        let (mut host, agent) = file_connection();
        let cancellation = CancellationToken::new();
        let transfer = tokio::spawn(serve_file_transfer(agent, true, cancellation.clone()));
        host.write_all(&[0, 0]).await.unwrap();
        host.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;

        cancellation.cancel();
        wait_for_file_transfer(transfer).await;
    }

    /// Cancelling a partial upload removes its temporary file before its worker exits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_a_partial_upload_preserves_the_destination() {
        let scratch = crate::create_scratch_path("services", "cancel-upload");
        std::fs::create_dir_all(&scratch).unwrap();
        let destination = scratch.join("file");
        std::fs::write(&destination, b"old").unwrap();
        let (mut host, agent) = file_connection();
        let cancellation = CancellationToken::new();
        let transfer = tokio::spawn(serve_file_transfer(agent, true, cancellation.clone()));

        terra_protocol::write_frame_async(
            &mut host,
            &SyncRequest::BeginSession {
                guest_root: scratch.to_string_lossy().into_owned(),
            },
        )
        .await
        .unwrap();
        assert_matches!(
            terra_protocol::read_frame_async::<SyncReply>(&mut host)
                .await
                .unwrap(),
            Some(SyncReply::SessionReady { .. })
        );
        terra_protocol::write_frame_async(
            &mut host,
            &SyncRequest::WriteFile {
                relative_path: "file".into(),
                size: 12,
                mode: 0o644,
                mtime_secs: 1,
                mtime_nanos: 0,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            terra_protocol::read_frame_async::<SyncReply>(&mut host)
                .await
                .unwrap(),
            Some(SyncReply::WriteFileReady)
        );
        host.write_all(b"new").await.unwrap();
        host.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;

        cancellation.cancel();
        wait_for_file_transfer(transfer).await;
        assert_eq!(std::fs::read(&destination).unwrap(), b"old");
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 1);
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_a_stalled_download_joins_the_file_worker() {
        let scratch = crate::create_scratch_path("services", "cancel-download");
        std::fs::create_dir_all(&scratch).unwrap();
        std::fs::write(scratch.join("file"), vec![0; 4 * 1024 * 1024]).unwrap();
        let (mut host, agent) = file_connection();
        let cancellation = CancellationToken::new();
        let transfer = tokio::spawn(serve_file_transfer(agent, true, cancellation.clone()));

        terra_protocol::write_frame_async(
            &mut host,
            &SyncRequest::BeginSession {
                guest_root: scratch.to_string_lossy().into_owned(),
            },
        )
        .await
        .unwrap();
        let _ = terra_protocol::read_frame_async::<SyncReply>(&mut host)
            .await
            .unwrap();
        terra_protocol::write_frame_async(
            &mut host,
            &SyncRequest::ReadFile {
                relative_path: "file".into(),
            },
        )
        .await
        .unwrap();
        assert_matches!(
            terra_protocol::read_frame_async::<SyncReply>(&mut host)
                .await
                .unwrap(),
            Some(SyncReply::ReadFileReady { .. })
        );
        tokio::time::sleep(Duration::from_millis(10)).await;

        cancellation.cancel();
        wait_for_file_transfer(transfer).await;
        std::fs::remove_dir_all(scratch).unwrap();
    }
}
