//! Guest-side vsock services.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::struct_field_names
)]

use crate::AsyncFile;
use crate::term::session::{ClientConn, DetachOutcome, Session};
use crate::term::tty::set_winsize;
use rustix::net::addr::{SocketAddrArg, SocketAddrLen, SocketAddrOpaque};
use rustix::net::{
    AddressFamily, SocketFlags, SocketType, acceptfrom_with, bind, listen, socket_with,
};
use std::fs::File;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;
use std::time::{Duration, Instant};
use terra_protocol::{
    AGENT_HELLO, AgentService, ClientInput, ControlReply, ControlRequest, MAX_SERVICE_FRAME_BYTES,
    TermSize, read_frame_async_with_limit,
};
use tokio::io::AsyncWriteExt as _;
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, watch};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub const VMADDR_CID_HOST: u32 = 2;

const ACCEPT_RETRY: Duration = Duration::from_millis(100);
const REFUSED_CONNECTION_LOG_INTERVAL: Duration = Duration::from_secs(1);
const STARTUP_WAIT: Duration = Duration::from_mins(5);
const SERVICE_SELECT_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct StartupGate(watch::Sender<StartupState>);

#[derive(Clone, Copy)]
enum StartupState {
    Pending,
    Ready,
    Failed,
}

impl StartupGate {
    pub(crate) fn new() -> Self {
        Self(watch::Sender::new(StartupState::Pending))
    }

    pub(crate) fn ready(&self) {
        self.0.send_replace(StartupState::Ready);
    }

    pub(crate) fn fail(&self) {
        self.0.send_replace(StartupState::Failed);
    }

    async fn wait(&self) -> bool {
        let mut state = self.0.subscribe();
        let outcome = tokio::time::timeout(
            STARTUP_WAIT,
            state.wait_for(|state| match state {
                StartupState::Pending => false,
                StartupState::Ready | StartupState::Failed => true,
            }),
        )
        .await;
        matches!(outcome, Ok(Ok(state)) if matches!(*state, StartupState::Ready))
    }
}

#[repr(C)]
struct SockaddrVm {
    svm_family: rustix::net::RawAddressFamily,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

pub struct VsockListener {
    fd: AsyncFd<OwnedFd>,
    last_refusal: Option<Instant>,
}

fn create_vsock_socket(cid: u32, port: u32) -> std::io::Result<(OwnedFd, SockaddrVm)> {
    let fd = socket_with(
        AddressFamily::VSOCK,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
    Ok((
        fd,
        SockaddrVm {
            svm_family: AddressFamily::VSOCK.as_raw(),
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: cid,
            svm_zero: [0; 4],
        },
    ))
}

// SAFETY: `f` receives a valid sockaddr_vm for this call.
#[allow(unsafe_code)]
unsafe impl SocketAddrArg for SockaddrVm {
    unsafe fn with_sockaddr<R>(
        &self,
        f: impl FnOnce(*const SocketAddrOpaque, SocketAddrLen) -> R,
    ) -> R {
        f(
            std::ptr::from_ref(self).cast(),
            std::mem::size_of::<Self>() as SocketAddrLen,
        )
    }
}

impl VsockListener {
    pub fn bind(port: u32) -> std::io::Result<Self> {
        let (fd, addr) = create_vsock_socket(u32::MAX, port)?;
        bind(&fd, &addr)?;
        listen(&fd, 8)?;
        let flags = rustix::fs::fcntl_getfl(&fd)?;
        rustix::fs::fcntl_setfl(&fd, flags | rustix::fs::OFlags::NONBLOCK)?;
        Ok(Self {
            fd: AsyncFd::new(fd)?,
            last_refusal: None,
        })
    }

    /// Accepts the next connection from the host, refusing all other peers.
    #[allow(unsafe_code)]
    async fn accept_host(&mut self) -> std::io::Result<File> {
        loop {
            let mut readiness = self.fd.readable().await?;
            let accepted =
                readiness.try_io(|fd| Ok(acceptfrom_with(fd.get_ref(), SocketFlags::CLOEXEC)?));
            let (fd, peer) = match accepted {
                Ok(result) => result?,
                Err(_) => continue,
            };
            let file = File::from(fd);
            let cid = peer
                .filter(|peer| {
                    peer.address_family() == AddressFamily::VSOCK
                        && peer.addr_len() as usize >= std::mem::size_of::<SockaddrVm>()
                })
                .map_or(u32::MAX, |peer| {
                    // SAFETY: the kernel returned a complete sockaddr_vm.
                    unsafe { std::ptr::read_unaligned(peer.as_ptr().cast::<SockaddrVm>()) }.svm_cid
                });
            if cid == VMADDR_CID_HOST {
                return Ok(file);
            }
            drop(file);
            let now = Instant::now();
            if self
                .last_refusal
                .is_none_or(|last| now.duration_since(last) >= REFUSED_CONNECTION_LOG_INTERVAL)
            {
                eprintln!(
                    "terra-agent: refused vsock connection from inside the guest (cid {cid})"
                );
                self.last_refusal = Some(now);
            }
        }
    }
}

pub fn connect(cid: u32, port: u32) -> std::io::Result<File> {
    let (fd, addr) = create_vsock_socket(cid, port)?;
    rustix::net::connect(&fd, &addr)?;
    Ok(File::from(fd))
}

pub(crate) async fn serve_agent_port(
    session: Arc<Session>,
    mut listener: VsockListener,
    workload_is_root: bool,
    initial_session: Option<mpsc::Sender<()>>,
    startup: StartupGate,
    cancellation: CancellationToken,
) {
    let tasks = TaskTracker::new();
    while let Some(accepted) = cancellation
        .run_until_cancelled(listener.accept_host())
        .await
    {
        match accepted {
            Ok(conn) => {
                tasks.spawn(serve_connection(
                    session.clone(),
                    conn,
                    workload_is_root,
                    initial_session.clone(),
                    startup.clone(),
                    cancellation.clone(),
                ));
            }
            Err(error) => {
                eprintln!("terra-agent: accept failed: {error}");
                cancellation
                    .run_until_cancelled(tokio::time::sleep(ACCEPT_RETRY))
                    .await;
            }
        }
    }
    tasks.close();
    tasks.wait().await;
}

async fn serve_connection(
    session: Arc<Session>,
    conn: File,
    workload_is_root: bool,
    initial_session: Option<mpsc::Sender<()>>,
    startup: StartupGate,
    cancellation: CancellationToken,
) {
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
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
        })
        .await;
    let Some(Ok(Some(service))) = service else {
        return;
    };
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
        AgentService::Sync
            if cancellation.run_until_cancelled(startup.wait()).await == Some(true) =>
        {
            let Ok(file) = prepare_file_transfer(conn) else {
                return;
            };
            serve_file_transfer(file, workload_is_root, cancellation).await;
        }
        AgentService::Exec
            if cancellation.run_until_cancelled(startup.wait()).await == Some(true) =>
        {
            Box::pin(crate::exec::serve_exec(
                conn,
                workload_is_root,
                cancellation,
            ))
            .await;
        }
        AgentService::Sync | AgentService::Exec => {}
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
    let Ok(reader) = conn
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
    let mut reader = reader;
    loop {
        match terra_protocol::read_frame_async::<ClientInput>(&mut reader).await {
            Ok(Some(ClientInput::Keys(bytes))) if session.send_input(&bytes).await.is_err() => {
                break;
            }
            Ok(Some(ClientInput::Keys(_) | ClientInput::Eof)) => {}
            Ok(Some(ClientInput::Resize(TermSize { rows, cols }))) => {
                if rows > 0
                    && cols > 0
                    && let Some((rows, cols)) = session.set_client_size(id, rows, cols).await
                {
                    set_winsize(session.input_fd(), rows, cols);
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
    if let DetachOutcome::Detached {
        size: Some((rows, cols)),
    } = session.detach_client(id).await
    {
        set_winsize(session.input_fd(), rows, cols);
    }
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
    match request {
        ControlRequest::List => {
            for (id, size) in session.list_clients().await {
                let size = size.map(|(rows, cols)| TermSize { rows, cols });
                if write_control_reply(&mut conn, &ControlReply::Client { id, size })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            let _ = write_control_reply(&mut conn, &ControlReply::Done).await;
        }
        ControlRequest::Detach { id } => match session.detach_client(id).await {
            DetachOutcome::Detached { size } => {
                if let Some((rows, cols)) = size {
                    set_winsize(session.input_fd(), rows, cols);
                }
                let _ = write_control_reply(&mut conn, &ControlReply::Detached { id }).await;
            }
            DetachOutcome::Missing => {
                let _ = write_control_reply(&mut conn, &ControlReply::Missing { id }).await;
            }
        },
        ControlRequest::DetachAll => {
            let (ids, size) = session.detach_all_clients().await;
            if let Some((rows, cols)) = size {
                set_winsize(session.input_fd(), rows, cols);
            }
            for id in ids {
                if write_control_reply(&mut conn, &ControlReply::Detached { id })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            let _ = write_control_reply(&mut conn, &ControlReply::Done).await;
        }
    }
}

async fn write_control_reply(conn: &mut AsyncFile, reply: &ControlReply) -> std::io::Result<()> {
    tokio::time::timeout(
        CONTROL_TIMEOUT,
        terra_protocol::write_frame_async(conn, reply),
    )
    .await
    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
}

#[cfg(test)]
mod tests {
    use super::*;
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
    async fn requests_wait_for_startup_or_fail_with_it() {
        let startup = StartupGate::new();
        let waiting = {
            let startup = startup.clone();
            tokio::spawn(async move { startup.wait().await })
        };
        tokio::task::yield_now().await;
        startup.ready();
        assert!(waiting.await.unwrap());

        let startup = StartupGate::new();
        startup.fail();
        assert!(!startup.wait().await);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn named_control_service_selection_lists_attached_clients() {
        let (input, _sink) = std::os::unix::net::UnixStream::pair().unwrap();
        let cancellation = CancellationToken::new();
        let tasks = TaskTracker::new();
        let session = Session::new(
            crate::into_async_file(input).unwrap(),
            &cancellation,
            &tasks,
        )
        .unwrap();
        let (client, client_sink) = std::os::unix::net::UnixStream::pair().unwrap();
        let client = ClientConn::from_vsock(File::from(OwnedFd::from(client))).unwrap();
        session.attach_client(&client).await.unwrap();
        drop(client_sink);

        let (host, agent) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut host = crate::into_async_file(host).unwrap();
        let serving = {
            let session = session.clone();
            tokio::spawn(async move {
                serve_connection(
                    session,
                    File::from(OwnedFd::from(agent)),
                    false,
                    None,
                    StartupGate::new(),
                    cancellation,
                )
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
        let scratch = crate::create_scratch_path("vsock", "cancel-upload");
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
        assert!(matches!(
            terra_protocol::read_frame_async::<SyncReply>(&mut host)
                .await
                .unwrap(),
            Some(SyncReply::SessionReady { .. })
        ));
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
        let scratch = crate::create_scratch_path("vsock", "cancel-download");
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
        assert!(matches!(
            terra_protocol::read_frame_async::<SyncReply>(&mut host)
                .await
                .unwrap(),
            Some(SyncReply::ReadFileReady { .. })
        ));
        tokio::time::sleep(Duration::from_millis(10)).await;

        cancellation.cancel();
        wait_for_file_transfer(transfer).await;
        std::fs::remove_dir_all(scratch).unwrap();
    }
}
