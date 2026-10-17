//! Windows worker confinement using Less-Privileged `AppContainer` tokens and jobs.

#![allow(unsafe_code)]

mod acl;
mod api;
mod sockets;

pub use sockets::LauncherSockets;

use super::{Access, Grant, Launch, PreparedLaunch, Role};
use anyhow::{Context, Result, bail, ensure};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, AsRawSocket, FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode};
use std::time::{Duration, Instant};
use terra_platform::filesystem::share::windows::symlink_broker;
use terra_platform::process;
use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenIsAppContainer};
use windows_sys::Win32::System::JobObjects::IsProcessInJob;
use windows_sys::Win32::System::Pipes::PeekNamedPipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, ResumeThread, WaitForMultipleObjects,
    WaitForSingleObject,
};

const BROKER_COMMIT_LIMIT_BYTES: usize = 512 << 20;
use terra_platform::process::sandbox_env::{APP_CONTAINER_MODE, WINDOWS_MODE, WINDOWS_ROLE};

const SPEC_ENV: &str = "TERRA_WINDOWS_SANDBOX_SPEC";
const IDENTITY_ENV: &str = "TERRA_WINDOWS_SANDBOX_IDENTITY";
const PARENT_ENV: &str = "TERRA_WINDOWS_SANDBOX_PARENT";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Supervisor,
    AppContainer,
}

impl Mode {
    const fn name(self) -> &'static str {
        match self {
            Self::Supervisor => "supervisor",
            Self::AppContainer => APP_CONTAINER_MODE,
        }
    }
}

struct Policy {
    role: Role,
    mode: Mode,
    memory_limit_bytes: usize,
    mitigations: api::Mitigations,
}

impl Policy {
    const fn for_role(role: Role) -> Self {
        match role {
            Role::Supervisor => Self {
                role,
                mode: Mode::Supervisor,
                memory_limit_bytes: 0,
                mitigations: api::Mitigations::NONE,
            },
            // Wasmtime maps its AOT components executable, so the VM keeps dynamic code.
            Role::Vm => Self {
                role,
                mode: Mode::AppContainer,
                memory_limit_bytes: 0,
                mitigations: api::Mitigations::WORKER,
            },
            Role::Network => Self {
                role,
                mode: Mode::AppContainer,
                memory_limit_bytes: BROKER_COMMIT_LIMIT_BYTES,
                mitigations: api::Mitigations::WORKER.prohibiting_dynamic_code(),
            },
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerSpec {
    role: Role,
    grants: Vec<WorkerGrant>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerGrant {
    path: PathBuf,
    writable: bool,
    identity: Option<String>,
}

pub struct Confinement {
    identity: File,
    inherited_identity: File,
    _parent: OwnedHandle,
    _spec: tempfile::NamedTempFile,
    trusted_directories: Vec<File>,
}

pub fn prepare_launch(launch: Launch<'_>) -> Result<PreparedLaunch> {
    ensure!(
        launch.role != Role::Supervisor,
        "supervisor confinement is installed after launching workers"
    );
    let (grants, trusted_directories) = build_worker_grants(launch.grants)?;
    let executable = std::fs::canonicalize(launch.command.get_program())
        .context("resolving Windows sandbox worker executable")?;
    let spec = super::write_worker_spec(
        &std::env::temp_dir(),
        &WorkerSpec {
            role: launch.role,
            grants,
        },
    )
    .context("creating Windows sandbox launch specification")?;
    let (identity, inherited_identity) = api::create_child_writer_pipe()?;
    // SAFETY: the current process identity is known; this handle can only observe its lifetime.
    let parent = api::own_handle(unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            1,
            std::process::id(),
        )
    })?;
    let mut command = Command::new(std::env::current_exe()?);
    // A detached supervisor has no console, so Windows would open a visible one for the wrapper.
    command.creation_flags(CREATE_NO_WINDOW);
    command.env_clear();
    for name in [
        "SystemRoot",
        "WINDIR",
        "USERPROFILE",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    for (name, value) in launch.command.get_envs() {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    command
        .arg(super::LAUNCHER_WORKER_ARG)
        .arg("--windows-worker")
        .arg("--")
        .arg(&executable)
        .args(launch.command.get_args())
        .env(SPEC_ENV, spec.path());
    process::pass_handle(
        &mut command,
        inherited_identity.as_raw_handle(),
        IDENTITY_ENV,
    )?;
    if let Some(directory) = launch.command.get_current_dir() {
        command.current_dir(directory);
    }
    process::pass_handle(&mut command, parent.as_raw_handle(), PARENT_ENV)?;
    Ok(PreparedLaunch {
        command,
        confinement: Confinement {
            identity,
            inherited_identity,
            _parent: parent,
            _spec: spec,
            trusted_directories,
        },
    })
}

fn build_worker_grants(grants: Vec<Grant>) -> Result<(Vec<WorkerGrant>, Vec<File>)> {
    let mut worker_grants = Vec::with_capacity(grants.len());
    let mut trusted_directories = Vec::new();
    for grant in grants {
        ensure!(
            grant.path.is_absolute(),
            "Windows sandbox grant must be absolute: {}",
            grant.path.display()
        );
        ensure!(
            grant.access != Access::Device,
            "Windows AppContainer device grants are unsupported"
        );
        let identity = grant
            .directory
            .as_ref()
            .map(terra_platform::filesystem::share::file_identity)
            .transpose()?
            .map(|identity| identity.to_string());
        if let Some(directory) = grant.directory {
            trusted_directories.push(directory);
        }
        worker_grants.push(WorkerGrant {
            path: grant.path,
            writable: grant.access == Access::ReadWrite,
            identity,
        });
    }
    Ok((worker_grants, trusted_directories))
}

/// Share roots whose identities the worker's grants were checked against.
pub type Resources = Vec<File>;

impl Confinement {
    pub(crate) fn confirm(
        mut self,
        child: &mut Child,
        timeout: Duration,
    ) -> Result<(u32, Resources)> {
        drop(self.inherited_identity);
        let pid = read_identity(&mut self.identity, child, timeout)?;
        Ok((pid, self.trusted_directories))
    }
}

fn read_identity(
    identity: &mut File,
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<u32> {
    let deadline = Instant::now() + timeout;
    loop {
        let mut available = 0;
        // SAFETY: identity is a live pipe and available is writable; no bytes are consumed.
        api::win_ok(unsafe {
            PeekNamedPipe(
                identity.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &raw mut available,
                std::ptr::null_mut(),
            )
        })
        .context("reading Windows sandbox worker identity")?;
        if available >= 4 {
            let mut bytes = [0; 4];
            identity.read_exact(&mut bytes)?;
            let pid = u32::from_le_bytes(bytes);
            ensure!(pid != 0, "Windows sandbox worker identity is zero");
            return Ok(pid);
        }
        ensure!(
            child.try_wait()?.is_none(),
            "Windows sandbox launcher exited before reporting its worker"
        );
        ensure!(
            Instant::now() < deadline,
            "Windows sandbox worker identity timed out"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

pub fn role_grants(_role: Role) -> Vec<Grant> {
    Vec::new()
}

/// The Windows supervisor stays unconfined; each worker's token and job carry its authority.
pub fn restrict_role(_role: Role) -> Result<()> {
    Ok(())
}

pub fn verify_worker_role(role: Role) -> Result<()> {
    let Some(declared_role) = std::env::var_os(WINDOWS_ROLE) else {
        return Ok(());
    };
    ensure!(
        declared_role == role.name(),
        "Windows sandbox launch role differs from worker entrypoint"
    );
    let mode = std::env::var(WINDOWS_MODE)?;
    verify_worker_token(&api::open_current_token(TOKEN_QUERY)?, role, &mode)?;
    ensure!(
        File::open("CONIN$").is_err()
            && std::fs::OpenOptions::new()
                .write(true)
                .open("CONOUT$")
                .is_err(),
        "Windows sandbox worker is attached to a console"
    );
    let mut in_job = 0;
    // SAFETY: the current process pseudo-handle is valid and in_job is writable.
    api::win_ok(unsafe {
        IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &raw mut in_job)
    })?;
    ensure!(
        in_job != 0,
        "Windows sandbox worker is outside its lifetime job"
    );
    Ok(())
}

fn verify_worker_token(token: &OwnedHandle, role: Role, mode: &str) -> Result<()> {
    let mut is_app_container = 0_u32;
    let mut returned = 0;
    // SAFETY: token is live and the output is a correctly sized DWORD.
    api::win_ok(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenIsAppContainer,
            (&raw mut is_app_container).cast(),
            4,
            &raw mut returned,
        )
    })?;
    match mode {
        APP_CONTAINER_MODE => {
            ensure!(
                is_app_container != 0,
                "Windows worker lacks its AppContainer token"
            );
            api::verify_capabilities(token, role)?;
        }
        "supervisor" => ensure!(
            role == Role::Supervisor,
            "supervisor token cannot launch a worker"
        ),
        mode => bail!("unknown Windows sandbox mode {mode}"),
    }
    Ok(())
}

/// Resolves this computer's DNS host name through the system resolver, the
/// path the broker's name lookups take.
#[cfg(test)]
fn resolve_computer_name() -> Result<()> {
    use std::net::ToSocketAddrs as _;
    use windows_sys::Win32::System::SystemInformation::{
        ComputerNameDnsHostname, GetComputerNameExW,
    };
    let mut name = [0_u16; 256];
    let mut length = u32::try_from(name.len())?;
    // SAFETY: name holds length UTF-16 units and length is writable.
    api::win_ok(unsafe {
        GetComputerNameExW(ComputerNameDnsHostname, name.as_mut_ptr(), &raw mut length)
    })?;
    let name = String::from_utf16(&name[..usize::try_from(length)?])?;
    ensure!(
        (name.as_str(), 0)
            .to_socket_addrs()
            .with_context(|| format!("resolving {name}"))?
            .next()
            .is_some(),
        "resolving {name} returned no addresses"
    );
    Ok(())
}

pub fn run_launcher_worker(arguments: impl Iterator<Item = OsString>) -> Result<ExitCode> {
    let mut arguments = arguments.peekable();
    if arguments.peek().is_some_and(|arg| arg == "--version") {
        ensure!(
            arguments.eq([OsString::from("--version")]),
            "invalid Windows sandbox version arguments"
        );
        println!("terra Windows sandbox {}", env!("CARGO_PKG_VERSION"));
        return Ok(ExitCode::SUCCESS);
    }
    ensure!(
        arguments.next().as_deref() == Some(OsStr::new("--windows-worker")),
        "Windows launcher requires --windows-worker"
    );
    ensure!(
        arguments.next().as_deref() == Some(OsStr::new("--")),
        "Windows launcher requires a worker after --"
    );
    let executable = arguments
        .next()
        .context("Windows launcher lacks a worker executable")?;
    run_worker(
        &executable,
        arguments,
        &super::read_worker_spec(Path::new(
            &std::env::var_os(SPEC_ENV)
                .context("Windows launcher lacks a startup specification")?,
        ))?,
    )
}

fn run_worker(
    executable: &OsStr,
    arguments: impl Iterator<Item = OsString>,
    spec: &WorkerSpec,
) -> Result<ExitCode> {
    process::initialize_winsock()?;
    let identity =
        claim_handle(IDENTITY_ENV)?.context("Windows launcher lacks its identity pipe")?;
    let parent = claim_handle(PARENT_ENV)?;
    if let Some(parent) = &parent {
        // SAFETY: parent is an inherited process handle with synchronization access.
        ensure!(
            unsafe { WaitForSingleObject(parent.as_raw_handle(), 0) } == WAIT_TIMEOUT,
            "Windows sandbox parent has exited"
        );
    }
    std::env::var(WINDOWS_ROLE).ok().map_or(Ok(()), |_| {
        bail!("a sandbox worker cannot run the trusted launcher")
    })?;
    let policy = Policy::for_role(spec.role);
    ensure!(
        policy.mode == Mode::AppContainer,
        "the {} role has no Windows sandbox worker",
        spec.role.name()
    );
    let job = api::create_worker_job(policy.memory_limit_bytes)?;
    let profile = api::Profile::create(policy.role)?;
    let mut grants = acl::Grants::new(&profile);
    let share_roots = apply_grants(&mut grants, spec)?;
    let socket_channel = (spec.role == Role::Network)
        .then(terra_platform::local_socket::create_local_pair)
        .transpose()?;
    let symlink_channel = (spec.role == Role::Vm && !share_roots.is_empty())
        .then(terra_platform::local_socket::create_local_pair)
        .transpose()?;
    let launcher_handles: Vec<_> = socket_channel
        .iter()
        .map(|(_, worker)| (sockets::LAUNCHER_SOCKETS_ENV, worker))
        .chain(
            symlink_channel
                .iter()
                .map(|(_, worker)| (symlink_broker::SYMLINK_BROKER_ENV, worker)),
        )
        .map(|(name, worker)| (name, worker.as_raw_socket() as HANDLE))
        .collect();
    let mut worker = api::spawn_worker(
        executable,
        arguments,
        &policy,
        &profile,
        &job,
        &launcher_handles,
    )?;
    let _launcher_sockets = socket_channel
        .map(|(launcher, _)| sockets::serve(launcher, worker.pid))
        .transpose()?;
    let _symlink_broker = symlink_channel
        .map(|(launcher, _)| symlink_broker::serve(launcher, share_roots))
        .transpose()?;
    if let Some(parent) = &parent {
        // SAFETY: parent remains live; a signaled handle prevents resuming the already job-confined child.
        ensure!(
            unsafe { WaitForSingleObject(parent.as_raw_handle(), 0) } == WAIT_TIMEOUT,
            "Windows sandbox parent exited during launch"
        );
    }
    // SAFETY: worker owns the initial thread created suspended and assigned atomically to job.
    ensure!(
        unsafe { ResumeThread(worker.thread.as_raw_handle()) } != u32::MAX,
        "resuming Windows sandbox worker failed: {}",
        std::io::Error::last_os_error()
    );
    let mut identity = File::from(identity);
    identity.write_all(&worker.pid.to_le_bytes())?;
    drop(identity);
    release_worker_handles(spec.role)?;
    let mut handles = vec![worker.process.as_raw_handle()];
    if let Some(parent) = &parent {
        handles.push(parent.as_raw_handle());
    }
    // SAFETY: both retained process handles support synchronization and the array length is exact.
    let signaled = unsafe {
        WaitForMultipleObjects(u32::try_from(handles.len())?, handles.as_ptr(), 0, INFINITE)
    };
    if signaled == WAIT_OBJECT_0 + 1 {
        drop(job);
        // SAFETY: closing job terminates the child; keep the process handle until termination completes.
        api::wait_for_exit(&worker.process)?;
        return Ok(ExitCode::FAILURE);
    }
    ensure!(
        signaled == WAIT_OBJECT_0,
        "waiting for Windows sandbox worker failed: {}",
        std::io::Error::last_os_error()
    );
    let mut code = 1;
    // SAFETY: the process handle is live and signaled, and code is writable.
    api::win_ok(unsafe { GetExitCodeProcess(worker.process.as_raw_handle(), &raw mut code) })?;
    worker.finish_console_relays();
    drop(job);
    grants.clear()?;
    Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)))
}

/// Grants the worker its paths and returns the share roots, each opened against the identity
/// the supervisor validated.
fn apply_grants(
    grants: &mut acl::Grants,
    spec: &WorkerSpec,
) -> Result<Vec<symlink_broker::ShareRoot>> {
    let mut share_roots = Vec::new();
    for grant in &spec.grants {
        if let Some(identity) = &grant.identity {
            share_roots.push(symlink_broker::ShareRoot {
                directory: terra_platform::filesystem::share::open_granted_share_root(
                    &grant.path,
                    identity.parse()?,
                )?,
                is_writable: grant.writable,
            });
        }
        grants.add(&grant.path, grant.writable)?;
    }
    Ok(share_roots)
}

/// Closes the wrapper's duplicates of the handles the worker inherited.
fn release_worker_handles(role: Role) -> Result<()> {
    for (_, name) in process::IPC_HANDLE_VARIABLES
        .into_iter()
        .chain(process::LISTENER_HANDLE_VARIABLES)
    {
        if let Some(socket) = process::inherited_handle(name)? {
            // SAFETY: Winsock is initialized and the worker inherited this socket; release the wrapper's duplicate.
            let status =
                unsafe { windows_sys::Win32::Networking::WinSock::closesocket(socket as usize) };
            if status != 0 {
                // SAFETY: query the thread-local Winsock error immediately after the failed close.
                bail!(
                    "closing inherited Windows sandbox IPC socket failed: {}",
                    std::io::Error::from_raw_os_error(unsafe {
                        windows_sys::Win32::Networking::WinSock::WSAGetLastError()
                    })
                );
            }
        }
    }
    if role == Role::Vm
        && let Some(lock) = process::inherited_handle(process::LOCK_HANDLE_VARIABLE)?
    {
        // SAFETY: the actual VM inherited the lock; the trusted wrapper releases its extra kernel handle.
        drop(unsafe { OwnedHandle::from_raw_handle(lock) });
    }
    Ok(())
}

fn claim_handle(name: &str) -> Result<Option<OwnedHandle>> {
    let Some(handle) = process::inherited_handle(name)? else {
        return Ok(None);
    };
    // SAFETY: the trusted launcher created and inherited this owned kernel handle exactly once.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    process::set_inheritable(handle.as_raw_handle(), false)?;
    Ok(Some(handle))
}

fn wide(value: &OsStr) -> Result<Vec<u16>> {
    let mut value: Vec<_> = value.encode_wide().collect();
    ensure!(!value.contains(&0), "Windows sandbox argument contains NUL");
    value.push(0);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn launcher_inherits_and_claims_the_parent_watch_handle() -> Result<()> {
        use windows_sys::Win32::Foundation::GetHandleInformation;
        use windows_sys::Win32::System::Threading::GetProcessId;

        const PARENT_PID_ENV: &str = "TERRA_WINDOWS_PARENT_HANDLE_TEST_PID";
        if let Ok(parent_pid) = std::env::var(PARENT_PID_ENV) {
            let parent = claim_handle(PARENT_ENV)?.context("parent watch handle is missing")?;
            // SAFETY: claim_handle owns the inherited process handle throughout both queries.
            assert_eq!(
                unsafe { GetProcessId(parent.as_raw_handle()) },
                parent_pid.parse::<u32>()?
            );
            // SAFETY: the inherited process handle has synchronization access and the parent is waiting for this child.
            assert_eq!(
                unsafe { WaitForSingleObject(parent.as_raw_handle(), 0) },
                WAIT_TIMEOUT
            );
            let mut flags = 0;
            // SAFETY: parent is live and flags is writable.
            api::win_ok(unsafe { GetHandleInformation(parent.as_raw_handle(), &raw mut flags) })?;
            assert_eq!(
                flags & windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT,
                0
            );
            return Ok(());
        }

        let executable = std::env::current_exe()?;
        let prepared = prepare_launch(Launch {
            role: Role::Vm,
            command: Command::new(&executable),
            grants: vec![Grant::new(&executable, Access::ReadOnly)],
            staging_directory: &std::env::temp_dir(),
        })?;
        let mut command = Command::new(&executable);
        command
            .args([
                "--exact",
                "windows::tests::launcher_inherits_and_claims_the_parent_watch_handle",
            ])
            .env_clear()
            .env(PARENT_PID_ENV, std::process::id().to_string());
        for (name, value) in prepared.command.get_envs() {
            if let Some(value) = value {
                command.env(name, value);
            }
        }
        let output = command.output()?;
        assert!(output.status.success(), "{output:?}");
        Ok(())
    }

    fn group_digits(value: usize) -> String {
        let digits = value.to_string();
        let groups: Vec<_> = digits
            .as_bytes()
            .rchunks(3)
            .rev()
            .map(|group| std::str::from_utf8(group).unwrap())
            .collect();
        groups.join(",")
    }

    /// docs/sandboxing-windows.md quotes the broker commit limit, grant cap and launcher connection limits;
    /// a change to any of them fails here.
    #[test]
    fn sandboxing_doc_quotes_the_windows_limits() {
        let doc = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../docs/sandboxing-windows.md"),
        )
        .unwrap()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
        for quote in [
            format!("{}-MiB commit limit", BROKER_COMMIT_LIMIT_BYTES >> 20),
            format!(
                "a launch may grant at most {} objects",
                group_digits(acl::MAX_GRANTED_OBJECTS)
            ),
            format!(
                "within {} seconds and at most {} at a time",
                sockets::CONNECT_TIMEOUT.as_secs(),
                sockets::MAX_PENDING_CONNECTS
            ),
        ] {
            assert!(
                doc.contains(&quote),
                "docs/sandboxing-windows.md must say: {quote}"
            );
        }
    }

    #[test]
    #[ignore = "requires native Windows and TERRA_BIN pointing to the newly built terra executable"]
    fn native_roles_enforce_vm_grants_and_broker_job() -> Result<()> {
        use std::net::{TcpListener, TcpStream};
        use std::process::Stdio;
        use terra_platform::local_socket::{LocalListener, LocalStream};

        let wrapper = PathBuf::from(
            std::env::var_os("TERRA_BIN")
                .context("set TERRA_BIN to the native terra executable")?,
        );
        ensure!(wrapper.is_absolute(), "TERRA_BIN must be an absolute path");
        let executable = std::env::current_exe()?;
        let directory = tempfile::tempdir()?;
        let directory_handle =
            terra_platform::filesystem::share::open_share_root(&directory.path().canonicalize()?)?;
        let directory_identity =
            terra_platform::filesystem::share::file_identity(&directory_handle)?;
        let protected = directory.path().join("protected");
        std::fs::write(&protected, b"read-only metadata")?;
        let local_path = directory.path().join("host.sock");
        let local_listener = LocalListener::bind(&local_path)?;
        drop(LocalStream::connect(&local_path)?);
        drop(local_listener.accept()?);
        let outside = tempfile::NamedTempFile::new()?;
        terra_platform::filesystem::set_owner_only(outside.path(), false)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        drop(TcpStream::connect(address)?);
        for role in [Role::Vm, Role::Network] {
            let mut worker_command = Command::new(&executable);
            worker_command
                .args([
                    "--exact",
                    "windows::tests::native_role_probe",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TERRA_WINDOWS_TEST_DIRECTORY", directory.path())
                .env(
                    "TERRA_WINDOWS_TEST_DIRECTORY_ID",
                    directory_identity.to_string(),
                )
                .env("TERRA_WINDOWS_TEST_OUTSIDE", outside.path())
                .env("TERRA_WINDOWS_TEST_ADDRESS", address.to_string());
            let mut grants = vec![Grant::new(&executable, Access::ReadOnly)];
            if role == Role::Vm {
                let mut share = Grant::new(directory.path(), Access::ReadWrite);
                share.directory = Some(terra_platform::filesystem::share::open_share_root(
                    &directory.path().canonicalize()?,
                )?);
                grants.extend([share, Grant::new(&protected, Access::ReadOnly)]);
            }
            let mut prepared = prepare_launch(Launch {
                role,
                command: worker_command,
                grants,
                staging_directory: &std::env::temp_dir(),
            })?;
            let mut command = Command::new(&wrapper);
            command.args(prepared.command.get_args()).env_clear();
            for (name, value) in prepared.command.get_envs() {
                if let Some(value) = value {
                    command.env(name, value);
                }
            }
            command
                .stdin(std::process::Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            prepared.command = command;
            let child = prepared.spawn(Duration::from_secs(30))?;
            let output = child.child.wait_with_output()?;
            ensure!(
                output.status.success(),
                "Windows {} native sandbox probe failed: stdout={} stderr={}",
                role.name(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        ensure!(
            std::fs::read(&protected)? == b"read-only metadata",
            "Windows worker changed protected metadata"
        );
        Ok(())
    }

    #[test]
    #[ignore = "internal subprocess for native_roles_enforce_vm_grants_and_broker_job"]
    fn native_role_probe() -> Result<()> {
        use std::net::{SocketAddr, TcpStream, UdpSocket};

        let role = match std::env::var(WINDOWS_ROLE)?.as_str() {
            "vm" => Role::Vm,
            "network" => Role::Network,
            other => bail!("unexpected native test role {other}"),
        };
        verify_worker_role(role)?;
        let directory = PathBuf::from(
            std::env::var_os("TERRA_WINDOWS_TEST_DIRECTORY")
                .context("native test directory is missing")?,
        );
        let outside = PathBuf::from(
            std::env::var_os("TERRA_WINDOWS_TEST_OUTSIDE")
                .context("native test outside file is missing")?,
        );
        let protected = directory.join("protected");
        probe_process_hardening(role)?;
        match role {
            Role::Vm => {
                ensure!(
                    std::fs::read(outside).is_err(),
                    "Windows VM read a host file outside its grants"
                );
                terra_hypervisor::vm::PreparedVm::capabilities()
                    .map_err(anyhow::Error::msg)
                    .context("AppContainer VM cannot access Windows Hypervisor Platform")?;
                ensure!(
                    std::fs::read(&protected)? == b"read-only metadata",
                    "Windows VM cannot read approved metadata"
                );
                ensure!(
                    std::fs::write(&protected, b"replace").is_err(),
                    "Windows worker wrote read-only metadata"
                );
                ensure!(
                    std::fs::remove_file(&protected).is_err(),
                    "Windows worker removed read-only metadata through its writable parent"
                );
                ensure!(
                    terra_platform::local_socket::LocalStream::connect(directory.join("host.sock"))
                        .is_err(),
                    "AppContainer VM reached a host AF_UNIX endpoint inside an approved share"
                );
                std::fs::write(directory.join("writable"), b"approved")?;
                probe_granted_share_mutations(&directory)?;
                let address: SocketAddr = std::env::var("TERRA_WINDOWS_TEST_ADDRESS")?.parse()?;
                ensure!(
                    TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_err(),
                    "AppContainer VM opened a host TCP socket"
                );
                ensure!(
                    UdpSocket::bind("0.0.0.0:0")
                        .and_then(|socket| socket.send_to(b"denied", address))
                        .is_err(),
                    "AppContainer VM sent a host UDP datagram"
                );
            }
            Role::Network => {
                ensure!(
                    std::fs::read(&outside).is_err() && std::fs::read(&protected).is_err(),
                    "AppContainer broker read a host file outside its grants"
                );
                let address: SocketAddr = std::env::var("TERRA_WINDOWS_TEST_ADDRESS")?.parse()?;
                ensure!(
                    TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_err(),
                    "AppContainer broker reached host loopback with its own socket"
                );
                let sockets = LauncherSockets::claim()?
                    .context("AppContainer broker lacks its socket channel")?;
                let (sender, receiver) = std::sync::mpsc::channel();
                sockets.connect_tcp(
                    address,
                    Box::new(move |reply| {
                        let _ = sender.send(reply);
                    }),
                );
                let tcp = receiver
                    .recv_timeout(Duration::from_secs(5))?
                    .context("AppContainer broker cannot reach loopback with launcher sockets")?;
                ensure!(
                    tcp.listen(1).is_err(),
                    "AppContainer broker can listen on a launcher socket"
                );
                let datagram = sockets.bind_udp(socket2::Domain::IPV4)?;
                datagram
                    .send_to(b"probe", &address.into())
                    .context("AppContainer broker cannot send loopback datagrams")?;
                resolve_computer_name().context("AppContainer broker cannot resolve names")?;
            }
            Role::Supervisor => bail!("supervisor cannot run a worker probe"),
        }
        Ok(())
    }

    /// Reads the creation-time mitigations back from the kernel and tries the wrapper's console,
    /// so a dropped process attribute fails here instead of silently weakening workers.
    fn probe_process_hardening(role: Role) -> Result<()> {
        use windows_sys::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};
        use windows_sys::Win32::System::Threading::{
            GetProcessMitigationPolicy, PROCESS_MITIGATION_POLICY, ProcessASLRPolicy,
            ProcessChildProcessPolicy, ProcessDynamicCodePolicy,
            ProcessExtensionPointDisablePolicy, ProcessFontDisablePolicy, ProcessImageLoadPolicy,
            ProcessSideChannelIsolationPolicy, ProcessStrictHandleCheckPolicy,
            ProcessSystemCallDisablePolicy,
        };

        let read_flags = |policy: PROCESS_MITIGATION_POLICY| -> Result<u32> {
            let mut flags = 0_u32;
            // SAFETY: every queried policy is a single DWORD of flags and flags is writable.
            api::win_ok(unsafe {
                GetProcessMitigationPolicy(
                    GetCurrentProcess(),
                    policy,
                    (&raw mut flags).cast(),
                    std::mem::size_of::<u32>(),
                )
            })
            .with_context(|| format!("reading Windows mitigation policy {policy}"))?;
            Ok(flags)
        };
        for (policy, required, name) in [
            (
                ProcessASLRPolicy,
                0b111,
                "bottom-up, forced and high-entropy ASLR",
            ),
            (
                ProcessStrictHandleCheckPolicy,
                0b11,
                "permanent strict handle checks",
            ),
            (
                ProcessSystemCallDisablePolicy,
                0b1,
                "Win32k system call denial",
            ),
            (
                ProcessExtensionPointDisablePolicy,
                0b1,
                "legacy extension point denial",
            ),
            (ProcessFontDisablePolicy, 0b1, "non-system font denial"),
            (
                ProcessImageLoadPolicy,
                0b111,
                "remote, low-label and non-System32 image denial",
            ),
            (ProcessChildProcessPolicy, 0b1, "child process denial"),
            (
                ProcessSideChannelIsolationPolicy,
                0b1001,
                "branch target isolation and SSBD",
            ),
        ] {
            let flags = read_flags(policy)?;
            ensure!(
                flags & required == required,
                "Windows {} worker lacks {name}: flags {flags:#x}",
                role.name()
            );
        }
        ensure!(
            (read_flags(ProcessDynamicCodePolicy)? & 1 != 0) == (role == Role::Network),
            "Windows {} worker has the wrong dynamic code policy",
            role.name()
        );
        // SAFETY: AttachConsole takes no pointers; success would only attach this probe.
        ensure!(
            unsafe { AttachConsole(ATTACH_PARENT_PROCESS) } == 0,
            "Windows {} worker attached to the wrapper's console",
            role.name()
        );
        Ok(())
    }

    fn probe_granted_share_mutations(directory: &Path) -> Result<()> {
        let expected_directory = std::env::var("TERRA_WINDOWS_TEST_DIRECTORY_ID")?.parse()?;
        let directory_handle = terra_platform::filesystem::share::open_granted_share_root(
            directory,
            expected_directory,
        )?;
        terra_platform::filesystem::share::windows::create_directory_at(
            &directory_handle,
            Path::new("platform-ops"),
        )?;
        std::fs::write(directory.join("platform-ops/source"), b"approved")?;
        terra_platform::filesystem::share::windows::rename_at(
            &directory_handle,
            Path::new("platform-ops/source"),
            &directory_handle,
            Path::new("platform-ops/renamed"),
        )?;
        terra_platform::filesystem::share::windows::hard_link_at(
            &directory_handle,
            Path::new("platform-ops/renamed"),
            &directory_handle,
            Path::new("platform-ops/linked"),
        )?;
        terra_platform::filesystem::share::windows::unlink_file_at(
            &directory_handle,
            Path::new("platform-ops/renamed"),
        )?;
        ensure!(
            std::fs::read(directory.join("platform-ops/linked"))? == b"approved",
            "AppContainer VM hard link lost its source content"
        );
        terra_platform::filesystem::share::windows::unlink_file_at(
            &directory_handle,
            Path::new("platform-ops/linked"),
        )?;
        terra_platform::filesystem::share::windows::remove_directory_at(
            &directory_handle,
            Path::new("platform-ops"),
        )?;
        let broker = symlink_broker::SymlinkBroker::inherited()
            .context("AppContainer VM with a writable share lacks its symlink channel")?;
        broker.symlink_at(
            &directory_handle,
            &directory_handle,
            Path::new("link"),
            "target",
        )?;
        ensure!(
            broker.readlink_at(&directory_handle, &directory_handle, Path::new("link"))?
                == Some("target".into()),
            "AppContainer VM cannot read its brokered symlink"
        );
        terra_platform::filesystem::share::windows::unlink_file_at(
            &directory_handle,
            Path::new("link"),
        )?;
        ensure!(
            terra_platform::filesystem::share::windows::create_directory_at(
                &directory_handle,
                Path::new("../escape"),
            )
            .is_err(),
            "AppContainer VM escaped its share through parent resolution"
        );
        Ok(())
    }
}
