//! Windows worker confinement using `AppContainer`, restricted tokens, and jobs.

#![allow(unsafe_code)]

mod acl;
mod api;

use super::{Access, Grant, Launch, PolicyBundle, Role, SpawnedLaunch};
use anyhow::{Context, Result, bail, ensure};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_QUERY, TokenHasRestrictions, TokenIsAppContainer,
};
use windows_sys::Win32::System::JobObjects::IsProcessInJob;
use windows_sys::Win32::System::Pipes::PeekNamedPipe;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, ResumeThread, WaitForMultipleObjects,
    WaitForSingleObject,
};

const SCHEMA_VERSION: u32 = 1;
const MAX_POLICY_BYTES: u64 = 16 << 10;
const MAX_SPEC_BYTES: u64 = 1 << 20;
const BROKER_COMMIT_LIMIT_BYTES: usize = 512 << 20;
const SPEC_ENV: &str = "TERRA_WINDOWS_SANDBOX_SPEC";
const IDENTITY_ENV: &str = "TERRA_WINDOWS_SANDBOX_IDENTITY";
const PARENT_ENV: &str = "TERRA_WINDOWS_SANDBOX_PARENT";
const MODE_ENV: &str = "TERRA_WINDOWS_SANDBOX_MODE";
const ROLE_ENV: &str = "TERRA_WINDOWS_SANDBOX_ROLE";
const IPC_ENVS: [&str; 2] = ["TERRA_NETWORK_HANDLE", "TERRA_CONFIG_HANDLE"];
const VM_LISTENER_ENVS: [&str; 4] = [
    "TERRA_AGENT_LISTENER_HANDLE",
    "TERRA_CONTROL_LISTENER_HANDLE",
    "TERRA_AGENT_CONTROL_LISTENER_HANDLE",
    "TERRA_AGENT_AGENT_LISTENER_HANDLE",
];
const LOCK_ENV: &str = "TERRA_INHERITED_LOCK_HANDLE";

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Supervisor,
    AppContainer,
    RestrictedTokenJob,
}

impl Mode {
    const fn name(self) -> &'static str {
        match self {
            Self::Supervisor => "supervisor",
            Self::AppContainer => "app_container",
            Self::RestrictedTokenJob => "restricted_token_job",
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema_version: u32,
    role: Role,
    mode: Mode,
    less_privileged: bool,
    memory_limit_bytes: usize,
}

impl Policy {
    const fn builtin(role: Role) -> Self {
        match role {
            Role::Supervisor => Self {
                schema_version: SCHEMA_VERSION,
                role,
                mode: Mode::Supervisor,
                less_privileged: false,
                memory_limit_bytes: 0,
            },
            Role::Vm => Self {
                schema_version: SCHEMA_VERSION,
                role,
                mode: Mode::AppContainer,
                less_privileged: true,
                memory_limit_bytes: 0,
            },
            Role::Network => Self {
                schema_version: SCHEMA_VERSION,
                role,
                mode: Mode::RestrictedTokenJob,
                less_privileged: false,
                memory_limit_bytes: BROKER_COMMIT_LIMIT_BYTES,
            },
        }
    }

    fn decode(bytes: &[u8], role: Role) -> Result<Self> {
        ensure!(
            bytes.len() as u64 <= MAX_POLICY_BYTES,
            "Windows sandbox policy exceeds its size limit"
        );
        let policy: Self =
            serde_json::from_slice(bytes).context("invalid Windows sandbox policy")?;
        ensure!(
            policy.schema_version == SCHEMA_VERSION,
            "unsupported Windows sandbox policy version"
        );
        ensure!(
            policy.role == role,
            "Windows sandbox policy role must be {}",
            role.name()
        );
        match (role, policy.mode) {
            (Role::Supervisor, Mode::Supervisor)
            | (Role::Vm, Mode::AppContainer | Mode::RestrictedTokenJob)
            | (Role::Network, Mode::RestrictedTokenJob) => {}
            (Role::Network, Mode::AppContainer) => {
                bail!("Windows network broker AppContainer mode is unsupported")
            }
            (Role::Supervisor, Mode::AppContainer | Mode::RestrictedTokenJob)
            | (Role::Vm | Role::Network, Mode::Supervisor) => {
                bail!("invalid Windows sandbox mode for {}", role.name())
            }
        }
        ensure!(
            policy.mode == Mode::AppContainer || !policy.less_privileged,
            "less_privileged requires app_container mode"
        );
        ensure!(
            role != Role::Supervisor || policy.memory_limit_bytes == 0,
            "supervisor sandbox memory limit must be zero"
        );
        ensure!(
            role != Role::Network || policy.memory_limit_bytes >= 64 << 20,
            "network sandbox memory limit must be at least 64 MiB"
        );
        Ok(policy)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerSpec {
    policy: Policy,
    grants: Vec<WorkerGrant>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerGrant {
    path: PathBuf,
    writable: bool,
    identity: Option<String>,
}

pub struct PreparedLaunch {
    pub command: Command,
    identity: File,
    inherited_identity: File,
    _parent: Option<OwnedHandle>,
    _spec: tempfile::NamedTempFile,
    trusted_directories: Vec<File>,
}

pub fn prepare_launch(launch: Launch<'_>) -> Result<PreparedLaunch> {
    ensure!(
        launch.role != Role::Supervisor,
        "supervisor confinement is installed after launching workers"
    );
    let policy = launch
        .policy
        .context("Windows sandbox launch requires its role policy")?;
    let policy = Policy::decode(policy, launch.role)?;
    if launch.role == Role::Vm && policy.mode == Mode::RestrictedTokenJob {
        log::warn!(
            "Windows VM restricted_token_job mode permits native host networking; select app_container for native network denial"
        );
    }
    let (grants, trusted_directories) = build_worker_grants(launch.grants)?;
    let executable = std::fs::canonicalize(launch.command.get_program())
        .context("resolving Windows sandbox worker executable")?;
    ensure!(
        grants.iter().any(|grant| !grant.writable
            && std::fs::canonicalize(&grant.path).ok().as_ref() == Some(&executable)),
        "Windows sandbox requires a read-only executable grant"
    );
    let bytes = serde_json::to_vec(&WorkerSpec { policy, grants })?;
    ensure!(
        bytes.len() as u64 <= MAX_SPEC_BYTES,
        "Windows sandbox launch specification exceeds its size limit"
    );
    let mut spec =
        tempfile::NamedTempFile::new().context("creating Windows sandbox launch specification")?;
    terra_platform::filesystem::set_owner_only(spec.path(), false)?;
    spec.write_all(&bytes)?;
    spec.flush()?;
    let (identity, inherited_identity) = api::create_identity_pipe()?;
    let parent = if launch.die_with_parent {
        // SAFETY: the current process identity is known; this handle can only observe its lifetime.
        Some(api::own_handle(unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                1,
                std::process::id(),
            )
        })?)
    } else {
        None
    };
    let mut command = Command::new(std::env::current_exe()?);
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
        .env(SPEC_ENV, spec.path())
        .env(
            IDENTITY_ENV,
            encode_handle(inherited_identity.as_raw_handle()),
        );
    if let Some(directory) = launch.command.get_current_dir() {
        command.current_dir(directory);
    }
    if let Some(parent) = &parent {
        command.env(PARENT_ENV, encode_handle(parent.as_raw_handle()));
    }
    Ok(PreparedLaunch {
        command,
        identity,
        inherited_identity,
        _parent: parent,
        _spec: spec,
        trusted_directories,
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
            .map(terra_platform::filesystem::file_identity)
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

impl PreparedLaunch {
    pub fn spawn(mut self, timeout: Duration) -> Result<SpawnedLaunch> {
        let mut child = self
            .command
            .spawn()
            .context("starting Windows sandbox launcher")?;
        drop(self.inherited_identity);
        let result = read_identity(&mut self.identity, &mut child, timeout);
        match result {
            Ok(pid) => Ok(SpawnedLaunch {
                child,
                pid,
                trusted_directories: self.trusted_directories,
            }),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(error)
            }
        }
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

pub fn resolve_policy(path: Option<&Path>, _allow_fallback: bool) -> Result<PolicyBundle> {
    if let Some(path) = path {
        ensure!(
            path.is_dir(),
            "Windows sandbox policy must be a directory containing supervisor.sandbox.json, vm.sandbox.json, and network.sandbox.json"
        );
    }
    let mut policies = Vec::with_capacity(3);
    for role in Role::ALL {
        let bytes = if let Some(path) = path {
            let filename = path.join(format!("{}.sandbox.json", role.name()));
            let mut bytes = Vec::new();
            File::open(&filename)
                .with_context(|| format!("opening {}", filename.display()))?
                .take(MAX_POLICY_BYTES + 1)
                .read_to_end(&mut bytes)?;
            bytes
        } else {
            serde_json::to_vec(&Policy::builtin(role))?
        };
        Policy::decode(&bytes, role)?;
        policies.push(bytes);
    }
    let [supervisor, vm, network] = policies
        .try_into()
        .map_err(|_| anyhow::anyhow!("Windows policy bundle is incomplete"))?;
    Ok(PolicyBundle {
        supervisor,
        vm,
        network,
    })
}

pub(super) fn uses_app_container(policy: &[u8], role: Role) -> Result<bool> {
    Ok(Policy::decode(policy, role)?.mode == Mode::AppContainer)
}

pub fn role_grants(_role: Role) -> Vec<Grant> {
    Vec::new()
}

pub fn install_policy(bytes: &[u8]) -> Result<()> {
    Policy::decode(bytes, Role::Supervisor)?;
    Ok(())
}

pub fn verify_worker_role(role: Role) -> Result<()> {
    let Some(declared_role) = std::env::var_os(ROLE_ENV) else {
        return Ok(());
    };
    ensure!(
        declared_role == role.name(),
        "Windows sandbox launch role differs from worker entrypoint"
    );
    let token = api::open_current_token(TOKEN_QUERY)?;
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
    match std::env::var(MODE_ENV)?.as_str() {
        "app_container" => {
            ensure!(
                is_app_container != 0,
                "Windows worker lacks its AppContainer token"
            );
            api::verify_capabilities(&token, role)?;
        }
        "restricted_token_job" => {
            ensure!(
                role != Role::Supervisor && is_app_container == 0,
                "restricted_token_job requires a VM or network worker"
            );
            let mut has_restrictions = 0_u32;
            // SAFETY: token is live and this token-information class initializes a DWORD.
            api::win_ok(unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenHasRestrictions,
                    (&raw mut has_restrictions).cast(),
                    4,
                    &raw mut returned,
                )
            })?;
            ensure!(
                has_restrictions != 0,
                "Windows VM lacks its restricted primary token"
            );
        }
        "supervisor" => ensure!(
            role == Role::Supervisor,
            "supervisor token cannot launch a worker"
        ),
        mode => bail!("unknown Windows sandbox mode {mode}"),
    }
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

pub fn run_launcher_worker(arguments: impl Iterator<Item = OsString>) -> Result<ExitCode> {
    let mut arguments = arguments.peekable();
    if arguments.peek().is_some_and(|arg| arg == "--version") {
        ensure!(
            arguments.eq([OsString::from("--version")]),
            "invalid Windows sandbox version arguments"
        );
        println!("terra Windows sandbox {SCHEMA_VERSION}");
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
    run_worker(&executable, arguments, &load_worker_spec()?)
}

fn load_worker_spec() -> Result<WorkerSpec> {
    let path =
        std::env::var_os(SPEC_ENV).context("Windows launcher lacks a startup specification")?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_SPEC_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_SPEC_BYTES,
        "Windows sandbox launch specification exceeds its size limit"
    );
    let spec: WorkerSpec = serde_json::from_slice(&bytes)?;
    Policy::decode(&serde_json::to_vec(&spec.policy)?, spec.policy.role)?;
    Ok(spec)
}

fn run_worker(
    executable: &OsStr,
    arguments: impl Iterator<Item = OsString>,
    spec: &WorkerSpec,
) -> Result<ExitCode> {
    let _winsock = api::Winsock::initialize()?;
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
    std::env::var(ROLE_ENV).ok().map_or(Ok(()), |_| {
        bail!("a sandbox worker cannot run the trusted launcher")
    })?;
    let job = api::create_worker_job(spec.policy.memory_limit_bytes)?;
    let profile = if spec.policy.mode == Mode::AppContainer {
        Some(api::Profile::create(spec.policy.role)?)
    } else {
        None
    };
    let mut grants = profile.as_ref().map(acl::Grants::new);
    if let Some(grants) = &mut grants {
        for grant in &spec.grants {
            if let Some(identity) = &grant.identity {
                let expected = identity.parse()?;
                terra_platform::filesystem::open_granted_share_root(&grant.path, expected)?;
            }
            grants.add(&grant.path, grant.writable)?;
        }
    }
    let worker = api::spawn_worker(executable, arguments, &spec.policy, profile.as_ref(), &job)?;
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
    for name in IPC_ENVS.into_iter().chain(VM_LISTENER_ENVS) {
        if let Some(socket) = parse_handle_env(name)? {
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
    if spec.policy.role == Role::Vm
        && let Some(lock) = parse_handle_env(LOCK_ENV)?
    {
        // SAFETY: the actual VM inherited the lock; the trusted wrapper releases its extra kernel handle.
        drop(unsafe { OwnedHandle::from_raw_handle(lock) });
    }
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
    drop(job);
    if let Some(grants) = &mut grants {
        grants.clear()?;
    }
    Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)))
}

fn encode_handle(handle: HANDLE) -> String {
    format!("{:x}", handle as usize)
}

fn parse_handle_env(name: &str) -> Result<Option<HANDLE>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .context("Windows sandbox handle is not ASCII")?;
    let radix = if IPC_ENVS.contains(&name) || VM_LISTENER_ENVS.contains(&name) {
        10
    } else {
        16
    };
    let handle = usize::from_str_radix(value.strip_prefix("0x").unwrap_or(value), radix)
        .with_context(|| format!("invalid Windows sandbox handle in {name}"))?;
    ensure!(
        handle != 0 && handle != usize::MAX,
        "invalid Windows sandbox handle in {name}"
    );
    Ok(Some(handle as HANDLE))
}

fn claim_handle(name: &str) -> Result<Option<OwnedHandle>> {
    parse_handle_env(name)?
        .map(|handle| {
            // SAFETY: the trusted launcher created and inherited this owned kernel handle exactly once.
            let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
            // SAFETY: clear inheritance on the live handle before any worker can be created.
            api::win_ok(unsafe {
                windows_sys::Win32::Foundation::SetHandleInformation(
                    handle.as_raw_handle(),
                    HANDLE_FLAG_INHERIT,
                    0,
                )
            })?;
            Ok(handle)
        })
        .transpose()
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
            assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
            return Ok(());
        }

        let executable = std::env::current_exe()?;
        let policy = serde_json::to_vec(&Policy::builtin(Role::Vm))?;
        let prepared = prepare_launch(Launch {
            role: Role::Vm,
            command: Command::new(&executable),
            grants: vec![Grant::new(&executable, Access::ReadOnly)],
            die_with_parent: true,
            policy: Some(&policy),
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

    #[test]
    fn role_policies_keep_network_authority_in_the_broker() {
        for role in Role::ALL {
            let policy = Policy::builtin(role);
            let bytes = serde_json::to_vec(&policy).unwrap();
            assert!(Policy::decode(&bytes, role).is_ok());
            for other in Role::ALL {
                if role != other {
                    assert!(Policy::decode(&bytes, other).is_err());
                }
            }
        }
        let mut policy = Policy::builtin(Role::Network);
        assert_eq!(policy.mode, Mode::RestrictedTokenJob);
        policy.mode = Mode::AppContainer;
        policy.less_privileged = true;
        assert!(Policy::decode(&serde_json::to_vec(&policy).unwrap(), Role::Network).is_err());
    }

    #[test]
    fn restricted_vm_mode_requires_an_explicit_policy() {
        assert_eq!(Policy::builtin(Role::Vm).mode, Mode::AppContainer);
        let mut policy = Policy::builtin(Role::Vm);
        policy.mode = Mode::RestrictedTokenJob;
        policy.less_privileged = false;
        assert!(Policy::decode(&serde_json::to_vec(&policy).unwrap(), Role::Vm).is_ok());
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

    /// docs/sandboxing.md quotes the broker commit limit and grant cap; a change to either fails here.
    #[test]
    fn sandboxing_doc_quotes_the_windows_limits() {
        let doc = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/sandboxing.md"),
        )
        .unwrap()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
        for quote in [
            format!("{}-MiB commit limit", BROKER_COMMIT_LIMIT_BYTES >> 20),
            format!(
                "broker `restricted_token_job`, {}-byte limit",
                group_digits(BROKER_COMMIT_LIMIT_BYTES)
            ),
            format!(
                "a launch may grant at most {} objects",
                group_digits(acl::MAX_GRANTED_OBJECTS)
            ),
        ] {
            assert!(doc.contains(&quote), "docs/sandboxing.md must say: {quote}");
        }
    }

    #[test]
    fn supervisor_policy_rejects_unenforced_memory_limits() {
        let mut policy = Policy::builtin(Role::Supervisor);
        policy.memory_limit_bytes = BROKER_COMMIT_LIMIT_BYTES;
        assert!(Policy::decode(&serde_json::to_vec(&policy).unwrap(), Role::Supervisor).is_err());
    }

    #[test]
    fn policy_bundle_reports_the_validated_app_container_mode() {
        let mut policies = resolve_policy(None, true).unwrap();
        assert!(policies.uses_app_container(Role::Vm).unwrap());
        assert!(!policies.uses_app_container(Role::Network).unwrap());
        assert!(!policies.uses_app_container(Role::Supervisor).unwrap());
        let mut restricted = Policy::builtin(Role::Vm);
        restricted.mode = Mode::RestrictedTokenJob;
        restricted.less_privileged = false;
        policies.vm = serde_json::to_vec(&restricted).unwrap();
        assert!(!policies.uses_app_container(Role::Vm).unwrap());
    }

    #[test]
    #[ignore = "requires native Windows and TERRA_BIN pointing to the newly built terra executable"]
    fn native_roles_enforce_vm_grants_and_broker_job() -> Result<()> {
        use std::net::{TcpListener, TcpStream};
        use std::process::Stdio;
        use terra_platform::io::local::{LocalListener, LocalStream};

        let wrapper = PathBuf::from(
            std::env::var_os("TERRA_BIN")
                .context("set TERRA_BIN to the native terra executable")?,
        );
        ensure!(wrapper.is_absolute(), "TERRA_BIN must be an absolute path");
        let executable = std::env::current_exe()?;
        let directory = tempfile::tempdir()?;
        let directory_handle =
            terra_platform::filesystem::open_share_root(&directory.path().canonicalize()?)?;
        let directory_identity = terra_platform::filesystem::file_identity(&directory_handle)?;
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
        let policies = resolve_policy(None, true)?;
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
                grants.extend([
                    Grant::new(directory.path(), Access::ReadWrite),
                    Grant::new(&protected, Access::ReadOnly),
                ]);
            }
            let policy = match role {
                Role::Vm => &policies.vm,
                Role::Network => &policies.network,
                Role::Supervisor => unreachable!(),
            };
            let mut prepared = prepare_launch(Launch {
                role,
                command: worker_command,
                grants,
                die_with_parent: true,
                policy: Some(policy),
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

        let role = match std::env::var(ROLE_ENV)?.as_str() {
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
        match role {
            Role::Vm => {
                ensure!(
                    std::fs::read(outside).is_err(),
                    "Windows VM read a host file outside its grants"
                );
                terra_platform::vm::PreparedVm::capabilities()
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
                    terra_platform::io::local::LocalStream::connect(directory.join("host.sock"))
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
                let address: SocketAddr = std::env::var("TERRA_WINDOWS_TEST_ADDRESS")?.parse()?;
                TcpStream::connect_timeout(&address, Duration::from_secs(1))
                    .context("restricted-token broker cannot use native loopback sockets")?;
                UdpSocket::bind("127.0.0.1:0")
                    .and_then(|socket| socket.send_to(b"probe", address))
                    .context("restricted-token broker cannot send native loopback datagrams")?;
            }
            Role::Supervisor => bail!("supervisor cannot run a worker probe"),
        }
        Ok(())
    }

    fn probe_granted_share_mutations(directory: &Path) -> Result<()> {
        let expected_directory = std::env::var("TERRA_WINDOWS_TEST_DIRECTORY_ID")?.parse()?;
        let directory_handle =
            terra_platform::filesystem::open_granted_share_root(directory, expected_directory)?;
        terra_platform::filesystem::create_directory_at(
            &directory_handle,
            Path::new("platform-ops"),
        )?;
        std::fs::write(directory.join("platform-ops/source"), b"approved")?;
        terra_platform::filesystem::rename_at(
            &directory_handle,
            Path::new("platform-ops/source"),
            &directory_handle,
            Path::new("platform-ops/renamed"),
        )?;
        terra_platform::filesystem::hard_link_at(
            &directory_handle,
            Path::new("platform-ops/renamed"),
            &directory_handle,
            Path::new("platform-ops/linked"),
        )?;
        terra_platform::filesystem::unlink_file_at(
            &directory_handle,
            Path::new("platform-ops/renamed"),
        )?;
        ensure!(
            std::fs::read(directory.join("platform-ops/linked"))? == b"approved",
            "AppContainer VM hard link lost its source content"
        );
        terra_platform::filesystem::unlink_file_at(
            &directory_handle,
            Path::new("platform-ops/linked"),
        )?;
        terra_platform::filesystem::remove_directory_at(
            &directory_handle,
            Path::new("platform-ops"),
        )?;
        ensure!(
            terra_platform::filesystem::create_directory_at(
                &directory_handle,
                Path::new("../escape"),
            )
            .is_err(),
            "AppContainer VM escaped its share through parent resolution"
        );
        Ok(())
    }
}
