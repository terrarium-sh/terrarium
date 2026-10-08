use super::{IPC_ENVS, MODE_ENV, Mode, Policy, ROLE_ENV, Result, Role, wide};
use anyhow::{Context, ensure};
use std::ffi::{OsStr, OsString, c_void};
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{
    HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LocalFree, SetHandleInformation,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Networking::WinSock::{WSACleanup, WSADATA, WSAStartup};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, DeriveCapabilitySidsFromName, EqualSid, FreeSid,
    GetTokenInformation, LUA_TOKEN, PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES,
    SID_AND_ATTRIBUTES, TOKEN_ALL_ACCESS, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TokenCapabilities,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, INFINITE,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
    PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

const NETWORK_CAPABILITIES: [&str; 3] = [
    "internetClient",
    "internetClientServer",
    "privateNetworkClientServer",
];
const DISABLE_WIN32K: u64 = 1 << 28;
const DISABLE_DYNAMIC_CODE: u64 = 1 << 36;

pub(super) fn win_ok(result: i32) -> Result<()> {
    ensure!(result != 0, "{}", std::io::Error::last_os_error());
    Ok(())
}

pub(super) fn own_handle(handle: HANDLE) -> Result<OwnedHandle> {
    ensure!(
        !handle.is_null() && handle != INVALID_HANDLE_VALUE,
        "{}",
        std::io::Error::last_os_error()
    );
    // SAFETY: the caller passes a newly acquired owned kernel handle after its failure check.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

pub(super) struct Winsock;

impl Winsock {
    pub(super) fn initialize() -> Result<Self> {
        let mut data = WSADATA::default();
        // SAFETY: the process-local Winsock initialization writes a correctly sized WSADATA.
        let status = unsafe { WSAStartup(0x0202, &raw mut data) };
        ensure!(
            status == 0,
            "Windows sandbox Winsock initialization failed: {}",
            std::io::Error::from_raw_os_error(status)
        );
        Ok(Self)
    }
}

impl Drop for Winsock {
    fn drop(&mut self) {
        // SAFETY: this guard balances WSAStartup after inherited sockets have been closed.
        unsafe {
            WSACleanup();
        }
    }
}

pub(super) struct LocalAllocation(pub(super) *mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: the APIs producing this allocation require LocalFree; null is also accepted.
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub(super) fn open_current_token(access: u32) -> Result<OwnedHandle> {
    let mut token = std::ptr::null_mut();
    // SAFETY: the current process pseudo-handle is valid and token is writable.
    win_ok(unsafe { OpenProcessToken(GetCurrentProcess(), access, &raw mut token) })?;
    own_handle(token)
}

pub(super) fn token_information(
    token: &OwnedHandle,
    class: TOKEN_INFORMATION_CLASS,
) -> Result<Vec<usize>> {
    let mut bytes = 0;
    // SAFETY: the zero-length query only writes the required buffer size.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            std::ptr::null_mut(),
            0,
            &raw mut bytes,
        );
    }
    ensure!(
        bytes != 0 && bytes <= 64 << 10,
        "Windows token information exceeds its limit"
    );
    let mut buffer = vec![0_usize; usize::try_from(bytes)?.div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: usize storage is suitably aligned for token structures and has the queried capacity.
    win_ok(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            buffer.as_mut_ptr().cast(),
            bytes,
            &raw mut bytes,
        )
    })?;
    Ok(buffer)
}

pub(super) fn verify_capabilities(token: &OwnedHandle, role: Role) -> Result<()> {
    let buffer = token_information(token, TokenCapabilities)?;
    // SAFETY: TokenCapabilities initializes the DWORD count before its aligned SID array.
    let count = usize::try_from(unsafe { *buffer.as_ptr().cast::<u32>() })?;
    ensure!(
        count <= 16
            && std::mem::offset_of!(TOKEN_GROUPS, Groups)
                + count * std::mem::size_of::<SID_AND_ATTRIBUTES>()
                <= std::mem::size_of_val(buffer.as_slice()),
        "invalid Windows token capability count"
    );
    // SAFETY: the preceding check bounds the initialized capability array.
    let capabilities = unsafe {
        std::slice::from_raw_parts(
            buffer
                .as_ptr()
                .cast::<SID_AND_ATTRIBUTES>()
                .byte_add(std::mem::offset_of!(TOKEN_GROUPS, Groups)),
            count,
        )
    };
    match role {
        Role::Vm => ensure!(
            capabilities.is_empty(),
            "Windows VM token has capabilities that may permit host networking"
        ),
        Role::Network => {
            for name in NETWORK_CAPABILITIES {
                let sid = derive_capability(name)?;
                ensure!(
                    capabilities.iter().any(|capability| {
                        // SAFETY: both SIDs are initialized and retained throughout the comparison.
                        (unsafe { EqualSid(capability.Sid, sid.0) }) != 0
                    }),
                    "Windows network broker lacks {name} capability"
                );
            }
        }
        Role::Supervisor => ensure!(
            capabilities.is_empty(),
            "supervisor cannot use a worker AppContainer"
        ),
    }
    Ok(())
}

fn derive_capability(name: &str) -> Result<LocalAllocation> {
    let name = wide(OsStr::new(name))?;
    let mut groups = std::ptr::null_mut();
    let mut group_count = 0;
    let mut capabilities = std::ptr::null_mut();
    let mut capability_count = 0;
    // SAFETY: all output arrays/counts are writable and name is NUL-terminated.
    win_ok(unsafe {
        DeriveCapabilitySidsFromName(
            name.as_ptr(),
            &raw mut groups,
            &raw mut group_count,
            &raw mut capabilities,
            &raw mut capability_count,
        )
    })?;
    let groups_owner = LocalAllocation(groups.cast());
    let capabilities_owner = LocalAllocation(capabilities.cast());
    // SAFETY: the API returned these arrays with exactly the corresponding lengths.
    let group_sids = if group_count == 0 {
        &[]
    } else {
        ensure!(
            !groups.is_null(),
            "Windows capability derivation returned no group array"
        );
        // SAFETY: a nonempty API-owned group array is retained by groups_owner.
        unsafe { std::slice::from_raw_parts(groups, usize::try_from(group_count)?) }
    };
    for sid in group_sids {
        drop(LocalAllocation(*sid));
    }
    // SAFETY: the API returned this initialized SID array.
    let capability_sids = if capability_count == 0 {
        &[]
    } else {
        ensure!(
            !capabilities.is_null(),
            "Windows capability derivation returned no capability array"
        );
        // SAFETY: a nonempty API-owned capability array is retained by capabilities_owner.
        unsafe { std::slice::from_raw_parts(capabilities, usize::try_from(capability_count)?) }
    };
    let mut owned_sids: Vec<_> = capability_sids
        .iter()
        .copied()
        .map(LocalAllocation)
        .collect();
    drop(groups_owner);
    drop(capabilities_owner);
    ensure!(
        owned_sids.len() == 1,
        "Windows capability derivation returned an unexpected SID count"
    );
    Ok(owned_sids.remove(0))
}

pub(super) struct Profile {
    name: Vec<u16>,
    pub(super) sid: PSID,
    _unique: tempfile::TempDir,
}

impl Profile {
    pub(super) fn create(role: Role) -> Result<Self> {
        let unique = tempfile::Builder::new()
            .prefix(&format!("terra-{}-", role.name()))
            .tempdir()?;
        let name = wide(
            unique
                .path()
                .file_name()
                .context("AppContainer name is missing")?,
        )?;
        let mut sid = std::ptr::null_mut();
        // SAFETY: names are NUL-terminated; the empty capability profile gains capabilities only at process launch.
        let result = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                name.as_ptr(),
                name.as_ptr(),
                std::ptr::null(),
                0,
                &raw mut sid,
            )
        };
        ensure!(
            result >= 0,
            "creating Windows AppContainer failed with HRESULT {result:#010x}"
        );
        ensure!(
            !sid.is_null(),
            "Windows AppContainer returned no package SID"
        );
        Ok(Self {
            name,
            sid,
            _unique: unique,
        })
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        // SAFETY: this instance uniquely owns the profile name and the profile SID.
        let result = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
        if result < 0 {
            log::warn!("removing Windows AppContainer failed with HRESULT {result:#010x}");
        }
        // SAFETY: CreateAppContainerProfile allocates its SID with the allocator paired with FreeSid.
        unsafe {
            FreeSid(self.sid);
        }
    }
}

pub(super) fn create_identity_pipe() -> Result<(File, File)> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())?,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    // SAFETY: attributes is initialized and both output handle locations are writable.
    win_ok(unsafe { CreatePipe(&raw mut read, &raw mut write, &raw const attributes, 0) })?;
    let read = own_handle(read)?;
    let write = own_handle(write)?;
    // SAFETY: only the write side belongs in the trusted launcher child.
    win_ok(unsafe { SetHandleInformation(read.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) })?;
    Ok((File::from(read), File::from(write)))
}

pub(super) fn create_worker_job(memory_limit: usize) -> Result<OwnedHandle> {
    // SAFETY: null attributes and name create an unnamed, non-inheritable job owned by the wrapper.
    let job = own_handle(unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) })?;
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    if memory_limit != 0 {
        limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        limits.ProcessMemoryLimit = memory_limit;
    }
    // SAFETY: job is live and the limit structure has the exact reported size.
    win_ok(unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            u32::try_from(std::mem::size_of_val(&limits))?,
        )
    })?;
    Ok(job)
}

struct Attributes {
    storage: Vec<usize>,
}

impl Attributes {
    fn new(count: u32) -> Result<Self> {
        let mut bytes = 0;
        // SAFETY: this first call only returns the needed size.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &raw mut bytes);
        }
        ensure!(bytes != 0, "Windows process attribute size is zero");
        let mut storage = vec![0_usize; bytes.div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: storage is pointer-aligned and contains at least the requested byte capacity.
        win_ok(unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), count, 0, &raw mut bytes)
        })?;
        Ok(Self { storage })
    }

    fn as_mut_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }

    fn insert<T>(&mut self, name: u32, value: &T) -> Result<()> {
        // SAFETY: every inserted value is retained by spawn_worker until process creation returns.
        win_ok(unsafe {
            UpdateProcThreadAttribute(
                self.as_mut_ptr(),
                0,
                name as usize,
                std::ptr::from_ref(value).cast(),
                std::mem::size_of::<T>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        })
    }

    fn insert_slice<T>(&mut self, name: u32, value: &[T]) -> Result<()> {
        // SAFETY: the caller retains the slice for the entire process attribute list lifetime.
        win_ok(unsafe {
            UpdateProcThreadAttribute(
                self.as_mut_ptr(),
                0,
                name as usize,
                value.as_ptr().cast(),
                std::mem::size_of_val(value),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        })
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: initialization succeeded and the storage is still live.
        unsafe {
            DeleteProcThreadAttributeList(self.as_mut_ptr());
        }
    }
}

pub(super) struct Worker {
    pub(super) process: OwnedHandle,
    pub(super) thread: OwnedHandle,
    pub(super) pid: u32,
}

impl Drop for Worker {
    fn drop(&mut self) {
        // SAFETY: the process handle belongs to this launch; on errors the worker must stop before grants are removed.
        if unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } != WAIT_OBJECT_0 {
            // SAFETY: CreateProcess returned a process handle with termination access.
            unsafe {
                TerminateProcess(self.process.as_raw_handle(), 1);
            }
            if let Err(error) = wait_for_exit(&self.process) {
                log::warn!("reaping Windows sandbox worker failed: {error:#}");
            }
        }
    }
}

pub(super) fn spawn_worker(
    executable: &OsStr,
    arguments: impl Iterator<Item = OsString>,
    policy: &Policy,
    profile: Option<&Profile>,
    job: &OwnedHandle,
) -> Result<Worker> {
    let executable_wide = wide(executable)?;
    let mut command_line = build_command_line(executable, arguments)?;
    let environment_wide = build_worker_environment(policy)?;
    let (stdio, inherited) = prepare_inherited_handles(policy.role)?;
    let capability_sids = build_capability_sids(policy)?;
    let mut capabilities: Vec<_> = capability_sids
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.0,
            Attributes: SE_GROUP_ENABLED.cast_unsigned(),
        })
        .collect();
    let security = SECURITY_CAPABILITIES {
        AppContainerSid: profile.map_or(std::ptr::null_mut(), |profile| profile.sid),
        Capabilities: if capabilities.is_empty() {
            std::ptr::null_mut()
        } else {
            capabilities.as_mut_ptr()
        },
        CapabilityCount: u32::try_from(capabilities.len())?,
        Reserved: 0,
    };
    let job_handles = [job.as_raw_handle()];
    let child_policy = 1_u32;
    let packages_opt_out = 1_u32;
    let mitigation = DISABLE_WIN32K
        | if policy.role == Role::Network {
            DISABLE_DYNAMIC_CODE
        } else {
            0
        };
    let mut attributes = Attributes::new(6)?;
    attributes.insert_slice(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherited)?;
    attributes.insert_slice(PROC_THREAD_ATTRIBUTE_JOB_LIST, &job_handles)?;
    attributes.insert(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &child_policy)?;
    attributes.insert(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigation)?;
    if profile.is_some() {
        attributes.insert(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &security)?;
        if policy.less_privileged {
            attributes.insert(
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                &packages_opt_out,
            )?;
        }
    }
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = u32::try_from(std::mem::size_of::<STARTUPINFOEXW>())?;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    [
        startup.StartupInfo.hStdInput,
        startup.StartupInfo.hStdOutput,
        startup.StartupInfo.hStdError,
    ] = stdio;
    startup.lpAttributeList = attributes.as_mut_ptr();
    let mut information = PROCESS_INFORMATION::default();
    let flags = CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT;
    let token = if policy.mode == Mode::RestrictedTokenJob {
        Some(create_restricted_token()?)
    } else {
        None
    };
    // SAFETY: every buffer and process attribute value remains live through this synchronous creation.
    // The job attribute attaches the process before creation returns, closing the suspend/assign orphan race.
    let result = unsafe {
        if let Some(token) = &token {
            CreateProcessAsUserW(
                token.as_raw_handle(),
                executable_wide.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                flags,
                environment_wide.as_ptr().cast(),
                std::ptr::null(),
                &raw const startup.StartupInfo,
                &raw mut information,
            )
        } else {
            CreateProcessW(
                executable_wide.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                flags,
                environment_wide.as_ptr().cast(),
                std::ptr::null(),
                &raw const startup.StartupInfo,
                &raw mut information,
            )
        }
    };
    win_ok(result).context("creating Windows sandbox worker (no weaker launch is attempted)")?;
    Ok(Worker {
        process: own_handle(information.hProcess)?,
        thread: own_handle(information.hThread)?,
        pid: information.dwProcessId,
    })
}

fn create_restricted_token() -> Result<OwnedHandle> {
    let source = open_current_token(TOKEN_ALL_ACCESS)?;
    let admin = wide(OsStr::new("S-1-5-32-544"))?;
    let mut sid = std::ptr::null_mut();
    // SAFETY: the string SID is NUL-terminated and the allocation output is writable.
    win_ok(unsafe { ConvertStringSidToSidW(admin.as_ptr(), &raw mut sid) })?;
    let sid = LocalAllocation(sid);
    let deny_admin = SID_AND_ATTRIBUTES {
        Sid: sid.0,
        Attributes: 0,
    };
    let mut restricted = std::ptr::null_mut();
    // SAFETY: the primary token is live, the administrator SID is retained, and restricted is writable.
    win_ok(unsafe {
        CreateRestrictedToken(
            source.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE | LUA_TOKEN,
            1,
            &raw const deny_admin,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &raw mut restricted,
        )
    })?;
    own_handle(restricted)
}

fn build_capability_sids(policy: &Policy) -> Result<Vec<LocalAllocation>> {
    if policy.role != Role::Network {
        return Ok(Vec::new());
    }
    let mut sids = NETWORK_CAPABILITIES
        .into_iter()
        .map(derive_capability)
        .collect::<Result<Vec<_>>>()?;
    if policy.less_privileged {
        sids.push(derive_capability("registryRead")?);
    }
    Ok(sids)
}

fn build_command_line(
    executable: &OsStr,
    arguments: impl Iterator<Item = OsString>,
) -> Result<Vec<u16>> {
    let mut command_line = Vec::new();
    append_quoted(&mut command_line, executable)?;
    for argument in arguments {
        command_line.push(u16::from(b' '));
        append_quoted(&mut command_line, &argument)?;
    }
    command_line.push(0);
    ensure!(
        command_line.len() <= 32767,
        "Windows worker command line exceeds its size limit"
    );
    Ok(command_line)
}

fn build_worker_environment(policy: &Policy) -> Result<Vec<u16>> {
    let mut environment: Vec<_> = std::env::vars_os()
        .filter(|(name, _)| {
            ![
                super::SPEC_ENV,
                super::IDENTITY_ENV,
                super::PARENT_ENV,
                ROLE_ENV,
                MODE_ENV,
            ]
            .iter()
            .any(|excluded| name.eq_ignore_ascii_case(excluded))
        })
        .collect();
    environment.push((ROLE_ENV.into(), policy.role.name().into()));
    environment.push((MODE_ENV.into(), policy.mode.name().into()));
    environment.sort_by(|(left, _), (right, _)| {
        left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase())
    });
    let mut environment_wide = Vec::new();
    for (name, value) in environment {
        environment_wide.extend(wide(&format_os_pair(&name, &value))?);
    }
    environment_wide.push(0);
    Ok(environment_wide)
}

fn prepare_inherited_handles(role: Role) -> Result<([HANDLE; 3], Vec<HANDLE>)> {
    let mut inherited = Vec::new();
    let mut stdio = [std::ptr::null_mut(); 3];
    for (slot, kind) in
        stdio
            .iter_mut()
            .zip([STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE])
    {
        // SAFETY: query the trusted wrapper's configured standard handle.
        *slot = unsafe { GetStdHandle(kind) };
        ensure!(
            !slot.is_null() && *slot != INVALID_HANDLE_VALUE,
            "Windows sandbox requires valid standard handles"
        );
        // SAFETY: these handles belong to this single-threaded wrapper and remain live through creation.
        win_ok(unsafe { SetHandleInformation(*slot, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) })?;
        inherited.push(*slot);
    }
    for name in IPC_ENVS {
        if let Some(socket) = super::parse_handle_env(name)? {
            inherited.push(socket);
        }
    }
    for name in super::VM_LISTENER_ENVS {
        if let Some(socket) = super::parse_handle_env(name)? {
            ensure!(
                role == Role::Vm,
                "network broker cannot inherit VM service listeners"
            );
            inherited.push(socket);
        }
    }
    if let Some(lock) = super::parse_handle_env(super::LOCK_ENV)? {
        ensure!(
            role == Role::Vm,
            "network broker cannot inherit the box run lock"
        );
        inherited.push(lock);
    }
    inherited.sort_unstable();
    inherited.dedup();
    Ok((stdio, inherited))
}

fn format_os_pair(name: &OsStr, value: &OsStr) -> OsString {
    let mut pair = name.to_os_string();
    pair.push("=");
    pair.push(value);
    pair
}

fn append_quoted(output: &mut Vec<u16>, value: &OsStr) -> Result<()> {
    let value: Vec<_> = value.encode_wide().collect();
    ensure!(!value.contains(&0), "Windows worker argument contains NUL");
    output.push(u16::from(b'"'));
    let mut backslashes = 0;
    for character in value {
        if character == u16::from(b'\\') {
            backslashes += 1;
            continue;
        }
        output.extend(std::iter::repeat_n(
            u16::from(b'\\'),
            backslashes * if character == u16::from(b'"') { 2 } else { 1 },
        ));
        backslashes = 0;
        if character == u16::from(b'"') {
            output.push(u16::from(b'\\'));
        }
        output.push(character);
    }
    output.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2));
    output.push(u16::from(b'"'));
    Ok(())
}

pub(super) fn wait_for_exit(process: &OwnedHandle) -> Result<()> {
    // SAFETY: process is a live synchronization handle.
    ensure!(
        unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) } == WAIT_OBJECT_0,
        "waiting for Windows sandbox termination failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_escaping_preserves_backslashes_quotes_and_empty_arguments() {
        for (argument, expected) in [
            ("", "\"\""),
            ("a b", "\"a b\""),
            ("a\"b", "\"a\\\"b\""),
            ("a\\", "\"a\\\\\""),
            ("a\\\"b", "\"a\\\\\\\"b\""),
        ] {
            let mut output = Vec::new();
            append_quoted(&mut output, OsStr::new(argument)).unwrap();
            assert_eq!(String::from_utf16(&output).unwrap(), expected);
        }
    }
}
