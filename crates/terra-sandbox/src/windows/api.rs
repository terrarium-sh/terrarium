use super::{Policy, Result, Role, wide};
use anyhow::{Context, ensure};
use std::ffi::{OsStr, OsString, c_void};
use std::fs::File;
use std::io::Read as _;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use terra_platform::process;
use terra_platform::process::sandbox_env::ROLE;
use windows_sys::Win32::Foundation::{
    HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LocalFree, SetHandleInformation,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};
use windows_sys::Win32::Security::{
    DeriveCapabilitySidsFromName, EqualSid, FreeSid, GetTokenInformation, PSID,
    SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES, TOKEN_GROUPS,
    TOKEN_INFORMATION_CLASS, TokenCapabilities,
};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::SystemServices::{JOB_OBJECT_UILIMIT_ALL, SE_GROUP_ENABLED};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DETACHED_PROCESS,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, INFINITE,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
    PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};
use windows_sys::Win32::System::WindowsProgramming::{
    PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT, PROCESS_CREATION_CHILD_PROCESS_RESTRICTED,
};

// VidExo gates WHP access behind this capability even for capability queries.
const HYPERVISOR_CAPABILITY: &str = "HypervisorPlatform";
// Lets Winsock initialize inside a Less-Privileged AppContainer.
const REGISTRY_READ_CAPABILITY: &str = "registryRead";
// Network isolation recognizes only the legacy SID; resolution and accept need it.
const INTERNET_CLIENT_SID: &str = "S-1-15-3-1";

// PROCESS_CREATION_MITIGATION_POLICY_*_ALWAYS_ON values from WinBase.h; windows-sys omits them.
const FORCE_RELOCATE_IMAGES: u64 = 1 << 8;
const HEAP_TERMINATE: u64 = 1 << 12;
const BOTTOM_UP_ASLR: u64 = 1 << 16;
const HIGH_ENTROPY_ASLR: u64 = 1 << 20;
const STRICT_HANDLE_CHECKS: u64 = 1 << 24;
const DISABLE_WIN32K: u64 = 1 << 28;
const DISABLE_EXTENSION_POINTS: u64 = 1 << 32;
const DISABLE_DYNAMIC_CODE: u64 = 1 << 36;
const DISABLE_NON_SYSTEM_FONTS: u64 = 1 << 48;
const BLOCK_REMOTE_IMAGES: u64 = 1 << 52;
const BLOCK_LOW_LABEL_IMAGES: u64 = 1 << 56;
const PREFER_SYSTEM32_IMAGES: u64 = 1 << 60;
// PROCESS_CREATION_MITIGATION_POLICY2_*_ALWAYS_ON values.
const MODULE_TAMPERING_PROTECTION: u64 = 1 << 12;
const RESTRICT_INDIRECT_BRANCH_PREDICTION: u64 = 1 << 16;
const DISABLE_SPECULATIVE_STORE_BYPASS: u64 = 1 << 24;

/// The two words of a worker's `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Mitigations([u64; 2]);

impl Mitigations {
    pub(super) const NONE: Self = Self([0; 2]);
    pub(super) const WORKER: Self = Self([
        FORCE_RELOCATE_IMAGES
            | HEAP_TERMINATE
            | BOTTOM_UP_ASLR
            | HIGH_ENTROPY_ASLR
            | STRICT_HANDLE_CHECKS
            | DISABLE_WIN32K
            | DISABLE_EXTENSION_POINTS
            | DISABLE_NON_SYSTEM_FONTS
            | BLOCK_REMOTE_IMAGES
            | BLOCK_LOW_LABEL_IMAGES
            | PREFER_SYSTEM32_IMAGES,
        MODULE_TAMPERING_PROTECTION
            | RESTRICT_INDIRECT_BRANCH_PREDICTION
            | DISABLE_SPECULATIVE_STORE_BYPASS,
    ]);

    pub(super) const fn prohibiting_dynamic_code(self) -> Self {
        Self([self.0[0] | DISABLE_DYNAMIC_CODE, self.0[1]])
    }
}

pub(super) fn win_ok(result: i32) -> Result<()> {
    if result == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
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
    let expected = role_capability_sids(role)?;
    let is_expected = |sid: PSID| {
        expected
            .iter()
            // SAFETY: both SIDs are initialized and retained throughout the comparison.
            .any(|capability| unsafe { EqualSid(sid, capability.0) } != 0)
    };
    ensure!(
        capabilities.len() == expected.len()
            && capabilities
                .iter()
                .all(|capability| is_expected(capability.Sid)),
        "Windows {} token must carry exactly its role capabilities",
        role.name()
    );
    Ok(())
}

/// The only capabilities each worker's token receives.
fn role_capability_sids(role: Role) -> Result<Vec<LocalAllocation>> {
    Ok(match role {
        Role::Supervisor => Vec::new(),
        Role::Vm => vec![
            derive_capability(REGISTRY_READ_CAPABILITY)?,
            derive_capability(HYPERVISOR_CAPABILITY)?,
        ],
        Role::Network => vec![
            derive_capability(REGISTRY_READ_CAPABILITY)?,
            sid_from_string(INTERNET_CLIENT_SID)?,
        ],
    })
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

/// Returns `(reader, writer)`; only the writer is inheritable.
pub(super) fn create_child_writer_pipe() -> Result<(File, File)> {
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
    // SAFETY: only the write side belongs in the child.
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
    })
    .context("limiting Windows sandbox worker job")?;
    let interface = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: JOB_OBJECT_UILIMIT_ALL,
    };
    // SAFETY: job is live and the restriction structure has the exact reported size.
    win_ok(unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectBasicUIRestrictions,
            (&raw const interface).cast(),
            u32::try_from(std::mem::size_of_val(&interface))?,
        )
    })
    .context("restricting Windows sandbox worker desktop access")?;
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
        .with_context(|| format!("setting Windows process attribute {name:#x}"))
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
        .with_context(|| format!("setting Windows process attribute {name:#x}"))
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
    console_relays: Vec<std::thread::JoinHandle<()>>,
}

impl Worker {
    /// Waits for console output the exited worker left in its pipes.
    pub(super) fn finish_console_relays(&mut self) {
        for relay in self.console_relays.drain(..) {
            let _ = relay.join();
        }
    }
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
    profile: &Profile,
    job: &OwnedHandle,
    launcher_handles: &[(&str, HANDLE)],
) -> Result<Worker> {
    let executable_wide = wide(executable)?;
    let mut command_line = build_command_line(executable, arguments)?;
    let environment_wide = build_worker_environment(policy, launcher_handles)?;
    let StandardHandles {
        handles: stdio,
        substitutes,
        console_relays,
    } = prepare_standard_handles().context("preparing Windows worker stdio")?;
    let inherited = list_inherited_handles(policy.role, &stdio, launcher_handles)
        .context("inheriting Windows worker handles")?;
    let capability_sids = role_capability_sids(policy.role)?;
    let mut capabilities: Vec<_> = capability_sids
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.0,
            Attributes: SE_GROUP_ENABLED.cast_unsigned(),
        })
        .collect();
    let security = SECURITY_CAPABILITIES {
        AppContainerSid: profile.sid,
        Capabilities: if capabilities.is_empty() {
            std::ptr::null_mut()
        } else {
            capabilities.as_mut_ptr()
        },
        CapabilityCount: u32::try_from(capabilities.len())?,
        Reserved: 0,
    };
    let job_handles = [job.as_raw_handle()];
    let child_policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
    let packages_opt_out = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    let mut attributes = Attributes::new(6)?;
    attributes.insert_slice(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherited)?;
    attributes.insert_slice(PROC_THREAD_ATTRIBUTE_JOB_LIST, &job_handles)?;
    attributes.insert(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &child_policy)?;
    attributes.insert(
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
        &policy.mitigations.0,
    )?;
    attributes.insert(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &security)?;
    attributes.insert(
        PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
        &packages_opt_out,
    )?;
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
    // An attached worker could open CONIN$ and queue keystrokes for the user's shell.
    let flags = CREATE_UNICODE_ENVIRONMENT
        | CREATE_SUSPENDED
        | EXTENDED_STARTUPINFO_PRESENT
        | DETACHED_PROCESS;
    // SAFETY: every buffer and process attribute value remains live through this synchronous creation.
    // The job attribute attaches the process before creation returns, closing the suspend/assign orphan race.
    let result = unsafe {
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
    };
    win_ok(result).context("creating Windows sandbox worker (no weaker launch is attempted)")?;
    // The worker's exit must be the relays' end of input.
    drop(substitutes);
    Ok(Worker {
        process: own_handle(information.hProcess)?,
        thread: own_handle(information.hThread)?,
        pid: information.dwProcessId,
        console_relays,
    })
}

fn sid_from_string(name: &str) -> Result<LocalAllocation> {
    let name = wide(OsStr::new(name))?;
    let mut sid = std::ptr::null_mut();
    // SAFETY: name is NUL-terminated and the allocation output is writable.
    win_ok(unsafe { ConvertStringSidToSidW(name.as_ptr(), &raw mut sid) })?;
    Ok(LocalAllocation(sid))
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

/// `launcher_handles` names the wrapper's own handles the worker inherits.
fn build_worker_environment(
    policy: &Policy,
    launcher_handles: &[(&str, HANDLE)],
) -> Result<Vec<u16>> {
    let mut environment: Vec<_> = std::env::vars_os()
        .filter(|(name, _)| {
            ![
                super::SPEC_ENV,
                super::IDENTITY_ENV,
                super::PARENT_ENV,
                super::sockets::LAUNCHER_SOCKETS_ENV,
                super::symlink_broker::SYMLINK_BROKER_ENV,
                ROLE,
            ]
            .iter()
            .any(|excluded| name.eq_ignore_ascii_case(excluded))
        })
        .collect();
    environment.push((ROLE.into(), policy.role.name().into()));
    for (name, handle) in launcher_handles {
        environment.push(((*name).into(), (*handle as usize).to_string().into()));
    }
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

/// Worker standard handles in which no console handle survives.
struct StandardHandles {
    handles: [HANDLE; 3],
    /// NUL and pipe ends standing in for console handles.
    substitutes: Vec<OwnedHandle>,
    console_relays: Vec<std::thread::JoinHandle<()>>,
}

/// A console handle would let the worker read the user's input or queue keystrokes, so console
/// input becomes NUL and console output a pipe relayed as plain text.
fn prepare_standard_handles() -> Result<StandardHandles> {
    let mut standard = StandardHandles {
        handles: [std::ptr::null_mut(); 3],
        substitutes: Vec::new(),
        console_relays: Vec::new(),
    };
    for (slot, kind) in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]
        .into_iter()
        .enumerate()
    {
        // SAFETY: query the trusted wrapper's configured standard handle.
        let mut handle = unsafe { GetStdHandle(kind) };
        ensure!(
            !handle.is_null() && handle != INVALID_HANDLE_VALUE,
            "Windows sandbox requires valid standard handles"
        );
        if is_console(handle) {
            let substitute = if kind == STD_INPUT_HANDLE {
                OwnedHandle::from(File::open("NUL")?)
            } else {
                let (reader, writer) = create_child_writer_pipe()?;
                let relay = std::thread::Builder::new()
                    .name("sandbox-console-relay".into())
                    .spawn(move || {
                        if kind == STD_OUTPUT_HANDLE {
                            relay_console_output(reader, std::io::stdout());
                        } else {
                            relay_console_output(reader, std::io::stderr());
                        }
                    })?;
                standard.console_relays.push(relay);
                OwnedHandle::from(writer)
            };
            handle = substitute.as_raw_handle();
            standard.substitutes.push(substitute);
        }
        // SAFETY: these handles stay live in this wrapper through worker creation.
        win_ok(unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) })?;
        standard.handles[slot] = handle;
    }
    Ok(standard)
}

fn is_console(handle: HANDLE) -> bool {
    let mut mode = 0;
    // SAFETY: handle is a live standard handle and mode is writable.
    unsafe { GetConsoleMode(handle, &raw mut mode) != 0 }
}

/// Keeps draining after the console fails so the worker never blocks on a full pipe.
fn relay_console_output(mut source: File, mut console: impl std::io::Write) {
    let mut pending = Vec::new();
    let mut buffer = [0; 4096];
    let mut is_console_writable = true;
    loop {
        let read = source.read(&mut buffer).unwrap_or(0);
        pending.extend_from_slice(&buffer[..read]);
        let complete = if read == 0 {
            pending.len()
        } else {
            complete_utf8_prefix(&pending)
        };
        let text = strip_control_characters(&pending[..complete]);
        pending.drain(..complete);
        is_console_writable = is_console_writable
            && console
                .write_all(text.as_bytes())
                .and_then(|()| console.flush())
                .is_ok();
        if read == 0 {
            return;
        }
    }
}

/// The prefix that holds no UTF-8 sequence cut off by the end of `bytes`.
fn complete_utf8_prefix(bytes: &[u8]) -> usize {
    match std::str::from_utf8(bytes) {
        Err(error) if error.error_len().is_none() => error.valid_up_to(),
        _ => bytes.len(),
    }
}

/// Escape sequences could write the user's clipboard or answer into console input.
fn strip_control_characters(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|character| {
            if character.is_control() && !matches!(character, '\n' | '\r' | '\t') {
                char::REPLACEMENT_CHARACTER
            } else {
                character
            }
        })
        .collect()
}

fn list_inherited_handles(
    role: Role,
    stdio: &[HANDLE; 3],
    launcher_handles: &[(&str, HANDLE)],
) -> Result<Vec<HANDLE>> {
    let mut inherited = stdio.to_vec();
    for (_, handle) in launcher_handles {
        process::set_inheritable(*handle, true)?;
        inherited.push(*handle);
    }
    for (_, name) in process::IPC_HANDLE_VARIABLES {
        if let Some(socket) = process::inherited_handle(name)? {
            inherited.push(socket);
        }
    }
    for (_, name) in process::LISTENER_HANDLE_VARIABLES {
        if let Some(socket) = process::inherited_handle(name)? {
            ensure!(
                role == Role::Vm,
                "network broker cannot inherit VM service listeners"
            );
            inherited.push(socket);
        }
    }
    if let Some(lock) = process::inherited_handle(process::LOCK_HANDLE_VARIABLE)? {
        ensure!(
            role == Role::Vm,
            "network broker cannot inherit the box run lock"
        );
        inherited.push(lock);
    }
    inherited.sort_unstable();
    inherited.dedup();
    Ok(inherited)
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

    /// Relayed worker output reaches the console without escape sequences or C1 controls, and a
    /// UTF-8 sequence split across reads survives intact.
    #[test]
    fn console_relay_strips_controls_and_keeps_split_utf8() {
        assert_eq!(
            strip_control_characters(b"ok\t\x1b]52;c;cm0gLXJm\x07\r\n\xc2\x9b2J"),
            "ok\t\u{fffd}]52;c;cm0gLXJm\u{fffd}\r\n\u{fffd}2J"
        );
        let split = "\u{e9}".as_bytes();
        assert_eq!(complete_utf8_prefix(&[b'a', split[0]]), 1);
        assert_eq!(complete_utf8_prefix(&[b'a', 0xff, b'b']), 3);

        let (reader, mut writer) = create_child_writer_pipe().unwrap();
        let relay = std::thread::spawn(move || {
            let mut console = Vec::new();
            relay_console_output(reader, &mut console);
            console
        });
        std::io::Write::write_all(&mut writer, &[b'a', split[0]]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::io::Write::write_all(&mut writer, &[split[1], 0x1b]).unwrap();
        drop(writer);
        assert_eq!(
            String::from_utf8(relay.join().unwrap()).unwrap(),
            "a\u{e9}\u{fffd}"
        );
    }

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
