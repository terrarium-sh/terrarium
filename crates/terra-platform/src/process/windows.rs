//! Windows child-process handoff and supervision.

#![allow(unsafe_code)]

use std::io::{Error, Result};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::process::Command;
use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, DETACHED_PROCESS, OpenThread, ResumeThread,
    THREAD_SUSPEND_RESUME,
};

pub fn detach(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(DETACHED_PROCESS);
}

/// Windows has no descriptor numbers to `dup2` into a child, so a child finds each inherited
/// handle through an environment variable keyed by the Unix descriptor target.
pub const IPC_HANDLE_VARIABLES: [(i32, &str); 2] =
    [(7, "TERRA_NETWORK_HANDLE"), (8, "TERRA_CONFIG_HANDLE")];
pub const LISTENER_HANDLE_VARIABLES: [(i32, &str); 4] = [
    (10, "TERRA_AGENT_LISTENER_HANDLE"),
    (11, "TERRA_CONTROL_LISTENER_HANDLE"),
    (12, "TERRA_AGENT_CONTROL_LISTENER_HANDLE"),
    (13, "TERRA_AGENT_AGENT_LISTENER_HANDLE"),
];
pub const LOCK_HANDLE_VARIABLE: &str = "TERRA_INHERITED_LOCK_HANDLE";

pub fn handle_variable(variables: &[(i32, &'static str)], target: i32) -> Result<&'static str> {
    variables
        .iter()
        .find(|(candidate, _)| *candidate == target)
        .map(|(_, variable)| *variable)
        .ok_or_else(|| Error::other(format!("no inherited handle variable for target {target}")))
}

/// Marks `handle` inheritable and names it in `variable` for the next child.
pub fn pass_handle(command: &mut Command, handle: HANDLE, variable: &str) -> Result<()> {
    set_inheritable(handle, true)?;
    command.env(variable, (handle as usize).to_string());
    Ok(())
}

/// Reads the handle a parent named in `variable`; `Ok(None)` means it passed none.
pub fn inherited_handle(variable: &str) -> Result<Option<HANDLE>> {
    let Some(value) = std::env::var_os(variable) else {
        return Ok(None);
    };
    let handle = value
        .to_str()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|handle| *handle != 0 && *handle != usize::MAX)
        .ok_or_else(|| Error::other(format!("invalid inherited handle in {variable}")))?;
    Ok(Some(handle as HANDLE))
}

#[allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "the kernel validates the handle and rejects an invalid one"
)]
pub fn set_inheritable(handle: HANDLE, is_inheritable: bool) -> Result<()> {
    // SAFETY: SetHandleInformation validates the handle and only changes its inheritance flag.
    win_ok(unsafe {
        windows_sys::Win32::Foundation::SetHandleInformation(
            handle,
            HANDLE_FLAG_INHERIT,
            if is_inheritable {
                HANDLE_FLAG_INHERIT
            } else {
                0
            },
        )
    })
}

/// Starts Winsock for the rest of the process; repeated calls are reference-counted by Windows.
pub fn initialize_winsock() -> Result<()> {
    use windows_sys::Win32::Networking::WinSock::{WSADATA, WSAStartup};
    let mut data = WSADATA::default();
    // SAFETY: data has the Winsock structure's full writable size.
    match unsafe { WSAStartup(0x0202, &raw mut data) } {
        0 => Ok(()),
        error => Err(Error::from_raw_os_error(error)),
    }
}

/// Takes ownership of the socket a parent named in `variable`, so descendants cannot inherit it.
pub fn claim_socket(variable: &str) -> Result<std::os::windows::io::RawSocket> {
    let socket = inherited_handle(variable)?
        .ok_or_else(|| Error::other(format!("{variable} names no inherited socket")))?;
    initialize_winsock()?;
    set_inheritable(socket, false)?;
    Ok(socket as std::os::windows::io::RawSocket)
}

pub fn pass_ipc(
    command: &mut Command,
    stream: &crate::local_socket::LocalStream,
    target: i32,
) -> Result<crate::local_socket::LocalStream> {
    use std::os::windows::io::AsRawSocket;
    let inherited = stream.try_clone()?;
    pass_handle(
        command,
        inherited.as_raw_socket() as HANDLE,
        handle_variable(&IPC_HANDLE_VARIABLES, target)?,
    )?;
    Ok(inherited)
}

pub fn claim_ipc(target: i32) -> Result<crate::local_socket::LocalStream> {
    use std::os::windows::io::FromRawSocket;
    let socket = claim_socket(handle_variable(&IPC_HANDLE_VARIABLES, target)?)?;
    // SAFETY: the whitelisted launcher transfers this inherited socket exclusively to the worker.
    let stream = unsafe { crate::local_socket::LocalStream::from_raw_socket(socket) };
    stream.peer_addr()?;
    Ok(stream)
}

pub struct VmChildGuard(OwnedHandle);

pub fn supervise_vm_child(command: &mut Command, foreground: bool) -> Result<Option<VmChildGuard>> {
    use std::os::windows::io::FromRawHandle;
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::JobObjects::{
        CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };
    if !foreground {
        detach(command);
        return Ok(None);
    }
    command.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED);
    // SAFETY: null means no security attributes or name; OwnedHandle closes the returned job.
    let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if raw.is_null() {
        return Err(Error::last_os_error());
    }
    // SAFETY: CreateJobObjectW returned this live, owned job handle.
    let job = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: job is live and the extended limit structure has the reported size.
    win_ok(unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            u32::try_from(std::mem::size_of_val(&limits)).map_err(Error::other)?,
        )
    })?;
    Ok(Some(VmChildGuard(job)))
}

pub fn attach_vm_child(guard: &VmChildGuard, child: &std::process::Child) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
    // SAFETY: both handles remain live through the assignment.
    win_ok(unsafe { AssignProcessToJobObject(guard.0.as_raw_handle(), child.as_raw_handle()) })?;
    // SAFETY: the system returns an owned snapshot or INVALID_HANDLE_VALUE.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(Error::last_os_error());
    }
    // SAFETY: CreateToolhelp32Snapshot returned this owned snapshot handle.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
    let mut entry = THREADENTRY32 {
        dwSize: u32::try_from(std::mem::size_of::<THREADENTRY32>()).map_err(Error::other)?,
        ..THREADENTRY32::default()
    };
    // SAFETY: snapshot remains live and entry has the required size.
    let mut found = unsafe { Thread32First(snapshot.as_raw_handle(), &raw mut entry) } != 0;
    while found {
        if entry.th32OwnerProcessID == child.id() {
            // SAFETY: the thread ID comes from the live system snapshot; null reports a failed open.
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if thread.is_null() {
                return Err(Error::last_os_error());
            }
            // SAFETY: OpenThread returned this owned thread handle.
            let thread = unsafe { OwnedHandle::from_raw_handle(thread) };
            // SAFETY: the new process was created suspended, and this thread belongs to it.
            if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
                return Err(Error::last_os_error());
            }
            return Ok(());
        }
        // SAFETY: snapshot remains live and entry remains writable for each iteration.
        found = unsafe { Thread32Next(snapshot.as_raw_handle(), &raw mut entry) } != 0;
    }
    Err(Error::other("created VM process has no initial thread"))
}

pub fn kill_vm_child(child: &mut std::process::Child) -> Result<()> {
    child.kill()
}

fn win_ok(ok: i32) -> Result<()> {
    (ok != 0).ok_or_else(Error::last_os_error)
}
