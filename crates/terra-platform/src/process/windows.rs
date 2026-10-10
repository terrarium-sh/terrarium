//! Windows child-process handoff and supervision.

#![allow(unsafe_code)]

use std::io::{Error, Result};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::process::Command;
use windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT;
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, DETACHED_PROCESS, OpenThread, ResumeThread,
    THREAD_SUSPEND_RESUME,
};

pub fn detach(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(DETACHED_PROCESS);
}

fn ipc_handle_environment(target: i32) -> Result<&'static str> {
    match target {
        7 => Ok("TERRA_NETWORK_HANDLE"),
        8 => Ok("TERRA_CONFIG_HANDLE"),
        _ => Err(Error::other("unsupported inherited IPC channel")),
    }
}

pub fn pass_ipc(
    command: &mut Command,
    stream: &crate::io::local::LocalStream,
    target: i32,
) -> Result<crate::io::local::LocalStream> {
    use std::os::windows::io::AsRawSocket;
    let inherited = stream.try_clone()?;
    let socket = inherited.as_raw_socket();
    // SAFETY: inherited owns this live socket; the launcher restricts inheritance to its handle list.
    win_ok(unsafe {
        windows_sys::Win32::Foundation::SetHandleInformation(
            socket as *mut std::ffi::c_void,
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    })?;
    command.env(ipc_handle_environment(target)?, socket.to_string());
    Ok(inherited)
}

pub fn claim_ipc(target: i32) -> Result<crate::io::local::LocalStream> {
    use std::os::windows::io::FromRawSocket;
    use windows_sys::Win32::Networking::WinSock::{WSADATA, WSAStartup};
    let socket = std::env::var(ipc_handle_environment(target)?)
        .map_err(Error::other)?
        .parse::<usize>()
        .map_err(Error::other)?;
    let mut data = WSADATA::default();
    // SAFETY: data has the Winsock structure's full writable size and initialization lasts until process exit.
    let result = unsafe { WSAStartup(0x0202, &raw mut data) };
    if result != 0 {
        return Err(Error::from_raw_os_error(result));
    }
    // SAFETY: the whitelisted launcher transfers this inherited socket exclusively to the worker.
    let stream = unsafe { crate::io::local::LocalStream::from_raw_socket(socket as u64) };
    // SAFETY: stream owns socket; no descendant may inherit this authority.
    win_ok(unsafe {
        windows_sys::Win32::Foundation::SetHandleInformation(
            socket as *mut std::ffi::c_void,
            HANDLE_FLAG_INHERIT,
            0,
        )
    })?;
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
