//! Windows host operations.

#![allow(unsafe_code)]

use super::SignalResult;
use std::fs::File;
use std::io::{Error, Result};
use std::os::windows::{
    ffi::OsStrExt,
    io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use std::path::Path;
use std::process::Command;
use windows_sys::Win32::Foundation::{FILETIME, HANDLE_FLAG_INHERIT, STILL_ACTIVE};
use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
use windows_sys::Win32::Security::{
    ACL, ACL_REVISION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
    GetLengthSid, GetTokenInformation, InitializeAcl, OBJECT_INHERIT_ACE,
    PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, DETACHED_PROCESS, GetCurrentProcess,
    GetExitCodeProcess, GetProcessTimes, OpenProcess, OpenProcessToken, OpenThread,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, ResumeThread, THREAD_SUSPEND_RESUME,
    TerminateProcess,
};

pub const MAX_SOCK_PATH: usize = 108;
const LOCK_HANDLE_ENV: &str = "TERRA_INHERITED_LOCK_HANDLE";

pub fn try_lock_run(path: &Path) -> std::result::Result<File, std::fs::TryLockError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ,
    };

    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION.cast_signed()) {
                std::fs::TryLockError::WouldBlock
            } else {
                std::fs::TryLockError::Error(error)
            }
        })?;
    let metadata = file.metadata().map_err(std::fs::TryLockError::Error)?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::fs::TryLockError::Error(Error::other(
            "run lock must be a regular file",
        )));
    }
    Ok(file)
}

pub fn host_addresses() -> Result<Vec<std::net::IpAddr>> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    let mut bytes = 15 * 1024_u32;
    loop {
        let words = usize::try_from(bytes)
            .unwrap_or(0)
            .div_ceil(std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>());
        let mut buffer =
            Vec::<std::mem::MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>::with_capacity(words);
        let allocated = words.saturating_mul(std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>());
        bytes = u32::try_from(allocated).unwrap_or(u32::MAX);
        // SAFETY: `buffer` is aligned for the adapter structure and has the capacity advertised in `bytes`.
        let status = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                0,
                std::ptr::null(),
                buffer.as_mut_ptr().cast(),
                &raw mut bytes,
            )
        };
        if status == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if status != NO_ERROR {
            return Err(Error::from_raw_os_error(
                i32::try_from(status).unwrap_or(i32::MAX),
            ));
        }
        let mut addresses = Vec::new();
        let mut adapter = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !adapter.is_null() {
            // SAFETY: the linked list is contained in the successfully initialized API buffer.
            let mut unicast = unsafe { (*adapter).FirstUnicastAddress };
            while !unicast.is_null() {
                // SAFETY: each unicast node and socket address is initialized by the API.
                let socket = unsafe { (*unicast).Address.lpSockaddr };
                if !socket.is_null() {
                    // SAFETY: the socket's family selects its concrete layout.
                    let address = unsafe {
                        match (*socket).sa_family {
                            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                                socket
                                    .cast::<SOCKADDR_IN>()
                                    .read_unaligned()
                                    .sin_addr
                                    .S_un
                                    .S_addr,
                            )))),
                            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(
                                socket
                                    .cast::<SOCKADDR_IN6>()
                                    .read_unaligned()
                                    .sin6_addr
                                    .u
                                    .Byte,
                            ))),
                            _ => None,
                        }
                    };
                    if let Some(address) = address {
                        addresses.push(address.to_canonical());
                    }
                }
                // SAFETY: the linked list is initialized by the API.
                unicast = unsafe { (*unicast).Next };
            }
            // SAFETY: the linked list is initialized by the API.
            adapter = unsafe { (*adapter).Next };
        }
        addresses.sort_unstable();
        addresses.dedup();
        return Ok(addresses);
    }
}

pub fn restrict_new_files() {}

pub fn set_open_file_mode(file: &File, mode: u32) -> Result<()> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(mode & 0o200 == 0);
    file.set_permissions(permissions)
}

pub fn make_sparse(file: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;

    let mut returned = 0;
    // SAFETY: `file` supplies a live synchronous handle, and the null buffers match FSCTL_SET_SPARSE.
    win_ok(unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    })
}

pub fn allocated_size(path: &Path, metadata: &std::fs::Metadata) -> u64 {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{GetLastError, NO_ERROR};
    use windows_sys::Win32::Storage::FileSystem::{GetCompressedFileSizeW, INVALID_FILE_SIZE};

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut high = 0u32;
    // SAFETY: `wide` is null-terminated and `high` is a valid writable pointer.
    let low = unsafe { GetCompressedFileSizeW(wide.as_ptr(), &raw mut high) };
    if low == INVALID_FILE_SIZE {
        // SAFETY: reading thread-local Win32 error code.
        let err = unsafe { GetLastError() };
        if err != NO_ERROR {
            return metadata.len();
        }
    }
    (u64::from(high) << 32) | u64::from(low)
}

pub fn set_owner_only(path: &Path, directory: bool) -> Result<()> {
    let sid = current_user_sid()?;
    let acl_size = std::mem::size_of::<ACL>()
        + std::mem::size_of::<u32>() * 2
        + std::mem::size_of_val(sid.as_slice());
    let mut acl = vec![0_u32; acl_size.div_ceil(std::mem::size_of::<u32>())];
    let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
    let inherit = if directory {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    // SAFETY: `acl` has the exact header, ACE, and SID capacity; `sid` remains live while
    // Windows copies it into the ACL.
    unsafe {
        win_ok(InitializeAcl(
            acl_ptr,
            u32::try_from(acl_size).unwrap_or(u32::MAX),
            ACL_REVISION,
        ))?;
        win_ok(AddAccessAllowedAceEx(
            acl_ptr,
            ACL_REVISION,
            inherit,
            FILE_ALL_ACCESS,
            sid.as_ptr().cast_mut().cast(),
        ))?;
    }
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: the path is NUL-terminated and `acl` lives for the call.
    let result = unsafe {
        SetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl_ptr,
            std::ptr::null(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::from_raw_os_error(
            i32::try_from(result).unwrap_or(i32::MAX),
        ))
    }
}

pub fn detach(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(DETACHED_PROCESS);
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

pub fn pass_lock(command: &mut Command, lock: &File) -> Result<File> {
    use std::os::windows::io::AsRawHandle;
    let inherited = lock.try_clone()?;
    let handle = inherited.as_raw_handle();
    // SAFETY: the `File` keeps this handle valid until CreateProcess duplicates it into the child.
    let ok = unsafe {
        windows_sys::Win32::Foundation::SetHandleInformation(
            handle,
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    };
    if ok == 0 {
        return Err(Error::last_os_error());
    }
    command.env(LOCK_HANDLE_ENV, format!("{handle:p}"));
    Ok(inherited)
}

pub fn claim_inherited_lock(expected: &Path) -> Option<File> {
    let handle = std::env::var(LOCK_HANDLE_ENV).ok()?;
    let raw = usize::from_str_radix(handle.strip_prefix("0x")?, 16).ok()? as *mut std::ffi::c_void;
    let same = file_handle_matches_path(raw, expected) && holds_run_lock(expected).ok()?;
    same.then(|| {
        // SAFETY: `pass_lock` marked precisely this live file handle inheritable for this child.
        let file = unsafe { File::from_raw_handle(raw) };
        // SAFETY: file owns raw; subsequent child processes must not inherit the run lock.
        win_ok(unsafe {
            windows_sys::Win32::Foundation::SetHandleInformation(raw, HANDLE_FLAG_INHERIT, 0)
        })
        .ok()?;
        Some(file)
    })
    .flatten()
}

pub fn holds_run_lock(path: &Path) -> Result<bool> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    match std::fs::OpenOptions::new()
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
    {
        Ok(_) => Ok(false),
        Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION.cast_signed()) => {
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

pub fn find_terminating_signal(_status: std::process::ExitStatus) -> Option<i32> {
    None
}

pub fn read_process_start_time(pid: u32) -> Option<u64> {
    with_process(
        pid,
        PROCESS_QUERY_LIMITED_INFORMATION,
        read_process_handle_start_time,
    )
    .flatten()
}

fn read_process_handle_start_time(process: *mut std::ffi::c_void) -> Option<u64> {
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: `process` is open and every FILETIME pointer is writable.
    let ok = unsafe {
        GetProcessTimes(
            process,
            &raw mut created,
            &raw mut exited,
            &raw mut kernel,
            &raw mut user,
        )
    };
    (ok != 0).then(|| u64::from(created.dwLowDateTime) | (u64::from(created.dwHighDateTime) << 32))
}

pub fn terminate_process(pid: u32, published_start_time: Option<u64>) -> Result<SignalResult> {
    let rights = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE;
    let Some(result) = with_process(pid, rights, |process| {
        let mut exit = 0;
        // SAFETY: `process` is an open process handle and `exit` is writable.
        win_ok(unsafe { GetExitCodeProcess(process, &raw mut exit) })?;
        if exit != STILL_ACTIVE as u32 {
            return Ok(SignalResult::IdentityUnknown);
        }
        if published_start_time
            .is_none_or(|published| read_process_handle_start_time(process) != Some(published))
        {
            return Ok(SignalResult::IdentityUnknown);
        }
        // SAFETY: `process` has PROCESS_TERMINATE access and its identity was verified through this handle.
        if unsafe { TerminateProcess(process, 1) } == 0 {
            return Err(Error::last_os_error());
        }
        Ok(SignalResult::Sent)
    }) else {
        return Ok(SignalResult::IdentityUnknown);
    };
    result
}

// Retained through process exit so console callbacks cannot race socket reuse.
static STOP_SOCKET: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);
static STOP_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn send_stop() {
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::Networking::WinSock::{INVALID_SOCKET, send};

    let Ok(socket) = usize::try_from(STOP_SOCKET.swap(u64::MAX, Ordering::SeqCst)) else {
        return;
    };
    if socket != INVALID_SOCKET {
        let byte = [terra_protocol::STOP_SIGNAL];
        // SAFETY: the retained socket stays open through process exit, and byte has the stated length.
        let _ = unsafe { send(socket, byte.as_ptr(), 1, 0) };
    }
}

pub fn register_stop_channel(channel: terra_platform::io::local::LocalStream) {
    use std::os::windows::io::IntoRawSocket;
    use std::sync::atomic::Ordering;

    STOP_SOCKET.store(channel.into_raw_socket(), Ordering::SeqCst);
    if STOP_REQUESTED.load(Ordering::SeqCst) {
        send_stop();
    }
}

extern "system" fn handle_console_control(event: u32) -> i32 {
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};

    if !matches!(event, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
        return 0;
    }
    STOP_REQUESTED.store(true, Ordering::SeqCst);
    send_stop();
    1
}

pub fn install_stop_signal_handlers() {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

    // SAFETY: the callback has the required ABI and remains available through process exit.
    if let Err(error) = win_ok(unsafe { SetConsoleCtrlHandler(Some(handle_console_control), 1) }) {
        log::warn!("could not install console stop handler: {error}");
    }
}

pub fn is_host_root() -> bool {
    false
}

fn current_user_sid() -> Result<Vec<u32>> {
    let mut token = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess is a pseudo-handle and token is writable.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned this owned token handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut needed = 0;
    // SAFETY: this query intentionally has no buffer and reports the required size.
    let _ = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &raw mut needed,
        )
    };
    let mut user = vec![
        0_usize;
        usize::try_from(needed)
            .unwrap_or(0)
            .div_ceil(std::mem::size_of::<usize>())
    ];
    // SAFETY: `user` has the size returned by the preceding query.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            user.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        )
    };
    if ok == 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: a successful TokenUser query initializes a TOKEN_USER at the buffer start.
    let token_user = unsafe { user.as_ptr().cast::<TOKEN_USER>().read_unaligned() };
    // SAFETY: TOKEN_USER contains a valid SID whose length Windows reports.
    let len = unsafe { GetLengthSid(token_user.User.Sid) };
    if len == 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: GetLengthSid bounds this source slice.
    Ok(unsafe {
        std::slice::from_raw_parts(
            token_user.User.Sid.cast::<u32>(),
            usize::try_from(len).unwrap_or(0) / std::mem::size_of::<u32>(),
        )
        .to_vec()
    })
}

fn with_process<T>(pid: u32, rights: u32, f: impl FnOnce(*mut std::ffi::c_void) -> T) -> Option<T> {
    if pid == 0 {
        return None;
    }
    // SAFETY: OpenProcess takes a numeric PID and returns either null or an owned handle.
    let process = unsafe { OpenProcess(rights, 0, pid) };
    if process.is_null() {
        return None;
    }
    // SAFETY: OpenProcess returned this owned process handle.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    Some(f(process.as_raw_handle()))
}

pub(crate) fn file_handle_matches_path(handle: *mut std::ffi::c_void, expected: &Path) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let Ok(expected) = File::open(expected) else {
        return false;
    };
    let mut inherited = BY_HANDLE_FILE_INFORMATION::default();
    let mut wanted = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: both handles are live for these calls and outputs are writable.
    unsafe {
        GetFileInformationByHandle(handle, &raw mut inherited) != 0
            && GetFileInformationByHandle(expected.as_raw_handle(), &raw mut wanted) != 0
            && inherited.dwVolumeSerialNumber == wanted.dwVolumeSerialNumber
            && inherited.nFileIndexHigh == wanted.nFileIndexHigh
            && inherited.nFileIndexLow == wanted.nFileIndexLow
    }
}

pub(crate) fn file_link_count(path: &Path) -> Result<u64> {
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_READ_ATTRIBUTES, GetFileInformationByHandle,
    };

    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .open(path)?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file handle is live and information is writable for this call.
    win_ok(unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) })?;
    Ok(u64::from(information.nNumberOfLinks))
}

fn win_ok(ok: i32) -> Result<()> {
    (ok != 0).then_some(()).ok_or_else(Error::last_os_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, EqualSid, GetAce, GetSecurityDescriptorControl, SE_DACL_PROTECTED,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_SPARSE_FILE;

    #[test]
    fn detached_launch_keeps_startup_pipes_without_parent_console() {
        use std::io::{Read as _, Write as _};
        use std::os::windows::process::CommandExt;
        use std::process::Stdio;
        use windows_sys::Win32::System::Console::{
            CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent, GetConsoleProcessList,
        };
        use windows_sys::Win32::System::Threading::CREATE_NEW_CONSOLE;

        let mut console_process = 0;
        // SAFETY: the buffer has the one process-ID slot reported to Windows.
        let console_processes = unsafe { GetConsoleProcessList(&raw mut console_process, 1) };
        let role = std::env::var("TERRA_TEST_DETACH_ROLE").ok();
        if role.as_deref() == Some("child") {
            assert_eq!(console_processes, 0);
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input).unwrap();
            assert_eq!(input, "startup input");
            std::io::stdout().write_all(b"startup output").unwrap();
            std::io::stderr().write_all(b"startup diagnostics").unwrap();
            return;
        }
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "sys::imp::tests::detached_launch_keeps_startup_pipes_without_parent_console",
            "--nocapture",
        ]);
        let mut stop_receiver = None;
        if role.as_deref() == Some("parent") {
            assert_ne!(console_processes, 0);
            let (host, receiver) = terra_platform::io::local::create_local_pair().unwrap();
            receiver
                .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
            register_stop_channel(host);
            stop_receiver = Some(receiver);
            install_stop_signal_handlers();
            command.env("TERRA_TEST_DETACH_ROLE", "child");
            assert!(supervise_vm_child(&mut command, false).unwrap().is_none());
            command.stdin(Stdio::piped());
        } else {
            command.env("TERRA_TEST_DETACH_ROLE", "parent");
            command.creation_flags(CREATE_NEW_CONSOLE);
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        if role.as_deref() == Some("parent") {
            // SAFETY: this subprocess owns an isolated console and installed a Ctrl+Break handler.
            assert_ne!(unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0) }, 0);
            let mut stop = [0];
            stop_receiver
                .as_mut()
                .unwrap()
                .read_exact(&mut stop)
                .unwrap();
            assert_eq!(stop, [terra_protocol::STOP_SIGNAL]);
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"startup input")
                .unwrap();
        }
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed;"));
        if role.as_deref() == Some("parent") {
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("startup output")
            );
            assert_eq!(output.stderr, b"startup diagnostics");
        }
    }

    #[test]
    fn console_interrupts_relay_one_stop_and_latch_before_registration() {
        use std::io::Read as _;
        use std::sync::atomic::Ordering;
        use terra_platform::io::local::create_local_pair;
        use windows_sys::Win32::System::Console::{
            CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT,
            CTRL_SHUTDOWN_EVENT,
        };

        for event in [CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT] {
            assert_eq!(handle_console_control(event), 0);
            assert!(!STOP_REQUESTED.load(Ordering::SeqCst));
        }
        for event in [CTRL_C_EVENT, CTRL_BREAK_EVENT] {
            let (host, mut guest) = create_local_pair().unwrap();
            guest
                .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
            if event == CTRL_C_EVENT {
                assert_eq!(handle_console_control(event), 1);
                assert!(STOP_REQUESTED.load(Ordering::SeqCst));
            }
            register_stop_channel(host);
            assert_eq!(handle_console_control(event), 1);
            let mut byte = [0];
            guest.read_exact(&mut byte).unwrap();
            assert_eq!(byte, [terra_protocol::STOP_SIGNAL]);
            assert_eq!(handle_console_control(event), 1);
            guest
                .set_read_timeout(Some(std::time::Duration::from_millis(50)))
                .unwrap();
            assert!(guest.read_exact(&mut byte).is_err());
            STOP_REQUESTED.store(false, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_sparse_file_keeps_the_sparse_attribute() {
        let file = tempfile::NamedTempFile::new().unwrap();
        make_sparse(file.as_file()).unwrap();
        assert_ne!(
            file.as_file().metadata().unwrap().file_attributes() & FILE_ATTRIBUTE_SPARSE_FILE,
            0
        );
    }

    #[test]
    fn the_handed_lock_handle_is_matched_by_identity() {
        let directory = tempfile::tempdir().unwrap();
        let lock_path = directory.path().join("terra.pid");
        let lock = try_lock_run(&lock_path).unwrap();
        let unrelated = tempfile::NamedTempFile::new().unwrap();
        assert!(file_handle_matches_path(lock.as_raw_handle(), &lock_path));
        assert!(!file_handle_matches_path(std::ptr::null_mut(), &lock_path));
        assert!(!file_handle_matches_path(INVALID_HANDLE_VALUE, &lock_path));
        assert!(!file_handle_matches_path(
            unrelated.as_file().as_raw_handle(),
            &lock_path
        ));
    }

    #[test]
    fn run_locks_reject_symlink_redirection() {
        let directory = tempfile::tempdir().unwrap();
        let redirected = directory.path().join("outside");
        let lock_path = directory.path().join("terra.pid");
        std::fs::write(&redirected, b"original").unwrap();
        std::os::windows::fs::symlink_file(&redirected, &lock_path).unwrap();
        assert!(try_lock_run(&lock_path).is_err());
        assert_eq!(std::fs::read(&redirected).unwrap(), b"original");
        std::fs::remove_file(&redirected).unwrap();
        assert!(try_lock_run(&lock_path).is_err());
        assert!(!redirected.exists());
    }

    #[test]
    fn owner_only_acl_grants_only_the_current_user_and_blocks_inheritance() {
        let root = tempfile::tempdir().unwrap();
        let sid = current_user_sid().unwrap();
        for directory in [false, true] {
            let path = root
                .path()
                .join(if directory { "directory" } else { "file" });
            if directory {
                std::fs::create_dir(&path).unwrap();
            } else {
                std::fs::write(&path, b"private").unwrap();
            }
            set_owner_only(&path, directory).unwrap();
            let wide = path
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let mut acl = std::ptr::null_mut();
            let mut descriptor = std::ptr::null_mut();
            let mut control = 0;
            let mut revision = 0;
            let mut entry = std::mem::MaybeUninit::uninit();
            // SAFETY: Windows owns the queried descriptor until LocalFree; every output pointer
            // is writable, and the successful queries bound the ACL and ACE reads.
            unsafe {
                assert_eq!(
                    GetNamedSecurityInfoW(
                        wide.as_ptr(),
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        &raw mut acl,
                        std::ptr::null_mut(),
                        &raw mut descriptor,
                    ),
                    0
                );
                assert_ne!(
                    GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision),
                    0
                );
                assert_ne!(control & SE_DACL_PROTECTED, 0);
                assert!(!acl.is_null());
                assert_eq!((*acl).AceCount, 1);
                assert_ne!(GetAce(acl, 0, entry.as_mut_ptr()), 0);
                // SAFETY: `GetAce` succeeded, so `entry` names the ACL's first ACE.
                let entry = &*entry.assume_init().cast::<ACCESS_ALLOWED_ACE>();
                assert_eq!(entry.Header.AceType, 0);
                assert_eq!(entry.Mask, FILE_ALL_ACCESS);
                assert_ne!(
                    EqualSid(
                        (&raw const entry.SidStart).cast_mut().cast(),
                        sid.as_ptr().cast_mut().cast()
                    ),
                    0
                );
                let inheritance = if directory {
                    OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
                } else {
                    0
                };
                assert_eq!(u32::from(entry.Header.AceFlags), inheritance);
                assert!(LocalFree(descriptor).is_null());
            }
        }
    }
}
