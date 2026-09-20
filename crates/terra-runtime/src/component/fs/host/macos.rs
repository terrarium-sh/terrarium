use std::io;

/// Permanently disables content access on future O_EVTONLY descriptors in this process and its children.
#[allow(unsafe_code)]
pub(super) fn restrict_event_only_descriptors() -> io::Result<()> {
    const IOPOL_TYPE_VFS_DISALLOW_RW_FOR_O_EVTONLY: libc::c_int = 10;
    const IOPOL_SCOPE_PROCESS: libc::c_int = 0;
    const IOPOL_VFS_DISALLOW_RW_FOR_O_EVTONLY_ON: libc::c_int = 1;

    unsafe extern "C" {
        fn setiopolicy_np(
            iotype: libc::c_int,
            scope: libc::c_int,
            policy: libc::c_int,
        ) -> libc::c_int;
    }

    // SAFETY: these are macOS sys/resource.h constants; the call takes no pointers.
    let result = unsafe {
        setiopolicy_np(
            IOPOL_TYPE_VFS_DISALLOW_RW_FOR_O_EVTONLY,
            IOPOL_SCOPE_PROCESS,
            IOPOL_VFS_DISALLOW_RW_FOR_O_EVTONLY_ON,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
