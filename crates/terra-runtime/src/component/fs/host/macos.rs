use std::io;

/// Permanently disables content access on future `O_EVTONLY` descriptors in this process and its children.
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

#[cfg(test)]
mod tests {
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;

    use super::restrict_event_only_descriptors;

    #[test]
    fn event_only_descriptor_allows_metadata_without_content_access() {
        use rustix::fs::{Mode, OFlags, openat};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("metadata");
        std::fs::write(&path, b"metadata").unwrap();
        let directory = std::fs::File::open(root.path()).unwrap();
        for mode in [0o600, 0o000] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            restrict_event_only_descriptors().expect("enable event-only descriptor policy");
            let flags = OFlags::from_bits_retain(libc::O_EVTONLY.cast_unsigned())
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC;
            let descriptor =
                openat(&directory, "metadata", flags, Mode::empty()).unwrap_or_else(|error| {
                    panic!("open event-only metadata descriptor, mode {mode:o}: {error}")
                });
            let mut file = std::fs::File::from(descriptor);
            assert_eq!(
                file.metadata()
                    .expect("read event-only descriptor metadata")
                    .len(),
                8
            );
            assert!(file.read(&mut [0; 1]).is_err());
        }
    }
}
