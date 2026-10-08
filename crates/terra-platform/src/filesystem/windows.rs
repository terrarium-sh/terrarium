use std::{fs::File, os::windows::io::AsRawHandle as _, ptr::null_mut};

use windows_sys::Wdk::Storage::FileSystem::{
    FileFsFullSizeInformation, NtQueryVolumeInformationFile,
};
use windows_sys::Wdk::System::SystemServices::FILE_FS_FULL_SIZE_INFORMATION;
use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{FromRawHandle as _, OwnedHandle};
use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
use windows_sys::Win32::Security::{
    ACL, ACL_REVISION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
    GetLengthSid, GetTokenInformation, InitializeAcl, OBJECT_INHERIT_ACE,
    PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::{Error, FilesystemStat};

#[allow(unsafe_code)]
pub(super) fn read_final_path(file: &File) -> std::io::Result<std::path::PathBuf> {
    use std::os::{windows::ffi::OsStringExt as _, windows::io::AsRawHandle as _};
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;

    const PATH_CAPACITY: u32 = 32_768;
    let mut path = vec![0; PATH_CAPACITY as usize];
    // SAFETY: `path` is writable for its stated length and `file` stays open.
    let len = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle().cast(),
            path.as_mut_ptr(),
            PATH_CAPACITY,
            0,
        )
    };
    if len == 0 || len >= PATH_CAPACITY {
        return Err(std::io::Error::last_os_error());
    }
    Ok(std::ffi::OsString::from_wide(&path[..len as usize]).into())
}

#[allow(unsafe_code)]
pub(super) fn stat(file: &File) -> Result<FilesystemStat, Error> {
    let mut status = IO_STATUS_BLOCK::default();
    let mut size = FILE_FS_FULL_SIZE_INFORMATION::default();
    // SAFETY: WASI opens synchronous handles; both output buffers stay live for the query.
    let result = unsafe {
        NtQueryVolumeInformationFile(
            file.as_raw_handle(),
            &raw mut status,
            (&raw mut size).cast(),
            u32::try_from(size_of_val(&size)).map_err(|_| Error::Io)?,
            FileFsFullSizeInformation,
        )
    };
    if result != 0 || status.Information < size_of_val(&size) {
        return Err(Error::Io);
    }
    let mut name_max = 0;
    // SAFETY: the handle stays open, name_max is writable, and the unused outputs are optional.
    let result = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            &raw mut name_max,
            null_mut(),
            null_mut(),
            0,
        )
    };
    if result == 0 {
        return Err(Error::Io);
    }
    let block_size = size
        .SectorsPerAllocationUnit
        .checked_mul(size.BytesPerSector)
        .filter(|bytes| *bytes != 0)
        .ok_or(Error::Io)?;
    Ok(FilesystemStat {
        blocks: u64::try_from(size.TotalAllocationUnits).map_err(|_| Error::Io)?,
        blocks_free: u64::try_from(size.ActualAvailableAllocationUnits).map_err(|_| Error::Io)?,
        blocks_available: u64::try_from(size.CallerAvailableAllocationUnits)
            .map_err(|_| Error::Io)?,
        files: 0,
        files_free: 0,
        block_size,
        name_max,
    })
}

#[allow(unsafe_code)]
pub(super) fn set_readonly(file: &File, readonly: bool) -> Result<(), Error> {
    use std::os::windows::io::{FromRawHandle as _, OwnedHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_WRITE_ATTRIBUTES, ReOpenFile,
    };
    // SAFETY: reopening the retained handle preserves the granted object without resolving a path.
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(Error::Access);
    }
    // SAFETY: ReOpenFile returned a new owned handle, consumed exactly once here.
    let writable = File::from(unsafe { OwnedHandle::from_raw_handle(handle) });
    let mut permissions = writable.metadata().map_err(|_| Error::Io)?.permissions();
    permissions.set_readonly(readonly);
    writable.set_permissions(permissions).map_err(|_| Error::Io)
}

#[allow(unsafe_code)]
pub(super) fn open_metadata_file(directory: &File, name: &str) -> Result<File, Error> {
    use std::os::windows::fs::MetadataExt as _;
    use std::os::windows::io::{FromRawHandle as _, OwnedHandle};
    use std::ptr::null;
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    };
    use windows_sys::Win32::Foundation::UNICODE_STRING;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, SYNCHRONIZE,
    };
    let mut encoded = name.encode_utf16().collect::<Vec<_>>();
    let length = u16::try_from(encoded.len() * 2).map_err(|_| Error::Access)?;
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: encoded.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>()).map_err(|_| Error::Io)?,
        RootDirectory: directory.as_raw_handle(),
        ObjectName: &raw const name,
        ..Default::default()
    };
    let mut status = IO_STATUS_BLOCK::default();
    let mut handle = null_mut();
    // SAFETY: the validated child name and directory handle remain live; reparse points are opened without following them.
    let result = unsafe {
        NtCreateFile(
            &raw mut handle,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &raw const attributes,
            &raw mut status,
            null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if result < 0 {
        return Err(Error::Access);
    }
    // SAFETY: a successful NtCreateFile returns one owned handle.
    let file = File::from(unsafe { OwnedHandle::from_raw_handle(handle) });
    if file.metadata().map_err(|_| Error::Io)?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(Error::Access);
    }
    Ok(file)
}

#[allow(unsafe_code)]
pub fn set_owner_only(path: &std::path::Path, directory: bool) -> std::io::Result<()> {
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
        Err(std::io::Error::from_raw_os_error(
            i32::try_from(result).unwrap_or(i32::MAX),
        ))
    }
}

#[allow(unsafe_code)]
fn current_user_sid() -> std::io::Result<Vec<u32>> {
    let mut token = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess is a pseudo-handle and token is writable.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(std::io::Error::last_os_error());
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
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful TokenUser query initializes a TOKEN_USER at the buffer start.
    let token_user = unsafe { user.as_ptr().cast::<TOKEN_USER>().read_unaligned() };
    // SAFETY: TOKEN_USER contains a valid SID whose length Windows reports.
    let len = unsafe { GetLengthSid(token_user.User.Sid) };
    if len == 0 {
        return Err(std::io::Error::last_os_error());
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

fn win_ok(ok: i32) -> std::io::Result<()> {
    (ok != 0)
        .then_some(())
        .ok_or_else(std::io::Error::last_os_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    #[test]
    fn metadata_handles_retain_the_opened_file() {
        let root = tempfile::tempdir().expect("root");
        let root_path = root.path().canonicalize().expect("canonical root");
        let original = root_path.join("original");
        std::fs::write(&original, b"original").expect("write original");
        let directory = super::super::open_share_root(&root_path).expect("open root");
        let mut file = open_metadata_file(&directory, "original").expect("open metadata");
        assert!(file.read(&mut [0]).is_err());
        assert!(file.write(b"changed").is_err());
        let moved = root_path.join("moved");
        std::fs::rename(&original, &moved).expect("rename original");
        std::fs::write(&original, b"replacement").expect("replace original");
        set_readonly(&file, true).expect("set readonly");
        assert!(
            moved
                .metadata()
                .expect("moved metadata")
                .permissions()
                .readonly()
        );
        assert!(
            !original
                .metadata()
                .expect("replacement metadata")
                .permissions()
                .readonly()
        );
        assert_eq!(file.metadata().expect("retained metadata").len(), 8);
        set_readonly(&file, false).expect("clear readonly");
        let filesystem = stat(&directory).expect("filesystem statistics");
        assert!(filesystem.block_size > 0);
        assert!(filesystem.name_max > 0);
        assert!(filesystem.blocks_free <= filesystem.blocks);
    }

    #[test]
    #[allow(unsafe_code)]
    fn owner_only_acl_grants_only_the_current_user_and_blocks_inheritance() {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
        use windows_sys::Win32::Security::{
            ACCESS_ALLOWED_ACE, EqualSid, GetAce, GetSecurityDescriptorControl, SE_DACL_PROTECTED,
        };
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
