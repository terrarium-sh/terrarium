use std::{fs::File, os::windows::io::AsRawHandle as _, ptr::null_mut};

use windows_sys::Wdk::Storage::FileSystem::{
    FileFsFullSizeInformation, NtQueryVolumeInformationFile,
};
use windows_sys::Wdk::System::SystemServices::FILE_FS_FULL_SIZE_INFORMATION;
use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

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
