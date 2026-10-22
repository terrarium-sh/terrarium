use std::{fs::File, os::windows::io::AsRawHandle as _, ptr::null_mut};

use std::os::windows::io::{FromRawHandle as _, OwnedHandle};
use std::path::{Component, Path, PathBuf};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use crate::filesystem::Error;

pub mod symlink_broker;

#[derive(Clone, Copy)]
pub struct FileAccess {
    pub read: bool,
    pub write: bool,
}

pub fn reopen_file_with_delete_sharing(file: &File, access: FileAccess) -> std::io::Result<File> {
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let desired_access = (if access.read { GENERIC_READ } else { 0 })
        | (if access.write { GENERIC_WRITE } else { 0 });
    reopen(
        file,
        desired_access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0,
    )
}

/// `directory` reopened without delete sharing, so nobody can rename it while the handle lives:
/// a metadata handle shares delete, and a guest could otherwise swap a junction in under the
/// path built from it. The pin needs data access: Windows skips share-mode checks for a handle
/// holding only `FILE_READ_ATTRIBUTES`.
fn pin_directory(directory: &File) -> std::io::Result<File> {
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    reopen(
        directory,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_FLAG_BACKUP_SEMANTICS,
    )
}

#[allow(unsafe_code)]
fn reopen(file: &File, desired_access: u32, share_mode: u32, flags: u32) -> std::io::Result<File> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::ReOpenFile;

    // SAFETY: reopening the retained handle preserves the granted object without resolving a path.
    let reopened = unsafe { ReOpenFile(file.as_raw_handle(), desired_access, share_mode, flags) };
    if reopened == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: ReOpenFile returned a new owned handle, consumed exactly once here.
    Ok(File::from(unsafe {
        OwnedHandle::from_raw_handle(reopened)
    }))
}

struct ResolvedLeaf {
    _parent: File,
    path: PathBuf,
}

#[derive(Clone, Copy)]
enum TrailingSeparator {
    Strip,
    Reject,
}

fn resolve_leaf(
    directory: &File,
    path: &Path,
    trailing_separator: TrailingSeparator,
) -> std::io::Result<ResolvedLeaf> {
    let (parent, leaf) = resolve_parent(directory, path, trailing_separator)?;
    let path = nt_final_path(&parent)?.join(leaf);
    Ok(ResolvedLeaf {
        _parent: parent,
        path,
    })
}

/// Opens the leaf's parent through the confined resolver; the leaf itself is not touched.
fn resolve_parent(
    directory: &File,
    path: &Path,
    trailing_separator: TrailingSeparator,
) -> std::io::Result<(File, std::ffi::OsString)> {
    use std::io::{Error, ErrorKind};

    let raw_path = path.as_os_str().to_string_lossy();
    let trimmed_path = raw_path.trim_end_matches(['/', '\\']);
    if trimmed_path.ends_with("/.")
        || trimmed_path.ends_with("\\.")
        || (matches!(trailing_separator, TrailingSeparator::Reject)
            && trimmed_path.len() != raw_path.len())
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "path must name a child",
        ));
    }
    let mut components = path.components();
    let Some(Component::Normal(leaf)) = components.next_back() else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "path must name a child",
        ));
    };
    let parent_path = components.as_path();
    let parent = if parent_path.as_os_str().is_empty() {
        pin_directory(directory)?
    } else {
        cap_primitives::fs::open_dir(directory, parent_path)?
    };
    Ok((parent, leaf.to_os_string()))
}

#[allow(unsafe_code)]
fn nt_final_path(directory: &File) -> std::io::Result<PathBuf> {
    use std::ffi::{OsStr, OsString};
    use std::os::windows::ffi::OsStringExt as _;
    use windows_sys::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, VOLUME_NAME_NT};

    let mut path = vec![0_u16; 32_768];
    // AppContainer denies DOS-volume translation even for granted directory handles.
    // SAFETY: the directory handle remains live and the buffer is writable for its full length.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            directory.as_raw_handle(),
            path.as_mut_ptr(),
            u32::try_from(path.len()).map_err(std::io::Error::other)?,
            VOLUME_NAME_NT,
        )
    };
    if length == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if length as usize >= path.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "resolved path is too long",
        ));
    }
    let nt_path = OsString::from_wide(&path[..length as usize]);
    if !Path::new(&nt_path).starts_with(OsStr::new(r"\Device")) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "resolved path is not a device path",
        ));
    }
    let mut global_root = OsString::from(r"\\?\GLOBALROOT");
    global_root.push(nt_path);
    Ok(PathBuf::from(global_root))
}

pub(super) fn matches_canonical_root(directory: &File, root: &Path) -> std::io::Result<bool> {
    use std::ffi::OsString;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::path::Prefix;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

    let mut components = root.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Ok(false);
    };
    if !matches!(
        prefix.kind(),
        Prefix::Disk(_) | Prefix::VerbatimDisk(_) | Prefix::UNC(_, _) | Prefix::VerbatimUNC(_, _)
    ) || !matches!(components.next(), Some(Component::RootDir))
    {
        return Ok(false);
    }
    let mut volume_root = OsString::from(prefix.as_os_str());
    volume_root.push(r"\");
    let volume_root = File::options()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(PathBuf::from(volume_root))?;
    let mut expected = nt_final_path(&volume_root)?;
    for component in components {
        let Component::Normal(name) = component else {
            return Ok(false);
        };
        expected.push(name);
    }
    Ok(nt_final_path(directory)? == expected)
}

pub fn read_base_dir(directory: &File) -> std::io::Result<std::fs::ReadDir> {
    let pinned = pin_directory(directory)?;
    std::fs::read_dir(nt_final_path(&pinned)?)
}

pub fn create_directory_at(directory: &File, path: &Path) -> std::io::Result<()> {
    let child = resolve_leaf(directory, path, TrailingSeparator::Strip)?;
    std::fs::create_dir(&child.path)
}

pub fn hard_link_at(
    old_directory: &File,
    old_path: &Path,
    new_directory: &File,
    new_path: &Path,
) -> std::io::Result<()> {
    let old = resolve_leaf(old_directory, old_path, TrailingSeparator::Reject)?;
    let new = resolve_leaf(new_directory, new_path, TrailingSeparator::Reject)?;
    std::fs::hard_link(&old.path, &new.path)
}

pub fn rename_at(
    old_directory: &File,
    old_path: &Path,
    new_directory: &File,
    new_path: &Path,
) -> std::io::Result<()> {
    let old = resolve_leaf(old_directory, old_path, TrailingSeparator::Strip)?;
    let new = resolve_leaf(new_directory, new_path, TrailingSeparator::Strip)?;
    std::fs::rename(&old.path, &new.path)
}

pub fn remove_directory_at(directory: &File, path: &Path) -> std::io::Result<()> {
    let child = resolve_leaf(directory, path, TrailingSeparator::Reject)?;
    std::fs::remove_dir(&child.path)
}

pub fn unlink_file_at(directory: &File, path: &Path) -> std::io::Result<()> {
    let child = resolve_leaf(directory, path, TrailingSeparator::Reject)?;
    std::fs::remove_file(&child.path)
}

#[allow(unsafe_code)]
pub(super) fn file_identity(file: &File) -> std::io::Result<super::FileIdentity> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };

    let mut information = FILE_ID_INFO::default();
    // SAFETY: file is live and information has the layout and size requested by FileIdInfo.
    let status = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&raw mut information).cast(),
            u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).map_err(std::io::Error::other)?,
        )
    };
    if status == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(super::FileIdentity {
        volume_serial: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
    })
}

/// Opens `name` relative to `parent` without resolving a path; `options` should include
/// `FILE_OPEN_REPARSE_POINT` whenever the child may be a link.
#[allow(unsafe_code)]
fn nt_open_child(
    parent: &File,
    name: &std::ffi::OsStr,
    access: u32,
    disposition: u32,
    options: u32,
) -> std::io::Result<File> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::ptr::null;
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile};
    use windows_sys::Win32::Foundation::{RtlNtStatusToDosError, UNICODE_STRING};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
    };
    let mut encoded = name.encode_wide().collect::<Vec<_>>();
    let length = u16::try_from(encoded.len() * 2).map_err(std::io::Error::other)?;
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: encoded.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>()).map_err(std::io::Error::other)?,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &raw const name,
        ..Default::default()
    };
    let mut status = IO_STATUS_BLOCK::default();
    let mut handle = null_mut();
    // SAFETY: the child name and parent handle remain live for the synchronous call.
    let result = unsafe {
        NtCreateFile(
            &raw mut handle,
            access | SYNCHRONIZE,
            &raw const attributes,
            &raw mut status,
            null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            disposition,
            options | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if result < 0 {
        // SAFETY: RtlNtStatusToDosError only translates the status value.
        let code = unsafe { RtlNtStatusToDosError(result) };
        return Err(std::io::Error::from_raw_os_error(
            i32::try_from(code).unwrap_or(i32::MAX),
        ));
    }
    // SAFETY: a successful NtCreateFile returns one owned handle.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(handle) }))
}

pub(super) fn open_metadata_file(directory: &File, name: &str) -> Result<File, Error> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Wdk::Storage::FileSystem::{FILE_OPEN, FILE_OPEN_REPARSE_POINT};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    };
    let file = nt_open_child(
        directory,
        std::ffi::OsStr::new(name),
        FILE_READ_ATTRIBUTES,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT,
    )
    .map_err(|_| Error::Access)?;
    if file.metadata().map_err(|_| Error::Io)?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(Error::Access);
    }
    Ok(file)
}

/// The version WSL writes ahead of the UTF-8 target in an `IO_REPARSE_TAG_LX_SYMLINK` buffer.
const WSL_SYMLINK_VERSION: u32 = 2;
/// Linux `PATH_MAX` less its terminator.
const MAX_SYMLINK_TARGET_BYTES: usize = 4095;
/// `ReparseTag`, `ReparseDataLength` and `Reserved` precede the reparse data.
const REPARSE_HEADER_BYTES: usize = 8;

/// Creates a Linux symlink the way WSL stores one, which Windows itself never follows; an
/// `AppContainer` may not set reparse points, so a sandboxed VM goes through [`symlink_broker`].
#[allow(unsafe_code)]
pub fn symlink_at(directory: &File, path: &Path, target: &str) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT, IO_REPARSE_TAG_LX_SYMLINK,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_DISPOSITION_INFO, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FileDispositionInfo,
        SetFileInformationByHandle,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;

    // Matches WASI's cap-std symlink-at; the raw code keeps the guest's EPERM across the broker.
    if target.starts_with('/') {
        return Err(Error::from_raw_os_error(
            windows_sys::Win32::Foundation::ERROR_PRIVILEGE_NOT_HELD.cast_signed(),
        ));
    }
    if target.is_empty() || target.len() > MAX_SYMLINK_TARGET_BYTES || target.contains('\0') {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "invalid symlink target",
        ));
    }
    let data_length = u16::try_from(4 + target.len()).map_err(Error::other)?;
    let mut buffer = Vec::with_capacity(REPARSE_HEADER_BYTES + usize::from(data_length));
    buffer.extend(IO_REPARSE_TAG_LX_SYMLINK.cast_unsigned().to_le_bytes());
    buffer.extend(data_length.to_le_bytes());
    buffer.extend(0_u16.to_le_bytes());
    buffer.extend(WSL_SYMLINK_VERSION.to_le_bytes());
    buffer.extend(target.as_bytes());
    let (parent, leaf) = resolve_parent(directory, path, TrailingSeparator::Reject)?;
    let link = nt_open_child(
        &parent,
        &leaf,
        FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | DELETE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
    )?;
    let mut returned = 0;
    // SAFETY: link is live and buffer holds the complete reparse data for the call.
    let is_set = unsafe {
        DeviceIoControl(
            link.as_raw_handle(),
            FSCTL_SET_REPARSE_POINT,
            buffer.as_ptr().cast(),
            u32::try_from(buffer.len()).map_err(Error::other)?,
            null_mut(),
            0,
            &raw mut returned,
            null_mut(),
        )
    } != 0;
    if is_set {
        return Ok(());
    }
    let error = Error::last_os_error();
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: link was opened with DELETE and disposition has the layout FileDispositionInfo expects.
    unsafe {
        SetFileInformationByHandle(
            link.as_raw_handle(),
            FileDispositionInfo,
            (&raw const disposition).cast(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO>()).map_err(Error::other)?,
        );
    }
    Err(error)
}

/// Reads a symlink [`symlink_at`] created; `Ok(None)` means the entry is not such a link.
#[allow(unsafe_code)]
pub fn read_wsl_symlink_at(directory: &File, path: &Path) -> std::io::Result<Option<String>> {
    use std::io::{Error, ErrorKind};
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_OPEN, FILE_OPEN_REPARSE_POINT, IO_REPARSE_TAG_LX_SYMLINK,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_READ_ATTRIBUTES,
        FileAttributeTagInfo, GetFileInformationByHandleEx, MAXIMUM_REPARSE_DATA_BUFFER_SIZE,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;

    let (parent, leaf) = resolve_parent(directory, path, TrailingSeparator::Reject)?;
    let link = nt_open_child(
        &parent,
        &leaf,
        FILE_READ_ATTRIBUTES,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT,
    )?;
    let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: link is live and tag has the layout FileAttributeTagInfo writes.
    if unsafe {
        GetFileInformationByHandleEx(
            link.as_raw_handle(),
            FileAttributeTagInfo,
            (&raw mut tag).cast(),
            u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>()).map_err(Error::other)?,
        )
    } == 0
    {
        return Err(Error::last_os_error());
    }
    if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        || tag.ReparseTag != IO_REPARSE_TAG_LX_SYMLINK.cast_unsigned()
    {
        return Ok(None);
    }
    let mut buffer = vec![0_u8; MAXIMUM_REPARSE_DATA_BUFFER_SIZE as usize];
    let mut returned = 0;
    // SAFETY: link is live and buffer is writable for its full length.
    if unsafe {
        DeviceIoControl(
            link.as_raw_handle(),
            FSCTL_GET_REPARSE_POINT,
            std::ptr::null(),
            0,
            buffer.as_mut_ptr().cast(),
            u32::try_from(buffer.len()).map_err(Error::other)?,
            &raw mut returned,
            null_mut(),
        )
    } == 0
    {
        return Err(Error::last_os_error());
    }
    parse_wsl_symlink(&buffer[..usize::try_from(returned).map_err(Error::other)?])
        .map(Some)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "malformed WSL symlink"))
}

fn parse_wsl_symlink(buffer: &[u8]) -> Option<String> {
    let header = buffer.get(..REPARSE_HEADER_BYTES)?;
    let data_length = usize::from(u16::from_le_bytes([header[4], header[5]]));
    let data = buffer.get(REPARSE_HEADER_BYTES..REPARSE_HEADER_BYTES + data_length)?;
    let (version, target) = data.split_first_chunk::<4>()?;
    (u32::from_le_bytes(*version) == WSL_SYMLINK_VERSION
        && !target.is_empty()
        && target.len() <= MAX_SYMLINK_TARGET_BYTES)
        .then(|| String::from_utf8(target.to_vec()).ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A WSL-style link round-trips its target, reads as a symlink to std (and so to WASI),
    /// is never followed by Windows, and is renamed and removed like any other entry.
    #[test]
    fn wsl_symlinks_round_trip_and_windows_never_follows_them() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("base"), b"target").unwrap();
        std::fs::create_dir(temp.path().join("nested")).unwrap();
        let directory =
            crate::filesystem::share::open_share_root(&temp.path().canonicalize().unwrap())
                .unwrap();
        symlink_at(&directory, Path::new("nested/link"), "../base").unwrap();
        assert_eq!(
            read_wsl_symlink_at(&directory, Path::new("nested/link")).unwrap(),
            Some("../base".into())
        );
        let metadata = std::fs::symlink_metadata(temp.path().join("nested/link")).unwrap();
        assert!(metadata.file_type().is_symlink());
        assert!(std::fs::read(temp.path().join("nested/link")).is_err());
        assert_eq!(
            symlink_at(&directory, Path::new("nested/link"), "other")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            read_wsl_symlink_at(&directory, Path::new("base")).unwrap(),
            None
        );
        rename_at(
            &directory,
            Path::new("nested/link"),
            &directory,
            Path::new("moved"),
        )
        .unwrap();
        assert_eq!(
            read_wsl_symlink_at(&directory, Path::new("moved")).unwrap(),
            Some("../base".into())
        );
        unlink_file_at(&directory, Path::new("moved")).unwrap();
        assert!(!temp.path().join("moved").exists());
        assert_eq!(std::fs::read(temp.path().join("base")).unwrap(), b"target");
    }

    #[test]
    fn wsl_symlinks_reject_escapes_and_invalid_targets() {
        let temp = tempfile::tempdir().unwrap();
        let directory =
            crate::filesystem::share::open_share_root(&temp.path().canonicalize().unwrap())
                .unwrap();
        for (path, target) in [
            ("../escape", "target"),
            ("link/", "target"),
            ("link", ""),
            ("link", "nul\0byte"),
        ] {
            assert!(symlink_at(&directory, Path::new(path), target).is_err());
        }
        assert!(symlink_at(&directory, Path::new("link"), &"x".repeat(4096)).is_err());
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
        let mut malformed = vec![0_u8; REPARSE_HEADER_BYTES];
        malformed[4..6].copy_from_slice(&8_u16.to_le_bytes());
        malformed.extend(1_u32.to_le_bytes());
        malformed.extend(b"link");
        assert_eq!(parse_wsl_symlink(&malformed), None);
        assert_eq!(parse_wsl_symlink(&malformed[..10]), None);
    }

    #[test]
    fn base_directory_iteration_uses_opened_handle() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("one"), b"one").unwrap();
        std::fs::write(temp.path().join("two"), b"two").unwrap();
        let directory = File::options()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(temp.path())
            .unwrap();
        let mut names = read_base_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            [
                std::ffi::OsString::from("one"),
                std::ffi::OsString::from("two")
            ]
        );
    }

    /// A guest's metadata handle shares delete. Holding a clone of it while acting on the path
    /// built from it would let the guest rename the directory and swap in a host-made junction
    /// that points outside the share.
    #[test]
    fn parent_resolution_pins_a_delete_sharing_directory() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("held")).unwrap();
        let metadata_handle = File::options()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(temp.path().join("held"))
            .unwrap();
        let (parent, _) = resolve_parent(
            &metadata_handle,
            Path::new("child"),
            TrailingSeparator::Reject,
        )
        .unwrap();
        assert!(std::fs::rename(temp.path().join("held"), temp.path().join("moved")).is_err());
        drop(parent);
        std::fs::rename(temp.path().join("held"), temp.path().join("moved")).unwrap();
    }

    #[test]
    fn leaf_mutations_preserve_names_with_trailing_spaces() {
        let temp = tempfile::tempdir().unwrap();
        let directory =
            crate::filesystem::share::open_share_root(&temp.path().canonicalize().unwrap())
                .unwrap();
        create_directory_at(&directory, Path::new(".. ")).unwrap();
        let names = read_base_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, [std::ffi::OsString::from(".. ")]);
        remove_directory_at(&directory, Path::new(".. ")).unwrap();
        assert!(temp.path().is_dir());
    }

    #[test]
    fn confined_parent_resolution_and_leaf_mutations() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

        let temp = tempfile::tempdir().unwrap();
        let directory = File::options()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(temp.path())
            .unwrap();
        create_directory_at(&directory, Path::new("nested")).unwrap();
        std::fs::write(temp.path().join("nested/source"), b"content").unwrap();
        rename_at(
            &directory,
            Path::new("nested/source"),
            &directory,
            Path::new("nested/renamed"),
        )
        .unwrap();
        hard_link_at(
            &directory,
            Path::new("nested/renamed"),
            &directory,
            Path::new("nested/linked"),
        )
        .unwrap();
        unlink_file_at(&directory, Path::new("nested/renamed")).unwrap();
        assert_eq!(
            std::fs::read(temp.path().join("nested/linked")).unwrap(),
            b"content"
        );
        unlink_file_at(&directory, Path::new("nested/linked")).unwrap();
        remove_directory_at(&directory, Path::new("nested")).unwrap();
        assert!(!temp.path().join("nested").exists());
        assert!(create_directory_at(&directory, Path::new("../escape")).is_err());
        assert!(create_directory_at(&directory, Path::new("\\escape")).is_err());
        std::fs::write(temp.path().join("trailing"), b"preserved").unwrap();
        assert!(unlink_file_at(&directory, Path::new("trailing/")).is_err());
        assert!(
            rename_at(
                &directory,
                Path::new("trailing/."),
                &directory,
                Path::new("moved"),
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(temp.path().join("trailing")).unwrap(),
            b"preserved"
        );

        let outside = tempfile::tempdir().unwrap();
        if std::os::windows::fs::symlink_dir(outside.path(), temp.path().join("redirect")).is_ok() {
            assert!(create_directory_at(&directory, Path::new("redirect/escape")).is_err());
            assert!(!outside.path().join("escape").exists());
        }
        std::fs::write(outside.path().join("target"), b"outside").unwrap();
        if std::os::windows::fs::symlink_file(
            outside.path().join("target"),
            temp.path().join("source-link"),
        )
        .is_ok()
        {
            hard_link_at(
                &directory,
                Path::new("source-link"),
                &directory,
                Path::new("linked-symlink"),
            )
            .unwrap();
            assert!(
                std::fs::symlink_metadata(temp.path().join("linked-symlink"))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
    }
}
