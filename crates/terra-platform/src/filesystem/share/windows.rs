use std::{fs::File, os::windows::io::AsRawHandle as _, ptr::null_mut};

use std::os::windows::io::{FromRawHandle as _, OwnedHandle};
use std::path::{Component, Path, PathBuf};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use crate::filesystem::Error;

#[derive(Clone, Copy)]
pub struct FileAccess {
    pub read: bool,
    pub write: bool,
}

#[allow(unsafe_code)]
pub fn reopen_file_with_delete_sharing(file: &File, access: FileAccess) -> std::io::Result<File> {
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, ReOpenFile,
    };

    let desired_access = (if access.read { GENERIC_READ } else { 0 })
        | (if access.write { GENERIC_WRITE } else { 0 });
    // SAFETY: reopening the retained handle preserves the granted object without resolving a path.
    let reopened = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
    };
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
        directory.try_clone()?
    } else {
        cap_primitives::fs::open_dir(directory, parent_path)?
    };
    let path = nt_final_path(&parent)?.join(leaf);
    Ok(ResolvedLeaf {
        _parent: parent,
        path,
    })
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
    std::fs::read_dir(nt_final_path(directory)?)
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

#[cfg(test)]
mod tests {
    use super::*;

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
