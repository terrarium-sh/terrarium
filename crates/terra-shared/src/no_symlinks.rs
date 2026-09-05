//! Open files without traversing symlinks.

#[cfg(all(unix, any(test, not(target_os = "linux"))))]
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Error, Result};
use std::path::Path;

/// The access pattern for [`open_no_symlinks`].
#[derive(Clone, Copy)]
pub enum OpenMode {
    Read,
    ReadDirectory,
    ReadNonblocking,
    CreateTruncate,
}

#[cfg(unix)]
pub fn open_no_symlinks(path: &Path, mode: OpenMode) -> Result<File> {
    #[cfg(target_os = "linux")]
    {
        open_linux(path, mode)
    }
    #[cfg(all(not(target_os = "linux"), unix))]
    {
        open_unix(path, mode)
    }
}

#[cfg(windows)]
pub fn open_no_symlinks(_path: &Path, _mode: OpenMode) -> Result<File> {
    Err(Error::other(
        "no-symlink open is not supported on this platform",
    ))
}

#[cfg(all(not(unix), not(windows)))]
pub fn open_no_symlinks(_path: &Path, _mode: OpenMode) -> Result<File> {
    Err(Error::other("this platform has no no-symlink file open"))
}

#[cfg(target_os = "linux")]
fn open_linux(path: &Path, mode: OpenMode) -> Result<File> {
    use rustix::fs::{CWD, Mode as FileMode, OFlags, ResolveFlags, openat2};

    let (flags, file_mode) = match mode {
        OpenMode::Read => (OFlags::RDONLY, FileMode::empty()),
        OpenMode::ReadDirectory => (OFlags::PATH | OFlags::DIRECTORY, FileMode::empty()),
        OpenMode::ReadNonblocking => (OFlags::RDONLY | OFlags::NONBLOCK, FileMode::empty()),
        OpenMode::CreateTruncate => (
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC,
            FileMode::from_raw_mode(0o600),
        ),
    };
    let fd = openat2(
        CWD,
        path,
        flags | OFlags::CLOEXEC,
        file_mode,
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| make_unix_open_error(path, error))?;
    Ok(fd.into())
}

#[cfg(all(not(target_os = "linux"), unix))]
fn open_unix(path: &Path, mode: OpenMode) -> Result<File> {
    use rustix::fs::{CWD, Mode as FileMode, OFlags, openat};

    let (flags, file_mode) = match mode {
        OpenMode::Read => (OFlags::RDONLY, FileMode::empty()),
        OpenMode::ReadDirectory => (OFlags::RDONLY | OFlags::DIRECTORY, FileMode::empty()),
        OpenMode::ReadNonblocking => (OFlags::RDONLY | OFlags::NONBLOCK, FileMode::empty()),
        OpenMode::CreateTruncate => (
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC,
            FileMode::from_raw_mode(0o600),
        ),
    };
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut components = path_components(path);
    let final_name = components.next_back().unwrap_or(path.as_os_str());
    let anchor = if path.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let mut directory = openat(CWD, anchor, directory_flags, FileMode::empty())
        .map_err(|error| make_unix_open_error(path, error))?;
    for component in components {
        directory = openat(&directory, component, directory_flags, FileMode::empty())
            .map_err(|error| make_unix_open_error(path, error))?;
    }
    openat(
        &directory,
        final_name,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        file_mode,
    )
    .map(Into::into)
    .map_err(|error| make_unix_open_error(path, error))
}

#[cfg(all(unix, any(test, not(target_os = "linux"))))]
fn path_components(path: &Path) -> impl DoubleEndedIterator<Item = &OsStr> {
    path.components()
        .filter(|component| {
            !matches!(
                component,
                std::path::Component::CurDir | std::path::Component::RootDir
            )
        })
        .map(std::path::Component::as_os_str)
}

#[cfg(unix)]
fn make_unix_open_error(path: &Path, error: rustix::io::Errno) -> Error {
    if error == rustix::io::Errno::LOOP {
        make_symlink_error(path)
    } else {
        error.into()
    }
}

#[must_use]
pub fn make_symlink_error(path: &Path) -> Error {
    Error::other(format!(
        "{} passes through a symlink, and terra does not follow one on a path \
         a sandbox may have planted - name the resolved path instead",
        path.display()
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn path_components_omit_the_anchor_and_leaf() {
        let mut absolute = path_components(Path::new("/a/b/c"));
        assert_eq!(absolute.next_back(), Some(OsStr::new("c")));
        assert_eq!(
            absolute.collect::<Vec<_>>(),
            [OsStr::new("a"), OsStr::new("b")]
        );

        let mut relative = path_components(Path::new("./a/b"));
        assert_eq!(relative.next_back(), Some(OsStr::new("b")));
        assert_eq!(relative.collect::<Vec<_>>(), [OsStr::new("a")]);
    }
}
