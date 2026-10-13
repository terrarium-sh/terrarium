//! Guest symlinks the trusted launcher creates and reads for a sandboxed VM, because an
//! `AppContainer` may neither set nor read reparse points.

use super::super::{FileIdentity, file_identity};
use crate::local_socket::LocalStream;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::io::FromRawSocket as _;
use std::path::Path;
use std::sync::{Mutex, OnceLock, PoisonError};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_GEN_FAILURE, ERROR_INVALID_PARAMETER,
    ERROR_NOT_A_REPARSE_POINT,
};

pub const SYMLINK_BROKER_ENV: &str = "TERRA_WINDOWS_SANDBOX_SYMLINKS";

const CREATE: u8 = 1;
const READ: u8 = 2;

/// A share root the launcher validated; links are created only beneath writable ones.
pub struct ShareRoot {
    pub directory: File,
    pub is_writable: bool,
}

/// One request naming a share by identity and a path beneath it; anything else ends the channel.
#[derive(Debug, PartialEq, Eq)]
enum Request {
    Create {
        root: FileIdentity,
        path: String,
        target: String,
    },
    Read {
        root: FileIdentity,
        path: String,
    },
}

impl Request {
    fn encode(&self) -> io::Result<Vec<u8>> {
        let (kind, root, texts) = match self {
            Self::Create { root, path, target } => (CREATE, root, vec![path, target]),
            Self::Read { root, path } => (READ, root, vec![path]),
        };
        let mut bytes = vec![kind];
        bytes.extend(root.volume_serial.to_le_bytes());
        bytes.extend(root.file_id);
        for text in texts {
            write_text(&mut bytes, text)?;
        }
        Ok(bytes)
    }

    /// Reads one request; `Ok(None)` is the VM closing the channel.
    fn read(channel: &mut impl Read) -> io::Result<Option<Self>> {
        let mut kind = [0];
        match channel.read_exact(&mut kind) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error),
        }
        let mut volume_serial = [0; 8];
        channel.read_exact(&mut volume_serial)?;
        let mut file_id = [0; 16];
        channel.read_exact(&mut file_id)?;
        let root = FileIdentity {
            volume_serial: u64::from_le_bytes(volume_serial),
            file_id,
        };
        let path = read_text(channel)?;
        match kind[0] {
            CREATE => Ok(Some(Self::Create {
                root,
                path,
                target: read_text(channel)?,
            })),
            READ => Ok(Some(Self::Read { root, path })),
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
    }
}

fn write_text(bytes: &mut Vec<u8>, text: &str) -> io::Result<()> {
    let length =
        u16::try_from(text.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    bytes.extend(length.to_le_bytes());
    bytes.extend(text.as_bytes());
    Ok(())
}

fn read_text(channel: &mut impl Read) -> io::Result<String> {
    let mut length = [0; 2];
    channel.read_exact(&mut length)?;
    let mut text = vec![0; usize::from(u16::from_le_bytes(length))];
    channel.read_exact(&mut text)?;
    String::from_utf8(text).map_err(|_| io::ErrorKind::InvalidData.into())
}

/// Answers the VM's requests on `channel` until it closes the channel or misbehaves.
pub fn serve(
    channel: LocalStream,
    share_roots: Vec<ShareRoot>,
) -> io::Result<std::thread::JoinHandle<()>> {
    let roots = share_roots
        .into_iter()
        .map(|root| Ok((file_identity(&root.directory)?, root)))
        .collect::<io::Result<Vec<_>>>()?;
    std::thread::Builder::new()
        .name("sandbox-launcher-symlinks".into())
        .spawn(move || {
            let mut channel = channel;
            while let Ok(Some(request)) = Request::read(&mut channel) {
                let mut reply = Vec::new();
                match answer(&roots, &request) {
                    Ok(target) => {
                        reply.extend(0_u32.to_le_bytes());
                        if let Some(target) = target
                            && write_text(&mut reply, &target).is_err()
                        {
                            return;
                        }
                    }
                    Err(error) => reply.extend(error_code(&error).to_le_bytes()),
                }
                if channel.write_all(&reply).is_err() {
                    return;
                }
            }
        })
}

fn answer(roots: &[(FileIdentity, ShareRoot)], request: &Request) -> io::Result<Option<String>> {
    let (Request::Create { root, .. } | Request::Read { root, .. }) = request;
    let (_, share) = roots
        .iter()
        .find(|(identity, _)| identity == root)
        .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
    match request {
        Request::Create { path, target, .. } => {
            if !share.is_writable {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            super::symlink_at(&share.directory, Path::new(path), target).map(|()| None)
        }
        Request::Read { path, .. } => {
            super::read_wsl_symlink_at(&share.directory, Path::new(path))?
                .map(Some)
                .ok_or_else(not_a_symlink)
        }
    }
}

fn not_a_symlink() -> io::Error {
    io::Error::from_raw_os_error(ERROR_NOT_A_REPARSE_POINT.cast_signed())
}

fn error_code(error: &io::Error) -> u32 {
    if let Some(code) = error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
    {
        return code;
    }
    match error.kind() {
        io::ErrorKind::PermissionDenied => ERROR_ACCESS_DENIED,
        io::ErrorKind::AlreadyExists => ERROR_ALREADY_EXISTS,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => ERROR_INVALID_PARAMETER,
        _ => ERROR_GEN_FAILURE,
    }
}

/// The VM's channel to the launcher; each request waits for its reply under the lock.
pub struct SymlinkBroker(Mutex<LocalStream>);

impl SymlinkBroker {
    /// The channel the Windows sandbox passed this process, or `None` outside the sandbox.
    #[allow(unsafe_code)]
    pub fn inherited() -> Option<&'static Self> {
        static BROKER: OnceLock<Option<SymlinkBroker>> = OnceLock::new();
        BROKER
            .get_or_init(|| {
                let socket = crate::process::claim_socket(SYMLINK_BROKER_ENV).ok()?;
                // SAFETY: the trusted launcher passed this inherited socket to this process alone.
                Some(Self(Mutex::new(unsafe {
                    LocalStream::from_raw_socket(socket)
                })))
            })
            .as_ref()
    }

    /// Creates the link at `path` beneath `directory`, which lies in the share opened as `root`.
    pub fn symlink_at(
        &self,
        root: &File,
        directory: &File,
        path: &Path,
        target: &str,
    ) -> io::Result<()> {
        let (root, path) = locate(root, directory, path)?;
        self.exchange(&Request::Create {
            root,
            path,
            target: target.to_owned(),
        })
        .map(drop)
    }

    /// Reads the link at `path` like [`super::read_wsl_symlink_at`]; `Ok(None)` means the entry
    /// is not such a link.
    pub fn readlink_at(
        &self,
        root: &File,
        directory: &File,
        path: &Path,
    ) -> io::Result<Option<String>> {
        let (root, path) = locate(root, directory, path)?;
        match self.exchange(&Request::Read { root, path }) {
            Err(error) if error.raw_os_error() == not_a_symlink().raw_os_error() => Ok(None),
            result => result,
        }
    }

    fn exchange(&self, request: &Request) -> io::Result<Option<String>> {
        let bytes = request.encode()?;
        let mut channel = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        channel.write_all(&bytes)?;
        let mut status = [0; 4];
        channel.read_exact(&mut status)?;
        match (u32::from_le_bytes(status), request) {
            (0, Request::Create { .. }) => Ok(None),
            (0, Request::Read { .. }) => read_text(&mut *channel).map(Some),
            (code, _) => Err(io::Error::from_raw_os_error(
                i32::try_from(code).unwrap_or(i32::MAX),
            )),
        }
    }
}

/// Names `path` beneath `directory` by its share's identity and its path from the share root.
fn locate(root: &File, directory: &File, path: &Path) -> io::Result<(FileIdentity, String)> {
    let beneath_root = super::nt_final_path(directory)?
        .strip_prefix(super::nt_final_path(root)?)
        .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?
        .join(path);
    let beneath_root = beneath_root
        .to_str()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    Ok((file_identity(root)?, beneath_root.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::ERROR_PRIVILEGE_NOT_HELD;

    #[test]
    fn requests_round_trip_and_truncation_is_an_error() {
        let root = FileIdentity {
            volume_serial: 7,
            file_id: [3; 16],
        };
        for request in [
            Request::Create {
                root,
                path: "nested/link".into(),
                target: "../base".into(),
            },
            Request::Read {
                root,
                path: "nested/link".into(),
            },
        ] {
            let bytes = request.encode().unwrap();
            assert_eq!(Request::read(&mut bytes.as_slice()).unwrap(), Some(request));
            assert!(Request::read(&mut &bytes[..bytes.len() - 1]).is_err());
        }
        assert_eq!(Request::read(&mut [].as_slice()).unwrap(), None);
        assert!(Request::read(&mut [9_u8; 32].as_slice()).is_err());
    }

    /// The launcher creates links only beneath writable roots and reads them beneath any root
    /// it holds: a read-only share refuses creation, an unknown share refuses both, a path
    /// cannot leave its root, and an absolute target is refused with the code the guest reads as
    /// `EPERM`, even from a VM that skips its own checks.
    #[test]
    fn launcher_respects_share_access() {
        let writable = tempfile::tempdir().unwrap();
        let read_only = tempfile::tempdir().unwrap();
        let unknown = tempfile::tempdir().unwrap();
        std::fs::create_dir(writable.path().join("nested")).unwrap();
        let open = |path: &Path| {
            crate::filesystem::share::open_share_root(&path.canonicalize().unwrap()).unwrap()
        };
        super::super::symlink_at(&open(read_only.path()), Path::new("link"), "host").unwrap();
        let (vm, launcher) = crate::local_socket::create_local_pair().unwrap();
        let _serving = serve(
            launcher,
            vec![
                ShareRoot {
                    directory: open(writable.path()),
                    is_writable: true,
                },
                ShareRoot {
                    directory: open(read_only.path()),
                    is_writable: false,
                },
            ],
        )
        .unwrap();
        let broker = SymlinkBroker(Mutex::new(vm));
        let root = open(writable.path());
        let nested = open(&writable.path().join("nested"));
        broker
            .symlink_at(&root, &nested, Path::new("link"), "../target")
            .unwrap();
        assert_eq!(
            broker
                .readlink_at(&root, &root, Path::new("nested/link"))
                .unwrap(),
            Some("../target".into())
        );
        assert_eq!(
            broker
                .readlink_at(&root, &root, Path::new("nested"))
                .unwrap(),
            None
        );
        assert!(
            broker
                .symlink_at(&root, &root, Path::new("../escape"), "target")
                .is_err()
        );
        assert_eq!(
            broker
                .symlink_at(&root, &root, Path::new("absolute"), "/etc/passwd")
                .unwrap_err()
                .raw_os_error(),
            Some(ERROR_PRIVILEGE_NOT_HELD.cast_signed())
        );
        assert!(!writable.path().join("absolute").exists());
        let read_only_root = open(read_only.path());
        assert_eq!(
            broker
                .readlink_at(&read_only_root, &read_only_root, Path::new("link"))
                .unwrap(),
            Some("host".into())
        );
        assert_eq!(
            broker
                .symlink_at(&read_only_root, &read_only_root, Path::new("new"), "target")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let unknown_root = open(unknown.path());
        std::fs::write(unknown.path().join("file"), b"").unwrap();
        assert!(
            broker
                .readlink_at(&unknown_root, &unknown_root, Path::new("file"))
                .is_err()
        );
        assert_eq!(std::fs::read_dir(read_only.path()).unwrap().count(), 1);
        assert!(!writable.path().parent().unwrap().join("escape").exists());
    }
}
