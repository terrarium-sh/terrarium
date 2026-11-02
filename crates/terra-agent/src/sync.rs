//! The agent's filesystem synchronization service (`AgentService::Sync`).

use crate::workload::{GuestUser, hand_over};
use rustix::fs::{Mode, OFlags};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;
use terra_protocol::{
    MAX_SYNC_FILE_BYTES, RootStatus, SyncEntry, SyncEntryKind, SyncReply, SyncRequest,
    encode_frame, read_frame, truncate_nanos,
};
use tokio_util::sync::CancellationToken;

const HASH_TIME_LIMIT: Duration = Duration::from_hours(1);
const DIGEST_PROGRESS_INTERVAL: Duration = Duration::from_millis(1500);
const PERMISSION_BITS: u32 = 0o777;
const _: () = assert!(
    terra_protocol::MAX_SYNC_PATH_BYTES >= libc::PATH_MAX as usize,
    "a relative path over the sync limit must already be too long for the kernel"
);

fn ensure_not_cancelled(cancellation: &CancellationToken) -> std::io::Result<()> {
    if cancellation.is_cancelled() {
        Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "file transfer cancelled",
        ))
    } else {
        Ok(())
    }
}

fn open_directory(
    base: impl std::os::fd::AsFd,
    path: impl rustix::path::Arg,
    symlink_flags: OFlags,
) -> std::io::Result<std::fs::File> {
    Ok(rustix::fs::openat(
        base,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | symlink_flags | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into())
}

fn generate_random_temp_name() -> std::io::Result<std::ffi::OsString> {
    let mut random = [0u8; 16];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())?;
    Ok(std::ffi::OsString::from(format!(
        ".terra-put-{:032x}",
        u128::from_le_bytes(random)
    )))
}

/// An entry made under a temporary name beside its destination; dropping it uncommitted
/// removes it.
struct PendingRename {
    parent: std::fs::File,
    temp_name: std::ffi::OsString,
    destination_name: std::ffi::OsString,
    is_committed: bool,
}

impl PendingRename {
    /// Opens the directory holding `destination` without following a link there, then makes the
    /// entry under a temporary name with `create_at`.
    fn create<T>(
        destination: &Path,
        create_at: impl FnOnce(&std::fs::File, &std::ffi::OsStr) -> rustix::io::Result<T>,
    ) -> std::io::Result<(Self, T)> {
        let parent_path = destination
            .parent()
            .ok_or_else(|| std::io::Error::other("destination has no parent directory"))?;
        let destination_name = destination
            .file_name()
            .ok_or_else(|| std::io::Error::other("destination has no file name"))?
            .to_owned();
        let parent = open_directory(rustix::fs::CWD, parent_path, OFlags::NOFOLLOW)?;
        let temp_name = generate_random_temp_name()?;
        let created = create_at(&parent, &temp_name)?;
        let pending = Self {
            parent,
            temp_name,
            destination_name,
            is_committed: false,
        };
        Ok((pending, created))
    }

    fn commit(mut self) -> std::io::Result<()> {
        rustix::fs::renameat(
            &self.parent,
            &self.temp_name,
            &self.parent,
            &self.destination_name,
        )?;
        self.is_committed = true;
        Ok(())
    }
}

impl Drop for PendingRename {
    fn drop(&mut self) {
        if !self.is_committed {
            let _ =
                rustix::fs::unlinkat(&self.parent, &self.temp_name, rustix::fs::AtFlags::empty());
        }
    }
}

pub(crate) fn ensure_directory(path: &Path, owner: GuestUser) -> std::io::Result<()> {
    open_or_create_directory(path, owner, OFlags::empty()).map(drop)
}

fn open_or_create_directory(
    path: &Path,
    owner: GuestUser,
    symlink_flags: OFlags,
) -> std::io::Result<std::fs::File> {
    let mut missing = Vec::new();
    let mut parent = 'ancestors: {
        for ancestor in path.ancestors() {
            match open_directory(rustix::fs::CWD, ancestor, symlink_flags) {
                Ok(handle) => break 'ancestors handle,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(
                        ancestor
                            .file_name()
                            .ok_or_else(|| std::io::Error::other("missing parent has no name"))?,
                    );
                }
                Err(error) => return Err(error),
            }
        }
        return Err(std::io::Error::other("no existing parent directory"));
    };
    for name in missing.into_iter().rev() {
        rustix::fs::mkdirat(&parent, name, Mode::from_raw_mode(0o755))
            .or_else(|error| (error == rustix::io::Errno::EXIST).ok_or(error))?;
        parent = open_directory(&parent, name, OFlags::NOFOLLOW)?;
        hand_over(&parent, owner)?;
    }
    Ok(parent)
}

/// Opens the entry at `path` itself, never a symlink's target.
fn open_entry(path: &Path) -> std::io::Result<std::fs::File> {
    Ok(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into())
}

fn open_regular_file(path: &Path) -> std::io::Result<(std::fs::File, std::fs::Metadata)> {
    let file = open_entry(path)?;
    let meta = file.metadata()?;
    if meta.is_dir() {
        return Err(std::io::Error::other("is a directory"));
    }
    if !meta.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    if meta.len() > MAX_SYNC_FILE_BYTES {
        return Err(std::io::Error::other(format!(
            "file is larger than the {} GiB sync limit",
            MAX_SYNC_FILE_BYTES >> 30
        )));
    }
    Ok((file, meta))
}

fn send_reply(conn: &mut impl Write, reply: &SyncReply) -> std::io::Result<()> {
    let frame = encode_frame(reply)?;
    conn.write_all(&frame)
}

/// Why a request failed.
#[derive(Debug)]
enum Failure {
    /// Replied to as [`SyncReply::Err`]; the session goes on.
    Request(std::io::Error),
    /// The connection broke or the stream lost its framing; the session ends.
    Session(std::io::Error),
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Self::Request(error)
    }
}

/// Sends a reply before the request's closing one.
fn send_partial(conn: &mut impl Write, reply: &SyncReply) -> Result<(), Failure> {
    send_reply(conn, reply).map_err(Failure::Session)
}

fn apply_attributes(
    file: &std::fs::File,
    mode: u32,
    mtime_secs: i64,
    mtime_nanos: u32,
) -> std::io::Result<()> {
    file.set_permissions(std::fs::Permissions::from_mode(mode & PERMISSION_BITS))?;
    file.set_times(terra_protocol::sync_file_times(mtime_secs, mtime_nanos)?)
}

fn is_unchanged_since(file: &std::fs::File, before: &std::fs::Metadata) -> bool {
    file.metadata().is_ok_and(|after| {
        before.len() == after.len() && before.modified().ok() == after.modified().ok()
    })
}

fn stream_exact(
    mut from: impl Read,
    mut to: impl Write,
    size: u64,
    cancellation: &CancellationToken,
) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    let mut remaining = size;
    while remaining > 0 {
        ensure_not_cancelled(cancellation)?;
        let want = usize::min(buf.len(), usize::try_from(remaining).unwrap_or(buf.len()));
        let n = match from.read(&mut buf[..want]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "premature end of file transfer stream",
                ));
            }
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        ensure_not_cancelled(cancellation)?;
        to.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}

fn truncated_mtime_nanos(metadata: &std::fs::Metadata) -> u32 {
    truncate_nanos(u32::try_from(metadata.mtime_nsec()).unwrap_or(0))
}

fn read_link_target(path: &Path) -> std::io::Result<String> {
    std::fs::read_link(path)?
        .into_os_string()
        .into_string()
        .map_err(|_| std::io::Error::other("non-UTF-8 symlink target"))
}

/// Describes the entry at `full`, reported to the host as `relative_path`.
fn entry_at(full: &Path, relative_path: String) -> std::io::Result<SyncEntry> {
    let metadata = std::fs::symlink_metadata(full)?;
    let file_type = metadata.file_type();
    let kind = if file_type.is_dir() {
        SyncEntryKind::Directory
    } else if file_type.is_symlink() {
        SyncEntryKind::Symlink {
            target: read_link_target(full)?,
        }
    } else if file_type.is_file() {
        if metadata.len() > MAX_SYNC_FILE_BYTES {
            let name = if relative_path.is_empty() {
                "the sync root"
            } else {
                &relative_path
            };
            return Err(std::io::Error::other(format!(
                "file is larger than the {} GiB sync limit: {name}",
                MAX_SYNC_FILE_BYTES >> 30
            )));
        }
        SyncEntryKind::File {
            size: metadata.len(),
        }
    } else {
        return Err(std::io::Error::other(format!(
            "unsupported special file: {relative_path}"
        )));
    };
    Ok(SyncEntry {
        relative_path,
        kind,
        mode: metadata.mode() & PERMISSION_BITS,
        mtime_secs: metadata.mtime(),
        mtime_nanos: truncated_mtime_nanos(&metadata),
    })
}

fn inspect_root(path: &Path) -> std::io::Result<RootStatus> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_dir() {
                Ok(RootStatus::ExistingDirectory)
            } else if file_type.is_symlink() {
                Ok(RootStatus::ExistingSymlink)
            } else if file_type.is_file() {
                Ok(RootStatus::ExistingFile)
            } else {
                Err(std::io::Error::other(format!(
                    "root {} is an unsupported file type",
                    path.display()
                )))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RootStatus::Missing),
        Err(e) => Err(std::io::Error::new(
            e.kind(),
            format!("inspecting root {}: {e}", path.display()),
        )),
    }
}

#[derive(Clone, Copy)]
struct WriteFileMeta {
    size: u64,
    mode: u32,
    mtime_secs: i64,
    mtime_nanos: u32,
}

/// The guest root a host sync works on, from `BeginSession` on.
struct Session {
    root: PathBuf,
    root_status: RootStatus,
    owner: GuestUser,
    cancellation: CancellationToken,
}

impl Session {
    fn begin(
        root: PathBuf,
        owner: GuestUser,
        cancellation: &CancellationToken,
    ) -> std::io::Result<Self> {
        Ok(Self {
            root_status: inspect_root(&root)?,
            root,
            owner,
            cancellation: cancellation.clone(),
        })
    }

    fn root_status(&self) -> RootStatus {
        self.root_status
    }

    fn ensure_not_cancelled(&self) -> std::io::Result<()> {
        ensure_not_cancelled(&self.cancellation)
    }

    fn resolve(&self, relative_path: &str) -> std::io::Result<PathBuf> {
        let mut path = self.root.clone();
        if !relative_path.is_empty() {
            for component in relative_path.split('/') {
                match std::fs::symlink_metadata(&path) {
                    Ok(meta) if meta.is_dir() => {}
                    Ok(_) => return Err(std::io::Error::other("sync parent is not a directory")),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                path.push(component);
            }
        }
        Ok(path)
    }

    fn resolve_creating_parent(&self, relative_path: &str) -> std::io::Result<PathBuf> {
        let path = self.resolve(relative_path)?;
        if let Some(parent) = path.parent() {
            ensure_directory(parent, self.owner)?;
        }
        Ok(path)
    }

    fn scan(&self, conn: &mut impl Write) -> Result<SyncReply, Failure> {
        self.ensure_not_cancelled()?;
        if self.root_status == RootStatus::Missing {
            return Ok(SyncReply::ScanComplete);
        }
        let root = entry_at(&self.root, String::new())?;
        let is_directory = root.kind == SyncEntryKind::Directory;
        send_partial(conn, &SyncReply::Entry(root))?;
        if is_directory {
            self.scan_tree(conn)?;
        }
        Ok(SyncReply::ScanComplete)
    }

    fn scan_tree(&self, conn: &mut impl Write) -> Result<(), Failure> {
        let mut pending_directories = VecDeque::from([String::new()]);
        while let Some(rel) = pending_directories.pop_front() {
            self.ensure_not_cancelled()?;
            let full = self.root.join(&rel);
            let read_dir = std::fs::read_dir(&full).map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!("reading directory {}: {e}", full.display()),
                )
            })?;
            for dir_entry in read_dir {
                self.ensure_not_cancelled()?;
                let child = self.child_entry(&rel, &dir_entry?.file_name())?;
                if child.kind == SyncEntryKind::Directory {
                    pending_directories.push_back(child.relative_path.clone());
                }
                send_partial(conn, &SyncReply::Entry(child))?;
            }
        }
        Ok(())
    }

    fn child_entry(&self, parent_rel: &str, name: &std::ffi::OsStr) -> std::io::Result<SyncEntry> {
        let name = name
            .to_str()
            .ok_or_else(|| std::io::Error::other("non-utf8 filename encountered"))?;
        let rel = if parent_rel.is_empty() {
            name.to_owned()
        } else {
            format!("{parent_rel}/{name}")
        };
        // No length check: the kernel refuses a path over PATH_MAX first ("File name too long").
        entry_at(&self.root.join(&rel), rel)
    }

    fn digest(&self, relative_path: &str, conn: &mut impl Write) -> Result<SyncReply, Failure> {
        let (mut file, before) = open_regular_file(&self.resolve(relative_path)?)?;
        let deadline = std::time::Instant::now() + HASH_TIME_LIMIT;
        let mut hasher = Sha256::new();
        // 64 KiB hashed 18% slower: SHA-256 then reads past the L1 cache.
        let mut buffer = [0u8; 8192];
        let mut total_hashed = 0u64;
        let mut last_report = std::time::Instant::now();
        loop {
            self.ensure_not_cancelled()?;
            if std::time::Instant::now() >= deadline || total_hashed > MAX_SYNC_FILE_BYTES {
                return Err(std::io::Error::other("hashing exceeded its limit").into());
            }
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    hasher.update(&buffer[..n]);
                    total_hashed += n as u64;
                    if last_report.elapsed() >= DIGEST_PROGRESS_INTERVAL {
                        send_partial(
                            conn,
                            &SyncReply::DigestProgress {
                                bytes_hashed: total_hashed,
                            },
                        )?;
                        last_report = std::time::Instant::now();
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        if !is_unchanged_since(&file, &before) {
            return Err(std::io::Error::other("source changed while hashing").into());
        }
        Ok(SyncReply::Digest {
            sha256: hasher.finalize().into(),
        })
    }

    fn write_file(
        &self,
        relative_path: &str,
        meta: WriteFileMeta,
        conn: &mut (impl Read + Write),
    ) -> Result<SyncReply, Failure> {
        let (upload, file) = PendingRename::create(
            &self.resolve_creating_parent(relative_path)?,
            |parent, name| {
                rustix::fs::openat(
                    parent,
                    name,
                    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
            },
        )?;
        let file = &mut std::fs::File::from(file);
        send_partial(conn, &SyncReply::WriteFileReady)?;
        stream_exact(&mut *conn, &mut *file, meta.size, &self.cancellation)?;
        self.ensure_not_cancelled()?;
        if !matches!(
            read_frame::<SyncRequest>(&mut *conn)?,
            Some(SyncRequest::CommitFile)
        ) {
            return Err(std::io::Error::other("upload was not committed by sender").into());
        }
        self.ensure_not_cancelled()?;
        file.set_len(meta.size)?;
        hand_over(&*file, self.owner)?;
        apply_attributes(file, meta.mode, meta.mtime_secs, meta.mtime_nanos)?;
        file.sync_all()?;
        self.ensure_not_cancelled()?;
        upload.commit()?;
        Ok(SyncReply::Success)
    }

    fn read_file(&self, relative_path: &str, conn: &mut impl Write) -> Result<SyncReply, Failure> {
        let (mut file, before) = open_regular_file(&self.resolve(relative_path)?)?;
        send_partial(
            conn,
            &SyncReply::ReadFileReady {
                size: before.len(),
                mode: before.mode() & PERMISSION_BITS,
                mtime_secs: before.mtime(),
                mtime_nanos: truncated_mtime_nanos(&before),
            },
        )?;
        // The host reads exactly `size` bytes next, so a reply can no longer be framed.
        stream_exact(&mut file, &mut *conn, before.len(), &self.cancellation)
            .map_err(Failure::Session)?;
        if !is_unchanged_since(&file, &before) {
            return Err(std::io::Error::other("source changed while transferring").into());
        }
        Ok(SyncReply::Success)
    }

    fn create_directory(&self, relative_path: &str, mode: u32) -> Result<SyncReply, Failure> {
        let dir_path = self.resolve_creating_parent(relative_path)?;
        let directory = open_or_create_directory(&dir_path, self.owner, OFlags::NOFOLLOW)?;
        directory.set_permissions(std::fs::Permissions::from_mode(
            (mode & PERMISSION_BITS) | 0o700,
        ))?;
        Ok(SyncReply::Success)
    }

    fn create_symlink(&self, relative_path: &str, target: &str) -> Result<SyncReply, Failure> {
        let (link, ()) = PendingRename::create(
            &self.resolve_creating_parent(relative_path)?,
            |parent, name| rustix::fs::symlinkat(target, parent, name),
        )?;
        link.commit()?;
        Ok(SyncReply::Success)
    }

    fn update_metadata(
        &self,
        relative_path: &str,
        mode: u32,
        mtime_secs: i64,
        mtime_nanos: u32,
    ) -> Result<SyncReply, Failure> {
        let entry = open_entry(&self.resolve(relative_path)?).map_err(|error| {
            if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
                std::io::Error::other("cannot update symlink metadata")
            } else {
                error
            }
        })?;
        apply_attributes(&entry, mode, mtime_secs, mtime_nanos)?;
        Ok(SyncReply::Success)
    }

    fn remove_entry(&self, relative_path: &str) -> Result<SyncReply, Failure> {
        if relative_path.is_empty() {
            return Err(std::io::Error::other("cannot remove session root itself").into());
        }
        let target = self.resolve(relative_path)?;
        if std::fs::symlink_metadata(&target)?.is_dir() {
            std::fs::remove_dir(&target)?;
        } else {
            std::fs::remove_file(&target)?;
        }
        Ok(SyncReply::Success)
    }
}

pub(crate) fn serve_sync_session(
    conn: &mut (impl Read + Write),
    owner: GuestUser,
    cancellation: &CancellationToken,
) -> std::io::Result<()> {
    ensure_not_cancelled(cancellation)?;
    let mut session = None;
    while let Some(request) = read_frame::<SyncRequest>(&mut *conn)? {
        ensure_not_cancelled(cancellation)?;
        let reply = match request {
            SyncRequest::BeginSession { guest_root } => {
                match Session::begin(guest_root.into(), owner, cancellation) {
                    Ok(begun) => Ok(SyncReply::SessionReady {
                        root_status: session.insert(begun).root_status(),
                    }),
                    Err(error) => {
                        session = None;
                        Err(Failure::Request(error))
                    }
                }
            }
            SyncRequest::EndSession => return send_reply(conn, &SyncReply::Success),
            SyncRequest::CommitFile => return Err(std::io::Error::other("unexpected file commit")),
            SyncRequest::ScanEntries => active(session.as_ref())?.scan(conn),
            SyncRequest::ComputeDigest { relative_path } => {
                active(session.as_ref())?.digest(&relative_path, conn)
            }
            SyncRequest::WriteFile {
                relative_path,
                size,
                mode,
                mtime_secs,
                mtime_nanos,
            } => active(session.as_ref())?.write_file(
                &relative_path,
                WriteFileMeta {
                    size,
                    mode,
                    mtime_secs,
                    mtime_nanos,
                },
                conn,
            ),
            SyncRequest::ReadFile { relative_path } => {
                active(session.as_ref())?.read_file(&relative_path, conn)
            }
            SyncRequest::CreateDir {
                relative_path,
                mode,
            } => active(session.as_ref())?.create_directory(&relative_path, mode),
            SyncRequest::CreateSymlink {
                relative_path,
                target,
            } => active(session.as_ref())?.create_symlink(&relative_path, &target),
            SyncRequest::UpdateMetadata {
                relative_path,
                mode,
                mtime_secs,
                mtime_nanos,
            } => active(session.as_ref())?.update_metadata(
                &relative_path,
                mode,
                mtime_secs,
                mtime_nanos,
            ),
            SyncRequest::RemoveEntry { relative_path } => {
                active(session.as_ref())?.remove_entry(&relative_path)
            }
        };
        match reply {
            Ok(reply) => send_reply(conn, &reply)?,
            Err(Failure::Request(error)) => send_reply(conn, &SyncReply::Err(error.to_string()))?,
            Err(Failure::Session(error)) => return Err(error),
        }
    }
    Ok(())
}

fn active(session: Option<&Session>) -> std::io::Result<&Session> {
    session.ok_or_else(|| std::io::Error::other("sync request before BeginSession"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn sync_resolves_parents_above_the_root_but_not_links_inside_it() {
        let scratch = crate::create_scratch_path("sync", "root-symlink-policy");
        let real = scratch.join("real");
        std::fs::create_dir_all(real.join("app")).unwrap();
        let alias = scratch.join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        assert_eq!(inspect_root(&alias).unwrap(), RootStatus::ExistingSymlink);
        let root = alias.join("app");
        assert_eq!(inspect_root(&root).unwrap(), RootStatus::ExistingDirectory);
        let session = test_session(&root, RootStatus::ExistingDirectory);
        let file = session.resolve("file").unwrap();
        std::fs::write(file, b"inside").unwrap();
        assert_eq!(std::fs::read(real.join("app/file")).unwrap(), b"inside");
        std::os::unix::fs::symlink(&real, root.join("link")).unwrap();
        assert!(session.resolve("link/file").is_err());
        assert!(
            test_session(&alias, RootStatus::ExistingSymlink)
                .resolve("file")
                .is_err()
        );
        std::fs::remove_dir_all(scratch).unwrap();
    }

    /// A workload can plant a link after the scan and before `CreateDir`. Neither
    /// directory preparation nor chmod may follow the replacement leaf.
    #[test]
    fn create_directory_rejects_a_leaf_replaced_by_a_symlink() {
        let scratch = crate::create_scratch_path("sync", "directory-symlink");
        let root = scratch.join("root");
        let outside = scratch.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o700)).unwrap();
        let session = test_session(&root, RootStatus::ExistingDirectory);
        session.scan(&mut TestConn::new(Vec::new())).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("new")).unwrap();
        assert!(session.create_directory("new", 0o777).is_err());
        assert_eq!(std::fs::metadata(&outside).unwrap().mode() & 0o777, 0o700);
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn directory_permissions_use_the_opened_inode_after_a_path_swap() {
        let scratch = crate::create_scratch_path("sync", "directory-handle");
        let directory = scratch.join("directory");
        let moved = scratch.join("moved");
        let outside = scratch.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o700)).unwrap();
        let handle =
            open_or_create_directory(&directory, GuestUser::Root, OFlags::NOFOLLOW).unwrap();
        std::fs::rename(&directory, &moved).unwrap();
        std::os::unix::fs::symlink(&outside, &directory).unwrap();
        handle
            .set_permissions(std::fs::Permissions::from_mode(0o755))
            .unwrap();
        assert_eq!(std::fs::metadata(&outside).unwrap().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(&moved).unwrap().mode() & 0o777, 0o755);
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn an_upload_without_commit_preserves_the_existing_file() {
        let scratch = crate::create_scratch_path("sync", "uncommitted-upload");
        std::fs::create_dir_all(&scratch).unwrap();
        let destination = scratch.join("file");
        std::fs::write(&destination, b"old").unwrap();
        for body in [b"short".as_slice(), b"new contents".as_slice()] {
            let mut input = begin_session(&scratch);
            input.extend(frame(&SyncRequest::WriteFile {
                relative_path: "file".into(),
                size: 12,
                mode: 0o644,
                mtime_secs: 100,
                mtime_nanos: 0,
            }));
            input.extend(body);
            let mut conn = TestConn::new(input);
            serve_sync_session(&mut conn, GuestUser::Root, &CancellationToken::new()).unwrap();
            assert_eq!(std::fs::read(&destination).unwrap(), b"old");
            assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 1);
        }
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn failed_upload_ready_reply_removes_the_temporary_file() {
        let scratch = crate::create_scratch_path("sync", "failed-upload-ready");
        std::fs::create_dir_all(&scratch).unwrap();
        let destination = scratch.join("file");
        std::fs::write(&destination, b"old").unwrap();
        let mut closed = std::io::Cursor::new(&mut [] as &mut [u8]);
        let written = test_session(&scratch, RootStatus::ExistingDirectory).write_file(
            "file",
            WriteFileMeta {
                size: 3,
                mode: 0o644,
                mtime_secs: 100,
                mtime_nanos: 0,
            },
            &mut closed,
        );
        assert_matches!(
            written,
            Err(Failure::Session(error)) if error.kind() == std::io::ErrorKind::WriteZero
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"old");
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 1);
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn mutation_errors_are_replied_to_without_ending_the_session() {
        let scratch = crate::create_scratch_path("sync", "mutation-errors");
        std::fs::create_dir_all(&scratch).unwrap();
        std::fs::write(scratch.join("file"), b"old").unwrap();
        std::os::unix::fs::symlink("file", scratch.join("link")).unwrap();
        let requests = [
            SyncRequest::BeginSession {
                guest_root: scratch.to_str().unwrap().into(),
            },
            SyncRequest::CreateDir {
                relative_path: "link".into(),
                mode: 0o777,
            },
            SyncRequest::CreateSymlink {
                relative_path: "file/child".into(),
                target: "target".into(),
            },
            SyncRequest::UpdateMetadata {
                relative_path: "link".into(),
                mode: 0o777,
                mtime_secs: 100,
                mtime_nanos: 0,
            },
            SyncRequest::RemoveEntry {
                relative_path: String::new(),
            },
            SyncRequest::EndSession,
        ];
        let mut conn = TestConn::new(requests.iter().flat_map(frame).collect());
        serve_sync_session(&mut conn, GuestUser::Root, &CancellationToken::new()).unwrap();
        assert_matches!(
            conn.replies().as_slice(),
            [
                SyncReply::SessionReady {
                    root_status: RootStatus::ExistingDirectory
                },
                SyncReply::Err(_),
                SyncReply::Err(_),
                SyncReply::Err(_),
                SyncReply::Err(_),
                SyncReply::Success,
            ]
        );
        assert_eq!(std::fs::read(scratch.join("file")).unwrap(), b"old");
        std::fs::remove_dir_all(scratch).unwrap();
    }

    struct TestConn {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
        /// Reading stops at this input offset and cancels the token.
        cancel_at: Option<(u64, CancellationToken)>,
    }

    fn test_session(root: &Path, root_status: RootStatus) -> Session {
        Session {
            root: root.to_path_buf(),
            root_status,
            owner: GuestUser::Root,
            cancellation: CancellationToken::new(),
        }
    }

    impl TestConn {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input: std::io::Cursor::new(input),
                output: Vec::new(),
                cancel_at: None,
            }
        }

        fn replies(&self) -> Vec<SyncReply> {
            let mut output = self.output.as_slice();
            std::iter::from_fn(|| read_frame(&mut output).unwrap()).collect()
        }
    }

    fn frame(request: &SyncRequest) -> Vec<u8> {
        encode_frame(request).unwrap()
    }

    fn begin_session(root: &Path) -> Vec<u8> {
        frame(&SyncRequest::BeginSession {
            guest_root: root.to_str().unwrap().into(),
        })
    }

    impl Read for TestConn {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let Some((cancel_at, cancellation)) = &self.cancel_at else {
                return self.input.read(buf);
            };
            let remaining = cancel_at.saturating_sub(self.input.position());
            let count = usize::min(buf.len(), usize::try_from(remaining).unwrap());
            let read = self.input.read(&mut buf[..count])?;
            if self.input.position() >= *cancel_at {
                cancellation.cancel();
            }
            Ok(read)
        }
    }

    impl Write for TestConn {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Cancelling while copying an upload keeps the destination and removes the temporary file.
    #[test]
    fn cancelling_upload_preserves_the_existing_file() {
        let scratch = crate::create_scratch_path("sync", "cancel-upload");
        std::fs::create_dir_all(&scratch).unwrap();
        let destination = scratch.join("file");
        std::fs::write(&destination, b"old").unwrap();
        let begin = begin_session(&scratch);
        let write = frame(&SyncRequest::WriteFile {
            relative_path: "file".into(),
            size: 12,
            mode: 0o644,
            mtime_secs: 100,
            mtime_nanos: 0,
        });
        let cancellation = CancellationToken::new();
        let mut input = begin.clone();
        input.extend(&write);
        input.extend(b"new contents");
        let mut conn = TestConn {
            cancel_at: Some((
                u64::try_from(begin.len() + write.len() + 1).unwrap(),
                cancellation.clone(),
            )),
            ..TestConn::new(input)
        };

        serve_sync_session(&mut conn, GuestUser::Root, &cancellation).unwrap();

        assert!(cancellation.is_cancelled());
        assert_eq!(std::fs::read(&destination).unwrap(), b"old");
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 1);
        std::fs::remove_dir_all(scratch).unwrap();
    }

    /// A child the scan cannot describe ends the scan with an error reply
    /// instead of dropping the connection without one.
    #[test]
    fn scan_replies_with_an_error_for_a_non_utf8_symlink_target() {
        use std::os::unix::ffi::OsStrExt as _;
        let scratch = crate::create_scratch_path("sync", "non-utf8-link-target");
        std::fs::create_dir_all(&scratch).unwrap();
        std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(b"\xff"), scratch.join("link"))
            .unwrap();
        let mut input = begin_session(&scratch);
        input.extend(frame(&SyncRequest::ScanEntries));
        input.extend(frame(&SyncRequest::EndSession));
        let mut conn = TestConn::new(input);
        serve_sync_session(&mut conn, GuestUser::Root, &CancellationToken::new()).unwrap();
        assert_matches!(
            conn.replies().as_slice(),
            [
                SyncReply::SessionReady { .. },
                SyncReply::Entry(_),
                SyncReply::Err(message),
                SyncReply::Success,
            ] if message == "non-UTF-8 symlink target"
        );
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn scan_replies_with_an_error_for_a_file_past_the_sync_limit() {
        let scratch = crate::create_scratch_path("sync", "oversized-file");
        std::fs::create_dir_all(&scratch).unwrap();
        std::fs::File::create(scratch.join("big"))
            .unwrap()
            .set_len(MAX_SYNC_FILE_BYTES + 1)
            .unwrap();
        let mut input = begin_session(&scratch);
        input.extend(frame(&SyncRequest::ScanEntries));
        input.extend(frame(&SyncRequest::EndSession));
        let mut conn = TestConn::new(input);
        serve_sync_session(&mut conn, GuestUser::Root, &CancellationToken::new()).unwrap();
        assert_matches!(
            conn.replies().as_slice(),
            [
                SyncReply::SessionReady { .. },
                SyncReply::Entry(_),
                SyncReply::Err(message),
                SyncReply::Success,
            ] if message == "file is larger than the 16 GiB sync limit: big"
        );
        std::fs::remove_dir_all(scratch).unwrap();
    }

    /// A workload can swap an entry for a link before `UpdateMetadata`; the chmod
    /// and times must land on the entry itself, never on the link's target.
    #[test]
    fn update_metadata_refuses_a_symlink_without_touching_its_target() {
        let scratch = crate::create_scratch_path("sync", "update-metadata-link");
        let outside = scratch.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = scratch.join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let updated = test_session(&root, RootStatus::ExistingDirectory)
            .update_metadata("link", 0o777, 100, 0);
        assert_matches!(
            updated,
            Err(Failure::Request(error)) if error.to_string() == "cannot update symlink metadata"
        );
        assert_eq!(std::fs::metadata(&outside).unwrap().mode() & 0o777, 0o700);
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn create_symlink_replaces_an_existing_entry_and_leaves_no_temporary_link() {
        let scratch = crate::create_scratch_path("sync", "create-symlink");
        std::fs::create_dir_all(&scratch).unwrap();
        std::fs::write(scratch.join("entry"), b"old").unwrap();
        let session = test_session(&scratch, RootStatus::ExistingDirectory);
        session.create_symlink("entry", "target").unwrap();
        session.create_symlink("nested/link", "../target").unwrap();
        assert_eq!(
            std::fs::read_link(scratch.join("entry")).unwrap(),
            Path::new("target")
        );
        assert_eq!(
            std::fs::read_link(scratch.join("nested/link")).unwrap(),
            Path::new("../target")
        );
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 2);
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn update_metadata_sets_mtime_on_directories_and_keeps_atime() {
        let scratch = crate::create_scratch_path("sync", "update-metadata-times");
        let directory = scratch.join("directory");
        std::fs::create_dir_all(&directory).unwrap();
        let accessed_before = std::fs::metadata(&directory).unwrap().accessed().unwrap();
        test_session(&scratch, RootStatus::ExistingDirectory)
            .update_metadata("directory", 0o755, 1000, 500)
            .unwrap();
        let metadata = std::fs::metadata(&directory).unwrap();
        assert_eq!((metadata.mtime(), metadata.mtime_nsec()), (1000, 500));
        assert_eq!(metadata.accessed().unwrap(), accessed_before);
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn random_temp_suffix_has_fixed_hex_shape() {
        let name = generate_random_temp_name().unwrap().into_string().unwrap();
        let suffix = name.strip_prefix(".terra-put-").unwrap();
        assert_eq!(suffix.len(), 32);
        assert!(suffix.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn remove_entry_removes_files_dirs_and_links_without_following() {
        let scratch = crate::create_scratch_path("sync", "remove-entry");
        let root = scratch.join("root");
        let outside = scratch.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(root.join("file"), b"x").unwrap();
        std::fs::create_dir(root.join("dir")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let session = test_session(&root, RootStatus::ExistingDirectory);
        for name in ["file", "dir", "link"] {
            assert_eq!(session.remove_entry(name).unwrap(), SyncReply::Success);
            assert!(std::fs::symlink_metadata(root.join(name)).is_err());
        }
        assert!(outside.is_dir());
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn scans_preserve_metadata_for_directories_files_and_symlinks() {
        let scratch = crate::create_scratch_path("sync", "scan-metadata");
        std::fs::create_dir_all(&scratch).unwrap();
        let file = scratch.join("file");
        std::fs::write(&file, b"contents").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::set_times(&file, terra_protocol::sync_file_times(1000, 0).unwrap()).unwrap();
        let link = scratch.join("link");
        std::os::unix::fs::symlink("file", &link).unwrap();

        for (path, root_status, kind) in [
            (
                &scratch,
                RootStatus::ExistingDirectory,
                SyncEntryKind::Directory,
            ),
            (
                &file,
                RootStatus::ExistingFile,
                SyncEntryKind::File { size: 8 },
            ),
            (
                &link,
                RootStatus::ExistingSymlink,
                SyncEntryKind::Symlink {
                    target: "file".into(),
                },
            ),
        ] {
            let mut conn = TestConn::new(Vec::new());
            assert_eq!(
                test_session(path, root_status).scan(&mut conn).unwrap(),
                SyncReply::ScanComplete
            );
            let metadata = std::fs::symlink_metadata(path).unwrap();
            let mut replies = conn.replies().into_iter();
            assert_eq!(
                replies.next(),
                Some(SyncReply::Entry(SyncEntry {
                    relative_path: String::new(),
                    kind: kind.clone(),
                    mode: metadata.mode() & 0o777,
                    mtime_secs: metadata.mtime(),
                    mtime_nanos: truncate_nanos(u32::try_from(metadata.mtime_nsec()).unwrap()),
                }))
            );
            let mut children: Vec<_> = replies
                .map_while(|reply| match reply {
                    SyncReply::Entry(entry) => Some(entry),
                    _ => None,
                })
                .collect();
            if kind == SyncEntryKind::Directory {
                children.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
                assert_eq!(children.len(), 2);
                assert_eq!(
                    (
                        children[0].relative_path.as_str(),
                        &children[0].kind,
                        children[0].mode,
                        children[0].mtime_secs
                    ),
                    ("file", &SyncEntryKind::File { size: 8 }, 0o640, 1000)
                );
                assert_eq!(
                    (children[1].relative_path.as_str(), &children[1].kind),
                    (
                        "link",
                        &SyncEntryKind::Symlink {
                            target: "file".into()
                        }
                    )
                );
            } else {
                assert_eq!(children, [] as [terra_protocol::SyncEntry; 0]);
            }
        }
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn sync_session_basic_round_trip() {
        let scratch = crate::create_scratch_path("sync", "session-roundtrip");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let mut input = begin_session(&scratch);
        input.extend(frame(&SyncRequest::WriteFile {
            relative_path: "hello.txt".to_string(),
            size: 5,
            mode: 0o644,
            mtime_secs: 1000,
            mtime_nanos: 0,
        }));
        input.extend_from_slice(b"world");
        input.extend(frame(&SyncRequest::CommitFile));
        input.extend(frame(&SyncRequest::EndSession));
        let mut conn = TestConn::new(input);
        serve_sync_session(&mut conn, GuestUser::Root, &CancellationToken::new()).unwrap();
        assert_eq!(
            conn.replies(),
            [
                SyncReply::SessionReady {
                    root_status: RootStatus::ExistingDirectory
                },
                SyncReply::WriteFileReady,
                SyncReply::Success,
                SyncReply::Success,
            ]
        );
        assert_eq!(std::fs::read(scratch.join("hello.txt")).unwrap(), b"world");
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn sync_hashing_reports_digest() {
        let scratch = crate::create_scratch_path("sync", "hash-test");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        std::fs::write(scratch.join("data.bin"), b"hello world").unwrap();
        let mut input = begin_session(&scratch);
        input.extend(frame(&SyncRequest::ComputeDigest {
            relative_path: "data.bin".to_string(),
        }));
        input.extend(frame(&SyncRequest::EndSession));
        let mut conn = TestConn::new(input);
        serve_sync_session(&mut conn, GuestUser::Root, &CancellationToken::new()).unwrap();
        let replies = conn.replies();
        let [
            SyncReply::SessionReady {
                root_status: RootStatus::ExistingDirectory,
            },
            progress @ ..,
            SyncReply::Digest { sha256 },
            SyncReply::Success,
        ] = replies.as_slice()
        else {
            panic!("unexpected replies: {replies:?}");
        };
        assert!(
            progress
                .iter()
                .all(|reply| matches!(reply, SyncReply::DigestProgress { .. }))
        );
        assert_eq!(*sha256, <[u8; 32]>::from(Sha256::digest(b"hello world")));
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
