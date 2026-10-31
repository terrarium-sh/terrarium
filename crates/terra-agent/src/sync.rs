//! The agent's filesystem synchronization service (`AgentService::Sync`).

use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;
use terra_protocol::{
    MAX_FILE_BYTES, MAX_SYNC_ENTRIES, MAX_SYNC_METADATA_BYTES, RootStatus, SyncEntry,
    SyncEntryKind, SyncManifestBudget, SyncManifestLimit, SyncReply, SyncRequest, encode_frame,
    read_frame, truncate_nanos, validate_relative_path,
};
use tokio_util::sync::CancellationToken;

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
    path: &Path,
    symlink_flags: rustix::fs::OFlags,
) -> std::io::Result<std::fs::File> {
    Ok(rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | symlink_flags
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?
    .into())
}

struct PreparedPut {
    file: std::fs::File,
    parent: std::fs::File,
    temp_name: std::ffi::OsString,
    destination_name: std::ffi::OsString,
    is_committed: bool,
}

impl Drop for PreparedPut {
    fn drop(&mut self) {
        if !self.is_committed {
            let _ =
                rustix::fs::unlinkat(&self.parent, &self.temp_name, rustix::fs::AtFlags::empty());
        }
    }
}

fn generate_random_temp_name() -> std::io::Result<std::ffi::OsString> {
    let mut random = [0u8; 16];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())?;
    Ok(std::ffi::OsString::from(format!(
        ".terra-put-{:032x}",
        u128::from_le_bytes(random)
    )))
}

fn create_put_temp(path: &Path) -> std::io::Result<PreparedPut> {
    use rustix::fs::{Mode, OFlags};
    let parent_path = path
        .parent()
        .ok_or_else(|| std::io::Error::other("destination has no parent directory"))?;
    let destination = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("destination has no file name"))?
        .to_owned();
    let parent = open_directory(parent_path, rustix::fs::OFlags::NOFOLLOW)?;
    let temp = generate_random_temp_name()?;
    let file = rustix::fs::openat(
        &parent,
        &temp,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    Ok(PreparedPut {
        file: file.into(),
        parent,
        temp_name: temp,
        destination_name: destination,
        is_committed: false,
    })
}

/// Who owns a directory or file the agent creates; the agent itself runs as root.
#[derive(Clone, Copy)]
pub(crate) enum Owner {
    Root,
    Workload,
}

impl Owner {
    pub(crate) const fn for_workload(workload_is_root: bool) -> Self {
        if workload_is_root {
            Self::Root
        } else {
            Self::Workload
        }
    }

    fn assign_to(self, created: impl std::os::fd::AsFd) -> std::io::Result<()> {
        match self {
            Self::Root => Ok(()),
            Self::Workload => {
                let (uid, gid) = crate::workload::workload_owner();
                Ok(rustix::fs::fchown(created, uid, gid)?)
            }
        }
    }
}

pub(crate) fn ensure_directory(path: &Path, owner: Owner) -> std::io::Result<()> {
    open_or_create_directory(path, owner, rustix::fs::OFlags::empty()).map(drop)
}

fn open_or_create_directory(
    path: &Path,
    owner: Owner,
    symlink_flags: rustix::fs::OFlags,
) -> std::io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};
    match open_directory(path, symlink_flags) {
        Ok(directory) => return Ok(directory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut missing = Vec::new();
    let mut parent = 'ancestors: {
        for ancestor in path.ancestors() {
            match open_directory(ancestor, symlink_flags) {
                Ok(handle) => break 'ancestors handle,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(ancestor.to_owned());
                }
                Err(error) => return Err(error),
            }
        }
        return Err(std::io::Error::other("no existing parent directory"));
    };
    for dir in missing.into_iter().rev() {
        let name = dir
            .file_name()
            .ok_or_else(|| std::io::Error::other("missing parent has no name"))?;
        rustix::fs::mkdirat(&parent, name, Mode::from_raw_mode(0o755))
            .or_else(|error| (error == rustix::io::Errno::EXIST).ok_or(error))?;
        parent = rustix::fs::openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .into();
        owner.assign_to(&parent)?;
    }
    Ok(parent)
}

fn open_sync_file(path: &Path) -> std::io::Result<(std::fs::File, std::fs::Metadata)> {
    let file: std::fs::File = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?
    .into();
    let meta = file.metadata()?;
    if meta.is_dir() {
        return Err(std::io::Error::other("is a directory"));
    }
    if !meta.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(std::io::Error::other(format!(
            "file is larger than the {MAX_FILE_BYTES}-byte limit"
        )));
    }
    Ok((file, meta))
}

fn send_reply(conn: &mut impl Write, reply: &SyncReply) -> std::io::Result<()> {
    let frame = encode_frame(reply)?;
    conn.write_all(&frame)
}

fn reply_on_error<T>(
    conn: &mut impl Write,
    result: std::io::Result<T>,
) -> std::io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            send_reply(conn, &SyncReply::Err(error.to_string()))?;
            Ok(None)
        }
    }
}

fn send_outcome(conn: &mut impl Write, outcome: std::io::Result<()>) -> std::io::Result<()> {
    let reply = match outcome {
        Ok(()) => SyncReply::Success,
        Err(error) => SyncReply::Err(error.to_string()),
    };
    send_reply(conn, &reply)
}

fn resolve_target_path(session_root: &Path, relative_path: &str) -> std::io::Result<PathBuf> {
    validate_relative_path(relative_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let mut path = session_root.to_path_buf();
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

fn resolve_target_path_creating_parent(
    session_root: &Path,
    relative_path: &str,
) -> std::io::Result<PathBuf> {
    let path = resolve_target_path(session_root, relative_path)?;
    if let Some(parent) = path.parent() {
        ensure_directory(parent, Owner::Root)?;
    }
    Ok(path)
}

fn is_unchanged_since(file: &std::fs::File, before: &std::fs::Metadata) -> bool {
    file.metadata().is_ok_and(|after| {
        before.len() == after.len() && before.modified().ok() == after.modified().ok()
    })
}

/// The outer error aborts the session; the inner error is reported to the peer.
fn hash_file(
    path: &Path,
    cancellation: &CancellationToken,
    mut report_progress: impl FnMut(u64) -> std::io::Result<()>,
) -> std::io::Result<std::io::Result<[u8; 32]>> {
    let (mut file, before) = match open_sync_file(path) {
        Ok(file) => file,
        Err(error) => return Ok(Err(error)),
    };
    let deadline = std::time::Instant::now() + Duration::from_hours(1);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    let mut total_hashed = 0u64;
    let mut last_report = std::time::Instant::now();
    loop {
        if let Err(error) = ensure_not_cancelled(cancellation) {
            return Ok(Err(error));
        }
        if std::time::Instant::now() >= deadline || total_hashed > MAX_FILE_BYTES {
            return Ok(Err(std::io::Error::other("hashing exceeded its limit")));
        }
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buffer[..n]);
                total_hashed += n as u64;
                if last_report.elapsed() >= Duration::from_millis(1500) {
                    report_progress(total_hashed)?;
                    last_report = std::time::Instant::now();
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Ok(Err(error)),
        }
    }
    if !is_unchanged_since(&file, &before) {
        return Ok(Err(std::io::Error::other("source changed while hashing")));
    }
    Ok(Ok(hasher.finalize().into()))
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

fn build_sync_entry(
    relative_path: String,
    kind: SyncEntryKind,
    metadata: &std::fs::Metadata,
    link_target: Option<String>,
) -> SyncEntry {
    SyncEntry {
        relative_path,
        kind,
        size: match kind {
            SyncEntryKind::File => metadata.len(),
            SyncEntryKind::Directory | SyncEntryKind::Symlink => 0,
        },
        mode: metadata.mode() & 0o777,
        mtime_secs: metadata.mtime(),
        mtime_nanos: truncated_mtime_nanos(metadata),
        link_target,
    }
}

fn build_child_entry(
    session_root: &Path,
    parent_rel: &Path,
    name: &std::ffi::OsStr,
    budget: &mut SyncManifestBudget,
    pending_directories: &mut VecDeque<PathBuf>,
) -> Result<SyncEntry, String> {
    let name = name
        .to_str()
        .ok_or_else(|| "non-utf8 filename encountered".to_owned())?;
    let child_rel = parent_rel.join(name);
    let rel_str = child_rel.to_string_lossy().into_owned();
    if rel_str.len() > terra_protocol::MAX_SYNC_PATH_BYTES {
        return Err(format!("relative path exceeds maximum length: {rel_str}"));
    }
    let full = session_root.join(&child_rel);
    let meta = std::fs::symlink_metadata(&full).map_err(|e| e.to_string())?;
    let mut link_target = None;
    let kind = if meta.is_dir() {
        pending_directories.push_back(child_rel);
        SyncEntryKind::Directory
    } else if meta.file_type().is_symlink() {
        link_target = Some(read_link_target(&full).map_err(|e| e.to_string())?);
        SyncEntryKind::Symlink
    } else if meta.is_file() {
        SyncEntryKind::File
    } else {
        return Err(format!("unsupported special file: {rel_str}"));
    };
    budget
        .add_entry(&rel_str, link_target.as_deref())
        .map_err(|limit| match limit {
            SyncManifestLimit::Entries => {
                format!("manifest exceeds maximum entries limit: {MAX_SYNC_ENTRIES}")
            }
            SyncManifestLimit::MetadataBytes => {
                format!("manifest metadata exceeds maximum bytes limit: {MAX_SYNC_METADATA_BYTES}")
            }
        })?;
    Ok(build_sync_entry(rel_str, kind, &meta, link_target))
}

fn scan_directory_tree(
    session_root: &Path,
    conn: &mut impl Write,
    cancellation: &CancellationToken,
) -> std::io::Result<()> {
    let mut budget = SyncManifestBudget::default();
    let mut pending_directories = VecDeque::from([PathBuf::new()]);
    while let Some(rel) = pending_directories.pop_front() {
        ensure_not_cancelled(cancellation)?;
        let full = if rel.as_os_str().is_empty() {
            session_root.to_path_buf()
        } else {
            session_root.join(&rel)
        };
        let read_dir = match std::fs::read_dir(&full) {
            Ok(read_dir) => read_dir,
            Err(e) => {
                return send_reply(
                    conn,
                    &SyncReply::Err(format!("reading directory {}: {e}", full.display())),
                );
            }
        };
        for dir_entry in read_dir {
            ensure_not_cancelled(cancellation)?;
            let child = dir_entry.map_err(|e| e.to_string()).and_then(|dir_entry| {
                build_child_entry(
                    session_root,
                    &rel,
                    &dir_entry.file_name(),
                    &mut budget,
                    &mut pending_directories,
                )
            });
            match child {
                Ok(child) => send_reply(conn, &SyncReply::Entry(child))?,
                Err(message) => return send_reply(conn, &SyncReply::Err(message)),
            }
        }
    }
    send_reply(conn, &SyncReply::ScanComplete)
}

fn handle_scan_entries(
    root_path: &Path,
    root_status: RootStatus,
    conn: &mut (impl Read + Write),
    cancellation: &CancellationToken,
) -> std::io::Result<()> {
    ensure_not_cancelled(cancellation)?;
    let kind = match root_status {
        RootStatus::ExistingDirectory => SyncEntryKind::Directory,
        RootStatus::ExistingFile => SyncEntryKind::File,
        RootStatus::ExistingSymlink => SyncEntryKind::Symlink,
        RootStatus::Missing => return send_reply(conn, &SyncReply::ScanComplete),
    };
    let metadata = std::fs::symlink_metadata(root_path)?;
    let link_target = match kind {
        SyncEntryKind::Symlink => Some(read_link_target(root_path)?),
        SyncEntryKind::Directory | SyncEntryKind::File => None,
    };
    send_reply(
        conn,
        &SyncReply::Entry(build_sync_entry(
            String::new(),
            kind,
            &metadata,
            link_target,
        )),
    )?;
    match kind {
        SyncEntryKind::Directory => scan_directory_tree(root_path, conn, cancellation),
        SyncEntryKind::File | SyncEntryKind::Symlink => send_reply(conn, &SyncReply::ScanComplete),
    }
}

fn handle_compute_digest(
    root_path: &Path,
    relative_path: &str,
    conn: &mut (impl Read + Write),
    cancellation: &CancellationToken,
) -> std::io::Result<()> {
    let Some(target) = reply_on_error(conn, resolve_target_path(root_path, relative_path))? else {
        return Ok(());
    };
    match hash_file(&target, cancellation, |bytes_hashed| {
        send_reply(conn, &SyncReply::DigestProgress { bytes_hashed })
    })? {
        Ok(sha256) => send_reply(conn, &SyncReply::Digest { sha256 }),
        Err(error) => send_reply(conn, &SyncReply::Err(error.to_string())),
    }
}

#[derive(Clone, Copy)]
struct WriteFileMeta {
    size: u64,
    mode: u32,
    mtime_secs: i64,
    mtime_nanos: u32,
}

fn handle_write_file(
    root_path: &Path,
    relative_path: &str,
    meta: WriteFileMeta,
    owner: Owner,
    conn: &mut (impl Read + Write),
    cancellation: &CancellationToken,
) -> std::io::Result<()> {
    let prepared = resolve_target_path_creating_parent(root_path, relative_path)
        .and_then(|target| create_put_temp(&target));
    let Some(mut upload) = reply_on_error(conn, prepared)? else {
        return Ok(());
    };
    send_reply(conn, &SyncReply::WriteFileReady)?;

    let result = (|| -> std::io::Result<()> {
        let file = &mut upload.file;
        stream_exact(&mut *conn, &mut *file, meta.size, cancellation)?;
        ensure_not_cancelled(cancellation)?;
        if !matches!(
            read_frame::<SyncRequest>(&mut *conn)?,
            Some(SyncRequest::CommitFile)
        ) {
            return Err(std::io::Error::other("upload was not committed by sender"));
        }
        ensure_not_cancelled(cancellation)?;
        file.set_len(meta.size)?;
        owner.assign_to(&*file)?;
        file.set_permissions(std::fs::Permissions::from_mode(meta.mode & 0o777))?;
        file.set_times(terra_protocol::sync_file_times(
            meta.mtime_secs,
            meta.mtime_nanos,
        )?)?;
        file.sync_all()?;
        ensure_not_cancelled(cancellation)?;
        rustix::fs::renameat(
            &upload.parent,
            &upload.temp_name,
            &upload.parent,
            &upload.destination_name,
        )?;
        upload.is_committed = true;
        Ok(())
    })();
    send_outcome(conn, result)
}

fn handle_read_file(
    root_path: &Path,
    relative_path: &str,
    conn: &mut (impl Read + Write),
    cancellation: &CancellationToken,
) -> std::io::Result<()> {
    let opened =
        resolve_target_path(root_path, relative_path).and_then(|target| open_sync_file(&target));
    let Some((mut file, before)) = reply_on_error(conn, opened)? else {
        return Ok(());
    };
    send_reply(
        conn,
        &SyncReply::ReadFileReady {
            size: before.len(),
            mode: before.mode() & 0o7777,
            mtime_secs: before.mtime(),
            mtime_nanos: truncated_mtime_nanos(&before),
        },
    )?;
    stream_exact(&mut file, &mut *conn, before.len(), cancellation)?;
    let outcome = if is_unchanged_since(&file, &before) {
        Ok(())
    } else {
        Err(std::io::Error::other("source changed while transferring"))
    };
    send_outcome(conn, outcome)
}

fn create_directory(
    root_path: &Path,
    relative_path: &str,
    mode: u32,
    owner: Owner,
) -> std::io::Result<()> {
    let dir_path = resolve_target_path_creating_parent(root_path, relative_path)?;
    let directory = open_or_create_directory(&dir_path, owner, rustix::fs::OFlags::NOFOLLOW)?;
    directory.set_permissions(std::fs::Permissions::from_mode((mode & 0o777) | 0o700))
}

fn create_symlink(root_path: &Path, relative_path: &str, target: &str) -> std::io::Result<()> {
    let link_path = resolve_target_path_creating_parent(root_path, relative_path)?;
    let temp = link_path.with_file_name(generate_random_temp_name()?);
    let result =
        std::os::unix::fs::symlink(target, &temp).and_then(|()| std::fs::rename(&temp, &link_path));
    let _ = std::fs::remove_file(&temp);
    result
}

fn update_metadata(
    root_path: &Path,
    relative_path: &str,
    mode: u32,
    mtime_secs: i64,
    mtime_nanos: u32,
) -> std::io::Result<()> {
    let target = resolve_target_path(root_path, relative_path)?;
    let meta = std::fs::symlink_metadata(&target)?;
    if meta.file_type().is_symlink() {
        return Err(std::io::Error::other("cannot update symlink metadata"));
    }
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode & 0o777))?;
    std::fs::set_times(
        &target,
        terra_protocol::sync_file_times(mtime_secs, mtime_nanos)?,
    )
}

fn remove_entry(root_path: &Path, relative_path: &str, is_dir: bool) -> std::io::Result<()> {
    if relative_path.is_empty() {
        return Err(std::io::Error::other("cannot remove session root itself"));
    }
    let target = resolve_target_path(root_path, relative_path)?;
    if is_dir {
        std::fs::remove_dir(&target)
    } else {
        std::fs::remove_file(&target)
    }
}

pub fn serve_sync_session(
    mut conn: impl Read + Write,
    workload_is_root: bool,
    cancellation: &CancellationToken,
) {
    let _ = handle_sync_session(&mut conn, workload_is_root, cancellation);
}

fn inspect_root_status(path: &Path) -> std::io::Result<RootStatus> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => Ok(RootStatus::ExistingDirectory),
        Ok(m) if m.file_type().is_symlink() => Ok(RootStatus::ExistingSymlink),
        Ok(m) if m.is_file() => Ok(RootStatus::ExistingFile),
        Ok(_) => Err(std::io::Error::other(format!(
            "root {} is an unsupported file type",
            path.display()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RootStatus::Missing),
        Err(e) => Err(std::io::Error::new(
            e.kind(),
            format!("inspecting root {}: {e}", path.display()),
        )),
    }
}

fn handle_sync_session(
    conn: &mut (impl Read + Write),
    workload_is_root: bool,
    cancellation: &CancellationToken,
) -> std::io::Result<()> {
    ensure_not_cancelled(cancellation)?;
    let owner = Owner::for_workload(workload_is_root);
    let mut session: Option<(PathBuf, RootStatus)> = None;

    while let Some(req) = read_frame::<SyncRequest>(&mut *conn)? {
        ensure_not_cancelled(cancellation)?;
        if let SyncRequest::BeginSession { guest_root } = &req {
            let root_path = PathBuf::from(guest_root);
            let Some(root_status) = reply_on_error(conn, inspect_root_status(&root_path))? else {
                return Ok(());
            };
            send_reply(conn, &SyncReply::SessionReady { root_status })?;
            session = Some((root_path, root_status));
            continue;
        }
        let Some((root_path, root_status)) = &session else {
            return Ok(());
        };
        let (root_path, root_status) = (root_path.as_path(), *root_status);
        match req {
            SyncRequest::BeginSession { .. } => unreachable!("handled before the session lookup"),
            SyncRequest::CommitFile => return Err(std::io::Error::other("unexpected file commit")),
            SyncRequest::ScanEntries => {
                handle_scan_entries(root_path, root_status, conn, cancellation)?;
            }
            SyncRequest::ComputeDigest { relative_path } => {
                handle_compute_digest(root_path, &relative_path, conn, cancellation)?;
            }
            SyncRequest::WriteFile {
                relative_path,
                size,
                mode,
                mtime_secs,
                mtime_nanos,
            } => {
                handle_write_file(
                    root_path,
                    &relative_path,
                    WriteFileMeta {
                        size,
                        mode,
                        mtime_secs,
                        mtime_nanos,
                    },
                    owner,
                    conn,
                    cancellation,
                )?;
            }
            SyncRequest::ReadFile { relative_path } => {
                handle_read_file(root_path, &relative_path, conn, cancellation)?;
            }
            SyncRequest::CreateDir {
                relative_path,
                mode,
            } => send_outcome(
                conn,
                create_directory(root_path, &relative_path, mode, owner),
            )?,
            SyncRequest::CreateSymlink {
                relative_path,
                target,
            } => send_outcome(conn, create_symlink(root_path, &relative_path, &target))?,
            SyncRequest::UpdateMetadata {
                relative_path,
                mode,
                mtime_secs,
                mtime_nanos,
            } => send_outcome(
                conn,
                update_metadata(root_path, &relative_path, mode, mtime_secs, mtime_nanos),
            )?,
            SyncRequest::RemoveEntry {
                relative_path,
                is_dir,
            } => send_outcome(conn, remove_entry(root_path, &relative_path, is_dir))?,
            SyncRequest::EndSession => return send_reply(conn, &SyncReply::Success),
        }
    }
    Ok(())
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
        assert_eq!(
            inspect_root_status(&alias).unwrap(),
            RootStatus::ExistingSymlink
        );
        let root = alias.join("app");
        assert_eq!(
            inspect_root_status(&root).unwrap(),
            RootStatus::ExistingDirectory
        );
        let file = resolve_target_path(&root, "file").unwrap();
        std::fs::write(file, b"inside").unwrap();
        assert_eq!(std::fs::read(real.join("app/file")).unwrap(), b"inside");
        std::os::unix::fs::symlink(&real, root.join("link")).unwrap();
        assert!(resolve_target_path(&root, "link/file").is_err());
        assert!(resolve_target_path(&alias, "file").is_err());
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
        let mut conn = TestConn {
            input: std::io::Cursor::new(Vec::new()),
            output: Vec::new(),
        };
        handle_scan_entries(
            &root,
            RootStatus::ExistingDirectory,
            &mut conn,
            &CancellationToken::new(),
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, root.join("new")).unwrap();
        assert!(create_directory(&root, "new", 0o777, Owner::Root).is_err());
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
            open_or_create_directory(&directory, Owner::Root, rustix::fs::OFlags::NOFOLLOW)
                .unwrap();
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
            let mut input = encode_frame(&SyncRequest::BeginSession {
                guest_root: scratch.to_str().unwrap().into(),
            })
            .unwrap();
            input.extend(
                encode_frame(&SyncRequest::WriteFile {
                    relative_path: "file".into(),
                    size: 12,
                    mode: 0o644,
                    mtime_secs: 100,
                    mtime_nanos: 0,
                })
                .unwrap(),
            );
            input.extend(body);
            let mut conn = TestConn {
                input: std::io::Cursor::new(input),
                output: Vec::new(),
            };
            serve_sync_session(&mut conn, true, &CancellationToken::new());
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
        let error = handle_write_file(
            &scratch,
            "file",
            WriteFileMeta {
                size: 3,
                mode: 0o644,
                mtime_secs: 100,
                mtime_nanos: 0,
            },
            Owner::Root,
            &mut closed,
            &CancellationToken::new(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WriteZero);
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
                is_dir: true,
            },
            SyncRequest::EndSession,
        ];
        let mut conn = TestConn {
            input: std::io::Cursor::new(
                requests
                    .iter()
                    .flat_map(|request| encode_frame(request).unwrap())
                    .collect(),
            ),
            output: Vec::new(),
        };
        serve_sync_session(&mut conn, true, &CancellationToken::new());
        let mut replies = conn.output.as_slice();
        assert_eq!(
            read_frame::<SyncReply>(&mut replies).unwrap(),
            Some(SyncReply::SessionReady {
                root_status: RootStatus::ExistingDirectory
            })
        );
        for _ in 0..4 {
            assert_matches!(
                read_frame::<SyncReply>(&mut replies).unwrap(),
                Some(SyncReply::Err(_))
            );
        }
        assert_eq!(
            read_frame::<SyncReply>(&mut replies).unwrap(),
            Some(SyncReply::Success)
        );
        assert_eq!(replies, []);
        assert_eq!(std::fs::read(scratch.join("file")).unwrap(), b"old");
        std::fs::remove_dir_all(scratch).unwrap();
    }

    struct TestConn {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for TestConn {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let read = self.input.read(buf)?;
            if read == 0 {
                Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            } else {
                Ok(read)
            }
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

    struct CancellingConn {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
        cancellation: CancellationToken,
        cancel_at: u64,
    }

    impl Read for CancellingConn {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let remaining = self.cancel_at.saturating_sub(self.input.position());
            let count = usize::min(buf.len(), usize::try_from(remaining).unwrap());
            let n = self.input.read(&mut buf[..count])?;
            if self.input.position() >= self.cancel_at {
                self.cancellation.cancel();
            }
            Ok(n)
        }
    }

    impl Write for CancellingConn {
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
        let begin = encode_frame(&SyncRequest::BeginSession {
            guest_root: scratch.to_str().unwrap().into(),
        })
        .unwrap();
        let write = encode_frame(&SyncRequest::WriteFile {
            relative_path: "file".into(),
            size: 12,
            mode: 0o644,
            mtime_secs: 100,
            mtime_nanos: 0,
        })
        .unwrap();
        let cancellation = CancellationToken::new();
        let mut input = begin.clone();
        input.extend(&write);
        input.extend(b"new contents");
        let mut conn = CancellingConn {
            input: std::io::Cursor::new(input),
            output: Vec::new(),
            cancellation: cancellation.clone(),
            cancel_at: u64::try_from(begin.len() + write.len() + 1).unwrap(),
        };

        serve_sync_session(&mut conn, true, &cancellation);

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
        let mut conn = TestConn {
            input: std::io::Cursor::new(Vec::new()),
            output: Vec::new(),
        };
        handle_scan_entries(
            &scratch,
            RootStatus::ExistingDirectory,
            &mut conn,
            &CancellationToken::new(),
        )
        .unwrap();
        let mut replies = conn.output.as_slice();
        assert_matches!(
            read_frame::<SyncReply>(&mut replies).unwrap(),
            Some(SyncReply::Entry(_))
        );
        assert_eq!(
            read_frame::<SyncReply>(&mut replies).unwrap(),
            Some(SyncReply::Err("non-UTF-8 symlink target".into()))
        );
        assert_eq!(replies, []);
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn update_metadata_sets_mtime_on_directories_and_keeps_atime() {
        let scratch = crate::create_scratch_path("sync", "update-metadata-times");
        let directory = scratch.join("directory");
        std::fs::create_dir_all(&directory).unwrap();
        let accessed_before = std::fs::metadata(&directory).unwrap().accessed().unwrap();
        update_metadata(&scratch, "directory", 0o755, 1000, 500).unwrap();
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
    fn scans_preserve_metadata_for_directories_files_and_symlinks() {
        let scratch = crate::create_scratch_path("sync", "scan-metadata");
        std::fs::create_dir_all(&scratch).unwrap();
        let file = scratch.join("file");
        std::fs::write(&file, b"contents").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::set_times(&file, terra_protocol::sync_file_times(1000, 0).unwrap()).unwrap();
        let link = scratch.join("link");
        std::os::unix::fs::symlink("file", &link).unwrap();

        for (path, status, kind, size, target) in [
            (
                &scratch,
                RootStatus::ExistingDirectory,
                SyncEntryKind::Directory,
                0,
                None,
            ),
            (
                &file,
                RootStatus::ExistingFile,
                SyncEntryKind::File,
                8,
                None,
            ),
            (
                &link,
                RootStatus::ExistingSymlink,
                SyncEntryKind::Symlink,
                0,
                Some("file"),
            ),
        ] {
            let mut conn = TestConn {
                input: std::io::Cursor::new(Vec::new()),
                output: Vec::new(),
            };
            handle_scan_entries(path, status, &mut conn, &CancellationToken::new()).unwrap();
            let metadata = std::fs::symlink_metadata(path).unwrap();
            let mut replies = conn.output.as_slice();
            assert_eq!(
                read_frame::<SyncReply>(&mut replies).unwrap(),
                Some(SyncReply::Entry(SyncEntry {
                    relative_path: String::new(),
                    kind,
                    size,
                    mode: metadata.mode() & 0o777,
                    mtime_secs: metadata.mtime(),
                    mtime_nanos: truncate_nanos(u32::try_from(metadata.mtime_nsec()).unwrap()),
                    link_target: target.map(str::to_owned),
                }))
            );
            let mut children = Vec::new();
            while let Some(SyncReply::Entry(entry)) = read_frame(&mut replies).unwrap() {
                children.push(entry);
            }
            if kind == SyncEntryKind::Directory {
                children.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
                assert_eq!(children.len(), 2);
                assert_eq!(
                    (
                        children[0].relative_path.as_str(),
                        children[0].kind,
                        children[0].size,
                        children[0].mode,
                        children[0].mtime_secs
                    ),
                    ("file", SyncEntryKind::File, 8, 0o640, 1000)
                );
                assert_eq!(
                    (
                        children[1].relative_path.as_str(),
                        children[1].kind,
                        children[1].size,
                        children[1].link_target.as_deref()
                    ),
                    ("link", SyncEntryKind::Symlink, 0, Some("file"))
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

        let mut input = Vec::new();
        let begin = SyncRequest::BeginSession {
            guest_root: scratch.to_str().unwrap().to_string(),
        };
        input.extend(encode_frame(&begin).unwrap());

        let write = SyncRequest::WriteFile {
            relative_path: "hello.txt".to_string(),
            size: 5,
            mode: 0o644,
            mtime_secs: 1000,
            mtime_nanos: 0,
        };
        input.extend(encode_frame(&write).unwrap());
        input.extend_from_slice(b"world");
        input.extend(encode_frame(&SyncRequest::CommitFile).unwrap());

        let end = SyncRequest::EndSession;
        input.extend(encode_frame(&end).unwrap());

        let mut conn = TestConn {
            input: std::io::Cursor::new(input),
            output: Vec::new(),
        };
        serve_sync_session(&mut conn, true, &CancellationToken::new());

        let mut out_cursor = std::io::Cursor::new(conn.output);
        let rep1: SyncReply = read_frame(&mut out_cursor).unwrap().unwrap();
        assert_eq!(
            rep1,
            SyncReply::SessionReady {
                root_status: RootStatus::ExistingDirectory
            }
        );
        let rep2: SyncReply = read_frame(&mut out_cursor).unwrap().unwrap();
        assert_eq!(rep2, SyncReply::WriteFileReady);

        let rep3: SyncReply = read_frame(&mut out_cursor).unwrap().unwrap();
        assert_eq!(rep3, SyncReply::Success);

        let rep4: SyncReply = read_frame(&mut out_cursor).unwrap().unwrap();
        assert_eq!(rep4, SyncReply::Success);

        assert_eq!(std::fs::read(scratch.join("hello.txt")).unwrap(), b"world");
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn sync_hashing_reports_digest() {
        let scratch = crate::create_scratch_path("sync", "hash-test");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let file_path = scratch.join("data.bin");
        std::fs::write(&file_path, b"hello world").unwrap();

        let mut input = Vec::new();
        let begin = SyncRequest::BeginSession {
            guest_root: scratch.to_str().unwrap().to_string(),
        };
        input.extend(encode_frame(&begin).unwrap());
        let digest_req = SyncRequest::ComputeDigest {
            relative_path: "data.bin".to_string(),
        };
        input.extend(encode_frame(&digest_req).unwrap());
        input.extend(encode_frame(&SyncRequest::EndSession).unwrap());

        let mut conn = TestConn {
            input: std::io::Cursor::new(input),
            output: Vec::new(),
        };
        serve_sync_session(&mut conn, true, &CancellationToken::new());

        let mut out_cursor = std::io::Cursor::new(conn.output);
        let rep1: SyncReply = read_frame(&mut out_cursor).unwrap().unwrap();
        assert_eq!(
            rep1,
            SyncReply::SessionReady {
                root_status: RootStatus::ExistingDirectory
            }
        );

        let mut digest = None;
        while let Ok(Some(rep)) = read_frame::<SyncReply>(&mut out_cursor) {
            match rep {
                SyncReply::DigestProgress { .. } => {}
                SyncReply::Digest { sha256 } => {
                    digest = Some(sha256);
                    break;
                }
                other => panic!("unexpected reply: {other:?}"),
            }
        }
        let expected = Sha256::digest(b"hello world");
        assert_eq!(digest, Some(expected.into()));

        let _ = std::fs::remove_dir_all(&scratch);
    }
}
