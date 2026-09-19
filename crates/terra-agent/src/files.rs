//! The agent's file port: one sync session per connection (`AgentService::Files`).

use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;
use terra_protocol::{
    MAX_FILE_BYTES, MAX_SYNC_ENTRIES, MAX_SYNC_METADATA_BYTES, RootStatus, SyncEntry,
    SyncEntryKind, SyncReply, SyncRequest, WORKLOAD_ID, encode_frame, read_frame, truncate_nanos,
    validate_relative_path,
};

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
    })
}

fn prepare_put(path: &Path) -> std::io::Result<PreparedPut> {
    match create_put_temp(path) {
        Ok(prepared) => Ok(prepared),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().unwrap_or(path);
            ensure_directory(parent, false)?;
            create_put_temp(path)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn ensure_directory(path: &Path, give_to_workload: bool) -> std::io::Result<()> {
    open_or_create_directory(path, give_to_workload, rustix::fs::OFlags::empty()).map(drop)
}

fn open_or_create_directory(
    path: &Path,
    give_to_workload: bool,
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
        rustix::fs::mkdirat(&parent, name, Mode::from_raw_mode(0o755)).or_else(|error| {
            (error == rustix::io::Errno::EXIST)
                .then_some(())
                .ok_or(error)
        })?;
        parent = rustix::fs::openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .into();
        if give_to_workload {
            rustix::fs::fchown(
                &parent,
                Some(rustix::process::Uid::from_raw(WORKLOAD_ID)),
                Some(rustix::process::Gid::from_raw(WORKLOAD_ID)),
            )?;
        }
    }
    Ok(parent)
}

fn inspect_file(path: &Path) -> std::io::Result<(std::fs::File, u32, u64, i64, u32)> {
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
    let mtime_secs = meta.mtime();
    let mtime_nanos = truncate_nanos(u32::try_from(meta.mtime_nsec()).unwrap_or(0));
    Ok((
        file,
        meta.permissions().mode() & 0o7777,
        meta.len(),
        mtime_secs,
        mtime_nanos,
    ))
}

fn send_reply_checked(conn: &mut impl Write, reply: &SyncReply) -> std::io::Result<()> {
    let frame = encode_frame(reply)?;
    conn.write_all(&frame)
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

enum HashProgress {
    Progress(u64),
    Done(std::io::Result<[u8; 32]>),
}

fn hash_file_worker(path: &Path, tx: &std::sync::mpsc::Sender<HashProgress>) {
    let mut file = match inspect_file(path) {
        Ok((file, ..)) => file,
        Err(e) => {
            let _ = tx.send(HashProgress::Done(Err(e)));
            return;
        }
    };
    let before = match file.metadata() {
        Ok(meta) => meta,
        Err(error) => {
            let _ = tx.send(HashProgress::Done(Err(error)));
            return;
        }
    };
    let deadline = std::time::Instant::now() + Duration::from_hours(1);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    let mut total_hashed = 0u64;
    let mut last_report = std::time::Instant::now();
    loop {
        if std::time::Instant::now() >= deadline || total_hashed > MAX_FILE_BYTES {
            let _ = tx.send(HashProgress::Done(Err(std::io::Error::other(
                "hashing exceeded its limit",
            ))));
            return;
        }
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buffer[..n]);
                total_hashed += n as u64;
                if last_report.elapsed() >= Duration::from_millis(1500) {
                    if tx.send(HashProgress::Progress(total_hashed)).is_err() {
                        return;
                    }
                    last_report = std::time::Instant::now();
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                let _ = tx.send(HashProgress::Done(Err(e)));
                return;
            }
        }
    }
    if !file.metadata().is_ok_and(|after| {
        before.len() == after.len() && before.modified().ok() == after.modified().ok()
    }) {
        let _ = tx.send(HashProgress::Done(Err(std::io::Error::other(
            "source changed while hashing",
        ))));
        return;
    }
    let digest = hasher.finalize();
    let _ = tx.send(HashProgress::Done(Ok(digest.into())));
}

fn stream_exact(mut from: impl Read, mut to: impl Write, size: u64) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    let mut remaining = size;
    while remaining > 0 {
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
        to.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}

fn set_path_mtime(path: &Path, mtime_secs: i64, mtime_nanos: u32) -> std::io::Result<()> {
    #[allow(clippy::cast_possible_wrap)]
    let times = rustix::fs::Timestamps {
        last_access: rustix::fs::Timespec {
            tv_sec: 0,
            tv_nsec: rustix::fs::UTIME_OMIT,
        },
        last_modification: rustix::fs::Timespec {
            tv_sec: mtime_secs as _,
            tv_nsec: mtime_nanos.into(),
        },
    };
    rustix::fs::utimensat(rustix::fs::CWD, path, &times, rustix::fs::AtFlags::empty())
        .map_err(std::io::Error::from)
}

struct ScanState<'a, W: Write> {
    session_root: &'a Path,
    conn: &'a mut W,
    entries_count: usize,
    total_metadata_bytes: usize,
}

impl<W: Write> ScanState<'_, W> {
    fn emit_child_entry(
        &mut self,
        rel: &Path,
        name: &str,
        queue: &mut VecDeque<PathBuf>,
    ) -> std::io::Result<bool> {
        let child_rel = if rel.as_os_str().is_empty() {
            PathBuf::from(name)
        } else {
            rel.join(name)
        };
        let rel_str = child_rel.to_string_lossy().into_owned();
        if rel_str.len() > terra_protocol::MAX_SYNC_PATH_BYTES {
            send_reply_checked(
                self.conn,
                &SyncReply::Err(format!("relative path exceeds maximum length: {rel_str}")),
            )?;
            return Ok(false);
        }
        let full = self.session_root.join(&child_rel);
        let meta = match std::fs::symlink_metadata(&full) {
            Ok(m) => m,
            Err(e) => {
                send_reply_checked(self.conn, &SyncReply::Err(e.to_string()))?;
                return Ok(false);
            }
        };
        self.entries_count += 1;
        if self.entries_count > MAX_SYNC_ENTRIES {
            send_reply_checked(
                self.conn,
                &SyncReply::Err(format!(
                    "manifest exceeds maximum entries limit: {MAX_SYNC_ENTRIES}"
                )),
            )?;
            return Ok(false);
        }
        let mut link_target = None;
        let kind = if meta.is_dir() {
            queue.push_back(child_rel);
            SyncEntryKind::Directory
        } else if meta.file_type().is_symlink() {
            match std::fs::read_link(&full) {
                Ok(t) => {
                    let target_str = t
                        .to_str()
                        .ok_or_else(|| std::io::Error::other("non-UTF-8 symlink target"))?
                        .to_owned();
                    self.total_metadata_bytes += target_str.len();
                    link_target = Some(target_str);
                    SyncEntryKind::Symlink
                }
                Err(e) => {
                    send_reply_checked(self.conn, &SyncReply::Err(e.to_string()))?;
                    return Ok(false);
                }
            }
        } else if meta.is_file() {
            SyncEntryKind::File
        } else {
            send_reply_checked(
                self.conn,
                &SyncReply::Err(format!("unsupported special file: {rel_str}")),
            )?;
            return Ok(false);
        };
        self.total_metadata_bytes += rel_str.len() + 32;
        if self.total_metadata_bytes > MAX_SYNC_METADATA_BYTES {
            send_reply_checked(
                self.conn,
                &SyncReply::Err(format!(
                    "manifest metadata exceeds maximum bytes limit: {MAX_SYNC_METADATA_BYTES}"
                )),
            )?;
            return Ok(false);
        }
        let mtime_secs = meta.mtime();
        let mtime_nanos = truncate_nanos(u32::try_from(meta.mtime_nsec()).unwrap_or(0));
        let sync_entry = SyncEntry {
            relative_path: rel_str,
            kind,
            size: if kind == SyncEntryKind::File {
                meta.len()
            } else {
                0
            },
            mode: meta.mode() & 0o777,
            mtime_secs,
            mtime_nanos,
            link_target,
        };
        send_reply_checked(self.conn, &SyncReply::Entry(sync_entry))?;
        Ok(true)
    }
}

fn scan_directory_tree(session_root: &Path, conn: &mut impl Write) -> std::io::Result<()> {
    let mut state = ScanState {
        session_root,
        conn,
        entries_count: 0,
        total_metadata_bytes: 0,
    };
    let mut queue = VecDeque::new();
    queue.push_back(PathBuf::new());

    while let Some(rel) = queue.pop_front() {
        let full = if rel.as_os_str().is_empty() {
            session_root.to_path_buf()
        } else {
            session_root.join(&rel)
        };
        let read_dir = match std::fs::read_dir(&full) {
            Ok(rd) => rd,
            Err(e) => {
                send_reply_checked(
                    state.conn,
                    &SyncReply::Err(format!("reading directory {}: {e}", full.display())),
                )?;
                return Ok(());
            }
        };
        for entry_res in read_dir {
            let entry = match entry_res {
                Ok(e) => e,
                Err(e) => {
                    send_reply_checked(state.conn, &SyncReply::Err(e.to_string()))?;
                    return Ok(());
                }
            };
            let file_name = entry.file_name();
            let Some(name_str) = file_name.to_str() else {
                send_reply_checked(
                    state.conn,
                    &SyncReply::Err("non-utf8 filename encountered".to_string()),
                )?;
                return Ok(());
            };
            if name_str == "." || name_str == ".." {
                continue;
            }
            if !state.emit_child_entry(&rel, name_str, &mut queue)? {
                return Ok(());
            }
        }
    }
    send_reply_checked(state.conn, &SyncReply::ScanComplete)
}

fn handle_scan_entries(
    root_path: &Path,
    root_status: RootStatus,
    conn: &mut (impl Read + Write),
) -> std::io::Result<()> {
    match root_status {
        RootStatus::ExistingDirectory => {
            let meta = std::fs::symlink_metadata(root_path)?;
            send_reply_checked(
                conn,
                &SyncReply::Entry(SyncEntry {
                    relative_path: String::new(),
                    kind: SyncEntryKind::Directory,
                    size: 0,
                    mode: meta.mode() & 0o777,
                    mtime_secs: meta.mtime(),
                    mtime_nanos: truncate_nanos(u32::try_from(meta.mtime_nsec()).unwrap_or(0)),
                    link_target: None,
                }),
            )?;
            scan_directory_tree(root_path, conn)
        }
        RootStatus::ExistingFile => {
            let meta = std::fs::symlink_metadata(root_path)?;
            let mtime_secs = meta.mtime();
            let mtime_nanos = truncate_nanos(u32::try_from(meta.mtime_nsec()).unwrap_or(0));
            send_reply_checked(
                conn,
                &SyncReply::Entry(SyncEntry {
                    relative_path: String::new(),
                    kind: SyncEntryKind::File,
                    size: meta.len(),
                    mode: meta.mode() & 0o777,
                    mtime_secs,
                    mtime_nanos,
                    link_target: None,
                }),
            )?;
            send_reply_checked(conn, &SyncReply::ScanComplete)
        }
        RootStatus::ExistingSymlink => {
            let meta = std::fs::symlink_metadata(root_path)?;
            let target = std::fs::read_link(root_path)?
                .to_str()
                .ok_or_else(|| std::io::Error::other("non-UTF-8 symlink target"))?
                .to_owned();
            let mtime_secs = meta.mtime();
            let mtime_nanos = truncate_nanos(u32::try_from(meta.mtime_nsec()).unwrap_or(0));
            send_reply_checked(
                conn,
                &SyncReply::Entry(SyncEntry {
                    relative_path: String::new(),
                    kind: SyncEntryKind::Symlink,
                    size: 0,
                    mode: meta.mode() & 0o777,
                    mtime_secs,
                    mtime_nanos,
                    link_target: Some(target),
                }),
            )?;
            send_reply_checked(conn, &SyncReply::ScanComplete)
        }
        RootStatus::Missing => send_reply_checked(conn, &SyncReply::ScanComplete),
    }
}

fn handle_compute_digest(
    root_path: &Path,
    relative_path: &str,
    conn: &mut (impl Read + Write),
) -> std::io::Result<()> {
    let target = match resolve_target_path(root_path, relative_path) {
        Ok(p) => p,
        Err(e) => return send_reply_checked(conn, &SyncReply::Err(e.to_string())),
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let thread_path = target.clone();
    std::thread::spawn(move || {
        hash_file_worker(&thread_path, &tx);
    });
    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(HashProgress::Progress(bytes_hashed)) => {
                send_reply_checked(conn, &SyncReply::DigestProgress { bytes_hashed })?;
            }
            Ok(HashProgress::Done(Ok(sha256))) => {
                return send_reply_checked(conn, &SyncReply::Digest { sha256 });
            }
            Ok(HashProgress::Done(Err(e))) => {
                return send_reply_checked(conn, &SyncReply::Err(e.to_string()));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return send_reply_checked(
                    conn,
                    &SyncReply::Err("hashing worker disconnected".to_string()),
                );
            }
        }
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
    workload_is_root: bool,
    conn: &mut (impl Read + Write),
) -> std::io::Result<()> {
    let target = match resolve_target_path(root_path, relative_path) {
        Ok(p) => p,
        Err(e) => return send_reply_checked(conn, &SyncReply::Err(e.to_string())),
    };
    let PreparedPut {
        mut file,
        parent,
        temp_name,
        destination_name,
    } = match prepare_put(&target) {
        Ok(p) => p,
        Err(e) => return send_reply_checked(conn, &SyncReply::Err(e.to_string())),
    };
    send_reply_checked(conn, &SyncReply::WriteFileReady)?;

    let result = (|| -> std::io::Result<()> {
        stream_exact(&mut *conn, &mut file, meta.size)?;
        if !matches!(
            read_frame::<SyncRequest>(&mut *conn)?,
            Some(SyncRequest::CommitFile)
        ) {
            return Err(std::io::Error::other("upload was not committed by sender"));
        }
        file.set_len(meta.size)?;
        if !workload_is_root {
            rustix::fs::fchown(
                &file,
                Some(rustix::process::Uid::from_raw(WORKLOAD_ID)),
                Some(rustix::process::Gid::from_raw(WORKLOAD_ID)),
            )
            .map_err(std::io::Error::from)?;
        }
        file.set_permissions(std::fs::Permissions::from_mode(meta.mode & 0o777))?;
        file.set_times(terra_protocol::sync_file_times(
            meta.mtime_secs,
            meta.mtime_nanos,
        )?)?;
        file.sync_all()?;
        drop(file);
        rustix::fs::renameat(&parent, &temp_name, &parent, &destination_name)
            .map_err(std::io::Error::from)
    })();

    let _ = rustix::fs::unlinkat(&parent, &temp_name, rustix::fs::AtFlags::empty());
    match result {
        Ok(()) => send_reply_checked(conn, &SyncReply::Success),
        Err(e) => send_reply_checked(conn, &SyncReply::Err(e.to_string())),
    }
}

fn handle_read_file(
    root_path: &Path,
    relative_path: &str,
    conn: &mut (impl Read + Write),
) -> std::io::Result<()> {
    let target = match resolve_target_path(root_path, relative_path) {
        Ok(p) => p,
        Err(e) => return send_reply_checked(conn, &SyncReply::Err(e.to_string())),
    };
    let (mut file, mode, size, mtime_secs, mtime_nanos) = match inspect_file(&target) {
        Ok(res) => res,
        Err(e) => return send_reply_checked(conn, &SyncReply::Err(e.to_string())),
    };
    send_reply_checked(
        conn,
        &SyncReply::ReadFileReady {
            size,
            mode,
            mtime_secs,
            mtime_nanos,
        },
    )?;
    let before = file.metadata()?;
    stream_exact(&mut file, &mut *conn, size)?;
    let after = file.metadata()?;
    if before.len() != after.len() || before.modified()? != after.modified()? {
        return send_reply_checked(
            conn,
            &SyncReply::Err("source changed while transferring".to_string()),
        );
    }
    send_reply_checked(conn, &SyncReply::Success)
}

fn handle_create_dir(
    root_path: &Path,
    relative_path: &str,
    mode: u32,
    workload_is_root: bool,
    conn: &mut (impl Read + Write),
) -> std::io::Result<()> {
    let dir_path = match resolve_target_path(root_path, relative_path) {
        Ok(p) => p,
        Err(e) => return send_reply_checked(conn, &SyncReply::Err(e.to_string())),
    };
    if let Some(parent) = dir_path.parent() {
        ensure_directory(parent, false)?;
    }
    let res = open_or_create_directory(&dir_path, !workload_is_root, rustix::fs::OFlags::NOFOLLOW)
        .and_then(|directory| {
            directory.set_permissions(std::fs::Permissions::from_mode((mode & 0o777) | 0o700))
        });
    match res {
        Ok(()) => send_reply_checked(conn, &SyncReply::Success),
        Err(e) => send_reply_checked(conn, &SyncReply::Err(e.to_string())),
    }
}

fn handle_create_symlink(
    root_path: &Path,
    relative_path: &str,
    target: &str,
    conn: &mut (impl Read + Write),
) -> std::io::Result<()> {
    let link_path = match resolve_target_path(root_path, relative_path) {
        Ok(p) => p,
        Err(e) => return send_reply_checked(conn, &SyncReply::Err(e.to_string())),
    };
    if let Some(parent) = link_path.parent() {
        ensure_directory(parent, false)?;
    }
    let temp = link_path.with_file_name(generate_random_temp_name()?);
    let result =
        std::os::unix::fs::symlink(target, &temp).and_then(|()| std::fs::rename(&temp, &link_path));
    let _ = std::fs::remove_file(&temp);
    match result {
        Ok(()) => send_reply_checked(conn, &SyncReply::Success),
        Err(e) => send_reply_checked(conn, &SyncReply::Err(e.to_string())),
    }
}

fn handle_update_metadata(
    root_path: &Path,
    relative_path: &str,
    mode: u32,
    mtime_secs: i64,
    mtime_nanos: u32,
    conn: &mut (impl Read + Write),
) -> std::io::Result<()> {
    let target = match resolve_target_path(root_path, relative_path) {
        Ok(p) => p,
        Err(e) => return send_reply_checked(conn, &SyncReply::Err(e.to_string())),
    };
    let meta = std::fs::symlink_metadata(&target)?;
    if meta.file_type().is_symlink() {
        return Err(std::io::Error::other("cannot update symlink metadata"));
    }
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode & 0o777))?;
    match set_path_mtime(&target, mtime_secs, mtime_nanos) {
        Ok(()) => send_reply_checked(conn, &SyncReply::Success),
        Err(e) => send_reply_checked(conn, &SyncReply::Err(e.to_string())),
    }
}

fn handle_remove_entry(
    root_path: &Path,
    relative_path: &str,
    is_dir: bool,
    conn: &mut (impl Read + Write),
) -> std::io::Result<()> {
    if relative_path.is_empty() {
        return send_reply_checked(
            conn,
            &SyncReply::Err("cannot remove session root itself".to_string()),
        );
    }
    let target = match resolve_target_path(root_path, relative_path) {
        Ok(p) => p,
        Err(e) => return send_reply_checked(conn, &SyncReply::Err(e.to_string())),
    };
    let res = if is_dir {
        std::fs::remove_dir(&target)
    } else {
        std::fs::remove_file(&target)
    };
    match res {
        Ok(()) => send_reply_checked(conn, &SyncReply::Success),
        Err(e) => send_reply_checked(conn, &SyncReply::Err(e.to_string())),
    }
}

pub fn serve_sync_session(mut conn: impl Read + Write, workload_is_root: bool) {
    let _ = handle_sync_session(&mut conn, workload_is_root);
}

fn inspect_root_status(
    path: &Path,
    guest_root: &str,
    conn: &mut impl Write,
) -> std::io::Result<Option<RootStatus>> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => Ok(Some(RootStatus::ExistingDirectory)),
        Ok(m) if m.file_type().is_symlink() => Ok(Some(RootStatus::ExistingSymlink)),
        Ok(m) if m.is_file() => Ok(Some(RootStatus::ExistingFile)),
        Ok(_) => {
            send_reply_checked(
                conn,
                &SyncReply::Err(format!("root {guest_root} is an unsupported file type")),
            )?;
            Ok(None)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Some(RootStatus::Missing)),
        Err(e) => {
            send_reply_checked(
                conn,
                &SyncReply::Err(format!("inspecting root {guest_root}: {e}")),
            )?;
            Ok(None)
        }
    }
}

fn init_session(conn: &mut (impl Read + Write)) -> std::io::Result<Option<(PathBuf, RootStatus)>> {
    let Some(SyncRequest::BeginSession { guest_root }) = read_frame::<SyncRequest>(&mut *conn)?
    else {
        return Ok(None);
    };

    let root_path = PathBuf::from(&guest_root);
    let Some(root_status) = inspect_root_status(&root_path, &guest_root, conn)? else {
        return Ok(None);
    };

    send_reply_checked(conn, &SyncReply::SessionReady { root_status })?;
    Ok(Some((root_path, root_status)))
}

fn handle_sync_session(
    conn: &mut (impl Read + Write),
    workload_is_root: bool,
) -> std::io::Result<()> {
    let Some((mut root_path, mut root_status)) = init_session(conn)? else {
        return Ok(());
    };

    while let Some(req) = read_frame::<SyncRequest>(&mut *conn)? {
        match req {
            SyncRequest::CommitFile => return Err(std::io::Error::other("unexpected file commit")),
            SyncRequest::BeginSession { guest_root } => {
                let p = PathBuf::from(&guest_root);
                let Some(status) = inspect_root_status(&p, &guest_root, conn)? else {
                    return Ok(());
                };
                root_path = p;
                root_status = status;
                send_reply_checked(conn, &SyncReply::SessionReady { root_status })?;
            }
            SyncRequest::ScanEntries => {
                handle_scan_entries(&root_path, root_status, conn)?;
            }
            SyncRequest::ComputeDigest { relative_path } => {
                handle_compute_digest(&root_path, &relative_path, conn)?;
            }
            SyncRequest::WriteFile {
                relative_path,
                size,
                mode,
                mtime_secs,
                mtime_nanos,
            } => {
                handle_write_file(
                    &root_path,
                    &relative_path,
                    WriteFileMeta {
                        size,
                        mode,
                        mtime_secs,
                        mtime_nanos,
                    },
                    workload_is_root,
                    conn,
                )?;
            }
            SyncRequest::ReadFile { relative_path } => {
                handle_read_file(&root_path, &relative_path, conn)?;
            }
            SyncRequest::CreateDir {
                relative_path,
                mode,
            } => {
                handle_create_dir(&root_path, &relative_path, mode, workload_is_root, conn)?;
            }
            SyncRequest::CreateSymlink {
                relative_path,
                target,
            } => {
                handle_create_symlink(&root_path, &relative_path, &target, conn)?;
            }
            SyncRequest::UpdateMetadata {
                relative_path,
                mode,
                mtime_secs,
                mtime_nanos,
            } => {
                handle_update_metadata(
                    &root_path,
                    &relative_path,
                    mode,
                    mtime_secs,
                    mtime_nanos,
                    conn,
                )?;
            }
            SyncRequest::RemoveEntry {
                relative_path,
                is_dir,
            } => {
                handle_remove_entry(&root_path, &relative_path, is_dir, conn)?;
            }
            SyncRequest::EndSession => {
                send_reply_checked(conn, &SyncReply::Success)?;
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_resolves_parents_above_the_root_but_not_links_inside_it() {
        let scratch = crate::create_scratch_path("sync", "root-symlink-policy");
        let real = scratch.join("real");
        std::fs::create_dir_all(real.join("app")).unwrap();
        let alias = scratch.join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let mut conn = Vec::new();
        assert_eq!(
            inspect_root_status(&alias, "alias", &mut conn).unwrap(),
            Some(RootStatus::ExistingSymlink)
        );
        let root = alias.join("app");
        assert_eq!(
            inspect_root_status(&root, "alias/app", &mut conn).unwrap(),
            Some(RootStatus::ExistingDirectory)
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
        handle_scan_entries(&root, RootStatus::ExistingDirectory, &mut conn).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("new")).unwrap();
        conn.output.clear();
        handle_create_dir(&root, "new", 0o777, true, &mut conn).unwrap();
        let reply = read_frame::<SyncReply>(&mut std::io::Cursor::new(conn.output))
            .unwrap()
            .unwrap();
        assert!(matches!(reply, SyncReply::Err(_)), "{reply:?}");
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
            open_or_create_directory(&directory, false, rustix::fs::OFlags::NOFOLLOW).unwrap();
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
            serve_sync_session(&mut conn, true);
            assert_eq!(std::fs::read(&destination).unwrap(), b"old");
            assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 1);
        }
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

    #[test]
    fn random_temp_suffix_has_fixed_hex_shape() {
        let name = generate_random_temp_name().unwrap().into_string().unwrap();
        let suffix = name.strip_prefix(".terra-put-").unwrap();
        assert_eq!(suffix.len(), 32);
        assert!(suffix.bytes().all(|byte| byte.is_ascii_hexdigit()));
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
        serve_sync_session(&mut conn, true);

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
        serve_sync_session(&mut conn, true);

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
