use super::plan::PlanAction;
use super::scan::{checked_host_path, meta_mtime_nanos, meta_mtime_secs, optional_metadata};
use super::security::{
    sanitize_guest_error_message, to_guest_mode, to_safe_mode, validate_download_symlink_target,
};
use crate::sys;
use crate::vm::image;
use anyhow::{Context, Result};
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};
use terra_protocol::{
    MAX_FILE_BYTES, SyncDirection, SyncReply, SyncRequest, read_frame_async_with_limit,
    write_frame_async,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_SYNC_FRAME_BYTES: usize = 64 * 1024;
const COPY_STALL_TIMEOUT: Duration = Duration::from_mins(1);
pub(super) const COPY_DATA_TIMEOUT: Duration = Duration::from_hours(1);

pub(super) async fn read_reply(stream: &mut (impl AsyncRead + Unpin)) -> Result<SyncReply> {
    let reply = tokio::time::timeout(
        COPY_STALL_TIMEOUT,
        read_frame_async_with_limit(stream, MAX_SYNC_FRAME_BYTES),
    )
    .await
    .context("waiting for agent reply")?
    .context("reading agent reply")?
    .ok_or_else(|| anyhow::anyhow!("agent closed connection without replying"))?;
    match reply {
        SyncReply::Err(err) => anyhow::bail!("guest: {}", sanitize_guest_error_message(&err)),
        other => Ok(other),
    }
}

pub(super) async fn send_request(
    stream: &mut (impl AsyncWrite + Unpin),
    req: &SyncRequest,
) -> Result<()> {
    tokio::time::timeout(COPY_STALL_TIMEOUT, write_frame_async(stream, req))
        .await
        .context("waiting to send sync request frame")?
        .context("sending sync request frame")
}

async fn write_file_data(stream: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> Result<()> {
    tokio::time::timeout(COPY_STALL_TIMEOUT, stream.write_all(bytes))
        .await
        .context("waiting to send file data to agent")?
        .context("sending file data to agent")
}

async fn read_file_data(stream: &mut (impl AsyncRead + Unpin), bytes: &mut [u8]) -> Result<usize> {
    tokio::time::timeout(COPY_STALL_TIMEOUT, stream.read(bytes))
        .await
        .context("waiting for file data from agent")?
        .context("receiving file data from agent")
}

fn install_host_symlink(target: &str, destination: &Path) -> Result<()> {
    let parent = destination.parent().context("symlink has no parent")?;
    let (staging, _) = sys::reserve_staging_directory(parent, "terra-sync")?;
    let temporary = staging.join("link");
    let result = (|| -> Result<()> {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, &temporary)?;
        #[cfg(windows)]
        {
            if parent.join(target).is_dir() {
                std::os::windows::fs::symlink_dir(target, &temporary)?;
            } else {
                std::os::windows::fs::symlink_file(target, &temporary)?;
            }
        }
        std::fs::rename(&temporary, destination)?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&temporary);
    #[cfg(windows)]
    let _ = std::fs::remove_dir(&temporary);
    let _ = std::fs::remove_dir(&staging);
    result
}

fn update_host_metadata(path: &Path, mode: u32, mtime_secs: i64, mtime_nanos: u32) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "cannot update symlink metadata"
    );
    anyhow::ensure!(
        !metadata.is_file() || sys::file_link_count(path)? <= 1,
        "cannot update metadata of hard-linked file {}; replace it with an independent copy before syncing",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(to_safe_mode(mode)))?;
    }
    #[cfg(windows)]
    {
        let mut permissions = metadata.permissions();
        permissions.set_readonly(mode & 0o200 == 0);
        std::fs::set_permissions(path, permissions)?;
    }
    sys::set_path_mtime(path, mtime_secs, mtime_nanos)
        .with_context(|| format!("setting timestamp on {}", path.display()))
}

async fn send_file_into_guest(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    host_path: &Path,
    rel_path: &str,
    meta: &std::fs::Metadata,
    deadline: Instant,
) -> Result<u64> {
    let size = meta.len();
    anyhow::ensure!(
        size <= MAX_FILE_BYTES,
        "file {} is {size} bytes, past the {} GiB sync limit",
        host_path.display(),
        MAX_FILE_BYTES >> 30
    );
    let mtime_secs = meta_mtime_secs(meta);
    let mtime_nanos = meta_mtime_nanos(meta);
    let mode = to_guest_mode(meta);

    send_request(
        stream,
        &SyncRequest::WriteFile {
            relative_path: rel_path.to_string(),
            size,
            mode,
            mtime_secs,
            mtime_nanos,
        },
    )
    .await?;

    match read_reply(stream).await? {
        SyncReply::WriteFileReady => {}
        other => anyhow::bail!("expected WriteFileReady from agent, got {other:?}"),
    }

    let mut file = sys::open_regular_file(host_path)
        .with_context(|| format!("opening {}", host_path.display()))?;
    let mut buf = vec![0u8; 16 * 1024];
    let mut sent = 0u64;
    while sent < size {
        if Instant::now() >= deadline {
            anyhow::bail!("file transfer ran past data transfer limit");
        }
        let want = usize::min(buf.len(), usize::try_from(size - sent).unwrap_or(buf.len()));
        let n = match file.read(&mut buf[..want]) {
            Ok(0) => {
                anyhow::bail!(
                    "{} shrank while being transferred (read {sent} of {size} bytes)",
                    host_path.display()
                );
            }
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context(format!("reading {}", host_path.display())),
        };
        write_file_data(stream, &buf[..n]).await?;
        sent += n as u64;
    }

    let after = file.metadata()?;
    anyhow::ensure!(
        after.len() == size && after.modified()? == meta.modified()?,
        "source changed while transferring; retry with a quiet source"
    );
    send_request(stream, &SyncRequest::CommitFile).await?;

    match read_reply(stream).await? {
        SyncReply::Success => {}
        other => anyhow::bail!("expected Success after file transfer, got {other:?}"),
    }
    Ok(sent)
}

async fn fetch_file_from_guest(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    guest_rel_path: &str,
    dst_full_path: &Path,
    expected: &(u64, u32, i64, u32),
    deadline: Instant,
) -> Result<u64> {
    send_request(
        stream,
        &SyncRequest::ReadFile {
            relative_path: guest_rel_path.to_string(),
        },
    )
    .await?;

    let (size, mode, mtime_secs, mtime_nanos) = match read_reply(stream).await? {
        SyncReply::ReadFileReady {
            size,
            mode,
            mtime_secs,
            mtime_nanos,
        } => (size, mode, mtime_secs, mtime_nanos),
        other => anyhow::bail!("expected ReadFileReady from agent, got {other:?}"),
    };

    anyhow::ensure!(
        (size, mode & 0o777, mtime_secs, mtime_nanos) == *expected,
        "guest file metadata changed since planning; retry with a quiet source"
    );
    anyhow::ensure!(
        size <= MAX_FILE_BYTES,
        "remote file is {size} bytes, past the {} GiB sync limit",
        MAX_FILE_BYTES >> 30
    );

    if let Some(parent) = dst_full_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }

    let mut staged = image::StagedFile::new(dst_full_path)?;
    let file = staged.file_mut();
    let mut buf = vec![0u8; 16 * 1024];
    let mut received = 0u64;
    while received < size {
        anyhow::ensure!(
            Instant::now() < deadline,
            "file transfer ran past data transfer limit"
        );
        let want = usize::min(
            buf.len(),
            usize::try_from(size - received).unwrap_or(buf.len()),
        );
        let n = read_file_data(stream, &mut buf[..want]).await?;
        anyhow::ensure!(
            n != 0,
            "transfer of {guest_rel_path} ended after {received} of {size} promised bytes"
        );
        image::write_sparse_chunk(file, &buf[..n])
            .with_context(|| format!("writing to {}", dst_full_path.display()))?;
        received += n as u64;
    }
    file.set_len(size)
        .with_context(|| format!("sizing {}", dst_full_path.display()))?;
    sys::set_open_file_mode(file, to_safe_mode(mode))
        .with_context(|| format!("setting permissions on {}", dst_full_path.display()))?;
    anyhow::ensure!(
        matches!(read_reply(stream).await?, SyncReply::Success),
        "guest did not confirm completed file transfer"
    );
    file.set_times(terra_protocol::sync_file_times(mtime_secs, mtime_nanos)?)?;
    staged.commit()?;

    Ok(size)
}

#[derive(Default)]
pub(super) struct SyncStats {
    pub(super) copied_count: usize,
    pub(super) metadata_updated_count: usize,
    pub(super) deleted_count: usize,
    pub(super) skipped_count: usize,
    pub(super) transferred_bytes: u64,
}

type TransferItem<'a> = (&'a String, Option<(u64, u32, i64, u32)>, Option<&'a String>);

fn dry_run_report(
    create_dirs: &[(&String, u32)],
    transfers_and_symlinks: &[TransferItem<'_>],
    file_meta_updates: &[(&String, u32, i64, u32)],
    deletions: &[(&String, bool)],
    dir_meta_updates: &[(&String, u32, i64, u32)],
) -> SyncStats {
    let mut stats = SyncStats::default();
    for (rel, _) in create_dirs {
        let rel = crate::render::escape_printable(rel);
        eprintln!("terra: [dry-run] mkdir {rel}");
    }
    for (rel, file_info, link_target) in transfers_and_symlinks {
        stats.copied_count += 1;
        if let Some((size, _, _, _)) = file_info {
            stats.transferred_bytes += *size;
            let rel = crate::render::escape_printable(rel);
            eprintln!("terra: [dry-run] copy {rel} ({size} bytes)");
        } else if let Some(target) = link_target {
            let target = crate::render::escape_printable(target);
            let rel = crate::render::escape_printable(rel);
            eprintln!("terra: [dry-run] symlink {rel} -> {target}");
        }
    }
    for (rel, _, _, _) in file_meta_updates {
        stats.metadata_updated_count += 1;
        let rel = crate::render::escape_printable(rel);
        eprintln!("terra: [dry-run] chmod/mtime {rel}");
    }
    for (rel, is_dir) in deletions {
        stats.deleted_count += 1;
        let kind = if *is_dir { "dir" } else { "file" };
        let rel = crate::render::escape_printable(rel);
        eprintln!("terra: [dry-run] rm {kind} {rel}");
    }
    for (rel, _, _, _) in dir_meta_updates {
        let rel = crate::render::escape_printable(rel);
        eprintln!("terra: [dry-run] dir mtime {rel}");
    }
    stats
}

async fn execute_create_dirs(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    create_dirs: &[(&String, u32)],
    direction: SyncDirection,
    host_target_root: &Path,
) -> Result<()> {
    for (rel_path, mode) in create_dirs {
        match direction {
            SyncDirection::HostToGuest => {
                send_request(
                    stream,
                    &SyncRequest::CreateDir {
                        relative_path: (*rel_path).clone(),
                        mode: *mode,
                    },
                )
                .await?;
                match read_reply(stream).await? {
                    SyncReply::Success => {}
                    other => anyhow::bail!("expected Success after CreateDir, got {other:?}"),
                }
            }
            SyncDirection::GuestToHost => {
                let dir_path = checked_host_path(host_target_root, rel_path)?;
                if let Some(meta) = optional_metadata(&dir_path)? {
                    anyhow::ensure!(meta.is_dir(), "destination directory is a file or symlink");
                }
                std::fs::create_dir_all(&dir_path)
                    .with_context(|| format!("creating directory {}", dir_path.display()))?;
            }
        }
    }
    Ok(())
}

async fn execute_transfers_and_symlinks(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    transfers_and_symlinks: &[TransferItem<'_>],
    direction: SyncDirection,
    host_source_root: &Path,
    host_target_root: &Path,
    deadline: Instant,
    stats: &mut SyncStats,
) -> Result<()> {
    for (rel_path, file_info, link_target) in transfers_and_symlinks {
        stats.copied_count += 1;
        if let Some(expected) = file_info {
            match direction {
                SyncDirection::HostToGuest => {
                    let local_file = if rel_path.is_empty() {
                        host_source_root.to_path_buf()
                    } else {
                        host_source_root.join(rel_path)
                    };
                    let meta = std::fs::symlink_metadata(&local_file)
                        .with_context(|| format!("reading {}", local_file.display()))?;
                    anyhow::ensure!(
                        meta.is_file()
                            && (
                                meta.len(),
                                to_guest_mode(&meta),
                                meta_mtime_secs(&meta),
                                meta_mtime_nanos(&meta)
                            ) == *expected,
                        "host source changed since planning"
                    );
                    let sent = send_file_into_guest(stream, &local_file, rel_path, &meta, deadline)
                        .await?;
                    stats.transferred_bytes += sent;
                }
                SyncDirection::GuestToHost => {
                    let local_file = checked_host_path(host_target_root, rel_path)?;
                    let received =
                        fetch_file_from_guest(stream, rel_path, &local_file, expected, deadline)
                            .await?;
                    stats.transferred_bytes += received;
                }
            }
        } else if let Some(target) = link_target {
            match direction {
                SyncDirection::HostToGuest => {
                    send_request(
                        stream,
                        &SyncRequest::CreateSymlink {
                            relative_path: (*rel_path).clone(),
                            target: (*target).clone(),
                        },
                    )
                    .await?;
                    match read_reply(stream).await? {
                        SyncReply::Success => {}
                        other => {
                            anyhow::bail!("expected Success after CreateSymlink, got {other:?}")
                        }
                    }
                }
                SyncDirection::GuestToHost => {
                    validate_download_symlink_target(rel_path, target)?;
                    let link_path = checked_host_path(host_target_root, rel_path)?;
                    if let Some(parent) = link_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    install_host_symlink(target, &link_path)?;
                }
            }
        }
    }
    Ok(())
}

async fn execute_file_meta_updates(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    file_meta_updates: &[(&String, u32, i64, u32)],
    direction: SyncDirection,
    host_target_root: &Path,
    stats: &mut SyncStats,
) -> Result<()> {
    for (rel_path, mode, mtime_secs, mtime_nanos) in file_meta_updates {
        stats.metadata_updated_count += 1;
        match direction {
            SyncDirection::HostToGuest => {
                send_request(
                    stream,
                    &SyncRequest::UpdateMetadata {
                        relative_path: (*rel_path).clone(),
                        mode: *mode,
                        mtime_secs: *mtime_secs,
                        mtime_nanos: *mtime_nanos,
                    },
                )
                .await?;
                match read_reply(stream).await? {
                    SyncReply::Success => {}
                    other => anyhow::bail!("expected Success after UpdateMetadata, got {other:?}"),
                }
            }
            SyncDirection::GuestToHost => {
                let local_path = checked_host_path(host_target_root, rel_path)?;
                update_host_metadata(&local_path, *mode, *mtime_secs, *mtime_nanos)?;
            }
        }
    }
    Ok(())
}

async fn execute_deletions(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    deletions: &[(&String, bool)],
    direction: SyncDirection,
    host_target_root: &Path,
    stats: &mut SyncStats,
) -> Result<()> {
    for (rel_path, is_dir) in deletions {
        stats.deleted_count += 1;
        match direction {
            SyncDirection::HostToGuest => {
                send_request(
                    stream,
                    &SyncRequest::RemoveEntry {
                        relative_path: (*rel_path).clone(),
                        is_dir: *is_dir,
                    },
                )
                .await?;
                match read_reply(stream).await? {
                    SyncReply::Success => {}
                    other => anyhow::bail!("expected Success after RemoveEntry, got {other:?}"),
                }
            }
            SyncDirection::GuestToHost => {
                let target = checked_host_path(host_target_root, rel_path)?;
                if *is_dir {
                    std::fs::remove_dir(&target)
                        .with_context(|| format!("removing directory {}", target.display()))?;
                } else {
                    std::fs::remove_file(&target)
                        .with_context(|| format!("removing file {}", target.display()))?;
                }
            }
        }
    }
    Ok(())
}

async fn execute_dir_meta_updates(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    dir_meta_updates: &[(&String, u32, i64, u32)],
    direction: SyncDirection,
    host_target_root: &Path,
) -> Result<()> {
    for (rel_path, mode, mtime_secs, mtime_nanos) in dir_meta_updates {
        match direction {
            SyncDirection::HostToGuest => {
                send_request(
                    stream,
                    &SyncRequest::UpdateMetadata {
                        relative_path: (*rel_path).clone(),
                        mode: *mode,
                        mtime_secs: *mtime_secs,
                        mtime_nanos: *mtime_nanos,
                    },
                )
                .await?;
                match read_reply(stream).await? {
                    SyncReply::Success => {}
                    other => anyhow::bail!(
                        "expected Success after directory UpdateMetadata, got {other:?}"
                    ),
                }
            }
            SyncDirection::GuestToHost => {
                let local_path = checked_host_path(host_target_root, rel_path)?;
                update_host_metadata(&local_path, *mode, *mtime_secs, *mtime_nanos)?;
            }
        }
    }
    Ok(())
}

pub(super) async fn execute_plan(
    actions: &[PlanAction],
    direction: SyncDirection,
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    host_target_root: &Path,
    host_source_root: &Path,
    is_dry_run: bool,
) -> Result<SyncStats> {
    let mut stats = SyncStats::default();
    let deadline = Instant::now() + COPY_DATA_TIMEOUT;

    let mut create_dirs = Vec::new();
    let mut transfers_and_symlinks = Vec::new();
    let mut file_meta_updates = Vec::new();
    let mut deletions = Vec::new();
    let mut dir_meta_updates = Vec::new();

    for action in actions {
        match action {
            PlanAction::CreateDir { rel_path, mode } => {
                create_dirs.push((rel_path, *mode));
            }
            PlanAction::TransferFile {
                rel_path,
                size,
                mode,
                mtime_secs,
                mtime_nanos,
            } => {
                transfers_and_symlinks.push((
                    rel_path,
                    Some((*size, *mode, *mtime_secs, *mtime_nanos)),
                    None,
                ));
            }
            PlanAction::CreateSymlink { rel_path, target } => {
                transfers_and_symlinks.push((rel_path, None, Some(target)));
            }
            PlanAction::UpdateFileMetadata {
                rel_path,
                mode,
                mtime_secs,
                mtime_nanos,
            } => {
                file_meta_updates.push((rel_path, *mode, *mtime_secs, *mtime_nanos));
            }
            PlanAction::RemoveEntry { rel_path, is_dir } => {
                deletions.push((rel_path, *is_dir));
            }
            PlanAction::UpdateDirMetadata {
                rel_path,
                mode,
                mtime_secs,
                mtime_nanos,
            } => {
                dir_meta_updates.push((rel_path, *mode, *mtime_secs, *mtime_nanos));
            }
            PlanAction::Skip { .. } => {
                stats.skipped_count += 1;
            }
        }
    }

    create_dirs.sort_by_key(|(p, _)| p.len());
    deletions.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
    dir_meta_updates.sort_by_key(|(p, _, _, _)| std::cmp::Reverse(p.len()));

    if is_dry_run {
        let dry_stats = dry_run_report(
            &create_dirs,
            &transfers_and_symlinks,
            &file_meta_updates,
            &deletions,
            &dir_meta_updates,
        );
        stats.copied_count = dry_stats.copied_count;
        stats.transferred_bytes = dry_stats.transferred_bytes;
        stats.metadata_updated_count = dry_stats.metadata_updated_count;
        stats.deleted_count = dry_stats.deleted_count;
        return Ok(stats);
    }

    execute_create_dirs(stream, &create_dirs, direction, host_target_root).await?;
    execute_transfers_and_symlinks(
        stream,
        &transfers_and_symlinks,
        direction,
        host_source_root,
        host_target_root,
        deadline,
        &mut stats,
    )
    .await?;
    execute_file_meta_updates(
        stream,
        &file_meta_updates,
        direction,
        host_target_root,
        &mut stats,
    )
    .await?;
    execute_deletions(stream, &deletions, direction, host_target_root, &mut stats).await?;
    execute_dir_meta_updates(stream, &dir_meta_updates, direction, host_target_root).await?;

    send_request(stream, &SyncRequest::EndSession).await?;
    anyhow::ensure!(
        matches!(read_reply(stream).await?, SyncReply::Success),
        "expected session completion"
    );
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{PendingPeer, peer};
    use super::*;

    #[tokio::test]
    async fn download_metadata_does_not_modify_hard_links_outside_the_tree() {
        let scratch = tempfile::tempdir().unwrap();
        let outside = scratch.path().join("outside");
        let root = scratch.path().join("destination");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(&outside, b"private").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        sys::set_path_mtime(&outside, 100, 0).unwrap();
        std::fs::hard_link(&outside, root.join("file")).unwrap();
        let before = std::fs::metadata(&outside).unwrap();
        let updates = [(String::from("file"), 0o755, 200, 0)];
        let error = execute_file_meta_updates(
            &mut peer(&[]),
            &[(&updates[0].0, updates[0].1, updates[0].2, updates[0].3)],
            SyncDirection::GuestToHost,
            &root,
            &mut SyncStats::default(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("hard-linked"), "{error:#}");
        let after = std::fs::metadata(&outside).unwrap();
        assert_eq!(before.permissions(), after.permissions());
        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
        std::fs::remove_file(root.join("file")).unwrap();
        std::fs::copy(&outside, root.join("file")).unwrap();
        update_host_metadata(&root.join("file"), 0o755, 200, 0).unwrap();
        update_host_metadata(&root, 0o755, 200, 0).unwrap();
        assert_eq!(
            meta_mtime_secs(&std::fs::metadata(root.join("file")).unwrap()),
            200
        );
        assert_eq!(
            std::fs::metadata(&outside).unwrap().modified().unwrap(),
            before.modified().unwrap()
        );
    }

    #[tokio::test]
    async fn interrupted_download_preserves_destination_and_suppresses_deletion() {
        let scratch = tempfile::tempdir().unwrap();
        let file = scratch.path().join("file");
        let extra = scratch.path().join("extra");
        std::fs::write(&file, b"old").unwrap();
        std::fs::write(&extra, b"keep").unwrap();
        let actions = [
            PlanAction::TransferFile {
                rel_path: "file".into(),
                size: 5,
                mode: 0o644,
                mtime_secs: 100,
                mtime_nanos: 0,
            },
            PlanAction::RemoveEntry {
                rel_path: "extra".into(),
                is_dir: false,
            },
        ];
        let mut guest = peer(&[SyncReply::ReadFileReady {
            size: 5,
            mode: 0o644,
            mtime_secs: 100,
            mtime_nanos: 0,
        }]);
        guest.0.get_mut().extend(b"bad");
        assert!(
            execute_plan(
                &actions,
                SyncDirection::GuestToHost,
                &mut guest,
                scratch.path(),
                Path::new("/guest"),
                false
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read(file).unwrap(), b"old");
        assert_eq!(std::fs::read(extra).unwrap(), b"keep");
        assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 2);
    }

    #[tokio::test]
    async fn download_requires_the_planned_metadata_and_completion_reply() {
        let scratch = tempfile::tempdir().unwrap();
        let destination = scratch.path().join("file");
        std::fs::write(&destination, b"old").unwrap();
        let expected = (3, 0o644, 100, 0);
        for size in [3, 4] {
            let mut guest = peer(&[SyncReply::ReadFileReady {
                size,
                mode: 0o644,
                mtime_secs: 100,
                mtime_nanos: 0,
            }]);
            guest.0.get_mut().extend(b"new");
            assert!(
                fetch_file_from_guest(
                    &mut guest,
                    "file",
                    &destination,
                    &expected,
                    Instant::now() + COPY_DATA_TIMEOUT
                )
                .await
                .is_err()
            );
            assert_eq!(std::fs::read(&destination).unwrap(), b"old");
        }
    }

    #[tokio::test]
    async fn canceled_download_preserves_destination_and_removes_the_staged_file() {
        let scratch = tempfile::tempdir().unwrap();
        let destination = scratch.path().join("file");
        std::fs::write(&destination, b"old").unwrap();
        let replies = [SyncReply::ReadFileReady {
            size: 3,
            mode: 0o644,
            mtime_secs: 100,
            mtime_nanos: 0,
        }];
        let destination_for_task = destination.clone();
        let (blocked_sender, blocked) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            fetch_file_from_guest(
                &mut PendingPeer {
                    peer: peer(&replies),
                    blocked: Some(blocked_sender),
                },
                "file",
                &destination_for_task,
                &(3, 0o644, 100, 0),
                Instant::now() + COPY_DATA_TIMEOUT,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(1), blocked)
            .await
            .expect("download never reached its pending read")
            .expect("download task ended before its pending read");
        assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 2);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(std::fs::read(&destination).unwrap(), b"old");
        assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 1);
    }

    #[test]
    #[cfg(unix)]
    fn failed_symlink_creation_preserves_the_previous_destination() {
        let scratch = tempfile::tempdir().unwrap();
        let destination = scratch.path().join("file");
        std::fs::write(&destination, b"old").unwrap();
        assert!(install_host_symlink("invalid\0target", &destination).is_err());
        assert_eq!(std::fs::read(destination).unwrap(), b"old");
        assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 1);
    }
}
