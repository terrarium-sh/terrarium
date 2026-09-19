use super::exec::{COPY_DATA_TIMEOUT, read_reply, send_request};
use super::security::{to_guest_mode, validate_manifest};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Instant;
use terra_protocol::{
    MAX_FILE_BYTES, MAX_SYNC_ENTRIES, MAX_SYNC_METADATA_BYTES, SyncEntry, SyncEntryKind, SyncReply,
    SyncRequest, truncate_nanos, validate_relative_path,
};
use tokio::io::{AsyncRead, AsyncWrite};

pub(super) fn optional_metadata(path: &Path) -> Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

pub(super) fn checked_host_path(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_relative_path(relative).map_err(anyhow::Error::msg)?;
    let mut path = root.to_path_buf();
    if !relative.is_empty() {
        for component in relative.split('/') {
            if let Some(meta) = optional_metadata(&path)? {
                anyhow::ensure!(
                    meta.is_dir(),
                    "sync parent must be a directory: {}",
                    path.display()
                );
            }
            path.push(component);
        }
    }
    Ok(path)
}

pub(super) fn meta_mtime_secs(meta: &std::fs::Metadata) -> i64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.mtime()
    }
    #[cfg(windows)]
    {
        meta.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs() as i64)
    }
}

pub(super) fn meta_mtime_nanos(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        truncate_nanos(u32::try_from(meta.mtime_nsec()).unwrap_or(0))
    }
    #[cfg(windows)]
    {
        meta.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
            .map_or(0, |d| truncate_nanos(d.subsec_nanos()))
    }
}

pub(super) fn single_host_entry_map(
    path: &Path,
    meta: &std::fs::Metadata,
) -> Result<BTreeMap<String, SyncEntry>> {
    let mut map = BTreeMap::new();
    let mtime_secs = meta_mtime_secs(meta);
    let mtime_nanos = meta_mtime_nanos(meta);
    let mode = to_guest_mode(meta);
    let kind = if meta.is_dir() {
        SyncEntryKind::Directory
    } else if meta.file_type().is_symlink() {
        SyncEntryKind::Symlink
    } else if meta.is_file() {
        SyncEntryKind::File
    } else {
        anyhow::bail!("unsupported special file: {}", path.display());
    };
    let link_target = if kind == SyncEntryKind::Symlink {
        Some(
            std::fs::read_link(path)?
                .to_str()
                .context("non-UTF-8 symlink target")?
                .to_owned(),
        )
    } else {
        None
    };
    anyhow::ensure!(meta.len() <= MAX_FILE_BYTES, "file exceeds sync size limit");
    map.insert(
        String::new(),
        SyncEntry {
            relative_path: String::new(),
            kind,
            size: if kind == SyncEntryKind::File {
                meta.len()
            } else {
                0
            },
            mode,
            mtime_secs,
            mtime_nanos,
            link_target,
        },
    );
    Ok(map)
}

pub(super) fn scan_host_directory(root_path: &Path) -> Result<BTreeMap<String, SyncEntry>> {
    let mut entries = single_host_entry_map(root_path, &std::fs::symlink_metadata(root_path)?)?;
    let mut queue = VecDeque::new();
    queue.push_back(PathBuf::new());
    let mut total_metadata_bytes = 0usize;

    while let Some(rel) = queue.pop_front() {
        let full = if rel.as_os_str().is_empty() {
            root_path.to_path_buf()
        } else {
            root_path.join(&rel)
        };
        let read_dir = std::fs::read_dir(&full)
            .with_context(|| format!("reading directory {}", full.display()))?;
        for entry_res in read_dir {
            let entry =
                entry_res.with_context(|| format!("reading entry in {}", full.display()))?;
            let file_name = entry.file_name();
            let name_str = file_name
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-utf8 filename in {}", full.display()))?;
            if name_str == "." || name_str == ".." {
                continue;
            }
            let child_rel = if rel.as_os_str().is_empty() {
                PathBuf::from(name_str)
            } else {
                rel.join(name_str)
            };
            let child_full = root_path.join(&child_rel);
            let meta = std::fs::symlink_metadata(&child_full)
                .with_context(|| format!("reading metadata of {}", child_full.display()))?;
            let file_type = meta.file_type();
            let (kind, link_target) = if file_type.is_dir() {
                (SyncEntryKind::Directory, None)
            } else if file_type.is_symlink() {
                let target = std::fs::read_link(&child_full)
                    .with_context(|| format!("reading link {}", child_full.display()))?;
                let target_str = target
                    .to_str()
                    .ok_or_else(|| {
                        anyhow::anyhow!("non-utf8 symlink target in {}", child_full.display())
                    })?
                    .to_string();
                (SyncEntryKind::Symlink, Some(target_str))
            } else if file_type.is_file() {
                (SyncEntryKind::File, None)
            } else {
                anyhow::bail!("unsupported special file: {}", child_full.display());
            };

            let rel_str = child_rel
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-utf8 path: {}", child_rel.display()))?
                .to_string();
            #[cfg(windows)]
            let rel_str = rel_str.replace('\\', "/");
            validate_relative_path(&rel_str).map_err(anyhow::Error::msg)?;
            anyhow::ensure!(meta.len() <= MAX_FILE_BYTES, "file exceeds sync size limit");
            let mtime_secs = meta_mtime_secs(&meta);
            let mtime_nanos = meta_mtime_nanos(&meta);
            let mode = to_guest_mode(&meta);
            let size = if kind == SyncEntryKind::File {
                meta.len()
            } else {
                0
            };

            total_metadata_bytes +=
                rel_str.len() + link_target.as_ref().map_or(0, std::string::String::len) + 32;
            anyhow::ensure!(
                entries.len() < MAX_SYNC_ENTRIES,
                "manifest exceeds maximum entry budget of {MAX_SYNC_ENTRIES} entries"
            );
            anyhow::ensure!(
                total_metadata_bytes <= MAX_SYNC_METADATA_BYTES,
                "manifest exceeds maximum metadata budget of {MAX_SYNC_METADATA_BYTES} bytes"
            );

            if kind == SyncEntryKind::Directory {
                queue.push_back(child_rel);
            }

            entries.insert(
                rel_str.clone(),
                SyncEntry {
                    relative_path: rel_str,
                    kind,
                    size,
                    mode,
                    mtime_secs,
                    mtime_nanos,
                    link_target,
                },
            );
        }
    }
    Ok(entries)
}

pub(super) async fn scan_guest_entries(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> Result<BTreeMap<String, SyncEntry>> {
    send_request(stream, &SyncRequest::ScanEntries).await?;
    let mut entries = BTreeMap::new();
    let mut total_metadata_bytes = 0usize;

    let deadline = Instant::now() + COPY_DATA_TIMEOUT;
    loop {
        anyhow::ensure!(
            Instant::now() < deadline,
            "guest scan exceeded its time limit"
        );
        match read_reply(stream).await? {
            SyncReply::Entry(entry) => {
                validate_relative_path(&entry.relative_path)
                    .map_err(|e| anyhow::anyhow!("invalid guest path: {e}"))?;
                total_metadata_bytes += entry.relative_path.len()
                    + entry
                        .link_target
                        .as_ref()
                        .map_or(0, std::string::String::len)
                    + 32;
                anyhow::ensure!(
                    entries.len() < MAX_SYNC_ENTRIES,
                    "guest manifest exceeds maximum entry budget of {MAX_SYNC_ENTRIES} entries"
                );
                anyhow::ensure!(
                    total_metadata_bytes <= MAX_SYNC_METADATA_BYTES,
                    "guest manifest exceeds maximum metadata budget of {MAX_SYNC_METADATA_BYTES} bytes"
                );
                anyhow::ensure!(
                    entries.insert(entry.relative_path.clone(), entry).is_none(),
                    "guest manifest contains a duplicate path"
                );
            }
            SyncReply::ScanComplete => break,
            other => anyhow::bail!("unexpected reply from agent during scan: {other:?}"),
        }
    }
    validate_manifest(&entries)?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn host_operations_refuse_existing_symlink_ancestors() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
        assert!(checked_host_path(root.path(), "link/file").is_err());
        assert!(checked_host_path(root.path(), "link").is_ok());
    }
}
