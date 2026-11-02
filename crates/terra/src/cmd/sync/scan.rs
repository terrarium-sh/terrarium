use super::exec::{COPY_DATA_TIMEOUT, read_reply, send_request};
use super::security::{to_guest_mode, validate_host_relative_path, validate_manifest};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Instant;
use terra_protocol::{
    MAX_SYNC_FILE_BYTES, SyncEntry, SyncEntryKind, SyncReply, SyncRequest, truncate_nanos,
    validate_relative_path,
};
use tokio::io::{AsyncRead, AsyncWrite};

const MAX_SYNC_ENTRIES: usize = 100_000;
const MAX_SYNC_METADATA_BYTES: usize = 16 * 1024 * 1024;
/// Fixed metadata a manifest entry costs on top of its path and link target.
const ENTRY_METADATA_OVERHEAD_BYTES: usize = 32;

/// Running entry and metadata budget for a sync manifest.
#[derive(Debug, Default)]
struct SyncManifestBudget {
    entries: usize,
    metadata_bytes: usize,
}

impl SyncManifestBudget {
    #[must_use]
    const fn with_existing_entries(entries: usize) -> Self {
        Self {
            entries,
            metadata_bytes: 0,
        }
    }

    fn add_entry(&mut self, path: &str, link_target: Option<&str>) -> Result<()> {
        let entries_exceeded = || {
            anyhow::anyhow!("manifest exceeds maximum entry budget of {MAX_SYNC_ENTRIES} entries")
        };
        let metadata_exceeded = || {
            anyhow::anyhow!(
                "manifest exceeds maximum metadata budget of {MAX_SYNC_METADATA_BYTES} bytes"
            )
        };
        self.entries = self.entries.checked_add(1).ok_or_else(entries_exceeded)?;
        if self.entries > MAX_SYNC_ENTRIES {
            return Err(entries_exceeded());
        }
        let metadata_bytes = path
            .len()
            .checked_add(link_target.map_or(0, str::len))
            .and_then(|bytes| bytes.checked_add(ENTRY_METADATA_OVERHEAD_BYTES))
            .ok_or_else(metadata_exceeded)?;
        self.metadata_bytes = self
            .metadata_bytes
            .checked_add(metadata_bytes)
            .ok_or_else(metadata_exceeded)?;
        if self.metadata_bytes > MAX_SYNC_METADATA_BYTES {
            return Err(metadata_exceeded());
        }
        Ok(())
    }
}

pub(super) fn optional_metadata(path: &Path) -> Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

/// `Path::join` with an empty `relative` would append a trailing separator.
pub(super) fn join_relative(root: &Path, relative: &str) -> PathBuf {
    if relative.is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative)
    }
}

pub(super) fn checked_host_path(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_host_relative_path(relative)?;
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
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
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

fn host_entry(path: &Path, meta: &std::fs::Metadata, relative_path: String) -> Result<SyncEntry> {
    let file_type = meta.file_type();
    let kind = if file_type.is_dir() {
        SyncEntryKind::Directory
    } else if file_type.is_symlink() {
        SyncEntryKind::Symlink {
            target: read_link_target(path)?,
        }
    } else if file_type.is_file() {
        anyhow::ensure!(
            meta.len() <= MAX_SYNC_FILE_BYTES,
            "file exceeds sync size limit"
        );
        SyncEntryKind::File { size: meta.len() }
    } else {
        anyhow::bail!("unsupported special file: {}", path.display());
    };
    Ok(SyncEntry {
        relative_path,
        kind,
        mode: to_guest_mode(meta),
        mtime_secs: meta_mtime_secs(meta),
        mtime_nanos: meta_mtime_nanos(meta),
    })
}

pub(super) fn single_host_entry_map(
    path: &Path,
    meta: &std::fs::Metadata,
) -> Result<BTreeMap<String, SyncEntry>> {
    let entry = host_entry(path, meta, String::new())?;
    Ok(BTreeMap::from([(String::new(), entry)]))
}

fn read_link_target(path: &Path) -> Result<String> {
    let target =
        std::fs::read_link(path).with_context(|| format!("reading link {}", path.display()))?;
    let target = target
        .to_str()
        .with_context(|| format!("non-UTF-8 symlink target in {}", path.display()))?
        .to_owned();
    #[cfg(windows)]
    let target = target.replace('\\', "/");
    Ok(target)
}

pub(super) fn scan_host_directory(root_path: &Path) -> Result<BTreeMap<String, SyncEntry>> {
    let mut entries = single_host_entry_map(root_path, &std::fs::symlink_metadata(root_path)?)?;
    let mut queue = VecDeque::new();
    queue.push_back(String::new());
    let mut budget = SyncManifestBudget::with_existing_entries(entries.len());

    while let Some(rel) = queue.pop_front() {
        let full = join_relative(root_path, &rel);
        let read_dir = std::fs::read_dir(&full)
            .with_context(|| format!("reading directory {}", full.display()))?;
        for entry_res in read_dir {
            let entry =
                entry_res.with_context(|| format!("reading entry in {}", full.display()))?;
            let file_name = entry.file_name();
            let name_str = file_name
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-utf8 filename in {}", full.display()))?;
            let child_rel = if rel.is_empty() {
                name_str.to_owned()
            } else {
                format!("{rel}/{name_str}")
            };
            validate_relative_path(&child_rel).map_err(anyhow::Error::msg)?;
            let child_full = join_relative(root_path, &child_rel);
            let meta = std::fs::symlink_metadata(&child_full)
                .with_context(|| format!("reading metadata of {}", child_full.display()))?;
            let sync_entry = host_entry(&child_full, &meta, child_rel.clone())?;
            budget.add_entry(&child_rel, sync_entry.kind.link_target())?;
            if sync_entry.kind == SyncEntryKind::Directory {
                queue.push_back(child_rel.clone());
            }
            entries.insert(child_rel, sync_entry);
        }
    }
    Ok(entries)
}

pub(super) async fn scan_guest_entries(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> Result<BTreeMap<String, SyncEntry>> {
    send_request(stream, &SyncRequest::ScanEntries).await?;
    let mut entries = BTreeMap::new();
    let mut budget = SyncManifestBudget::default();

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
                budget
                    .add_entry(&entry.relative_path, entry.kind.link_target())
                    .context("guest manifest")?;
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn host_operations_refuse_existing_symlink_ancestors() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
        assert!(checked_host_path(root.path(), "link/file").is_err());
        assert!(checked_host_path(root.path(), "link").is_ok());
    }
}

#[cfg(test)]
mod manifest_budget_tests {
    use super::*;

    #[test]
    fn manifest_budget_rejects_entries_and_metadata_after_the_limit() {
        let mut entry_budget = SyncManifestBudget::with_existing_entries(MAX_SYNC_ENTRIES - 1);
        assert!(entry_budget.add_entry("entry", None).is_ok());
        let error = entry_budget.add_entry("one-too-many", None).unwrap_err();
        assert!(error.to_string().contains("entry budget"), "{error:#}");

        let mut metadata_budget = SyncManifestBudget::default();
        let metadata = "a".repeat(MAX_SYNC_METADATA_BYTES - ENTRY_METADATA_OVERHEAD_BYTES);
        assert!(metadata_budget.add_entry(&metadata, None).is_ok());
        let error = metadata_budget.add_entry("a", None).unwrap_err();
        assert!(error.to_string().contains("metadata budget"), "{error:#}");
    }
}
