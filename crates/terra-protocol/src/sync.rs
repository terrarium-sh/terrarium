//! Wire protocol types for filesystem synchronization (`AgentService::Sync`).

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

/// Maximum file size supported by sync operations: 16 GiB.
pub const MAX_FILE_BYTES: u64 = 16 << 30;

/// Maximum entries permitted in a single sync manifest before refusing to proceed.
pub const MAX_SYNC_ENTRIES: usize = 100_000;

/// Maximum length in bytes of any relative or root path on the wire.
pub const MAX_SYNC_PATH_BYTES: usize = 4096;

/// Total budget on accumulated metadata bytes from untrusted manifest frames.
pub const MAX_SYNC_METADATA_BYTES: usize = 16 * 1024 * 1024;

/// Upper limit on untrusted error message frames from guest.
pub const MAX_SYNC_ERROR_BYTES: usize = 4096;

/// Deterministic timestamp precision in nanoseconds: 1 microsecond (1,000 ns).
/// Preserved identically across Linux ext4 (1 ns), APFS (1 ns), and Windows NTFS (100 ns).
pub const SYNC_TIMESTAMP_PRECISION_NANOS: u32 = 1_000;

/// Truncate nanoseconds to [`SYNC_TIMESTAMP_PRECISION_NANOS`].
#[must_use]
pub const fn truncate_nanos(nanos: u32) -> u32 {
    (nanos / SYNC_TIMESTAMP_PRECISION_NANOS) * SYNC_TIMESTAMP_PRECISION_NANOS
}

/// Synchronization direction relative to the host.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncDirection {
    HostToGuest,
    GuestToHost,
}

/// Kind of synchronized filesystem entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncEntryKind {
    File,
    Directory,
    Symlink,
}

/// A scanned filesystem entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncEntry {
    #[serde(deserialize_with = "deserialize_relative_path")]
    pub relative_path: String,
    pub kind: SyncEntryKind,
    #[serde(deserialize_with = "deserialize_sync_file_size")]
    pub size: u64,
    pub mode: u32,
    pub mtime_secs: i64,
    #[serde(deserialize_with = "deserialize_nanos")]
    pub mtime_nanos: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_target: Option<String>,
}

/// The status of the guest sync root at session startup.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RootStatus {
    ExistingDirectory,
    ExistingFile,
    ExistingSymlink,
    Missing,
}

/// Host requests sent to the guest agent over [`crate::AgentService::Sync`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncRequest {
    /// Open the sync session for a specific guest root.
    BeginSession {
        #[serde(deserialize_with = "deserialize_abs_path")]
        guest_root: String,
    },
    /// Scan and stream all entries within the session root.
    ScanEntries,
    /// Request SHA-256 digest of a regular file under the session root.
    ComputeDigest {
        #[serde(deserialize_with = "deserialize_relative_path")]
        relative_path: String,
    },
    /// Prepare to write a regular file into the guest. Followed by `size` raw bytes after `WriteFileReady`.
    WriteFile {
        #[serde(deserialize_with = "deserialize_relative_path")]
        relative_path: String,
        #[serde(deserialize_with = "deserialize_sync_file_size")]
        size: u64,
        mode: u32,
        mtime_secs: i64,
        #[serde(deserialize_with = "deserialize_nanos")]
        mtime_nanos: u32,
    },
    CommitFile,
    /// Prepare to read a regular file from the guest. Followed by `size` raw bytes from guest after `ReadFileReady`.
    ReadFile {
        #[serde(deserialize_with = "deserialize_relative_path")]
        relative_path: String,
    },
    /// Create a directory on the guest.
    CreateDir {
        #[serde(deserialize_with = "deserialize_relative_path")]
        relative_path: String,
        mode: u32,
    },
    /// Create a symbolic link on the guest.
    CreateSymlink {
        #[serde(deserialize_with = "deserialize_relative_path")]
        relative_path: String,
        target: String,
    },
    /// Update mode and timestamp of an existing guest entry without rewriting content.
    UpdateMetadata {
        #[serde(deserialize_with = "deserialize_relative_path")]
        relative_path: String,
        mode: u32,
        mtime_secs: i64,
        #[serde(deserialize_with = "deserialize_nanos")]
        mtime_nanos: u32,
    },
    /// Remove an entry under the session root.
    RemoveEntry {
        #[serde(deserialize_with = "deserialize_relative_path")]
        relative_path: String,
        is_dir: bool,
    },
    /// Gracefully end the sync session.
    EndSession,
}

/// Guest agent replies sent to the host over [`crate::AgentService::Sync`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncReply {
    /// The session has opened and resolved the guest root.
    SessionReady { root_status: RootStatus },
    /// One entry emitted during scanning.
    Entry(SyncEntry),
    /// All entries have been emitted.
    ScanComplete,
    /// Keepalive/progress update emitted while hashing large files.
    DigestProgress { bytes_hashed: u64 },
    /// Computed SHA-256 digest of a file.
    Digest { sha256: [u8; 32] },
    /// Agent is ready to receive `size` raw bytes for `WriteFile`.
    WriteFileReady,
    /// Agent is about to stream `size` raw bytes for `ReadFile`.
    ReadFileReady {
        #[serde(deserialize_with = "deserialize_sync_file_size")]
        size: u64,
        mode: u32,
        mtime_secs: i64,
        #[serde(deserialize_with = "deserialize_nanos")]
        mtime_nanos: u32,
    },
    /// Operation completed successfully.
    Success,
    /// Operation failed; untrusted guest-chosen error message.
    Err(#[serde(deserialize_with = "deserialize_sync_error")] String),
}

pub fn sync_file_times(seconds: i64, nanos: u32) -> std::io::Result<std::fs::FileTimes> {
    use std::time::{Duration, UNIX_EPOCH};
    let time = if seconds >= 0 {
        UNIX_EPOCH.checked_add(Duration::new(seconds.unsigned_abs(), nanos))
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(seconds.unsigned_abs()))
            .and_then(|time| time.checked_add(Duration::from_nanos(u64::from(nanos))))
    };
    time.map(|time| std::fs::FileTimes::new().set_modified(time))
        .ok_or_else(|| std::io::Error::other("modification time is outside the supported range"))
}

fn deserialize_abs_path<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let path = String::deserialize(deserializer)?;
    if path.is_empty() {
        return Err(D::Error::custom("guest path cannot be empty"));
    }
    if path.len() > MAX_SYNC_PATH_BYTES {
        return Err(D::Error::custom("guest path exceeds maximum length"));
    }
    if path.contains('\0') {
        return Err(D::Error::custom("guest path cannot contain NUL bytes"));
    }
    if !path.starts_with('/') {
        return Err(D::Error::custom("guest path must be absolute"));
    }
    Ok(path)
}

fn deserialize_relative_path<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let path = String::deserialize(deserializer)?;
    validate_relative_path(&path).map_err(D::Error::custom)?;
    Ok(path)
}

/// Validates that a relative path is safely bounded within the synchronized root.
/// Allows `""` to represent the root itself.
pub fn validate_relative_path(path: &str) -> Result<(), &'static str> {
    if path.is_empty() {
        return Ok(());
    }
    if path.len() > MAX_SYNC_PATH_BYTES {
        return Err("relative path exceeds maximum length");
    }
    if path.contains('\0') {
        return Err("relative path cannot contain NUL bytes");
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err("relative path cannot start with a path separator");
    }
    for component in path.split('/') {
        if component.is_empty() {
            return Err("relative path contains empty components");
        }
        if component == "." || component == ".." {
            return Err("relative path contains dot or dot-dot components");
        }
        #[cfg(windows)]
        if component.contains('\\') || component.contains(':') {
            return Err("relative path contains invalid Windows characters");
        }
    }
    Ok(())
}

fn deserialize_sync_file_size<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let size = u64::deserialize(deserializer)?;
    if size > MAX_FILE_BYTES {
        return Err(D::Error::custom(format!(
            "file size {size} exceeds the {MAX_FILE_BYTES}-byte limit"
        )));
    }
    Ok(size)
}

fn deserialize_nanos<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let nanos = u32::deserialize(deserializer)?;
    if nanos >= 1_000_000_000 {
        return Err(D::Error::custom("nanoseconds must be less than 1 billion"));
    }
    Ok(truncate_nanos(nanos))
}

fn deserialize_sync_error<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let message = String::deserialize(deserializer)?;
    if message.len() > MAX_SYNC_ERROR_BYTES {
        return Err(D::Error::custom("error message exceeds length limit"));
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_relative_path_properties() {
        assert!(validate_relative_path("").is_ok());
        assert!(validate_relative_path("foo").is_ok());
        assert!(validate_relative_path("foo/bar/baz.txt").is_ok());

        assert!(validate_relative_path("/foo").is_err());
        assert!(validate_relative_path("foo//bar").is_err());
        assert!(validate_relative_path("foo/./bar").is_err());
        assert!(validate_relative_path("foo/../bar").is_err());
        assert!(validate_relative_path("foo\0bar").is_err());
        assert!(validate_relative_path(&"a/".repeat(3000)).is_err());
    }

    #[test]
    fn nanosecond_truncation_is_deterministic() {
        assert_eq!(truncate_nanos(0), 0);
        assert_eq!(truncate_nanos(999), 0);
        assert_eq!(truncate_nanos(1_000), 1_000);
        assert_eq!(truncate_nanos(1_999), 1_000);
        assert_eq!(truncate_nanos(123_456_789), 123_456_000);
    }

    #[test]
    fn sync_requests_and_replies_round_trip() {
        let req = SyncRequest::BeginSession {
            guest_root: "/app".to_string(),
        };
        let encoded = serde_json::to_string(&req).unwrap();
        let decoded: SyncRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(req, decoded);

        let entry = SyncEntry {
            relative_path: "src/main.rs".to_string(),
            kind: SyncEntryKind::File,
            size: 1024,
            mode: 0o644,
            mtime_secs: 1_700_000_000,
            mtime_nanos: 500_000,
            link_target: None,
        };
        let rep = SyncReply::Entry(entry);
        let encoded = serde_json::to_string(&rep).unwrap();
        let decoded: SyncReply = serde_json::from_str(&encoded).unwrap();
        assert_eq!(rep, decoded);
    }

    #[test]
    fn reject_oversized_file_size() {
        let json = serde_json::json!({
            "WriteFile": {
                "relative_path": "big.bin",
                "size": MAX_FILE_BYTES + 1,
                "mode": 0o644,
                "mtime_secs": 0,
                "mtime_nanos": 0,
            }
        });
        assert!(serde_json::from_value::<SyncRequest>(json).is_err());
    }

    #[test]
    fn reject_invalid_nanoseconds() {
        let json = serde_json::json!({
            "WriteFile": {
                "relative_path": "time.bin",
                "size": 10,
                "mode": 0o644,
                "mtime_secs": 0,
                "mtime_nanos": 1_000_000_000,
            }
        });
        assert!(serde_json::from_value::<SyncRequest>(json).is_err());
    }
}
