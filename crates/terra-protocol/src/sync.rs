//! Wire protocol types for filesystem synchronization (`AgentService::Sync`).

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

pub const MAX_SYNC_FILE_BYTES: u64 = 16 << 30;
pub const MAX_SYNC_PATH_BYTES: usize = 4096;

/// Microseconds survive ext4 and APFS (1 ns) as well as NTFS (100 ns).
const SYNC_TIMESTAMP_PRECISION_NANOS: u32 = 1_000;

#[must_use]
pub const fn truncate_nanos(nanos: u32) -> u32 {
    (nanos / SYNC_TIMESTAMP_PRECISION_NANOS) * SYNC_TIMESTAMP_PRECISION_NANOS
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncEntryKind {
    File {
        #[serde(deserialize_with = "deserialize_sync_file_size")]
        size: u64,
    },
    Directory,
    Symlink {
        target: String,
    },
}

impl SyncEntryKind {
    #[must_use]
    pub fn link_target(&self) -> Option<&str> {
        match self {
            Self::Symlink { target } => Some(target),
            Self::File { .. } | Self::Directory => None,
        }
    }
}

/// A scanned filesystem entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncEntry {
    #[serde(deserialize_with = "deserialize_relative_path")]
    pub relative_path: String,
    pub kind: SyncEntryKind,
    pub mode: u32,
    pub mtime_secs: i64,
    #[serde(deserialize_with = "deserialize_nanos")]
    pub mtime_nanos: u32,
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
    BeginSession {
        #[serde(deserialize_with = "deserialize_abs_path")]
        guest_root: String,
    },
    ScanEntries,
    ComputeDigest {
        #[serde(deserialize_with = "deserialize_relative_path")]
        relative_path: String,
    },
    /// `size` raw bytes follow once the agent replies `WriteFileReady`.
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
    ReadFile {
        #[serde(deserialize_with = "deserialize_relative_path")]
        relative_path: String,
    },
    CreateDir {
        #[serde(deserialize_with = "deserialize_relative_path")]
        relative_path: String,
        mode: u32,
    },
    CreateSymlink {
        #[serde(deserialize_with = "deserialize_relative_path")]
        relative_path: String,
        target: String,
    },
    UpdateMetadata {
        #[serde(deserialize_with = "deserialize_relative_path")]
        relative_path: String,
        mode: u32,
        mtime_secs: i64,
        #[serde(deserialize_with = "deserialize_nanos")]
        mtime_nanos: u32,
    },
    RemoveEntry {
        #[serde(deserialize_with = "deserialize_relative_path")]
        relative_path: String,
    },
    EndSession,
}

impl crate::Message for SyncRequest {
    /// A symlink's path and target, plus the variant's fixed fields.
    const MAX_PAYLOAD_BYTES: usize = 2 * MAX_SYNC_PATH_BYTES + 64;
}

/// Guest agent replies sent to the host over [`crate::AgentService::Sync`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncReply {
    SessionReady {
        root_status: RootStatus,
    },
    Entry(SyncEntry),
    ScanComplete,
    /// Keeps the host waiting while a large file hashes.
    DigestProgress {
        bytes_hashed: u64,
    },
    Digest {
        sha256: [u8; 32],
    },
    WriteFileReady,
    /// `size` raw bytes follow this reply.
    ReadFileReady {
        #[serde(deserialize_with = "deserialize_sync_file_size")]
        size: u64,
        mode: u32,
        mtime_secs: i64,
        #[serde(deserialize_with = "deserialize_nanos")]
        mtime_nanos: u32,
    },
    Success,
    Err(String),
}

impl crate::Message for SyncReply {
    const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
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
    if !path.starts_with('/') {
        return Err(D::Error::custom("guest path must be absolute"));
    }
    validate_wire_path(&path).map_err(D::Error::custom)?;
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

fn validate_wire_path(path: &str) -> Result<(), &'static str> {
    if path.len() > MAX_SYNC_PATH_BYTES {
        return Err("path exceeds maximum length");
    }
    if path.contains('\0') {
        return Err("path cannot contain NUL bytes");
    }
    Ok(())
}

/// Validates the slash-separated relative path syntax used on the wire.
/// Allows `""` to represent the synchronized root.
pub fn validate_relative_path(path: &str) -> Result<(), &'static str> {
    if path.is_empty() {
        return Ok(());
    }
    validate_wire_path(path)?;
    for component in path.split('/') {
        if component.is_empty() {
            return Err("relative path contains empty components");
        }
        if component == "." || component == ".." {
            return Err("relative path contains dot or dot-dot components");
        }
    }
    Ok(())
}

fn deserialize_sync_file_size<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let size = u64::deserialize(deserializer)?;
    if size > MAX_SYNC_FILE_BYTES {
        return Err(D::Error::custom("file size exceeds the sync limit"));
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
    fn wire_paths_are_platform_neutral() {
        assert!(validate_relative_path("dir\\name/file:name").is_ok());
        assert!(validate_relative_path("\\foo").is_ok());
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
        let encoded = crate::encode_frame(&req).unwrap();
        let decoded: SyncRequest = crate::read_frame(&mut encoded.as_slice()).unwrap().unwrap();
        assert_eq!(req, decoded);

        let entry = SyncEntry {
            relative_path: "src/main.rs".to_string(),
            kind: SyncEntryKind::File { size: 1024 },
            mode: 0o644,
            mtime_secs: 1_700_000_000,
            mtime_nanos: 500_000,
        };
        let rep = SyncReply::Entry(entry);
        let encoded = crate::encode_frame(&rep).unwrap();
        let decoded: SyncReply = crate::read_frame(&mut encoded.as_slice()).unwrap().unwrap();
        assert_eq!(rep, decoded);
    }

    #[test]
    fn binary_sync_requests_reject_invalid_metadata() {
        for (path, size, nanos) in [
            ("big.bin", MAX_SYNC_FILE_BYTES + 1, 0),
            ("time.bin", 10, 1_000_000_000),
            ("../escape", 10, 0),
        ] {
            let request = SyncRequest::WriteFile {
                relative_path: path.into(),
                size,
                mode: 0o644,
                mtime_secs: 0,
                mtime_nanos: nanos,
            };
            let frame = crate::encode_frame(&request).unwrap();
            assert!(crate::read_frame::<SyncRequest>(&mut frame.as_slice()).is_err());
        }
    }

    #[test]
    fn sync_entries_reject_oversized_file_size() {
        let entry = SyncEntry {
            relative_path: "big.bin".into(),
            kind: SyncEntryKind::File {
                size: MAX_SYNC_FILE_BYTES + 1,
            },
            mode: 0o644,
            mtime_secs: 0,
            mtime_nanos: 0,
        };
        let frame = crate::encode_frame(&SyncReply::Entry(entry)).unwrap();
        assert!(crate::read_frame::<SyncReply>(&mut frame.as_slice()).is_err());
    }

    #[test]
    fn the_largest_requests_fit_the_request_limit() {
        let relative_path = "a".repeat(MAX_SYNC_PATH_BYTES);
        for request in [
            SyncRequest::CreateSymlink {
                relative_path: relative_path.clone(),
                target: "b".repeat(MAX_SYNC_PATH_BYTES),
            },
            SyncRequest::WriteFile {
                relative_path: relative_path.clone(),
                size: MAX_SYNC_FILE_BYTES,
                mode: u32::MAX,
                mtime_secs: i64::MIN,
                mtime_nanos: 999_999_000,
            },
            SyncRequest::UpdateMetadata {
                relative_path,
                mode: u32::MAX,
                mtime_secs: i64::MIN,
                mtime_nanos: 999_999_000,
            },
        ] {
            let frame = crate::encode_frame(&request).unwrap();
            assert_eq!(
                crate::read_frame::<SyncRequest>(&mut frame.as_slice()).unwrap(),
                Some(request)
            );
        }
    }

    #[test]
    fn the_largest_replies_fit_the_reply_limit() {
        for reply in [
            SyncReply::Entry(SyncEntry {
                relative_path: "a".repeat(MAX_SYNC_PATH_BYTES),
                kind: SyncEntryKind::Symlink {
                    target: "b".repeat(MAX_SYNC_PATH_BYTES),
                },
                mode: u32::MAX,
                mtime_secs: i64::MIN,
                mtime_nanos: 999_999_000,
            }),
            SyncReply::ReadFileReady {
                size: MAX_SYNC_FILE_BYTES,
                mode: u32::MAX,
                mtime_secs: i64::MIN,
                mtime_nanos: 999_999_000,
            },
        ] {
            let frame = crate::encode_frame(&reply).unwrap();
            assert_eq!(
                crate::read_frame::<SyncReply>(&mut frame.as_slice()).unwrap(),
                Some(reply)
            );
        }
    }
}
