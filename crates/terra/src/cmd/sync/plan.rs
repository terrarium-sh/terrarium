use super::exec::{COPY_DATA_TIMEOUT, read_reply, send_request};
use super::names::HostNames;
use super::scan::{optional_metadata, scan_host_directory};
use super::security::{effective_mode, validate_download_links, validate_manifest};
use crate::sys;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use std::time::Instant;
use terra_protocol::{
    MAX_FILE_BYTES, SyncDirection, SyncEntry, SyncEntryKind, SyncReply, SyncRequest,
};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum PlanAction {
    CreateDir {
        rel_path: String,
        mode: u32,
    },
    TransferFile {
        rel_path: String,
        size: u64,
        mode: u32,
        mtime_secs: i64,
        mtime_nanos: u32,
    },
    CreateSymlink {
        rel_path: String,
        target: String,
    },
    UpdateFileMetadata {
        rel_path: String,
        mode: u32,
        mtime_secs: i64,
        mtime_nanos: u32,
    },
    UpdateDirMetadata {
        rel_path: String,
        mode: u32,
        mtime_secs: i64,
        mtime_nanos: u32,
    },
    RemoveEntry {
        rel_path: String,
        is_dir: bool,
    },
    Skip {
        rel_path: String,
    },
}

pub(super) fn validate_plan_conflicts(
    source_entries: &BTreeMap<String, SyncEntry>,
    target_entries: &BTreeMap<String, SyncEntry>,
) -> Result<()> {
    validate_manifest(source_entries)?;
    validate_manifest(target_entries)?;

    for (path, src) in source_entries {
        if let Some(dst) = target_entries.get(path) {
            if src.kind == SyncEntryKind::Directory && dst.kind != SyncEntryKind::Directory {
                anyhow::bail!(
                    "cannot overwrite file/symlink '{path}' with a directory; remove the file/symlink first"
                );
            }
            if src.kind != SyncEntryKind::Directory && dst.kind == SyncEntryKind::Directory {
                anyhow::bail!(
                    "cannot overwrite directory '{path}' with a file/symlink; remove the directory first"
                );
            }
        }
    }
    Ok(())
}

fn hash_file_worker(path: &Path) -> Result<[u8; 32]> {
    let mut file = sys::open_regular_file(path)?;
    let before = file.metadata()?;
    let deadline = Instant::now() + COPY_DATA_TIMEOUT;
    let mut total_bytes = 0_u64;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        anyhow::ensure!(
            Instant::now() < deadline && total_bytes <= MAX_FILE_BYTES,
            "hashing exceeded its limit"
        );
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buf[..n]);
                total_bytes += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    let after = file.metadata()?;
    anyhow::ensure!(
        before.len() == after.len() && before.modified()? == after.modified()?,
        "source changed while hashing"
    );
    Ok(hasher.finalize().into())
}

async fn compute_checksum_pair(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    guest_rel_path: &str,
    host_file_path: &Path,
    guest_is_source: bool,
) -> Result<([u8; 32], [u8; 32])> {
    send_request(
        stream,
        &SyncRequest::ComputeDigest {
            relative_path: guest_rel_path.to_string(),
        },
    )
    .await?;

    let local_path = host_file_path.to_path_buf();
    let host_hash = tokio::task::spawn_blocking(move || hash_file_worker(&local_path));

    let deadline = Instant::now() + COPY_DATA_TIMEOUT;
    let guest_sha = loop {
        anyhow::ensure!(
            Instant::now() < deadline,
            "checksum exceeded its time limit"
        );
        match read_reply(stream).await? {
            SyncReply::DigestProgress { .. } => {}
            SyncReply::Digest { sha256 } => break sha256,
            other => anyhow::bail!("unexpected reply from agent during digest: {other:?}"),
        }
    };

    let host_sha = tokio::time::timeout(
        deadline.saturating_duration_since(Instant::now()),
        host_hash,
    )
    .await
    .context("local hashing worker timed out")?
    .context("local hashing worker failed")??;

    if guest_is_source {
        Ok((guest_sha, host_sha))
    } else {
        Ok((host_sha, guest_sha))
    }
}

#[allow(clippy::too_many_arguments)]
async fn plan_file_update(
    rel_path: &str,
    src: &SyncEntry,
    dst: &SyncEntry,
    is_checksum: bool,
    direction: SyncDirection,
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    host_target_root: &Path,
    host_source_root: &Path,
) -> Result<PlanAction> {
    if dst.kind != SyncEntryKind::File || src.size != dst.size {
        return Ok(PlanAction::TransferFile {
            rel_path: rel_path.to_string(),
            size: src.size,
            mode: src.mode,
            mtime_secs: src.mtime_secs,
            mtime_nanos: src.mtime_nanos,
        });
    }

    let is_identical = if is_checksum {
        let (host_file_path, guest_is_src) = match direction {
            SyncDirection::HostToGuest => (
                if rel_path.is_empty() {
                    host_source_root.to_path_buf()
                } else {
                    host_source_root.join(rel_path)
                },
                false,
            ),
            SyncDirection::GuestToHost => (
                if rel_path.is_empty() {
                    host_target_root.to_path_buf()
                } else {
                    host_target_root.join(rel_path)
                },
                true,
            ),
        };
        let (src_sha, dst_sha) =
            compute_checksum_pair(stream, rel_path, &host_file_path, guest_is_src).await?;
        src_sha == dst_sha
    } else {
        src.mtime_secs == dst.mtime_secs && src.mtime_nanos == dst.mtime_nanos
    };

    if is_identical {
        let mode_differs = effective_mode(src.mode, direction, src.kind) != dst.mode;
        let mtime_differs = src.mtime_secs != dst.mtime_secs || src.mtime_nanos != dst.mtime_nanos;
        if mode_differs || mtime_differs {
            Ok(PlanAction::UpdateFileMetadata {
                rel_path: rel_path.to_string(),
                mode: src.mode,
                mtime_secs: src.mtime_secs,
                mtime_nanos: src.mtime_nanos,
            })
        } else {
            Ok(PlanAction::Skip {
                rel_path: rel_path.to_string(),
            })
        }
    } else {
        Ok(PlanAction::TransferFile {
            rel_path: rel_path.to_string(),
            size: src.size,
            mode: src.mode,
            mtime_secs: src.mtime_secs,
            mtime_nanos: src.mtime_nanos,
        })
    }
}

fn find_changed_parent(action: &PlanAction) -> Option<String> {
    let path = match action {
        PlanAction::CreateDir { rel_path, .. }
        | PlanAction::TransferFile { rel_path, .. }
        | PlanAction::CreateSymlink { rel_path, .. }
        | PlanAction::RemoveEntry { rel_path, .. } => rel_path,
        PlanAction::UpdateFileMetadata { .. }
        | PlanAction::UpdateDirMetadata { .. }
        | PlanAction::Skip { .. } => return None,
    };
    (!path.is_empty()).then(|| {
        path.rsplit_once('/')
            .map_or("", |(parent, _)| parent)
            .to_owned()
    })
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub(super) async fn build_plan(
    source_entries: &BTreeMap<String, SyncEntry>,
    target_entries: &BTreeMap<String, SyncEntry>,
    is_checksum: bool,
    is_delete: bool,
    direction: SyncDirection,
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    host_target_root: &Path,
    host_source_root: &Path,
) -> Result<Vec<PlanAction>> {
    validate_plan_conflicts(source_entries, target_entries)?;
    if direction == SyncDirection::GuestToHost {
        let standalone_source;
        let sibling_entries;
        let (link_root, link_source, link_target) = if let Some(entry) = source_entries
            .get("")
            .filter(|entry| entry.kind == SyncEntryKind::Symlink)
        {
            let parent = host_target_root
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let name = host_target_root
                .file_name()
                .and_then(|name| name.to_str())
                .context("symlink destination name is not valid UTF-8")?;
            let mut entry = entry.clone();
            name.clone_into(&mut entry.relative_path);
            standalone_source = BTreeMap::from([(name.to_owned(), entry)]);
            sibling_entries = if optional_metadata(parent)?.is_some() {
                scan_host_directory(parent)?
            } else {
                BTreeMap::new()
            };
            (parent, &standalone_source, &sibling_entries)
        } else {
            (host_target_root, source_entries, target_entries)
        };
        let names = HostNames::new(link_root, link_source, link_target)?;
        let validation = validate_download_links(link_source, link_target, &|parent, component| {
            names.resolve_component(parent, component)
        });
        let cleanup = names.close();
        validation?;
        cleanup?;
    }

    let mut actions = Vec::new();
    for (rel_path, src) in source_entries {
        match target_entries.get(rel_path) {
            None => match src.kind {
                SyncEntryKind::Directory => {
                    actions.push(PlanAction::CreateDir {
                        rel_path: rel_path.clone(),
                        mode: src.mode,
                    });
                    actions.push(PlanAction::UpdateDirMetadata {
                        rel_path: rel_path.clone(),
                        mode: src.mode,
                        mtime_secs: src.mtime_secs,
                        mtime_nanos: src.mtime_nanos,
                    });
                }
                SyncEntryKind::File => {
                    actions.push(PlanAction::TransferFile {
                        rel_path: rel_path.clone(),
                        size: src.size,
                        mode: src.mode,
                        mtime_secs: src.mtime_secs,
                        mtime_nanos: src.mtime_nanos,
                    });
                }
                SyncEntryKind::Symlink => {
                    let target = src.link_target.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("symlink entry missing target: {rel_path}")
                    })?;
                    actions.push(PlanAction::CreateSymlink {
                        rel_path: rel_path.clone(),
                        target: target.clone(),
                    });
                }
            },
            Some(dst) => match src.kind {
                SyncEntryKind::Directory => {
                    let mode_differs = effective_mode(src.mode, direction, src.kind) != dst.mode;
                    let mtime_differs =
                        src.mtime_secs != dst.mtime_secs || src.mtime_nanos != dst.mtime_nanos;
                    if mode_differs || mtime_differs {
                        actions.push(PlanAction::UpdateDirMetadata {
                            rel_path: rel_path.clone(),
                            mode: src.mode,
                            mtime_secs: src.mtime_secs,
                            mtime_nanos: src.mtime_nanos,
                        });
                    } else {
                        actions.push(PlanAction::Skip {
                            rel_path: rel_path.clone(),
                        });
                    }
                }
                SyncEntryKind::Symlink => {
                    if dst.kind != SyncEntryKind::Symlink || src.link_target != dst.link_target {
                        let target = src.link_target.as_ref().ok_or_else(|| {
                            anyhow::anyhow!("symlink entry missing target: {rel_path}")
                        })?;
                        actions.push(PlanAction::CreateSymlink {
                            rel_path: rel_path.clone(),
                            target: target.clone(),
                        });
                    } else {
                        actions.push(PlanAction::Skip {
                            rel_path: rel_path.clone(),
                        });
                    }
                }
                SyncEntryKind::File => {
                    actions.push(
                        plan_file_update(
                            rel_path,
                            src,
                            dst,
                            is_checksum,
                            direction,
                            stream,
                            host_target_root,
                            host_source_root,
                        )
                        .await?,
                    );
                }
            },
        }
    }

    for (rel_path, dst) in target_entries {
        if !rel_path.is_empty() && !source_entries.contains_key(rel_path) {
            if is_delete {
                actions.push(PlanAction::RemoveEntry {
                    rel_path: rel_path.clone(),
                    is_dir: dst.kind == SyncEntryKind::Directory,
                });
            } else {
                actions.push(PlanAction::Skip {
                    rel_path: rel_path.clone(),
                });
            }
        }
    }

    let changed_parents: BTreeSet<String> =
        actions.iter().filter_map(find_changed_parent).collect();
    for action in &mut actions {
        if let PlanAction::Skip { rel_path } = action
            && changed_parents.contains(rel_path)
            && let Some(source) = source_entries.get(rel_path)
            && source.kind == SyncEntryKind::Directory
        {
            *action = PlanAction::UpdateDirMetadata {
                rel_path: rel_path.clone(),
                mode: source.mode,
                mtime_secs: source.mtime_secs,
                mtime_nanos: source.mtime_nanos,
            };
        }
    }

    Ok(actions)
}

#[cfg(test)]
mod tests {
    use super::super::test_support::peer;
    use super::*;
    use std::assert_matches;

    #[tokio::test]
    async fn directory_updates_follow_actual_child_mutations() {
        use super::super::test_support::entry;

        for direction in [SyncDirection::HostToGuest, SyncDirection::GuestToHost] {
            let root = tempfile::tempdir().unwrap();
            let mut unchanged = BTreeMap::new();
            for path in ["", "changed", "changed/nested", "untouched"] {
                std::fs::create_dir_all(root.path().join(path)).unwrap();
                unchanged.insert(path.into(), entry(path, SyncEntryKind::Directory, None));
            }
            let path = "changed/nested/file";
            let file = entry(path, SyncEntryKind::File, None);
            let mut replaced = file.clone();
            replaced.mtime_secs += 1;
            let mut metadata_only = file.clone();
            metadata_only.mode = 0o644;
            let directory = entry(path, SyncEntryKind::Directory, None);
            let link = entry(path, SyncEntryKind::Symlink, Some("../nested"));
            for (source_file, target_file, is_delete, expected) in [
                (Some(file.clone()), Some(file.clone()), false, vec![]),
                (
                    Some(file.clone()),
                    Some(replaced),
                    false,
                    vec!["changed/nested"],
                ),
                (Some(metadata_only), Some(file.clone()), false, vec![]),
                (Some(file.clone()), None, false, vec!["changed/nested"]),
                (None, Some(file.clone()), true, vec!["changed/nested"]),
                (None, Some(file.clone()), false, vec![]),
                (Some(link), None, false, vec!["changed/nested"]),
                (Some(directory), None, false, vec!["changed/nested", path]),
            ] {
                let mut source = unchanged.clone();
                let mut target = unchanged.clone();
                source.extend(source_file.map(|entry| (path.into(), entry)));
                target.extend(target_file.map(|entry| (path.into(), entry)));
                for entry in target.values_mut() {
                    entry.mode = effective_mode(entry.mode, direction, entry.kind);
                }
                let actions = build_plan(
                    &source,
                    &target,
                    false,
                    is_delete,
                    direction,
                    &mut peer(&[]),
                    root.path(),
                    root.path(),
                )
                .await
                .unwrap();
                let updates: Vec<_> = actions
                    .iter()
                    .filter_map(|action| match action {
                        PlanAction::UpdateDirMetadata { rel_path, .. } => Some(rel_path.as_str()),
                        _ => None,
                    })
                    .collect();
                assert_eq!(updates, expected, "{direction:?}: {actions:?}");
            }
        }
    }

    #[tokio::test]
    async fn root_child_changes_and_directory_metadata_are_both_preserved() {
        use super::super::test_support::entry;

        let target: BTreeMap<_, _> = [
            entry("", SyncEntryKind::Directory, None),
            entry("metadata", SyncEntryKind::Directory, None),
        ]
        .into_iter()
        .map(|entry| (entry.relative_path.clone(), entry))
        .collect();
        let mut source = target.clone();
        source.get_mut("metadata").unwrap().mtime_secs += 1;
        source.insert("file".into(), entry("file", SyncEntryKind::File, None));
        let actions = build_plan(
            &source,
            &target,
            false,
            false,
            SyncDirection::HostToGuest,
            &mut peer(&[]),
            Path::new("."),
            Path::new("."),
        )
        .await
        .unwrap();
        assert_matches!(
            &actions[0],
            PlanAction::UpdateDirMetadata { rel_path, .. } if rel_path.is_empty()
        );
        assert_matches!(
            &actions[2],
            PlanAction::UpdateDirMetadata { rel_path, mtime_secs: 101, .. } if rel_path == "metadata"
        );
    }

    /// Equal metadata can hide a checksum-detected replacement, which still changes the parent mtime.
    #[tokio::test]
    async fn checksum_replacement_restores_only_the_direct_parent() {
        use super::super::test_support::entry;

        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("nested")).unwrap();
        std::fs::write(root.path().join("nested/file"), []).unwrap();
        let source: BTreeMap<_, _> = [
            entry("", SyncEntryKind::Directory, None),
            entry("nested", SyncEntryKind::Directory, None),
            entry("nested/file", SyncEntryKind::File, None),
        ]
        .into_iter()
        .map(|entry| (entry.relative_path.clone(), entry))
        .collect();
        let actions = build_plan(
            &source,
            &source,
            true,
            false,
            SyncDirection::HostToGuest,
            &mut peer(&[SyncReply::Digest { sha256: [0; 32] }]),
            root.path(),
            root.path(),
        )
        .await
        .unwrap();
        assert_matches!(&actions[0], PlanAction::Skip { rel_path } if rel_path.is_empty());
        assert_matches!(
            &actions[1],
            PlanAction::UpdateDirMetadata { rel_path, .. } if rel_path == "nested"
        );
        assert_matches!(&actions[2], PlanAction::TransferFile { .. });
    }

    #[tokio::test]
    #[ignore = "microbenchmark: run in release mode with --ignored --nocapture"]
    async fn benchmark_one_file_delta_directory_updates() {
        use super::super::exec::execute_plan;
        use super::super::test_support::entry;
        use terra_protocol::{read_frame_async, write_frame_async};

        let mut source = BTreeMap::new();
        for path in
            std::iter::once(String::new()).chain((0..10_000).map(|index| format!("dir{index:05}")))
        {
            source.insert(path.clone(), entry(&path, SyncEntryKind::Directory, None));
        }
        let path = "dir00000/file";
        source.insert(path.into(), entry(path, SyncEntryKind::File, None));
        let mut target = source.clone();
        target.get_mut(path).unwrap().mtime_secs += 1;
        for sample in 0..11 {
            let start = Instant::now();
            let actions = build_plan(
                &source,
                &target,
                false,
                false,
                SyncDirection::HostToGuest,
                &mut peer(&[]),
                Path::new("."),
                Path::new("."),
            )
            .await
            .unwrap();
            let planning = start.elapsed();
            let updates: Vec<_> = actions
                .into_iter()
                .filter(|action| matches!(action, PlanAction::UpdateDirMetadata { .. }))
                .collect();
            let (mut client, mut server) = tokio::io::duplex(4096);
            let respond = async {
                let mut requests = 0;
                loop {
                    let request: SyncRequest =
                        read_frame_async(&mut server).await.unwrap().unwrap();
                    write_frame_async(&mut server, &SyncReply::Success)
                        .await
                        .unwrap();
                    if matches!(request, SyncRequest::EndSession) {
                        break;
                    }
                    assert_matches!(request, SyncRequest::UpdateMetadata { .. });
                    requests += 1;
                }
                requests
            };
            let start = Instant::now();
            let (result, requests) = tokio::join!(
                execute_plan(
                    &updates,
                    SyncDirection::HostToGuest,
                    &mut client,
                    Path::new("."),
                    Path::new("."),
                    false
                ),
                respond,
            );
            result.unwrap();
            assert_eq!(requests, updates.len());
            if sample != 0 {
                println!(
                    "sync_bench sample={sample} directories=10001 updates={requests} plan_ns={} metadata_protocol_ns={}",
                    planning.as_nanos(),
                    start.elapsed().as_nanos()
                );
            }
        }
    }

    #[tokio::test]
    async fn plan_detects_conflicts_between_directories_and_files() {
        let mut source = BTreeMap::new();
        source.insert(
            "conflict".to_string(),
            SyncEntry {
                relative_path: "conflict".to_string(),
                kind: SyncEntryKind::Directory,
                size: 0,
                mode: 0o755,
                mtime_secs: 100,
                mtime_nanos: 0,
                link_target: None,
            },
        );
        let mut target = BTreeMap::new();
        target.insert(
            "conflict".to_string(),
            SyncEntry {
                relative_path: "conflict".to_string(),
                kind: SyncEntryKind::File,
                size: 10,
                mode: 0o644,
                mtime_secs: 100,
                mtime_nanos: 0,
                link_target: None,
            },
        );

        let mut dummy = peer(&[]);
        let err = build_plan(
            &source,
            &target,
            false,
            false,
            SyncDirection::HostToGuest,
            &mut dummy,
            Path::new("/dummy"),
            Path::new("/dummy"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("cannot overwrite file"), "{err}");

        // Reverse: source file over target directory
        let err2 = build_plan(
            &target,
            &source,
            false,
            false,
            SyncDirection::HostToGuest,
            &mut dummy,
            Path::new("/dummy"),
            Path::new("/dummy"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err2.contains("cannot overwrite directory"), "{err2}");
    }

    #[tokio::test]
    async fn plan_deletions_gated_by_delete_flag() {
        let source = BTreeMap::new();
        let mut target = BTreeMap::new();
        target.insert(
            "extra.txt".to_string(),
            SyncEntry {
                relative_path: "extra.txt".to_string(),
                kind: SyncEntryKind::File,
                size: 10,
                mode: 0o644,
                mtime_secs: 100,
                mtime_nanos: 0,
                link_target: None,
            },
        );

        let mut dummy = peer(&[]);
        // Without --delete: extra is skipped
        let plan_no_delete = build_plan(
            &source,
            &target,
            false,
            false,
            SyncDirection::HostToGuest,
            &mut dummy,
            Path::new("/dummy"),
            Path::new("/dummy"),
        )
        .await
        .unwrap();
        assert_eq!(
            plan_no_delete,
            vec![PlanAction::Skip {
                rel_path: "extra.txt".to_string(),
            }]
        );

        // With --delete: extra is planned for removal
        let plan_with_delete = build_plan(
            &source,
            &target,
            false,
            true,
            SyncDirection::HostToGuest,
            &mut dummy,
            Path::new("/dummy"),
            Path::new("/dummy"),
        )
        .await
        .unwrap();
        assert_eq!(
            plan_with_delete,
            vec![PlanAction::RemoveEntry {
                rel_path: "extra.txt".to_string(),
                is_dir: false,
            }]
        );
    }

    #[tokio::test]
    async fn plan_skips_when_metadata_matches_and_updates_when_it_differs() {
        let make_entry = |mode: u32, mtime_secs: i64| SyncEntry {
            relative_path: "file.txt".to_string(),
            kind: SyncEntryKind::File,
            size: 42,
            mode,
            mtime_secs,
            mtime_nanos: 0,
            link_target: None,
        };

        let mut source = BTreeMap::new();
        source.insert("file.txt".to_string(), make_entry(0o644, 100));

        // Matching target: skip
        let mut target_match = BTreeMap::new();
        target_match.insert("file.txt".to_string(), make_entry(0o644, 100));

        let mut dummy = peer(&[]);
        let plan_match = build_plan(
            &source,
            &target_match,
            false,
            false,
            SyncDirection::HostToGuest,
            &mut dummy,
            Path::new("/dummy"),
            Path::new("/dummy"),
        )
        .await
        .unwrap();
        assert_eq!(
            plan_match,
            vec![PlanAction::Skip {
                rel_path: "file.txt".to_string()
            }]
        );

        // Mode differs but same size and timestamp: metadata update only
        let mut target_mode_diff = BTreeMap::new();
        target_mode_diff.insert("file.txt".to_string(), make_entry(0o755, 100));

        let plan_mode_diff = build_plan(
            &source,
            &target_mode_diff,
            false,
            false,
            SyncDirection::HostToGuest,
            &mut dummy,
            Path::new("/dummy"),
            Path::new("/dummy"),
        )
        .await
        .unwrap();
        assert_eq!(
            plan_mode_diff,
            vec![PlanAction::UpdateFileMetadata {
                rel_path: "file.txt".to_string(),
                mode: 0o644,
                mtime_secs: 100,
                mtime_nanos: 0,
            }]
        );

        // Timestamp differs: body transfer
        let mut target_mtime_diff = BTreeMap::new();
        target_mtime_diff.insert("file.txt".to_string(), make_entry(0o644, 200));

        let plan_mtime_diff = build_plan(
            &source,
            &target_mtime_diff,
            false,
            false,
            SyncDirection::HostToGuest,
            &mut dummy,
            Path::new("/dummy"),
            Path::new("/dummy"),
        )
        .await
        .unwrap();
        assert_eq!(
            plan_mtime_diff,
            vec![PlanAction::TransferFile {
                rel_path: "file.txt".to_string(),
                size: 42,
                mode: 0o644,
                mtime_secs: 100,
                mtime_nanos: 0,
            }]
        );
    }
}
