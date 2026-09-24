//! One-way file and directory synchronization between the host and a running box.

mod endpoint;
mod exec;
mod names;
mod plan;
mod scan;
mod security;
#[cfg(test)]
mod test_support;

use self::endpoint::{
    DestinationPlacement, GuestEndpoint, HostEndpoint, SourcePlacement, Transfer, parse_endpoints,
    resolve_placement,
};
use self::exec::{SyncStats, execute_plan, read_reply, send_request};
use self::plan::build_plan;
use self::scan::{
    optional_metadata, scan_guest_entries, scan_host_directory, single_host_entry_map,
};
use self::security::validate_root_kind;
use crate::cli::SyncArgs;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use terra_protocol::{AgentService, RootStatus, SyncDirection, SyncReply, SyncRequest};
use tokio::io::{AsyncRead, AsyncWrite};

/// Synchronize a file or directory tree between the host and a running box.
pub async fn run(args: &SyncArgs, name: Option<&str>, project_dir: &Path) -> Result<ExitCode> {
    let transfer = parse_endpoints(&args.src, &args.dst)?;
    let bx = &crate::resolve::resolve_pinned_box(project_dir, name)?;

    let mut stream = crate::session::connect_to_running_agent(
        bx,
        "sync",
        AgentService::Sync,
        "sync service",
        args.agent.agent_timeout,
    )
    .await?;

    match transfer {
        Transfer::Upload { host, guest } => {
            sync_host_to_guest(&mut stream, &host, &guest, args).await
        }
        Transfer::Download { guest, host } => {
            sync_guest_to_host(&mut stream, &guest, &host, args).await
        }
    }
    .map_err(|error| anyhow::anyhow!(crate::render::escape_printable(&format!("{error:#}"))))
}

#[allow(clippy::too_many_lines)]
async fn sync_host_to_guest(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    src_endpoint: &HostEndpoint,
    dst_endpoint: &GuestEndpoint,
    args: &SyncArgs,
) -> Result<ExitCode> {
    let src_path = &src_endpoint.path;
    let src_has_trailing = src_endpoint.has_trailing_separator;
    let dst_path_str = &dst_endpoint.path;
    let dst_has_trailing = dst_endpoint.has_trailing_separator;

    let src_meta = match std::fs::symlink_metadata(src_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("source does not exist: {}", src_path.display())
        }
        Err(e) => return Err(e).context(format!("reading {}", src_path.display())),
    };

    if src_meta.file_type().is_symlink() && src_has_trailing {
        anyhow::bail!("source is a symlink but has a trailing separator");
    }
    if !src_meta.is_dir() && !src_meta.is_file() && !src_meta.file_type().is_symlink() {
        anyhow::bail!("unsupported special file: {}", src_path.display());
    }
    if args.delete && !src_meta.is_dir() {
        anyhow::bail!("--delete is valid only when synchronizing a directory");
    }

    send_request(
        stream,
        &SyncRequest::BeginSession {
            guest_root: dst_path_str.clone(),
        },
    )
    .await?;

    let initial_root_status = match read_reply(stream).await? {
        SyncReply::SessionReady { root_status } => root_status,
        other => anyhow::bail!("expected SessionReady, got {other:?}"),
    };

    if dst_has_trailing
        && matches!(
            initial_root_status,
            RootStatus::ExistingFile | RootStatus::ExistingSymlink
        )
    {
        anyhow::bail!("destination {dst_path_str} ends in a separator but is an existing file");
    }

    let is_dir_sync = src_meta.is_dir();
    let src_name = src_path
        .file_name()
        .unwrap_or(std::ffi::OsStr::new(""))
        .to_str()
        .context("source name is not valid UTF-8")?;

    let effective_guest_root = resolve_placement(
        SourcePlacement {
            name: src_name,
            is_dir: is_dir_sync,
            has_trailing: src_has_trailing || src_name.is_empty(),
        },
        DestinationPlacement {
            path: dst_path_str,
            is_existing_dir: initial_root_status == RootStatus::ExistingDirectory,
            has_trailing: dst_has_trailing,
        },
    );

    let mut effective_root_status = initial_root_status;
    if effective_guest_root != *dst_path_str {
        send_request(
            stream,
            &SyncRequest::BeginSession {
                guest_root: effective_guest_root.clone(),
            },
        )
        .await?;
        match read_reply(stream).await? {
            SyncReply::SessionReady { root_status } => effective_root_status = root_status,
            other => anyhow::bail!("expected SessionReady on re-root, got {other:?}"),
        }
    }
    let single_file_name = if is_dir_sync {
        None
    } else {
        Some(src_name.to_string())
    };

    let source_entries = if is_dir_sync {
        scan_host_directory(src_path)?
    } else {
        single_host_entry_map(src_path, &src_meta)?
    };

    let target_entries = scan_guest_entries(stream).await?;
    validate_root_kind(&target_entries, effective_root_status)?;

    let actions = build_plan(
        &source_entries,
        &target_entries,
        args.checksum,
        args.delete,
        SyncDirection::HostToGuest,
        stream,
        Path::new(&effective_guest_root),
        src_path,
    )
    .await?;

    let stats = execute_plan(
        &actions,
        SyncDirection::HostToGuest,
        stream,
        Path::new(&effective_guest_root),
        src_path,
        args.dry_run,
    )
    .await?;

    report_result(
        src_path.to_str().unwrap_or("?"),
        &effective_guest_root,
        &stats,
        args.dry_run,
        single_file_name.is_some(),
    );
    Ok(ExitCode::SUCCESS)
}

#[allow(clippy::too_many_lines)]
async fn sync_guest_to_host(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    src_endpoint: &GuestEndpoint,
    dst_endpoint: &HostEndpoint,
    args: &SyncArgs,
) -> Result<ExitCode> {
    let src_path_str = &src_endpoint.path;
    let src_has_trailing = src_endpoint.has_trailing_separator;
    let dst_path = &dst_endpoint.path;
    let dst_has_trailing = dst_endpoint.has_trailing_separator;

    send_request(
        stream,
        &SyncRequest::BeginSession {
            guest_root: src_path_str.clone(),
        },
    )
    .await?;

    let initial_root_status = match read_reply(stream).await? {
        SyncReply::SessionReady { root_status } => root_status,
        other => anyhow::bail!("expected SessionReady, got {other:?}"),
    };

    if initial_root_status == RootStatus::Missing {
        anyhow::bail!("guest source {src_path_str} does not exist");
    }
    if initial_root_status == RootStatus::ExistingSymlink && src_has_trailing {
        anyhow::bail!("guest source {src_path_str} is a symlink but has a trailing separator");
    }
    if args.delete && initial_root_status != RootStatus::ExistingDirectory {
        anyhow::bail!("--delete is valid only when synchronizing a directory");
    }

    let dst_meta = optional_metadata(dst_path)?;
    if dst_has_trailing && dst_meta.as_ref().is_some_and(|m| !m.is_dir()) {
        anyhow::bail!(
            "destination {} ends in a separator but is an existing file",
            dst_path.display()
        );
    }

    let is_dir_sync = initial_root_status == RootStatus::ExistingDirectory;
    let src_name = Path::new(src_path_str)
        .file_name()
        .unwrap_or(std::ffi::OsStr::new(""))
        .to_str()
        .context("guest source name is not valid UTF-8")?;

    let effective_host_root_str = resolve_placement(
        SourcePlacement {
            name: src_name,
            is_dir: is_dir_sync,
            has_trailing: src_has_trailing || src_name.is_empty(),
        },
        DestinationPlacement {
            path: dst_path.to_str().context("dst path is not UTF-8")?,
            is_existing_dir: dst_meta.as_ref().is_some_and(std::fs::Metadata::is_dir),
            has_trailing: dst_has_trailing,
        },
    );
    let effective_host_root = PathBuf::from(effective_host_root_str);
    if initial_root_status == RootStatus::ExistingSymlink && effective_host_root == *dst_path {
        anyhow::bail!(
            "cannot sync guest symlink {src_path_str} to {}: the link target would resolve outside \
             the destination; sync the link's target instead, or place the link inside a directory \
             destination",
            dst_path.display()
        );
    }
    let single_file_name = if is_dir_sync {
        None
    } else {
        Some(src_name.to_string())
    };

    let source_entries = scan_guest_entries(stream).await?;

    let target_entries = match optional_metadata(&effective_host_root)? {
        Some(meta) if meta.is_dir() => scan_host_directory(&effective_host_root)?,
        Some(meta) => single_host_entry_map(&effective_host_root, &meta)?,
        None => BTreeMap::new(),
    };
    validate_root_kind(&source_entries, initial_root_status)?;

    let actions = build_plan(
        &source_entries,
        &target_entries,
        args.checksum,
        args.delete,
        SyncDirection::GuestToHost,
        stream,
        &effective_host_root,
        Path::new(src_path_str),
    )
    .await?;

    let stats = execute_plan(
        &actions,
        SyncDirection::GuestToHost,
        stream,
        &effective_host_root,
        Path::new(src_path_str),
        args.dry_run,
    )
    .await?;

    report_result(
        src_path_str,
        &effective_host_root.display().to_string(),
        &stats,
        args.dry_run,
        single_file_name.is_some(),
    );
    Ok(ExitCode::SUCCESS)
}

fn report_result(from: &str, to: &str, stats: &SyncStats, is_dry_run: bool, is_single_file: bool) {
    let from = crate::render::escape_printable(from);
    let to = crate::render::escape_printable(to);
    if is_dry_run {
        eprintln!(
            "terra: [dry-run] sync {from} -> {to} ({} planned copies, {} estimated bytes, {} planned deletes)",
            stats.copied_count, stats.transferred_bytes, stats.deleted_count
        );
    } else if is_single_file && stats.copied_count == 1 && stats.deleted_count == 0 {
        eprintln!(
            "terra: copied {from} -> {to} ({} bytes)",
            stats.transferred_bytes
        );
    } else {
        eprintln!(
            "terra: sync {from} -> {to} ({} copied, {} bytes, {} metadata updated, {} deleted, {} skipped)",
            stats.copied_count,
            stats.transferred_bytes,
            stats.metadata_updated_count,
            stats.deleted_count,
            stats.skipped_count
        );
    }
}

#[cfg(test)]
mod tests {
    use super::plan::validate_plan_conflicts;
    use super::scan::meta_mtime_secs;
    use super::test_support::{entry, peer};
    use super::*;
    use terra_protocol::{SyncEntryKind, SyncReply};

    #[tokio::test]
    async fn malformed_guest_trees_are_rejected_before_planning() {
        let source = BTreeMap::from([
            ("a".into(), entry("a", SyncEntryKind::Symlink, Some("."))),
            (
                "a/escape".into(),
                entry("a/escape", SyncEntryKind::File, None),
            ),
        ]);
        assert!(validate_plan_conflicts(&source, &BTreeMap::new()).is_err());
        let mut guest = peer(&[
            SyncReply::Entry(entry("a", SyncEntryKind::File, None)),
            SyncReply::Entry(entry("a", SyncEntryKind::File, None)),
            SyncReply::ScanComplete,
        ]);
        assert!(
            scan_guest_entries(&mut guest)
                .await
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn download_rejects_links_through_pending_deletions_and_replacements() {
        for delete in [true, false] {
            let scratch = tempfile::tempdir().unwrap();
            let destination = scratch.path().join("destination");
            std::fs::create_dir_all(destination.join("d")).unwrap();
            std::os::unix::fs::symlink("..", destination.join("d/up")).unwrap();
            let mut source = vec![
                entry("", SyncEntryKind::Directory, None),
                entry("a", SyncEntryKind::Symlink, Some("d/up/../../x")),
                entry("z", SyncEntryKind::File, None),
            ];
            if !delete {
                source.extend([
                    entry("d", SyncEntryKind::Directory, None),
                    entry("d/up", SyncEntryKind::File, None),
                ]);
            }
            let mut replies = vec![SyncReply::SessionReady {
                root_status: RootStatus::ExistingDirectory,
            }];
            replies.extend(source.into_iter().map(SyncReply::Entry));
            replies.extend([
                SyncReply::ScanComplete,
                SyncReply::ReadFileReady {
                    size: 99,
                    mode: 0o644,
                    mtime_secs: 100,
                    mtime_nanos: 0,
                },
            ]);
            let args = SyncArgs {
                src: ":/source/".into(),
                dst: destination.to_str().unwrap().into(),
                delete,
                checksum: false,
                dry_run: false,
                agent: crate::cli::AgentTimeoutArg {
                    agent_timeout: None,
                },
            };
            let Transfer::Download {
                guest: src,
                host: dst,
            } = parse_endpoints(&args.src, &args.dst).unwrap()
            else {
                panic!("expected download transfer");
            };
            let error = sync_guest_to_host(&mut peer(&replies), &src, &dst, &args)
                .await
                .unwrap_err();
            assert!(
                std::fs::symlink_metadata(destination.join("a")).is_err(),
                "{error:#}"
            );
            assert!(error.to_string().contains("escapes"), "{error:#}");
            assert_eq!(
                std::fs::read_link(destination.join("d/up")).unwrap(),
                Path::new("..")
            );
        }
    }

    /// A guest symlink whose destination is the root itself would resolve its
    /// target relative to the destination's parent, outside the synced tree.
    #[tokio::test]
    async fn download_rejects_a_symlink_that_replaces_the_destination() {
        let scratch = tempfile::tempdir().unwrap();
        let destination = scratch.path().join("out");
        let args = SyncArgs {
            src: ":/link".into(),
            dst: destination.to_str().unwrap().into(),
            delete: false,
            checksum: false,
            dry_run: false,
            agent: crate::cli::AgentTimeoutArg {
                agent_timeout: None,
            },
        };
        let Transfer::Download {
            guest: src,
            host: dst,
        } = parse_endpoints(&args.src, &args.dst).unwrap()
        else {
            panic!("expected download transfer");
        };
        let replies = [SyncReply::SessionReady {
            root_status: RootStatus::ExistingSymlink,
        }];
        let error = sync_guest_to_host(&mut peer(&replies), &src, &dst, &args)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("symlink"), "{error:#}");
        assert!(std::fs::symlink_metadata(&destination).is_err());
    }

    #[tokio::test]
    async fn empty_directory_download_creates_root_but_dry_run_does_not() {
        let scratch = tempfile::tempdir().unwrap();
        let destination = scratch.path().join("new");
        let mut args = SyncArgs {
            src: ":/empty/".into(),
            dst: destination.to_str().unwrap().into(),
            delete: true,
            checksum: false,
            dry_run: true,
            agent: crate::cli::AgentTimeoutArg {
                agent_timeout: None,
            },
        };
        let Transfer::Download {
            guest: src,
            host: dst,
        } = parse_endpoints(&args.src, &args.dst).unwrap()
        else {
            panic!("expected download transfer");
        };
        let replies = [
            SyncReply::SessionReady {
                root_status: RootStatus::ExistingDirectory,
            },
            SyncReply::Entry(entry("", SyncEntryKind::Directory, None)),
            SyncReply::ScanComplete,
            SyncReply::Success,
        ];
        sync_guest_to_host(&mut peer(&replies), &src, &dst, &args)
            .await
            .unwrap();
        assert!(!destination.exists());
        args.dry_run = false;
        sync_guest_to_host(&mut peer(&replies), &src, &dst, &args)
            .await
            .unwrap();
        assert!(destination.is_dir());
        assert_eq!(
            meta_mtime_secs(&std::fs::metadata(&destination).unwrap()),
            100
        );
    }

    #[tokio::test]
    async fn unicode_download_preserves_dry_run_contents_and_directory_timestamps() {
        let scratch = tempfile::tempdir().unwrap();
        let destination = scratch.path().join("destination");
        std::fs::create_dir_all(destination.join("日本語")).unwrap();
        std::fs::write(destination.join("extra"), b"keep until successful transfer").unwrap();
        let root_modified = destination.metadata().unwrap().modified().unwrap();
        let child_modified = destination
            .join("日本語")
            .metadata()
            .unwrap()
            .modified()
            .unwrap();
        let mut args = SyncArgs {
            src: ":/source/".into(),
            dst: destination.to_str().unwrap().into(),
            delete: true,
            checksum: false,
            dry_run: true,
            agent: crate::cli::AgentTimeoutArg {
                agent_timeout: None,
            },
        };
        let Transfer::Download {
            guest: src,
            host: dst,
        } = parse_endpoints(&args.src, &args.dst).unwrap()
        else {
            panic!("expected download");
        };
        let replies = [
            SyncReply::SessionReady {
                root_status: RootStatus::ExistingDirectory,
            },
            SyncReply::Entry(entry("", SyncEntryKind::Directory, None)),
            SyncReply::Entry(entry("日本語", SyncEntryKind::Directory, None)),
            SyncReply::Entry(entry("日本語/café.txt", SyncEntryKind::File, None)),
            SyncReply::ScanComplete,
            SyncReply::ReadFileReady {
                size: 0,
                mode: 0o755,
                mtime_secs: 100,
                mtime_nanos: 0,
            },
            SyncReply::Success,
            SyncReply::Success,
        ];
        sync_guest_to_host(&mut peer(&replies), &src, &dst, &args)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(destination.join("extra")).unwrap(),
            b"keep until successful transfer"
        );
        assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 2);
        assert_eq!(
            std::fs::read_dir(destination.join("日本語"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            destination.metadata().unwrap().modified().unwrap(),
            root_modified
        );
        assert_eq!(
            destination
                .join("日本語")
                .metadata()
                .unwrap()
                .modified()
                .unwrap(),
            child_modified
        );

        args.dry_run = false;
        sync_guest_to_host(&mut peer(&replies), &src, &dst, &args)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(destination.join("日本語/café.txt")).unwrap(),
            b""
        );
        assert!(!destination.join("extra").exists());
        assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 1);
        assert_eq!(
            std::fs::read_dir(destination.join("日本語"))
                .unwrap()
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn unrepresentable_names_fail_before_transfers_or_deletions() {
        let destination = tempfile::tempdir().unwrap();
        std::fs::write(destination.path().join("extra"), b"keep").unwrap();
        let modified = destination.path().metadata().unwrap().modified().unwrap();
        let args = SyncArgs {
            src: ":/source/".into(),
            dst: destination.path().to_str().unwrap().into(),
            delete: true,
            checksum: false,
            dry_run: false,
            agent: crate::cli::AgentTimeoutArg {
                agent_timeout: None,
            },
        };
        let Transfer::Download {
            guest: src,
            host: dst,
        } = parse_endpoints(&args.src, &args.dst).unwrap()
        else {
            panic!("expected download");
        };
        let replies = [
            SyncReply::SessionReady {
                root_status: RootStatus::ExistingDirectory,
            },
            SyncReply::Entry(entry("", SyncEntryKind::Directory, None)),
            SyncReply::Entry(entry("a", SyncEntryKind::File, None)),
            SyncReply::Entry(entry(&"x".repeat(300), SyncEntryKind::File, None)),
            SyncReply::ScanComplete,
        ];
        let error = sync_guest_to_host(&mut peer(&replies), &src, &dst, &args)
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("cannot be created"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read(destination.path().join("extra")).unwrap(),
            b"keep"
        );
        assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 1);
        assert_eq!(
            destination.path().metadata().unwrap().modified().unwrap(),
            modified
        );
    }
}
