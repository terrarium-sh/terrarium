//! One-way file and directory synchronization between the host and a running box.

use crate::cli::SyncArgs;
use crate::sys;
use crate::vm::image;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};
use terra_protocol::{
    AgentService, MAX_FILE_BYTES, MAX_SYNC_ENTRIES, MAX_SYNC_ERROR_BYTES, MAX_SYNC_METADATA_BYTES,
    MAX_SYNC_PATH_BYTES, RootStatus, SyncDirection, SyncEntry, SyncEntryKind, SyncReply,
    SyncRequest, encode_frame, read_frame_with_limit, truncate_nanos, validate_relative_path,
};

const MAX_SYNC_FRAME_BYTES: usize = 64 * 1024;
const COPY_STALL_TIMEOUT: Duration = Duration::from_mins(1);
const COPY_DATA_TIMEOUT: Duration = Duration::from_hours(1);
const MAX_SYNC_LINK_WORK_BYTES: usize = 64 * 1024 * 1024;

/// Synchronize a file or directory tree between the host and a running box.
pub fn run(args: &SyncArgs, name: Option<&str>, project_dir: &Path) -> Result<ExitCode> {
    let (src_endpoint, dst_endpoint, direction) = parse_endpoints(&args.src, &args.dst)?;
    let bx = &crate::resolve::resolve_pinned_box(project_dir, name)?;

    let mut stream = crate::session::connect_to_running_agent(
        bx,
        "sync",
        AgentService::Files,
        "file service",
        args.agent.agent_timeout,
    )?;
    stream
        .set_read_timeout(Some(COPY_STALL_TIMEOUT))
        .context("setting sync read timeout")?;
    stream
        .set_write_timeout(Some(COPY_STALL_TIMEOUT))
        .context("setting sync write timeout")?;

    match direction {
        SyncDirection::HostToGuest => {
            sync_host_to_guest(&mut stream, &src_endpoint, &dst_endpoint, args)
        }
        SyncDirection::GuestToHost => {
            sync_guest_to_host(&mut stream, &src_endpoint, &dst_endpoint, args)
        }
    }
    .map_err(|error| anyhow::anyhow!(crate::render::escape_printable(&format!("{error:#}"))))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Endpoint {
    Guest {
        path: String,
        has_trailing_separator: bool,
    },
    Host {
        path: PathBuf,
        has_trailing_separator: bool,
    },
}

fn parse_endpoint(raw: &str) -> Result<Endpoint> {
    if let Some(rest) = raw.strip_prefix("box:").or_else(|| raw.strip_prefix(':')) {
        anyhow::ensure!(
            rest.starts_with('/'),
            "the box's side of sync is an absolute path, and '{raw}' is not (use 'box:/path' or ':/path')"
        );
        let path = if rest == "/" {
            rest
        } else {
            rest.trim_end_matches('/')
        };
        anyhow::ensure!(
            !path.is_empty(),
            "guest path is empty after removing trailing separators; use 'box:/' or ':/' for the guest root"
        );
        return Ok(Endpoint::Guest {
            path: path.to_owned(),
            has_trailing_separator: raw.ends_with('/'),
        });
    }

    let is_windows_drive =
        raw.len() >= 2 && raw.as_bytes()[0].is_ascii_alphabetic() && raw.as_bytes()[1] == b':';

    if !is_windows_drive
        && let Some(colon_pos) = raw.find(':')
        && colon_pos > 0
        && !raw[..colon_pos].contains(['/', '\\'])
        && raw[colon_pos..].starts_with(":/")
    {
        let box_name = &raw[..colon_pos];
        let rest = &raw[colon_pos + 1..];
        anyhow::bail!(
            "'{raw}' looks like a named box endpoint; terra selects the box on the CLI: terra {box_name} sync ... box:{rest}"
        );
    }

    let has_trailing_separator = raw.ends_with('/') || (cfg!(windows) && raw.ends_with('\\'));
    Ok(Endpoint::Host {
        path: PathBuf::from(raw).components().collect(),
        has_trailing_separator,
    })
}

fn parse_endpoints(src: &str, dst: &str) -> Result<(Endpoint, Endpoint, SyncDirection)> {
    let src_endpoint = parse_endpoint(src).context("parsing source endpoint")?;
    let dst_endpoint = parse_endpoint(dst).context("parsing destination endpoint")?;

    match (&src_endpoint, &dst_endpoint) {
        (Endpoint::Guest { .. }, Endpoint::Guest { .. }) => {
            anyhow::bail!(
                "sync operates between host and a box; both source and destination cannot be inside the box"
            );
        }
        (Endpoint::Host { .. }, Endpoint::Host { .. }) => {
            anyhow::bail!(
                "sync operates between host and a box; exactly one of source and destination must be inside the box ('box:/path' or ':/path')"
            );
        }
        (Endpoint::Host { .. }, Endpoint::Guest { .. }) => {
            Ok((src_endpoint, dst_endpoint, SyncDirection::HostToGuest))
        }
        (Endpoint::Guest { .. }, Endpoint::Host { .. }) => {
            Ok((src_endpoint, dst_endpoint, SyncDirection::GuestToHost))
        }
    }
}

fn read_reply(stream: &mut impl Read) -> Result<SyncReply> {
    let reply = read_frame_with_limit(stream, MAX_SYNC_FRAME_BYTES)
        .context("reading agent reply")?
        .ok_or_else(|| anyhow::anyhow!("agent closed connection without replying"))?;
    match reply {
        SyncReply::Err(err) => anyhow::bail!("guest: {}", sanitize_guest_error_message(&err)),
        other => Ok(other),
    }
}

fn send_request(stream: &mut impl Write, req: &SyncRequest) -> Result<()> {
    let frame = encode_frame(req).context("encoding sync request frame")?;
    stream
        .write_all(&frame)
        .context("sending sync request frame")?;
    Ok(())
}

fn sanitize_guest_error_message(err: &str) -> String {
    let mut chars = err.chars();
    let message: String = chars.by_ref().take(MAX_SYNC_ERROR_BYTES).collect();
    let mut out = crate::render::escape_printable(&message);
    if chars.next().is_some() {
        out.push('…');
    }
    out
}

fn to_guest_mode(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    }
    #[cfg(windows)]
    {
        match (meta.is_dir(), meta.permissions().readonly()) {
            (true, true) => 0o555,
            (true, false) => 0o755,
            (false, true) => 0o444,
            (false, false) => 0o644,
        }
    }
}

fn to_safe_mode(guest_mode: u32) -> u32 {
    guest_mode & 0o755
}

fn effective_mode(mode: u32, direction: SyncDirection, kind: SyncEntryKind) -> u32 {
    if cfg!(windows) && direction == SyncDirection::GuestToHost {
        return match (kind == SyncEntryKind::Directory, mode & 0o200 == 0) {
            (true, true) => 0o555,
            (true, false) => 0o755,
            (false, true) => 0o444,
            (false, false) => 0o644,
        };
    }
    match direction {
        SyncDirection::HostToGuest => mode & 0o777,
        SyncDirection::GuestToHost => to_safe_mode(mode),
    }
}

fn optional_metadata(path: &Path) -> Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn checked_host_path(root: &Path, relative: &str) -> Result<PathBuf> {
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

fn validate_manifest(entries: &BTreeMap<String, SyncEntry>) -> Result<()> {
    for (path, entry) in entries {
        validate_relative_path(path).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(entry.relative_path == *path, "manifest path mismatch");
        anyhow::ensure!(entry.size <= MAX_FILE_BYTES, "file exceeds sync size limit");
        anyhow::ensure!(
            (entry.kind == SyncEntryKind::Symlink) == entry.link_target.is_some(),
            "manifest link target does not match its entry kind"
        );
        #[cfg(windows)]
        for component in path.split('/').filter(|part| !part.is_empty()) {
            validate_windows_name(component)?;
        }
        if !path.is_empty() {
            if let Some(root) = entries.get("") {
                anyhow::ensure!(
                    root.kind == SyncEntryKind::Directory,
                    "manifest root has children but is not a directory"
                );
            }
            let mut parent = path.as_str();
            while let Some((prefix, _)) = parent.rsplit_once('/') {
                anyhow::ensure!(
                    entries
                        .get(prefix)
                        .is_some_and(|entry| entry.kind == SyncEntryKind::Directory),
                    "manifest entry has a missing or non-directory ancestor"
                );
                parent = prefix;
            }
        }
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn validate_windows_name(name: &str) -> Result<()> {
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    });
    anyhow::ensure!(
        !reserved
            && !name.ends_with(['.', ' '])
            && !name
                .chars()
                .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c)),
        "guest filename is not representable on Windows"
    );
    Ok(())
}

fn manifest_lookup_key(path: &str) -> String {
    #[cfg(target_os = "macos")]
    {
        macos_manifest_lookup_key(path)
    }
    #[cfg(not(target_os = "macos"))]
    if cfg!(windows) {
        path.to_lowercase()
    } else {
        path.to_owned()
    }
}

#[cfg(any(target_os = "macos", test))]
fn macos_manifest_lookup_key(path: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    path.nfd().flat_map(char::to_lowercase).nfd().collect()
}

fn validate_case_aliases(
    source: &BTreeMap<String, SyncEntry>,
    target: &BTreeMap<String, SyncEntry>,
) -> Result<()> {
    let mut names = BTreeMap::new();
    for path in source.keys().chain(target.keys()) {
        if let Some(previous) = names.insert(manifest_lookup_key(path), path) {
            anyhow::ensure!(
                previous == path,
                "sync paths differ only in case or Unicode normalization; rename one before syncing"
            );
        }
    }
    Ok(())
}

fn validate_root_kind(entries: &BTreeMap<String, SyncEntry>, status: RootStatus) -> Result<()> {
    let kind = match status {
        RootStatus::ExistingDirectory => SyncEntryKind::Directory,
        RootStatus::ExistingFile => SyncEntryKind::File,
        RootStatus::ExistingSymlink => SyncEntryKind::Symlink,
        RootStatus::Missing => {
            anyhow::ensure!(
                entries.is_empty(),
                "missing guest root has manifest entries"
            );
            return Ok(());
        }
    };
    anyhow::ensure!(
        entries.get("").is_some_and(|entry| entry.kind == kind),
        "guest manifest root does not match session status"
    );
    Ok(())
}

fn validate_download_links(
    source: &BTreeMap<String, SyncEntry>,
    destination: &BTreeMap<String, SyncEntry>,
) -> Result<()> {
    let mut links = BTreeMap::new();
    for (path, entry) in source.iter().chain(destination) {
        if entry.link_target.is_some() {
            links.insert(
                manifest_lookup_key(path),
                [
                    source
                        .get(path)
                        .and_then(|entry| entry.link_target.as_deref()),
                    destination
                        .get(path)
                        .and_then(|entry| entry.link_target.as_deref()),
                ],
            );
        }
    }
    let mut remaining_work = MAX_SYNC_LINK_WORK_BYTES;
    for (path, entry) in source {
        if let Some(target) = &entry.link_target {
            validate_link_resolutions(path, target, &links, &mut remaining_work)?;
        }
    }
    Ok(())
}

fn spend_link_work(remaining: &mut usize, bytes: usize) -> Result<()> {
    *remaining = remaining
        .checked_sub(bytes)
        .context("symlink resolution exceeded its work limit; sync a smaller subtree")?;
    Ok(())
}

fn validate_link_resolutions(
    path: &str,
    target: &str,
    links: &BTreeMap<String, [Option<&str>; 2]>,
    remaining_work: &mut usize,
) -> Result<()> {
    validate_download_symlink_target(path, target)?;
    spend_link_work(remaining_work, path.len() + target.len() + 1)?;
    let mut parent: Vec<String> = path.split('/').map(str::to_owned).collect();
    parent.pop();
    let pending: VecDeque<String> = target.split('/').map(str::to_owned).collect();
    let mut branches = vec![(parent, pending, 0)];
    while let Some((mut resolved, mut pending, followed)) = branches.pop() {
        while let Some(component) = pending.pop_front() {
            spend_link_work(remaining_work, component.len() + 1)?;
            match component.as_str() {
                "" | "." => continue,
                ".." => {
                    anyhow::ensure!(
                        resolved.pop().is_some(),
                        "guest symlink chain escapes destination root"
                    );
                    continue;
                }
                _ => {}
            }
            #[cfg(windows)]
            validate_windows_name(&component)?;
            resolved.push(component);
            let name = resolved.join("/");
            spend_link_work(remaining_work, name.len())?;
            if let Some(targets) = links.get(&manifest_lookup_key(&name)) {
                for (index, target) in targets.iter().enumerate() {
                    if index == 1 && target == &targets[0] {
                        continue;
                    }
                    let copy_bytes = name.len()
                        + pending.iter().map(|part| part.len() + 1).sum::<usize>()
                        + target.map_or(0, str::len)
                        + 1;
                    spend_link_work(remaining_work, copy_bytes)?;
                    let mut next_path = resolved.clone();
                    let mut next_pending = pending.clone();
                    let mut next_followed = followed;
                    if let Some(link) = target {
                        next_followed += 1;
                        anyhow::ensure!(
                            next_followed <= 40,
                            "guest symlink chain is cyclic or too deep"
                        );
                        validate_download_symlink_target(&name, link)?;
                        next_path.pop();
                        for part in link.split('/').rev() {
                            next_pending.push_front(part.to_owned());
                        }
                    }
                    branches.push((next_path, next_pending, next_followed));
                }
                break;
            }
        }
    }
    Ok(())
}

fn meta_mtime_secs(meta: &std::fs::Metadata) -> i64 {
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

fn meta_mtime_nanos(meta: &std::fs::Metadata) -> u32 {
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

fn validate_download_symlink_target(entry_rel_path: &str, target: &str) -> Result<()> {
    anyhow::ensure!(!target.is_empty(), "symlink target cannot be empty");
    anyhow::ensure!(
        target.len() <= MAX_SYNC_PATH_BYTES,
        "symlink target exceeds maximum length"
    );
    anyhow::ensure!(!target.contains('\0'), "symlink target contains NUL bytes");
    anyhow::ensure!(
        !target.starts_with('/'),
        "rejecting absolute symlink target '{target}' from guest"
    );
    #[cfg(windows)]
    {
        anyhow::ensure!(
            !target.starts_with('\\') && !target.contains(':'),
            "rejecting Windows absolute/drive symlink target '{target}' from guest"
        );
    }
    let parent_depth = if entry_rel_path.is_empty() {
        0
    } else {
        Path::new(entry_rel_path)
            .parent()
            .map_or(0, |p| p.components().count())
    };
    let mut current_depth = parent_depth;
    for component in target.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            anyhow::ensure!(
                current_depth > 0,
                "rejecting symlink '{entry_rel_path}' -> '{target}' that escapes destination root"
            );
            current_depth -= 1;
        } else {
            current_depth += 1;
        }
    }
    Ok(())
}

fn scan_host_directory(root_path: &Path) -> Result<BTreeMap<String, SyncEntry>> {
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

fn scan_guest_entries(stream: &mut (impl Read + Write)) -> Result<BTreeMap<String, SyncEntry>> {
    send_request(stream, &SyncRequest::ScanEntries)?;
    let mut entries = BTreeMap::new();
    let mut total_metadata_bytes = 0usize;

    let deadline = Instant::now() + COPY_DATA_TIMEOUT;
    loop {
        anyhow::ensure!(
            Instant::now() < deadline,
            "guest scan exceeded its time limit"
        );
        match read_reply(stream)? {
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

fn compute_checksum_pair(
    stream: &mut (impl Read + Write),
    guest_rel_path: &str,
    host_file_path: &Path,
    guest_is_source: bool,
) -> Result<([u8; 32], [u8; 32])> {
    send_request(
        stream,
        &SyncRequest::ComputeDigest {
            relative_path: guest_rel_path.to_string(),
        },
    )?;

    let (tx, rx) = std::sync::mpsc::channel();
    let local_path = host_file_path.to_path_buf();
    std::thread::spawn(move || {
        let _ = tx.send(hash_file_worker(&local_path));
    });

    let deadline = Instant::now() + COPY_DATA_TIMEOUT;
    let guest_sha = loop {
        anyhow::ensure!(
            Instant::now() < deadline,
            "checksum exceeded its time limit"
        );
        match read_reply(stream)? {
            SyncReply::DigestProgress { .. } => {}
            SyncReply::Digest { sha256 } => break sha256,
            other => anyhow::bail!("unexpected reply from agent during digest: {other:?}"),
        }
    };

    let host_sha = rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| anyhow::anyhow!("local hashing worker thread failed"))??;

    if guest_is_source {
        Ok((guest_sha, host_sha))
    } else {
        Ok((host_sha, guest_sha))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PlanAction {
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

fn validate_plan_conflicts(
    source_entries: &BTreeMap<String, SyncEntry>,
    target_entries: &BTreeMap<String, SyncEntry>,
) -> Result<()> {
    validate_manifest(source_entries)?;
    validate_manifest(target_entries)?;
    validate_case_aliases(source_entries, target_entries)?;

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

#[allow(clippy::too_many_arguments)]
fn plan_file_update(
    rel_path: &str,
    src: &SyncEntry,
    dst: &SyncEntry,
    is_checksum: bool,
    direction: SyncDirection,
    stream: &mut (impl Read + Write),
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
            compute_checksum_pair(stream, rel_path, &host_file_path, guest_is_src)?;
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

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn build_plan(
    source_entries: &BTreeMap<String, SyncEntry>,
    target_entries: &BTreeMap<String, SyncEntry>,
    is_checksum: bool,
    is_delete: bool,
    direction: SyncDirection,
    stream: &mut (impl Read + Write),
    host_target_root: &Path,
    host_source_root: &Path,
) -> Result<Vec<PlanAction>> {
    validate_plan_conflicts(source_entries, target_entries)?;
    if direction == SyncDirection::GuestToHost {
        validate_download_links(source_entries, target_entries)?;
    }

    let mut actions = Vec::new();
    let tree_differs = source_entries.iter().any(|(path, source)| {
        target_entries.get(path).is_none_or(|target| {
            let mut expected = source.clone();
            expected.mode = effective_mode(source.mode, direction, source.kind);
            expected != *target
        })
    }) || (is_delete
        && target_entries
            .keys()
            .any(|path| !source_entries.contains_key(path)));

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
                    if mode_differs || mtime_differs || tree_differs {
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
                    actions.push(plan_file_update(
                        rel_path,
                        src,
                        dst,
                        is_checksum,
                        direction,
                        stream,
                        host_target_root,
                        host_source_root,
                    )?);
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

    Ok(actions)
}

fn send_file_into_guest(
    stream: &mut (impl Read + Write),
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
    )?;

    match read_reply(stream)? {
        SyncReply::WriteFileReady => {}
        other => anyhow::bail!("expected WriteFileReady from agent, got {other:?}"),
    }

    let mut file = sys::open_regular_file(host_path)
        .with_context(|| format!("opening {}", host_path.display()))?;
    let mut buf = [0u8; 16 * 1024];
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
        stream
            .write_all(&buf[..n])
            .context("sending file data to agent")?;
        sent += n as u64;
    }

    let after = file.metadata()?;
    anyhow::ensure!(
        after.len() == size && after.modified()? == meta.modified()?,
        "source changed while transferring; retry with a quiet source"
    );
    send_request(stream, &SyncRequest::CommitFile)?;

    match read_reply(stream)? {
        SyncReply::Success => {}
        other => anyhow::bail!("expected Success after file transfer, got {other:?}"),
    }
    Ok(sent)
}

fn fetch_file_from_guest(
    stream: &mut (impl Read + Write),
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
    )?;

    let (size, mode, mtime_secs, mtime_nanos) = match read_reply(stream)? {
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

    image::staged_write(dst_full_path, |file| {
        let mut buf = [0u8; 16 * 1024];
        let mut received = 0u64;
        while received < size {
            if Instant::now() >= deadline {
                anyhow::bail!("file transfer ran past data transfer limit");
            }
            let want = usize::min(
                buf.len(),
                usize::try_from(size - received).unwrap_or(buf.len()),
            );
            let n = match stream.read(&mut buf[..want]) {
                Ok(0) => {
                    anyhow::bail!(
                        "transfer of {guest_rel_path} ended after {received} of {size} promised bytes"
                    );
                }
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e).context("receiving file data from agent"),
            };
            image::write_sparse_chunk(file, &buf[..n])
                .context(format!("writing to {}", dst_full_path.display()))?;
            received += n as u64;
        }
        file.set_len(size)
            .with_context(|| format!("sizing {}", dst_full_path.display()))?;
        sys::set_open_file_mode(file, to_safe_mode(mode))
            .with_context(|| format!("setting permissions on {}", dst_full_path.display()))?;
        anyhow::ensure!(
            matches!(read_reply(stream)?, SyncReply::Success),
            "guest did not confirm completed file transfer"
        );
        file.set_times(terra_protocol::sync_file_times(mtime_secs, mtime_nanos)?)?;
        Ok(())
    })?;

    Ok(size)
}

#[derive(Default)]
struct SyncStats {
    copied_count: usize,
    metadata_updated_count: usize,
    deleted_count: usize,
    skipped_count: usize,
    transferred_bytes: u64,
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

fn execute_create_dirs(
    stream: &mut (impl Read + Write),
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
                )?;
                match read_reply(stream)? {
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

fn execute_transfers_and_symlinks(
    stream: &mut (impl Read + Write),
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
                    let sent =
                        send_file_into_guest(stream, &local_file, rel_path, &meta, deadline)?;
                    stats.transferred_bytes += sent;
                }
                SyncDirection::GuestToHost => {
                    let local_file = checked_host_path(host_target_root, rel_path)?;
                    let received =
                        fetch_file_from_guest(stream, rel_path, &local_file, expected, deadline)?;
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
                    )?;
                    match read_reply(stream)? {
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

fn execute_file_meta_updates(
    stream: &mut (impl Read + Write),
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
                )?;
                match read_reply(stream)? {
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

fn execute_deletions(
    stream: &mut (impl Read + Write),
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
                )?;
                match read_reply(stream)? {
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

fn execute_dir_meta_updates(
    stream: &mut (impl Read + Write),
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
                )?;
                match read_reply(stream)? {
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

fn execute_plan(
    actions: &[PlanAction],
    direction: SyncDirection,
    stream: &mut (impl Read + Write),
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

    execute_create_dirs(stream, &create_dirs, direction, host_target_root)?;
    execute_transfers_and_symlinks(
        stream,
        &transfers_and_symlinks,
        direction,
        host_source_root,
        host_target_root,
        deadline,
        &mut stats,
    )?;
    execute_file_meta_updates(
        stream,
        &file_meta_updates,
        direction,
        host_target_root,
        &mut stats,
    )?;
    execute_deletions(stream, &deletions, direction, host_target_root, &mut stats)?;
    execute_dir_meta_updates(stream, &dir_meta_updates, direction, host_target_root)?;

    send_request(stream, &SyncRequest::EndSession)?;
    anyhow::ensure!(
        matches!(read_reply(stream)?, SyncReply::Success),
        "expected session completion"
    );
    Ok(stats)
}
#[derive(Clone, Copy)]
struct SourcePlacement<'a> {
    name: &'a str,
    is_dir: bool,
    has_trailing: bool,
}

#[derive(Clone, Copy)]
struct DestinationPlacement<'a> {
    path: &'a str,
    is_existing_dir: bool,
    has_trailing: bool,
}

fn resolve_placement(src: SourcePlacement<'_>, dst: DestinationPlacement<'_>) -> String {
    if src.is_dir {
        if src.has_trailing {
            dst.path.to_string()
        } else if dst.is_existing_dir {
            format!("{}/{}", dst.path.trim_end_matches('/'), src.name)
        } else {
            dst.path.to_string()
        }
    } else if dst.is_existing_dir || dst.has_trailing {
        format!("{}/{}", dst.path.trim_end_matches('/'), src.name)
    } else {
        dst.path.to_string()
    }
}

fn single_host_entry_map(
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

#[allow(clippy::too_many_lines)]
fn sync_host_to_guest(
    stream: &mut (impl Read + Write),
    src_endpoint: &Endpoint,
    dst_endpoint: &Endpoint,
    args: &SyncArgs,
) -> Result<ExitCode> {
    let (src_path, src_has_trailing) = match src_endpoint {
        Endpoint::Host {
            path,
            has_trailing_separator,
        } => (path, *has_trailing_separator),
        Endpoint::Guest { .. } => unreachable!(),
    };
    let (dst_path_str, dst_has_trailing) = match dst_endpoint {
        Endpoint::Guest {
            path,
            has_trailing_separator,
        } => (path, *has_trailing_separator),
        Endpoint::Host { .. } => unreachable!(),
    };

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
    )?;

    let initial_root_status = match read_reply(stream)? {
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
        )?;
        match read_reply(stream)? {
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

    let target_entries = scan_guest_entries(stream)?;
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
    )?;

    let stats = execute_plan(
        &actions,
        SyncDirection::HostToGuest,
        stream,
        Path::new(&effective_guest_root),
        src_path,
        args.dry_run,
    )?;

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
fn sync_guest_to_host(
    stream: &mut (impl Read + Write),
    src_endpoint: &Endpoint,
    dst_endpoint: &Endpoint,
    args: &SyncArgs,
) -> Result<ExitCode> {
    let (src_path_str, src_has_trailing) = match src_endpoint {
        Endpoint::Guest {
            path,
            has_trailing_separator,
        } => (path, *has_trailing_separator),
        Endpoint::Host { .. } => unreachable!(),
    };
    let (dst_path, dst_has_trailing) = match dst_endpoint {
        Endpoint::Host {
            path,
            has_trailing_separator,
        } => (path, *has_trailing_separator),
        Endpoint::Guest { .. } => unreachable!(),
    };

    send_request(
        stream,
        &SyncRequest::BeginSession {
            guest_root: src_path_str.clone(),
        },
    )?;

    let initial_root_status = match read_reply(stream)? {
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
    let single_file_name = if is_dir_sync {
        None
    } else {
        Some(src_name.to_string())
    };

    let source_entries = scan_guest_entries(stream)?;

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
    )?;

    let stats = execute_plan(
        &actions,
        SyncDirection::GuestToHost,
        stream,
        &effective_host_root,
        Path::new(src_path_str),
        args.dry_run,
    )?;

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
    use super::*;

    fn entry(path: &str, kind: SyncEntryKind, target: Option<&str>) -> SyncEntry {
        SyncEntry {
            relative_path: path.into(),
            kind,
            size: 0,
            mode: 0o755,
            mtime_secs: 100,
            mtime_nanos: 0,
            link_target: target.map(str::to_owned),
        }
    }

    struct Peer(std::io::Cursor<Vec<u8>>);

    impl Read for Peer {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(bytes)
        }
    }

    impl Write for Peer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn peer(replies: &[SyncReply]) -> Peer {
        Peer(std::io::Cursor::new(
            replies
                .iter()
                .flat_map(|reply| encode_frame(reply).unwrap())
                .collect(),
        ))
    }

    #[test]
    fn macos_lookup_keys_match_canonical_unicode_variants() {
        for (composed, decomposed) in [("CAFÉ", "cafe\u{301}"), ("각", "\u{1100}\u{1161}\u{11a8}")]
        {
            assert_eq!(
                macos_manifest_lookup_key(composed),
                macos_manifest_lookup_key(decomposed)
            );
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn downloaded_links_cannot_escape_through_unicode_aliases() {
        for (name, alias) in [("café", "cafe\u{301}"), ("cafe\u{301}", "café")] {
            let destination = BTreeMap::from([(
                name.into(),
                entry(name, SyncEntryKind::Symlink, Some("/outside")),
            )]);
            let source = BTreeMap::from([(
                "link".into(),
                entry("link", SyncEntryKind::Symlink, Some(alias)),
            )]);
            assert!(validate_download_links(&source, &destination).is_err());
            let source = BTreeMap::from([(alias.into(), entry(alias, SyncEntryKind::File, None))]);
            assert!(validate_case_aliases(&source, &destination).is_err());
        }
    }

    #[test]
    fn download_metadata_does_not_modify_hard_links_outside_the_tree() {
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

    #[test]
    fn malformed_guest_trees_are_rejected_before_planning() {
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
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn symlink_chains_cannot_escape_through_dot_dot() {
        let mut source = BTreeMap::from([
            ("a".into(), entry("a", SyncEntryKind::Symlink, Some("."))),
            ("b".into(), entry("b", SyncEntryKind::Symlink, Some("a/.."))),
        ]);
        assert!(validate_download_links(&source, &BTreeMap::new()).is_err());
        source.get_mut("b").unwrap().link_target = Some("a/safe".into());
        assert!(validate_download_links(&source, &BTreeMap::new()).is_ok());
        let destination = BTreeMap::from([(
            "outside".into(),
            entry("outside", SyncEntryKind::Symlink, Some("/tmp")),
        )]);
        source.get_mut("b").unwrap().link_target = Some("outside/file".into());
        assert!(validate_download_links(&source, &destination).is_err());
    }

    #[test]
    fn link_validation_checks_old_and_new_symlink_targets() {
        let source = BTreeMap::from([
            (
                "a".into(),
                entry("a", SyncEntryKind::Symlink, Some("d/up/../../x")),
            ),
            (
                "d/up".into(),
                entry("d/up", SyncEntryKind::Symlink, Some("safe")),
            ),
        ]);
        let destination = BTreeMap::from([(
            "d/up".into(),
            entry("d/up", SyncEntryKind::Symlink, Some("..")),
        )]);
        assert!(validate_download_links(&source, &BTreeMap::new()).is_ok());
        assert!(validate_download_links(&source, &destination).is_err());
    }

    /// Resolution work, including branches through old and new targets, consumes
    /// one budget shared by all source links rather than restarting per link.
    #[test]
    fn link_resolution_budget_is_shared_across_source_links() {
        let links = BTreeMap::from([("alias".into(), [Some("."), Some("subdir")])]);
        let mut remaining = MAX_SYNC_LINK_WORK_BYTES;
        validate_link_resolutions("a", "alias/file", &links, &mut remaining).unwrap();
        let used = MAX_SYNC_LINK_WORK_BYTES - remaining;
        remaining = 2 * used - 1;
        validate_link_resolutions("a", "alias/file", &links, &mut remaining).unwrap();
        let error =
            validate_link_resolutions("b", "alias/file", &links, &mut remaining).unwrap_err();
        assert!(error.to_string().contains("work limit"), "{error:#}");
    }

    /// A failed download must not leave a link that escapes through a destination
    /// link scheduled for deletion or replacement later in the same plan.
    #[test]
    #[cfg(unix)]
    fn download_rejects_links_through_pending_deletions_and_replacements() {
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
            let (src, dst, _) = parse_endpoints(&args.src, &args.dst).unwrap();
            let error = sync_guest_to_host(&mut peer(&replies), &src, &dst, &args).unwrap_err();
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

    #[test]
    #[cfg(unix)]
    fn host_operations_refuse_existing_symlink_ancestors() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
        assert!(checked_host_path(root.path(), "link/file").is_err());
        assert!(checked_host_path(root.path(), "link").is_ok());
    }

    #[test]
    fn empty_directory_download_creates_root_but_dry_run_does_not() {
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
        let (src, dst, _) = parse_endpoints(&args.src, &args.dst).unwrap();
        let replies = [
            SyncReply::SessionReady {
                root_status: RootStatus::ExistingDirectory,
            },
            SyncReply::Entry(entry("", SyncEntryKind::Directory, None)),
            SyncReply::ScanComplete,
            SyncReply::Success,
        ];
        sync_guest_to_host(&mut peer(&replies), &src, &dst, &args).unwrap();
        assert!(!destination.exists());
        args.dry_run = false;
        sync_guest_to_host(&mut peer(&replies), &src, &dst, &args).unwrap();
        assert!(destination.is_dir());
        assert_eq!(
            meta_mtime_secs(&std::fs::metadata(&destination).unwrap()),
            100
        );
    }

    #[test]
    fn interrupted_download_preserves_destination_and_suppresses_deletion() {
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
            .is_err()
        );
        assert_eq!(std::fs::read(file).unwrap(), b"old");
        assert_eq!(std::fs::read(extra).unwrap(), b"keep");
        assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 2);
    }

    #[test]
    fn windows_names_cannot_alias_devices_or_streams() {
        for name in [
            "NUL",
            "con.txt",
            "COM1",
            "a:stream",
            "a\\b",
            "trailing.",
            "trailing ",
        ] {
            assert!(validate_windows_name(name).is_err(), "{name}");
        }
        assert!(validate_windows_name("normal.txt").is_ok());
    }

    #[test]
    fn download_requires_the_planned_metadata_and_completion_reply() {
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
                .is_err()
            );
            assert_eq!(std::fs::read(&destination).unwrap(), b"old");
        }
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

    #[test]
    fn parse_endpoint_identifies_guest_and_host() {
        assert_eq!(
            parse_endpoint("box:/app/out").unwrap(),
            Endpoint::Guest {
                path: "/app/out".to_string(),
                has_trailing_separator: false,
            }
        );
        assert_eq!(
            parse_endpoint(":/app/out/").unwrap(),
            Endpoint::Guest {
                path: "/app/out".to_string(),
                has_trailing_separator: true,
            }
        );
        assert_eq!(
            parse_endpoint("./local/path/").unwrap(),
            Endpoint::Host {
                path: PathBuf::from("./local/path/"),
                has_trailing_separator: true,
            }
        );
    }

    #[test]
    fn relative_guest_path_is_rejected() {
        assert!(parse_endpoint("box:relative/path").is_err());
        assert!(parse_endpoint(":relative/path").is_err());
        for invalid in ["box://", "://", "box:////", ":////"] {
            assert!(
                parse_endpoint(invalid)
                    .unwrap_err()
                    .to_string()
                    .contains("guest path is empty")
            );
        }
        for root in ["box:/", ":/"] {
            assert_eq!(
                parse_endpoint(root).unwrap(),
                Endpoint::Guest {
                    path: "/".into(),
                    has_trailing_separator: true,
                }
            );
        }
    }

    #[test]
    fn named_box_prefix_suggests_cli_spelling() {
        let err = parse_endpoint("dev:/app").unwrap_err().to_string();
        assert!(err.contains("terra dev sync"), "{err}");
    }

    #[test]
    fn exactly_one_guest_endpoint_required() {
        assert!(parse_endpoints("box:/a", "box:/b").is_err());
        assert!(parse_endpoints("./a", "./b").is_err());
        assert!(parse_endpoints("./a", "box:/b").is_ok());
        assert!(parse_endpoints(":/a", "./b").is_ok());
    }

    #[test]
    fn symlink_escaping_destination_root_is_rejected() {
        assert!(validate_download_symlink_target("sub/link", "../../etc/passwd").is_err());
        assert!(validate_download_symlink_target("sub/link", "../foo").is_ok());
        assert!(validate_download_symlink_target("link", "../outside").is_err());
        assert!(validate_download_symlink_target("link", "/etc/passwd").is_err());
    }

    #[test]
    fn guest_error_cannot_drive_terminal() {
        let plain = "No such file or directory (os error 2)";
        assert_eq!(sanitize_guest_error_message(plain), plain);

        for raw in ["\x1b]0;pwned\x07", "\x1b[2J\x1b[H", "a\rterra: copied ok"] {
            let out = sanitize_guest_error_message(raw);
            assert!(!out.contains('\x1b'));
            assert!(!out.contains('\r'));
            assert!(!out.contains('\x07'));
        }
    }

    #[test]
    fn guest_cannot_hand_out_setuid_or_group_write_on_host() {
        assert_eq!(to_safe_mode(0o755), 0o755);
        assert_eq!(to_safe_mode(0o600), 0o600);
        assert_eq!(to_safe_mode(0o4755), 0o755);
        assert_eq!(to_safe_mode(0o2755), 0o755);
        assert_eq!(to_safe_mode(0o1777), 0o755);
        assert_eq!(to_safe_mode(0o666), 0o644);
        assert_eq!(to_safe_mode(u32::MAX), 0o755);
    }

    #[test]
    fn plan_detects_conflicts_between_directories_and_files() {
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

        let mut dummy = std::io::Cursor::new(Vec::new());
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
        .unwrap_err()
        .to_string();
        assert!(err2.contains("cannot overwrite directory"), "{err2}");
    }

    #[test]
    fn plan_deletions_gated_by_delete_flag() {
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

        let mut dummy = std::io::Cursor::new(Vec::new());
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
        .unwrap();
        assert_eq!(
            plan_with_delete,
            vec![PlanAction::RemoveEntry {
                rel_path: "extra.txt".to_string(),
                is_dir: false,
            }]
        );
    }

    #[test]
    fn plan_skips_when_metadata_matches_and_updates_when_it_differs() {
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

        let mut dummy = std::io::Cursor::new(Vec::new());
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

    #[test]
    fn placement_table_all_rows() {
        #[allow(clippy::fn_params_excessive_bools)]
        fn check(
            is_src_dir: bool,
            src_has_trailing: bool,
            src_name: &str,
            dst_path: &str,
            dst_has_trailing: bool,
            dst_is_existing_dir: bool,
        ) -> String {
            resolve_placement(
                SourcePlacement {
                    name: src_name,
                    is_dir: is_src_dir,
                    has_trailing: src_has_trailing || src_name.is_empty(),
                },
                DestinationPlacement {
                    path: dst_path,
                    is_existing_dir: dst_is_existing_dir,
                    has_trailing: dst_has_trailing,
                },
            )
        }

        // Row 1: file a -> existing directory dest/ -> dest/a
        assert_eq!(check(false, false, "a", "dest", true, true), "dest/a");
        assert_eq!(check(false, false, "a", "dest", false, true), "dest/a");

        // Row 2: file a -> file path or absent dest -> dest
        assert_eq!(check(false, false, "a", "dest", false, false), "dest");

        // Row 3: directory src/ -> directory or absent dest -> contents under dest/
        assert_eq!(check(true, true, "src", "dest", false, true), "dest");
        assert_eq!(check(true, true, "src", "dest", false, false), "dest");

        // Row 4: directory src -> existing directory dest -> subtree dest/src/
        assert_eq!(check(true, false, "src", "dest", false, true), "dest/src");

        // Row 5: directory src -> absent dest -> subtree rooted at dest/
        assert_eq!(check(true, false, "src", "dest", false, false), "dest");
    }
}
