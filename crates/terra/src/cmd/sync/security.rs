use anyhow::{Context, Result};
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use terra_protocol::{
    MAX_FILE_BYTES, MAX_SYNC_ERROR_BYTES, MAX_SYNC_PATH_BYTES, RootStatus, SyncDirection,
    SyncEntry, SyncEntryKind, validate_relative_path,
};

const MAX_SYNC_LINK_WORK_BYTES: usize = 64 * 1024 * 1024;

pub(super) fn sanitize_guest_error_message(err: &str) -> String {
    let mut chars = err.chars();
    let message: String = chars.by_ref().take(MAX_SYNC_ERROR_BYTES).collect();
    let mut out = crate::render::escape_printable(&message);
    if chars.next().is_some() {
        out.push('…');
    }
    out
}

pub(super) fn to_guest_mode(meta: &std::fs::Metadata) -> u32 {
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

pub(super) fn to_safe_mode(guest_mode: u32) -> u32 {
    guest_mode & 0o755
}

pub(super) fn effective_mode(mode: u32, direction: SyncDirection, kind: SyncEntryKind) -> u32 {
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

pub(super) fn validate_manifest(entries: &BTreeMap<String, SyncEntry>) -> Result<()> {
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
                .any(|c| c.is_control() || "<>:\"/\\|?*~".contains(c)),
        "sync name is not supported on Windows; rename devices, short-name aliases, or invalid characters"
    );
    Ok(())
}

pub(super) fn validate_root_kind(
    entries: &BTreeMap<String, SyncEntry>,
    status: RootStatus,
) -> Result<()> {
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

pub(super) fn validate_download_links(
    source: &BTreeMap<String, SyncEntry>,
    destination: &BTreeMap<String, SyncEntry>,
    resolve_component: &impl Fn(&str, &str) -> Result<String>,
) -> Result<()> {
    let mut links = BTreeMap::new();
    for (path, entry) in source.iter().chain(destination) {
        if entry.link_target.is_some() {
            links.insert(
                path.clone(),
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
            validate_link_resolutions(
                path,
                target,
                &links,
                &mut remaining_work,
                resolve_component,
            )?;
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
    resolve_component: &impl Fn(&str, &str) -> Result<String>,
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
            let parent = resolved.join("/");
            spend_link_work(remaining_work, parent.len())?;
            resolved.push(resolve_component(&parent, &component)?);
            let name = resolved.join("/");
            spend_link_work(remaining_work, name.len())?;
            if let Some(targets) = links.get(&name) {
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

pub(super) fn validate_download_symlink_target(entry_rel_path: &str, target: &str) -> Result<()> {
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
    for component in target
        .split('/')
        .filter(|part| !matches!(*part, "" | "." | ".."))
    {
        validate_windows_name(component)?;
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

#[cfg(test)]
mod tests {
    use super::super::test_support::entry;
    use super::*;

    fn validate_links(
        source: &BTreeMap<String, SyncEntry>,
        destination: &BTreeMap<String, SyncEntry>,
    ) -> Result<()> {
        validate_download_links(
            source,
            destination,
            &|_, component| Ok(component.to_owned()),
        )
    }

    #[test]
    fn sync_manifests_accept_unicode_names() {
        for name in [
            "café",
            "cafe\u{301}",
            "ß",
            "ſ",
            "日本語",
            "file with spaces",
        ] {
            let entries = BTreeMap::from([(name.into(), entry(name, SyncEntryKind::File, None))]);
            validate_manifest(&entries).unwrap();
            validate_download_symlink_target("link", name).unwrap();
        }
    }

    #[test]
    fn windows_names_reject_devices_streams_and_short_aliases() {
        for name in [
            "NUL", "con.txt", "COM1", "COM¹", "a:stream", "a\\b", "a.", "a ", "LONGFI~1",
        ] {
            assert!(validate_windows_name(name).is_err(), "{name}");
        }
        for name in ["café", "日本語", "file with spaces.txt"] {
            validate_windows_name(name).unwrap();
        }
    }

    #[test]
    fn symlink_chains_cannot_escape_through_dot_dot() {
        let mut source = BTreeMap::from([
            ("a".into(), entry("a", SyncEntryKind::Symlink, Some("."))),
            ("b".into(), entry("b", SyncEntryKind::Symlink, Some("a/.."))),
        ]);
        assert!(validate_links(&source, &BTreeMap::new()).is_err());
        source.get_mut("b").unwrap().link_target = Some("a/safe".into());
        assert!(validate_links(&source, &BTreeMap::new()).is_ok());
        let destination = BTreeMap::from([(
            "outside".into(),
            entry("outside", SyncEntryKind::Symlink, Some("/tmp")),
        )]);
        source.get_mut("b").unwrap().link_target = Some("outside/file".into());
        assert!(validate_links(&source, &destination).is_err());
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
        assert!(validate_links(&source, &BTreeMap::new()).is_ok());
        assert!(validate_links(&source, &destination).is_err());
    }

    /// Resolution work, including branches through old and new targets, consumes
    /// one budget shared by all source links rather than restarting per link.
    #[test]
    fn link_resolution_budget_is_shared_across_source_links() {
        let links = BTreeMap::from([("alias".into(), [Some("."), Some("subdir")])]);
        let mut remaining = MAX_SYNC_LINK_WORK_BYTES;
        validate_link_resolutions(
            "a",
            "alias/file",
            &links,
            &mut remaining,
            &|_, component| Ok(component.to_owned()),
        )
        .unwrap();
        let used = MAX_SYNC_LINK_WORK_BYTES - remaining;
        remaining = 2 * used - 1;
        validate_link_resolutions(
            "a",
            "alias/file",
            &links,
            &mut remaining,
            &|_, component| Ok(component.to_owned()),
        )
        .unwrap();
        let error = validate_link_resolutions(
            "b",
            "alias/file",
            &links,
            &mut remaining,
            &|_, component| Ok(component.to_owned()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("work limit"), "{error:#}");
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
}
