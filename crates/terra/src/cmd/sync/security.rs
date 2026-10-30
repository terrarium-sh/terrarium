use anyhow::{Context, Result};
use std::collections::{BTreeMap, VecDeque};
use std::path::{Component, Path};
use terra_protocol::{
    MAX_FILE_BYTES, MAX_SYNC_ERROR_BYTES, MAX_SYNC_PATH_BYTES, RootStatus, SyncDirection,
    SyncEntry, SyncEntryKind, validate_relative_path,
};

const MAX_SYNC_LINK_WORK_BYTES: usize = 64 * 1024 * 1024;
/// Linux's own limit on symlinks followed in one resolution.
const MAX_SYMLINK_FOLLOWS: usize = 40;

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
    windows_host_mode(meta.permissions().readonly())
}

/// Windows stores only the read-only attribute, so like a mount a host entry is `0755` or `0555`.
#[cfg(windows)]
fn windows_host_mode(is_readonly: bool) -> u32 {
    if is_readonly { 0o555 } else { 0o755 }
}

pub(super) fn to_safe_mode(guest_mode: u32) -> u32 {
    guest_mode & 0o755
}

pub(super) fn effective_mode(mode: u32, direction: SyncDirection) -> u32 {
    #[cfg(windows)]
    if direction == SyncDirection::GuestToHost {
        return windows_host_mode(mode & 0o200 == 0);
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
    let links: BTreeMap<&str, Vec<LinkSide>> = source
        .iter()
        .chain(destination)
        .filter(|(_, entry)| entry.link_target.is_some())
        .map(|(path, _)| {
            let sides = link_sides(source.get(path), destination.get(path));
            (path.as_str(), sides)
        })
        .collect();
    let mut remaining_work = MAX_SYNC_LINK_WORK_BYTES;
    for path in links.keys() {
        validate_link_resolutions(path, &links, &mut remaining_work, resolve_component)?;
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LinkAuthor {
    Guest,
    Host,
}

/// One side's entry at a path that is a symlink on either side; `target` is `None` for a guest
/// file or directory that replaces a host link.
#[derive(Clone, Copy)]
struct LinkSide<'a> {
    target: Option<&'a str>,
    author: LinkAuthor,
}

/// The guest's entry, which the sync installs, then a host link it does not repeat, which may
/// survive without `--delete`.
fn link_sides<'a>(guest: Option<&'a SyncEntry>, host: Option<&'a SyncEntry>) -> Vec<LinkSide<'a>> {
    let guest = guest.map(|entry| LinkSide {
        target: entry.link_target.as_deref(),
        author: LinkAuthor::Guest,
    });
    let host = host
        .and_then(|entry| entry.link_target.as_deref())
        .filter(|target| guest.is_none_or(|guest| guest.target != Some(*target)))
        .map(|target| LinkSide {
            target: Some(target),
            author: LinkAuthor::Host,
        });
    guest.into_iter().chain(host).collect()
}

fn spend_link_work(remaining: &mut usize, bytes: usize) -> Result<()> {
    *remaining = remaining
        .checked_sub(bytes)
        .context("symlink resolution exceeded its work limit; sync a smaller subtree")?;
    Ok(())
}

/// One partial resolution of a link chain.
struct Branch {
    resolved: Vec<String>,
    pending: VecDeque<String>,
    followed: usize,
    is_guest_influenced: bool,
}

/// Walks every resolution of the link at `path`, through each side of every link it crosses. A
/// chain that touches no guest entry is the host's own and may leave the root.
fn validate_link_resolutions(
    path: &str,
    links: &BTreeMap<&str, Vec<LinkSide>>,
    remaining_work: &mut usize,
    resolve_component: &impl Fn(&str, &str) -> Result<String>,
) -> Result<()> {
    let mut resolved: Vec<String> = path.split('/').map(str::to_owned).collect();
    let name = resolved.pop().unwrap_or_default();
    let mut branches = vec![Branch {
        resolved,
        pending: VecDeque::from([name]),
        followed: 0,
        is_guest_influenced: false,
    }];
    while let Some(branch) = branches.pop() {
        walk_branch(
            branch,
            links,
            remaining_work,
            resolve_component,
            &mut branches,
        )?;
    }
    Ok(())
}

/// Resolves `branch` up to the next link, where it forks one branch per side of that link.
fn walk_branch(
    mut branch: Branch,
    links: &BTreeMap<&str, Vec<LinkSide>>,
    remaining_work: &mut usize,
    resolve_component: &impl Fn(&str, &str) -> Result<String>,
    branches: &mut Vec<Branch>,
) -> Result<()> {
    while let Some(component) = branch.pending.pop_front() {
        spend_link_work(remaining_work, component.len() + 1)?;
        match component.as_str() {
            "" | "." => continue,
            ".." => {
                if branch.resolved.pop().is_none() {
                    anyhow::ensure!(
                        !branch.is_guest_influenced,
                        "guest symlink chain escapes destination root"
                    );
                    return Ok(());
                }
                continue;
            }
            _ => {}
        }
        #[cfg(windows)]
        validate_windows_name(&component)?;
        let parent = branch.resolved.join("/");
        spend_link_work(remaining_work, parent.len())?;
        branch
            .resolved
            .push(resolve_component(&parent, &component)?);
        let name = branch.resolved.join("/");
        spend_link_work(remaining_work, name.len())?;
        let Some(sides) = links.get(name.as_str()) else {
            continue;
        };
        for side in sides {
            let copy_bytes = name.len()
                + branch
                    .pending
                    .iter()
                    .map(|part| part.len() + 1)
                    .sum::<usize>()
                + side.target.map_or(0, str::len)
                + 1;
            spend_link_work(remaining_work, copy_bytes)?;
            let mut next = Branch {
                resolved: branch.resolved.clone(),
                pending: branch.pending.clone(),
                followed: branch.followed,
                is_guest_influenced: branch.is_guest_influenced || side.author == LinkAuthor::Guest,
            };
            if let Some(link) = side.target {
                next.followed += 1;
                if !follows_link(&name, link, next.followed, next.is_guest_influenced)? {
                    continue;
                }
                next.resolved.pop();
                for part in link.split('/').rev() {
                    next.pending.push_front(part.to_owned());
                }
            }
            branches.push(next);
        }
        return Ok(());
    }
    Ok(())
}

/// A guest-influenced chain must stay inside the root; a host-only chain is dropped where it
/// leaves what the walk can follow.
fn follows_link(
    name: &str,
    link: &str,
    followed: usize,
    is_guest_influenced: bool,
) -> Result<bool> {
    if !is_guest_influenced {
        let is_rooted = matches!(
            Path::new(link).components().next(),
            Some(Component::Prefix(_) | Component::RootDir)
        );
        return Ok(followed <= MAX_SYMLINK_FOLLOWS && !is_rooted);
    }
    anyhow::ensure!(
        followed <= MAX_SYMLINK_FOLLOWS,
        "guest symlink chain is cyclic or too deep"
    );
    validate_download_symlink_target(name, link)?;
    Ok(true)
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

    /// A Windows host file uploads executable, as a mount shows it, and a download predicts the
    /// mode the host then reports, so neither direction rewrites modes on every sync.
    #[cfg(windows)]
    #[test]
    fn windows_host_modes_match_mounts_in_both_directions() {
        let file = tempfile::NamedTempFile::new().unwrap();
        for (is_readonly, guest_mode) in [(true, 0o444), (false, 0o644)] {
            let mut permissions = file.as_file().metadata().unwrap().permissions();
            permissions.set_readonly(is_readonly);
            std::fs::set_permissions(file.path(), permissions).unwrap();
            let host_mode = to_guest_mode(&file.as_file().metadata().unwrap());
            assert_eq!(host_mode, if is_readonly { 0o555 } else { 0o755 });
            assert_eq!(
                effective_mode(guest_mode, SyncDirection::GuestToHost),
                host_mode
            );
        }
    }

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

    /// A surviving destination link is re-walked: without `--delete`, a guest that once synced
    /// `a -> x/..` with `x -> deep/sub` could later retarget `x -> .` and leave `a` pointing at
    /// the destination's parent. Host-written links that touch no guest entry still pass.
    #[test]
    fn surviving_destination_links_cannot_be_redirected_out_of_the_root() {
        let destination = BTreeMap::from([
            ("a".into(), entry("a", SyncEntryKind::Symlink, Some("x/.."))),
            (
                "x".into(),
                entry("x", SyncEntryKind::Symlink, Some("deep/sub")),
            ),
            (
                "host".into(),
                entry("host", SyncEntryKind::Symlink, Some("/tmp")),
            ),
            (
                "up".into(),
                entry("up", SyncEntryKind::Symlink, Some("../sibling")),
            ),
        ]);
        let mut source = BTreeMap::from([(
            "x".into(),
            entry("x", SyncEntryKind::Symlink, Some("deep/sub")),
        )]);
        validate_links(&source, &destination).unwrap();
        source.get_mut("x").unwrap().link_target = Some(".".into());
        assert!(validate_links(&source, &destination).is_err());
        source.insert("x".into(), entry("x", SyncEntryKind::Directory, None));
        let mut deeper = destination.clone();
        deeper.get_mut("a").unwrap().link_target = Some("x/../..".into());
        assert!(validate_links(&BTreeMap::new(), &deeper).is_ok());
        assert!(validate_links(&source, &deeper).is_err());
    }

    /// A Windows host link leaves the root through a drive as well as through `/`; read as a
    /// relative path, `C:` would fail the guest's Windows name check.
    #[cfg(windows)]
    #[test]
    fn windows_host_links_to_a_drive_leave_the_root() {
        let destination = BTreeMap::from(
            [
                ("drive", "C:/dir"),
                ("drive_relative", "C:dir"),
                ("share", "//server/share"),
            ]
            .map(|(path, target)| {
                (
                    path.to_owned(),
                    entry(path, SyncEntryKind::Symlink, Some(target)),
                )
            }),
        );
        validate_links(&BTreeMap::new(), &destination).unwrap();
    }

    /// Resolution work, including branches through old and new targets, consumes
    /// one budget shared by all source links rather than restarting per link.
    #[test]
    fn link_resolution_budget_is_shared_across_source_links() {
        let [a, b] = ["a", "b"].map(|name| entry(name, SyncEntryKind::Symlink, Some("alias/file")));
        let guest_alias = entry("alias", SyncEntryKind::Symlink, Some("."));
        let host_alias = entry("alias", SyncEntryKind::Symlink, Some("subdir"));
        let links = BTreeMap::from([
            ("a", link_sides(Some(&a), None)),
            ("b", link_sides(Some(&b), None)),
            ("alias", link_sides(Some(&guest_alias), Some(&host_alias))),
        ]);
        let walk = |path, remaining: &mut usize| {
            validate_link_resolutions(path, &links, remaining, &|_, component| {
                Ok(component.to_owned())
            })
        };
        let mut remaining = MAX_SYNC_LINK_WORK_BYTES;
        walk("a", &mut remaining).unwrap();
        let used = MAX_SYNC_LINK_WORK_BYTES - remaining;
        remaining = 2 * used - 1;
        walk("a", &mut remaining).unwrap();
        let error = walk("b", &mut remaining).unwrap_err();
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
