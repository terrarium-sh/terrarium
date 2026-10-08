use crate::{Access, Grant, Role};
use anyhow::{Context, Result, bail, ensure};
use std::collections::BTreeSet;
use std::path::Path;

pub(super) const fn marker(role: Role) -> &'static [u8] {
    match role {
        Role::Supervisor => b"terra-app-sandbox-v1:supervisor",
        Role::Vm => b"terra-app-sandbox-v1:vm",
        Role::Network => b"terra-app-sandbox-v1:network",
    }
}

pub(super) fn render_entitlements(
    role: Role,
    grants: &[Grant],
    denied_probe: &Path,
) -> Result<String> {
    ensure!(
        role != Role::Supervisor,
        "the macOS supervisor owns lifecycle authority"
    );
    let denied_probe = std::fs::canonicalize(denied_probe)?;
    let mut read_only = BTreeSet::new();
    let mut read_write = BTreeSet::new();
    let mut resolved_grants = Vec::new();
    for grant in grants {
        ensure!(
            grant.path.is_absolute(),
            "macOS sandbox grant must be absolute: {}",
            grant.path.display()
        );
        let (path, is_directory) = resolve_grant_path(grant)?;
        resolved_grants.push((path.clone(), is_directory, grant.access));
        ensure!(
            path != denied_probe && !(is_directory && denied_probe.starts_with(&path)),
            "macOS sandbox grant {} covers the confinement probe; narrow the grant",
            grant.path.display()
        );
        let path = path
            .to_str()
            .with_context(|| format!("macOS sandbox grant must be UTF-8: {}", path.display()))?;
        let mut path = escape_xml(path)?;
        if is_directory && !path.ends_with('/') {
            path.push('/');
        }
        match grant.access {
            Access::ReadOnly => {
                read_only.insert(path);
            }
            Access::ReadWrite => {
                read_write.insert(path);
            }
            Access::Device => bail!("macOS device grants require an explicit platform entitlement"),
        }
    }
    for (read_only_path, _, access) in &resolved_grants {
        if *access != Access::ReadOnly {
            continue;
        }
        ensure!(
            !resolved_grants
                .iter()
                .any(|(writable_path, is_directory, access)| {
                    *access == Access::ReadWrite
                        && (read_only_path == writable_path
                            || (*is_directory && read_only_path.starts_with(writable_path)))
                }),
            "macOS App Sandbox cannot keep {} read-only inside a writable grant; narrow the writable grant",
            read_only_path.display()
        );
    }
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n<key>com.apple.security.app-sandbox</key><true/>\n",
    );
    match role {
        Role::Vm => {
            xml.push_str("<key>com.apple.security.hypervisor</key><true/>\n");
            // Wasmtime publishes its AOT code using mprotect, rather than MAP_JIT.
            xml.push_str(
                "<key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>\n",
            );
        }
        Role::Network => {
            xml.push_str("<key>com.apple.security.network.client</key><true/>\n<key>com.apple.security.network.server</key><true/>\n");
        }
        Role::Supervisor => unreachable!("the supervisor was rejected above"),
    }
    append_paths(&mut xml, "read-only", read_only);
    append_paths(&mut xml, "read-write", read_write);
    xml.push_str("</dict></plist>\n");
    Ok(xml)
}

fn resolve_grant_path(grant: &Grant) -> Result<(std::path::PathBuf, bool)> {
    match std::fs::metadata(&grant.path) {
        Ok(metadata) => {
            if let Some(directory) = &grant.directory {
                let pinned = directory.metadata()?;
                ensure!(
                    metadata.is_dir() && pinned.is_dir(),
                    "macOS directory grant is not a directory"
                );
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    ensure!(
                        metadata.dev() == pinned.dev() && metadata.ino() == pinned.ino(),
                        "macOS sandbox grant {} changed after being opened",
                        grant.path.display()
                    );
                }
            }
            Ok((std::fs::canonicalize(&grant.path)?, metadata.is_dir()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure!(
                grant.directory.is_none(),
                "macOS pinned directory grant is missing"
            );
            let parent = grant
                .path
                .parent()
                .context("macOS sandbox grant has no parent")?;
            let name = grant
                .path
                .file_name()
                .context("macOS sandbox grant has no filename")?;
            Ok((std::fs::canonicalize(parent)?.join(name), false))
        }
        Err(error) => Err(error)
            .with_context(|| format!("reading macOS sandbox grant {}", grant.path.display())),
    }
}

fn append_paths(xml: &mut String, access: &str, paths: BTreeSet<String>) {
    if paths.is_empty() {
        return;
    }
    xml.push_str("<key>com.apple.security.temporary-exception.files.absolute-path.");
    xml.push_str(access);
    xml.push_str("</key><array>\n");
    for path in paths {
        xml.push_str("<string>");
        xml.push_str(&path);
        xml.push_str("</string>\n");
    }
    xml.push_str("</array>\n");
}

pub(super) fn escape_xml(value: &str) -> Result<String> {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            '\t'
            | '\n'
            | '\r'
            | ' '..='\u{d7ff}'
            | '\u{e000}'..='\u{fffd}'
            | '\u{10000}'..='\u{10ffff}' => escaped.push(character),
            _ => bail!("macOS sandbox path contains a character unsupported by XML property lists"),
        }
    }
    Ok(escaped)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guest-controlled filenames cannot inject new entitlements, and each
    /// role has only its platform authority. A broad grant fails the
    /// independent activation probe instead of manufacturing a passing result.
    #[test]
    fn role_authority_and_grant_escaping_are_independent() -> Result<()> {
        let root = tempfile::tempdir()?;
        let probe = root.path().join("probe");
        std::fs::write(&probe, b"host-only")?;
        let share = root.path().join("share&'é");
        std::fs::create_dir(&share)?;
        let grants = [Grant::new(&share, Access::ReadOnly)];
        let vm = render_entitlements(Role::Vm, &grants, &probe)?;
        let network = render_entitlements(Role::Network, &[], &probe)?;
        assert!(vm.contains("com.apple.security.hypervisor"));
        assert!(vm.contains("com.apple.security.cs.allow-unsigned-executable-memory"));
        assert!(!vm.contains("com.apple.security.network."));
        assert!(vm.contains("share&amp;&apos;é/</string>"));
        assert_eq!(escape_xml("<>\"")?, "&lt;&gt;&quot;");
        assert!(network.contains("com.apple.security.network.client"));
        assert!(network.contains("com.apple.security.network.server"));
        assert!(!network.contains("com.apple.security.hypervisor"));
        assert!(!network.contains("com.apple.security.cs.allow-unsigned"));
        assert!(!network.contains("temporary-exception.files.absolute-path.read-write"));
        assert!(render_entitlements(Role::Supervisor, &[], &probe).is_err());
        assert!(
            render_entitlements(
                Role::Vm,
                &[Grant::new(root.path(), Access::ReadOnly)],
                &probe
            )
            .is_err()
        );
        assert!(escape_xml("illegal\0path").is_err());
        let writable_parent = root.path().join("writable");
        std::fs::create_dir(&writable_parent)?;
        let metadata = writable_parent.join("host.pid");
        std::fs::write(&metadata, "trusted identity")?;
        assert!(
            render_entitlements(
                Role::Vm,
                &[
                    Grant::new(&writable_parent, Access::ReadWrite),
                    Grant::new(&metadata, Access::ReadOnly),
                ],
                &probe
            )
            .is_err()
        );
        assert!(
            render_entitlements(
                Role::Vm,
                &[
                    Grant::new(&writable_parent, Access::ReadOnly),
                    Grant::new(&metadata, Access::ReadWrite),
                ],
                &probe
            )
            .is_ok()
        );
        for role in Role::ALL {
            assert!(marker(role).ends_with(role.name().as_bytes()));
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_replaced_directory_grant_fails_before_signing() -> Result<()> {
        let root = tempfile::tempdir()?;
        let share = root.path().join("share");
        let probe = root.path().join("probe");
        std::fs::create_dir(&share)?;
        std::fs::write(&probe, b"host-only")?;
        let mut grant = Grant::new(&share, Access::ReadOnly);
        grant.directory = Some(std::fs::File::open(&share)?);
        std::fs::rename(&share, root.path().join("original"))?;
        std::fs::create_dir(&share)?;
        assert!(render_entitlements(Role::Vm, &[grant], &probe).is_err());
        Ok(())
    }
}
