//! The guest root image's fixed layout, shared by the image build and the agent.

/// First subordinate uid and gid the workload user owns, for rootless containers.
pub const SUBORDINATE_ID_START: u32 = 100_000;
pub const SUBORDINATE_ID_COUNT: u32 = 65_536;

/// tmpfs directory the agent fills from the plan on every boot.
pub const PER_BOOT_DIR: &str = "/run/terra";
pub const PER_BOOT_RESOLV_CONF: &str = "/run/terra/resolv.conf";
pub const PER_BOOT_DOAS_CONF: &str = "/run/terra/doas.conf";
pub const PER_BOOT_DOAS_DIR: &str = "/run/terra/doas.d";
pub const PER_BOOT_LOCALTIME: &str = "/run/terra/localtime";
pub const PER_BOOT_SANDBOX_INFO: &str = "/run/terra/README.md";

/// Root paths linked to per-boot files on tmpfs.
pub const PER_BOOT_LINKS: [(&str, &str); 5] = [
    ("/etc/resolv.conf", PER_BOOT_RESOLV_CONF),
    ("/etc/doas.conf", PER_BOOT_DOAS_CONF),
    ("/etc/doas.d", PER_BOOT_DOAS_DIR),
    ("/etc/localtime", PER_BOOT_LOCALTIME),
    ("/terra/README.md", PER_BOOT_SANDBOX_INFO),
];

/// Restores [`PER_BOOT_LINKS`] after commands such as `sed -i` replace the symlinks.
#[cfg(unix)]
pub fn link_per_boot_files(root: &std::path::Path) -> std::io::Result<()> {
    for (link, target) in PER_BOOT_LINKS {
        let link = root.join(link.trim_start_matches('/'));
        match std::fs::symlink_metadata(&link) {
            Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(&link)?,
            Ok(_) => std::fs::remove_file(&link)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if let Some(parent) = link.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::os::unix::fs::symlink(target, &link)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_link_points_into_the_per_boot_dir_and_none_repeats() {
        let mut links = std::collections::BTreeSet::new();
        for (link, target) in PER_BOOT_LINKS {
            assert!(
                target.starts_with(&format!("{PER_BOOT_DIR}/")),
                "{link} -> {target}"
            );
            assert!(link.starts_with('/') && !link.starts_with(PER_BOOT_DIR));
            assert!(links.insert(link), "{link} repeats");
        }
    }
}
