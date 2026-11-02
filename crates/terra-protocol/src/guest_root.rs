//! The guest root image's fixed layout and workload identity, shared by the image build and the agent.

/// tmpfs directory the agent fills from the plan on every boot.
pub const PER_BOOT_DIR: &str = "/run/terra";
// The per-boot files' names inside `PER_BOOT_DIR`.
pub const PER_BOOT_RESOLV_CONF: &str = "resolv.conf";
pub const PER_BOOT_DOAS_CONF: &str = "doas.conf";
pub const PER_BOOT_DOAS_DIR: &str = "doas.d";
pub const PER_BOOT_LOCALTIME: &str = "localtime";
pub const PER_BOOT_SANDBOX_INFO: &str = "README.md";

/// Root paths linked to the per-boot file of that name in [`PER_BOOT_DIR`].
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
    for (link, name) in PER_BOOT_LINKS {
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
        std::os::unix::fs::symlink(std::path::Path::new(PER_BOOT_DIR).join(name), &link)?;
    }
    Ok(())
}

/// Workload user name (cosmetic, for shell prompts).
pub const WORKLOAD_USER_NAME: &str = "terri";

/// The non-root workload user's uid and gid.
pub const WORKLOAD_ID: u32 = 1000;

pub const WORKLOAD_HOME: &str = "/home/terri";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_workload_home_to_user() {
        assert_eq!(WORKLOAD_HOME, format!("/home/{WORKLOAD_USER_NAME}"));
    }

    #[test]
    fn every_link_names_a_per_boot_file_and_none_repeats() {
        let mut links = std::collections::BTreeSet::new();
        for (link, name) in PER_BOOT_LINKS {
            assert!(!name.is_empty() && !name.contains('/'), "{link} -> {name}");
            assert!(link.starts_with('/') && !link.starts_with(PER_BOOT_DIR));
            assert!(links.insert(link), "{link} repeats");
        }
    }
}
