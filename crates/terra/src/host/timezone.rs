use std::path::Path;
use terra_shared::HostTimezone;

pub fn collect() -> Option<HostTimezone> {
    collect_from_path(Path::new("/etc/localtime"))
}

fn collect_from_path(path: &Path) -> Option<HostTimezone> {
    #[cfg(unix)]
    {
        if let Ok(bytes) = std::fs::read(path)
            && bytes.len() >= 4
            && bytes[0..4] == *b"TZif"
        {
            return Some(HostTimezone::Tzif(bytes));
        }
        if let Ok(target) = std::fs::read_link(path) {
            let s = target.to_string_lossy();
            if let Some(pos) = s.find("zoneinfo/") {
                let name = &s[pos + "zoneinfo/".len()..];
                if !name.is_empty() && !name.contains('\0') {
                    return Some(HostTimezone::Iana(name.to_string()));
                }
            } else {
                let candidate = s.trim_start_matches('/');
                if candidate.contains('/') && !candidate.contains("..") && !candidate.contains('\0')
                {
                    return Some(HostTimezone::Iana(candidate.to_string()));
                }
            }
        }
        None
    }
    #[cfg(windows)]
    {
        // ponytail: Windows host mapping deferred — guest keeps UTC until needed.
        let _ = path;
        None
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn tzif_read_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("localtime");
        let mut bytes = b"TZif".to_vec();
        bytes.extend_from_slice(&[0u8; 32]);
        std::fs::write(&p, &bytes).unwrap();
        assert_eq!(collect_from_path(&p), Some(HostTimezone::Tzif(bytes)));
    }

    #[test]
    fn iana_from_symlink_zoneinfo() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("localtime");
        // Use a path that looks like zoneinfo but does not exist, so fs::read follows
        // the link and fails, falling through to the symlink name path.
        // If the file existed, collect would prefer Tzif (raw bytes).
        let target = Path::new("/usr/share/zoneinfo/Europe/Prague");
        // Create a dangling link to a unique name to force the Iana branch.
        let dangling = Path::new("/usr/share/zoneinfo/Europe/Prague-tz-test-nonexistent");
        symlink(dangling, &p).unwrap();
        let _ = target; // keep original intent documented
        assert_eq!(
            collect_from_path(&p),
            Some(HostTimezone::Iana(
                "Europe/Prague-tz-test-nonexistent".into()
            ))
        );
    }

    #[test]
    fn iana_from_relative_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("localtime");
        symlink(Path::new("Europe/Prague"), &p).unwrap();
        assert_eq!(
            collect_from_path(&p),
            Some(HostTimezone::Iana("Europe/Prague".into()))
        );
    }

    #[test]
    fn unmapped_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("localtime");
        std::fs::write(&p, b"not tzif").unwrap();
        // regular file not TZif and not a symlink -> None
        assert_eq!(collect_from_path(&p), None);
    }

    #[test]
    fn missing_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("missing");
        assert_eq!(collect_from_path(&p), None);
    }
}
