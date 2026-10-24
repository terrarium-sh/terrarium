#![cfg_attr(test, allow(clippy::unwrap_used))]
//! Writes the workload user, its home and the per-boot symlinks into an unpacked root tree.

#[cfg(not(unix))]
fn main() {
    eprintln!("guest-identity builds the Linux guest image on a Unix host");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() -> std::io::Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let [tree, owners_file] = arguments.as_slice() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "usage: guest-identity TREE OWNERS_FILE",
        ));
    };
    unix::write_identity(tree.as_ref(), owners_file.as_ref())
}

#[cfg(unix)]
mod unix {
    use std::{fmt::Write as _, fs, io, io::Write, os::unix::fs::PermissionsExt, path::Path};

    use terra_protocol::guest_root::{SUBORDINATE_ID_COUNT, SUBORDINATE_ID_START};
    use terra_protocol::{WORKLOAD_HOME, WORKLOAD_ID, WORKLOAD_USER_NAME};

    const CONTAINERS_CONF_DIR: &str = ".config/containers";
    const CONTAINERS_CONF: &str = "[engine]\ncgroup_manager = \"cgroupfs\"\n";

    pub fn write_identity(tree: &Path, owners_file: &Path) -> io::Result<()> {
        let name = WORKLOAD_USER_NAME;
        let id = WORKLOAD_ID;
        append_once(
            tree,
            "etc/passwd",
            &format!("{name}:x:{id}:{id}::{WORKLOAD_HOME}:/bin/sh"),
        )?;
        append_once(tree, "etc/group", &format!("{name}:x:{id}:"))?;
        append_once(tree, "etc/shadow", &format!("{name}:!::0:::::"))?;
        let subordinate = format!("{name}:{SUBORDINATE_ID_START}:{SUBORDINATE_ID_COUNT}");
        append_once(tree, "etc/subuid", &subordinate)?;
        append_once(tree, "etc/subgid", &subordinate)?;

        let home = join(tree, WORKLOAD_HOME);
        let config_dir = home.join(CONTAINERS_CONF_DIR);
        fs::create_dir_all(&config_dir)?;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o755))?;
        fs::write(config_dir.join("containers.conf"), CONTAINERS_CONF)?;

        terra_protocol::guest_root::link_per_boot_files(tree)?;

        let mut owners = String::new();
        for path in [
            WORKLOAD_HOME.to_owned(),
            format!("{WORKLOAD_HOME}/.config"),
            format!("{WORKLOAD_HOME}/{CONTAINERS_CONF_DIR}"),
            format!("{WORKLOAD_HOME}/{CONTAINERS_CONF_DIR}/containers.conf"),
        ] {
            writeln!(owners, "sif {path} uid {id}\nsif {path} gid {id}")
                .map_err(io::Error::other)?;
        }
        fs::write(owners_file, owners)
    }

    fn join(tree: &Path, absolute: &str) -> std::path::PathBuf {
        tree.join(absolute.trim_start_matches('/'))
    }

    fn append_once(tree: &Path, file: &str, line: &str) -> io::Result<()> {
        let path = tree.join(file);
        let existing = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error),
        };
        let owner = line.split(':').next().unwrap_or_default();
        if existing.lines().any(|l| l.split(':').next() == Some(owner)) {
            return Ok(());
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        if !existing.is_empty() && !existing.ends_with('\n') {
            file.write_all(b"\n")?;
        }
        writeln!(file, "{line}")
    }

    #[cfg(test)]
    mod tests {
        use std::os::unix::fs::MetadataExt;

        use super::*;
        use terra_protocol::guest_root::PER_BOOT_LINKS;

        fn seeded_tree() -> tempfile::TempDir {
            let tree = tempfile::tempdir().unwrap();
            let root = tree.path();
            fs::create_dir_all(root.join("etc/doas.d")).unwrap();
            fs::write(root.join("etc/doas.d/x.conf"), "x").unwrap();
            fs::write(root.join("etc/doas.conf"), "permit root\n").unwrap();
            fs::write(root.join("etc/passwd"), "root:x:0:0:root:/root:/bin/sh\n").unwrap();
            fs::write(root.join("etc/group"), "root:x:0:root\n").unwrap();
            fs::write(root.join("etc/shadow"), "root:::0:::::\n").unwrap();
            fs::set_permissions(root.join("etc/shadow"), fs::Permissions::from_mode(0o640))
                .unwrap();
            tree
        }

        #[test]
        fn lines_are_appended_once_and_modes_kept() {
            let tree = seeded_tree();
            let owners = tree.path().join("owners");
            write_identity(tree.path(), &owners).unwrap();
            write_identity(tree.path(), &owners).unwrap();
            let read = |file: &str| fs::read_to_string(tree.path().join(file)).unwrap();
            assert_eq!(
                read("etc/passwd"),
                "root:x:0:0:root:/root:/bin/sh\nterri:x:1000:1000::/home/terri:/bin/sh\n"
            );
            assert_eq!(read("etc/group"), "root:x:0:root\nterri:x:1000:\n");
            assert_eq!(read("etc/shadow"), "root:::0:::::\nterri:!::0:::::\n");
            assert_eq!(read("etc/subuid"), "terri:100000:65536\n");
            assert_eq!(read("etc/subgid"), "terri:100000:65536\n");
            let mode = fs::metadata(tree.path().join("etc/shadow")).unwrap().mode();
            assert_eq!(mode & 0o777, 0o640);
        }

        #[test]
        fn unreadable_identity_files_are_left_unchanged() {
            let tree = seeded_tree();
            let path = tree.path().join("etc/passwd");
            let contents = b"root:\xff";
            fs::write(&path, contents).unwrap();
            let error = write_identity(tree.path(), &tree.path().join("owners")).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(fs::read(path).unwrap(), contents);
        }

        #[test]
        fn links_replace_existing_files_and_directories() {
            let tree = seeded_tree();
            write_identity(tree.path(), &tree.path().join("owners")).unwrap();
            for (link, target) in PER_BOOT_LINKS {
                let read = fs::read_link(join(tree.path(), link)).unwrap();
                assert_eq!(read, Path::new(target), "{link}");
            }
            assert!(tree.path().join("terra").is_dir());
        }

        #[test]
        fn home_and_owners_cover_exactly_the_workload_paths() {
            let tree = seeded_tree();
            let owners = tree.path().join("owners");
            write_identity(tree.path(), &owners).unwrap();
            let conf = tree
                .path()
                .join("home/terri/.config/containers/containers.conf");
            assert_eq!(fs::read_to_string(conf).unwrap(), CONTAINERS_CONF);
            assert_eq!(
                fs::read_to_string(owners).unwrap(),
                "sif /home/terri uid 1000\nsif /home/terri gid 1000\n\
                 sif /home/terri/.config uid 1000\nsif /home/terri/.config gid 1000\n\
                 sif /home/terri/.config/containers uid 1000\nsif /home/terri/.config/containers gid 1000\n\
                 sif /home/terri/.config/containers/containers.conf uid 1000\n\
                 sif /home/terri/.config/containers/containers.conf gid 1000\n"
            );
        }
    }
}
