use super::scan::{checked_host_path, optional_metadata};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, FileTimes};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use terra_protocol::{SyncEntry, SyncEntryKind};

pub(super) struct HostNames {
    directories: BTreeMap<String, usize>,
    probes: Vec<DirectoryProbe>,
}

impl HostNames {
    pub(super) fn new(
        root: &Path,
        source: &BTreeMap<String, SyncEntry>,
        destination: &BTreeMap<String, SyncEntry>,
    ) -> Result<Self> {
        let mut children = BTreeMap::<&str, BTreeSet<&str>>::new();
        for path in source
            .keys()
            .chain(destination.keys())
            .filter(|path| !path.is_empty())
        {
            let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
            children.entry(parent).or_default().insert(name);
        }
        let mut names = Self {
            directories: BTreeMap::new(),
            probes: Vec::new(),
        };
        for (parent, children) in children {
            names.add_directory(root, parent, destination)?;
            let probe = &names.probes[names.directories[parent]];
            for name in children {
                probe
                    .insert_name(name)
                    .with_context(|| format!("checking sync names in '{parent}'"))?;
            }
        }
        Ok(names)
    }

    fn add_directory(
        &mut self,
        root: &Path,
        relative: &str,
        destination: &BTreeMap<String, SyncEntry>,
    ) -> Result<()> {
        if self.directories.contains_key(relative) {
            return Ok(());
        }
        let path = checked_host_path(root, relative)?;
        let is_existing = if relative.is_empty() {
            optional_metadata(&path)?.is_some_and(|meta| meta.is_dir())
        } else {
            destination
                .get(relative)
                .is_some_and(|entry| entry.kind == SyncEntryKind::Directory)
        };
        let probe = if is_existing {
            DirectoryProbe::new(&path, true)?
        } else if relative.is_empty() {
            let mut ancestor = path;
            while !ancestor.is_dir() {
                anyhow::ensure!(
                    ancestor.pop(),
                    "sync destination has no existing parent directory"
                );
                if ancestor.as_os_str().is_empty() {
                    ancestor.push(".");
                }
            }
            DirectoryProbe::new(&ancestor, false)?
        } else {
            let parent = relative.rsplit_once('/').map_or("", |(parent, _)| parent);
            self.add_directory(root, parent, destination)?;
            DirectoryProbe::new(self.probes[self.directories[parent]].staging_path(), false)?
        };
        self.directories
            .insert(relative.to_owned(), self.probes.len());
        self.probes.push(probe);
        Ok(())
    }

    pub(super) fn resolve_component(&self, parent: &str, component: &str) -> Result<String> {
        let Some(index) = self.directories.get(parent) else {
            return Ok(component.to_owned());
        };
        match std::fs::read_to_string(self.probes[*index].names_path().join(component)) {
            Ok(name) => Ok(name),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(component.to_owned()),
            Err(error) => {
                Err(error).context("resolving a sync filename on the destination filesystem")
            }
        }
    }

    pub(super) fn close(mut self) -> Result<()> {
        let mut result = Ok(());
        while let Some(mut probe) = self.probes.pop() {
            if let Err(error) = probe.close() {
                result = Err(error);
            }
        }
        result
    }
}

impl Drop for HostNames {
    fn drop(&mut self) {
        while self.probes.pop().is_some() {}
    }
}

struct DirectoryProbe {
    staging: Option<TempDir>,
    path: PathBuf,
    parent: PathBuf,
    parent_times: FileTimes,
}

impl DirectoryProbe {
    /// `represents_parent` checks the existing directory's settings instead of a new child's inherited settings.
    fn new(parent: &Path, represents_parent: bool) -> Result<Self> {
        let parent_file = open_directory(parent)?;
        let parent_times = FileTimes::new().set_modified(parent_file.metadata()?.modified()?);
        let staging = tempfile::Builder::new().prefix(".terra-sync-names-").tempdir_in(parent)
            .with_context(|| format!("creating sync name probes in {}; the directory must be writable, including for dry runs", parent.display()))?;
        let probe = Self {
            path: staging.path().to_owned(),
            staging: Some(staging),
            parent: parent.to_owned(),
            parent_times,
        };
        std::fs::create_dir(probe.names_path())?;
        #[cfg(any(target_os = "linux", windows))]
        {
            let staging_file = open_directory(probe.staging_path())?;
            let names_file = open_directory(&probe.names_path())?;
            verify_comparison_settings(&staging_file, &names_file)?;
            if represents_parent {
                verify_comparison_settings(&parent_file, &names_file)?;
            }
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        let _ = represents_parent;
        Ok(probe)
    }

    fn staging_path(&self) -> &Path {
        &self.path
    }

    fn names_path(&self) -> PathBuf {
        self.staging_path().join("names")
    }

    fn insert_name(&self, name: &str) -> Result<()> {
        let path = self.names_path().join(name);
        match File::create_new(&path) {
            Ok(mut file) => file
                .write_all(name.as_bytes())
                .context("writing a sync name probe"),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let previous = std::fs::read_to_string(path)?;
                anyhow::bail!(
                    "sync names '{previous}' and '{name}' identify the same destination entry; rename one before syncing"
                )
            }
            Err(error) => Err(error).with_context(|| {
                format!("filename '{name}' cannot be created on the destination filesystem")
            }),
        }
    }

    fn close(&mut self) -> Result<()> {
        if let Some(staging) = self.staging.take() {
            let cleanup = staging.close().context("removing sync name probes");
            let restore = open_directory(&self.parent)
                .and_then(|directory| directory.set_times(self.parent_times))
                .context("restoring directory timestamp after sync name probes");
            cleanup?;
            restore?;
        }
        Ok(())
    }
}

impl Drop for DirectoryProbe {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn open_directory(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES,
        };
        options
            .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    }
    options.open(path)
}

#[cfg(any(target_os = "linux", windows))]
fn verify_comparison_settings(parent: &File, probe: &File) -> Result<()> {
    anyhow::ensure!(
        read_case_setting(parent)? == read_case_setting(probe)?,
        "destination directory does not inherit its filename comparison settings; sync into a directory with inherited settings"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
/// `None` means the filesystem does not expose per-directory case settings.
fn read_case_setting(directory: &File) -> Result<Option<u32>> {
    const FS_CASEFOLD_FL: u32 = 0x4000_0000;
    match rustix::fs::ioctl_getflags(directory) {
        Ok(flags) => Ok(Some(flags.bits() & FS_CASEFOLD_FL)),
        Err(rustix::io::Errno::NOTTY | rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::INVAL) => {
            Ok(None)
        }
        Err(error) => Err(error).context("reading directory case-folding settings"),
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
/// `None` means the filesystem does not expose per-directory case settings.
fn read_case_setting(directory: &File) -> Result<Option<u32>> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_CASE_SENSITIVE_INFO, FileCaseSensitiveInfo, GetFileInformationByHandleEx,
    };
    let mut info = FILE_CASE_SENSITIVE_INFO::default();
    // SAFETY: the live directory handle and correctly sized output buffer match the information class.
    let result = unsafe {
        GetFileInformationByHandleEx(
            directory.as_raw_handle(),
            FileCaseSensitiveInfo,
            std::ptr::from_mut(&mut info).cast(),
            u32::try_from(std::mem::size_of_val(&info))?,
        )
    };
    if result != 0 {
        return Ok(Some(info.Flags));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error().is_some_and(|code| {
        code == ERROR_INVALID_PARAMETER.cast_signed() || code == ERROR_NOT_SUPPORTED.cast_signed()
    }) {
        return Ok(None);
    }
    Err(error).context("reading directory case-sensitivity settings")
}

#[cfg(test)]
mod tests {
    use super::super::security::validate_download_links;
    use super::super::test_support::entry;
    use super::*;

    #[test]
    fn collision_checks_follow_the_actual_filesystem() {
        for (name, alias) in [
            ("café", "cafe\u{301}"),
            ("ß", "ss"),
            ("ſ", "S"),
            ("Data", "data"),
        ] {
            let root = tempfile::tempdir().unwrap();
            std::fs::write(root.path().join(name), b"keep").unwrap();
            let is_alias = root.path().join(alias).exists();
            let modified = root.path().metadata().unwrap().modified().unwrap();
            let source = BTreeMap::from([(alias.into(), entry(alias, SyncEntryKind::File, None))]);
            let destination =
                BTreeMap::from([(name.into(), entry(name, SyncEntryKind::File, None))]);
            let result = HostNames::new(root.path(), &source, &destination);
            assert_eq!(result.is_err(), is_alias, "{name}, {alias}");
            if let Ok(names) = result {
                assert_eq!(names.resolve_component("", name).unwrap(), name);
                assert_eq!(names.resolve_component("", alias).unwrap(), alias);
                names.close().unwrap();
            }
            assert_eq!(std::fs::read(root.path().join(name)).unwrap(), b"keep");
            assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
            assert_eq!(
                root.path().metadata().unwrap().modified().unwrap(),
                modified
            );

            HostNames::new(root.path(), &destination, &destination)
                .unwrap()
                .close()
                .unwrap();
            let mut combined = destination.clone();
            combined.extend(source);
            let result = HostNames::new(root.path(), &combined, &BTreeMap::new());
            assert_eq!(
                result.is_err(),
                is_alias,
                "incoming collision: {name}, {alias}"
            );
        }
    }

    /// Hard-linked probe markers emulate alias lookup on case-sensitive test
    /// volumes, so every host exercises the escaping-chain regressions.
    #[test]
    fn link_checks_follow_unicode_aliases_including_directory_components() {
        for (name, alias) in [("ß", "ss"), ("ſ", "S"), ("café", "cafe\u{301}")] {
            let root = tempfile::tempdir().unwrap();
            for existing in [false, true] {
                let mut source = BTreeMap::from([
                    ("dir".into(), entry("dir", SyncEntryKind::Directory, None)),
                    (
                        "dir/up".into(),
                        entry("dir/up", SyncEntryKind::Symlink, Some("..")),
                    ),
                    (
                        "link".into(),
                        entry(
                            "link",
                            SyncEntryKind::Symlink,
                            Some(&format!("{alias}/up/..")),
                        ),
                    ),
                ]);
                let link = entry(name, SyncEntryKind::Symlink, Some("dir"));
                let mut destination = BTreeMap::new();
                if existing {
                    destination.insert(name.into(), link);
                } else {
                    source.insert(name.into(), link);
                }
                let names = HostNames::new(root.path(), &source, &destination).unwrap();
                let probe = &names.probes[names.directories[""]];
                if !probe.names_path().join(alias).exists() {
                    std::fs::hard_link(
                        probe.names_path().join(name),
                        probe.names_path().join(alias),
                    )
                    .unwrap();
                }
                let result =
                    validate_download_links(&source, &destination, &|parent, component| {
                        names.resolve_component(parent, component)
                    });
                assert!(result.unwrap_err().to_string().contains("escapes"));
                names.close().unwrap();
            }

            let source = BTreeMap::from([
                (name.into(), entry(name, SyncEntryKind::Directory, None)),
                (
                    format!("{name}/up"),
                    entry(&format!("{name}/up"), SyncEntryKind::Symlink, Some("..")),
                ),
                (
                    "link".into(),
                    entry(
                        "link",
                        SyncEntryKind::Symlink,
                        Some(&format!("{alias}/up/..")),
                    ),
                ),
            ]);
            let names = HostNames::new(root.path(), &source, &BTreeMap::new()).unwrap();
            let probe = &names.probes[names.directories[""]];
            if !probe.names_path().join(alias).exists() {
                std::fs::hard_link(
                    probe.names_path().join(name),
                    probe.names_path().join(alias),
                )
                .unwrap();
            }
            assert!(
                validate_download_links(&source, &BTreeMap::new(), &|parent, component| {
                    names.resolve_component(parent, component)
                })
                .unwrap_err()
                .to_string()
                .contains("escapes")
            );
            names.close().unwrap();
        }
    }

    #[test]
    fn missing_directories_are_only_created_in_probes_and_drop_cleans_up() {
        let root = tempfile::tempdir().unwrap();
        let modified = root.path().metadata().unwrap().modified().unwrap();
        let source = BTreeMap::from([
            (
                "日本語".into(),
                entry("日本語", SyncEntryKind::Directory, None),
            ),
            (
                "日本語/café".into(),
                entry("日本語/café", SyncEntryKind::File, None),
            ),
        ]);
        let names = HostNames::new(
            &root.path().join("missing/nested"),
            &source,
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(names.resolve_component("日本語", "café").unwrap(), "café");
        assert!(!root.path().join("missing").exists());
        drop(names);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        assert_eq!(
            root.path().metadata().unwrap().modified().unwrap(),
            modified
        );
    }
}
