use crate::{Access, Grant, Role};
use anyhow::{Context, Result, bail, ensure};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const BASE_PROFILE: &str = include_str!("profiles/base.sb");
const VM_PROFILE: &str = include_str!("profiles/vm.sb");
const NETWORK_PROFILE: &str = include_str!("profiles/network.sb");

#[cfg_attr(
    not(target_os = "macos"),
    allow(dead_code, reason = "only the macOS backend launches workers")
)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerSpec {
    pub(super) role: Role,
    pub(super) grants: Vec<WorkerGrant>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerGrant {
    pub(super) path: PathBuf,
    pub(super) writable: bool,
    pub(super) is_directory: bool,
}

pub(super) struct Profile {
    pub(super) text: String,
    pub(super) parameters: Vec<(String, String)>,
}

pub(super) fn resolve_grants(grants: &[Grant], spec_directory: &Path) -> Result<Vec<WorkerGrant>> {
    let spec_directory = std::fs::canonicalize(spec_directory)?;
    let mut resolved = Vec::new();
    for grant in grants {
        ensure!(
            grant.path.is_absolute(),
            "macOS sandbox grant must be absolute: {}",
            grant.path.display()
        );
        let (path, is_directory) = resolve_grant_path(grant)?;
        ensure!(
            path != spec_directory && !(is_directory && spec_directory.starts_with(&path)),
            "macOS sandbox grant {} covers the confinement probe; narrow the grant",
            grant.path.display()
        );
        path_text(&path)?;
        let writable = match grant.access {
            Access::ReadOnly => false,
            Access::ReadWrite => true,
            Access::Device => bail!(
                "macOS sandbox does not support device grants; remove the device grant {}",
                grant.path.display()
            ),
        };
        resolved.push(WorkerGrant {
            path,
            writable,
            is_directory,
        });
    }
    for read_only in resolved.iter().filter(|grant| !grant.writable) {
        ensure!(
            !resolved.iter().any(|writable| {
                writable.writable
                    && (read_only.path == writable.path
                        || (writable.is_directory && read_only.path.starts_with(&writable.path)))
            }),
            "macOS sandbox cannot keep {} read-only inside a writable grant; narrow the writable grant",
            read_only.path.display()
        );
    }
    Ok(resolved)
}

pub(super) fn render_profile(
    role: Role,
    executable: &Path,
    grants: &[WorkerGrant],
) -> Result<Profile> {
    let role_profile = match role {
        Role::Vm => VM_PROFILE,
        Role::Network => NETWORK_PROFILE,
        Role::Supervisor => bail!("the macOS supervisor owns lifecycle authority"),
    };
    let mut text = format!("{BASE_PROFILE}{role_profile}");
    let mut parameters = vec![(String::from("EXECUTABLE"), path_text(executable)?)];
    for (index, grant) in grants.iter().enumerate() {
        let operations = if grant.writable {
            "file-read* file-write*"
        } else {
            "file-read*"
        };
        let filter = if grant.is_directory {
            "subpath"
        } else {
            "literal"
        };
        writeln!(
            text,
            "(allow {operations} ({filter} (param \"GRANT_{index}\")))"
        )?;
        parameters.push((format!("GRANT_{index}"), path_text(&grant.path)?));
    }
    Ok(Profile { text, parameters })
}

fn path_text(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .with_context(|| format!("macOS sandbox path must be UTF-8: {}", path.display()))?
        .to_owned())
}

fn resolve_grant_path(grant: &Grant) -> Result<(PathBuf, bool)> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn profile_text_never_contains_grant_paths() -> Result<()> {
        let root = tempfile::tempdir()?;
        let staging = root.path().join("staging");
        std::fs::create_dir(&staging)?;
        let share = root.path().join("share\") (allow default) (\"é");
        std::fs::create_dir(&share)?;
        let grants = resolve_grants(&[Grant::new(&share, Access::ReadOnly)], &staging)?;
        let profile = render_profile(Role::Vm, Path::new("/usr/local/bin/terra"), &grants)?;
        assert!(!profile.text.contains("allow default"));
        assert!(!profile.text.contains("/usr/local/bin/terra"));
        assert_eq!(
            profile.parameters[0],
            (
                String::from("EXECUTABLE"),
                String::from("/usr/local/bin/terra")
            )
        );
        assert_eq!(
            profile.parameters[1].1,
            std::fs::canonicalize(&share)?.to_str().unwrap()
        );
        Ok(())
    }

    #[test]
    fn role_profiles_split_hypervisor_and_network_authority() -> Result<()> {
        let exe = Path::new("/usr/local/bin/terra");
        let vm = render_profile(Role::Vm, exe, &[])?;
        let network = render_profile(Role::Network, exe, &[])?;
        assert!(!vm.text.contains("network-") && !vm.text.contains("system-socket"));
        assert!(network.text.contains("network-outbound"));
        assert!(!vm.text.contains("process-fork") && !network.text.contains("process-fork"));
        assert!(!vm.text.contains("allow default") && !network.text.contains("allow default"));
        assert_eq!(network.parameters.len(), 1);
        assert!(render_profile(Role::Supervisor, exe, &[]).is_err());
        Ok(())
    }

    #[test]
    fn grant_rules_follow_kind_and_access() -> Result<()> {
        let root = tempfile::tempdir()?;
        let staging = root.path().join("staging");
        std::fs::create_dir(&staging)?;
        let directory = root.path().join("dir");
        std::fs::create_dir(&directory)?;
        let missing_file = root.path().join("missing");
        let grants = resolve_grants(
            &[
                Grant::new(&directory, Access::ReadOnly),
                Grant::new(&missing_file, Access::ReadWrite),
            ],
            &staging,
        )?;
        let profile = render_profile(Role::Vm, Path::new("/bin/terra"), &grants)?;
        assert!(
            profile
                .text
                .contains("(allow file-read* (subpath (param \"GRANT_0\")))\n")
        );
        assert!(
            profile
                .text
                .contains("(allow file-read* file-write* (literal (param \"GRANT_1\")))\n")
        );
        assert_eq!(
            profile.parameters[2],
            (
                String::from("GRANT_1"),
                std::fs::canonicalize(root.path())?
                    .join("missing")
                    .to_str()
                    .unwrap()
                    .to_owned()
            )
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn grants_resolve_symlinked_paths() -> Result<()> {
        let root = tempfile::tempdir()?;
        let staging = root.path().join("staging");
        std::fs::create_dir(&staging)?;
        let real = root.path().join("real");
        std::fs::create_dir(&real)?;
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&real, &link)?;
        let grants = resolve_grants(&[Grant::new(&link, Access::ReadOnly)], &staging)?;
        assert_eq!(grants[0].path, std::fs::canonicalize(&real)?);
        assert!(grants[0].is_directory && !grants[0].writable);
        Ok(())
    }

    #[test]
    fn grants_covering_the_spec_directory_or_splitting_writes_are_rejected() -> Result<()> {
        let root = tempfile::tempdir()?;
        let staging = root.path().join("staging");
        std::fs::create_dir(&staging)?;
        for cover in [root.path(), staging.as_path()] {
            let access = if cover == staging {
                Access::ReadWrite
            } else {
                Access::ReadOnly
            };
            let error = resolve_grants(&[Grant::new(cover, access)], &staging).unwrap_err();
            assert!(format!("{error:#}").contains("covers the confinement probe"));
        }
        let device = root.path().join("device");
        std::fs::write(&device, "")?;
        let error = resolve_grants(&[Grant::new(&device, Access::Device)], &staging).unwrap_err();
        assert!(format!("{error:#}").contains("does not support device grants"));
        let writable_parent = root.path().join("writable");
        std::fs::create_dir(&writable_parent)?;
        let metadata = writable_parent.join("host.pid");
        std::fs::write(&metadata, "trusted identity")?;
        assert!(
            resolve_grants(
                &[
                    Grant::new(&writable_parent, Access::ReadWrite),
                    Grant::new(&metadata, Access::ReadOnly),
                ],
                &staging
            )
            .is_err()
        );
        assert!(
            resolve_grants(
                &[
                    Grant::new(&writable_parent, Access::ReadOnly),
                    Grant::new(&metadata, Access::ReadWrite),
                ],
                &staging
            )
            .is_ok()
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_replaced_directory_grant_fails_before_launch() -> Result<()> {
        let root = tempfile::tempdir()?;
        let share = root.path().join("share");
        let staging = root.path().join("staging");
        std::fs::create_dir(&share)?;
        std::fs::create_dir(&staging)?;
        let mut grant = Grant::new(&share, Access::ReadOnly);
        grant.directory = Some(std::fs::File::open(&share)?);
        std::fs::rename(&share, root.path().join("original"))?;
        std::fs::create_dir(&share)?;
        assert!(resolve_grants(&[grant], &staging).is_err());
        Ok(())
    }
}
