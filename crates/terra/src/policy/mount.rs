//! What a recipe may share with the sandbox.

use crate::recipe::{Mount, Recipe};
use crate::state;
use crate::state::BoxRef;
use anyhow::{Context as _, Result};
use std::path::{Path, PathBuf};

use crate::sys::canonicalize_existing_prefix;

/// A protected path terra could not determine is left out of the guards, not
/// an error: an unset `$HOME` names no directory to protect.
fn find_existing_prefix<E>(path: Result<PathBuf, E>) -> Option<PathBuf> {
    path.ok().map(|p| canonicalize_existing_prefix(&p))
}

/// Refuse a mount that overlaps terra's own state or binary: a mount
/// containing `~/.terra` is a sandbox that can rewrite its own next boot.
/// Sharing the project directory itself is fine.
fn validate_mounts_against_terra_paths(mounts: &[Mount], bx: &BoxRef) -> Result<()> {
    struct Protected {
        path: PathBuf,
        what_shared: &'static str,
        refuse_even_readonly: bool,
    }

    let protected = [
        Some(Protected {
            path: canonicalize_existing_prefix(bx.get_dir()),
            what_shared: "this box's own state - its recipe, disk images and sockets",
            refuse_even_readonly: true,
        }),
        find_existing_prefix(state::get_terra_home_path()).map(|path| Protected {
            path,
            what_shared: "terra's own directory - the shared recipes, and where every box on \
                   this machine is kept",
            refuse_even_readonly: true,
        }),
        find_existing_prefix(state::get_box_home_path()).map(|path| Protected {
            path,
            what_shared: "every box on this machine - their recipes, disk images and sockets",
            refuse_even_readonly: true,
        }),
        find_existing_prefix(std::env::current_exe()).map(|path| Protected {
            path,
            what_shared: "the terra binary itself - re-executed by every interactive or \
                   detached run",
            refuse_even_readonly: false,
        }),
    ];

    for mount in mounts {
        let host = canonicalize_existing_prefix(&mount.host);
        for p in protected.iter().flatten() {
            if mount.readonly && !p.refuse_even_readonly {
                continue;
            }
            if p.path.starts_with(&host) || host.starts_with(&p.path) {
                anyhow::bail!(
                    "mount '{}' would share {} with the sandbox.\n\
                     A guest that can write {} decides what its next boot mounts and \
                     what it may reach, so this is refused.\n\
                     (share a subdirectory instead - `host: ./src` - or keep the \
                     whole box elsewhere: `terra --project <dir>`)",
                    crate::render::escape_printable_path(&mount.host),
                    p.what_shared,
                    crate::render::escape_printable_path(&p.path),
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn resolve_setup_mounts(recipe: &mut Recipe, bx: &BoxRef) -> Result<()> {
    resolve_phase_mounts(&mut recipe.setup.mounts, bx)
}

pub(crate) fn resolve_workload_mounts(recipe: &mut Recipe, bx: &BoxRef) -> Result<()> {
    resolve_phase_mounts(&mut recipe.workload.mounts, bx)
}

fn resolve_phase_mounts(mounts: &mut [Mount], bx: &BoxRef) -> Result<()> {
    for mount in mounts.iter_mut() {
        mount.host = std::fs::canonicalize(&mount.host).with_context(|| {
            format!(
                "resolving mount host path '{}'",
                crate::render::escape_printable_path(&mount.host)
            )
        })?;
        anyhow::ensure!(
            mount.host.is_dir(),
            "mount host '{}' must be a directory",
            crate::render::escape_printable_path(&mount.host)
        );
    }
    validate_mounts_against_terra_paths(mounts, bx)
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SensitiveMount<'a> {
    pub phase: &'static str,
    pub host: &'a Path,
    pub readonly: bool,
    pub category: &'static str,
}

impl SensitiveMount<'_> {
    pub(crate) fn warning(&self) -> String {
        let access = if self.readonly {
            "read-only"
        } else {
            "read-write"
        };
        format!(
            "{} mount '{}' shares sensitive host {} ({access}) with the sandbox",
            self.phase,
            crate::render::escape_printable_path(self.host),
            self.category
        )
    }
}

pub(crate) struct SensitiveTarget {
    pub path: PathBuf,
    pub category: &'static str,
}

fn sensitive_targets() -> Vec<SensitiveTarget> {
    let mut targets = Vec::new();
    if let Ok(home) = crate::sys::resolve_home_dir() {
        for (rel, category) in [
            (".ssh", "SSH keys and configuration"),
            (".aws", "AWS credentials"),
            (".gnupg", "GnuPG keys"),
            (".docker", "Docker credentials"),
            (".kube", "Kubernetes cluster credentials"),
            (".config/gcloud", "Google Cloud credentials"),
            (".azure", "Azure credentials"),
        ] {
            targets.push(SensitiveTarget {
                path: canonicalize_existing_prefix(&home.join(rel)),
                category,
            });
        }
    }
    for (path, category) in [
        ("/etc/shadow", "host shadow passwords"),
        ("/etc/sudoers", "host sudo rules"),
        ("/etc/sudoers.d", "host sudo rules"),
        ("/etc/pam.d", "host PAM authentication rules"),
    ] {
        targets.push(SensitiveTarget {
            path: canonicalize_existing_prefix(Path::new(path)),
            category,
        });
    }
    targets
}

pub(crate) fn find_sensitive_mounts_with_targets<'a>(
    mounts: impl IntoIterator<Item = (&'static str, &'a Path, bool)>,
    targets: &[SensitiveTarget],
) -> Vec<SensitiveMount<'a>> {
    let mut sensitive = Vec::new();
    for (phase, mount, readonly) in mounts {
        let host = canonicalize_existing_prefix(mount);
        for target in targets {
            if host.starts_with(&target.path) || target.path.starts_with(&host) {
                sensitive.push(SensitiveMount {
                    phase,
                    host: mount,
                    readonly,
                    category: target.category,
                });
                break;
            }
        }
    }
    sensitive
}

#[derive(Clone, Copy)]
pub(crate) enum GrantPhases {
    SetupAndWorkload,
    Workload,
}

pub(crate) fn find_sensitive_mounts(
    recipe: &Recipe,
    phases: GrantPhases,
) -> Vec<SensitiveMount<'_>> {
    let setup_mounts = match phases {
        GrantPhases::SetupAndWorkload => recipe.setup.mounts.as_slice(),
        GrantPhases::Workload => &[],
    };
    let mounts = setup_mounts
        .iter()
        .map(|mount| ("setup", mount.host.as_path(), mount.readonly))
        .chain(
            recipe
                .workload
                .mounts
                .iter()
                .map(|mount| ("workload", mount.host.as_path(), mount.readonly)),
        );
    find_sensitive_mounts_with_targets(mounts, &sensitive_targets())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipe::{Mount, resolve_env_file};

    fn resolve_box_ref(project_dir: &Path) -> BoxRef {
        BoxRef::resolve(project_dir, "dev").unwrap()
    }

    fn build_mounts(host: &Path, readonly: bool) -> Vec<Mount> {
        vec![Mount {
            host: host.to_path_buf(),
            guest: PathBuf::from("/work"),
            readonly,
        }]
    }

    fn paths(mounts: &[Mount]) -> impl Iterator<Item = (&'static str, &Path, bool)> {
        mounts
            .iter()
            .map(|mount| ("workload", mount.host.as_path(), mount.readonly))
    }

    /// A mount containing the box's own state lets the guest rewrite what its
    /// own next boot mounts and may reach.
    #[test]
    fn a_mount_containing_the_box_state_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());

        // The box's state directory, and its parent (`~/.terra/box/<slug>`).
        let err = validate_mounts_against_terra_paths(&build_mounts(b.get_dir(), false), &b)
            .unwrap_err()
            .to_string();
        assert!(err.contains("this box's own state"), "{err}");
        assert!(err.contains("--project"), "it should say what to do: {err}");
        assert!(
            validate_mounts_against_terra_paths(
                &build_mounts(b.get_dir().parent().unwrap(), false),
                &b
            )
            .is_err()
        );

        // The project directory does not contain the state (`~/.terra/box`),
        // so "sandbox my project" shares clean.
        assert!(validate_mounts_against_terra_paths(&build_mounts(dir.path(), false), &b).is_ok());
        assert!(validate_mounts_against_terra_paths(&[], &b).is_ok());
    }

    /// `~/.terra` covers shared recipes and every box's state, so mounts of
    /// the home directory are refused even outside this box's own state.
    #[test]
    fn a_mount_containing_terra_home_is_refused() {
        let _home = crate::sys::TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());
        let shared = state::ensure_terra_home().unwrap().join("shared");
        std::fs::create_dir_all(&shared).unwrap();
        let err = validate_mounts_against_terra_paths(&build_mounts(&shared, false), &b)
            .unwrap_err()
            .to_string();
        assert!(err.contains("terra's own directory"), "{err}");
    }

    /// Reading the state alone already hands over live sockets and disk images.
    #[test]
    fn a_read_only_share_of_terra_state_is_still_refused() {
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());
        assert!(validate_mounts_against_terra_paths(&build_mounts(b.get_dir(), true), &b).is_err());
    }

    /// None of the protected paths is guaranteed to exist when a recipe is
    /// checked: a box's state directory is created only after approval, and
    /// a first run has no `~/.terra` yet. The mount host resolves fully, so
    /// the protected path has to resolve as far as it can - otherwise a
    /// symlinked home would be compared under its unresolved spelling and
    /// slip past.
    #[test]
    fn a_protected_path_that_is_not_there_yet_resolves_the_parent_it_does_have() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("real-home");
        std::fs::create_dir_all(&home).unwrap();
        let linked = dir.path().join("home");
        crate::sys::symlink_dir(&home, &linked).unwrap();

        let resolved = std::fs::canonicalize(&home).unwrap();
        assert_eq!(
            canonicalize_existing_prefix(&linked.join(".terra")),
            resolved.join(".terra")
        );
        assert_eq!(
            canonicalize_existing_prefix(&linked.join(".terra/box/dev")),
            resolved.join(".terra/box/dev"),
            "a whole missing tail is kept, not dropped"
        );
        // Both spellings of a path that is not there answer alike, which is the
        // property the containment check rests on.
        assert_eq!(
            canonicalize_existing_prefix(&linked.join(".terra")),
            canonicalize_existing_prefix(&home.join(".terra"))
        );

        // …and the box's own state is refused before anything has created it.
        let b = resolve_box_ref(dir.path());
        assert!(!b.get_dir().exists());
        assert!(
            validate_mounts_against_terra_paths(&build_mounts(b.get_dir(), false), &b).is_err()
        );
    }

    /// A symlink is the same share by another name: compared after resolution.
    #[test]
    fn a_symlink_to_a_protected_path_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("innocent");
        crate::sys::symlink_file(std::env::current_exe().unwrap(), &link).unwrap();
        let err = validate_mounts_against_terra_paths(
            &build_mounts(&link, false),
            &resolve_box_ref(dir.path()),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("the terra binary"), "{err}");
    }

    #[test]
    fn protected_mount_errors_escape_control_characters() {
        let _home = crate::sys::TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let bx = resolve_box_ref(dir.path());
        let host = bx.get_dir().join("data\x1b\x07");
        let error = validate_mounts_against_terra_paths(&build_mounts(&host, false), &bx)
            .unwrap_err()
            .to_string();
        assert!(error.contains("would share"), "{error}");
        assert!(!error.contains(['\x1b', '\x07']), "{error:?}");
    }

    #[test]
    fn changed_mount_and_env_file_targets_are_refused() {
        let _home = crate::sys::TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        let safe = dir.path().join("safe");
        let private = dir.path().join("private");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&safe).unwrap();
        std::fs::create_dir_all(&private).unwrap();
        std::fs::write(safe.join("env"), "A=safe\n").unwrap();
        std::fs::write(private.join("env"), "A=private\n").unwrap();
        crate::sys::symlink_dir(&safe, project.join("share")).unwrap();
        crate::sys::symlink_file(safe.join("env"), project.join("env")).unwrap();
        let bx = resolve_box_ref(&project);
        std::fs::create_dir_all(bx.get_dir()).unwrap();

        let recipe = || Recipe {
            workload: crate::recipe::Workload {
                mounts: build_mounts(&project.join("share"), false),
                ..crate::recipe::Workload::default()
            },
            env_file: Some(project.join("env")),
            ..Recipe::default()
        };
        let mut approved = recipe();
        resolve_workload_mounts(&mut approved, &bx).unwrap();
        resolve_env_file(&mut approved).unwrap();
        std::fs::write(
            bx.get_dir().join(state::PINNED_PATHS_FILE),
            yaml_serde::to_string(&state::PinnedPaths::new(&approved, Vec::new())).unwrap(),
        )
        .unwrap();

        crate::sys::remove_directory_symlink(project.join("share")).unwrap();
        crate::sys::symlink_dir(&private, project.join("share")).unwrap();
        std::fs::remove_file(project.join("env")).unwrap();
        crate::sys::symlink_file(private.join("env"), project.join("env")).unwrap();
        let mut changed = recipe();
        resolve_workload_mounts(&mut changed, &bx).unwrap();
        resolve_env_file(&mut changed).unwrap();
        let error = bx
            .verify_workload_pins(&changed)
            .expect_err("a changed target must not be granted")
            .to_string();
        assert!(error.contains("moved since the last setup"), "{error}");
    }

    /// A guest that can write the terra binary picks what the next run does, as
    /// the launching user, before any sandbox exists.
    #[test]
    fn a_mount_containing_the_terra_binary_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());
        let exe = std::env::current_exe().unwrap();

        let err =
            validate_mounts_against_terra_paths(&build_mounts(exe.parent().unwrap(), false), &b)
                .unwrap_err()
                .to_string();
        assert!(err.contains("the terra binary"), "{err}");
        // Read-only cannot rewrite it, and reading it gives away nothing that
        // shipping the binary did not.
        assert!(
            validate_mounts_against_terra_paths(&build_mounts(exe.parent().unwrap(), true), &b)
                .is_ok()
        );
        for readonly in [false, true] {
            let mut recipe = Recipe::default();
            recipe.setup.mounts = build_mounts(exe.parent().unwrap(), readonly);
            assert_eq!(resolve_setup_mounts(&mut recipe, &b).is_ok(), readonly);
        }
    }

    #[test]
    fn sensitive_mounts_are_detected() {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let id_rsa = ssh_dir.join("id_rsa");
        std::fs::write(&id_rsa, "secret").unwrap();
        let project_dir = dir.path().join("project");
        std::fs::create_dir_all(&project_dir).unwrap();

        let targets = vec![
            SensitiveTarget {
                path: canonicalize_existing_prefix(&ssh_dir),
                category: "SSH keys and configuration",
            },
            SensitiveTarget {
                path: canonicalize_existing_prefix(Path::new("/etc/shadow")),
                category: "host shadow passwords",
            },
        ];

        let mounts = vec![
            Mount {
                host: ssh_dir.clone(),
                guest: PathBuf::from("/ssh"),
                readonly: false,
            },
            Mount {
                host: id_rsa.clone(),
                guest: PathBuf::from("/key"),
                readonly: true,
            },
            Mount {
                host: project_dir,
                guest: PathBuf::from("/src"),
                readonly: false,
            },
        ];

        let sensitive = find_sensitive_mounts_with_targets(paths(&mounts), &targets);
        assert_eq!(sensitive.len(), 2);
        assert_eq!(sensitive[0].host, ssh_dir);
        assert!(!sensitive[0].readonly);
        assert_eq!(sensitive[0].category, "SSH keys and configuration");

        assert_eq!(sensitive[1].host, id_rsa);
        assert!(sensitive[1].readonly);
        assert_eq!(sensitive[1].category, "SSH keys and configuration");
    }

    #[test]
    fn sensitive_mount_warnings_cover_the_requested_phases() {
        let home = crate::sys::TestHome::new();
        let ssh_dir = home.get_path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let recipe = Recipe {
            setup: crate::recipe::Setup {
                mounts: vec![Mount {
                    host: ssh_dir.clone(),
                    guest: PathBuf::from("/setup"),
                    readonly: false,
                }],
                ..crate::recipe::Setup::default()
            },
            workload: crate::recipe::Workload {
                mounts: vec![Mount {
                    host: ssh_dir.clone(),
                    guest: PathBuf::from("/workload"),
                    readonly: true,
                }],
                ..crate::recipe::Workload::default()
            },
            ..Recipe::default()
        };
        let sensitive = find_sensitive_mounts(&recipe, GrantPhases::SetupAndWorkload);
        assert_eq!(sensitive.len(), 2);
        assert_eq!(sensitive[0].phase, "setup");
        assert_eq!(sensitive[0].host, ssh_dir);
        assert!(!sensitive[0].readonly);
        assert_eq!(sensitive[1].phase, "workload");
        assert_eq!(sensitive[1].host, ssh_dir);
        assert!(sensitive[1].readonly);
        assert_eq!(
            find_sensitive_mounts(&recipe, GrantPhases::Workload),
            sensitive[1..]
        );
    }
}
