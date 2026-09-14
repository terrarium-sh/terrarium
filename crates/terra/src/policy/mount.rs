//! What a recipe may share with the sandbox, and when a pinned recipe must be
//! doubted because a guest could have written it through one of its shares.

use crate::state::BoxRef;
use crate::{config, state};
use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
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
fn validate_mounts_against_terra_paths(mounts: &[config::Mount], bx: &BoxRef) -> Result<()> {
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
        find_existing_prefix(state::get_cache_path()).map(|path| Protected {
            path,
            what_shared: "the kernel and agent every box on this machine boots",
            refuse_even_readonly: true,
        }),
        find_existing_prefix(std::env::current_exe()).map(|path| Protected {
            path,
            what_shared: "the terra binary itself - re-executed by every interactive or \
                   detached run",
            refuse_even_readonly: false,
        }),
    ];

    for m in mounts {
        let host = canonicalize_existing_prefix(&m.host);
        for p in protected.iter().flatten() {
            if m.readonly && !p.refuse_even_readonly {
                continue;
            }
            if p.path.starts_with(&host) || host.starts_with(&p.path) {
                anyhow::bail!(
                    "mount '{}' would share {} with the sandbox.\n\
                     A guest that can write {} decides what its next boot mounts and \
                     what it may reach, so this is refused.\n\
                     (share a subdirectory instead - `host: ./src` - or keep the \
                     whole box elsewhere: `terra --project <dir>`)",
                    crate::render::escape_printable_path(&m.host),
                    p.what_shared,
                    crate::render::escape_printable_path(&p.path),
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn resolve_mounts(cfg: &config::Config, bx: &BoxRef) -> Result<Vec<config::Mount>> {
    let mut mounts = cfg.mounts.clone();
    for m in &mut mounts {
        m.host = std::fs::canonicalize(&m.host).with_context(|| {
            format!(
                "resolving mount host path '{}'",
                crate::render::escape_printable_path(&m.host)
            )
        })?;
    }
    validate_mounts_against_terra_paths(&mounts, bx)?;
    Ok(mounts)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PinnedPaths {
    mounts: Vec<PathBuf>,
    env_file: Option<PathBuf>,
}

impl PinnedPaths {
    pub(crate) fn from_config(cfg: &config::Config) -> Self {
        Self {
            mounts: cfg.mounts.iter().map(|mount| mount.host.clone()).collect(),
            env_file: cfg.env_file.clone(),
        }
    }
}

pub(crate) fn load_pinned_paths(bx: &BoxRef) -> Result<Option<PinnedPaths>> {
    let path = bx.get_dir().join(state::PINNED_PATHS_FILE);
    match config::read_recipe_text(&path) {
        Ok(text) => yaml_serde::from_str(&text)
            .map(Some)
            .with_context(|| format!("reading {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

pub(crate) fn verify_pinned_paths(bx: &BoxRef, current: &PinnedPaths) -> Result<()> {
    anyhow::ensure!(
        load_pinned_paths(bx)?.as_ref() == Some(current),
        "a share or env_file moved since it was pinned - run `terra {} setup` again",
        bx.get_name()
    );
    Ok(())
}

/// The first writable mount of `ran_recipe` whose host directory contains
/// `recipe_file` - the share a guest could have written the file through.
pub(crate) fn find_writable_mount_containing(
    recipe_file: &Path,
    ran_recipe: &str,
    project_dir: &Path,
) -> Result<Option<PathBuf>> {
    let file = canonicalize_existing_prefix(recipe_file);
    Ok(
        config::list_declared_writable_shares(ran_recipe, project_dir)?
            .into_iter()
            .find_map(|share| {
                let share = canonicalize_existing_prefix(&share);
                file.starts_with(&share).then_some(share)
            }),
    )
}

/// ponytail: only current pins count; tracking past writable shares requires a persistent share history.
pub(crate) fn list_pinned_recipes_across_boxes(
    project_dir: &Path,
) -> Result<Vec<(PathBuf, String)>> {
    let current_state = state::get_project_state_dir(project_dir)?;
    let mut recipes = Vec::new();
    for (_, project_state) in state::list_boxes_in(&state::get_box_home_path()?)? {
        let origin = if project_state == current_state {
            Some(project_dir.to_path_buf())
        } else {
            state::read_origin(&project_state)
        };
        for (_, box_dir) in state::list_boxes_in(&project_state)? {
            let recipe = match config::read_recipe_text(&box_dir.join(state::RECIPE_FILE)) {
                Ok(recipe) => recipe,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).with_context(|| format!("reading {}", box_dir.display()));
                }
            };
            let origin = origin.as_ref().with_context(|| {
                format!(
                    "missing project origin for {}; restore {} before adopting a recipe",
                    box_dir.display(),
                    project_state.join(state::ORIGIN_FILE).display()
                )
            })?;
            recipes.push((origin.clone(), recipe));
        }
    }
    Ok(recipes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve_box_ref(project_dir: &Path) -> BoxRef {
        BoxRef::resolve(project_dir, "dev").unwrap()
    }

    fn build_mounts(host: &Path, readonly: bool) -> Vec<config::Mount> {
        vec![config::Mount {
            host: host.to_path_buf(),
            guest: PathBuf::from("/work"),
            readonly,
        }]
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

    /// A recipe file inside a share a box let its guest write may have been
    /// authored by that guest.
    #[test]
    fn a_recipe_file_inside_a_writable_share_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let inside = project.join("app.yaml");
        std::fs::write(&inside, "hw:\n  cpus: 2\n").unwrap();
        let outside = dir.path().join("elsewhere.yaml");
        std::fs::write(&outside, "hw:\n  cpus: 2\n").unwrap();

        // What the box previously ran: the project shared read-write.
        let ran = format!(
            "mounts:\n  - host: {}\n    guest: /work\n",
            project.display()
        );

        assert_eq!(
            find_writable_mount_containing(&inside, &ran, dir.path()).unwrap(),
            Some(std::fs::canonicalize(&project).unwrap()),
            "a source inside a writable share must be reported"
        );
        assert_eq!(
            find_writable_mount_containing(&outside, &ran, dir.path()).unwrap(),
            None,
            "a source outside every share is nobody's to have written"
        );

        // Read-only shares cannot have been written by the guest.
        let ro = format!(
            "mounts:\n  - host: {}\n    guest: /work\n    readonly: true\n",
            project.display()
        );
        assert_eq!(
            find_writable_mount_containing(&inside, &ro, dir.path()).unwrap(),
            None
        );

        assert!(
            find_writable_mount_containing(&inside, "mounts: [{host: /nope-", dir.path()).is_err()
        );
    }

    /// The guest can delete a sibling's mount host through a writable share;
    /// that used to stop the pinned recipe parsing and answered "no share
    /// could have authored this", flipping the prompt's default to yes.
    /// Whether a host path exists is a boot's question, not this one's.
    #[test]
    fn a_share_that_was_deleted_does_not_silence_the_authorship_check() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let smuggled = project.join("evil.yaml");
        std::fs::write(&smuggled, "hw:\n  cpus: 2\n").unwrap();

        // What the box ran: the project read-write, plus a second share the
        // guest can remove through the first one.
        let ran = format!(
            "mounts:\n  - host: {}\n    guest: /work\n  - host: {}/data\n    guest: /data\n",
            project.display(),
            project.display()
        );
        assert!(
            !project.join("data").exists(),
            "the guest already deleted it"
        );

        assert_eq!(
            find_writable_mount_containing(&smuggled, &ran, dir.path()).unwrap(),
            Some(std::fs::canonicalize(&project).unwrap()),
            "a deleted sibling share must not silence the check"
        );
    }

    /// The same hole as
    /// [`a_share_that_was_deleted_does_not_silence_the_authorship_check`],
    /// reached through `env_file:` instead of a mount: the guest deletes the
    /// dotenv a *sibling*'s pinned recipe names, that recipe stops parsing,
    /// and the sibling's writable share stops counting - so a recipe the
    /// guest smuggled in pins with no warning. [`config::parse_recipe`] never
    /// reads env files, which is what keeps this parse working.
    #[test]
    fn a_deleted_env_file_does_not_silence_the_authorship_check() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let smuggled = project.join("evil.yaml");
        std::fs::write(&smuggled, "hw:\n  cpus: 2\n").unwrap();

        // What the box ran: the project read-write, plus a dotenv the guest can
        // delete through that very share.
        let ran = format!(
            "mounts:\n  - host: {}\n    guest: /work\nenv_file: ./secrets.env\n",
            project.display()
        );
        assert!(
            !project.join("secrets.env").exists(),
            "the guest already deleted it"
        );

        assert_eq!(
            find_writable_mount_containing(&smuggled, &ran, dir.path()).unwrap(),
            Some(std::fs::canonicalize(&project).unwrap()),
            "a deleted env_file must not silence the check"
        );
    }

    /// The gate reads pins written by every terra that came before, and
    /// `config::validate` tightens between releases: `hw.mem_mib`'s floor and
    /// the "opens nothing" allow rule each refuse recipes that were once
    /// pinnable. Running a pin through the full validation answered "no share
    /// could have authored this" for every one of them, which flips the pinning
    /// prompt's default to yes on a recipe a guest may have written.
    #[test]
    fn a_pin_this_terra_would_now_refuse_still_answers_the_gate() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let smuggled = project.join("evil.yaml");
        std::fs::write(&smuggled, "hw:\n  cpus: 2\n").unwrap();

        // What an older terra pinned: the project shared read-write, plus
        // hardware this one refuses.
        let ran = format!(
            "hw:\n  mem_mib: 64\nmounts:\n  - host: {}\n    guest: /work\n",
            project.display()
        );
        assert!(
            config::parse_recipe(&ran, dir.path(), Path::new("a pinned recipe")).is_err(),
            "this recipe has to be one today's validation refuses, or it proves nothing"
        );
        assert_eq!(
            find_writable_mount_containing(&smuggled, &ran, dir.path()).unwrap(),
            Some(std::fs::canonicalize(&project).unwrap()),
            "a pin this terra would refuse took its shares out of the gate"
        );
    }

    /// The gate also reads pins a *newer* terra wrote: a recipe field this
    /// binary does not know fails `Config`'s `deny_unknown_fields` parse
    /// outright, which used to answer "no share could have authored this" -
    /// the same silent yes as a refused pin. The mounts are read through a
    /// lenient mirror instead, so only the fields the gate needs decide.
    #[test]
    fn a_pin_with_fields_this_terra_does_not_know_still_answers_the_gate() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let smuggled = project.join("evil.yaml");
        std::fs::write(&smuggled, "hw:\n  cpus: 2\n").unwrap();

        // What a newer terra pinned: an unknown top-level section, and an
        // unknown per-mount field.
        let ran = format!(
            "quotas:\n  io_mib: 64\nmounts:\n  - host: {}\n    guest: /work\n    idmap: false\n",
            project.display()
        );
        assert!(
            config::parse_recipe(&ran, dir.path(), Path::new("a pinned recipe")).is_err(),
            "this recipe has to be one today's Config cannot parse, or it proves nothing"
        );
        assert_eq!(
            find_writable_mount_containing(&smuggled, &ran, dir.path()).unwrap(),
            Some(std::fs::canonicalize(&project).unwrap()),
            "a pin with unknown fields took its shares out of the gate"
        );

        // …and a host this terra refuses to expand (`~alice`, pinned before
        // the refusal existed) counts as the boot that ran it placed it -
        // joined onto the project - rather than silently not counting.
        let inside_old = project.join("~alice/data");
        std::fs::create_dir_all(&inside_old).unwrap();
        let smuggled_old = inside_old.join("evil.yaml");
        std::fs::write(&smuggled_old, "hw:\n  cpus: 2\n").unwrap();
        assert_eq!(
            find_writable_mount_containing(
                &smuggled_old,
                "mounts:\n  - host: ~alice/data\n    guest: /work\n",
                &project
            )
            .unwrap(),
            Some(std::fs::canonicalize(&inside_old).unwrap()),
            "an unexpandable host dropped the share it names"
        );
    }

    /// The same silent yes reached through a single *entry* rather than the
    /// whole document: a mount a future terra spells differently - a bare
    /// string, or one whose `host` moved - fails its own deserialization, and
    /// reading the list as one unit took every share beside it down with that
    /// entry. The gate then answered "no share could have authored this" for a
    /// recipe the guest smuggled in through the share it did not read.
    #[test]
    fn one_unreadable_mount_entry_does_not_drop_the_shares_beside_it() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let smuggled = project.join("evil.yaml");
        std::fs::write(&smuggled, "hw:\n  cpus: 2\n").unwrap();

        for odd in ["- \"./src:/work\"", "- {guest: /work}"] {
            let ran = format!(
                "mounts:\n  {odd}\n  - host: {}\n    guest: /w\n",
                project.display()
            );
            assert!(
                config::parse_recipe(&ran, dir.path(), Path::new("a pinned recipe")).is_err(),
                "{odd} has to be an entry today's Config cannot read, or it proves nothing"
            );
            assert_eq!(
                find_writable_mount_containing(&smuggled, &ran, dir.path()).unwrap(),
                Some(std::fs::canonicalize(&project).unwrap()),
                "{odd} took the writable share beside it out of the gate"
            );
        }

        assert!(find_writable_mount_containing(&smuggled, "mounts: nope\n", dir.path()).is_err());
    }

    /// `~/.terra` covers the shared recipes, the kernel cache and every other
    /// box's state - refused even outside this box's own state.
    #[test]
    fn a_mount_containing_terra_home_is_refused() {
        let _home = crate::sys::TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());
        let home = state::ensure_terra_home().unwrap();
        let cache = home.join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        let err = validate_mounts_against_terra_paths(&build_mounts(&cache, false), &b)
            .unwrap_err()
            .to_string();
        assert!(err.contains("terra's own directory"), "{err}");
    }

    /// Reading the state alone already hands over live sockets, disk images
    /// and the kernel.
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
    #[cfg(unix)]
    #[test]
    fn a_protected_path_that_is_not_there_yet_resolves_the_parent_it_does_have() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("real-home");
        std::fs::create_dir_all(&home).unwrap();
        let linked = dir.path().join("home");
        std::os::unix::fs::symlink(&home, &linked).unwrap();

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
    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_protected_path_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("innocent");
        std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &link).unwrap();
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

    #[cfg(unix)]
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
        std::os::unix::fs::symlink(&safe, project.join("share")).unwrap();
        std::os::unix::fs::symlink(safe.join("env"), project.join("env")).unwrap();
        let bx = resolve_box_ref(&project);
        std::fs::create_dir_all(bx.get_dir()).unwrap();

        let config = || config::Config {
            mounts: build_mounts(&project.join("share"), false),
            env_file: Some(project.join("env")),
            ..config::Config::default()
        };
        let mut approved = config();
        approved.mounts = resolve_mounts(&approved, &bx).unwrap();
        config::resolve_env_file(&mut approved).unwrap();
        std::fs::write(
            bx.get_dir().join(state::PINNED_PATHS_FILE),
            yaml_serde::to_string(&PinnedPaths::from_config(&approved)).unwrap(),
        )
        .unwrap();

        std::fs::remove_file(project.join("share")).unwrap();
        std::os::unix::fs::symlink(&private, project.join("share")).unwrap();
        std::fs::remove_file(project.join("env")).unwrap();
        std::os::unix::fs::symlink(private.join("env"), project.join("env")).unwrap();
        let mut changed = config();
        changed.mounts = resolve_mounts(&changed, &bx).unwrap();
        config::resolve_env_file(&mut changed).unwrap();
        let error = verify_pinned_paths(&bx, &PinnedPaths::from_config(&changed))
            .expect_err("a changed target must not be granted")
            .to_string();
        assert!(error.contains("moved since it was pinned"), "{error}");
    }

    /// Every box of the directory answers, not just the one being set up - a
    /// sibling's writable share could have authored a new box's recipe.
    #[test]
    fn list_pinned_recipes_across_boxes_in_the_directory() {
        let _home = crate::sys::TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        assert!(
            list_pinned_recipes_across_boxes(project)
                .unwrap()
                .is_empty()
        );

        for (name, text) in [("a", "hw:\n  cpus: 1\n"), ("b", "hw:\n  cpus: 2\n")] {
            let b = BoxRef::resolve(project, name).unwrap();
            std::fs::create_dir_all(b.get_dir()).unwrap();
            std::fs::write(b.get_dir().join(crate::state::RECIPE_FILE), text).unwrap();
        }
        // A box directory without a pinned recipe (never set up) is skipped.
        std::fs::create_dir_all(BoxRef::resolve(project, "c").unwrap().get_dir()).unwrap();

        let recipes = list_pinned_recipes_across_boxes(project).unwrap();
        assert_eq!(recipes.len(), 2, "{recipes:?}");
        assert!(recipes.iter().any(|(_, recipe)| recipe.contains("cpus: 1")));
        assert!(recipes.iter().any(|(_, recipe)| recipe.contains("cpus: 2")));
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
    }
}
