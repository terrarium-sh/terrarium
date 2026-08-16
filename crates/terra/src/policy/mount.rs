//! What a recipe may share with the sandbox, and when a pinned recipe must be
//! doubted because a guest could have written it through one of its shares.

use crate::state::BoxRef;
use crate::{config, state};
use anyhow::Result;
use std::path::{Path, PathBuf};

/// The paths we guard may not exist yet when they're checked, and a symlink
/// must not sneak a protected path past under a different name. So resolve as
/// much as the disk actually has, and keep the rest as written.
fn canonicalize_existing_prefix(p: &Path) -> PathBuf {
    let (mut existing, mut rest) = (p.to_path_buf(), PathBuf::new());
    loop {
        if let Ok(resolved) = std::fs::canonicalize(&existing) {
            return resolved.join(rest);
        }
        let Some(name) = existing.file_name().map(PathBuf::from) else {
            return p.to_path_buf();
        };
        rest = name.join(rest);
        if !existing.pop() {
            return p.to_path_buf();
        }
    }
}

/// Refuse a mount that overlaps terra's own state or binary: a mount
/// containing `~/.terra` is a sandbox that can rewrite its own next boot.
/// Sharing the project directory itself is fine.
fn check_mounts_exclude_terra_paths(cfg: &config::Config, bx: &BoxRef) -> Result<()> {
    struct Protected {
        path: PathBuf,
        what_shared: &'static str,
        refuse_even_readonly: bool,
    }

    let protected = [
        Some(Protected {
            path: canonicalize_existing_prefix(bx.dir()),
            what_shared: "this box's own state - its recipe, disk images and sockets",
            refuse_even_readonly: true,
        }),
        state::terra_home_path().ok().map(|home| Protected {
            path: canonicalize_existing_prefix(&home),
            what_shared: "terra's own directory - the shared recipes, and where every box on \
                   this machine is kept",
            refuse_even_readonly: true,
        }),
        state::box_home_path().ok().map(|dir| Protected {
            path: canonicalize_existing_prefix(&dir),
            what_shared: "every box on this machine - their recipes, disk images and sockets",
            refuse_even_readonly: true,
        }),
        state::cache_path().ok().map(|dir| Protected {
            path: canonicalize_existing_prefix(&dir),
            what_shared: "the kernel and agent every box on this machine boots",
            refuse_even_readonly: true,
        }),
        std::env::current_exe().ok().map(|exe| Protected {
            path: canonicalize_existing_prefix(&exe),
            what_shared: "the terra binary itself - re-executed by every interactive or detached run",
            refuse_even_readonly: false,
        }),
    ];

    for m in &cfg.mounts {
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
                    m.host.display(),
                    p.what_shared,
                    p.path.display(),
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn resolve_and_check_mounts(cfg: &mut config::Config, bx: &BoxRef) -> Result<()> {
    config::resolve_mounts(cfg)?;
    check_mounts_exclude_terra_paths(cfg, bx)
}

/// The first writable mount of `ran_recipe` whose host directory contains
/// `recipe_file` - the share a guest could have written the file through.
pub(crate) fn writable_mount_containing(
    recipe_file: &Path,
    ran_recipe: &str,
    project_dir: &Path,
) -> Option<PathBuf> {
    let file = canonicalize_existing_prefix(recipe_file);
    config::get_declared_writable_shares(ran_recipe, project_dir)
        .into_iter()
        .find(|share| file.starts_with(canonicalize_existing_prefix(share)))
}

/// The recipe each box in `project_dir` is pinned to run - every box, because
/// a *sibling*'s writable share could have written both a new recipe file and
/// the `terra.yaml` entry naming it.
///
/// ponytail: only what is pinned *now* counts; closing that fully needs a log
/// of every share a box ever had. Add it only if mounts start changing often.
pub(crate) fn pinned_recipes_across_boxes(project_dir: &Path) -> Vec<String> {
    state::existing_names(project_dir)
        .iter()
        .filter_map(|n| BoxRef::resolve(project_dir, n).ok())
        .filter_map(|b| std::fs::read_to_string(b.recipe()).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bx(project_dir: &Path) -> BoxRef {
        BoxRef::resolve(project_dir, "dev").unwrap()
    }

    fn mount(host: &Path, readonly: bool) -> config::Config {
        config::Config {
            mounts: vec![config::Mount {
                host: host.to_path_buf(),
                guest: PathBuf::from("/work"),
                readonly,
            }],
            ..serde_yaml::from_str("{}").unwrap()
        }
    }

    /// A mount containing the box's own state lets the guest rewrite what its
    /// own next boot mounts and may reach.
    #[test]
    fn a_mount_containing_the_box_state_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let b = bx(dir.path());

        // The box's state directory, and its parent (`~/.terra/box/<slug>`).
        let err = check_mounts_exclude_terra_paths(&mount(b.dir(), false), &b)
            .unwrap_err()
            .to_string();
        assert!(err.contains("this box's own state"), "{err}");
        assert!(err.contains("--project"), "it should say what to do: {err}");
        assert!(
            check_mounts_exclude_terra_paths(&mount(b.dir().parent().unwrap(), false), &b).is_err()
        );

        // The project directory does not contain the state (`~/.terra/box`),
        // so "sandbox my project" shares clean.
        assert!(check_mounts_exclude_terra_paths(&mount(dir.path(), false), &b).is_ok());
        assert!(check_mounts_exclude_terra_paths(&serde_yaml::from_str("{}").unwrap(), &b).is_ok());
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
            writable_mount_containing(&inside, &ran, dir.path()),
            Some(std::fs::canonicalize(&project).unwrap()),
            "a source inside a writable share must be reported"
        );
        assert_eq!(
            writable_mount_containing(&outside, &ran, dir.path()),
            None,
            "a source outside every share is nobody's to have written"
        );

        // Read-only shares cannot have been written by the guest.
        let ro = format!(
            "mounts:\n  - host: {}\n    guest: /work\n    readonly: true\n",
            project.display()
        );
        assert_eq!(writable_mount_containing(&inside, &ro, dir.path()), None);

        // A previous recipe that is not YAML at all cannot answer; the check
        // steps aside rather than wedging the box.
        assert_eq!(
            writable_mount_containing(&inside, "mounts: [{host: /nope-", dir.path()),
            None
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
            writable_mount_containing(&smuggled, &ran, dir.path()),
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
            writable_mount_containing(&smuggled, &ran, dir.path()),
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
            writable_mount_containing(&smuggled, &ran, dir.path()),
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
            writable_mount_containing(&smuggled, &ran, dir.path()),
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
            writable_mount_containing(
                &smuggled_old,
                "mounts:\n  - host: ~alice/data\n    guest: /work\n",
                &project
            ),
            Some(inside_old),
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
                writable_mount_containing(&smuggled, &ran, dir.path()),
                Some(std::fs::canonicalize(&project).unwrap()),
                "{odd} took the writable share beside it out of the gate"
            );
        }

        // A `mounts:` that is no list at all still answers "none": there is no
        // entry to read, which is a different thing from one that cannot be.
        assert_eq!(
            writable_mount_containing(&smuggled, "mounts: nope\n", dir.path()),
            None
        );
    }

    /// `~/.terra` covers the shared recipes, the kernel cache and every other
    /// box's state - refused even outside this box's own state.
    #[test]
    fn a_mount_containing_terra_home_is_refused() {
        let _home = crate::sys::TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = bx(dir.path());
        let home = state::ensure_terra_home().unwrap();
        let cache = home.join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        let err = check_mounts_exclude_terra_paths(&mount(&cache, false), &b)
            .unwrap_err()
            .to_string();
        assert!(err.contains("terra's own directory"), "{err}");
    }

    /// A box directory `config.yaml` moved out of `~/.terra` is guarded where
    /// it now is: sharing it hands over every other box's recipe and images -
    /// the same handover, on whatever disk the operator pointed it at - and
    /// `~/.terra` no longer contains it to catch it by accident.
    #[test]
    fn a_relocated_box_directory_is_refused_where_it_now_is() {
        let _home = crate::sys::TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        // A directory of its own, the way a second disk is: sharing the project
        // is only an ordinary mount while the boxes are not kept inside it.
        let disk = tempfile::tempdir().unwrap();
        let ssd = disk.path().to_path_buf();
        std::fs::create_dir_all(ssd.join("boxes")).unwrap();
        std::fs::create_dir_all(ssd.join("cache")).unwrap();
        std::fs::write(
            state::ensure_terra_home()
                .unwrap()
                .join(state::SETTINGS_FILE),
            format!(
                "storage:\n  boxes: {ssd}/boxes\n  cache: {ssd}/cache\n",
                ssd = ssd.display()
            ),
        )
        .unwrap();

        let b = bx(dir.path());
        // A *sibling* project's boxes: the one share that contains neither this
        // box's own state nor `~/.terra`, so nothing but the relocated box
        // directory can refuse it.
        let sibling = state::project_state_dir(&dir.path().join("another-project")).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        for (shared, named) in [
            (sibling, "every box on this machine"),
            (ssd.join("cache"), "the kernel and agent"),
            (ssd.join("boxes"), "state"),
        ] {
            let err = check_mounts_exclude_terra_paths(&mount(&shared, false), &b)
                .unwrap_err()
                .to_string();
            assert!(err.contains(named), "{}: {err}", shared.display());
        }
        // The project itself is still an ordinary share.
        assert!(check_mounts_exclude_terra_paths(&mount(dir.path(), false), &b).is_ok());
    }

    /// Reading the state alone already hands over live sockets, disk images
    /// and the kernel.
    #[test]
    fn a_read_only_share_of_terra_state_is_still_refused() {
        let dir = tempfile::tempdir().unwrap();
        let b = bx(dir.path());
        assert!(check_mounts_exclude_terra_paths(&mount(b.dir(), true), &b).is_err());
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
        let b = bx(dir.path());
        assert!(!b.dir().exists());
        assert!(check_mounts_exclude_terra_paths(&mount(b.dir(), false), &b).is_err());
    }

    /// A symlink is the same share by another name: compared after resolution.
    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_protected_path_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("innocent");
        std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &link).unwrap();
        let err = check_mounts_exclude_terra_paths(&mount(&link, false), &bx(dir.path()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("the terra binary"), "{err}");
    }

    /// Every box of the directory answers, not just the one being set up - a
    /// sibling's writable share could have authored a new box's recipe.
    #[test]
    fn pinned_recipes_across_boxes_lists_every_box_of_the_directory() {
        let _home = crate::sys::TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        assert!(pinned_recipes_across_boxes(project).is_empty());

        for (name, text) in [("a", "hw:\n  cpus: 1\n"), ("b", "hw:\n  cpus: 2\n")] {
            let b = BoxRef::resolve(project, name).unwrap();
            std::fs::create_dir_all(b.dir()).unwrap();
            std::fs::write(b.recipe(), text).unwrap();
        }
        // A box directory without a pinned recipe (never set up) is skipped.
        std::fs::create_dir_all(BoxRef::resolve(project, "c").unwrap().dir()).unwrap();

        let recipes = pinned_recipes_across_boxes(project);
        assert_eq!(recipes.len(), 2, "{recipes:?}");
        assert!(recipes.iter().any(|r| r.contains("cpus: 1")));
        assert!(recipes.iter().any(|r| r.contains("cpus: 2")));
    }

    /// A guest that can write the terra binary picks what the next run does, as
    /// the launching user, before any sandbox exists.
    #[test]
    fn a_mount_containing_the_terra_binary_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let b = bx(dir.path());
        let exe = std::env::current_exe().unwrap();

        let err = check_mounts_exclude_terra_paths(&mount(exe.parent().unwrap(), false), &b)
            .unwrap_err()
            .to_string();
        assert!(err.contains("the terra binary"), "{err}");
        // Read-only cannot rewrite it, and reading it gives away nothing that
        // shipping the binary did not.
        assert!(check_mounts_exclude_terra_paths(&mount(exe.parent().unwrap(), true), &b).is_ok());
    }
}
