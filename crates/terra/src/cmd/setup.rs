//! `terra setup`: pin an approved recipe, then prepare the guest filesystem.

use crate::approval::{Approval, ApprovedRecipe, request_recipe_approval};
use crate::recipe::resolve;
use crate::recipe::{Recipe, VolumeLifetime, load_path};
use crate::render::escape_printable_path;
use crate::state::{BoxRef, BoxSetupState};
use crate::vm::boot;
use crate::{cli, state};
use anyhow::{Context, Result};
use std::fs::File;
use std::path::Path;
use std::process::ExitCode;

/// `terra [BOX] setup` - pin a recipe, build the filesystem, run `on_create`.
pub async fn run(
    args: &cli::SetupArgs,
    name: Option<&str>,
    project_dir: &Path,
    cwd: &Path,
    is_at_a_terminal: bool,
) -> Result<ExitCode> {
    let target = resolve::resolve_recipe(name, project_dir, resolve::Purpose::Pin { cwd })?;
    let held = target.bx.lock_if_present()?;
    let approval = if args.dry_run {
        Approval::Reported
    } else {
        Approval::ChosenByHand {
            trust_recipe: args.trust_recipe,
        }
    };
    let approved = request_recipe_approval(target, &approval, is_at_a_terminal)?;
    if args.dry_run {
        // The refusals have run; the rest is the disk work a dry run exists
        // not to do.
        eprintln!(
            "terra: --dry-run: {} - `terra setup` would take this recipe, \
             and nothing was pinned or built",
            approved.bx
        );
        return Ok(ExitCode::SUCCESS);
    }
    let rebuild = if args.rebuild {
        Rebuild::Yes
    } else {
        Rebuild::No
    };
    let PreparedBox { lock, root } = prepare_box(&approved, rebuild, held)?;
    let ApprovedRecipe { bx, mut recipe, .. } = approved;
    if !bx.is_set_up() {
        match root {
            RootPlan::Bake => {}
            RootPlan::Keep => recipe.hooks.on_create.clear(),
        }
        boot::run_setup_vm(&recipe, &bx, &lock).await?;
    }
    eprintln!("terra: {bx} is ready - `terra {}` boots it", bx.get_name());
    Ok(ExitCode::SUCCESS)
}

#[derive(Debug, Clone, Copy)]
enum Rebuild {
    Yes,
    No,
}

/// What setup does with a box's root image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootPlan {
    /// Lay down a new root and bake `on_create` into it.
    Bake,
    /// Keep the baked root, and the result of the `on_create` it ran.
    Keep,
}

struct PreparedBox {
    lock: File,
    root: RootPlan,
}

/// Prepare the box under `held`, the lock taken before approval, or a new one
/// for a box that had no state to lock then.
fn prepare_box(
    approved: &ApprovedRecipe,
    rebuild: Rebuild,
    held: Option<File>,
) -> Result<PreparedBox> {
    let ApprovedRecipe {
        bx,
        recipe,
        new_pin,
        ..
    } = approved;
    let lock = match held {
        Some(lock) => lock,
        None => bx.lock_and_repair()?,
    };
    bx.prepare_state_dir()?;
    let root = plan_root(bx, rebuild)?;
    match root {
        RootPlan::Bake => discard_root(bx)?,
        RootPlan::Keep => {
            if let Some(new_file) = new_pin {
                report_kept_root(bx, recipe, new_file);
            }
        }
    }
    approved.write_pin(bx.get_dir())?;
    install_or_grow_images(bx, recipe, rebuild)?;
    Ok(PreparedBox { lock, root })
}

fn plan_root(bx: &BoxRef, rebuild: Rebuild) -> Result<RootPlan> {
    Ok(match (rebuild, bx.get_setup_state()?) {
        (Rebuild::No, BoxSetupState::Stale | BoxSetupState::SetUp) => RootPlan::Keep,
        (Rebuild::Yes | Rebuild::No, BoxSetupState::Missing) => RootPlan::Bake,
        (Rebuild::Yes, BoxSetupState::Unbaked | BoxSetupState::Stale | BoxSetupState::SetUp) => {
            eprintln!("terra: --rebuild: rebuilding {bx} from scratch");
            RootPlan::Bake
        }
        (Rebuild::No, BoxSetupState::Unbaked) => {
            eprintln!("terra: {bx}'s last setup did not finish on_create; creating it again");
            RootPlan::Bake
        }
    })
}

/// Remove the root image, stamp first: an old stamp beside a new root would
/// read as baked.
fn discard_root(bx: &BoxRef) -> Result<()> {
    bx.remove_setup_stamp()?;
    let img = bx.get_dir().join(state::ROOTFS_FILE);
    if img.exists() {
        std::fs::remove_file(&img).with_context(|| format!("removing {}", img.display()))?;
    }
    Ok(())
}

/// Say what a new pin leaves as it was on a kept root; reads the pin it replaces.
fn report_kept_root(bx: &BoxRef, recipe: &Recipe, new_pin: &resolve::RecipeFile) {
    let pinned = bx.get_dir().join(state::RECIPE_FILE);
    if !pinned.exists() {
        return;
    }
    eprintln!(
        "terra: recipe updated from {} (the box keeps its filesystem; \
         `terra {} setup --rebuild` rebuilds it)",
        escape_printable_path(&new_pin.from),
        bx.get_name()
    );
    if load_path(&pinned, bx.get_project_dir())
        .is_ok_and(|pinned| pinned.hooks.on_create != recipe.hooks.on_create)
    {
        eprintln!(
            "terra: on_create changed, but {bx} keeps the result of the old one \
             (`terra {} setup --rebuild` runs the new one)",
            bx.get_name()
        );
    }
}

fn install_or_grow_images(bx: &BoxRef, recipe: &Recipe, rebuild: Rebuild) -> Result<()> {
    let img = bx.get_dir().join(state::ROOTFS_FILE);
    if !img.exists() {
        eprintln!("terra: creating {bx} ({} MiB)", recipe.hw.rootfs_mib);
    }
    crate::vm::image::install_or_grow_rootfs_image(&img, recipe.hw.rootfs_mib)
        .with_context(|| format!("preparing {}", img.display()))?;
    for volume in &recipe.volumes {
        if volume.lifetime == VolumeLifetime::Box {
            let path = bx.get_volume_image_path(&volume.name);
            crate::vm::image::install_or_grow_volume_image(&path, volume.size_mib)
                .with_context(|| format!("preparing volume image {}", path.display()))?;
        }
    }
    let recipe_volumes: Vec<String> = recipe.volumes.iter().map(|v| v.name.clone()).collect();
    sweep_or_keep_unused_volumes(bx, &recipe_volumes, rebuild)
}

fn sweep_or_keep_unused_volumes(
    bx: &BoxRef,
    recipe_volumes: &[String],
    rebuild: Rebuild,
) -> Result<()> {
    for img in bx.list_unused_volume_images(recipe_volumes)? {
        if matches!(rebuild, Rebuild::No) {
            eprintln!(
                "terra: {} holds a volume the recipe no longer names - kept \
                 (`terra {name} storage prune` removes it, and so does \
                 `terra {name} setup --rebuild`)",
                img.display(),
                name = bx.get_name()
            );
            continue;
        }
        match std::fs::remove_file(&img) {
            Ok(()) => eprintln!(
                "terra: removed {} - the recipe no longer names that volume",
                img.display()
            ),
            Err(e) => eprintln!("terra: warning: could not remove {}: {e}", img.display()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::approve_by_hand;
    use crate::recipe::resolve::ResolvedRecipe;
    use sha2::{Digest as _, Sha256};

    #[test]
    fn a_changed_pinned_target_needs_explicit_trust_before_any_source_can_boot_it() {
        for changed_env_file in [false, true] {
            let _home = crate::sys::TestHome::new();
            let dir = tempfile::tempdir().unwrap();
            let project = dir.path().join("project");
            let safe = dir.path().join("safe");
            let private = dir.path().join("private");
            std::fs::create_dir_all(&project).unwrap();
            std::fs::create_dir_all(safe.join("share")).unwrap();
            std::fs::create_dir_all(private.join("share")).unwrap();
            std::fs::write(safe.join("env"), "A=safe\n").unwrap();
            std::fs::write(private.join("env"), "A=private\n").unwrap();
            crate::sys::symlink_dir(safe.join("share"), project.join("share")).unwrap();
            crate::sys::symlink_file(safe.join("env"), project.join("env")).unwrap();
            let recipe_text =
                "mounts:\n  - {host: ./share, guest: /work}\nenv_file: ./env\n".to_string();
            let bx = BoxRef::resolve(&project, "dev").unwrap();
            let recipe = || resolve::RecipeFile {
                from: project.join("dev.yaml"),
                text: recipe_text.clone(),
            };
            let target = |source| ResolvedRecipe {
                bx: bx.clone(),
                source,
                manifest: None,
            };
            let approved =
                approve_by_hand(target(resolve::Source::File(recipe())), false, true).unwrap();
            prepare_box(&approved, Rebuild::No, None).unwrap();

            let path = if changed_env_file { "env" } else { "share" };
            if changed_env_file {
                std::fs::remove_file(project.join(path)).unwrap();
            } else {
                crate::sys::remove_directory_symlink(project.join(path)).unwrap();
            }
            let replacement = if changed_env_file {
                private.join("env")
            } else {
                private.join("share")
            };
            if changed_env_file {
                crate::sys::symlink_file(replacement, project.join(path)).unwrap();
            } else {
                crate::sys::symlink_dir(replacement, project.join(path)).unwrap();
            }

            for source in [resolve::Source::Pinned, resolve::Source::File(recipe())] {
                let error = target(source)
                    .load_pinned_recipe()
                    .expect_err("a changed target must not boot")
                    .to_string();
                assert!(error.contains("moved since it was pinned"), "{error}");
            }

            for source in [
                resolve::Source::Pinned,
                resolve::Source::File(recipe()),
                resolve::Source::Manifest(recipe()),
                resolve::Source::File(resolve::RecipeFile {
                    text: format!("{recipe_text}# edited recipe\n"),
                    ..recipe()
                }),
            ] {
                let error = approve_by_hand(target(source), false, false)
                    .expect_err("changed targets require explicit trust")
                    .to_string();
                assert!(
                    error.contains("target changed since it was pinned"),
                    "{error}"
                );
                assert!(error.contains("--trust-recipe"), "{error}");
            }

            let refreshed = approve_by_hand(target(resolve::Source::Pinned), true, true)
                .expect("explicit trust refreshes pinned targets");
            prepare_box(&refreshed, Rebuild::No, None).unwrap();
            target(resolve::Source::Pinned)
                .load_pinned_recipe()
                .expect("the refreshed pin boots");
        }
    }

    /// A volume the recipe dropped keeps its image: deleting data is never a
    /// side effect of a pin or a boot - it used to be, loudly but with nobody
    /// asked. `--rebuild` is the clean slate asked for by name, so only it
    /// sweeps, and a volume the recipe still names survives even that.
    #[test]
    fn a_dropped_volume_s_image_is_kept_until_rebuild_asks_for_the_sweep() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        for name in ["data", "old"] {
            std::fs::write(bx.get_volume_image_path(name), b"image").unwrap();
        }
        let recipe_volumes = vec!["data".to_string()];

        sweep_or_keep_unused_volumes(&bx, &recipe_volumes, Rebuild::No).unwrap();
        assert!(
            bx.get_volume_image_path("old").exists(),
            "a plain pin or boot deleted a volume's data"
        );
        assert!(bx.get_volume_image_path("data").exists());

        sweep_or_keep_unused_volumes(&bx, &recipe_volumes, Rebuild::Yes).unwrap();
        assert!(
            !bx.get_volume_image_path("old").exists(),
            "--rebuild sweeps it"
        );
        assert!(
            bx.get_volume_image_path("data").exists(),
            "a named volume was swept"
        );
    }

    /// Setup applies the recipe's sizes and start only uses them: setup makes
    /// and grows every box-lifetime volume, and leaves a boot-lifetime one to
    /// the boot that replaces it anyway.
    #[test]
    fn setup_makes_and_grows_box_volumes_and_leaves_boot_volumes_to_the_boot() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        let prepare = |size_mib| {
            let recipe = yaml_serde::from_str::<crate::recipe::Recipe>(&format!(
                "volumes:\n  - {{name: kept, guest: /kept, size_mib: {size_mib}}}\n  - {{name: scratch, guest: /scratch, size_mib: 8, lifetime: boot}}\n"
            ))
            .unwrap();
            let approved = ApprovedRecipe {
                bx: bx.clone(),
                recipe,
                new_pin: None,
                pinned_paths: None,
            };
            drop(prepare_box(&approved, Rebuild::No, None).unwrap());
        };
        let kept_mib = || {
            std::fs::metadata(bx.get_volume_image_path("kept"))
                .unwrap()
                .len()
                >> 20
        };
        prepare(8);
        assert_eq!(kept_mib(), 8);
        assert!(!bx.get_volume_image_path("scratch").exists());
        prepare(16);
        assert_eq!(kept_mib(), 16);
    }

    fn prepare_with_root(
        recipe: &str,
        root_and_stamp: Option<(&[u8], Option<&[u8]>)>,
        rebuild: Rebuild,
    ) -> (BoxRef, PreparedBox, tempfile::TempDir, crate::sys::TestHome) {
        let dir = tempfile::tempdir().unwrap();
        let home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::RECIPE_FILE), recipe).unwrap();
        if let Some((root, stamp)) = root_and_stamp {
            std::fs::write(bx.get_dir().join(state::ROOTFS_FILE), root).unwrap();
            if let Some(stamp) = stamp {
                std::fs::write(bx.get_dir().join(state::SETUP_STAMP), stamp).unwrap();
            }
        }
        let approved = ApprovedRecipe {
            bx: bx.clone(),
            recipe: yaml_serde::from_str::<crate::recipe::Recipe>(recipe).unwrap(),
            new_pin: None,
            pinned_paths: None,
        };
        let prepared = prepare_box(&approved, rebuild, None).unwrap();
        (bx, prepared, dir, home)
    }

    /// A root with no stamp, or an empty one, never finished a bake: setup
    /// replaces it rather than reusing it. `--rebuild` replaces even a baked
    /// root, and takes its stamp with it.
    #[test]
    fn setup_replaces_a_root_that_never_finished_a_bake() {
        let digest = [7u8; 32];
        for (root_and_stamp, rebuild) in [
            (None, Rebuild::No),
            (Some((&b"old"[..], None)), Rebuild::No),
            (Some((&b"old"[..], Some(&b""[..]))), Rebuild::No),
            (Some((&b"old"[..], Some(&digest[..]))), Rebuild::Yes),
        ] {
            let (bx, prepared, _dir, _home) = prepare_with_root("{}", root_and_stamp, rebuild);
            assert_eq!(prepared.root, RootPlan::Bake);
            let root = std::fs::read(bx.get_dir().join(state::ROOTFS_FILE)).unwrap();
            assert!(!root.starts_with(b"old"), "the old root was reused");
            assert!(!bx.get_dir().join(state::SETUP_STAMP).exists());
        }
    }

    /// A baked root is kept whatever pin its stamp names, and keeps its stamp
    /// until the setup VM succeeds.
    #[test]
    fn setup_keeps_a_baked_root_and_its_stamp() {
        let current_digest = Sha256::digest(b"{}");
        for stamp in [&current_digest[..], &[9u8; 32][..]] {
            let (bx, prepared, _dir, _home) =
                prepare_with_root("{}", Some((b"baked", Some(stamp))), Rebuild::No);
            assert_eq!(prepared.root, RootPlan::Keep);
            let root = std::fs::read(bx.get_dir().join(state::ROOTFS_FILE)).unwrap();
            assert!(root.starts_with(b"baked"));
            assert_eq!(
                std::fs::read(bx.get_dir().join(state::SETUP_STAMP)).unwrap(),
                stamp
            );
        }
    }

    /// The stamp names the pin the root is set up for. Pinning a new recipe
    /// keeps the old digest, which no longer matches, so a re-setup that fails
    /// or dies before its VM finishes leaves the box unbootable rather than
    /// booting the new recipe against a root prepared for the old one.
    /// Re-pinning nothing keeps it set up.
    #[test]
    fn a_new_pin_is_not_bootable_until_its_setup_vm_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        crate::vm::image::install_or_grow_rootfs_image(&bx.get_dir().join(state::ROOTFS_FILE), 512)
            .unwrap();
        std::fs::write(bx.get_dir().join(state::RECIPE_FILE), "{}").unwrap();
        let stamp = bx.get_dir().join(state::SETUP_STAMP);
        for (new_pin, is_set_up) in [
            (None, true),
            (
                Some(resolve::RecipeFile {
                    from: dir.path().join("dev.yaml"),
                    text: "hw: {cpus: 1}\n".into(),
                }),
                false,
            ),
        ] {
            bx.write_setup_stamp().unwrap();
            let approved = ApprovedRecipe {
                bx: bx.clone(),
                recipe: yaml_serde::from_str::<crate::recipe::Recipe>("{}").unwrap(),
                new_pin,
                pinned_paths: None,
            };
            drop(prepare_box(&approved, Rebuild::No, None).unwrap());
            assert!(stamp.exists());
            assert_eq!(bx.is_set_up(), is_set_up);
        }
    }

    /// In-place edits need setup even when no image is installed or grown.
    /// Boot refuses the old stamp, and setup keeps the root and the stamp until
    /// its VM succeeds.
    #[test]
    fn an_in_place_recipe_edit_invalidates_setup_without_rebuilding() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        let rootfs = bx.get_dir().join(state::ROOTFS_FILE);
        crate::vm::image::install_or_grow_rootfs_image(&rootfs, 512).unwrap();
        let recipe_path = bx.get_dir().join(state::RECIPE_FILE);
        for recipe in [
            "mounts: [{host: ., guest: /new-share}]\n",
            "volumes: [{name: scratch, guest: /new-volume, size_mib: 8, lifetime: boot}]\n",
            "workload: {workdir: /new-work}\n",
            "hw: {rootfs_readonly: true}\n",
        ] {
            std::fs::write(&recipe_path, "{}").unwrap();
            bx.write_setup_stamp().unwrap();
            assert!(bx.is_set_up());
            std::fs::write(&recipe_path, recipe).unwrap();
            assert!(!bx.is_set_up(), "{recipe}");
            assert!(bx.lock_finished().is_err(), "{recipe}");

            let approved = ApprovedRecipe {
                bx: bx.clone(),
                recipe: yaml_serde::from_str::<crate::recipe::Recipe>(recipe).unwrap(),
                new_pin: None,
                pinned_paths: None,
            };
            drop(prepare_box(&approved, Rebuild::No, None).unwrap());
            assert!(bx.get_dir().join(state::SETUP_STAMP).exists(), "{recipe}");
            assert!(!bx.is_set_up(), "{recipe}");
            assert_eq!(std::fs::metadata(&rootfs).unwrap().len(), 512 << 20);
            bx.write_setup_stamp().unwrap();
            assert!(bx.is_set_up(), "{recipe}");
            drop(bx.lock_finished().unwrap());
        }
    }

    /// A dry run answers about the setup it stands for and leaves no trace of
    /// it. Both halves are the point: it reaches the same refusals - here a
    /// mount of the box's own state - and a box that was never set up is still
    /// never set up afterwards, so nothing about a `--dry-run` can be the
    /// reason a later real setup behaves differently.
    #[tokio::test]
    async fn a_dry_run_reaches_the_refusals_and_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(&project, "dev").unwrap();
        let dry_run = cli::SetupArgs {
            trust_recipe: false,
            rebuild: false,
            dry_run: true,
        };

        // A recipe a setup would take: reported, and nothing is built.
        std::fs::write(project.join("dev.yaml"), "hw:\n  cpus: 1\n").unwrap();
        run(&dry_run, Some("./dev.yaml"), &project, &project, false)
            .await
            .unwrap();
        assert!(
            !bx.get_dir().join(state::ROOTFS_FILE).exists(),
            "a dry run built the guest filesystem"
        );
        assert!(
            !bx.get_dir().join(state::RECIPE_FILE).exists(),
            "a dry run pinned the recipe"
        );

        // …and one it would refuse fails the dry run with the same complaint.
        // Written to the same file name, so the box is still `dev` and the
        // mount is of that box's own state rather than another box's.
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(
            project.join("dev.yaml"),
            format!(
                "mounts:\n  - host: {}\n    guest: /work\n",
                bx.get_dir().display()
            ),
        )
        .unwrap();
        let err = format!(
            "{:#}",
            run(&dry_run, Some("./dev.yaml"), &project, &project, false)
                .await
                .expect_err("a dry run must not pass a recipe `terra setup` would refuse")
        );
        assert!(err.contains("this box's own state"), "{err}");
        assert!(
            !bx.get_dir().join(state::RECIPE_FILE).exists(),
            "a refused dry run pinned the recipe"
        );
    }

    /// Setup takes the box's lock before it puts the recipe to anyone, so a
    /// box another terra holds is refused up front - a dry run included - and
    /// nothing changes under the question.
    #[tokio::test]
    async fn a_held_box_is_refused_before_its_recipe_is_asked_about() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(&project, "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(project.join("dev.yaml"), "hw:\n  cpus: 1\n").unwrap();
        let dry_run = cli::SetupArgs {
            trust_recipe: false,
            rebuild: false,
            dry_run: true,
        };

        let held = bx.lock_run().unwrap();
        let err = format!(
            "{:#}",
            run(&dry_run, Some("./dev.yaml"), &project, &project, false)
                .await
                .expect_err("a held box must be refused")
        );
        assert!(err.contains("locked by another terra command"), "{err}");
        drop(held);

        run(&dry_run, Some("./dev.yaml"), &project, &project, false)
            .await
            .unwrap();
    }
}
