//! `terra setup`: apply an approved recipe, then prepare the guest filesystem.

use crate::approval::{ApplyEffect, Approval, ApprovedRecipe, review_recipe};
use crate::recipe::resolve;
use crate::recipe::{Recipe, VolumeLifetime};
use crate::state::{BoxRef, BoxSetupState};
use crate::vm::boot;
use crate::{cli, state};
use anyhow::{Context, Result};
use std::fs::File;
use std::path::Path;
use std::process::ExitCode;

/// `terra [BOX] setup` - apply a recipe, build the filesystem, run `on_create`.
pub async fn run(
    args: &cli::SetupArgs,
    name: Option<&str>,
    project_dir: &Path,
    cwd: &Path,
    is_at_a_terminal: bool,
) -> Result<ExitCode> {
    let target = resolve::resolve_recipe(name, project_dir, resolve::Purpose::Apply { cwd })?;
    let held = target.bx.lock_if_present()?;
    let rebuild = if args.rebuild {
        Rebuild::Yes
    } else {
        Rebuild::No
    };
    let review = review_recipe(target)?;
    let plan = plan_root(review.get_box(), rebuild, review.get_changed_text())?;
    let effect = plan.get_effect(review.get_changed_text().is_some());
    let approval = if args.dry_run {
        Approval::Reported
    } else {
        Approval::ChosenByHand {
            trust_recipe: args.trust_recipe,
        }
    };
    let approved = review.approve(&approval, effect, is_at_a_terminal)?;
    if args.dry_run {
        // The refusals have run; the rest is the disk work a dry run exists
        // not to do.
        eprintln!(
            "terra: --dry-run: {}; nothing was changed",
            describe_dry_run(&approved, plan)
        );
        return Ok(ExitCode::SUCCESS);
    }
    let PreparedBox { lock, plan } = prepare_box(&approved, plan, rebuild, held)?;
    let ApprovedRecipe { bx, recipe, .. } = approved;
    if plan != RootPlan::Keep {
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

/// What setup does to the box's root image. The root always matches what the
/// applied recipe gave the setup boot that baked it, so changing that rebuilds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootPlan {
    Keep,
    Create,
    Rebuild(RebuildReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RebuildReason {
    RecipeChanged,
    /// The applied recipe is unchanged, but its root was baked for other setup inputs, as by an older terra.
    NotBakedForAppliedRecipe,
    Unfinished,
    Asked,
}

impl RootPlan {
    fn get_effect(self, has_changed_recipe: bool) -> ApplyEffect {
        match self {
            RootPlan::Keep if has_changed_recipe => ApplyEffect::Update,
            RootPlan::Keep => ApplyEffect::PinPaths,
            RootPlan::Create => ApplyEffect::Create,
            RootPlan::Rebuild(_) => ApplyEffect::Rebuild,
        }
    }
}

impl RebuildReason {
    fn describe(self) -> &'static str {
        match self {
            RebuildReason::RecipeChanged => "the recipe changed",
            RebuildReason::NotBakedForAppliedRecipe => {
                "its root was not baked for the applied recipe"
            }
            RebuildReason::Unfinished => "its last setup did not finish",
            RebuildReason::Asked => "asked for with --rebuild",
        }
    }
}

/// Plan for `changed_text`, the recipe about to be applied, or for the applied
/// recipe when it is `None`.
fn plan_root(bx: &BoxRef, rebuild: Rebuild, changed_text: Option<&str>) -> Result<RootPlan> {
    let setup_state = bx.get_setup_state()?;
    Ok(match (rebuild, setup_state) {
        (Rebuild::Yes | Rebuild::No, BoxSetupState::Missing) => RootPlan::Create,
        (Rebuild::Yes, BoxSetupState::Unbaked | BoxSetupState::Stale | BoxSetupState::SetUp) => {
            RootPlan::Rebuild(RebuildReason::Asked)
        }
        (Rebuild::No, BoxSetupState::Unbaked) => RootPlan::Rebuild(RebuildReason::Unfinished),
        (Rebuild::No, BoxSetupState::Stale | BoxSetupState::SetUp) => {
            let (is_baked_for_it, reason) = match changed_text {
                Some(text) => (bx.is_root_baked_for(text)?, RebuildReason::RecipeChanged),
                None => (
                    setup_state == BoxSetupState::SetUp,
                    RebuildReason::NotBakedForAppliedRecipe,
                ),
            };
            if is_baked_for_it {
                RootPlan::Keep
            } else {
                RootPlan::Rebuild(reason)
            }
        }
    })
}

fn describe_dry_run(approved: &ApprovedRecipe, plan: RootPlan) -> String {
    let bx = &approved.bx;
    match plan {
        RootPlan::Keep if approved.changed_recipe.is_some() => {
            let paths = if approved.pinned_paths.is_some() {
                ", update its share and env_file paths,"
            } else {
                ""
            };
            format!("setup would apply the new recipe to {bx}{paths} and keep its root")
        }
        RootPlan::Keep if approved.pinned_paths.is_some() => {
            format!("setup would update {bx}'s share and env_file paths")
        }
        RootPlan::Keep => format!("{bx} is already set up for this recipe"),
        RootPlan::Create if approved.recipe.hooks.on_create.is_empty() => {
            format!("setup would create {bx}")
        }
        RootPlan::Create => format!("setup would create {bx} and run on_create"),
        RootPlan::Rebuild(reason) => {
            format!(
                "setup would rebuild {bx} from scratch: {}",
                reason.describe()
            )
        }
    }
}

struct PreparedBox {
    lock: File,
    plan: RootPlan,
}

/// Carry out the approved plan under `held`, the lock taken before approval, or
/// a new one for a box that had no state to lock then.
fn prepare_box(
    approved: &ApprovedRecipe,
    approved_plan: RootPlan,
    rebuild: Rebuild,
    held: Option<File>,
) -> Result<PreparedBox> {
    let ApprovedRecipe { bx, recipe, .. } = approved;
    let lock = match held {
        Some(lock) => lock,
        None => bx.lock_and_repair()?,
    };
    let plan = replan_under_lock(approved, approved_plan, rebuild)?;
    bx.prepare_state_dir()?;
    match plan {
        RootPlan::Keep if approved.changed_recipe.is_some() => {
            eprintln!("terra: {bx} keeps its root: the change only affects its boots");
        }
        RootPlan::Keep => {}
        RootPlan::Create => discard_root(bx)?,
        RootPlan::Rebuild(reason) => {
            eprintln!(
                "terra: rebuilding {bx} from scratch: {} - on_create runs again; box volumes are kept",
                reason.describe()
            );
            discard_root(bx)?;
        }
    }
    approved.write_applied_recipe(bx.get_dir())?;
    install_or_grow_images(bx, recipe, rebuild)?;
    Ok(PreparedBox { lock, plan })
}

/// Plan again now that the box is locked: a box that had no state to lock
/// while the question was open may have been set up since, and the plan
/// approved for it must not discard that root unasked.
fn replan_under_lock(
    approved: &ApprovedRecipe,
    approved_plan: RootPlan,
    rebuild: Rebuild,
) -> Result<RootPlan> {
    let bx = &approved.bx;
    let changed_text = approved
        .changed_recipe
        .as_ref()
        .map(|file| file.text.as_str());
    let plan = plan_root(bx, rebuild, changed_text)?;
    anyhow::ensure!(
        plan == RootPlan::Keep || plan == approved_plan,
        "{bx} changed while setup was waiting for an answer - run `terra {} setup` again",
        bx.get_name()
    );
    Ok(plan)
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

    /// Plan and carry out a setup's disk work, as `run` does.
    fn prepare(approved: &ApprovedRecipe, rebuild: Rebuild) -> Result<File> {
        let changed_text = approved
            .changed_recipe
            .as_ref()
            .map(|file| file.text.as_str());
        let plan = plan_root(&approved.bx, rebuild, changed_text)?;
        Ok(prepare_box(approved, plan, rebuild, None)?.lock)
    }
    use crate::recipe::resolve::ResolvedRecipe;

    #[test]
    fn a_changed_target_needs_explicit_trust_before_any_source_can_boot_it() {
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
            prepare(&approved, Rebuild::No).unwrap();

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

            for source in [resolve::Source::Applied, resolve::Source::File(recipe())] {
                let error = target(source)
                    .load_applied_recipe()
                    .expect_err("a changed target must not boot")
                    .to_string();
                assert!(error.contains("moved since the last setup"), "{error}");
            }

            for source in [
                resolve::Source::Applied,
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
                    error.contains("target changed since the last setup"),
                    "{error}"
                );
                assert!(error.contains("--trust-recipe"), "{error}");
            }

            let refreshed = approve_by_hand(target(resolve::Source::Applied), true, true)
                .expect("explicit trust refreshes applied targets");
            prepare(&refreshed, Rebuild::No).unwrap();
            target(resolve::Source::Applied)
                .load_applied_recipe()
                .expect("the refreshed applied recipe boots");
        }
    }

    /// A volume the recipe dropped keeps its image: deleting data is never a
    /// side effect of an applied recipe or a boot - it used to be, loudly but with nobody
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
            "a plain apply or boot deleted a volume's data"
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
                changed_recipe: None,
                pinned_paths: None,
            };
            drop(prepare(&approved, Rebuild::No).unwrap());
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
    ) -> (BoxRef, tempfile::TempDir, crate::sys::TestHome) {
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
            changed_recipe: None,
            pinned_paths: None,
        };
        drop(prepare(&approved, rebuild).unwrap());
        (bx, dir, home)
    }

    /// A root with no stamp, or an empty one, never finished a bake, and a
    /// root stamped for another applied recipe was baked for another recipe: setup
    /// replaces both rather than reusing them. `--rebuild` replaces even a
    /// root baked for this applied recipe, and takes its stamp with it.
    #[test]
    fn setup_replaces_a_root_not_baked_for_the_applied_recipe() {
        let current_digest = state::digest_setup_boot_inputs("{}");
        let other_digest = [7u8; 32];
        for (root_and_stamp, rebuild) in [
            (None, Rebuild::No),
            (Some((&b"old"[..], None)), Rebuild::No),
            (Some((&b"old"[..], Some(&b""[..]))), Rebuild::No),
            (Some((&b"old"[..], Some(&other_digest[..]))), Rebuild::No),
            (Some((&b"old"[..], Some(&current_digest[..]))), Rebuild::Yes),
        ] {
            let (bx, _dir, _home) = prepare_with_root("{}", root_and_stamp, rebuild);
            let root = std::fs::read(bx.get_dir().join(state::ROOTFS_FILE)).unwrap();
            assert!(!root.starts_with(b"old"), "the old root was reused");
            assert!(!bx.get_dir().join(state::SETUP_STAMP).exists());
        }
    }

    /// Setup on an unchanged applied recipe keeps the root baked for it, and its stamp.
    #[test]
    fn setup_keeps_a_root_baked_for_the_applied_recipe() {
        let stamp = state::digest_setup_boot_inputs("{}");
        let (bx, _dir, _home) =
            prepare_with_root("{}", Some((b"baked", Some(&stamp))), Rebuild::No);
        let root = std::fs::read(bx.get_dir().join(state::ROOTFS_FILE)).unwrap();
        assert!(root.starts_with(b"baked"));
        assert_eq!(
            std::fs::read(bx.get_dir().join(state::SETUP_STAMP)).unwrap(),
            stamp.as_slice()
        );
    }

    /// Applying a new recipe rebuilds the root and drops its stamp, so a
    /// re-setup that fails or dies before its VM finishes leaves the box
    /// unbootable rather than booting the new recipe against a root baked for
    /// the old one. Re-applying nothing keeps it set up.
    #[test]
    fn a_changed_recipe_rebuilds_the_root_and_is_not_bootable_until_its_setup_vm_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        crate::vm::image::install_or_grow_rootfs_image(&bx.get_dir().join(state::ROOTFS_FILE), 512)
            .unwrap();
        std::fs::write(bx.get_dir().join(state::RECIPE_FILE), "{}").unwrap();
        let stamp = bx.get_dir().join(state::SETUP_STAMP);
        for (changed_recipe, is_set_up) in [
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
                changed_recipe,
                pinned_paths: None,
            };
            drop(prepare(&approved, Rebuild::No).unwrap());
            assert_eq!(stamp.exists(), is_set_up);
            assert_eq!(bx.is_set_up(), is_set_up);
        }
    }

    /// An in-place edit of the applied recipe needs setup even when no image is
    /// installed or grown: boot refuses the old stamp, and setup rebuilds the
    /// root for the edited recipe.
    #[test]
    fn an_in_place_recipe_edit_invalidates_setup_and_rebuilds_the_root() {
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
                changed_recipe: None,
                pinned_paths: None,
            };
            drop(prepare(&approved, Rebuild::No).unwrap());
            assert!(!bx.get_dir().join(state::SETUP_STAMP).exists(), "{recipe}");
            assert!(!bx.is_set_up(), "{recipe}");
            assert_eq!(std::fs::metadata(&rootfs).unwrap().len(), 512 << 20);
            bx.write_setup_stamp().unwrap();
            assert!(bx.is_set_up(), "{recipe}");
            drop(bx.lock_finished().unwrap());
        }
    }

    /// A setup that waited at its question for a box with no state does not
    /// discard a root another setup finished meanwhile: the same recipe keeps
    /// it, and a different one is refused rather than rebuilt unasked.
    #[test]
    fn a_setup_replans_under_the_lock_it_took_after_asking() {
        for (other_recipe, keeps) in [("{}", true), ("hw: {cpus: 5}\n", false)] {
            let dir = tempfile::tempdir().unwrap();
            let _home = crate::sys::TestHome::new();
            let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
            let approved = ApprovedRecipe {
                bx: bx.clone(),
                recipe: Recipe::default(),
                changed_recipe: Some(resolve::RecipeFile {
                    from: dir.path().join("dev.yaml"),
                    text: "# mine\n{}\n".into(),
                }),
                pinned_paths: None,
            };
            let plan = plan_root(&bx, Rebuild::No, Some("# mine\n{}\n")).unwrap();
            assert_eq!(plan, RootPlan::Create);

            std::fs::create_dir_all(bx.get_dir()).unwrap();
            std::fs::write(bx.get_dir().join(state::ROOTFS_FILE), b"theirs").unwrap();
            std::fs::write(bx.get_dir().join(state::RECIPE_FILE), other_recipe).unwrap();
            bx.write_setup_stamp().unwrap();

            let prepared = prepare_box(&approved, plan, Rebuild::No, None);
            let root = std::fs::read(bx.get_dir().join(state::ROOTFS_FILE)).unwrap();
            assert!(root.starts_with(b"theirs"), "{other_recipe}");
            if keeps {
                assert_eq!(prepared.unwrap().plan, RootPlan::Keep);
            } else {
                let error = prepared.err().expect("a different recipe rebuilt unasked");
                assert!(error.to_string().contains("changed while setup"), "{error}");
            }
        }
    }

    /// Only what the setup boot sees decides a rebuild. A new `run`, daemon,
    /// `on_start`/`pre_stop` hook, `sudo`, published port, component memory or
    /// read-only flag is applied over the baked root, which stays bootable with
    /// no setup VM; `workdir` is made on the root by the setup boot, and
    /// `on_create` reads `hw.cpus`, so changing either rebuilds.
    #[test]
    fn only_what_the_setup_boot_sees_rebuilds_the_root() {
        for (text, keeps) in [
            (
                "workload: {run: exec bash -l}\ndaemons: [sleep 9]\n\
                 hooks: {on_start: [true], pre_stop: [true]}\n",
                true,
            ),
            (
                "hw: {rootfs_readonly: true}\ncomponents: {memory_mib: 96}\nsudo: [apk]\n\
                 network: {ports: ['8080:80']}\n",
                true,
            ),
            ("workload: {workdir: /srv}\n", false),
            ("hw: {cpus: 3}\n", false),
            ("hooks: {on_create: [true]}\n", false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let _home = crate::sys::TestHome::new();
            let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
            std::fs::create_dir_all(bx.get_dir()).unwrap();
            std::fs::write(bx.get_dir().join(state::ROOTFS_FILE), b"baked").unwrap();
            std::fs::write(bx.get_dir().join(state::RECIPE_FILE), "{}").unwrap();
            bx.write_setup_stamp().unwrap();
            let approved = ApprovedRecipe {
                bx: bx.clone(),
                recipe: yaml_serde::from_str(text).unwrap(),
                changed_recipe: Some(resolve::RecipeFile {
                    from: dir.path().join("dev.yaml"),
                    text: text.into(),
                }),
                pinned_paths: None,
            };
            drop(prepare(&approved, Rebuild::No).unwrap());
            let root = std::fs::read(bx.get_dir().join(state::ROOTFS_FILE)).unwrap();
            assert_eq!(root.starts_with(b"baked"), keeps, "{text}");
            assert_eq!(bx.is_set_up(), keeps, "{text}");
            assert_eq!(
                std::fs::read_to_string(bx.get_dir().join(state::RECIPE_FILE)).unwrap(),
                text,
                "the new recipe was not applied"
            );
        }
    }

    /// A dry run says what the real setup would do to the box, from the same
    /// decision the real setup acts on.
    #[test]
    fn a_dry_run_says_what_setup_would_do() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        let describe = |has_changed_recipe: bool| {
            let approved = ApprovedRecipe {
                bx: bx.clone(),
                recipe: Recipe::default(),
                changed_recipe: has_changed_recipe.then(|| resolve::RecipeFile {
                    from: dir.path().join("dev.yaml"),
                    text: "hw: {cpus: 1}\n".into(),
                }),
                pinned_paths: None,
            };
            let changed_text = approved
                .changed_recipe
                .as_ref()
                .map(|file| file.text.as_str());
            let plan = plan_root(&bx, Rebuild::No, changed_text).unwrap();
            describe_dry_run(&approved, plan)
        };

        let created = describe(true);
        assert!(
            created.contains("would create") && !created.contains("on_create"),
            "{created}"
        );
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::ROOTFS_FILE), b"root").unwrap();
        std::fs::write(bx.get_dir().join(state::RECIPE_FILE), "{}").unwrap();
        bx.write_setup_stamp().unwrap();
        assert!(
            describe(false).contains("already set up"),
            "{}",
            describe(false)
        );
        assert!(
            describe(true).contains("the recipe changed"),
            "{}",
            describe(true)
        );
        let with_on_create = ApprovedRecipe {
            bx: bx.clone(),
            recipe: yaml_serde::from_str("hooks: {on_create: [true]}\n").unwrap(),
            changed_recipe: None,
            pinned_paths: None,
        };
        let created_with_on_create = describe_dry_run(&with_on_create, RootPlan::Create);
        assert!(
            created_with_on_create.contains("and run on_create"),
            "{created_with_on_create}"
        );
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
            "a dry run applied the recipe"
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
            "a refused dry run applied the recipe"
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
