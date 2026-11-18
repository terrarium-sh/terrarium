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

/// `terra [BOX] setup` - apply a recipe, build the filesystem, run setup.
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
    let mut approved = review.approve(&approval, effect, is_at_a_terminal)?;
    if args.dry_run {
        // The refusals have run; the rest is the disk work a dry run exists
        // not to do.
        eprintln!(
            "terra: --dry-run: {}; nothing was changed",
            describe_dry_run(&approved, plan)
        );
        return Ok(ExitCode::SUCCESS);
    }
    let PreparedBox { lock, plan } = prepare_box(&mut approved, plan, rebuild, held)?;
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

/// What setup does to the box's root image.
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
        RootPlan::Create if approved.recipe.setup.run.is_empty() => {
            format!("setup would create {bx}")
        }
        RootPlan::Create => format!("setup would create {bx} and run setup"),
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
    approved: &mut ApprovedRecipe,
    approved_plan: RootPlan,
    rebuild: Rebuild,
    held: Option<File>,
) -> Result<PreparedBox> {
    let (lock, plan) = if let Some(lock) = held {
        (lock, approved_plan)
    } else {
        let lock = approved.bx.lock_and_repair()?;
        (lock, replan_under_lock(approved, approved_plan, rebuild)?)
    };
    let bx = &approved.bx;
    bx.prepare_state_dir()?;
    match plan {
        RootPlan::Keep if approved.changed_recipe.is_some() => {
            eprintln!("terra: {bx} keeps its root: the change only affects its boots");
        }
        RootPlan::Keep => {}
        RootPlan::Create => discard_root(bx)?,
        RootPlan::Rebuild(reason) => {
            eprintln!(
                "terra: rebuilding {bx} from scratch: {} - setup runs again; box volumes are kept",
                reason.describe()
            );
            discard_root(bx)?;
        }
    }
    approved.write_applied_recipe(bx.get_dir())?;
    install_or_grow_images(bx, &approved.recipe, rebuild)?;
    Ok(PreparedBox { lock, plan })
}

/// A competing setup may have built the root while this one awaited approval.
/// Keeping that root also keeps the setup grants recorded by its builder.
fn replan_under_lock(
    approved: &mut ApprovedRecipe,
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
    if plan == RootPlan::Keep && approved.pinned_paths.is_some() {
        let existing = bx.load_pinned_paths()?;
        let updated = state::PinnedPaths::for_kept_root(&approved.recipe, existing.as_ref());
        approved.pinned_paths = (existing.as_ref() != Some(&updated)).then_some(updated);
    }
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
    fn prepare(mut approved: ApprovedRecipe, rebuild: Rebuild) -> Result<File> {
        let changed_text = approved
            .changed_recipe
            .as_ref()
            .map(|file| file.text.as_str());
        let plan = plan_root(&approved.bx, rebuild, changed_text)?;
        Ok(prepare_box(&mut approved, plan, rebuild, None)?.lock)
    }
    use crate::recipe::resolve::ResolvedRecipe;

    #[tokio::test]
    async fn oversized_phase_plans_are_refused_before_replacing_the_applied_recipe_or_root() {
        let _home = crate::sys::TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let original = "setup: {run: ['true']}\n";
        let original_pins = state::PinnedPaths::for_setup(&yaml_serde::from_str(original).unwrap());
        let command = "x".repeat(terra_protocol::MAX_PLAN_BYTES);
        let args = cli::SetupArgs {
            trust_recipe: true,
            rebuild: false,
            dry_run: false,
        };
        for (name, recipe) in [
            ("large-setup", format!("setup:\n  run:\n    - {command}\n")),
            (
                "large-workload",
                format!("{original}workload:\n  run: {command}\n"),
            ),
        ] {
            let bx = BoxRef::resolve(project, name).unwrap();
            std::fs::create_dir_all(bx.get_dir()).unwrap();
            let applied_recipe = bx.get_dir().join(state::RECIPE_FILE);
            let root = bx.get_dir().join(state::ROOTFS_FILE);
            state::write_applied_recipe(bx.get_dir(), Some(original), Some(&original_pins))
                .unwrap();
            std::fs::write(&root, b"baked root").unwrap();
            bx.write_setup_stamp().unwrap();
            let recipe_arg = format!("./{name}.yaml");
            std::fs::write(project.join(&recipe_arg), recipe).unwrap();

            let error = run(&args, Some(&recipe_arg), project, project, false)
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("boot plan exceeds its encoded size limit"),
                "{name}: {error:#}"
            );
            assert_eq!(std::fs::read_to_string(applied_recipe).unwrap(), original);
            assert_eq!(std::fs::read(root).unwrap(), b"baked root");
            assert_eq!(
                bx.load_pinned_paths().unwrap().as_ref(),
                Some(&original_pins)
            );
            assert!(bx.is_set_up());
        }
    }

    #[tokio::test]
    async fn an_applied_box_with_missing_pins_needs_approval_to_recover() {
        let _home = crate::sys::TestHome::new();
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path();
        let setup_share = project.join("setup-share");
        std::fs::create_dir(&setup_share).unwrap();
        std::fs::create_dir(project.join("share")).unwrap();
        std::fs::write(project.join("env"), "VAR=value\n").unwrap();
        for (name, text) in [
            (
                "with-setup",
                "setup: {mounts: [{host: ./setup-share, guest: /share}]}\n",
            ),
            (
                "with-workload",
                "workload: {mounts: [{host: ./share, guest: /share}]}\n",
            ),
            ("with-dotenv", "env_file: ./env\n"),
            ("empty", "network: {enabled: false}\n"),
        ] {
            let bx = BoxRef::resolve(project, name).unwrap();
            let recipe_arg = format!("./{name}.yaml");
            let recipe_path = project.join(&recipe_arg);
            let applied = || ResolvedRecipe {
                bx: bx.clone(),
                source: resolve::Source::Applied,
                manifest: None,
            };
            std::fs::create_dir_all(bx.get_dir()).unwrap();
            let root = bx.get_dir().join(state::ROOTFS_FILE);
            let applied_recipe = bx.get_dir().join(state::RECIPE_FILE);
            std::fs::write(&applied_recipe, text).unwrap();
            std::fs::write(&root, b"baked root").unwrap();
            bx.write_setup_stamp().unwrap();

            let pins = bx.get_dir().join(state::PINNED_PATHS_FILE);
            let error = applied().load_applied_recipe().unwrap_err();
            assert!(
                error.to_string().contains(state::PINNED_PATHS_FILE),
                "{error:#}"
            );

            std::fs::write(recipe_path, format!("{text}env: {{REVIEW_TEST: new}}\n")).unwrap();
            for name in [name, recipe_arg.as_str()] {
                let error = run(
                    &cli::SetupArgs {
                        trust_recipe: false,
                        rebuild: false,
                        dry_run: false,
                    },
                    Some(name),
                    project,
                    project,
                    false,
                )
                .await
                .unwrap_err()
                .to_string();
                assert!(error.contains(state::PINNED_PATHS_FILE), "{error}");
                assert!(error.contains("--trust-recipe"), "{error}");
                assert!(!pins.exists());
                assert_eq!(std::fs::read(&root).unwrap(), b"baked root");
                assert_eq!(std::fs::read_to_string(&applied_recipe).unwrap(), text);
            }

            if name == "with-setup" {
                std::fs::remove_dir(&setup_share).unwrap();
            }
            let result = run(
                &cli::SetupArgs {
                    trust_recipe: true,
                    rebuild: false,
                    dry_run: false,
                },
                Some(name),
                project,
                project,
                false,
            )
            .await
            .unwrap();
            assert_eq!(result, ExitCode::SUCCESS);
            assert!(bx.is_set_up());
            let mut root_prefix = [0; b"baked root".len()];
            std::io::Read::read_exact(&mut File::open(root).unwrap(), &mut root_prefix).unwrap();
            assert_eq!(&root_prefix, b"baked root");
            assert_eq!(std::fs::read_to_string(applied_recipe).unwrap(), text);
            let refreshed_pins = bx.load_pinned_paths().unwrap().unwrap();
            assert_eq!(refreshed_pins.setup_mounts, [] as [std::path::PathBuf; 0]);
            applied().load_applied_recipe().unwrap();
        }
    }

    #[tokio::test]
    async fn keeping_a_baked_root_ignores_missing_and_retargeted_setup_mounts() {
        let _home = crate::sys::TestHome::new();
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        for path in [&project, &first, &second] {
            std::fs::create_dir(path).unwrap();
        }
        let source = project.join("sdk");
        crate::sys::symlink_dir(&first, &source).unwrap();
        let recipe_path = project.join("dev.yaml");
        let text = "network: {enabled: false}\nsetup: {mounts: [{host: ./sdk, guest: /sdk}]}\n";
        std::fs::write(&recipe_path, text).unwrap();
        let target = resolve::resolve_recipe(
            Some("./dev.yaml"),
            &project,
            resolve::Purpose::Apply { cwd: &project },
        )
        .unwrap();
        let bx = target.bx.clone();
        let original = approve_by_hand(target, false, false).unwrap();
        drop(prepare(original, Rebuild::No).unwrap());
        bx.write_setup_stamp().unwrap();
        let original_pins = bx.load_pinned_paths().unwrap();

        let keep = cli::SetupArgs {
            trust_recipe: false,
            rebuild: false,
            dry_run: false,
        };
        let preview = cli::SetupArgs {
            dry_run: true,
            ..keep
        };
        let rebuild = cli::SetupArgs {
            rebuild: true,
            ..keep
        };
        let setup = async |args: &cli::SetupArgs| {
            run(args, Some("./dev.yaml"), &project, &project, false).await
        };
        crate::sys::remove_directory_symlink(&source).unwrap();
        assert_eq!(setup(&keep).await.unwrap(), ExitCode::SUCCESS);
        assert_eq!(setup(&preview).await.unwrap(), ExitCode::SUCCESS);
        let error = setup(&rebuild).await.unwrap_err().to_string();
        assert!(error.contains("resolving mount host path"), "{error}");
        assert!(error.contains("sdk"), "{error}");

        let setup_edit =
            "network: {enabled: false}\nsetup: {mounts: [{host: ./sdk, guest: /other}]}\n";
        std::fs::write(&recipe_path, setup_edit).unwrap();
        let error = setup(&preview).await.unwrap_err().to_string();
        assert!(error.contains("resolving mount host path"), "{error}");

        let runtime_edit = format!("{text}workload: {{run: 'true'}}\n");
        std::fs::write(&recipe_path, &runtime_edit).unwrap();
        assert_eq!(setup(&keep).await.unwrap(), ExitCode::SUCCESS);
        assert_eq!(
            std::fs::read_to_string(bx.get_dir().join(state::RECIPE_FILE)).unwrap(),
            runtime_edit
        );
        assert!(bx.is_set_up());

        crate::sys::symlink_dir(&second, &source).unwrap();
        assert_eq!(setup(&keep).await.unwrap(), ExitCode::SUCCESS);
        let error = setup(&rebuild).await.unwrap_err().to_string();
        assert!(
            error.contains("target changed since the last setup"),
            "{error}"
        );
        assert!(error.contains("--trust-recipe"), "{error}");

        crate::sys::remove_directory_symlink(&source).unwrap();
        crate::sys::symlink_dir(bx.get_dir(), &source).unwrap();
        assert_eq!(setup(&preview).await.unwrap(), ExitCode::SUCCESS);
        std::fs::write(&recipe_path, setup_edit).unwrap();
        let error = setup(&preview).await.unwrap_err().to_string();
        assert!(error.contains("this box's own state"), "{error}");
        assert!(bx.is_set_up());
        assert_eq!(bx.load_pinned_paths().unwrap(), original_pins);
    }

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
                "workload:\n  mounts:\n    - {host: ./share, guest: /work}\nenv_file: ./env\n"
                    .to_string();
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
            prepare(approved, Rebuild::No).unwrap();

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
            prepare(refreshed, Rebuild::No).unwrap();
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
            drop(prepare(approved, Rebuild::No).unwrap());
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
        drop(prepare(approved, rebuild).unwrap());
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
            drop(prepare(approved, Rebuild::No).unwrap());
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
            "workload: {mounts: [{host: ., guest: /new-share}]}\n",
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
            drop(prepare(approved, Rebuild::No).unwrap());
            assert!(!bx.get_dir().join(state::SETUP_STAMP).exists(), "{recipe}");
            assert!(!bx.is_set_up(), "{recipe}");
            assert_eq!(std::fs::metadata(&rootfs).unwrap().len(), 512 << 20);
            bx.write_setup_stamp().unwrap();
            assert!(bx.is_set_up(), "{recipe}");
            drop(bx.lock_finished().unwrap());
        }
    }

    /// A setup racing creation keeps the other setup's baked root and its
    /// approved setup mounts. A root baked for a different recipe needs a retry.
    #[test]
    fn a_setup_replans_under_the_lock_it_took_after_asking() {
        let recipe = "setup: {mounts: [{host: ./sdk, guest: /sdk}]}\nworkload: {mounts: [{host: ./src, guest: /src}]}\n";
        let workload_edit = recipe.replace("./src", "./other");
        for (other_recipe, keeps_root) in [
            (recipe, true),
            (workload_edit.as_str(), true),
            ("hw: {cpus: 5}\n", false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let _home = crate::sys::TestHome::new();
            let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
            let pins = |text, source| {
                state::PinnedPaths::new(
                    &yaml_serde::from_str(text).unwrap(),
                    vec![dir.path().join(source)],
                )
            };
            let candidate_text = format!("# mine\n{recipe}");
            let mut approved = ApprovedRecipe {
                bx: bx.clone(),
                recipe: yaml_serde::from_str(recipe).unwrap(),
                changed_recipe: Some(resolve::RecipeFile {
                    from: dir.path().join("dev.yaml"),
                    text: candidate_text.clone(),
                }),
                pinned_paths: Some(pins(recipe, "mine")),
            };
            let plan = plan_root(&bx, Rebuild::No, Some(&candidate_text)).unwrap();
            assert_eq!(plan, RootPlan::Create);

            std::fs::create_dir_all(bx.get_dir()).unwrap();
            let root_path = bx.get_dir().join(state::ROOTFS_FILE);
            std::fs::write(&root_path, b"theirs").unwrap();
            let their_pins = pins(other_recipe, "theirs");
            state::write_applied_recipe(bx.get_dir(), Some(other_recipe), Some(&their_pins))
                .unwrap();
            bx.write_setup_stamp().unwrap();

            let prepared = prepare_box(&mut approved, plan, Rebuild::No, None);
            let mut root = [0; b"theirs".len()];
            std::io::Read::read_exact(&mut File::open(root_path).unwrap(), &mut root).unwrap();
            assert_eq!(&root, b"theirs");
            if keeps_root {
                assert_eq!(prepared.unwrap().plan, RootPlan::Keep);
                assert_eq!(approved.pinned_paths.is_some(), other_recipe != recipe);
                assert_eq!(
                    bx.load_pinned_paths().unwrap(),
                    Some(pins(recipe, "theirs"))
                );
            } else {
                let error = prepared.err().expect("a different recipe rebuilt unasked");
                assert!(error.to_string().contains("changed while setup"), "{error}");
                assert_eq!(bx.load_pinned_paths().unwrap(), Some(their_pins));
            }
        }
    }

    #[test]
    fn an_approved_keep_plan_cannot_turn_into_a_setup_boot() {
        let _home = crate::sys::TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        let root = bx.get_dir().join(state::ROOTFS_FILE);
        std::fs::write(&root, b"baked root").unwrap();
        let recipe_path = bx.get_dir().join(state::RECIPE_FILE);
        std::fs::write(&recipe_path, "{}").unwrap();
        bx.write_setup_stamp().unwrap();
        let mut approved = ApprovedRecipe {
            bx: bx.clone(),
            recipe: Recipe::default(),
            changed_recipe: None,
            pinned_paths: None,
        };
        let plan = plan_root(&bx, Rebuild::No, None).unwrap();
        assert_eq!(plan, RootPlan::Keep);
        bx.remove_setup_stamp().unwrap();

        let error = prepare_box(&mut approved, plan, Rebuild::No, None)
            .err()
            .expect("the keep plan no longer applies");
        assert!(error.to_string().contains("changed while setup"), "{error}");
        assert_eq!(std::fs::read(root).unwrap(), b"baked root");
    }

    /// Only what the setup boot sees decides a rebuild. A new runtime command,
    /// daemon, lifecycle hook, `workload.sudo`, published port, component
    /// memory or read-only flag is applied over the baked root, which stays
    /// bootable with no setup VM. A new runtime mount's source and access are
    /// equally runtime-only, but its destination is baked; setup commands,
    /// their workdir and mounts shape the root, and setup reads `hw.cpus`.
    #[test]
    fn only_what_the_setup_boot_sees_rebuilds_the_root() {
        for (text, keeps) in [
            (
                "workload:\n  run: exec bash -l\n  daemons: [sleep 9]\n  \
                 on_start: [true]\n  pre_stop: [true]\n  sudo: [apk]\n",
                true,
            ),
            (
                "hw: {rootfs_readonly: true}\ncomponents: {memory_mib: 96}\n\
                 network: {ports: ['8080:80']}\n",
                true,
            ),
            (
                "workload: {mounts: [{host: /elsewhere, guest: /work, readonly: true}]}\n",
                false,
            ),
            ("workload: {workdir: /srv}\n", false),
            ("hw: {cpus: 3}\n", false),
            ("setup: {run: [true]}\n", false),
            ("setup: {workdir: /srv}\n", false),
            ("setup: {mounts: [{host: ., guest: /setup}]}\n", false),
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
            drop(prepare(approved, Rebuild::No).unwrap());
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
            created.contains("would create") && !created.contains("run setup"),
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
        let with_setup = ApprovedRecipe {
            bx: bx.clone(),
            recipe: yaml_serde::from_str("setup: {run: [true]}\n").unwrap(),
            changed_recipe: None,
            pinned_paths: None,
        };
        let created_with_setup = describe_dry_run(&with_setup, RootPlan::Create);
        assert!(
            created_with_setup.contains("and run setup"),
            "{created_with_setup}"
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
        assert_eq!(
            run(&dry_run, Some("./dev.yaml"), &project, &project, false)
                .await
                .unwrap(),
            ExitCode::SUCCESS
        );
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
                "workload:\n  mounts:\n    - host: {}\n      guest: /work\n",
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

        assert_eq!(
            run(&dry_run, Some("./dev.yaml"), &project, &project, false)
                .await
                .unwrap(),
            ExitCode::SUCCESS
        );
    }
}
