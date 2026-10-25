//! Pin approved recipes and host paths, then prepare the guest filesystem.
//! Approval prevents a guest-written recipe in a writable share from granting new host access.

use crate::policy::mount;
use crate::render::{escape_printable_path, render_policy_summary};
use crate::resolve::{self, ResolvedBox};
use crate::state::{BoxRef, Holder};
use crate::vm::boot;
use crate::{cli, config, state, sys};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

enum Approval {
    ChosenByHand { trust_recipe: bool },
    Reported,
}

#[derive(Debug)]
struct ApprovedRecipe {
    bx: BoxRef,
    cfg: config::Config,
    new_pin: Option<resolve::Recipe>,
    pinned_paths: Option<mount::PinnedPaths>,
}

struct GuestWritableFile {
    recipe_or_manifest: PathBuf,
    share: PathBuf,
}

enum RecipeAuthorship {
    WritableShare(GuestWritableFile),
    UnreadablePinnedRecipe,
}

fn find_guest_writable_share_containing(
    bx: &BoxRef,
    from: &Path,
    via_manifest: bool,
) -> Option<RecipeAuthorship> {
    let Ok(previous) = mount::list_pinned_recipes_across_boxes(bx.get_project_dir()) else {
        return Some(RecipeAuthorship::UnreadablePinnedRecipe);
    };
    let manifest = bx.get_project_dir().join(config::MANIFEST_FILE);
    let carriers: &[&Path] = if via_manifest {
        &[from, &manifest]
    } else {
        &[from]
    };
    for file in carriers {
        for (origin, recipe) in &previous {
            match mount::find_writable_mount_containing(file, recipe, origin) {
                Ok(Some(share)) => {
                    return Some(RecipeAuthorship::WritableShare(GuestWritableFile {
                        recipe_or_manifest: (*file).to_path_buf(),
                        share,
                    }));
                }
                Ok(None) => {}
                Err(_) => return Some(RecipeAuthorship::UnreadablePinnedRecipe),
            }
        }
    }
    None
}

fn build_adoption_reason(from: &Path, authorship: &RecipeAuthorship) -> String {
    use std::fmt::Write as _;
    let RecipeAuthorship::WritableShare(file) = authorship else {
        return format!(
            "a box's pinned recipe cannot be read to determine whether a guest could have written {}",
            escape_printable_path(from)
        );
    };
    let mut why = format!(
        "{} lives inside '{}', which a box of this directory shares read-write - \
         a guest may be the author of it",
        escape_printable_path(&file.recipe_or_manifest),
        escape_printable_path(&file.share),
    );
    if file.recipe_or_manifest != from {
        let _ = write!(
            why,
            ", and it is what names {} as this box's recipe",
            escape_printable_path(from)
        );
    }
    why
}

/// What one pinning does about the recipe it would pin
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum PinAction {
    WithoutAsking,
    WarnAndPin,
    Ask,
    ReportOnly,
    RefuseUnasked,
}

/// The one table a pinning's fate is read from: who vouches, whether a guest
/// could have written it, and whether there is anyone to ask.
fn decide_pinning(approval: &Approval, is_suspect: bool, is_at_a_terminal: bool) -> PinAction {
    match (approval, is_suspect, is_at_a_terminal) {
        (Approval::ChosenByHand { .. }, false, _) => PinAction::WithoutAsking,
        (Approval::ChosenByHand { trust_recipe: true }, true, _) => PinAction::WarnAndPin,
        (Approval::Reported, false, _) | (Approval::Reported, true, true) => PinAction::ReportOnly,
        (Approval::ChosenByHand { .. } | Approval::Reported, _, false) => PinAction::RefuseUnasked,
        (Approval::ChosenByHand { .. }, _, true) => PinAction::Ask,
    }
}

fn render_approval_page(lead: &str, warning: Option<&str>, cfg: &config::Config) -> String {
    use std::fmt::Write as _;
    let mut page = format!("{lead}\n");
    if let Some(warning) = warning {
        let _ = writeln!(page, "{warning}");
    }
    let _ = write!(page, "It would grant:\n{}", render_policy_summary(cfg));
    page
}

/// Carry out the settled [`PinAction`]: `Ok(())` means pin it.
fn put_the_question(
    action: PinAction,
    lead: &str,
    warning: Option<&str>,
    cfg: &config::Config,
    box_name: &str,
) -> Result<()> {
    match action {
        PinAction::WithoutAsking => Ok(()),
        PinAction::WarnAndPin => {
            if let Some(warning) = warning {
                eprintln!("terra: {warning} Pinning it anyway (--trust-recipe).");
            }
            Ok(())
        }
        PinAction::ReportOnly => {
            if let Some(warning) = warning {
                eprintln!(
                    "terra: {warning} A real setup would put it to you, and needs \
                     --trust-recipe where there is no terminal to ask on."
                );
            }
            Ok(())
        }
        PinAction::RefuseUnasked => anyhow::bail!(
            "{page}\n\
             There is no terminal to ask on. Review the file, then \
             `terra {box_name} setup --trust-recipe` to pin it.",
            page = render_approval_page(lead, warning, cfg)
        ),
        PinAction::Ask => {
            // stderr: a question on stdout would vanish into `terra setup >
            // log` and read as a hang.
            eprintln!("terra: {}", render_approval_page(lead, warning, cfg));
            anyhow::ensure!(
                confirm("terra: pin it? [y/N] ")?,
                "not pinned - the box is unchanged"
            );
            Ok(())
        }
    }
}

fn confirm(prompt: &str) -> Result<bool> {
    eprint!("{prompt}");
    std::io::Write::flush(&mut std::io::stderr()).context("prompting")?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("reading the answer")?;
    Ok(answer_is_yes(&answer))
}

fn answer_is_yes(answer: &str) -> bool {
    let answer = answer.trim();
    answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes")
}

fn request_recipe_approval(
    target: ResolvedBox,
    approval: &Approval,
    is_at_a_terminal: bool,
) -> Result<ApprovedRecipe> {
    let (mut cfg, paths) = read_config(&target)?;
    let ResolvedBox {
        bx,
        source,
        manifest: _,
    } = target;
    let (source, via_manifest) = match source {
        resolve::Source::Pinned => (None, false),
        resolve::Source::File(r) => (Some(r), false),
        resolve::Source::Manifest(r) => (Some(r), true),
    };
    let previous_paths = mount::load_pinned_paths(&bx)?;
    let has_changed_targets = previous_paths
        .as_ref()
        .is_some_and(|pinned| pinned != &paths);
    let new_pin = source.filter(|recipe| {
        let pinned_text =
            std::fs::read_to_string(bx.get_dir().join(state::RECIPE_FILE)).unwrap_or_default();
        recipe.text != pinned_text
    });
    if new_pin.is_some() || has_changed_targets {
        let guest_writable = new_pin
            .as_ref()
            .and_then(|r| find_guest_writable_share_containing(&bx, &r.from, via_manifest));
        let sensitive_mounts = mount::find_sensitive_mounts(&cfg.mounts);
        let has_readwrite_sensitive = sensitive_mounts.iter().any(|s| !s.mount.readonly);
        let is_suspect = has_changed_targets || guest_writable.is_some() || has_readwrite_sensitive;
        let lead = build_pinning_lead(&bx, new_pin.as_ref());
        let warning = build_pinning_warning(
            new_pin.as_ref(),
            guest_writable.as_ref(),
            &sensitive_mounts,
            has_changed_targets,
        );
        put_the_question(
            decide_pinning(approval, is_suspect, is_at_a_terminal),
            &lead,
            (!warning.is_empty()).then_some(warning.as_str()),
            &cfg,
            bx.get_name(),
        )?;
    }
    let pinned_paths = (previous_paths.as_ref() != Some(&paths)).then_some(paths);
    config::merge_env_file(&mut cfg)?;
    crate::vm::encode_boot_plan(
        &boot::BootSpec {
            cfg: cfg.clone(),
            project_dir: bx.get_project_dir().to_path_buf(),
            root: false,
            mode: terra_protocol::PlanMode::Run,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        },
        bx.get_name(),
    )?;
    Ok(ApprovedRecipe {
        bx,
        cfg,
        new_pin,
        pinned_paths,
    })
}

/// Load the pinned recipe and verify its approved host paths.
pub fn load_pinned_config(target: ResolvedBox) -> Result<(BoxRef, config::Config)> {
    let (mut cfg, paths) = read_config(&target)?;
    mount::verify_pinned_paths(&target.bx, &paths)?;
    config::merge_env_file(&mut cfg)?;
    Ok((target.bx, cfg))
}

fn read_config(target: &ResolvedBox) -> Result<(config::Config, mount::PinnedPaths)> {
    target.bx.ensure_sockets_fit()?;
    sys::validate_host_root()?;
    let mut cfg = target.parse_recipe_without_env_file()?;
    cfg.mounts = mount::resolve_mounts(&cfg, &target.bx)?;
    validate_storage_devices(&cfg)?;
    config::resolve_env_file(&mut cfg)?;
    let paths = mount::PinnedPaths::from_config(&cfg);
    Ok((cfg, paths))
}

fn build_pinning_lead(bx: &BoxRef, recipe: Option<&resolve::Recipe>) -> String {
    match recipe {
        Some(recipe) => format!("pinning {} to {bx}", escape_printable_path(&recipe.from)),
        None => format!("updating pinned paths for {bx}"),
    }
}

fn build_pinning_warning(
    recipe: Option<&resolve::Recipe>,
    guest_writable: Option<&RecipeAuthorship>,
    sensitive_mounts: &[mount::SensitiveMount<'_>],
    has_changed_targets: bool,
) -> String {
    let mut warnings = Vec::new();
    if has_changed_targets {
        warnings.push(
            "WARNING: a share or env_file target changed since it was pinned; review the new host paths before approving.".to_string(),
        );
    }
    if let (Some(recipe), Some(authorship)) = (recipe, guest_writable) {
        warnings.push(format!(
            "WARNING: {}.",
            build_adoption_reason(&recipe.from, authorship)
        ));
    }
    for sensitive in sensitive_mounts {
        let access = if sensitive.mount.readonly {
            "read-only"
        } else {
            "read-write"
        };
        warnings.push(format!(
            "WARNING: mount '{}' shares sensitive host {} ({access}) with the sandbox.",
            escape_printable_path(&sensitive.mount.host),
            sensitive.category
        ));
    }
    warnings.join("\n")
}

fn validate_storage_devices(cfg: &config::Config) -> Result<()> {
    let count = cfg
        .mounts
        .len()
        .checked_add(cfg.volumes.len())
        .ok_or_else(|| anyhow::anyhow!("too many volumes and host-directory mounts"))?;
    anyhow::ensure!(
        count <= crate::vm::MAX_GUEST_STORAGE_DEVICES,
        "a box supports at most {} combined volumes and host-directory mounts; remove a volume or mount",
        crate::vm::MAX_GUEST_STORAGE_DEVICES
    );
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum Rebuild {
    Yes,
    No,
}

/// Take the box lock and undo what a run that died part-way left behind.
fn lock_and_repair_box(bx: &BoxRef) -> Result<File> {
    // Locked before anything on disk moves - a setup racing a finished `rm`
    // would otherwise resurrect the state directory after rm reported it gone.
    let lock = bx.lock_run()?;
    crate::cmd::storage::recover_import(bx)?;
    // Under the lock anything staged here predates this run - a setup or boot
    // that died part-way through an install.
    crate::vm::image::sweep_staging_temps(bx.get_dir(), |_| false);
    Ok(lock)
}

/// Take the box lock for a boot, refusing a box whose setup did not finish.
pub fn lock_finished_box(bx: &BoxRef) -> Result<File> {
    let lock = lock_and_repair_box(bx)?;
    ensure_project_dir_exists(bx)?;
    anyhow::ensure!(
        bx.is_set_up(),
        "{bx} is not set up for its recipe - `terra {} setup` finishes it",
        bx.get_name()
    );
    Ok(lock)
}

fn would_install_or_grow(path: &Path, size_mib: u32) -> bool {
    std::fs::metadata(path).map_or(true, |image| image.len() < u64::from(size_mib) << 20)
}

fn prepare_box(approved: &ApprovedRecipe, rebuild: Rebuild) -> Result<File> {
    let ApprovedRecipe {
        bx,
        cfg,
        new_pin,
        pinned_paths,
    } = approved;
    let lock = lock_and_repair_box(bx)?;
    prepare_box_state_dir(bx)?;
    // see a_new_pin_is_not_bootable_until_its_setup_vm_succeeds
    if new_pin.is_some() || !bx.is_set_up() {
        bx.remove_setup_stamp()?;
    }
    let recipe_path = bx.get_dir().join(state::RECIPE_FILE);
    if let Some(r) = new_pin {
        if recipe_path.exists() {
            eprintln!(
                "terra: recipe updated from {} (the box keeps its filesystem; \
                 `terra {} setup --rebuild` rebuilds it)",
                escape_printable_path(&r.from),
                bx.get_name()
            );
        }
        crate::vm::image::staged_write(&recipe_path, |out| {
            out.write_all(r.text.as_bytes())
                .with_context(|| format!("recording {}", recipe_path.display()))
        })?;
    }
    if let Some(paths) = pinned_paths {
        let path = bx.get_dir().join(state::PINNED_PATHS_FILE);
        crate::vm::image::staged_write(&path, |out| {
            yaml_serde::to_writer(&mut *out, paths).context("serializing pinned paths")
        })?;
    }
    let img = bx.get_dir().join(state::ROOTFS_FILE);
    if matches!(rebuild, Rebuild::Yes) && img.exists() {
        eprintln!("terra: --rebuild: rebuilding {bx} from scratch");
        std::fs::remove_file(&img)
            .with_context(|| format!("removing {} for rebuild", img.display()))?;
    }
    if !img.exists() {
        eprintln!("terra: creating {bx} ({} MiB)", cfg.hw.rootfs_mib);
    }
    if would_install_or_grow(&img, cfg.hw.rootfs_mib) {
        bx.remove_setup_stamp()?;
    }
    crate::vm::image::install_or_grow_rootfs_image(&img, cfg.hw.rootfs_mib)
        .with_context(|| format!("preparing {}", img.display()))?;
    for volume in &cfg.volumes {
        if volume.lifetime == config::VolumeLifetime::Box {
            let path = bx.get_volume_image_path(&volume.name);
            crate::vm::image::install_or_grow_volume_image(&path, volume.size_mib)
                .with_context(|| format!("preparing volume image {}", path.display()))?;
        }
    }
    let configured: Vec<String> = cfg.volumes.iter().map(|v| v.name.clone()).collect();
    sweep_or_keep_unused_volumes(bx, &configured, rebuild)?;
    Ok(lock)
}

fn sweep_or_keep_unused_volumes(
    bx: &BoxRef,
    configured: &[String],
    rebuild: Rebuild,
) -> Result<()> {
    for img in bx.list_unused_volume_images(configured)? {
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

fn refuse_a_case_variant_of_an_existing_box(bx: &BoxRef) -> Result<()> {
    let clash = state::list_existing_names(bx.get_project_dir())?
        .into_iter()
        .find(|existing| existing != bx.get_name() && existing.eq_ignore_ascii_case(bx.get_name()));
    if let Some(existing) = clash {
        anyhow::bail!(
            "{} already has a box called '{existing}', which differs from '{}' only by \
             case - a case-insensitive filesystem (APFS, NTFS) gives the two one \
             directory, so they would share a lock, a recipe and a root filesystem \
             (name this one something else, or `terra {existing}` for the box that is \
             already there)",
            bx.get_project_dir().display(),
            bx.get_name(),
        );
    }
    Ok(())
}

/// Refused rather than created: a typo'd `--project` would silently mint a
/// directory and a box for it.
fn ensure_project_dir_exists(bx: &BoxRef) -> Result<()> {
    anyhow::ensure!(
        bx.get_project_dir().is_dir(),
        "{} is not a directory, so it can have no box (--project names the \
         directory a box belongs to - check the spelling, or create it first)",
        bx.get_project_dir().display()
    );
    Ok(())
}

fn prepare_box_state_dir(bx: &BoxRef) -> Result<()> {
    ensure_project_dir_exists(bx)?;
    refuse_a_case_variant_of_an_existing_box(bx)?;
    // Box state inherits the box directory's protection, which
    // [`state::ensure_box_home`] enforces.
    state::ensure_box_home()?;
    std::fs::create_dir_all(bx.get_dir())
        .with_context(|| format!("creating box state {}", bx.get_dir().display()))?;
    sys::set_owner_only(bx.get_dir(), true)
        .with_context(|| format!("securing box state {}", bx.get_dir().display()))?;
    bx.write_origin()?;
    Ok(())
}

/// `terra [BOX] setup` - pin a recipe, build the filesystem, run `on_create`.
pub async fn run(
    args: &cli::SetupArgs,
    name: Option<&str>,
    project_dir: &Path,
    cwd: &Path,
    is_at_a_terminal: bool,
) -> Result<ExitCode> {
    let target = resolve::resolve_for_setup(name, project_dir, cwd)?;

    match target.bx.get_holder()? {
        Holder::Free => {}
        Holder::SettingUp => return Err(target.bx.setup_holds_it()),
        Holder::Running => anyhow::bail!(
            "{} is running - `terra {} stop` before setting it up again \
             (its recipe is pinned for as long as the VM holds it)",
            target.bx,
            target.bx.get_name()
        ),
    }

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
             and nothing was changed",
            approved.bx
        );
        return Ok(ExitCode::SUCCESS);
    }
    let rebuild = if args.rebuild {
        Rebuild::Yes
    } else {
        Rebuild::No
    };
    let lock = prepare_box(&approved, rebuild)?;
    let ApprovedRecipe { bx, cfg, .. } = approved;

    if !bx.is_set_up() {
        boot::run_setup_vm(&cfg, &bx, &lock).await?;
    }
    eprintln!("terra: {bx} is ready - `terra {}` boots it", bx.get_name());
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_boot_plans_are_refused_after_dotenv_merge_before_preparation() {
        let _home = crate::sys::TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        for dotenv in [false, true] {
            let bx = BoxRef::resolve(dir.path(), if dotenv { "merged" } else { "recipe" }).unwrap();
            let recipe = if dotenv {
                let value = "x".repeat(600 << 10);
                std::fs::write(dir.path().join("large.env"), format!("EXTRA={value}")).unwrap();
                format!("env:\n  RECIPE: {value}\nenv_file: large.env\n")
            } else {
                format!(
                    "env:\n  RECIPE: {}\n",
                    "x".repeat(terra_protocol::MAX_PLAN_BYTES)
                )
            };
            assert!((recipe.len() as u64) < config::MAX_RECIPE_BYTES);
            let target = ResolvedBox {
                bx: bx.clone(),
                source: resolve::Source::File(resolve::Recipe {
                    from: dir.path().join("large.yaml"),
                    text: recipe,
                }),
                manifest: None,
            };
            let error = request_recipe_approval(
                target,
                &Approval::ChosenByHand { trust_recipe: true },
                false,
            )
            .unwrap_err();
            assert!(error.to_string().contains("boot plan"), "{error:#}");
            assert!(!bx.get_dir().exists());
        }
    }

    #[test]
    fn another_projects_relative_share_makes_recipe_and_manifest_suspect() {
        let _home = crate::sys::TestHome::new();
        let root = tempfile::tempdir().unwrap();
        let origin = root.path().join("origin");
        let target = root.path().join("target");
        std::fs::create_dir_all(&origin).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        let writer = BoxRef::resolve(&origin, "writer").unwrap();
        std::fs::create_dir_all(writer.get_dir()).unwrap();
        writer.write_origin().unwrap();
        std::fs::write(
            writer.get_dir().join(state::RECIPE_FILE),
            "mounts:\n  - host: ../target\n    guest: /work\n",
        )
        .unwrap();
        let bx = BoxRef::resolve(&target, "dev").unwrap();
        assert!(matches!(
            find_guest_writable_share_containing(&bx, &target.join("evil.yaml"), false),
            Some(RecipeAuthorship::WritableShare(_))
        ));
        assert!(matches!(
            find_guest_writable_share_containing(&bx, &root.path().join("outside.yaml"), true),
            Some(RecipeAuthorship::WritableShare(_))
        ));
        assert!(
            find_guest_writable_share_containing(&bx, &root.path().join("outside.yaml"), false)
                .is_none()
        );
        std::fs::write(writer.get_dir().join(state::RECIPE_FILE), [0xff]).unwrap();
        assert!(matches!(
            find_guest_writable_share_containing(&bx, &target.join("evil.yaml"), false),
            Some(RecipeAuthorship::UnreadablePinnedRecipe)
        ));
    }

    #[test]
    fn combined_volumes_and_mounts_fit_the_vmm() {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(crate::vm::MAX_GUEST_STORAGE_DEVICES, 32);
        let cfg = config::Config {
            mounts: (0..crate::vm::MAX_GUEST_STORAGE_DEVICES)
                .map(|index| config::Mount {
                    host: format!("/host/{index}").into(),
                    guest: format!("/guest/{index}").into(),
                    readonly: false,
                })
                .collect(),
            ..config::Config::default()
        };
        assert!(validate_storage_devices(&cfg).is_ok());

        let mut over = cfg;
        over.volumes.push(config::Volume {
            name: "over".into(),
            guest: Some("/data".into()),
            rootfs_overlay: false,
            size_mib: 1,
            lifetime: config::VolumeLifetime::Box,
        });
        let err = validate_storage_devices(&over).unwrap_err().to_string();
        assert!(
            err.contains("combined volumes and host-directory mounts"),
            "{err}"
        );
        assert!(
            err.contains(&crate::vm::MAX_GUEST_STORAGE_DEVICES.to_string()),
            "{err}"
        );
    }

    /// Re-pinning an *already pinned* box still consults every sibling's
    /// shares: a guest in box `b`, which shares the project read-write, can
    /// write a new recipe file for box `a` - so pinning it must be treated as
    /// suspect. Off a terminal that refuses, naming `--trust-recipe`; the flag
    /// pins it with a warning. (The gap this pins: `a`'s own pin has no
    /// mounts, so checking only it answered "nobody could have written this".)
    #[test]
    fn a_sibling_share_makes_a_repin_suspect_too() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let _home = crate::sys::TestHome::new();
        let a = BoxRef::resolve(&project, "a").unwrap();
        let b = BoxRef::resolve(&project, "b").unwrap();
        std::fs::create_dir_all(a.get_dir()).unwrap();
        std::fs::create_dir_all(b.get_dir()).unwrap();
        std::fs::write(a.get_dir().join(state::RECIPE_FILE), "hw:\n  cpus: 1\n").unwrap();
        std::fs::write(
            b.get_dir().join(state::RECIPE_FILE),
            format!(
                "mounts:\n  - host: {}\n    guest: /work\n",
                project.display()
            ),
        )
        .unwrap();

        let smuggled = project.join("a-new.yaml");
        std::fs::write(&smuggled, "hw:\n  cpus: 2\n").unwrap();
        let target = || ResolvedBox {
            bx: a.clone(),
            source: resolve::Source::File(resolve::Recipe {
                from: smuggled.clone(),
                text: "hw:\n  cpus: 2\n".to_string(),
            }),
            manifest: None,
        };

        std::fs::write(project.join("unreadable.env"), [0xff]).unwrap();
        let mut refused = target();
        if let resolve::Source::File(recipe) = &mut refused.source {
            recipe.text.push_str("env_file: unreadable.env\n");
        }
        let err = request_recipe_approval(
            refused,
            &Approval::ChosenByHand {
                trust_recipe: false,
            },
            false,
        )
        .expect_err("a sibling's writable share should have made this pin suspect")
        .to_string();
        assert!(err.contains("may be the author"), "{err}");
        assert!(err.contains("--trust-recipe"), "{err}");

        // The flag pins it anyway - with the warning, but without a question,
        // so it never reaches the prompt whether there is a terminal or not.
        for is_at_a_terminal in [false, true] {
            let approved = request_recipe_approval(
                target(),
                &Approval::ChosenByHand { trust_recipe: true },
                is_at_a_terminal,
            )
            .expect("--trust-recipe should pin without asking");
            assert!(approved.new_pin.is_some(), "the recipe should be adopted");
        }
    }

    #[test]
    fn readwrite_sensitive_mounts_are_suspect_and_warn_on_pinning() {
        let home = crate::sys::TestHome::new();
        let ssh_dir = home.get_path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        let bx = BoxRef::resolve(&project, "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();

        let recipe_path = project.join("recipe.yaml");
        let recipe_text = format!(
            "mounts:\n  - host: {}\n    guest: /ssh\n    readonly: false\n",
            ssh_dir.display()
        );
        std::fs::write(&recipe_path, &recipe_text).unwrap();

        let target = || ResolvedBox {
            bx: bx.clone(),
            source: resolve::Source::File(resolve::Recipe {
                from: recipe_path.clone(),
                text: recipe_text.clone(),
            }),
            manifest: None,
        };

        let err = request_recipe_approval(
            target(),
            &Approval::ChosenByHand {
                trust_recipe: false,
            },
            false,
        )
        .expect_err("read-write sensitive mount must be suspect")
        .to_string();

        assert!(err.contains("shares sensitive host SSH keys"), "{err}");
        assert!(err.contains("(read-write)"), "{err}");
        assert!(err.contains("--trust-recipe"), "{err}");

        let approved = request_recipe_approval(
            target(),
            &Approval::ChosenByHand { trust_recipe: true },
            false,
        )
        .expect("--trust-recipe should pin with sensitive mount");
        assert!(approved.new_pin.is_some());
    }

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
            let recipe = || resolve::Recipe {
                from: project.join("dev.yaml"),
                text: recipe_text.clone(),
            };
            let target = |source| ResolvedBox {
                bx: bx.clone(),
                source,
                manifest: None,
            };
            let approved = request_recipe_approval(
                target(resolve::Source::File(recipe())),
                &Approval::ChosenByHand {
                    trust_recipe: false,
                },
                true,
            )
            .unwrap();
            prepare_box(&approved, Rebuild::No).unwrap();

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
                let error = load_pinned_config(target(source))
                    .expect_err("a changed target must not boot")
                    .to_string();
                assert!(error.contains("moved since it was pinned"), "{error}");
            }

            for source in [
                resolve::Source::Pinned,
                resolve::Source::File(recipe()),
                resolve::Source::Manifest(recipe()),
                resolve::Source::File(resolve::Recipe {
                    text: format!("{recipe_text}# edited recipe\n"),
                    ..recipe()
                }),
            ] {
                let error = request_recipe_approval(
                    target(source),
                    &Approval::ChosenByHand {
                        trust_recipe: false,
                    },
                    false,
                )
                .expect_err("changed targets require explicit trust")
                .to_string();
                assert!(
                    error.contains("target changed since it was pinned"),
                    "{error}"
                );
                assert!(error.contains("--trust-recipe"), "{error}");
            }

            let refreshed = request_recipe_approval(
                target(resolve::Source::Pinned),
                &Approval::ChosenByHand { trust_recipe: true },
                true,
            )
            .expect("explicit trust refreshes pinned targets");
            prepare_box(&refreshed, Rebuild::No).unwrap();
            load_pinned_config(target(resolve::Source::Pinned)).expect("the refreshed pin boots");
        }
    }

    /// Two names differing only by case are one directory on a case-insensitive
    /// filesystem, where the second box silently shares the first's lock,
    /// pinned recipe and root filesystem - two boxes on one ext4, and a `terra
    /// dev stop` that stops `DEV`. The refusal is here rather than in
    /// [`crate::name::validate_box_name`] because it is about the siblings a
    /// name lands beside, not about the name itself.
    ///
    /// It fires on Linux too, where the two really are separate directories:
    /// one rule everywhere means a project that sets up on one machine sets up
    /// on the next, and the name is refused rather than folded to lower case,
    /// because a box nobody named is not terra's to invent.
    #[test]
    fn a_name_an_existing_box_holds_in_another_case_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let dev = BoxRef::resolve(dir.path(), "dev").unwrap();
        prepare_box_state_dir(&dev).unwrap();

        let shouting = BoxRef::resolve(dir.path(), "DEV").unwrap();
        let err = prepare_box_state_dir(&shouting)
            .expect_err("a case variant of an existing box must not be set up beside it")
            .to_string();
        assert!(err.contains("only by case"), "{err}");
        assert!(
            err.contains("terra dev"),
            "the box that is already there: {err}"
        );

        // The box itself is not its own clash, so setting it up again is fine…
        prepare_box_state_dir(&dev).unwrap();
        // …and a name that is nobody's variant is untouched.
        prepare_box_state_dir(&BoxRef::resolve(dir.path(), "ci").unwrap()).unwrap();
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
        let configured = vec!["data".to_string()];

        sweep_or_keep_unused_volumes(&bx, &configured, Rebuild::No).unwrap();
        assert!(
            bx.get_volume_image_path("old").exists(),
            "a plain pin or boot deleted a volume's data"
        );
        assert!(bx.get_volume_image_path("data").exists());

        sweep_or_keep_unused_volumes(&bx, &configured, Rebuild::Yes).unwrap();
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
            let cfg = yaml_serde::from_str::<crate::config::Config>(&format!(
                "volumes:\n  - {{name: kept, guest: /kept, size_mib: {size_mib}}}\n  - {{name: scratch, guest: /scratch, size_mib: 8, lifetime: boot}}\n"
            ))
            .unwrap();
            let approved = ApprovedRecipe {
                bx: bx.clone(),
                cfg,
                new_pin: None,
                pinned_paths: None,
            };
            drop(prepare_box(&approved, Rebuild::No).unwrap());
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

    /// The setup VM grows the root filesystem, so installing or growing its
    /// image invalidates setup even when the recipe's stamp matches. Volumes
    /// grow on run boots and do not require another setup VM.
    #[test]
    fn only_root_image_installation_or_growth_invalidates_setup() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        let stamp = bx.get_dir().join(state::SETUP_STAMP);
        let prepare = |recipe: &str| {
            std::fs::write(bx.get_dir().join(state::RECIPE_FILE), recipe).unwrap();
            bx.write_setup_stamp().unwrap();
            let approved = ApprovedRecipe {
                bx: bx.clone(),
                cfg: yaml_serde::from_str::<crate::config::Config>(recipe).unwrap(),
                new_pin: None,
                pinned_paths: None,
            };
            drop(prepare_box(&approved, Rebuild::No).unwrap());
            stamp.exists()
        };
        let volume = |size_mib| {
            format!(
                "hw: {{rootfs_mib: 1024}}\nvolumes: [{{name: v, guest: /v, size_mib: {size_mib}}}]\n"
            )
        };
        assert!(
            !prepare("hw: {rootfs_mib: 512}\n"),
            "a fresh root image kept the stamp"
        );
        assert!(
            prepare("hw: {rootfs_mib: 512}\n"),
            "an unchanged image lost the stamp"
        );
        assert!(
            !prepare("hw: {rootfs_mib: 1024}\n"),
            "a grown root image kept the stamp"
        );
        assert!(prepare(&volume(8)), "a fresh volume invalidated setup");
        assert!(prepare(&volume(16)), "a grown volume invalidated setup");
        assert!(prepare(&volume(16)), "unchanged images lost the stamp");
    }

    /// A stamp belongs to the rootfs it proves: `--rebuild` makes a new
    /// filesystem, so the old setup's proof must go with it - or a rebuild
    /// would inherit a setup that never ran on it.
    #[test]
    fn rebuild_takes_the_setup_stamp_with_the_rootfs() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::ROOTFS_FILE), b"old").unwrap();
        std::fs::write(bx.get_dir().join(state::RECIPE_FILE), "{}").unwrap();
        bx.write_setup_stamp().unwrap();

        let approved = ApprovedRecipe {
            bx: bx.clone(),
            cfg: yaml_serde::from_str::<crate::config::Config>("{}").unwrap(),
            new_pin: None,
            pinned_paths: None,
        };
        prepare_box(&approved, Rebuild::Yes).unwrap();

        assert!(
            bx.get_dir().join(state::ROOTFS_FILE).exists(),
            "--rebuild left no rootfs behind"
        );
        assert!(
            !bx.get_dir().join(state::SETUP_STAMP).exists(),
            "the rebuilt box kept the old rootfs's setup stamp"
        );
    }

    /// The stamp proves setup's VM ran for the pinned recipe. Pinning a new
    /// one drops it before the pin changes, so a re-setup that fails - or dies
    /// before its VM finishes - leaves the box unbootable rather than booting
    /// the new recipe against a root prepared for the old one. Re-pinning
    /// nothing keeps it: the image still fits the recipe it was set up for.
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
        for (new_pin, is_stamp_kept) in [
            (None, true),
            (
                Some(resolve::Recipe {
                    from: dir.path().join("dev.yaml"),
                    text: "hw: {cpus: 1}\n".into(),
                }),
                false,
            ),
        ] {
            bx.write_setup_stamp().unwrap();
            let approved = ApprovedRecipe {
                bx: bx.clone(),
                cfg: yaml_serde::from_str::<crate::config::Config>("{}").unwrap(),
                new_pin,
                pinned_paths: None,
            };
            drop(prepare_box(&approved, Rebuild::No).unwrap());
            assert_eq!(stamp.exists(), is_stamp_kept);
            assert_eq!(bx.is_set_up(), is_stamp_kept);
        }
    }

    /// In-place edits need setup even when no image is installed or grown.
    /// Boot refuses the old stamp, and setup drops it before running its VM.
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
            assert!(lock_finished_box(&bx).is_err(), "{recipe}");

            let approved = ApprovedRecipe {
                bx: bx.clone(),
                cfg: yaml_serde::from_str::<crate::config::Config>(recipe).unwrap(),
                new_pin: None,
                pinned_paths: None,
            };
            drop(prepare_box(&approved, Rebuild::No).unwrap());
            assert!(!bx.get_dir().join(state::SETUP_STAMP).exists(), "{recipe}");
            assert_eq!(std::fs::metadata(&rootfs).unwrap().len(), 512 << 20);
            bx.write_setup_stamp().unwrap();
            assert!(bx.is_set_up(), "{recipe}");
            drop(lock_finished_box(&bx).unwrap());
        }
    }

    /// A box boots only once setup finished for its pinned recipe. Missing,
    /// legacy empty, and mismatched stamps all need a setup VM to succeed.
    #[test]
    fn a_box_whose_setup_did_not_finish_is_not_locked_for_a_boot() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::RECIPE_FILE), "{}").unwrap();
        let rootfs = bx.get_dir().join(state::ROOTFS_FILE);
        let stamp = bx.get_dir().join(state::SETUP_STAMP);
        let refusal = || {
            lock_finished_box(&bx)
                .expect_err("an unfinished setup must not boot")
                .to_string()
        };

        assert!(refusal().contains("terra dev setup"));
        std::fs::write(&stamp, b"").unwrap();
        assert!(
            refusal().contains("terra dev setup"),
            "stamp without a root image"
        );
        std::fs::remove_file(&stamp).unwrap();
        std::fs::write(&rootfs, b"").unwrap();
        assert!(
            refusal().contains("terra dev setup"),
            "root image without a stamp"
        );
        std::fs::write(&stamp, b"").unwrap();
        assert!(refusal().contains("terra dev setup"), "legacy empty stamp");
        bx.write_setup_stamp().unwrap();
        lock_finished_box(&bx).unwrap();
    }

    /// A set-up box whose project directory is gone is listed as `gone`, so
    /// booting it is refused the way a box for a typo'd directory is.
    #[test]
    fn a_set_up_box_whose_project_directory_is_gone_is_not_locked_for_a_boot() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let project = dir.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let bx = BoxRef::resolve(&project, "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::ROOTFS_FILE), b"").unwrap();
        std::fs::write(bx.get_dir().join(state::RECIPE_FILE), "{}").unwrap();
        bx.write_setup_stamp().unwrap();
        std::fs::remove_dir(&project).unwrap();

        let refusal = lock_finished_box(&bx)
            .expect_err("a box without its project directory must not boot")
            .to_string();

        assert!(
            refusal.contains(&project.display().to_string()),
            "{refusal}"
        );
    }

    /// The whole of what a pinning does about the person, off the three things
    /// that decide it. One row differs from its neighbours by nothing a call
    /// site could see - `--trust-recipe` on a recipe nobody suspects pins in
    /// silence rather than warning - so the table is pinned here rather than
    /// reconstructed from the routes that reach it.
    #[test]
    fn what_a_pinning_asks_is_decided_by_who_vouches_for_it() {
        let by_hand = |trust_recipe| Approval::ChosenByHand { trust_recipe };

        // A person named the recipe and nothing suspects it: pinned in silence,
        // terminal or not, `--trust-recipe` or not.
        for trust_recipe in [false, true] {
            for is_at_a_terminal in [false, true] {
                assert_eq!(
                    decide_pinning(&by_hand(trust_recipe), false, is_at_a_terminal),
                    PinAction::WithoutAsking,
                    "trust_recipe={trust_recipe} is_at_a_terminal={is_at_a_terminal}"
                );
            }
        }

        // A suspect one is put to them, and refused where
        // there is nobody to ask - `--trust-recipe` answers it either way.
        assert_eq!(decide_pinning(&by_hand(false), true, true), PinAction::Ask);
        assert_eq!(
            decide_pinning(&by_hand(false), true, false),
            PinAction::RefuseUnasked
        );
        for is_at_a_terminal in [false, true] {
            assert_eq!(
                decide_pinning(&by_hand(true), true, is_at_a_terminal),
                PinAction::WarnAndPin,
                "is_at_a_terminal={is_at_a_terminal}"
            );
        }

        // A dry run pins nothing, so it never asks - but it refuses exactly
        // where the setup it stands for would, which is the whole of its
        // promise: a suspect recipe with nobody to ask is a `terra setup` that
        // fails, and a dry run reporting that one clean would be a lie.
        for is_at_a_terminal in [false, true] {
            assert_eq!(
                decide_pinning(&Approval::Reported, false, is_at_a_terminal),
                PinAction::ReportOnly,
                "is_at_a_terminal={is_at_a_terminal}"
            );
        }
        assert_eq!(
            decide_pinning(&Approval::Reported, true, true),
            PinAction::ReportOnly
        );
        assert_eq!(
            decide_pinning(&Approval::Reported, true, false),
            PinAction::RefuseUnasked
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

    /// What a typed answer means, on the one question that decides whether
    /// bytes a sandbox may have written become the box's pinned recipe.
    ///
    /// Anything that is not a yes is a no - an answer this cannot read must
    /// never be the one that pins.
    #[test]
    fn only_a_yes_pins_and_a_bare_enter_refuses() {
        for yes in ["y", "Y", "yes", "Yes", "YES", " y \n", "yes\r\n"] {
            assert!(answer_is_yes(yes), "{yes:?} is a yes");
        }
        // `yep` and `ok` included, because a recipe is pinned on a yes, not on
        // a not-quite-no.
        for no in [
            "", "\n", "  \n", "\r\n", "n", "N", "no", "No", "yep", "ok", "sure", "y es", "1",
        ] {
            assert!(!answer_is_yes(no), "{no:?} is not a yes");
        }
    }
}
