//! `terra setup` - read a recipe, pin it to a box, and build the guest
//! filesystem. A boot runs only what a pin through here accepted, so a guest
//! with a writable share never chooses what a later boot mounts or reaches.

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

/// The route by which a pin is vouched for: who answers the question, or that
/// nobody is asked.
pub enum Approval {
    ChosenByHand { trust_recipe: bool },
    Offer,
    Reported,
}

/// A recipe approved for one box: every refusal has run, so [`prepare_box`] is
/// disk work only.
#[derive(Debug)]
pub struct ApprovedRecipe {
    pub bx: BoxRef,
    pub cfg: config::Config,
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
    Ask { default_yes: bool },
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
        (Approval::ChosenByHand { .. } | Approval::Offer | Approval::Reported, _, false) => {
            PinAction::RefuseUnasked
        }
        (Approval::ChosenByHand { .. } | Approval::Offer, _, true) => PinAction::Ask {
            default_yes: !is_suspect,
        },
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
        PinAction::Ask { default_yes } => {
            // stderr: a question on stdout would vanish into `terra setup >
            // log` and read as a hang.
            eprintln!("terra: {}", render_approval_page(lead, warning, cfg));
            anyhow::ensure!(
                confirm(
                    if default_yes {
                        "terra: pin it? [Y/n] "
                    } else {
                        "terra: pin it? [y/N] "
                    },
                    default_yes,
                )?,
                "not pinned - the box is unchanged"
            );
            Ok(())
        }
    }
}

fn confirm(prompt: &str, default_yes: bool) -> Result<bool> {
    eprint!("{prompt}");
    std::io::Write::flush(&mut std::io::stderr()).context("prompting")?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("reading the answer")?;
    Ok(answer_is_yes(&answer, default_yes))
}

fn answer_is_yes(answer: &str, default_yes: bool) -> bool {
    match answer.trim() {
        "" => default_yes,
        a => a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes"),
    }
}

/// `refresh_pinned_paths` lets an explicit setup replace a pin's path targets.
pub fn request_recipe_approval(
    target: ResolvedBox,
    approval: &Approval,
    is_at_a_terminal: bool,
    refresh_pinned_paths: bool,
) -> Result<ApprovedRecipe> {
    target.bx.ensure_sockets_fit()?;
    sys::validate_host_root()?;
    let mut cfg = target.parse_recipe_without_env_file()?;
    let ResolvedBox {
        bx,
        source,
        manifest_divergence: _,
    } = target;
    let (source, via_manifest) = match source {
        resolve::Source::Pinned => (None, false),
        resolve::Source::File(r) => (Some(r), false),
        resolve::Source::Manifest(r) => (Some(r), true),
    };
    cfg.mounts = mount::resolve_mounts(&cfg, &bx)?;
    validate_storage_devices(&cfg)?;

    let mut new_pin = None;
    if let Some(r) = source {
        let pinned_text =
            std::fs::read_to_string(bx.get_dir().join(state::RECIPE_FILE)).unwrap_or_default();
        if r.text != pinned_text {
            let guest_writable = find_guest_writable_share_containing(&bx, &r.from, via_manifest);
            let sensitive_mounts = mount::find_sensitive_mounts(&cfg.mounts);
            let has_readwrite_sensitive = sensitive_mounts.iter().any(|s| !s.mount.readonly);
            let is_suspect = guest_writable.is_some() || has_readwrite_sensitive;
            let lead = match approval {
                // A dry run's refusal reads as the real setup's would.
                Approval::ChosenByHand { .. } | Approval::Reported => {
                    format!("pinning {} to {bx}", escape_printable_path(&r.from))
                }
                Approval::Offer => format!(
                    "no box '{}' in {} yet - {} would build it",
                    bx.get_name(),
                    bx.get_project_dir().display(),
                    escape_printable_path(&r.from)
                ),
            };
            let mut warnings = Vec::new();
            if let Some(authorship) = &guest_writable {
                warnings.push(format!(
                    "WARNING: {}.",
                    build_adoption_reason(&r.from, authorship)
                ));
            }
            for s in &sensitive_mounts {
                let access = if s.mount.readonly {
                    "read-only"
                } else {
                    "read-write"
                };
                warnings.push(format!(
                    "WARNING: mount '{}' shares sensitive host {} ({access}) with the sandbox.",
                    escape_printable_path(&s.mount.host),
                    s.category
                ));
            }
            let warning = (!warnings.is_empty()).then(|| warnings.join("\n"));
            put_the_question(
                decide_pinning(approval, is_suspect, is_at_a_terminal),
                &lead,
                warning.as_deref(),
                &cfg,
                bx.get_name(),
            )?;
            new_pin = Some(r);
        }
    }
    config::resolve_env_file(&mut cfg)?;
    let paths = mount::PinnedPaths::from_config(&cfg);
    let pinned_paths = if mount::load_pinned_paths(&bx)?.as_ref() == Some(&paths) {
        None
    } else if refresh_pinned_paths || new_pin.is_some() {
        Some(paths)
    } else {
        mount::verify_pinned_paths(&bx, &paths)?;
        None
    };
    config::merge_env_file(&mut cfg)?;
    Ok(ApprovedRecipe {
        bx,
        cfg,
        new_pin,
        pinned_paths,
    })
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

pub struct PreparedBox {
    pub lock: File,
    pub fresh_rootfs: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum Rebuild {
    Yes,
    No,
}

pub fn prepare_box(approved: &ApprovedRecipe, rebuild: Rebuild) -> Result<PreparedBox> {
    let ApprovedRecipe {
        bx,
        cfg,
        new_pin,
        pinned_paths,
    } = approved;
    // Locked before anything on disk moves - a setup racing a finished `rm`
    // would otherwise resurrect the state directory after rm reported it gone.
    let lock = bx.lock_run()?;
    crate::cmd::storage::recover_import(bx)?;
    prepare_box_state_dir(bx)?;
    // Under the lock anything staged here predates this run - a setup or boot
    // that died part-way through an install.
    crate::vm::image::sweep_staging_temps(bx.get_dir(), |_| false);
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
        let _ = std::fs::remove_file(bx.get_dir().join(state::BAKE_STAMP));
    }
    let fresh = !img.exists();
    if fresh {
        eprintln!("terra: creating {bx} ({} MiB)", cfg.hw.rootfs_mib);
    }
    crate::vm::image::ensure_rootfs_image(&img, cfg.hw.rootfs_mib)
        .with_context(|| format!("preparing {}", img.display()))?;
    let configured: Vec<String> = cfg.volumes.iter().map(|v| v.name.clone()).collect();
    sweep_or_keep_unused_volumes(bx, &configured, rebuild)?;
    Ok(PreparedBox {
        lock,
        fresh_rootfs: fresh,
    })
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

fn prepare_box_state_dir(bx: &BoxRef) -> Result<()> {
    // Refused rather than created: a typo'd `--project` would silently mint a
    // directory and a box for it.
    anyhow::ensure!(
        bx.get_project_dir().is_dir(),
        "{} is not a directory, so it can have no box (--project names the \
         directory a box belongs to - check the spelling, or create it first)",
        bx.get_project_dir().display()
    );
    refuse_a_case_variant_of_an_existing_box(bx)?;
    // Box state inherits the box directory's protection, which
    // [`state::ensure_box_home`] enforces.
    state::ensure_box_home()?;
    std::fs::create_dir_all(bx.get_dir())
        .with_context(|| format!("creating box state {}", bx.get_dir().display()))?;
    sys::set_owner_only(bx.get_dir(), true)
        .with_context(|| format!("securing box state {}", bx.get_dir().display()))?;
    bx.write_origin();
    Ok(())
}

/// `terra [BOX] setup` - pin a recipe, build the filesystem, bake `on_create`.
pub async fn run(
    args: &cli::SetupArgs,
    name: Option<&str>,
    project_dir: &Path,
    cwd: &Path,
    is_at_a_terminal: bool,
) -> Result<ExitCode> {
    let target = resolve::resolve_for_setup(name, project_dir, cwd)?;

    match target.bx.get_holder() {
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
    let approved = request_recipe_approval(target, &approval, is_at_a_terminal, true)?;
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
    let prepared = prepare_box(&approved, rebuild)?;
    let ApprovedRecipe { bx, cfg, .. } = approved;

    // Ungated: the guest skips a bake its stamp says already ran, so
    // re-running setup stays cheap.
    if !cfg.hooks.on_create.is_empty() {
        boot::run_bake(&cfg, &bx, &prepared.lock).await?;
    }
    eprintln!("terra: {bx} is ready - `terra {}` boots it", bx.get_name());
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        writer.write_origin();
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
            guest: "/data".into(),
            size_mib: 1,
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
            manifest_divergence: None,
        };

        // Approval must precede reading even a missing env_file.
        let mut refused = target();
        if let resolve::Source::File(recipe) = &mut refused.source {
            recipe.text.push_str("env_file: missing.env\n");
        }
        let err = request_recipe_approval(
            refused,
            &Approval::ChosenByHand {
                trust_recipe: false,
            },
            false,
            true,
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
                true,
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
            manifest_divergence: None,
        };

        let err = request_recipe_approval(
            target(),
            &Approval::ChosenByHand {
                trust_recipe: false,
            },
            false,
            true,
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
            true,
        )
        .expect("--trust-recipe should pin with sensitive mount");
        assert!(approved.new_pin.is_some());
    }

    #[test]
    fn a_changed_pinned_target_needs_setup_before_any_source_can_boot_it() {
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
            let initial = ResolvedBox {
                bx: bx.clone(),
                source: resolve::Source::File(recipe()),
                manifest_divergence: None,
            };
            let approved = request_recipe_approval(
                initial,
                &Approval::ChosenByHand {
                    trust_recipe: false,
                },
                true,
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
                let error = request_recipe_approval(
                    ResolvedBox {
                        bx: bx.clone(),
                        source,
                        manifest_divergence: None,
                    },
                    &Approval::Offer,
                    true,
                    false,
                )
                .expect_err("a changed target must not boot")
                .to_string();
                assert!(error.contains("moved since it was pinned"), "{error}");
            }

            let refreshed = request_recipe_approval(
                ResolvedBox {
                    bx: bx.clone(),
                    source: resolve::Source::Pinned,
                    manifest_divergence: None,
                },
                &Approval::ChosenByHand {
                    trust_recipe: false,
                },
                true,
                true,
            )
            .expect("an explicit setup refreshes pinned targets");
            prepare_box(&refreshed, Rebuild::No).unwrap();
            request_recipe_approval(
                ResolvedBox {
                    bx,
                    source: resolve::Source::Pinned,
                    manifest_divergence: None,
                },
                &Approval::Offer,
                true,
                false,
            )
            .expect("the refreshed pin boots");
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
            std::fs::write(bx.get_volume_image(name), b"image").unwrap();
        }
        let configured = vec!["data".to_string()];

        sweep_or_keep_unused_volumes(&bx, &configured, Rebuild::No).unwrap();
        assert!(
            bx.get_volume_image("old").exists(),
            "a plain pin or boot deleted a volume's data"
        );
        assert!(bx.get_volume_image("data").exists());

        sweep_or_keep_unused_volumes(&bx, &configured, Rebuild::Yes).unwrap();
        assert!(!bx.get_volume_image("old").exists(), "--rebuild sweeps it");
        assert!(
            bx.get_volume_image("data").exists(),
            "a named volume was swept"
        );
    }

    /// A stamp belongs to the rootfs it proves: `--rebuild` makes a new
    /// filesystem, so the old bake's proof must go with it - or a rebuild
    /// would inherit a bake that never ran on it.
    #[test]
    fn rebuild_takes_the_bake_stamp_with_the_rootfs() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::ROOTFS_FILE), b"old").unwrap();
        std::fs::write(bx.get_dir().join(state::BAKE_STAMP), b"").unwrap();

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
            !bx.get_dir().join(state::BAKE_STAMP).exists(),
            "the rebuilt box kept the old rootfs's bake stamp"
        );
    }

    /// The whole of what a pinning does about the person, off the three things
    /// that decide it. Two rows differ from their neighbours by nothing a call
    /// site could see - `--trust-recipe` on a recipe nobody suspects pins in
    /// silence rather than warning, and the offer is put even where a named
    /// recipe would not be - so the table is pinned here rather than
    /// reconstructed from the four routes that reach it.
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

        // A suspect one is put to them, defaulting to no, and refused where
        // there is nobody to ask - `--trust-recipe` answers it either way.
        assert_eq!(
            decide_pinning(&by_hand(false), true, true),
            PinAction::Ask { default_yes: false }
        );
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

        // The offer is itself the question, so it is always put - and it is the
        // one route that can default to yes.
        assert_eq!(
            decide_pinning(&Approval::Offer, false, true),
            PinAction::Ask { default_yes: true }
        );
        assert_eq!(
            decide_pinning(&Approval::Offer, true, true),
            PinAction::Ask { default_yes: false }
        );
        for is_suspect in [false, true] {
            assert_eq!(
                decide_pinning(&Approval::Offer, is_suspect, false),
                PinAction::RefuseUnasked,
                "is_suspect={is_suspect}"
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
    /// The default is the whole reason both spellings of the prompt exist: a
    /// bare Enter takes the offer on a recipe nobody suspects and refuses one
    /// that is suspect, so which one was asked has to survive an empty line.
    /// Anything that is not a yes is a no - an answer this cannot read must
    /// never be the one that pins.
    #[test]
    fn only_a_yes_pins_and_a_bare_enter_takes_the_default_it_was_offered() {
        for yes in ["y", "Y", "yes", "Yes", "YES", " y \n", "yes\r\n"] {
            assert!(answer_is_yes(yes, false), "{yes:?} is a yes");
            assert!(answer_is_yes(yes, true), "{yes:?} is a yes");
        }
        // A bare Enter is the default the prompt spelled out, either way.
        for empty in ["", "\n", "  \n", "\r\n"] {
            assert!(answer_is_yes(empty, true), "{empty:?} under [Y/n]");
            assert!(!answer_is_yes(empty, false), "{empty:?} under [y/N]");
        }
        // Everything else is a no, whichever default was offered - `yep` and
        // `ok` included, because a recipe is pinned on a yes, not on a
        // not-quite-no.
        for no in ["n", "N", "no", "No", "yep", "ok", "sure", "y es", "1"] {
            assert!(!answer_is_yes(no, false), "{no:?} is not a yes");
            assert!(!answer_is_yes(no, true), "{no:?} is not a yes");
        }
    }
}
