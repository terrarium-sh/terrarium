//! Approve a recipe before it is applied, and write the applied recipe it becomes.
//! Approval prevents a guest-written recipe in a writable share from granting new host access.

use crate::policy::mount;
use crate::recipe::resolve::{self, ResolvedRecipe};
use crate::recipe::{MANIFEST_FILE, Recipe, list_declared_writable_shares, merge_env_file};
use crate::render::{escape_printable_path, render_policy_summary, render_recipe_for_review};
use crate::state::{self, BoxRef};
use crate::sys::canonicalize_existing_prefix;
use crate::vm::boot;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub(crate) enum Approval {
    ChosenByHand { trust_recipe: bool },
    Reported,
}

#[derive(Debug)]
pub(crate) struct ApprovedRecipe {
    pub(crate) bx: BoxRef,
    pub(crate) recipe: Recipe,
    pub(crate) changed_recipe: Option<resolve::RecipeFile>,
    pub(crate) pinned_paths: Option<state::PinnedPaths>,
}

impl ApprovedRecipe {
    /// Write the applied recipe files this approval changes into `dir`, and name them.
    pub(crate) fn write_applied_recipe(&self, dir: &Path) -> Result<Vec<&'static str>> {
        state::write_applied_recipe(
            dir,
            self.changed_recipe.as_ref().map(|file| file.text.as_str()),
            self.pinned_paths.as_ref(),
        )
    }
}

/// A loaded recipe and how it differs from what the box has applied, before
/// anyone is asked about it.
pub(crate) struct RecipeReview {
    bx: BoxRef,
    recipe: Recipe,
    paths: state::PinnedPaths,
    previous_paths: Option<state::PinnedPaths>,
    changed_recipe: Option<ChangedRecipe>,
}

pub(crate) fn review_recipe(target: ResolvedRecipe) -> Result<RecipeReview> {
    let (recipe, paths) = target.load_recipe()?;
    let ResolvedRecipe {
        bx,
        source,
        manifest: _,
    } = target;
    let previous_paths = bx.load_pinned_paths()?;
    let changed_recipe = find_changed_recipe(&bx, source);
    Ok(RecipeReview {
        bx,
        recipe,
        paths,
        previous_paths,
        changed_recipe,
    })
}

impl RecipeReview {
    pub(crate) fn get_box(&self) -> &BoxRef {
        &self.bx
    }

    pub(crate) fn get_changed_text(&self) -> Option<&str> {
        self.changed_recipe
            .as_ref()
            .map(|changed| changed.file.text.as_str())
    }

    /// Ask about the changes, when they need asking, naming `effect` as what a yes does.
    pub(crate) fn approve(
        self,
        approval: &Approval,
        effect: ApplyEffect,
        is_at_a_terminal: bool,
    ) -> Result<ApprovedRecipe> {
        let RecipeReview {
            bx,
            mut recipe,
            paths,
            previous_paths,
            changed_recipe,
        } = self;
        let has_changed_targets = previous_paths
            .as_ref()
            .is_some_and(|applied| applied != &paths);
        if changed_recipe.is_some() || has_changed_targets {
            ask_to_apply_recipe(
                &bx,
                changed_recipe.as_ref(),
                &recipe,
                has_changed_targets,
                effect,
                approval,
                is_at_a_terminal,
            )?;
        }
        let pinned_paths = (previous_paths.as_ref() != Some(&paths)).then_some(paths);
        merge_env_file(&mut recipe)?;
        ensure_boot_plan_fits(&bx, &recipe)?;
        Ok(ApprovedRecipe {
            bx,
            recipe,
            changed_recipe: changed_recipe.map(|changed| changed.file),
            pinned_paths,
        })
    }
}

/// A recipe that differs from the applied recipe, and what brought it to setup.
struct ChangedRecipe {
    file: resolve::RecipeFile,
    carrier: RecipeCarrier,
}

/// What brought a recipe to setup, which decides who could have written it.
#[derive(Clone, Copy)]
enum RecipeCarrier {
    File,
    Manifest,
    StorageArtifact,
}

fn find_changed_recipe(bx: &BoxRef, source: resolve::Source) -> Option<ChangedRecipe> {
    let (file, carrier) = match source {
        resolve::Source::Applied => return None,
        resolve::Source::File(file) => (file, RecipeCarrier::File),
        resolve::Source::Manifest(file) => (file, RecipeCarrier::Manifest),
        resolve::Source::Artifact(file) => (file, RecipeCarrier::StorageArtifact),
    };
    // An import always asks, so running it without --trust-recipe always shows the recipe.
    let is_changed =
        matches!(carrier, RecipeCarrier::StorageArtifact) || !bx.is_recipe_applied(&file.text);
    is_changed.then_some(ChangedRecipe { file, carrier })
}

fn ask_to_apply_recipe(
    bx: &BoxRef,
    changed_recipe: Option<&ChangedRecipe>,
    recipe: &Recipe,
    has_changed_targets: bool,
    effect: ApplyEffect,
    approval: &Approval,
    is_at_a_terminal: bool,
) -> Result<()> {
    let authorship = changed_recipe.and_then(|recipe| find_recipe_authorship(bx, recipe));
    let sensitive_mounts = mount::find_sensitive_mounts(&recipe.mounts);
    let has_readwrite_sensitive = sensitive_mounts.iter().any(|s| !s.mount.readonly);
    let is_suspect = has_changed_targets || authorship.is_some() || has_readwrite_sensitive;
    let new_file = changed_recipe.map(|changed| &changed.file);
    let page = ApprovalPage {
        bx,
        effect,
        lead: build_apply_lead(bx, new_file, recipe, effect)?,
        warnings: build_apply_warnings(
            new_file,
            authorship.as_ref(),
            &sensitive_mounts,
            has_changed_targets,
        ),
        recipe,
    };
    put_the_question(
        decide_applying(approval, is_suspect, is_at_a_terminal),
        &page,
    )
}

/// Why someone other than the person may have written a recipe.
enum RecipeAuthorship {
    WritableShare {
        recipe_or_manifest: PathBuf,
        share: PathBuf,
    },
    UnreadableAppliedRecipe,
    StorageArtifact,
}

fn find_recipe_authorship(bx: &BoxRef, changed: &ChangedRecipe) -> Option<RecipeAuthorship> {
    let manifest = bx.get_project_dir().join(MANIFEST_FILE);
    let carriers: &[&Path] = match changed.carrier {
        RecipeCarrier::File => &[&changed.file.from],
        RecipeCarrier::Manifest => &[&changed.file.from, &manifest],
        RecipeCarrier::StorageArtifact => return Some(RecipeAuthorship::StorageArtifact),
    };
    let Ok(previous) = state::list_applied_recipes_across_boxes(bx.get_project_dir()) else {
        return Some(RecipeAuthorship::UnreadableAppliedRecipe);
    };
    for file in carriers {
        for (origin, recipe) in &previous {
            match find_writable_mount_containing(file, recipe, origin) {
                Ok(Some(share)) => {
                    return Some(RecipeAuthorship::WritableShare {
                        recipe_or_manifest: (*file).to_path_buf(),
                        share,
                    });
                }
                Ok(None) => {}
                Err(_) => return Some(RecipeAuthorship::UnreadableAppliedRecipe),
            }
        }
    }
    None
}

/// The first writable mount of `ran_recipe` whose host directory contains
/// `recipe_file` - the share a guest could have written the file through.
fn find_writable_mount_containing(
    recipe_file: &Path,
    ran_recipe: &str,
    project_dir: &Path,
) -> Result<Option<PathBuf>> {
    let file = canonicalize_existing_prefix(recipe_file);
    Ok(list_declared_writable_shares(ran_recipe, project_dir)?
        .into_iter()
        .find_map(|share| {
            let share = canonicalize_existing_prefix(&share);
            file.starts_with(&share).then_some(share)
        }))
}

fn build_apply_lead(
    bx: &BoxRef,
    file: Option<&resolve::RecipeFile>,
    recipe: &Recipe,
    effect: ApplyEffect,
) -> Result<String> {
    let review = || render_recipe_for_review(recipe).context("rendering the recipe for review");
    Ok(match (file, effect) {
        (Some(file), _) => format!(
            "applying {} to {bx}:\n{}",
            escape_printable_path(&file.from),
            review()?
        ),
        (None, ApplyEffect::PinPaths) => format!("updating {bx}'s share and env_file paths"),
        (
            None,
            ApplyEffect::Create | ApplyEffect::Rebuild | ApplyEffect::Update | ApplyEffect::Import,
        ) => {
            format!("applying {bx}'s recipe again:\n{}", review()?)
        }
    })
}

fn build_apply_warnings(
    file: Option<&resolve::RecipeFile>,
    authorship: Option<&RecipeAuthorship>,
    sensitive_mounts: &[mount::SensitiveMount<'_>],
    has_changed_targets: bool,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if has_changed_targets {
        warnings.push(
            "WARNING: a share or env_file target changed since the last setup; review the new host paths before approving.".to_string(),
        );
    }
    if let (Some(file), Some(authorship)) = (file, authorship) {
        warnings.push(format!(
            "WARNING: {}.",
            build_adoption_reason(&file.from, authorship)
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
    warnings
}

fn build_adoption_reason(from: &Path, authorship: &RecipeAuthorship) -> String {
    use std::fmt::Write as _;
    let (recipe_or_manifest, share) = match authorship {
        RecipeAuthorship::WritableShare {
            recipe_or_manifest,
            share,
        } => (recipe_or_manifest, share),
        RecipeAuthorship::UnreadableAppliedRecipe => {
            return format!(
                "a box's applied recipe cannot be read to determine whether a guest could have written {}",
                escape_printable_path(from)
            );
        }
        RecipeAuthorship::StorageArtifact => {
            return format!(
                "this recipe came from the storage artifact {}, written by whoever exported it; \
                 review it before approving",
                escape_printable_path(from)
            );
        }
    };
    let mut why = format!(
        "{} lives inside '{}', which a box of this directory shares read-write - \
         a guest may be the author of it",
        escape_printable_path(recipe_or_manifest),
        escape_printable_path(share),
    );
    if recipe_or_manifest != from {
        let _ = write!(
            why,
            ", and it is what names {} as this box's recipe",
            escape_printable_path(from)
        );
    }
    why
}

/// What a yes does to the box, which the question names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApplyEffect {
    Create,
    Rebuild,
    Update,
    PinPaths,
    Import,
}

/// What applying puts to the person: what it applies, why to doubt it, what it grants.
struct ApprovalPage<'a> {
    bx: &'a BoxRef,
    effect: ApplyEffect,
    lead: String,
    warnings: Vec<String>,
    recipe: &'a Recipe,
}

impl ApprovalPage<'_> {
    fn render(&self) -> String {
        use std::fmt::Write as _;

        let mut page = format!("{}\n", self.lead);
        for warning in &self.warnings {
            page.push_str(warning);
            page.push('\n');
        }
        page.push_str("It would grant:\n");
        page.push_str(&render_policy_summary(self.recipe));
        if self.effect == ApplyEffect::Rebuild {
            let _ = writeln!(
                page,
                "Rebuilding replaces {}'s root filesystem and runs on_create again; \
                 box volumes are kept.",
                self.bx
            );
        }
        page
    }

    fn question(&self) -> String {
        let bx = self.bx;
        match self.effect {
            ApplyEffect::Create => format!("terra: create {bx} with it? [y/N] "),
            ApplyEffect::Rebuild => format!("terra: rebuild {bx} with it? [y/N] "),
            ApplyEffect::Update => format!("terra: apply it to {bx}? [y/N] "),
            ApplyEffect::PinPaths => "terra: use the new paths? [y/N] ".to_string(),
            ApplyEffect::Import => format!("terra: import it into {bx}? [y/N] "),
        }
    }
}

/// What applying does about the recipe it would apply
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ApplyAction {
    WithoutAsking,
    WarnAndApply,
    Ask,
    ReportOnly,
    RefuseUnasked,
}

/// The one table applying's fate is read from: who vouches, whether a guest
/// could have written it, and whether there is anyone to ask.
fn decide_applying(approval: &Approval, is_suspect: bool, is_at_a_terminal: bool) -> ApplyAction {
    match (approval, is_suspect, is_at_a_terminal) {
        (Approval::ChosenByHand { .. }, false, _) => ApplyAction::WithoutAsking,
        (Approval::ChosenByHand { trust_recipe: true }, true, _) => ApplyAction::WarnAndApply,
        (Approval::Reported, false, _) | (Approval::Reported, true, true) => {
            ApplyAction::ReportOnly
        }
        (Approval::ChosenByHand { .. } | Approval::Reported, _, false) => {
            ApplyAction::RefuseUnasked
        }
        (Approval::ChosenByHand { .. }, _, true) => ApplyAction::Ask,
    }
}

/// Carry out the settled [`ApplyAction`]: `Ok(())` means apply it.
fn put_the_question(action: ApplyAction, page: &ApprovalPage<'_>) -> Result<()> {
    let warning = page.warnings.join("\n");
    match action {
        ApplyAction::WithoutAsking => Ok(()),
        ApplyAction::WarnAndApply => {
            if !warning.is_empty() {
                eprintln!("terra: {warning} Applying it anyway (--trust-recipe).");
            }
            Ok(())
        }
        ApplyAction::ReportOnly => {
            if !warning.is_empty() {
                eprintln!(
                    "terra: {warning} A real setup would put it to you, and needs \
                     --trust-recipe where there is no terminal to ask on."
                );
            }
            Ok(())
        }
        ApplyAction::RefuseUnasked => anyhow::bail!(
            "{}\n\
             There is no terminal to ask on. Review the recipe, then run this \
             again with --trust-recipe to apply it.",
            page.render()
        ),
        ApplyAction::Ask => {
            // stderr: a question on stdout would vanish into `terra setup >
            // log` and read as a hang.
            eprintln!("terra: {}", page.render());
            anyhow::ensure!(
                confirm(&page.question())?,
                "not applied - the box is unchanged"
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

fn ensure_boot_plan_fits(bx: &BoxRef, recipe: &Recipe) -> Result<()> {
    crate::vm::encode_boot_plan(
        &boot::BootSpec {
            recipe: recipe.clone(),
            project_dir: bx.get_project_dir().to_path_buf(),
            root: false,
            mode: terra_protocol::PlanMode::Run,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        },
        bx.get_name(),
    )?;
    Ok(())
}

/// Review and approve a recipe a person named, as tests drive it.
#[cfg(test)]
pub(crate) fn approve_by_hand(
    target: ResolvedRecipe,
    trust_recipe: bool,
    is_at_a_terminal: bool,
) -> Result<ApprovedRecipe> {
    review_recipe(target)?.approve(
        &Approval::ChosenByHand { trust_recipe },
        ApplyEffect::Rebuild,
        is_at_a_terminal,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipe::{MAX_RECIPE_BYTES, parse_recipe};

    /// Only a rebuild warns that the root filesystem goes, and the question
    /// names what a yes does.
    #[test]
    fn only_a_rebuild_page_says_the_root_is_replaced() {
        let _home = crate::sys::TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        let recipe = Recipe::default();
        let page = |effect| ApprovalPage {
            bx: &bx,
            effect,
            lead: String::new(),
            warnings: Vec::new(),
            recipe: &recipe,
        };
        let rebuild = page(ApplyEffect::Rebuild);
        assert!(rebuild.render().contains("Rebuilding replaces"));
        assert!(rebuild.question().contains("rebuild"));
        for effect in [
            ApplyEffect::Create,
            ApplyEffect::Update,
            ApplyEffect::PinPaths,
            ApplyEffect::Import,
        ] {
            let page = page(effect);
            assert!(!page.render().contains("Rebuilding"), "{effect:?}");
            assert!(!page.question().contains("rebuild"), "{effect:?}");
        }
    }

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
            assert!((recipe.len() as u64) < MAX_RECIPE_BYTES);
            let target = ResolvedRecipe {
                bx: bx.clone(),
                source: resolve::Source::File(resolve::RecipeFile {
                    from: dir.path().join("large.yaml"),
                    text: recipe,
                }),
                manifest: None,
            };
            let error = approve_by_hand(target, true, false).unwrap_err();
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
        let authorship = |from: PathBuf, carrier| {
            find_recipe_authorship(
                &bx,
                &ChangedRecipe {
                    file: resolve::RecipeFile {
                        from,
                        text: String::new(),
                    },
                    carrier,
                },
            )
        };
        assert!(matches!(
            authorship(target.join("evil.yaml"), RecipeCarrier::File),
            Some(RecipeAuthorship::WritableShare { .. })
        ));
        assert!(matches!(
            authorship(root.path().join("outside.yaml"), RecipeCarrier::Manifest),
            Some(RecipeAuthorship::WritableShare { .. })
        ));
        assert!(authorship(root.path().join("outside.yaml"), RecipeCarrier::File).is_none());
        std::fs::write(writer.get_dir().join(state::RECIPE_FILE), [0xff]).unwrap();
        assert!(matches!(
            authorship(target.join("evil.yaml"), RecipeCarrier::File),
            Some(RecipeAuthorship::UnreadableAppliedRecipe)
        ));
    }

    /// Re-applying an *already applied* box still consults every sibling's
    /// shares: a guest in box `b`, which shares the project read-write, can
    /// write a new recipe file for box `a` - so applying it must be treated as
    /// suspect. Off a terminal that refuses, naming `--trust-recipe`; the flag
    /// applies it with a warning. (The gap this pins: `a`'s own applied recipe has no
    /// mounts, so checking only it answered "nobody could have written this".)
    #[test]
    fn a_sibling_share_makes_a_reapply_suspect_too() {
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
        let target = || ResolvedRecipe {
            bx: a.clone(),
            source: resolve::Source::File(resolve::RecipeFile {
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
        let err = approve_by_hand(refused, false, false)
            .expect_err("a sibling's writable share should have made this apply suspect")
            .to_string();
        assert!(err.contains("may be the author"), "{err}");
        assert!(err.contains("--trust-recipe"), "{err}");

        // The flag applies it anyway - with the warning, but without a question,
        // so it never reaches the prompt whether there is a terminal or not.
        for is_at_a_terminal in [false, true] {
            let approved = approve_by_hand(target(), true, is_at_a_terminal)
                .expect("--trust-recipe should apply without asking");
            assert!(
                approved.changed_recipe.is_some(),
                "the recipe should be adopted"
            );
        }
    }

    #[test]
    fn readwrite_sensitive_mounts_are_suspect_and_warn_on_applying() {
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

        let target = || ResolvedRecipe {
            bx: bx.clone(),
            source: resolve::Source::File(resolve::RecipeFile {
                from: recipe_path.clone(),
                text: recipe_text.clone(),
            }),
            manifest: None,
        };

        let err = approve_by_hand(target(), false, false)
            .expect_err("read-write sensitive mount must be suspect")
            .to_string();

        assert!(err.contains("shares sensitive host SSH keys"), "{err}");
        assert!(err.contains("(read-write)"), "{err}");
        assert!(err.contains("--trust-recipe"), "{err}");

        let approved = approve_by_hand(target(), true, false)
            .expect("--trust-recipe should apply with sensitive mount");
        assert!(approved.changed_recipe.is_some());
    }

    /// The whole of what applying does about the person, off the three things
    /// that decide it. One row differs from its neighbours by nothing a call
    /// site could see - `--trust-recipe` on a recipe nobody suspects applies in
    /// silence rather than warning - so the table is pinned here rather than
    /// reconstructed from the routes that reach it.
    #[test]
    fn what_applying_asks_is_decided_by_who_vouches_for_it() {
        let by_hand = |trust_recipe| Approval::ChosenByHand { trust_recipe };

        // A person named the recipe and nothing suspects it: applied in silence,
        // terminal or not, `--trust-recipe` or not.
        for trust_recipe in [false, true] {
            for is_at_a_terminal in [false, true] {
                assert_eq!(
                    decide_applying(&by_hand(trust_recipe), false, is_at_a_terminal),
                    ApplyAction::WithoutAsking,
                    "trust_recipe={trust_recipe} is_at_a_terminal={is_at_a_terminal}"
                );
            }
        }

        // A suspect one is put to them, and refused where
        // there is nobody to ask - `--trust-recipe` answers it either way.
        assert_eq!(
            decide_applying(&by_hand(false), true, true),
            ApplyAction::Ask
        );
        assert_eq!(
            decide_applying(&by_hand(false), true, false),
            ApplyAction::RefuseUnasked
        );
        for is_at_a_terminal in [false, true] {
            assert_eq!(
                decide_applying(&by_hand(true), true, is_at_a_terminal),
                ApplyAction::WarnAndApply,
                "is_at_a_terminal={is_at_a_terminal}"
            );
        }

        // A dry run applies nothing, so it never asks - but it refuses exactly
        // where the setup it stands for would, which is the whole of its
        // promise: a suspect recipe with nobody to ask is a `terra setup` that
        // fails, and a dry run reporting that one clean would be a lie.
        for is_at_a_terminal in [false, true] {
            assert_eq!(
                decide_applying(&Approval::Reported, false, is_at_a_terminal),
                ApplyAction::ReportOnly,
                "is_at_a_terminal={is_at_a_terminal}"
            );
        }
        assert_eq!(
            decide_applying(&Approval::Reported, true, true),
            ApplyAction::ReportOnly
        );
        assert_eq!(
            decide_applying(&Approval::Reported, true, false),
            ApplyAction::RefuseUnasked
        );
    }

    /// What a typed answer means, on the one question that decides whether
    /// bytes a sandbox may have written become the box's applied recipe.
    ///
    /// Anything that is not a yes is a no - an answer this cannot read must
    /// never be the one that applies.
    #[test]
    fn only_a_yes_applies_and_a_bare_enter_refuses() {
        for yes in ["y", "Y", "yes", "Yes", "YES", " y \n", "yes\r\n"] {
            assert!(answer_is_yes(yes), "{yes:?} is a yes");
        }
        // `yep` and `ok` included, because a recipe is applied on a yes, not on
        // a not-quite-no.
        for no in [
            "", "\n", "  \n", "\r\n", "n", "N", "no", "No", "yep", "ok", "sure", "y es", "1",
        ] {
            assert!(!answer_is_yes(no), "{no:?} is not a yes");
        }
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
    /// that used to stop the applied recipe parsing and answered "no share
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
    /// dotenv a *sibling*'s applied recipe names, that recipe stops parsing,
    /// and the sibling's writable share stops counting - so a recipe the
    /// guest smuggled in applied recipes with no warning. [`parse_recipe`] never
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

    /// The gate reads applied recipes written by every terra that came before, and
    /// `validate` tightens between releases: `hw.mem_mib`'s floor and
    /// the "opens nothing" allow rule each refuse recipes that were once
    /// accepted. Running an applied recipe through the full validation answered "no share
    /// could have authored this" for every one of them, which flips the apply
    /// prompt's default to yes on a recipe a guest may have written.
    #[test]
    fn an_applied_recipe_this_terra_would_now_refuse_still_answers_the_gate() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let smuggled = project.join("evil.yaml");
        std::fs::write(&smuggled, "hw:\n  cpus: 2\n").unwrap();

        // What an older terra applied: the project shared read-write, plus
        // hardware this one refuses.
        let ran = format!(
            "hw:\n  mem_mib: 64\nmounts:\n  - host: {}\n    guest: /work\n",
            project.display()
        );
        assert!(
            parse_recipe(&ran, dir.path(), Path::new("an applied recipe")).is_err(),
            "this recipe has to be one today's validation refuses, or it proves nothing"
        );
        assert_eq!(
            find_writable_mount_containing(&smuggled, &ran, dir.path()).unwrap(),
            Some(std::fs::canonicalize(&project).unwrap()),
            "an applied recipe this terra would refuse took its shares out of the gate"
        );
    }

    /// The gate also reads applied recipes a *newer* terra wrote: a recipe field this
    /// binary does not know fails `Recipe`'s `deny_unknown_fields` parse
    /// outright, which used to answer "no share could have authored this" -
    /// the same silent yes as a refused applied recipe. The mounts are read through a
    /// lenient mirror instead, so only the fields the gate needs decide.
    #[test]
    fn an_applied_recipe_with_fields_this_terra_does_not_know_still_answers_the_gate() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let smuggled = project.join("evil.yaml");
        std::fs::write(&smuggled, "hw:\n  cpus: 2\n").unwrap();

        // What a newer terra applied: an unknown top-level section, and an
        // unknown per-mount field.
        let ran = format!(
            "quotas:\n  io_mib: 64\nmounts:\n  - host: {}\n    guest: /work\n    idmap: false\n",
            project.display()
        );
        assert!(
            parse_recipe(&ran, dir.path(), Path::new("an applied recipe")).is_err(),
            "this recipe has to be one today's Recipe cannot parse, or it proves nothing"
        );
        assert_eq!(
            find_writable_mount_containing(&smuggled, &ran, dir.path()).unwrap(),
            Some(std::fs::canonicalize(&project).unwrap()),
            "an applied recipe with unknown fields took its shares out of the gate"
        );

        // …and a host this terra refuses to expand (`~alice`, applied before
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
                parse_recipe(&ran, dir.path(), Path::new("an applied recipe")).is_err(),
                "{odd} has to be an entry today's Recipe cannot read, or it proves nothing"
            );
            assert_eq!(
                find_writable_mount_containing(&smuggled, &ran, dir.path()).unwrap(),
                Some(std::fs::canonicalize(&project).unwrap()),
                "{odd} took the writable share beside it out of the gate"
            );
        }

        assert!(find_writable_mount_containing(&smuggled, "mounts: nope\n", dir.path()).is_err());
    }
}
