//! Which box a BOX argument means, and which recipe file it points at. The one
//! place `terra.yaml` is read per resolution - it commonly sits in a share a
//! guest can write, so a second read could see a different manifest.

use crate::state::{self, BoxRef};
use crate::{config, config::MANIFEST_FILE};
use anyhow::{Context as _, Result, anyhow};
use std::path::{Path, PathBuf};

/// What one BOX argument denotes: a bare word names a box, a path names a
/// recipe file.
#[derive(Debug)]
pub enum BoxArg {
    Name(String),
    RecipePath { path: String, name: String },
}

impl BoxArg {
    pub fn parse(arg: &str) -> Result<Self> {
        if !is_path(arg) {
            crate::name::validate_box_name(arg)?;
            return Ok(Self::Name(arg.to_string()));
        }
        let name = Path::new(arg)
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        crate::name::validate_box_name(&name).with_context(|| format!("resolving '{arg}'"))?;
        Ok(Self::RecipePath {
            path: arg.to_string(),
            name,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Recipe {
    pub from: PathBuf,
    pub text: String,
}

/// Where the recipe a target resolves to comes from.
#[derive(Debug)]
pub enum Source {
    Pinned,
    File(Recipe),
    Manifest(Recipe),
}

#[derive(Debug)]
pub struct ResolvedBox {
    pub bx: BoxRef,
    pub source: Source,
    pub manifest_divergence: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Existence {
    MustExist,
    MayBeMissing,
}

#[derive(Debug, Clone, Copy)]
enum PinSource {
    Operate,
    Setup,
}

impl ResolvedBox {
    pub(crate) fn parse_recipe_without_env_file(&self) -> Result<config::Config> {
        match &self.source {
            Source::Pinned => config::load_path(
                &self.bx.get_dir().join(state::RECIPE_FILE),
                self.bx.get_project_dir(),
            ),
            Source::File(r) | Source::Manifest(r) => {
                config::parse_recipe(&r.text, self.bx.get_project_dir(), &r.from)
            }
        }
    }
}

/// The box `name` — or the directory's only one — which must be set up already.
pub fn resolve_pinned_box(project_dir: &Path, name: Option<&str>) -> Result<BoxRef> {
    Ok(resolve(name, project_dir, None, Existence::MustExist)?.bx)
}

/// A BOX argument read for `terra setup`: the recipe to pin. A name pins what
/// the manifest chose even when the box is already set up - `setup` is the one
/// verb that re-reads the manifest, so a reference pointing nowhere is the
/// manifest's fault, and the pin never outlives a `terra.yaml` edit.
pub fn resolve_for_setup(arg: Option<&str>, project_dir: &Path, cwd: &Path) -> Result<ResolvedBox> {
    resolve_inner(
        arg,
        project_dir,
        Some(cwd),
        Existence::MayBeMissing,
        PinSource::Setup,
    )
}

/// The one resolution: a BOX argument becomes the box and where its recipe
/// comes from. `cwd` is the directory the verb reads recipe files against -
/// unset, the verb takes box names only, and `existence` decides whether a box
/// nobody set up resolves at all. Only `setup` consults the manifest over an
/// existing pin; the verbs that answer from a pin - `show`, a boot - tolerate
/// a manifest that points nowhere.
pub fn resolve(
    arg: Option<&str>,
    project_dir: &Path,
    cwd: Option<&Path>,
    existence: Existence,
) -> Result<ResolvedBox> {
    resolve_inner(arg, project_dir, cwd, existence, PinSource::Operate)
}

fn resolve_inner(
    arg: Option<&str>,
    project_dir: &Path,
    cwd: Option<&Path>,
    existence: Existence,
    pin_source: PinSource,
) -> Result<ResolvedBox> {
    let manifest = config::load_manifest_or_warn(project_dir);
    let name = match arg {
        None => choose_default_box_name(project_dir, manifest.as_ref())?,
        Some(arg) => match BoxArg::parse(arg)? {
            BoxArg::Name(name) => name,
            BoxArg::RecipePath { path, name } => {
                let cwd = cwd.ok_or_else(|| {
                    anyhow!(
                        "'{path}' is a recipe path - this command takes a box name \
                         (`terra {path} setup` is what reads and pins the file)"
                    )
                })?;
                let recipe = read_recipe(&path, cwd)?
                    .ok_or_else(|| build_missing_recipe_error(&path, &path, cwd))?;
                return Ok(ResolvedBox {
                    bx: BoxRef::resolve(project_dir, &name)?,
                    source: Source::File(recipe),
                    manifest_divergence: None,
                });
            }
        },
    };

    let bx = BoxRef::resolve(project_dir, &name)?;
    let pinned = bx.get_dir().join(state::RECIPE_FILE).exists();

    if cwd.is_none() {
        if matches!(existence, Existence::MustExist) && !pinned {
            return Err(build_missing_box_error(
                project_dir,
                Some(&name),
                manifest.as_ref(),
            ));
        }
        return Ok(ResolvedBox {
            bx,
            source: Source::Pinned,
            manifest_divergence: None,
        });
    }

    if pinned && matches!(pin_source, PinSource::Operate) {
        let divergence = find_manifest_divergence(&bx, manifest.as_ref());
        return Ok(ResolvedBox {
            bx,
            source: Source::Pinned,
            manifest_divergence: divergence,
        });
    }

    let manifest_reference = manifest.as_ref().and_then(|m| m.boxes.get(bx.get_name()));
    if let Some(reference) = manifest_reference {
        if let Some(recipe) = read_recipe(reference, bx.get_project_dir())? {
            return Ok(ResolvedBox {
                bx,
                source: Source::Manifest(recipe),
                manifest_divergence: None,
            });
        }
        let missing = build_missing_recipe_error(bx.get_name(), reference, bx.get_project_dir());
        return if pinned {
            // The box is set up; only the manifest's reference is wrong, so the
            // "never been set up" lead would lie.
            Err(missing)
        } else {
            Err(missing.context(
                build_missing_box_error(project_dir, Some(bx.get_name()), manifest.as_ref())
                    .to_string(),
            ))
        };
    }

    if pinned {
        return Ok(ResolvedBox {
            bx,
            source: Source::Pinned,
            manifest_divergence: None,
        });
    }

    Err(build_missing_recipe_error(
        bx.get_name(),
        bx.get_name(),
        bx.get_project_dir(),
    ))
}

/// The recipe `terra setup` would pin next, when the manifest names a
/// different file than the box's own pin - what a boot runs today versus
/// what the next `setup` would switch it to.
fn find_manifest_divergence(bx: &BoxRef, manifest: Option<&config::Manifest>) -> Option<PathBuf> {
    let reference = manifest?.boxes.get(bx.get_name())?;
    let chosen = read_recipe(reference, bx.get_project_dir()).ok()??;
    let pinned = config::read_recipe_text(&bx.get_dir().join(state::RECIPE_FILE)).ok()?;
    (chosen.text != pinned).then_some(chosen.from)
}

pub(crate) fn choose_default_box_name(
    project_dir: &Path,
    manifest: Option<&config::Manifest>,
) -> Result<String> {
    let existing = state::list_existing_names(project_dir)?;
    let names = list_known_names_with(&existing, manifest);
    match names.as_slice() {
        [] => Err(build_missing_box_error(project_dir, None, manifest)),
        [one] => Ok(one.clone()),
        // Several declared, none set up: they are declarations, and the error
        // for that names the manifest they came from.
        _ if existing.is_empty() => Err(build_missing_box_error(project_dir, None, manifest)),
        many => anyhow::bail!(
            "{} has several boxes - name one: {}",
            project_dir.display(),
            many.join(", ")
        ),
    }
}

/// The names of every box of `project_dir`: those on disk, plus those the
/// manifest declares, sorted.
pub(crate) fn list_known_names(
    project_dir: &Path,
    manifest: Option<&config::Manifest>,
) -> Result<Vec<String>> {
    let existing = state::list_existing_names(project_dir)?;
    Ok(list_known_names_with(&existing, manifest))
}

fn list_known_names_with(existing: &[String], manifest: Option<&config::Manifest>) -> Vec<String> {
    let mut names = existing.to_vec();
    names.extend(manifest.iter().flat_map(|m| m.boxes.keys().cloned()));
    names.sort();
    names.dedup();
    names
}

/// "This directory has no such box" - the one error for it, with the manifest
/// named when it declares what the directory has.
#[must_use]
fn build_missing_box_error(
    project_dir: &Path,
    name: Option<&str>,
    manifest: Option<&config::Manifest>,
) -> anyhow::Error {
    let default_hint = || {
        format!(
            "`terra <box> setup` makes one, from {} or a recipe path",
            config::MANIFEST_FILE
        )
    };
    let hint = match (name, manifest) {
        (Some(n), Some(m)) => {
            if m.boxes.contains_key(n) {
                format!(
                    "{} declares it, but it has never been set up: `terra {n} setup`",
                    config::MANIFEST_FILE
                )
            } else {
                default_hint()
            }
        }
        (None, Some(m)) => {
            if m.boxes.is_empty() {
                default_hint()
            } else {
                format!(
                    "{} declares {}, and none is set up yet: `terra <box> setup`",
                    config::MANIFEST_FILE,
                    m.boxes.keys().cloned().collect::<Vec<_>>().join(", ")
                )
            }
        }
        (Some(_) | None, None) => default_hint(),
    };
    match name {
        Some(n) => anyhow!("no box '{n}' in {} - {hint}", project_dir.display()),
        None => anyhow!("no box in {} - {hint}", project_dir.display()),
    }
}

pub(crate) fn read_recipe(reference: &str, source_dir: &Path) -> Result<Option<Recipe>> {
    if !is_path(reference) {
        return Ok(None);
    }
    let path = config::resolve_recipe_path(Path::new(reference), source_dir)?;
    match config::read_recipe_text(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        r => {
            let text = r.with_context(|| {
                format!("reading {}", crate::render::escape_printable_path(&path))
            })?;
            Ok(Some(Recipe { from: path, text }))
        }
    }
}

/// The one error for a recipe that is not there.
#[must_use]
pub(crate) fn build_missing_recipe_error(
    arg: &str,
    reference: &str,
    source_dir: &Path,
) -> anyhow::Error {
    if !is_path(reference) {
        return anyhow!(
            "no recipe for '{arg}': a bare word names a box, and a recipe file is \
             named by path\n(`terra ./{arg}.yaml setup`, or a {MANIFEST_FILE} entry)"
        );
    }
    let tried = match config::resolve_recipe_path(Path::new(reference), source_dir) {
        Ok(p) => p.display().to_string(),
        Err(e) => return e,
    };
    let tried = crate::render::escape_printable(&tried);
    let reference = crate::render::escape_printable(reference);
    let arg = crate::render::escape_printable(arg);
    if reference == arg {
        anyhow!("config not found: {tried} (terra {reference} setup reads and pins the file)")
    } else {
        anyhow!(
            "config not found: {tried}\n\
             (box '{arg}' in {MANIFEST_FILE} points at '{reference}')"
        )
    }
}

#[must_use]
pub(crate) fn is_path(arg: &str) -> bool {
    arg.starts_with(['.', '/', '~'])
        || arg.contains(std::path::is_separator)
        || Path::new(arg)
            .extension()
            .is_some_and(crate::name::is_recipe_ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve_recipe_path(reference: &str, source_dir: &Path) -> Result<PathBuf> {
        config::resolve_recipe_path(Path::new(reference), source_dir)
    }

    /// A bare word is a box, never a file: there is no directory of profiles it
    /// could resolve into, so a recipe reaches terra by path alone.
    #[cfg(unix)]
    #[test]
    fn unreadable_recipe_reference_errors_escape_terminal_controls() {
        let dir = tempfile::tempdir().unwrap();
        let name = "./bad\x1b]0;title\x07.yaml";
        std::fs::create_dir(dir.path().join(name)).unwrap();
        let error = format!("{:#}", read_recipe(name, dir.path()).unwrap_err());
        assert!(!error.contains(['\x1b', '\x07']), "{error:?}");
    }

    #[test]
    fn missing_recipe_errors_escape_terminal_controls() {
        let error =
            build_missing_recipe_error("dev", "./bad\x1b]0;title\x07.yaml", Path::new("/project"))
                .to_string();
        assert!(!error.contains(['\x1b', '\x07']), "{error:?}");
    }

    #[test]
    fn a_bare_word_names_no_recipe_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pi-dev.yaml"), "hw:\n  cpus: 1\n").unwrap();
        assert!(matches!(BoxArg::parse("pi-dev").unwrap(), BoxArg::Name(n) if n == "pi-dev"));
        assert!(read_recipe("pi-dev", dir.path()).unwrap().is_none());
        let err = build_missing_recipe_error("pi-dev", "pi-dev", dir.path()).to_string();
        assert!(err.contains("named by path"), "{err}");
        assert!(
            err.contains("terra ./pi-dev.yaml setup"),
            "the fix is spelled out: {err}"
        );
    }

    #[test]
    fn dotted_path_is_local() {
        let project = tempfile::tempdir().unwrap();
        let p = resolve_recipe_path("./pi-dev.yaml", project.path()).unwrap();
        assert_eq!(p, project.path().join("pi-dev.yaml"));
    }

    #[test]
    fn absolute_path_is_kept() {
        let directory = tempfile::tempdir().unwrap();
        let recipe = directory.path().join("x.yaml");
        let project = directory.path().join("project");
        let p = resolve_recipe_path(recipe.to_str().unwrap(), &project).unwrap();
        assert_eq!(p, recipe);
    }

    #[test]
    fn tilde_expands() {
        let p = resolve_recipe_path("~/.terra/x.yaml", Path::new("/proj")).unwrap();
        assert_eq!(p, std::env::home_dir().unwrap().join(".terra/x.yaml"));
    }

    /// A bare `ci.yaml` means the file in front of you - the spelling *is* a
    /// recipe filename, and [`crate::name::validate_box_name`] refuses it as a
    /// name for the same reason.
    #[test]
    fn a_bare_yaml_filename_is_a_path() {
        let project = tempfile::tempdir().unwrap();
        for file in ["ci.yaml", "ci.yml"] {
            assert!(is_path(file), "{file}");
            let p = resolve_recipe_path(file, project.path()).unwrap();
            assert_eq!(p, project.path().join(file));
        }
        assert!(!is_path("ci"));
        assert!(!is_path("ci.v2"), "an extension that is not a recipe's");
        assert!(
            matches!(BoxArg::parse("ci.yaml").unwrap(), BoxArg::RecipePath { name, .. } if name == "ci")
        );
    }

    /// A path whose stem is not a valid box name is refused with the rule and
    /// the argument it came from - never quietly rewritten into a name nobody
    /// typed (`My Recipe.yaml` used to become a box called `My_Recipe`).
    #[test]
    fn a_stem_that_is_not_a_name_is_refused_not_munged() {
        assert!(
            matches!(BoxArg::parse("./ci.v2.yaml").unwrap(), BoxArg::RecipePath { name, .. } if name == "ci.v2")
        );
        for bad in [
            "./My Recipe.yaml",
            "./.hidden.yaml",
            "./é.yaml",
            "./-x.yaml",
        ] {
            let err = format!("{:#}", BoxArg::parse(bad).unwrap_err());
            assert!(err.contains("cannot name a box"), "{bad}: {err}");
            assert!(err.contains(bad), "the argument it came from: {err}");
        }
    }

    /// A manifest entry wins over the pinned recipe for `terra setup`, so one
    /// name is one box in every clone of the project - and a name the manifest
    /// does not declare never reads a file at all.
    #[test]
    fn the_manifest_chooses_what_a_name_resolves_to() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(MANIFEST_FILE),
            "boxes:\n  dev: ./dev-recipe.yaml\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("dev-recipe.yaml"), "hw:\n  cpus: 1\n").unwrap();

        let t = resolve(
            Some("dev"),
            dir.path(),
            Some(dir.path()),
            Existence::MayBeMissing,
        )
        .unwrap();
        let Source::Manifest(r) = &t.source else {
            panic!("the manifest chose this recipe, so the source must say so")
        };
        assert_eq!(r.from, dir.path().join("dev-recipe.yaml"));

        let e = resolve(
            Some("other"),
            dir.path(),
            Some(dir.path()),
            Existence::MayBeMissing,
        )
        .unwrap_err();
        assert!(e.to_string().contains("bare word"), "{e}");
    }

    /// A `terra.yaml` reference is the manifest's, so it resolves beside the
    /// manifest - never against the shell's directory, which would give
    /// `terra --project` a different recipe per caller and make one name mean
    /// two files. The same rule a relative `mounts[].host` follows.
    #[test]
    fn a_manifest_reference_resolves_against_the_project_not_the_shell() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(project.join(MANIFEST_FILE), "boxes:\n  dev: ./dev.yaml\n").unwrap();
        std::fs::write(project.join("dev.yaml"), "hw:\n  cpus: 3\n").unwrap();
        std::fs::write(elsewhere.join("dev.yaml"), "hw:\n  cpus: 9\n").unwrap();

        let t = resolve(
            Some("dev"),
            &project,
            Some(&elsewhere),
            Existence::MayBeMissing,
        )
        .unwrap();
        let Source::Manifest(r) = &t.source else {
            panic!("the manifest chose this recipe, so the source must say so")
        };
        assert_eq!(r.from, project.join("dev.yaml"));
        assert!(
            r.text.contains("cpus: 3"),
            "the shell's directory supplied the recipe: {}",
            r.text
        );

        std::fs::write(
            project.join(MANIFEST_FILE),
            "boxes:\n  dev: ./only-here.yaml\n",
        )
        .unwrap();
        std::fs::write(elsewhere.join("only-here.yaml"), "hw:\n  cpus: 9\n").unwrap();
        let e = resolve(
            Some("dev"),
            &project,
            Some(&elsewhere),
            Existence::MayBeMissing,
        )
        .expect_err("a reference pointing nowhere in the project must not resolve");
        let msg = format!("{e:#}");
        assert!(msg.contains("config not found"), "{msg}");
        assert!(
            msg.contains(&project.display().to_string()),
            "the path it looked for is the project's: {msg}"
        );
        assert!(
            !msg.contains(&elsewhere.display().to_string()),
            "it looked in the shell's directory: {msg}"
        );
    }

    /// Which resolutions read a recipe path typed on the command line, and
    /// which refuse one. The split is whether the verb can *run* a recipe:
    /// `setup` pins one, `show` prints one, and a boot offers to pin one before
    /// it runs - so all three read the file. The verbs that operate on an
    /// existing box read no recipe at all, and for them the fix is spelled out
    /// rather than the path being quietly taken for a name.
    #[test]
    fn a_recipe_path_is_read_only_where_there_is_a_shell_directory_for_it() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ci.yaml"), "hw:\n  cpus: 1\n").unwrap();

        let e = resolve(Some("./ci.yaml"), dir.path(), None, Existence::MustExist).unwrap_err();
        assert!(format!("{e:#}").contains("box name"), "{e:#}");

        // The three that carry the shell's directory read the file it names.
        let t = resolve(
            Some("./ci.yaml"),
            dir.path(),
            Some(dir.path()),
            Existence::MayBeMissing,
        )
        .unwrap();
        let Source::File(r) = &t.source else {
            panic!("a typed path is the recipe, whatever the box has pinned")
        };
        assert_eq!(r.from, dir.path().join("ci.yaml"));
        assert_eq!(t.bx.get_name(), "ci", "the box takes the file's stem");
    }

    /// The operate verbs read no recipe. `rm` addresses what is not there
    /// without complaint; the verbs that need a box get "no box", not "not
    /// running", for a name nobody set up.
    #[test]
    fn operating_on_a_box_resolves_lexically_unless_the_box_must_exist() {
        let dir = tempfile::tempdir().unwrap();
        assert!(resolve(Some("dev"), dir.path(), None, Existence::MayBeMissing,).is_ok());
        let err = resolve(Some("dev"), dir.path(), None, Existence::MustExist)
            .expect_err("a box nobody set up must not satisfy must_exist")
            .to_string();
        assert!(err.contains("no box 'dev'"), "{err}");
    }

    /// A missing recipe is `Ok(None)`, not an error: a box that is already set
    /// up answers from its own copy. The error, when the caller does want one,
    /// says which file was looked for and who asked for it.
    #[test]
    fn a_missing_recipe_is_reported_but_not_an_error_by_itself() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_recipe("./nope.yaml", dir.path()).unwrap().is_none());

        let plain =
            build_missing_recipe_error("./nope.yaml", "./nope.yaml", dir.path()).to_string();
        assert!(plain.contains("config not found"), "{plain}");
        assert!(!plain.contains(MANIFEST_FILE), "{plain}");

        let via_manifest = build_missing_recipe_error("dev", "./gone.yaml", dir.path()).to_string();
        assert!(via_manifest.contains("config not found"), "{via_manifest}");
        assert!(via_manifest.contains(MANIFEST_FILE), "{via_manifest}");

        std::fs::write(dir.path().join("here.yaml"), "hw:\n  cpus: 1\n").unwrap();
        let found = read_recipe("./here.yaml", dir.path()).unwrap().unwrap();
        assert_eq!(found.from, dir.path().join("here.yaml"));
        assert!(found.text.contains("cpus: 1"));
    }

    /// The bare form funnels every purpose failure into "no box" - but the
    /// real cause rides underneath as context, not thrown away: an unreadable
    /// recipe and a box that was never set up need different fixes.
    #[test]
    fn start_target_keeps_the_real_error_underneath_the_no_box_lead() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(MANIFEST_FILE),
            "boxes:\n  dev: ./gone.yaml\n",
        )
        .unwrap();
        let chain = format!(
            "{:#}",
            resolve(
                Some("dev"),
                dir.path(),
                Some(dir.path()),
                Existence::MayBeMissing,
            )
            .unwrap_err()
        );
        assert!(chain.contains("no box 'dev'"), "{chain}");
        assert!(chain.contains("never been set up"), "{chain}");
        assert!(
            chain.contains("config not found") && chain.contains("gone.yaml"),
            "the cause was discarded: {chain}"
        );
    }

    /// A reading says when the manifest names a recipe other than the pin.
    /// `terra show` answers about what a boot runs - the pin - while the very
    /// next `terra setup` pins what the manifest names, so the review between
    /// the two used to show neither the recipe that would win nor that there
    /// was a second one at all.
    #[test]
    fn a_reading_says_when_the_manifest_would_pin_something_else() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::RECIPE_FILE), "hw:\n  cpus: 1\n").unwrap();
        std::fs::write(
            dir.path().join(MANIFEST_FILE),
            "boxes:\n  dev: ./dev.yaml\n",
        )
        .unwrap();

        // The same recipe by both routes is no divergence: a pin the manifest
        // agrees with is what a settled project looks like.
        std::fs::write(dir.path().join("dev.yaml"), "hw:\n  cpus: 1\n").unwrap();
        let agreed = resolve(
            Some("dev"),
            dir.path(),
            Some(dir.path()),
            Existence::MayBeMissing,
        )
        .unwrap();
        assert!(matches!(agreed.source, Source::Pinned));
        assert_eq!(agreed.manifest_divergence, None);

        // …and an edited manifest is named, with the file that would win.
        std::fs::write(dir.path().join("dev.yaml"), "hw:\n  cpus: 8\n").unwrap();
        let diverged = resolve(
            Some("dev"),
            dir.path(),
            Some(dir.path()),
            Existence::MayBeMissing,
        )
        .unwrap();
        assert!(
            matches!(diverged.source, Source::Pinned),
            "the pin is still what a boot runs"
        );
        assert_eq!(
            diverged.manifest_divergence,
            Some(dir.path().join("dev.yaml")),
            "the recipe `terra setup` would pin instead goes unreported"
        );

        // A typed path is the recipe, so there is nothing for it to diverge from.
        assert_eq!(
            resolve(
                Some("./dev.yaml"),
                dir.path(),
                Some(dir.path()),
                Existence::MayBeMissing,
            )
            .unwrap()
            .manifest_divergence,
            None
        );
    }

    /// `terra.yaml` lives in the project root, which is exactly what a box
    /// shares, so its own guest can leave it unparseable. That must not take
    /// the box away from the host: every verb that needs only a *box* carries
    /// on from what is set up on disk, so the box that did it can still be
    /// stopped, removed and read.
    ///
    /// `setup` is the exception, and the reason the split is by verb: it is
    /// what reads the manifest to decide which recipe to pin, and falling back
    /// to the box's own older pin there would look like a recipe edit that took
    /// effect.
    #[test]
    fn a_broken_manifest_does_not_take_the_box_away() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(MANIFEST_FILE), "boxes: [not, a, map\n").unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::RECIPE_FILE), "hw:\n  cpus: 1\n").unwrap();

        assert!(resolve(Some("dev"), dir.path(), None, Existence::MustExist).is_ok());
        assert!(
            resolve(None, dir.path(), None, Existence::MustExist).is_ok(),
            "and by default"
        );

        let started = resolve(
            Some("dev"),
            dir.path(),
            Some(dir.path()),
            Existence::MayBeMissing,
        )
        .unwrap();
        assert!(matches!(started.source, Source::Pinned));

        // `setup` also tolerates a broken manifest when a pin exists: the
        // lenient `load_manifest_or_warn` reads it as nothing, so the pin wins
        // by default. A broken manifest with no pin still surfaces as
        // no recipe rather than `failed to parse`.
        let t = resolve_for_setup(Some("dev"), dir.path(), dir.path()).unwrap();
        assert!(matches!(t.source, Source::Pinned));
    }

    /// A manifest reference pointing nowhere is the setup verb's to blame, not
    /// the box's: `setup` re-reads the manifest over an existing pin, so a
    /// dangling entry must fail it - naming `terra.yaml` - and the "never been
    /// set up" lead, which a pinned box would make a lie, stays off.
    #[test]
    fn setup_blames_the_manifest_for_a_dangling_reference_to_a_pinned_box() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::RECIPE_FILE), "hw:\n  cpus: 1\n").unwrap();
        std::fs::write(
            dir.path().join(MANIFEST_FILE),
            "boxes:\n  dev: ./gone.yaml\n",
        )
        .unwrap();

        let err = format!(
            "{:#}",
            resolve_for_setup(Some("dev"), dir.path(), dir.path())
                .expect_err("a dangling manifest reference must fail setup")
        );
        assert!(err.contains(MANIFEST_FILE), "{err}");
        assert!(err.contains("gone.yaml"), "{err}");
        assert!(!err.contains("never been set up"), "{err}");
    }

    /// The "no box" lead is for a recipe that is *missing*: one that is there
    /// but unreadable must surface as its own error, because "never been set
    /// up - `terra dev setup`" prescribes a command that fails the same way.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_recipe_is_its_own_error_not_a_missing_box() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(MANIFEST_FILE),
            "boxes:\n  dev: ./locked.yaml\n",
        )
        .unwrap();
        let locked = dir.path().join("locked.yaml");
        std::fs::write(&locked, "hw:\n  cpus: 1\n").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_to_string(&locked).is_ok() {
            return; // root reads through 0o000, so there is nothing to pin here
        }
        let chain = format!(
            "{:#}",
            resolve(
                Some("dev"),
                dir.path(),
                Some(dir.path()),
                Existence::MayBeMissing,
            )
            .unwrap_err()
        );
        assert!(chain.contains("reading"), "{chain}");
        assert!(
            !chain.contains("never been set up"),
            "an unreadable recipe was misreported as a box that was never set up: {chain}"
        );
    }
}
