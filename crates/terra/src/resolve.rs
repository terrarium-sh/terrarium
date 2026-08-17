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

impl ResolvedBox {
    /// The recipe this target names, parsed against the box's own directory
    /// with `env_file:` merged over `env:`. Not the config a boot runs: mounts
    /// are absolute here, but neither canonicalized nor checked to exist.
    pub(crate) fn parsed_recipe(&self) -> Result<config::Config> {
        let mut cfg = self.parsed_recipe_without_env_file()?;
        config::merge_env_file(&mut cfg)?;
        Ok(cfg)
    }

    /// The same read with the `env_file:` merge left to the caller.
    pub(crate) fn parsed_recipe_without_env_file(&self) -> Result<config::Config> {
        match &self.source {
            Source::Pinned => config::load_path(&self.bx.recipe(), self.bx.project_dir()),
            Source::File(r) | Source::Manifest(r) => {
                config::parse_recipe(&r.text, self.bx.project_dir(), &r.from)
            }
        }
    }
}

/// The box `name` — or the directory's only one — which must be set up already.
pub fn resolve_pinned_box(project_dir: &Path, name: Option<&str>) -> Result<BoxRef> {
    resolve_box(project_dir, name, true)
}

/// The box `name`, set up or not.
pub fn resolve_any_box(project_dir: &Path, name: Option<&str>) -> Result<BoxRef> {
    resolve_box(project_dir, name, false)
}

fn resolve_box(project_dir: &Path, name: Option<&str>, must_exist: bool) -> Result<BoxRef> {
    Ok(resolve(name, project_dir, Purpose::Operate { must_exist })?.bx)
}

#[derive(Clone, Copy)]
enum Purpose<'a> {
    Setup { cwd: &'a Path },
    Show { cwd: &'a Path },
    Boot { cwd: &'a Path },
    Operate { must_exist: bool },
}

impl<'a> Purpose<'a> {
    fn cwd(self) -> Option<&'a Path> {
        match self {
            Purpose::Setup { cwd } | Purpose::Show { cwd } | Purpose::Boot { cwd } => Some(cwd),
            Purpose::Operate { .. } => None,
        }
    }
}

/// The one wording for a recipe path handed to a verb that takes names only.
fn recipe_path_refused(path: &str) -> anyhow::Error {
    anyhow!(
        "'{path}' is a recipe path - this command takes a box name \
         (`terra {path} setup` is what reads and pins the file)"
    )
}

/// A BOX argument read for pinning: the recipe to pin. A typed path pins its
/// file; a name pins what the manifest chose - or the box's own pin when the
/// manifest is silent.
pub fn resolve_for_setup(arg: Option<&str>, project_dir: &Path, cwd: &Path) -> Result<ResolvedBox> {
    resolve(arg, project_dir, Purpose::Setup { cwd })
}

/// A BOX argument read for display: the recipe a boot would run, pinned
/// nowhere. A typed path is read. The box's own pin outranks the manifest's
/// choice, and a broken manifest is tolerated.
pub fn resolve_for_show(arg: Option<&str>, project_dir: &Path, cwd: &Path) -> Result<ResolvedBox> {
    resolve(arg, project_dir, Purpose::Show { cwd })
}

/// A BOX argument read for a boot: the recipe the box already pinned, or - for
/// a box not set up yet - the one the manifest or a typed path names. A missing
/// recipe reads as "no box".
pub fn resolve_for_boot(arg: Option<&str>, project_dir: &Path, cwd: &Path) -> Result<ResolvedBox> {
    resolve(arg, project_dir, Purpose::Boot { cwd })
}

/// The one resolution: a BOX argument, and which [`Purpose`] reads it, become
/// the box and where its recipe comes from.
fn resolve(arg: Option<&str>, project_dir: &Path, purpose: Purpose) -> Result<ResolvedBox> {
    let manifest = match purpose {
        Purpose::Setup { .. } => config::load_manifest(project_dir)?,
        Purpose::Show { .. } | Purpose::Boot { .. } | Purpose::Operate { .. } => {
            config::load_manifest_or_warn(project_dir)
        }
    };
    let name = match arg {
        None => default_box_name(project_dir, manifest.as_ref())?,
        Some(arg) => match BoxArg::parse(arg)? {
            BoxArg::Name(name) => name,
            BoxArg::RecipePath { path, name } => {
                let Some(cwd) = purpose.cwd() else {
                    return Err(recipe_path_refused(&path));
                };
                let recipe =
                    read_recipe(&path, cwd)?.ok_or_else(|| no_such_recipe(&path, &path, cwd))?;
                return Ok(ResolvedBox {
                    bx: BoxRef::resolve(project_dir, &name)?,
                    source: Source::File(recipe),
                    manifest_divergence: None,
                });
            }
        },
    };

    let bx = BoxRef::resolve(project_dir, &name)?;
    let source = source_for_name(&bx, purpose, manifest.as_ref())?;
    let manifest_divergence = manifest_divergence(&bx, purpose, &source, manifest.as_ref());
    Ok(ResolvedBox {
        bx,
        source,
        manifest_divergence,
    })
}

/// The manifest's recipe path, when it differs from the box's pin.
fn manifest_divergence(
    bx: &BoxRef,
    purpose: Purpose,
    source: &Source,
    manifest: Option<&config::Manifest>,
) -> Option<PathBuf> {
    match purpose {
        Purpose::Show { .. } => {}
        Purpose::Setup { .. } | Purpose::Boot { .. } | Purpose::Operate { .. } => return None,
    }
    match source {
        Source::Pinned => {}
        Source::File(_) | Source::Manifest(_) => return None,
    }
    let reference = manifest?.boxes.get(bx.name())?;
    let chosen = read_recipe(reference, bx.project_dir()).ok()??;
    let pinned = std::fs::read_to_string(bx.recipe()).ok()?;
    (chosen.text != pinned).then_some(chosen.from)
}

/// The recipe a *name* resolves to - the box's own pin, or the one the manifest
/// chose for it.
fn source_for_name(
    bx: &BoxRef,
    purpose: Purpose,
    manifest: Option<&config::Manifest>,
) -> Result<Source> {
    let (name, project_dir) = (bx.name(), bx.project_dir());
    let pinned = bx.recipe().exists();

    match purpose {
        Purpose::Operate { must_exist } => {
            if must_exist && !pinned {
                return Err(no_such_box(project_dir, Some(name), manifest));
            }
            Ok(Source::Pinned)
        }
        Purpose::Setup { .. } => {
            chosen_recipe(bx, manifest, pinned)?.ok_or_else(|| nothing_to_run(bx, manifest))
        }
        Purpose::Show { .. } | Purpose::Boot { .. } => {
            if pinned {
                return Ok(Source::Pinned);
            }
            chosen_recipe(bx, manifest, pinned)?.ok_or_else(|| {
                let missing = nothing_to_run(bx, manifest);
                match purpose {
                    Purpose::Boot { .. } => {
                        missing.context(no_such_box(project_dir, Some(name), manifest).to_string())
                    }
                    _ => missing,
                }
            })
        }
    }
}

/// `Ok(None)` is no recipe behind this name at all; `Err` only for one that is
/// there and could not be read.
fn chosen_recipe(
    bx: &BoxRef,
    manifest: Option<&config::Manifest>,
    pinned: bool,
) -> Result<Option<Source>> {
    match manifest.and_then(|m| m.boxes.get(bx.name())) {
        Some(reference) => Ok(read_recipe(reference, bx.project_dir())?.map(Source::Manifest)),
        None => Ok(pinned.then_some(Source::Pinned)),
    }
}

#[must_use]
fn nothing_to_run(bx: &BoxRef, manifest: Option<&config::Manifest>) -> anyhow::Error {
    let reference = manifest
        .and_then(|m| m.boxes.get(bx.name()))
        .map_or(bx.name(), String::as_str);
    no_such_recipe(bx.name(), reference, bx.project_dir())
}

pub(crate) fn default_box_name(
    project_dir: &Path,
    manifest: Option<&config::Manifest>,
) -> Result<String> {
    match &list_known_names(project_dir, manifest)[..] {
        [] => Err(no_such_box(project_dir, None, manifest)),
        [one] => Ok(one.clone()),
        // Several declared, none set up: they are declarations, and the error
        // for that names the manifest they came from.
        _ if state::existing_names(project_dir).is_empty() => {
            Err(no_such_box(project_dir, None, manifest))
        }
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
) -> Vec<String> {
    let mut names = state::existing_names(project_dir);
    for name in manifest.iter().flat_map(|m| m.boxes.keys()) {
        if !names.contains(name) {
            names.push(name.clone());
        }
    }
    names.sort();
    names
}

/// "This directory has no such box" - the one error for it, with the manifest
/// named when it declares what the directory has.
#[must_use]
fn no_such_box(
    project_dir: &Path,
    name: Option<&str>,
    manifest: Option<&config::Manifest>,
) -> anyhow::Error {
    let hint = match (name, &manifest) {
        (Some(n), Some(m)) if m.boxes.contains_key(n) => format!(
            "{} declares it, but it has never been set up: `terra {n} setup`",
            config::MANIFEST_FILE
        ),
        (None, Some(m)) if !m.boxes.is_empty() => format!(
            "{} declares {}, and none is set up yet: `terra <box> setup`",
            config::MANIFEST_FILE,
            m.boxes.keys().cloned().collect::<Vec<_>>().join(", ")
        ),
        _ => format!(
            "`terra <box> setup` makes one, from {} or a recipe path",
            config::MANIFEST_FILE
        ),
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
    let path = config::recipe_path(Path::new(reference), source_dir)?;
    if !path.exists() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(Some(Recipe { from: path, text }))
}

/// The one error for a recipe that is not there.
#[must_use]
pub(crate) fn no_such_recipe(arg: &str, reference: &str, source_dir: &Path) -> anyhow::Error {
    if !is_path(reference) {
        return anyhow!(
            "no recipe for '{arg}': a bare word names a box, and a recipe file is \
             named by path\n(`terra ./{arg}.yaml setup`, or a {MANIFEST_FILE} entry)"
        );
    }
    let tried = match config::recipe_path(Path::new(reference), source_dir) {
        Ok(p) => p.display().to_string(),
        Err(e) => return e,
    };
    if reference == arg {
        anyhow!("config not found: {tried}")
    } else {
        anyhow!(
            "config not found: {tried}\n\
             (box '{arg}' in {MANIFEST_FILE} points at '{reference}')"
        )
    }
}

pub(crate) fn names_recipe_file(arg: &str) -> bool {
    Path::new(arg)
        .extension()
        .is_some_and(|e| e == "yaml" || e == "yml")
}

pub(crate) fn is_path(arg: &str) -> bool {
    arg.starts_with(['.', '/', '~'])
        || arg.contains(std::path::is_separator)
        || names_recipe_file(arg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`config::recipe_path`] as this module's callers spell it.
    fn recipe_path(reference: &str, source_dir: &Path) -> Result<PathBuf> {
        config::recipe_path(Path::new(reference), source_dir)
    }

    /// A bare word is a box, never a file: there is no directory of profiles it
    /// could resolve into, so a recipe reaches terra by path alone.
    #[test]
    fn a_bare_word_names_no_recipe_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pi-dev.yaml"), "hw:\n  cpus: 1\n").unwrap();
        assert!(matches!(BoxArg::parse("pi-dev").unwrap(), BoxArg::Name(n) if n == "pi-dev"));
        assert!(read_recipe("pi-dev", dir.path()).unwrap().is_none());
        let err = no_such_recipe("pi-dev", "pi-dev", dir.path()).to_string();
        assert!(err.contains("named by path"), "{err}");
        assert!(
            err.contains("terra ./pi-dev.yaml setup"),
            "the fix is spelled out: {err}"
        );
    }

    #[test]
    fn dotted_path_is_local() {
        let p = recipe_path("./pi-dev.yaml", Path::new("/proj")).unwrap();
        assert_eq!(p, PathBuf::from("/proj/pi-dev.yaml"));
    }

    #[test]
    fn absolute_path_is_kept() {
        let p = recipe_path("/etc/x.yaml", Path::new("/proj")).unwrap();
        assert_eq!(p, PathBuf::from("/etc/x.yaml"));
    }

    #[test]
    fn tilde_expands() {
        let p = recipe_path("~/.terra/x.yaml", Path::new("/proj")).unwrap();
        assert_eq!(p, std::env::home_dir().unwrap().join(".terra/x.yaml"));
    }

    /// A bare `ci.yaml` means the file in front of you - the spelling *is* a
    /// recipe filename, and [`crate::name::validate_box_name`] refuses it as a
    /// name for the same reason.
    #[test]
    fn a_bare_yaml_filename_is_a_path() {
        for file in ["ci.yaml", "ci.yml"] {
            assert!(is_path(file), "{file}");
            let p = recipe_path(file, Path::new("/proj")).unwrap();
            assert_eq!(p, Path::new("/proj").join(file));
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

        let t = resolve_for_setup(Some("dev"), dir.path(), dir.path()).unwrap();
        let Source::Manifest(r) = &t.source else {
            panic!("the manifest chose this recipe, so the source must say so")
        };
        assert_eq!(r.from, dir.path().join("dev-recipe.yaml"));

        let e = resolve_for_setup(Some("other"), dir.path(), dir.path()).unwrap_err();
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
        // The same relative spelling, in the directory the shell happens to be
        // in: whichever of the two is read decides what the box runs.
        std::fs::write(elsewhere.join("dev.yaml"), "hw:\n  cpus: 9\n").unwrap();

        let t = resolve_for_setup(Some("dev"), &project, &elsewhere).unwrap();
        let Source::Manifest(r) = &t.source else {
            panic!("the manifest chose this recipe, so the source must say so")
        };
        assert_eq!(r.from, project.join("dev.yaml"));
        assert!(
            r.text.contains("cpus: 3"),
            "the shell's directory supplied the recipe: {}",
            r.text
        );

        // …and a reference that is missing beside the manifest is reported as
        // missing there, whatever the shell's directory happens to hold.
        std::fs::write(
            project.join(MANIFEST_FILE),
            "boxes:\n  dev: ./only-here.yaml\n",
        )
        .unwrap();
        std::fs::write(elsewhere.join("only-here.yaml"), "hw:\n  cpus: 9\n").unwrap();
        let e = resolve_for_setup(Some("dev"), &project, &elsewhere)
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

        // The box-name verbs (`exec`, `stop`, `rm`, `logs`) refuse it.
        let e = resolve_box(dir.path(), Some("./ci.yaml"), true).unwrap_err();
        assert!(format!("{e:#}").contains("box name"), "{e:#}");

        // The three that carry the shell's directory read the file it names.
        for read in [resolve_for_setup, resolve_for_show, resolve_for_boot] {
            let t = read(Some("./ci.yaml"), dir.path(), dir.path()).unwrap();
            let Source::File(r) = &t.source else {
                panic!("a typed path is the recipe, whatever the box has pinned")
            };
            assert_eq!(r.from, dir.path().join("ci.yaml"));
            assert_eq!(t.bx.name(), "ci", "the box takes the file's stem");
        }
    }

    /// The operate verbs read no recipe. `rm` addresses what is not there
    /// without complaint; the verbs that need a box get "no box", not "not
    /// running", for a name nobody set up.
    #[test]
    fn operating_on_a_box_resolves_lexically_unless_the_box_must_exist() {
        let dir = tempfile::tempdir().unwrap();
        assert!(resolve_box(dir.path(), Some("dev"), false).is_ok());
        let err = resolve_box(dir.path(), Some("dev"), true)
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

        let plain = no_such_recipe("./nope.yaml", "./nope.yaml", dir.path()).to_string();
        assert!(plain.contains("config not found"), "{plain}");
        assert!(!plain.contains(MANIFEST_FILE), "{plain}");

        let via_manifest = no_such_recipe("dev", "./gone.yaml", dir.path()).to_string();
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
            resolve_for_boot(Some("dev"), dir.path(), dir.path()).unwrap_err()
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
        std::fs::create_dir_all(bx.dir()).unwrap();
        std::fs::write(bx.recipe(), "hw:\n  cpus: 1\n").unwrap();
        std::fs::write(
            dir.path().join(MANIFEST_FILE),
            "boxes:\n  dev: ./dev.yaml\n",
        )
        .unwrap();

        // The same recipe by both routes is no divergence: a pin the manifest
        // agrees with is what a settled project looks like.
        std::fs::write(dir.path().join("dev.yaml"), "hw:\n  cpus: 1\n").unwrap();
        let agreed = resolve_for_show(Some("dev"), dir.path(), dir.path()).unwrap();
        assert!(matches!(agreed.source, Source::Pinned));
        assert_eq!(agreed.manifest_divergence, None);

        // …and an edited manifest is named, with the file that would win.
        std::fs::write(dir.path().join("dev.yaml"), "hw:\n  cpus: 8\n").unwrap();
        let diverged = resolve_for_show(Some("dev"), dir.path(), dir.path()).unwrap();
        assert!(
            matches!(diverged.source, Source::Pinned),
            "the pin is still what a boot runs"
        );
        assert_eq!(
            diverged.manifest_divergence,
            Some(dir.path().join("dev.yaml")),
            "the recipe `terra setup` would pin instead goes unreported"
        );

        // Every other purpose is silent: `setup` re-pins rather than reporting,
        // a boot runs the pin, and the operating verbs read no recipe at all.
        assert_eq!(
            resolve_for_setup(Some("dev"), dir.path(), dir.path())
                .unwrap()
                .manifest_divergence,
            None
        );
        assert_eq!(
            resolve_for_boot(Some("dev"), dir.path(), dir.path())
                .unwrap()
                .manifest_divergence,
            None
        );

        // A typed path is the recipe, so there is nothing for it to diverge from.
        assert_eq!(
            resolve_for_show(Some("./dev.yaml"), dir.path(), dir.path())
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
        std::fs::create_dir_all(bx.dir()).unwrap();
        std::fs::write(bx.recipe(), "hw:\n  cpus: 1\n").unwrap();

        // The box-name verbs - `stop`, `rm`, `logs`, `exec`, `cp`.
        assert!(resolve_box(dir.path(), Some("dev"), true).is_ok());
        assert!(
            resolve_box(dir.path(), None, true).is_ok(),
            "and by default"
        );

        // …and a boot, which runs the pinned recipe the manifest has no say in.
        let started = resolve_for_boot(Some("dev"), dir.path(), dir.path()).unwrap();
        assert!(matches!(started.source, Source::Pinned));

        // `setup` refuses, naming the file to fix.
        let chain = format!(
            "{:#}",
            resolve_for_setup(Some("dev"), dir.path(), dir.path())
                .expect_err("setup must not pin from a manifest it could not read")
        );
        assert!(chain.contains("failed to parse"), "{chain}");
        assert!(chain.contains(MANIFEST_FILE), "{chain}");
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
            resolve_for_boot(Some("dev"), dir.path(), dir.path()).unwrap_err()
        );
        assert!(chain.contains("reading"), "{chain}");
        assert!(
            !chain.contains("never been set up"),
            "an unreadable recipe was misreported as a box that was never set up: {chain}"
        );
    }
}
