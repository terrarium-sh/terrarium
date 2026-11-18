//! A box's applied recipe: the recipe it was set up from, and the host paths that recipe was approved for.

use super::{
    BoxRef, ORIGIN_FILE, get_box_home_path, get_project_state_dir, list_boxes_in, read_origin,
};
use crate::recipe::{Recipe, mount_host_paths, read_recipe_text};
use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// The one user-authored file in a box's state dir.
pub const RECIPE_FILE: &str = "recipe.yaml";

pub const PINNED_PATHS_FILE: &str = "pinned-paths.yaml";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PinnedPaths {
    #[serde(default)]
    pub(crate) setup_mounts: Vec<PathBuf>,
    mounts: Vec<PathBuf>,
    env_file: Option<PathBuf>,
}

impl PinnedPaths {
    pub(crate) fn new(recipe: &Recipe, setup_mounts: Vec<PathBuf>) -> Self {
        Self {
            setup_mounts,
            mounts: mount_host_paths(&recipe.workload.mounts).cloned().collect(),
            env_file: recipe.env_file.clone(),
        }
    }

    pub(crate) fn for_setup(recipe: &Recipe) -> Self {
        Self::new(
            recipe,
            mount_host_paths(&recipe.setup.mounts).cloned().collect(),
        )
    }

    pub(crate) fn for_kept_root(recipe: &Recipe, existing: Option<&Self>) -> Self {
        let setup_mounts = existing.map_or_else(Vec::new, |pins| pins.setup_mounts.clone());
        Self::new(recipe, setup_mounts)
    }

    pub(crate) fn matches_workload(&self, recipe: &Recipe) -> bool {
        self.env_file == recipe.env_file
            && mount_host_paths(&recipe.workload.mounts).eq(&self.mounts)
    }
}

impl BoxRef {
    pub(crate) fn has_applied_recipe(&self) -> bool {
        self.get_dir().join(RECIPE_FILE).exists()
    }

    pub(crate) fn load_applied_recipe(&self) -> Result<Recipe> {
        crate::recipe::load_path(&self.get_dir().join(RECIPE_FILE), self.get_project_dir())
            .with_context(|| {
                format!(
                    "reading {self}'s applied recipe; update the source recipe and apply it with \
                     `terra <recipe-path> setup` or a terra.yaml alias"
                )
            })
    }

    pub(crate) fn load_pinned_paths(&self) -> Result<Option<PinnedPaths>> {
        let path = self.get_dir().join(PINNED_PATHS_FILE);
        match read_recipe_text(&path) {
            Ok(text) => yaml_serde::from_str(&text)
                .map(Some)
                .with_context(|| format!("reading {}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub(crate) fn verify_workload_pins(&self, recipe: &Recipe) -> Result<()> {
        let pinned = self.load_pinned_paths()?.with_context(|| {
            format!(
                "{PINNED_PATHS_FILE} is missing - run `terra {} setup` to approve the host paths",
                self.get_name()
            )
        })?;
        anyhow::ensure!(
            pinned.matches_workload(recipe),
            "a share or env_file moved since the last setup - run `terra {} setup` again",
            self.get_name()
        );
        Ok(())
    }
}

/// Write the applied recipe files that change into `dir`, and name them.
pub(crate) fn write_applied_recipe(
    dir: &Path,
    recipe: Option<&str>,
    pinned_paths: Option<&PinnedPaths>,
) -> Result<Vec<&'static str>> {
    let mut written = Vec::new();
    if let Some(text) = recipe {
        let path = dir.join(RECIPE_FILE);
        crate::vm::image::staged_write(&path, |out| {
            out.write_all(text.as_bytes())
                .with_context(|| format!("recording {}", path.display()))
        })?;
        written.push(RECIPE_FILE);
    }
    if let Some(paths) = pinned_paths {
        let path = dir.join(PINNED_PATHS_FILE);
        crate::vm::image::staged_write(&path, |out| {
            yaml_serde::to_writer(&mut *out, paths).context("serializing pinned paths")
        })?;
        written.push(PINNED_PATHS_FILE);
    }
    Ok(written)
}

/// ponytail: only current applied recipes count; tracking past writable shares requires a persistent share history.
pub(crate) fn list_applied_recipes_across_boxes(
    project_dir: &Path,
) -> Result<Vec<(PathBuf, String)>> {
    let current_state = get_project_state_dir(project_dir)?;
    let mut recipes = Vec::new();
    for (_, project_state) in list_boxes_in(&get_box_home_path()?)? {
        let origin = if project_state == current_state {
            Some(project_dir.to_path_buf())
        } else {
            read_origin(&project_state)
        };
        for (_, box_dir) in list_boxes_in(&project_state)? {
            let recipe = match read_recipe_text(&box_dir.join(RECIPE_FILE)) {
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
                    project_state.join(ORIGIN_FILE).display()
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

    /// Every box of the directory answers, not just the one being set up - a
    /// sibling's writable share could have authored a new box's recipe.
    #[test]
    fn list_applied_recipes_across_boxes_in_the_directory() {
        let _home = crate::sys::TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        assert_eq!(
            list_applied_recipes_across_boxes(project).unwrap(),
            Vec::<(PathBuf, String)>::new()
        );

        for (name, text) in [("a", "hw:\n  cpus: 1\n"), ("b", "hw:\n  cpus: 2\n")] {
            let b = BoxRef::resolve(project, name).unwrap();
            std::fs::create_dir_all(b.get_dir()).unwrap();
            std::fs::write(b.get_dir().join(crate::state::RECIPE_FILE), text).unwrap();
        }
        // A box directory without an applied recipe (never set up) is skipped.
        std::fs::create_dir_all(BoxRef::resolve(project, "c").unwrap().get_dir()).unwrap();

        let recipes = list_applied_recipes_across_boxes(project).unwrap();
        assert_eq!(recipes.len(), 2, "{recipes:?}");
        assert!(recipes.iter().any(|(_, recipe)| recipe.contains("cpus: 1")));
        assert!(recipes.iter().any(|(_, recipe)| recipe.contains("cpus: 2")));
    }
}
