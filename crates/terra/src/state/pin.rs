//! A box's pin: the recipe it was set up from, and the host paths that recipe was approved for.

use super::{
    BoxRef, ORIGIN_FILE, get_box_home_path, get_project_state_dir, list_boxes_in, read_origin,
};
use crate::recipe::{Recipe, read_recipe_text};
use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// The one user-authored file in a box's state dir.
pub const RECIPE_FILE: &str = "recipe.yaml";

pub const PINNED_PATHS_FILE: &str = "pinned-paths.yaml";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PinnedPaths {
    mounts: Vec<PathBuf>,
    env_file: Option<PathBuf>,
}

impl PinnedPaths {
    pub(crate) fn from_recipe(recipe: &Recipe) -> Self {
        Self {
            mounts: recipe
                .mounts
                .iter()
                .map(|mount| mount.host.clone())
                .collect(),
            env_file: recipe.env_file.clone(),
        }
    }
}

impl BoxRef {
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

    pub(crate) fn verify_pinned_paths(&self, current: &PinnedPaths) -> Result<()> {
        anyhow::ensure!(
            self.load_pinned_paths()?.as_ref() == Some(current),
            "a share or env_file moved since it was pinned - run `terra {} setup` again",
            self.get_name()
        );
        Ok(())
    }
}

/// Write the pin files that change into `dir`, and name them.
pub(crate) fn write_pin(
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

/// ponytail: only current pins count; tracking past writable shares requires a persistent share history.
pub(crate) fn list_pinned_recipes_across_boxes(
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
    fn list_pinned_recipes_across_boxes_in_the_directory() {
        let _home = crate::sys::TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        assert_eq!(
            list_pinned_recipes_across_boxes(project).unwrap(),
            Vec::<(PathBuf, String)>::new()
        );

        for (name, text) in [("a", "hw:\n  cpus: 1\n"), ("b", "hw:\n  cpus: 2\n")] {
            let b = BoxRef::resolve(project, name).unwrap();
            std::fs::create_dir_all(b.get_dir()).unwrap();
            std::fs::write(b.get_dir().join(crate::state::RECIPE_FILE), text).unwrap();
        }
        // A box directory without a pinned recipe (never set up) is skipped.
        std::fs::create_dir_all(BoxRef::resolve(project, "c").unwrap().get_dir()).unwrap();

        let recipes = list_pinned_recipes_across_boxes(project).unwrap();
        assert_eq!(recipes.len(), 2, "{recipes:?}");
        assert!(recipes.iter().any(|(_, recipe)| recipe.contains("cpus: 1")));
        assert!(recipes.iter().any(|(_, recipe)| recipe.contains("cpus: 2")));
    }
}
