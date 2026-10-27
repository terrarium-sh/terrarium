//! Loading a resolved box's recipe, with its host paths resolved.

use super::resolve::{ResolvedRecipe, Source};
use super::{Recipe, load_path, merge_env_file, parse_recipe, resolve_env_file};
use crate::policy::mount;
use crate::state::{self, BoxRef};
use anyhow::Result;

impl ResolvedRecipe {
    /// Load the pinned recipe and verify its approved host paths.
    pub(crate) fn load_pinned_recipe(self) -> Result<(BoxRef, Recipe)> {
        let (mut recipe, paths) = self.load_recipe()?;
        self.bx.verify_pinned_paths(&paths)?;
        merge_env_file(&mut recipe)?;
        Ok((self.bx, recipe))
    }

    /// The recipe with its mounts and `env_file` resolved, and the host paths
    /// those would pin.
    pub(crate) fn load_recipe(&self) -> Result<(Recipe, state::PinnedPaths)> {
        self.bx.ensure_sockets_fit()?;
        crate::sys::validate_host_root()?;
        let mut recipe = self.parse_recipe_without_env_file()?;
        recipe.mounts = mount::resolve_mounts(&recipe, &self.bx)?;
        resolve_env_file(&mut recipe)?;
        let paths = state::PinnedPaths::from_recipe(&recipe);
        Ok((recipe, paths))
    }

    pub(crate) fn parse_recipe_without_env_file(&self) -> Result<Recipe> {
        match &self.source {
            Source::Pinned => load_path(
                &self.bx.get_dir().join(state::RECIPE_FILE),
                self.bx.get_project_dir(),
            ),
            Source::File(r) | Source::Manifest(r) | Source::Artifact(r) => {
                parse_recipe(&r.text, self.bx.get_project_dir(), &r.from)
            }
        }
    }
}
