//! Loading a resolved box's recipe, with its host paths resolved.

use super::resolve::{ResolvedRecipe, Source};
use super::{Recipe, merge_env_file, parse_recipe, resolve_env_file};
use crate::policy::mount;
use crate::state::BoxRef;
use anyhow::Result;

impl ResolvedRecipe {
    /// Load the applied recipe and verify its approved host paths.
    pub(crate) fn load_applied_recipe(self) -> Result<(BoxRef, Recipe)> {
        let mut recipe = self.load_workload_paths()?;
        self.bx.verify_workload_pins(&recipe)?;
        merge_env_file(&mut recipe)?;
        Ok((self.bx, recipe))
    }

    pub(crate) fn load_workload_paths(&self) -> Result<Recipe> {
        self.bx.ensure_sockets_fit()?;
        crate::sys::validate_host_root()?;
        let mut recipe = self.parse_recipe_without_env_file()?;
        mount::resolve_workload_mounts(&mut recipe, &self.bx)?;
        resolve_env_file(&mut recipe)?;
        Ok(recipe)
    }

    pub(crate) fn parse_recipe_without_env_file(&self) -> Result<Recipe> {
        match &self.source {
            Source::Applied => self.bx.load_applied_recipe(),
            Source::File(r) | Source::Manifest(r) | Source::Artifact(r) => {
                parse_recipe(&r.text, self.bx.get_project_dir(), &r.from)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state;

    /// Setup sources are approved again by setup, but normal boots need only
    /// the workload sources and must still refuse a changed workload target.
    #[test]
    fn workload_loading_ignores_removed_or_retargeted_setup_sources() {
        let _home = crate::sys::TestHome::new();
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        let setup_source = directory.path().join("setup");
        let workload_source = directory.path().join("workload");
        let replacement = directory.path().join("replacement");
        for path in [&project, &setup_source, &workload_source, &replacement] {
            std::fs::create_dir(path).unwrap();
        }
        crate::sys::symlink_dir(&setup_source, project.join("setup")).unwrap();
        crate::sys::symlink_dir(&workload_source, project.join("workload")).unwrap();
        let bx = BoxRef::resolve(&project, "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        let text = "network: {enabled: false}\n\
                    setup: {mounts: [{host: ./setup, guest: /setup}]}\n\
                    workload: {mounts: [{host: ./workload, guest: /work}]}\n";
        std::fs::write(bx.get_dir().join(state::RECIPE_FILE), text).unwrap();
        let target = || ResolvedRecipe {
            bx: bx.clone(),
            source: Source::Applied,
            manifest: None,
        };
        let approve_build = || crate::approval::approve_by_hand(target(), true, false);
        approve_build()
            .unwrap()
            .write_applied_recipe(bx.get_dir())
            .unwrap();

        crate::sys::remove_directory_symlink(project.join("setup")).unwrap();
        std::fs::remove_dir(&setup_source).unwrap();
        target().load_applied_recipe().unwrap();
        assert_eq!(
            crate::cmd::show::run(
                &crate::cli::ShowArgs {
                    with_env_values: false,
                    json: false,
                },
                Some("dev"),
                &project,
                &project,
            )
            .unwrap(),
            std::process::ExitCode::SUCCESS
        );
        assert!(approve_build().is_err());

        crate::sys::symlink_dir(&replacement, project.join("setup")).unwrap();
        let (_, workload_recipe) = target().load_applied_recipe().unwrap();
        assert_eq!(workload_recipe.setup.mounts[0].host, project.join("setup"));
        assert!(approve_build().unwrap().pinned_paths.is_some());

        crate::sys::remove_directory_symlink(project.join("workload")).unwrap();
        crate::sys::symlink_dir(&replacement, project.join("workload")).unwrap();
        let error = target().load_applied_recipe().unwrap_err();
        assert!(error.to_string().contains("moved since the last setup"));
    }
}
