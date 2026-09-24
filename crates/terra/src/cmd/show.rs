//! `terra show` - print the fully-resolved config a boot would use.

use crate::policy::mount;
use crate::{config, render, resolve};
use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

pub fn run(
    args: &crate::cli::ShowArgs,
    name: Option<&str>,
    project_dir: &Path,
    cwd: &Path,
) -> Result<ExitCode> {
    let target = resolve::resolve(
        name,
        project_dir,
        Some(cwd),
        resolve::Existence::MayBeMissing,
    )?;
    if let Some(from) = &target.manifest_divergence {
        eprintln!(
            "terra: note: this is {}'s pinned recipe, which is what a boot runs - \
             {} names {} instead, and `terra {} setup` would pin that one",
            target.bx.get_name(),
            config::MANIFEST_FILE,
            render::escape_printable_path(from),
            target.bx.get_name()
        );
    }

    let is_pinned = matches!(target.source, resolve::Source::Pinned);
    let mut cfg = target.parse_recipe_without_env_file()?;
    match mount::resolve_mounts(&cfg, &target.bx) {
        Ok(mounts) => {
            for s in mount::find_sensitive_mounts(&mounts) {
                let access = if s.mount.readonly {
                    "read-only"
                } else {
                    "read-write"
                };
                eprintln!(
                    "terra: warning: mount '{}' shares sensitive host {} ({access}) with the sandbox",
                    render::escape_printable_path(&s.mount.host),
                    s.category
                );
            }
            cfg.mounts = mounts;
        }
        Err(e) if is_pinned => return Err(e),
        Err(e) => eprintln!("terra: warning: `terra setup` would refuse this recipe:\n{e:#}"),
    }
    let env_values = config::resolve_env_file(&mut cfg).and_then(|()| {
        if is_pinned {
            mount::verify_pinned_paths(&target.bx, &mount::PinnedPaths::from_config(&cfg))?;
        }
        config::merge_env_file(&mut cfg)
    });
    if let Err(e) = env_values {
        if is_pinned {
            return Err(e);
        }
        eprintln!(
            "terra: warning: {e:#}\n\
             terra: printing the recipe without those values - a boot would refuse it"
        );
    }
    let target;
    let to_show = if args.with_env_values {
        &cfg
    } else {
        target = render::redact_config_env(&cfg);
        &target
    };
    let output = if args.json {
        render::render_config_json(to_show).context("serializing config to json")?
    } else {
        render::render_config_yaml(to_show).context("serializing config")?
    };
    render::finish_stdout_write(std::io::stdout().lock().write_all(output.as_bytes()))?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{self, BoxRef};

    /// `show` is what a recipe is reviewed with before it is trusted, so it
    /// runs the checks that decide whether `terra setup` would take it - and
    /// reports rather than returns them, because a recipe whose mounts are not
    /// there yet is still worth reading. A recipe mounting terra's own state
    /// used to print clean and then be refused at the setup nobody had run yet.
    #[test]
    fn show_resolves_and_judges_the_mounts_a_boot_would_get() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(project.join("src")).unwrap();
        std::fs::create_dir_all(project.join("sub")).unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(&project, "dev").unwrap();

        // A mount of the box's own state is what `terra setup` refuses.
        let refused = config::parse_recipe(
            &format!(
                "mounts:\n  - host: {}\n    guest: /work\n",
                bx.get_dir().display()
            ),
            &project,
            Path::new("r.yaml"),
        )
        .unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        let err = mount::resolve_mounts(&refused, &bx)
            .expect_err("a mount of the box's own state must be reported")
            .to_string();
        assert!(err.contains("this box's own state"), "{err}");

        let mut ok = config::parse_recipe(
            "mounts:\n  - host: ./sub/../src\n    guest: /work\n",
            &project,
            Path::new("r.yaml"),
        )
        .unwrap();
        ok.mounts = mount::resolve_mounts(&ok, &bx).unwrap();
        assert_eq!(
            ok.mounts[0].host,
            std::fs::canonicalize(project.join("src")).unwrap()
        );
    }

    /// `show` is the verb a recipe is *reviewed* with, so a file the recipe
    /// merely names must not be able to stop it printing: an `env_file:` is
    /// commonly the one thing the reader of an unfamiliar recipe has not
    /// created yet, and refusing here sent them to read the YAML by hand -
    /// exactly the reading `show` exists to replace. Only the values go
    /// missing, and a warning says so.
    ///
    /// The other half is what makes the leniency safe to have: a pin exports
    /// those values into the guest, so `terra setup` still refuses the same
    /// recipe rather than pinning one whose environment is half there.
    #[tokio::test]
    async fn show_prints_a_recipe_whose_env_file_is_not_there_yet() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("dev.yaml"),
            "env:\n  MODEL: gpt-4o\nenv_file: ./secrets.env\n",
        )
        .unwrap();

        let show = crate::cli::ShowArgs {
            with_env_values: false,
            json: false,
        };
        run(&show, Some("./dev.yaml"), &project, &project)
            .expect("a recipe naming a dotenv nobody has created yet must still print");

        let err = crate::cmd::setup::run(
            &crate::cli::SetupArgs {
                trust_recipe: false,
                rebuild: false,
                dry_run: true,
            },
            Some("./dev.yaml"),
            &project,
            &project,
            false,
        )
        .await
        .expect_err("a pin must still refuse a dotenv it cannot read")
        .to_string();
        assert!(err.contains("resolving env file"), "{err}");

        // …and the file being there is not a thing `show` needs told twice:
        // the values are merged as a boot would merge them.
        std::fs::write(project.join("secrets.env"), "API_KEY=sk-1\n").unwrap();
        let target = resolve::resolve(
            Some("./dev.yaml"),
            &project,
            Some(&project),
            resolve::Existence::MayBeMissing,
        )
        .unwrap();
        let mut cfg = target.parse_recipe_without_env_file().unwrap();
        config::resolve_env_file(&mut cfg).unwrap();
        config::merge_env_file(&mut cfg).unwrap();
        assert_eq!(cfg.env["API_KEY"], "sk-1");
    }

    /// `show` promises the configuration a boot runs, and a boot refuses a pin
    /// whose share moved: it used to print the repointed target, a mount no
    /// boot would grant.
    #[test]
    fn show_refuses_a_pinned_recipe_whose_paths_moved() {
        let _home = crate::sys::TestHome::new();
        for recipe in [
            "mounts:\n  - host: ./share\n    guest: /work\n",
            "env_file: ./share/values.env\n",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let project = dir.path().join("project");
            let safe = dir.path().join("safe");
            let private = dir.path().join("private");
            std::fs::create_dir_all(&project).unwrap();
            std::fs::create_dir_all(&safe).unwrap();
            std::fs::create_dir_all(&private).unwrap();
            std::fs::write(safe.join("values.env"), "KEY=value\n").unwrap();
            std::fs::write(private.join("values.env"), [0xff]).unwrap();
            crate::sys::symlink_dir(&safe, project.join("share")).unwrap();

            let bx = BoxRef::resolve(&project, "dev").unwrap();
            std::fs::create_dir_all(bx.get_dir()).unwrap();
            std::fs::write(bx.get_dir().join(state::RECIPE_FILE), recipe).unwrap();
            let mut cfg = config::parse_recipe(recipe, &project, Path::new("dev.yaml")).unwrap();
            cfg.mounts = mount::resolve_mounts(&cfg, &bx).unwrap();
            config::resolve_env_file(&mut cfg).unwrap();
            std::fs::write(
                bx.get_dir().join(state::PINNED_PATHS_FILE),
                yaml_serde::to_string(&mount::PinnedPaths::from_config(&cfg)).unwrap(),
            )
            .unwrap();

            let show = crate::cli::ShowArgs {
                with_env_values: false,
                json: false,
            };
            assert!(run(&show, Some("dev"), &project, &project).is_ok());

            crate::sys::remove_directory_symlink(project.join("share")).unwrap();
            crate::sys::symlink_dir(&private, project.join("share")).unwrap();
            let err = run(&show, Some("dev"), &project, &project)
                .expect_err("a repointed path must not print clean")
                .to_string();
            assert!(err.contains("moved since it was pinned"), "{err}");
        }
    }

    #[test]
    fn show_prints_recipe_with_sensitive_mounts() {
        let home = crate::sys::TestHome::new();
        let ssh_dir = home.get_path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("dev.yaml"),
            format!(
                "mounts:\n  - host: {}\n    guest: /ssh\n    readonly: true\n",
                ssh_dir.display()
            ),
        )
        .unwrap();

        let show = crate::cli::ShowArgs {
            with_env_values: false,
            json: false,
        };
        assert!(run(&show, Some("./dev.yaml"), &project, &project).is_ok());
    }

    #[test]
    fn show_json_mode_renders_valid_json() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("dev.yaml"), "env:\n  SECRET: pass123\n").unwrap();

        let show = crate::cli::ShowArgs {
            with_env_values: false,
            json: true,
        };
        assert!(run(&show, Some("./dev.yaml"), &project, &project).is_ok());

        let show_with_env = crate::cli::ShowArgs {
            with_env_values: true,
            json: true,
        };
        assert!(run(&show_with_env, Some("./dev.yaml"), &project, &project).is_ok());
    }
}
