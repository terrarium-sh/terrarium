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

    let mut cfg = target.parse_recipe_without_env_file()?;
    if let Err(e) =
        config::resolve_env_file(&mut cfg).and_then(|()| config::merge_env_file(&mut cfg))
    {
        eprintln!(
            "terra: warning: {e:#}\n\
             terra: printing the recipe without those values - a boot would refuse it"
        );
    }
    match mount::resolve_mounts(&cfg, &target.bx) {
        Ok(mounts) => {
            for s in mount::find_sensitive_mounts(&mounts) {
                let access = match s.mount.readonly {
                    true =>  "read-only",
                    false => "read-write"
                };
                eprintln!(
                    "terra: warning: mount '{}' shares sensitive host {} ({access}) with the sandbox",
                    render::escape_printable_path(&s.mount.host),
                    s.category
                );
            }
            cfg.mounts = mounts;
        }
        Err(e) => eprintln!("terra: warning: `terra setup` would refuse this recipe:\n{e:#}"),
    }
    let yaml = if args.with_env_values {
        yaml_serde::to_string(&cfg).context("serializing config")?
    } else {
        render::render_redacted_config_yaml(&cfg).context("serializing config")?
    };
    render::finish_stdout_write(std::io::stdout().lock().write_all(yaml.as_bytes()))?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::BoxRef;

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
    #[test]
    fn show_prints_a_recipe_whose_env_file_is_not_there_yet() {
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
        };
        assert!(run(&show, Some("./dev.yaml"), &project, &project).is_ok());
    }
}
