//! Build custom VM launches and protect launcher assets from guest-written shares.

use super::boot::{BootSpec, VM_PROCESS_FLAG_ARG};
use super::launcher_config::LauncherConfig;
use crate::config;
use crate::policy::mount;
use crate::state::{self, BoxRef};
use crate::sys::canonicalize_existing_prefix;
use anyhow::{Context as _, Result, ensure};
use std::path::Path;
use std::process::Command;

pub(super) fn custom_command(
    init: &Path,
    exe: &Path,
    spec: &BootSpec,
    bx: &BoxRef,
) -> Result<Command> {
    ensure!(init.is_absolute(), "VM initializer path must be absolute");
    ensure!(exe.is_absolute(), "terra executable path must be absolute");
    ensure!(
        spec.project_dir.is_absolute(),
        "project path must be absolute"
    );
    ensure!(bx.get_dir().is_absolute(), "box path must be absolute");

    let mode = match spec.mode {
        terra_protocol::PlanMode::Create => "create",
        terra_protocol::PlanMode::Run => "run",
    };
    let mut command = Command::new(init);
    command
        .arg("--config")
        .arg(bx.get_dir().join(state::RECIPE_FILE))
        .arg("--project")
        .arg(&spec.project_dir)
        .arg("--mode")
        .arg(mode)
        .arg("--")
        .arg(exe)
        .arg(VM_PROCESS_FLAG_ARG)
        .arg(bx.get_dir());
    Ok(command)
}

pub(super) fn validate_assets(
    launcher: &LauncherConfig,
    spec: &BootSpec,
    bx: &BoxRef,
) -> Result<()> {
    let assets: Vec<(&str, &Path)> = match launcher {
        LauncherConfig::Direct | LauncherConfig::Bwrap { policy: None, .. } => Vec::new(),
        LauncherConfig::Custom(path) => vec![("VM initializer", path)],
        LauncherConfig::Bwrap {
            policy: Some(path), ..
        } => vec![("Bubblewrap policy", path)],
    };
    if assets.is_empty() {
        return Ok(());
    }

    let recipes = mount::list_pinned_recipes_across_boxes(bx.get_project_dir())
        .context("checking pinned recipes for guest-writable launcher assets")?;
    let box_home = state::get_box_home_path()?;
    for (kind, path) in assets {
        anyhow::ensure!(
            !lies_inside_share(path, &box_home),
            "{kind} '{}' is inside writable box state; move it outside {}",
            crate::render::escape_printable_path(path),
            crate::render::escape_printable_path(&box_home),
        );
        for share in spec.cfg.mounts.iter().filter(|mount| !mount.readonly) {
            if lies_inside_share(path, &share.host) {
                anyhow::bail!(
                    "{kind} '{}' is inside writable share '{}'; move it outside guest-writable shares",
                    crate::render::escape_printable_path(path),
                    crate::render::escape_printable_path(&share.host),
                );
            }
        }
        for (project_dir, recipe) in &recipes {
            let share = mount::find_writable_mount_containing(path, recipe, project_dir)
                .with_context(|| {
                    format!(
                        "checking pinned recipes for {kind} '{}'",
                        crate::render::escape_printable_path(path)
                    )
                })?;
            let lexical_share = config::list_declared_writable_shares(recipe, project_dir)
                .context("checking pinned writable share paths")?
                .into_iter()
                .find(|share| lies_inside_share(path, share));
            if let Some(share) = share.or(lexical_share) {
                anyhow::bail!(
                    "{kind} '{}' is inside pinned writable share '{}'; move it outside guest-writable shares",
                    crate::render::escape_printable_path(path),
                    crate::render::escape_printable_path(&share),
                );
            }
        }
    }
    Ok(())
}

fn lies_inside_share(path: &Path, share: &Path) -> bool {
    let share = canonicalize_existing_prefix(share);
    path.ancestors().any(|ancestor| {
        ancestor.starts_with(&share) || canonicalize_existing_prefix(ancestor).starts_with(&share)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use std::path::PathBuf;
    use terra_protocol::PlanMode;

    fn spec(project_dir: &Path, mode: PlanMode) -> BootSpec {
        BootSpec {
            cfg: config::Config::default(),
            project_dir: project_dir.to_path_buf(),
            root: false,
            mode,
            foreground: false,
            builtin_bwrap: false,
        }
    }

    #[test]
    fn custom_command_passes_exact_path_arguments_for_create_and_run() {
        use std::ffi::OsString;

        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project ;$'é 中");
        let bx = BoxRef::from_state_dir(dir.path().join("box `whoami`"), &project);
        let init = dir.path().join("init ;$'é 中");
        let exe = dir.path().join("terra ;$'é 中");

        for (mode, spelling) in [(PlanMode::Create, "create"), (PlanMode::Run, "run")] {
            let command = custom_command(&init, &exe, &spec(&project, mode), &bx).unwrap();
            assert_eq!(command.get_program(), init.as_os_str());
            assert_eq!(
                command.get_args().map(OsString::from).collect::<Vec<_>>(),
                [
                    OsString::from("--config"),
                    bx.get_dir().join(state::RECIPE_FILE).into_os_string(),
                    OsString::from("--project"),
                    project.clone().into_os_string(),
                    OsString::from("--mode"),
                    OsString::from(spelling),
                    OsString::from("--"),
                    exe.clone().into_os_string(),
                    OsString::from(VM_PROCESS_FLAG_ARG),
                    bx.get_dir().as_os_str().to_os_string(),
                ]
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn custom_command_preserves_non_utf8_paths() {
        use std::os::unix::ffi::OsStringExt;

        let dir = tempfile::tempdir().unwrap();
        let odd = std::ffi::OsString::from_vec(b"raw-\xff".to_vec());
        let project = dir.path().join(&odd);
        let bx = BoxRef::from_state_dir(dir.path().join(&odd), &project);
        let init = dir.path().join(&odd);
        let exe = dir.path().join(&odd);
        let command = custom_command(&init, &exe, &spec(&project, PlanMode::Run), &bx).unwrap();
        let args = command.get_args().collect::<Vec<_>>();
        assert_eq!(args[1], bx.get_dir().join(state::RECIPE_FILE).as_os_str());
        assert_eq!(args[3], project.as_os_str());
        assert_eq!(args[7], exe.as_os_str());
        assert_eq!(args[9], bx.get_dir().as_os_str());
    }

    #[cfg(unix)]
    #[test]
    fn custom_script_can_exec_vm_with_stdin_intact() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;
        use std::process::Stdio;

        let dir = tempfile::tempdir().unwrap();
        let init = dir.path().join("initializer");
        let exe = dir.path().join("mock terra");
        std::fs::write(
            &init,
            b"#!/bin/sh\nwhile [ \"$1\" != '--' ]; do shift; done\nshift\nexec \"$@\"\n",
        )
        .unwrap();
        std::fs::write(&exe, b"#!/bin/sh\ncat\n").unwrap();
        for path in [&init, &exe] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bx = BoxRef::from_state_dir(dir.path().join("box"), dir.path());
        let mut command =
            custom_command(&init, &exe, &spec(dir.path(), PlanMode::Run), &bx).unwrap();
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"boot JSON stays on stdin")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"boot JSON stays on stdin");
    }

    #[test]
    fn assets_inside_current_or_sibling_writable_shares_are_refused() {
        let _home = crate::sys::TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        let share = project.join("share");
        std::fs::create_dir_all(&share).unwrap();
        let bx = BoxRef::resolve(&project, "dev").unwrap();
        let asset = share.join("initializer");
        let launcher = LauncherConfig::Custom(asset.clone());
        let mut current = spec(&project, PlanMode::Run);
        current.cfg.mounts.push(config::Mount {
            host: share.clone(),
            guest: PathBuf::from("/share"),
            readonly: false,
        });
        let error = validate_assets(&launcher, &current, &bx)
            .unwrap_err()
            .to_string();
        assert!(error.contains("writable share"), "{error}");

        current.cfg.mounts[0].readonly = true;
        validate_assets(&launcher, &current, &bx).unwrap();
        let sibling = BoxRef::resolve(&project, "sibling").unwrap();
        std::fs::create_dir_all(sibling.get_dir()).unwrap();
        let mut pinned = config::Config::default();
        pinned.mounts.push(config::Mount {
            host: share.clone(),
            guest: PathBuf::from("/share"),
            readonly: false,
        });
        std::fs::write(
            sibling.get_dir().join(state::RECIPE_FILE),
            yaml_serde::to_string(&pinned).unwrap(),
        )
        .unwrap();
        let error = validate_assets(&launcher, &current, &bx)
            .unwrap_err()
            .to_string();
        assert!(error.contains("pinned writable share"), "{error}");

        let policy = LauncherConfig::Bwrap {
            policy: Some(asset),
            allow_fallback: true,
        };
        let error = validate_assets(&policy, &current, &bx)
            .unwrap_err()
            .to_string();
        assert!(error.contains("Bubblewrap policy"), "{error}");

        for launcher in [
            LauncherConfig::Custom(bx.get_dir().join("initializer")),
            LauncherConfig::Bwrap {
                policy: Some(sibling.get_dir().join("policy.yml")),
                allow_fallback: true,
            },
        ] {
            let error = validate_assets(&launcher, &current, &bx).unwrap_err();
            assert!(error.to_string().contains("writable box state"), "{error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_inside_a_share_cannot_hide_a_launcher_asset() {
        let _home = crate::sys::TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        let share = project.join("share");
        std::fs::create_dir_all(&share).unwrap();
        let outside = dir.path().join("outside");
        std::fs::write(&outside, b"launcher").unwrap();
        let asset = share.join("launcher");
        std::os::unix::fs::symlink(&outside, &asset).unwrap();
        let bx = BoxRef::resolve(&project, "dev").unwrap();
        let mut spec = spec(&project, PlanMode::Run);
        spec.cfg.mounts.push(config::Mount {
            host: share.clone(),
            guest: PathBuf::from("/share"),
            readonly: false,
        });
        assert!(validate_assets(&LauncherConfig::Custom(asset), &spec, &bx).is_err());

        let alias = project.join("share alias");
        std::os::unix::fs::symlink(&share, &alias).unwrap();
        assert!(
            validate_assets(&LauncherConfig::Custom(alias.join("launcher")), &spec, &bx).is_err()
        );
    }
}
