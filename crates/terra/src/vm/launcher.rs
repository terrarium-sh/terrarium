//! Build custom VM launches and protect launcher assets from guest-written shares.

use super::boot::{BootSpec, VM_PROCESS_FLAG_ARG};
use crate::config;
use crate::policy::mount;
use crate::sandbox::config::LauncherConfig;
use crate::state::{self, BoxRef};
use crate::sys::canonicalize_existing_prefix;
use anyhow::{Context as _, Result, ensure};
use std::path::Path;
use std::process::Command;
use terra_sandbox::{Access, Grant, Launch};

pub(super) fn prepare_sandbox_launch(
    spec: &BootSpec,
    bx: &BoxRef,
    exe: &Path,
    policy: Option<&[u8]>,
    self_test: Option<[u16; 3]>,
) -> Result<terra_sandbox::PreparedLaunch> {
    let grants = build_sandbox_grants(spec, bx, exe)?;
    #[cfg(any(target_os = "macos", windows))]
    let grants = {
        let mut grants = grants;
        if self_test.is_some() {
            grants.push(Grant::new(
                super::supervisor::self_test_directory(bx),
                Access::ReadWrite,
            ));
        }
        grants
    };
    let mut command = Command::new(exe);
    command
        .arg(if self_test.is_some() {
            super::supervisor::VM_SELF_TEST_ARG
        } else {
            VM_PROCESS_FLAG_ARG
        })
        .arg(bx.get_dir());
    if let Some(ports) = self_test {
        command.args(ports.map(|port| port.to_string()));
    }
    for name in ["RUST_LOG", "TERRA_BOOT_TRACE", "TERRA_ALLOW_ROOT"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    terra_sandbox::prepare_launch(Launch {
        role: terra_sandbox::Role::Vm,
        command,
        grants,
        die_with_parent: true,
        policy,
        staging_directory: &crate::state::get_terra_home_path()?,
    })
}

fn build_sandbox_grants(spec: &BootSpec, bx: &BoxRef, exe: &Path) -> Result<Vec<Grant>> {
    ensure!(
        bx.get_dir().is_absolute(),
        "the box state path must be absolute"
    );
    ensure!(
        bx.get_dir().is_dir(),
        "box state directory {} does not exist",
        bx.get_dir().display()
    );
    let mut grants = terra_sandbox::role_grants(terra_sandbox::Role::Vm);
    grants.push(Grant::new(exe, Access::ReadOnly));
    if spec.mode == terra_protocol::PlanMode::Run {
        for share in &spec.cfg.mounts {
            let mut grant = Grant::new(
                &share.host,
                if share.readonly {
                    Access::ReadOnly
                } else {
                    Access::ReadWrite
                },
            );
            grant.directory = Some(
                terra_platform::filesystem::open_share_root(&share.host)
                    .with_context(|| format!("opening approved share {}", share.host.display()))?,
            );
            grants.push(grant);
        }
    }
    #[cfg(target_os = "linux")]
    grants.push(Grant::new(bx.get_dir(), Access::ReadWrite));
    #[cfg(any(target_os = "macos", windows))]
    {
        grants.push(Grant::new(bx.get_dir(), Access::ReadOnly));
        for name in [state::ROOTFS_FILE, state::DIAGNOSTICS_LOG] {
            grants.push(Grant::new(bx.get_dir().join(name), Access::ReadWrite));
        }
        #[cfg(target_os = "macos")]
        grants.push(Grant::new(
            bx.get_dir().join("runtime-logs"),
            Access::ReadWrite,
        ));
        #[cfg(windows)]
        grants.push(Grant::new(
            bx.get_dir().join(state::LOG_FILE),
            Access::ReadWrite,
        ));
        for volume in &spec.cfg.volumes {
            grants.push(Grant::new(
                bx.get_volume_image(&volume.name),
                Access::ReadWrite,
            ));
        }
    }
    for name in [
        state::RECIPE_FILE,
        state::PINNED_PATHS_FILE,
        state::ORIGIN_FILE,
        state::BAKE_STAMP,
        state::HOST_PID_FILE,
        state::SUPERVISOR_PID_FILE,
        state::PID_FILE,
    ] {
        let path = bx.get_dir().join(name);
        if path.exists() {
            ensure!(
                std::fs::symlink_metadata(&path)?.file_type().is_file(),
                "box metadata {} is not a regular file",
                path.display()
            );
            grants.push(Grant::new(path, Access::ReadOnly));
        }
    }
    Ok(grants)
}

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
        LauncherConfig::Direct | LauncherConfig::Sandboxed { policy: None, .. } => Vec::new(),
        LauncherConfig::Custom(path) => vec![("VM initializer", path)],
        LauncherConfig::Sandboxed {
            policy: Some(path), ..
        } => vec![("Sandbox policy", path)],
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

    #[test]
    fn sandbox_grants_keep_metadata_readonly_and_exclude_bake_shares() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        let box_dir = base.join("box");
        let share = base.join("share");
        std::fs::create_dir_all(&box_dir).unwrap();
        std::fs::create_dir_all(&share).unwrap();
        let recipe = box_dir.join(state::RECIPE_FILE);
        std::fs::write(&recipe, "{}").unwrap();
        let exe = base.join("terra");
        let bx = BoxRef::from_state_dir(box_dir, &base);
        let mut spec = spec(&base, terra_protocol::PlanMode::Run);
        spec.cfg.mounts.push(config::Mount {
            host: share.clone(),
            guest: "/share".into(),
            readonly: true,
        });
        let grants = build_sandbox_grants(&spec, &bx, &exe).unwrap();
        assert!(grants.iter().any(|grant| {
            grant.path == share && grant.access == Access::ReadOnly && grant.directory.is_some()
        }));
        assert!(grants.iter().any(|grant| {
            grant.path == recipe && grant.access == Access::ReadOnly && grant.directory.is_none()
        }));
        #[cfg(target_os = "linux")]
        let box_access = Access::ReadWrite;
        #[cfg(any(target_os = "macos", windows))]
        let box_access = Access::ReadOnly;
        assert!(
            grants
                .iter()
                .any(|grant| { grant.path == bx.get_dir() && grant.access == box_access })
        );
        #[cfg(any(target_os = "macos", windows))]
        for name in [state::ROOTFS_FILE, state::DIAGNOSTICS_LOG] {
            assert!(grants.iter().any(|grant| {
                grant.path == bx.get_dir().join(name) && grant.access == Access::ReadWrite
            }));
        }
        spec.mode = terra_protocol::PlanMode::Create;
        let grants = build_sandbox_grants(&spec, &bx, &exe).unwrap();
        assert!(!grants.iter().any(|grant| grant.path == share));
        let moved = base.join("moved");
        std::fs::rename(&share, &moved).unwrap();
        crate::sys::symlink_dir(&moved, &share).unwrap();
        spec.mode = terra_protocol::PlanMode::Run;
        assert!(build_sandbox_grants(&spec, &bx, &exe).is_err());
    }

    fn spec(project_dir: &Path, mode: PlanMode) -> BootSpec {
        BootSpec {
            cfg: config::Config::default(),
            project_dir: project_dir.to_path_buf(),
            root: false,
            mode,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
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
    fn custom_script_preserves_boot_input_and_network_broker_channel() {
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
        std::fs::write(&exe, b"#!/bin/sh\ncat\ncat <&7\n").unwrap();
        for path in [&init, &exe] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bx = BoxRef::from_state_dir(dir.path().join("box"), dir.path());
        let mut command =
            custom_command(&init, &exe, &spec(dir.path(), PlanMode::Run), &bx).unwrap();
        let (mut broker, worker) = terra_platform::io::local::create_local_pair().unwrap();
        let inherited =
            crate::sys::pass_ipc(&mut command, &worker, super::super::supervisor::NETWORK_FD)
                .unwrap();
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        drop((inherited, worker));
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"boot JSON stays on stdin")
            .unwrap();
        broker.write_all(b"; broker requests stay on IPC").unwrap();
        broker.shutdown(std::net::Shutdown::Write).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert_eq!(
            output.stdout,
            b"boot JSON stays on stdin; broker requests stay on IPC"
        );
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

        let policy = LauncherConfig::Sandboxed {
            policy: Some(asset),
            allow_fallback: true,
        };
        let error = validate_assets(&policy, &current, &bx)
            .unwrap_err()
            .to_string();
        assert!(error.contains("Sandbox policy"), "{error}");

        for launcher in [
            LauncherConfig::Custom(bx.get_dir().join("initializer")),
            LauncherConfig::Sandboxed {
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
