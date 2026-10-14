//! Build the sandboxed VM launch and its grants.

use super::boot::{BootSpec, VM_PROCESS_FLAG_ARG};
use crate::state::{self, BoxRef};
use anyhow::{Context as _, Result, ensure};
use std::path::Path;
use std::process::Command;
use terra_sandbox::{Access, Grant, Launch};

pub(super) fn prepare_vm_launch(
    spec: &BootSpec,
    bx: &BoxRef,
    exe: &Path,
) -> Result<terra_sandbox::PreparedLaunch> {
    let grants = build_sandbox_grants(spec, bx)?;
    let mut command = Command::new(exe);
    command.arg(VM_PROCESS_FLAG_ARG).arg(bx.get_dir());
    for name in ["RUST_LOG", "TERRA_BOOT_TRACE", "TERRA_ALLOW_ROOT"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(windows)]
    {
        if spec.mode == terra_protocol::PlanMode::Run {
            for (index, mount) in spec.cfg.mounts.iter().enumerate() {
                let identity = granted_directory_identity(&grants, &mount.host)?;
                command.env(
                    format!("TERRA_WINDOWS_MOUNT_ID_{index}"),
                    identity.to_string(),
                );
            }
        }
    }
    terra_sandbox::prepare_launch(Launch {
        role: terra_sandbox::Role::Vm,
        command,
        grants,
        staging_directory: &crate::state::get_terra_home_path()?,
    })
}

#[cfg(windows)]
fn granted_directory_identity(
    grants: &[Grant],
    path: &Path,
) -> Result<terra_platform::filesystem::share::FileIdentity> {
    let directory = grants
        .iter()
        .find(|grant| grant.path == path)
        .and_then(|grant| grant.directory.as_ref())
        .with_context(|| format!("missing validated Windows share root {}", path.display()))?;
    Ok(terra_platform::filesystem::share::file_identity(directory)?)
}

fn build_sandbox_grants(spec: &BootSpec, bx: &BoxRef) -> Result<Vec<Grant>> {
    ensure!(
        bx.get_dir().is_absolute(),
        "the box state path must be absolute"
    );
    ensure!(
        bx.get_dir().is_dir(),
        "box state directory {} does not exist",
        bx.get_dir().display()
    );
    let mut grants = Vec::new();
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
                terra_platform::filesystem::share::open_share_root(&share.host)
                    .with_context(|| format!("opening approved share {}", share.host.display()))?,
            );
            grants.push(grant);
        }
    }
    #[cfg(target_os = "linux")]
    grants.push(Grant::new(bx.get_dir(), Access::ReadWrite));
    #[cfg(any(target_os = "macos", windows))]
    {
        // Windows grants are DACL entries on every object beneath the path, so a directory
        // grant would expose stale volumes and logs the box configuration no longer names.
        #[cfg(target_os = "macos")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
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
        let bx = BoxRef::from_state_dir(box_dir, &base);
        let mut spec = spec(&base, terra_protocol::PlanMode::Run);
        spec.cfg.mounts.push(config::Mount {
            host: share.clone(),
            guest: "/share".into(),
            readonly: true,
        });
        let grants = build_sandbox_grants(&spec, &bx).unwrap();
        assert!(grants.iter().any(|grant| {
            grant.path == share && grant.access == Access::ReadOnly && grant.directory.is_some()
        }));
        assert!(grants.iter().any(|grant| {
            grant.path == recipe && grant.access == Access::ReadOnly && grant.directory.is_none()
        }));
        #[cfg(target_os = "linux")]
        let box_access = Some(Access::ReadWrite);
        #[cfg(target_os = "macos")]
        let box_access = Some(Access::ReadOnly);
        #[cfg(windows)]
        let box_access = None;
        assert_eq!(
            grants
                .iter()
                .find(|grant| grant.path == bx.get_dir())
                .map(|grant| grant.access),
            box_access
        );
        #[cfg(any(target_os = "macos", windows))]
        for name in [state::ROOTFS_FILE, state::DIAGNOSTICS_LOG] {
            assert!(grants.iter().any(|grant| {
                grant.path == bx.get_dir().join(name) && grant.access == Access::ReadWrite
            }));
        }
        spec.mode = terra_protocol::PlanMode::Create;
        let grants = build_sandbox_grants(&spec, &bx).unwrap();
        assert!(!grants.iter().any(|grant| grant.path == share));
        let moved = base.join("moved");
        std::fs::rename(&share, &moved).unwrap();
        crate::sys::symlink_dir(&moved, &share).unwrap();
        spec.mode = terra_protocol::PlanMode::Run;
        assert!(build_sandbox_grants(&spec, &bx).is_err());
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
}
