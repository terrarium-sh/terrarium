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
            for (index, mount) in spec.recipe.mounts.iter().enumerate() {
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
        for share in &spec.recipe.mounts {
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
    // The box directory itself stays ungranted: it holds stale volumes the recipe no longer names
    // and entries the host CLI trusts, such as an import journal.
    grants.push(Grant::new(
        bx.get_dir().join(state::RUNTIME_LOG_DIR),
        Access::ReadWrite,
    ));
    for volume in &spec.recipe.volumes {
        grants.push(Grant::new(
            bx.get_volume_image_path(&volume.name),
            Access::ReadWrite,
        ));
    }
    grants.push(Grant::new(
        bx.get_dir().join(state::ROOTFS_FILE),
        match super::rootfs_access(spec) {
            terra_runtime::component::AccessMode::ReadOnly => Access::ReadOnly,
            terra_runtime::component::AccessMode::ReadWrite => Access::ReadWrite,
        },
    ));
    for name in [
        state::RECIPE_FILE,
        state::PINNED_PATHS_FILE,
        state::ORIGIN_FILE,
        state::SETUP_STAMP,
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
    use crate::recipe::{Mount, Recipe, Volume, VolumeLifetime};
    use terra_protocol::PlanMode;

    #[test]
    fn sandbox_grants_keep_metadata_readonly_and_exclude_setup_shares() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        let box_dir = base.join("box");
        let share = base.join("share");
        std::fs::create_dir_all(&box_dir).unwrap();
        std::fs::create_dir_all(&share).unwrap();
        let recipe = box_dir.join(state::RECIPE_FILE);
        std::fs::write(&recipe, "{}").unwrap();
        let bx = BoxRef::from_state_dir(box_dir, &base);
        std::fs::write(bx.get_volume_image_path("stale"), "").unwrap();
        let mut spec = spec(&base, terra_protocol::PlanMode::Run);
        spec.recipe.mounts.push(Mount {
            host: share.clone(),
            guest: "/share".into(),
            readonly: true,
        });
        spec.recipe.volumes.push(Volume {
            name: "scratch".into(),
            guest: Some("/scratch".into()),
            rootfs_overlay: false,
            size_mib: 8,
            lifetime: VolumeLifetime::Boot,
        });
        let grants = build_sandbox_grants(&spec, &bx).unwrap();
        assert!(grants.iter().any(|grant| {
            grant.path == share && grant.access == Access::ReadOnly && grant.directory.is_some()
        }));
        assert!(grants.iter().any(|grant| {
            grant.path == recipe && grant.access == Access::ReadOnly && grant.directory.is_none()
        }));
        assert!(grants.iter().any(|grant| {
            grant.path == bx.get_volume_image_path("scratch") && grant.access == Access::ReadWrite
        }));
        assert!(!grants.iter().any(|grant| {
            grant.path == bx.get_dir() || grant.path == bx.get_volume_image_path("stale")
        }));
        assert!(grants.iter().any(|grant| {
            grant.path == bx.get_dir().join(state::RUNTIME_LOG_DIR)
                && grant.access == Access::ReadWrite
        }));
        spec.mode = terra_protocol::PlanMode::Create;
        let grants = build_sandbox_grants(&spec, &bx).unwrap();
        assert!(!grants.iter().any(|grant| grant.path == share));
        assert!(grants.iter().any(|grant| {
            grant.path == bx.get_volume_image_path("scratch") && grant.access == Access::ReadWrite
        }));
        let moved = base.join("moved");
        std::fs::rename(&share, &moved).unwrap();
        crate::sys::symlink_dir(&moved, &share).unwrap();
        spec.mode = terra_protocol::PlanMode::Run;
        assert!(build_sandbox_grants(&spec, &bx).is_err());
    }

    /// The worker's sandbox grants the root image exactly the access the disk
    /// is opened with, so a read-only boot cannot reopen it for writing.
    #[test]
    fn the_root_image_grant_follows_the_boots_rootfs_access() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        let box_dir = base.join("box");
        std::fs::create_dir_all(&box_dir).unwrap();
        let bx = BoxRef::from_state_dir(box_dir, &base);
        let rootfs = bx.get_dir().join(state::ROOTFS_FILE);
        let rootfs_grant = |mode, rootfs_readonly| {
            let mut spec = spec(&base, mode);
            spec.recipe.hw.rootfs_readonly = rootfs_readonly;
            build_sandbox_grants(&spec, &bx)
                .unwrap()
                .into_iter()
                .filter(|grant| grant.path == rootfs)
                .map(|grant| grant.access)
                .collect::<Vec<_>>()
        };
        assert_eq!(rootfs_grant(PlanMode::Run, true), [Access::ReadOnly]);
        assert_eq!(rootfs_grant(PlanMode::Create, true), [Access::ReadWrite]);
        assert_eq!(rootfs_grant(PlanMode::Run, false), [Access::ReadWrite]);
    }

    fn spec(project_dir: &Path, mode: PlanMode) -> BootSpec {
        BootSpec {
            recipe: Recipe::default(),
            project_dir: project_dir.to_path_buf(),
            root: false,
            mode,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        }
    }
}
