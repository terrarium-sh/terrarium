//! Guest mounts: the mount call itself, and the shares and volumes a plan names.

use crate::workload::GuestUser;
use anyhow::{Context, Result};
use rustix::mount::MountFlags;
use std::ffi::CStr;
use std::path::Path;

/// Mounts that hold guest data carry no setuid binaries or device nodes.
pub(crate) const DATA_MOUNT_FLAGS: MountFlags = MountFlags::NOSUID.union(MountFlags::NODEV);

pub(crate) fn mount(source: &str, target: &str, fstype: &str, flags: MountFlags) -> Result<()> {
    let data = if fstype == "ext4" && !flags.contains(MountFlags::RDONLY) {
        c"discard"
    } else {
        c""
    };
    mount_with_data(source, target, fstype, flags, data)
}

pub(crate) fn mount_with_data(
    source: &str,
    target: &str,
    fstype: &str,
    flags: MountFlags,
    data: &CStr,
) -> Result<()> {
    rustix::mount::mount(source, target, fstype, flags, data)
        .map_err(std::io::Error::from)
        .with_context(|| format!("mounting {target}"))
}

pub(crate) fn mount_shares_and_volumes(plan: &terra_protocol::Plan) -> Result<()> {
    for share in &plan.shares {
        mount_share(share)?;
    }
    mount_volumes(plan)
}

pub(crate) fn unmount_shares(plan: &terra_protocol::Plan) -> Result<()> {
    let mut cleanup = Ok(());
    for share in plan.shares.iter().rev() {
        let guest_path = share.guest.as_str();
        loop {
            match rustix::mount::unmount(guest_path, rustix::mount::UnmountFlags::DETACH) {
                Ok(()) => {}
                Err(rustix::io::Errno::NOENT | rustix::io::Errno::INVAL) => break,
                Err(error) => {
                    let error =
                        Err(error).with_context(|| format!("unmounting setup share {guest_path}"));
                    cleanup = cleanup.and(error);
                    break;
                }
            }
        }
    }
    cleanup
}

fn mount_volumes(plan: &terra_protocol::Plan) -> Result<()> {
    for volume in &plan.volumes {
        prepare_mount_point(&volume.guest)?;
        mount(&volume.dev, &volume.guest, "ext4", DATA_MOUNT_FLAGS)?;
        if let Err(error) = std::fs::File::open(&volume.guest)
            .and_then(|root| crate::workload::hand_over(root, GuestUser::from_plan(plan)))
        {
            eprintln!(
                "terra-agent: warning: could not chown {}: {error}",
                volume.guest
            );
        }
    }
    Ok(())
}

fn mount_share(share: &terra_protocol::Share) -> Result<()> {
    prepare_mount_point(&share.guest)?;
    let flags = if share.readonly {
        MountFlags::RDONLY
    } else {
        MountFlags::empty()
    };
    mount(
        &share.tag,
        &share.guest,
        "virtiofs",
        flags | DATA_MOUNT_FLAGS,
    )
}

pub(crate) fn prepare_mount_points(plan: &terra_protocol::Plan) -> Result<()> {
    plan.mount_points
        .iter()
        .chain(plan.volumes.iter().map(|volume| &volume.guest))
        .map(|path| prepare_mount_point(path))
        .fold(Ok(()), Result::and)
}

fn prepare_mount_point(path: &str) -> Result<()> {
    crate::sync::ensure_directory(Path::new(path), GuestUser::Root)
        .with_context(|| format!("creating mount point {path}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn mount_point_preparation_continues_after_an_error() {
        let directory = crate::create_scratch_path("mounts", "prepare-all");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let file = directory.join("file");
        fs::write(&file, []).unwrap();
        let valid = directory.join("valid");

        let mut plan = terra_protocol::Plan::bare_run(None);
        plan.mount_points = [&file, &valid]
            .map(|path| path.to_str().unwrap().to_owned())
            .into();
        let result = prepare_mount_points(&plan);
        assert!(valid.is_dir());
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("creating mount point {}", file.display())
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_symlinked_mount_point_is_supported() {
        let real = crate::create_scratch_path("mounts", "mp-real");
        let link = crate::create_scratch_path("mounts", "mp-link");
        let fresh = crate::create_scratch_path("mounts", "mp-fresh");
        let _ = fs::remove_dir_all(&real);
        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&fresh);
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        prepare_mount_point(&link.to_string_lossy()).unwrap();
        prepare_mount_point(&link.join("src").to_string_lossy()).unwrap();
        assert!(real.join("src").is_dir());
        assert!(prepare_mount_point(&real.to_string_lossy()).is_ok());
        assert!(prepare_mount_point(&fresh.join("a/b").to_string_lossy()).is_ok());
        assert!(fresh.join("a/b").is_dir());

        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&real);
        let _ = fs::remove_dir_all(&fresh);
    }
}
