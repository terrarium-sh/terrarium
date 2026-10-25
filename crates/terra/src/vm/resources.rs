use anyhow::{Context, Result};

use super::boot::BootSpec;
use crate::config::VolumeLifetime;
use crate::state::BoxRef;

pub(super) fn prepare_volumes(spec: &BootSpec, bx: &BoxRef) -> Result<()> {
    for volume in &spec.cfg.volumes {
        let path = bx.get_volume_image_path(&volume.name);
        match volume.lifetime {
            VolumeLifetime::Boot => {
                remove_volume_image(&path)
                    .with_context(|| format!("emptying volume image {}", path.display()))?;
                super::image::install_or_grow_volume_image(&path, volume.size_mib)
                    .with_context(|| format!("preparing volume image {}", path.display()))?;
            }
            VolumeLifetime::Box => anyhow::ensure!(
                path.exists(),
                "volume image {} is missing - `terra {} setup` creates it",
                path.display(),
                bx.get_name()
            ),
        }
    }
    Ok(())
}

/// Frees host disk after the VM exits; the next start replaces the image anyway.
pub(super) fn remove_boot_lifetime_volume_images(spec: &BootSpec, bx: &BoxRef) {
    for volume in &spec.cfg.volumes {
        if volume.lifetime != VolumeLifetime::Boot {
            continue;
        }
        let path = bx.get_volume_image_path(&volume.name);
        if let Err(error) = remove_volume_image(&path) {
            log::warn!("removing volume image {}: {error}", path.display());
        }
    }
}

fn remove_volume_image(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

/// Broker sockets plus its IPC, runtime, and resolver descriptors.
#[cfg(unix)]
const MIN_BROKER_OPEN_FILES: u64 =
    (terra_network::MAX_RESOURCES + terra_network::MAX_LISTENERS + 64) as u64;

/// Raises the broker's soft descriptor limit; a common soft default of 1024
/// would refuse admitted flows with `EMFILE`.
#[cfg(unix)]
pub(super) fn raise_broker_open_files() -> Result<()> {
    let limits = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    anyhow::ensure!(
        limits
            .maximum
            .is_none_or(|maximum| maximum >= MIN_BROKER_OPEN_FILES),
        "the network broker needs an open-file hard limit of at least {MIN_BROKER_OPEN_FILES}; raise it with `ulimit -Hn` or the service's LimitNOFILE"
    );
    if limits
        .current
        .is_none_or(|current| current >= MIN_BROKER_OPEN_FILES)
    {
        return Ok(());
    }
    rustix::process::setrlimit(
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(MIN_BROKER_OPEN_FILES),
            maximum: limits.maximum,
        },
    )
    .context("raising network broker file descriptors")
}

#[cfg(unix)]
pub(super) fn limit_vm_process() -> Result<()> {
    let current = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    rustix::process::setrlimit(
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(
                current
                    .current
                    .unwrap_or(u64::MAX)
                    .min(terra_limits::MAX_VM_OPEN_FILES as u64),
            ),
            maximum: current.maximum,
        },
    )
    .context("limiting VM file descriptors")?;
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: rustix::process::getrlimit(rustix::process::Resource::Core).maximum,
        },
    )
    .context("disabling VM core dumps")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Volume};
    use std::path::PathBuf;

    /// A boot-lifetime image is replaced by a fresh one before every boot and
    /// removed after it; a box-lifetime image next to it, which setup made,
    /// keeps its bytes.
    #[test]
    fn a_boot_lifetime_volume_starts_fresh_and_a_box_lifetime_volume_keeps_its_data() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().join("state"), dir.path());
        std::fs::create_dir(bx.get_dir()).unwrap();
        let volume = |name: &str, lifetime| Volume {
            name: name.into(),
            guest: Some(format!("/{name}").into()),
            rootfs_overlay: false,
            size_mib: 8,
            lifetime,
        };
        let spec = BootSpec {
            cfg: Config {
                volumes: vec![
                    volume("scratch", VolumeLifetime::Boot),
                    volume("kept", VolumeLifetime::Box),
                ],
                ..Config::default()
            },
            project_dir: PathBuf::from("/project"),
            root: false,
            mode: terra_protocol::PlanMode::Run,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        };
        // A box-lifetime image is setup's to make; a boot without one is refused.
        let missing = prepare_volumes(&spec, &bx).unwrap_err().to_string();
        assert!(missing.contains("terra state setup"), "{missing}");
        super::super::image::install_or_grow_volume_image(&bx.get_volume_image_path("kept"), 8)
            .unwrap();

        prepare_volumes(&spec, &bx).unwrap();
        let fresh = std::fs::read(bx.get_volume_image_path("scratch")).unwrap();

        for name in ["scratch", "kept"] {
            let mut image = std::fs::read(bx.get_volume_image_path(name)).unwrap();
            image[1 << 20] = 0xAA;
            std::fs::write(bx.get_volume_image_path(name), image).unwrap();
        }
        prepare_volumes(&spec, &bx).unwrap();

        assert_eq!(
            std::fs::read(bx.get_volume_image_path("scratch")).unwrap(),
            fresh
        );
        assert_eq!(
            std::fs::read(bx.get_volume_image_path("kept")).unwrap()[1 << 20],
            0xAA
        );

        remove_boot_lifetime_volume_images(&spec, &bx);
        assert!(!bx.get_volume_image_path("scratch").exists());
        assert!(bx.get_volume_image_path("kept").exists());
    }
}
