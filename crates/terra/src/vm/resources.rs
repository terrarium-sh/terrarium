use anyhow::{Context, Result};

use super::boot::BootSpec;
use crate::state::BoxRef;

pub(super) fn prepare_volumes(spec: &BootSpec, bx: &BoxRef) -> Result<()> {
    for volume in &spec.cfg.volumes {
        let path = bx.get_volume_image(&volume.name);
        super::image::ensure_volume_image(&path, volume.size_mib)
            .with_context(|| format!("preparing volume image {}", path.display()))?;
    }
    Ok(())
}

pub(super) fn limit_vm_process() -> Result<()> {
    #[cfg(unix)]
    {
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
    }
    Ok(())
}
