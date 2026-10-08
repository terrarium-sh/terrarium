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
