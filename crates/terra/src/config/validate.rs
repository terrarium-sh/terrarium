use anyhow::{Result, bail};
use std::collections::BTreeMap;
use std::path::Path;

use super::{Config, MIN_MEM_MIB};

pub(crate) fn validate_env(env: &BTreeMap<String, String>) -> Result<()> {
    for (k, v) in env {
        // Whitespace included: `export KEY=val`, the spelling every dotenv
        // written for `source` uses, otherwise parses as a name with a space in
        // it - which the agent exports and nothing in the guest can read. It is
        // refused rather than stripped, because a name nobody typed is not
        // terra's to invent.
        if k.is_empty() || k.contains(['\0', '=']) || k.chars().any(char::is_whitespace) {
            anyhow::bail!(
                "invalid environment variable name {k:?} \
                 (a name cannot be empty or contain whitespace, a NUL or '=' - \
                 an env_file line is `KEY=VAL`, with no `export`)"
            );
        }
        if v.contains('\0') {
            anyhow::bail!("invalid value for environment variable {k}: it cannot contain a NUL");
        }
    }
    Ok(())
}

pub(crate) fn validate(cfg: &Config) -> Result<()> {
    for m in &cfg.mounts {
        if !m.guest.is_absolute() {
            bail!("mount guest path must be absolute: '{}'", m.guest.display());
        }
    }

    if let Some(dir) = &cfg.workload.workdir
        && !dir.is_absolute()
    {
        bail!("workload.workdir must be absolute: '{}'", dir.display());
    }

    if cfg.hw.rootfs_mib == 0 {
        bail!(
            "hw.rootfs_mib must be > 0 (the state is always a bounded image; use mounts for uncapped scratch)"
        );
    }

    // A VM the hypervisor cannot build fails deep inside libkrun, in a
    // background process whose only report is a replayed log - so the numbers
    // that decide whether it can be built are checked against the recipe.
    if cfg.hw.cpus == 0 {
        bail!("hw.cpus must be > 0 (a VM needs at least one vCPU)");
    }
    if cfg.hw.mem_mib < MIN_MEM_MIB {
        bail!(
            "hw.mem_mib is {} MiB, under the {MIN_MEM_MIB} MiB a guest needs to boot \
             (it would die part-way through the boot instead of starting)",
            cfg.hw.mem_mib
        );
    }

    // doas fails *closed* on a parse error, silently revoking every grant - so
    // anything that could break a rule out of its own line is refused here.
    for c in &cfg.sudo {
        if c.is_empty() {
            bail!("sudo entries must be command names, not empty strings");
        }
        if c.split_whitespace().count() > 1 || c.chars().any(char::is_control) {
            bail!(
                "sudo entry '{c}' must be a bare command, without arguments \
                 (it permits the command with any arguments)"
            );
        }
    }

    if cfg.volumes.len() > terra_shared::MAX_VOLUMES {
        bail!(
            "{} volumes configured; at most {} fit (one guest block device each)",
            cfg.volumes.len(),
            terra_shared::MAX_VOLUMES
        );
    }
    for (i, v) in cfg.volumes.iter().enumerate() {
        // The name becomes a host filename in the box's state dir: no
        // separators, no traversal.
        if matches!(v.name.as_str(), "" | "." | "..") || v.name.contains(['/', '\\']) {
            bail!(
                "volume name '{}' must be a plain name (it names the image file)",
                v.name
            );
        }
        // Two volumes on one image would mount the same ext4 read-write twice.
        if cfg.volumes[..i].iter().any(|p| p.name == v.name) {
            bail!("duplicate volume name '{}'", v.name);
        }
        if !v.guest.is_absolute() {
            bail!(
                "volume '{}' guest path must be absolute: '{}'",
                v.name,
                v.guest.display()
            );
        }
        if v.size_mib == 0 {
            bail!("volume '{}' must have size_mib > 0", v.name);
        }
    }

    // A broken `network:` would otherwise fail mid-boot, in the background
    // gateway - after the recipe was pinned - so it is refused here instead.
    crate::policy::network::parse_port_mappings(&cfg.network.ports)?;
    crate::policy::network::validate(&cfg.network)?;

    validate_env(&cfg.env)?;
    check_one_thing_per_guest_path(cfg)?;
    Ok(())
}

/// Refuse two entries claiming one guest path. They are mounted in recipe
/// order, so the later one silently wins and the earlier one is a line in the
/// recipe that does nothing.
fn check_one_thing_per_guest_path(cfg: &Config) -> Result<()> {
    let claims: Vec<(&Path, String)> = cfg
        .mounts
        .iter()
        .map(|m| {
            (
                m.guest.as_path(),
                format!("mount from '{}'", m.host.display()),
            )
        })
        .chain(
            cfg.volumes
                .iter()
                .map(|v| (v.guest.as_path(), format!("volume '{}'", v.name))),
        )
        .collect();
    for (i, (guest, what)) in claims.iter().enumerate() {
        if let Some((_, earlier)) = claims[..i].iter().find(|(p, _)| p == guest) {
            bail!(
                "guest path '{}' is claimed twice, by {earlier} and by {what} \
                 (the later one would be mounted over the earlier)",
                guest.display()
            );
        }
    }
    Ok(())
}
