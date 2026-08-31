use anyhow::{Result, bail};
use std::collections::{BTreeMap, HashMap, HashSet};

use super::{Config, MIN_MEM_MIB};
use terra_shared::contract::MAX_VOLUMES;

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
    validate_workdir(cfg)?;
    validate_hw(cfg)?;
    validate_sudo(cfg)?;
    validate_volumes(cfg)?;
    validate_network(cfg)?;
    validate_env(&cfg.env)?;
    validate_one_thing_per_guest_path(cfg)?;
    Ok(())
}

fn validate_workdir(cfg: &Config) -> Result<()> {
    if let Some(dir) = &cfg.workload.workdir
        && !dir.is_absolute()
    {
        bail!("workload.workdir must be absolute: '{}'", dir.display());
    }
    Ok(())
}

fn validate_hw(cfg: &Config) -> Result<()> {
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
    Ok(())
}

fn validate_sudo(cfg: &Config) -> Result<()> {
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
    Ok(())
}

fn validate_volumes(cfg: &Config) -> Result<()> {
    if cfg.volumes.len() > MAX_VOLUMES {
        bail!(
            "{} volumes configured; at most {} fit (one guest block device each)",
            cfg.volumes.len(),
            MAX_VOLUMES
        );
    }
    let mut seen = HashSet::new();
    for v in &cfg.volumes {
        // The name becomes a host filename in the box's state dir: no
        // separators, no traversal.
        if matches!(v.name.as_str(), "" | "." | "..") || v.name.contains(['/', '\\']) {
            bail!(
                "volume name '{}' must be a plain name (it names the image file)",
                v.name
            );
        }
        // Two volumes on one image would mount the same ext4 read-write twice.
        if !seen.insert(&v.name) {
            bail!("duplicate volume name '{}'", v.name);
        }
        if v.size_mib == 0 {
            bail!("volume '{}' must have size_mib > 0", v.name);
        }
    }
    Ok(())
}

fn validate_network(cfg: &Config) -> Result<()> {
    // A broken `network:` would otherwise fail mid-boot, in the background
    // gateway - after the recipe was pinned - so it is refused here instead.
    crate::policy::network::rules::parse_port_mappings(&cfg.network.ports)?;
    let _ = crate::policy::network::runtime::BoxPolicy::new(&cfg.network)?;
    Ok(())
}

/// Refuse two entries claiming one guest path. They are mounted in recipe
/// order, so the later one silently wins and the earlier one is a line in the
/// recipe that does nothing.
fn validate_one_thing_per_guest_path(cfg: &Config) -> Result<()> {
    let claims = cfg
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
        );
    let mut seen = HashMap::new();
    for (guest, what) in claims {
        if let Some(earlier) = seen.insert(guest, what.clone()) {
            bail!(
                "guest path '{}' is claimed twice, by {earlier} and by {what} \
                 (the later one would be mounted over the earlier)",
                guest.display()
            );
        }
    }
    Ok(())
}
