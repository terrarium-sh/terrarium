use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, HashMap, HashSet};

use super::{MIN_MEM_MIB, Recipe, VolumeLifetime};
use std::path::Path;
use terra_protocol::MAX_VOLUMES;

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
            anyhow::bail!(
                "invalid value for environment variable {}: it cannot contain a NUL",
                crate::render::escape_printable(k)
            );
        }
    }
    Ok(())
}

pub(crate) fn validate(recipe: &Recipe) -> Result<()> {
    validate_workdir(recipe)?;
    validate_hw(recipe)?;
    recipe.components.memory_limits()?;
    validate_sudo(recipe)?;
    validate_volumes(recipe)?;
    validate_storage_devices(recipe)?;
    validate_network(recipe)?;
    validate_env(&recipe.env)?;
    validate_guest_paths(recipe)?;
    Ok(())
}

fn validate_workdir(recipe: &Recipe) -> Result<()> {
    if let Some(dir) = &recipe.workload.workdir
        && !dir.as_os_str().to_string_lossy().starts_with('/')
    {
        bail!(
            "workload.workdir must be absolute: '{}'",
            crate::render::escape_printable_path(dir)
        );
    }
    Ok(())
}

fn validate_hw(recipe: &Recipe) -> Result<()> {
    if recipe.hw.rootfs_mib == 0 {
        bail!(
            "hw.rootfs_mib must be > 0 (the state is always a bounded image; use mounts for uncapped scratch)"
        );
    }
    // A VM the VMM cannot build fails in a
    // background process whose only report is a replayed log - so the numbers
    // that decide whether it can be built are checked against the recipe.
    if recipe.hw.cpus == 0 {
        bail!("hw.cpus must be > 0 (a VM needs at least one vCPU)");
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if usize::from(recipe.hw.cpus) > terra_runtime::machine::MAX_VCPUS {
        bail!(
            "hw.cpus is {}; at most {} vCPUs fit this machine",
            recipe.hw.cpus,
            terra_runtime::machine::MAX_VCPUS
        );
    }
    if recipe.hw.mem_mib < MIN_MEM_MIB {
        bail!(
            "hw.mem_mib is {} MiB, under the {MIN_MEM_MIB} MiB a guest needs to boot \
             (it would die part-way through the boot instead of starting)",
            recipe.hw.mem_mib
        );
    }
    Ok(())
}

fn validate_sudo(recipe: &Recipe) -> Result<()> {
    // doas fails *closed* on a parse error, silently revoking every grant - so
    // anything that could break a rule out of its own line is refused here.
    for c in &recipe.sudo {
        if c.is_empty() {
            bail!("sudo entries must be command names, not empty strings");
        }
        if c.split_whitespace().count() > 1 || c.chars().any(char::is_control) {
            bail!(
                "sudo entry '{}' must be a bare command, without arguments \
                 (it permits the command with any arguments)",
                crate::render::escape_printable(c)
            );
        }
    }
    Ok(())
}

fn validate_volumes(recipe: &Recipe) -> Result<()> {
    if recipe.volumes.len() > MAX_VOLUMES {
        bail!(
            "the recipe names {} volumes; at most {} fit (one guest block device each)",
            recipe.volumes.len(),
            MAX_VOLUMES
        );
    }
    let mut seen = HashSet::new();
    let mut has_overlay = false;
    for v in &recipe.volumes {
        crate::name::validate_storage_name(&v.name).context("invalid volume name")?;
        anyhow::ensure!(
            v.name.len() <= 247,
            "volume names must be at most 247 characters; shorten the name"
        );
        if !seen.insert(v.name.to_ascii_lowercase()) {
            bail!(
                "duplicate volume name '{}' (names are case-insensitive); rename one volume",
                crate::render::escape_printable(&v.name)
            );
        }
        if v.size_mib == 0 {
            bail!(
                "volume '{}' must have size_mib > 0",
                crate::render::escape_printable(&v.name)
            );
        }
        let name = crate::render::escape_printable(&v.name);
        match (&v.guest, v.rootfs_overlay) {
            (Some(_), false) => {}
            (Some(_), true) => bail!(
                "volume '{name}' sets both guest and rootfs_overlay; keep one \
                 (guest mounts it at a path, rootfs_overlay makes it the root's writable layer)"
            ),
            (None, false) => {
                bail!("volume '{name}' needs a target: set guest: /path, or rootfs_overlay: true")
            }
            (None, true) => {
                anyhow::ensure!(
                    !has_overlay,
                    "volume '{name}' is a second rootfs_overlay; only one volume can be the root's writable layer"
                );
                has_overlay = true;
                anyhow::ensure!(
                    recipe.hw.rootfs_readonly,
                    "volume '{name}' is a rootfs_overlay, which layers over a read-only root; set hw.rootfs_readonly: true"
                );
                anyhow::ensure!(
                    v.lifetime == VolumeLifetime::Boot,
                    "volume '{name}' is a rootfs_overlay, so it must be fresh each boot; set lifetime: boot (the default is box)"
                );
            }
        }
    }
    Ok(())
}

pub(super) fn validate_storage_devices(recipe: &Recipe) -> Result<()> {
    let count = recipe
        .mounts
        .len()
        .checked_add(recipe.volumes.len())
        .ok_or_else(|| anyhow::anyhow!("too many volumes and host-directory mounts"))?;
    anyhow::ensure!(
        count <= crate::vm::MAX_GUEST_STORAGE_DEVICES,
        "a box supports at most {} combined volumes and host-directory mounts; remove a volume or mount",
        crate::vm::MAX_GUEST_STORAGE_DEVICES
    );
    Ok(())
}

fn validate_network(recipe: &Recipe) -> Result<()> {
    if !recipe.network.enabled {
        anyhow::ensure!(
            recipe.network.mode == super::NetworkMode::Allowlist
                && recipe.network.allow.is_empty()
                && recipe.network.hosts.is_empty()
                && recipe.network.ports.is_empty(),
            "network.enabled: false requires allowlist mode and empty allow, hosts, and ports; remove those grants or enable networking"
        );
        return Ok(());
    }
    crate::policy::network::rules::parse_port_mappings(&recipe.network.ports)?;
    terra_policy::BoxPolicy::new(
        &recipe.network.host_policy()?,
        terra_network::config::GATEWAY_ADDRESSES,
    )
    .map_err(anyhow::Error::msg)?;
    Ok(())
}

/// Refuse two entries claiming one guest path. They are mounted in recipe
/// order, so the later one silently wins and the earlier one is a line in the
/// recipe that does nothing.
fn validate_guest_paths(recipe: &Recipe) -> Result<()> {
    let claims = recipe
        .mounts
        .iter()
        .map(|m| {
            (
                m.guest.as_path(),
                format!(
                    "mount from '{}'",
                    crate::render::escape_printable_path(&m.host)
                ),
            )
        })
        .chain(recipe.volumes.iter().filter_map(|v| {
            Some((
                v.guest.as_deref()?,
                format!("volume '{}'", crate::render::escape_printable(&v.name)),
            ))
        }));
    let mut seen = HashMap::new();
    for (guest, what) in claims {
        anyhow::ensure!(
            guest != Path::new("/"),
            "guest path '/' on {what} would hide the root filesystem; pick a subdirectory \
             (a volume takes a read-only root's writes with rootfs_overlay: true)"
        );
        if let Some(earlier) = seen.insert(guest, what.clone()) {
            bail!(
                "guest path '{}' is claimed twice, by {earlier} and by {what} \
                 (the later one would be mounted over the earlier)",
                crate::render::escape_printable_path(guest)
            );
        }
    }
    Ok(())
}
