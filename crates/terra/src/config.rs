//! Parse and validate a YAML recipe into a [`Config`]

#[cfg(test)]
mod tests;
mod validate;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use validate::{validate, validate_env};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub hw: Hw,
    pub mounts: Vec<Mount>,
    pub volumes: Vec<Volume>,
    pub network: Network,
    pub hooks: Hooks,
    /// Background shell lines, restarted on failure for the box's lifetime.
    /// Exit 0 ends the daemon; anything else respawns after 1s.
    pub daemons: Vec<String>,
    pub workload: Workload,
    /// Commands the workload user may run as root through `doas` (aliased to
    /// `sudo`). Empty grants nothing.
    pub sudo: Vec<String>,
    /// Exported for the workload and hooks, `env_file:` merged on top (last
    /// wins). `BTreeMap` so the export order is deterministic.
    pub env: BTreeMap<String, String>,
    /// A dotenv-style file merged over `env:` - the file wins. `KEY=VAL`
    /// lines only, no space around the `=`.
    pub env_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Hw {
    pub cpus: u8,
    pub mem_mib: u32,
    /// Sparse, so only what gets written costs.
    pub rootfs_mib: u32,
}

impl Default for Hw {
    fn default() -> Self {
        Self {
            cpus: 2,
            mem_mib: 1024,
            rootfs_mib: 512,
        }
    }
}

/// Under this the guest kernel dies part-way through boot, which reads as a
/// hang rather than an error - so a recipe naming less is refused here instead.
const MIN_MEM_MIB: u32 = 128;

const MAX_ENV_FILE_BYTES: u64 = 1 << 20;

/// A bounded scratch volume
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Volume {
    /// Names the image file (`vol-<name>.img` under the box's state dir).
    /// Renaming starts a fresh image.
    pub name: String,
    pub guest: PathBuf,
    /// Writes past this fail with ENOSPC.
    pub size_mib: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    /// `.`, `~`, or a relative path resolves against the project directory
    pub host: PathBuf,
    pub guest: PathBuf,
    #[serde(default)]
    pub readonly: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Public addresses without a rule. The host, its LAN and every private
    /// range stay out of reach in this mode too - `allow` / `hosts` rules are
    /// how a recipe opens one.
    #[serde(rename = "unrestricted-public")]
    UnrestrictedPublic,
    /// Nothing without a rule; an empty allowlist reaches nothing.
    #[default]
    Allowlist,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Network {
    pub mode: NetworkMode,
    /// `HOST-or-IP-or-CIDR[:PORT]`, or `[v6]:port`. No port means any port.
    pub allow: Vec<String>,
    pub hosts: Vec<StaticDnsRecord>,
    /// Expose a guest listener on the host loopback: `"HOST[:GUEST]"`, so a bare
    /// `"8080"` means `8080:8080`. Bound on `127.0.0.1` only.
    pub ports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StaticDnsRecord {
    pub name: String,
    /// An IP address, or `HOST_LOOPBACK` for the machine terra is running on.
    pub addr: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Hooks {
    /// One-time setup baked into the box's filesystem, before any share is
    /// mounted.
    pub on_create: Vec<String>,
    /// Every boot, before the workload.
    pub on_start: Vec<String>,
    pub pre_stop: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Workload {
    pub entrypoint: PathBuf,
    pub args: Vec<String>,
    /// Where the workload starts, as an absolute guest path. Unset, the
    /// workload starts in the workload user's home (`/home/terri`).
    pub workdir: Option<PathBuf>,
}

impl Default for Workload {
    fn default() -> Self {
        Self {
            entrypoint: PathBuf::from("/bin/sh"),
            args: Vec::new(),
            workdir: None,
        }
    }
}

/// The project manifest: the project's boxes by name (`ci: ./ci.yaml`),
/// committed with the code. References only - each a recipe path,
/// never a recipe: the manifest lives in a tree a guest can write, and the
/// worst a reference can do is point at a recipe the user already has, which
/// pinning asks about.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub boxes: BTreeMap<String, String>,
}

pub const MANIFEST_FILE: &str = "terra.yaml";

pub fn load_manifest(project_dir: &Path) -> Result<Option<Manifest>> {
    let path = project_dir.join(MANIFEST_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let manifest: Manifest = yaml_serde::from_str(&text)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    for (name, reference) in &manifest.boxes {
        crate::name::validate_box_name(name).with_context(|| format!("in {}", path.display()))?;
        if !crate::resolve::is_path(reference) {
            bail!(
                "box '{name}' in {} points at '{reference}', which is not a recipe path \
                 (a reference is a path, e.g. ./{reference}.yaml)",
                path.display()
            );
        }
    }
    Ok(Some(manifest))
}

/// [`load_manifest`], degrading a broken manifest to "none" with a warning.
///
/// `terra.yaml` sits in the project root, which is exactly what a box shares,
/// so a guest can leave it unparseable - and every verb that only needs a *box*
/// would then refuse, taking `stop`, `rm` and `logs` away from the box that did
/// it.
#[must_use]
pub fn load_manifest_or_warn(project_dir: &Path) -> Option<Manifest> {
    match load_manifest(project_dir) {
        Ok(manifest) => manifest,
        Err(e) => {
            eprintln!(
                "terra: warning: {e:#}\n\
                 terra: continuing without it - box names resolve from what is set up on \
                 disk, and `terra setup` needs it fixed"
            );
            None
        }
    }
}

pub(crate) fn resolve_mounts_for(mounts: &mut [Mount]) -> Result<()> {
    for m in mounts {
        m.host = std::fs::canonicalize(&m.host)
            .with_context(|| format!("resolving mount host path '{}'", m.host.display()))?;
    }
    Ok(())
}

pub fn load_path(path: &Path, project_dir: &Path) -> Result<Config> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_recipe(&text, project_dir, path)
}

pub fn parse_recipe(text: &str, project_dir: &Path, source: &Path) -> Result<Config> {
    let mut cfg: Config = yaml_serde::from_str(text)
        .with_context(|| format!("failed to parse YAML from {}", source.display()))?;
    for mount in &mut cfg.mounts {
        mount.host = resolve_recipe_path(&mount.host, project_dir)?;
    }
    if let Some(file) = &cfg.env_file {
        cfg.env_file = Some(resolve_recipe_path(file, project_dir)?);
    }
    for path in cfg
        .mounts
        .iter_mut()
        .map(|mount| &mut mount.guest)
        .chain(cfg.volumes.iter_mut().map(|volume| &mut volume.guest))
    {
        *path = normalize_guest_path(path)?;
    }
    for command in &mut cfg.sudo {
        *command = command.trim().to_string();
    }
    validate(&cfg)?;
    Ok(cfg)
}

fn normalize_guest_path(path: &Path) -> Result<PathBuf> {
    use std::path::Component;
    if !path.is_absolute() {
        bail!("guest path must be absolute: '{}'", path.display());
    }
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => normalized.push(name),
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(_) => bail!("guest path '{}' is not absolute", path.display()),
        }
    }
    Ok(normalized)
}
/// The writable shares a recipe declares, read leniently.
#[must_use]
pub(crate) fn list_declared_writable_shares(text: &str, project_dir: &Path) -> Vec<PathBuf> {
    let Ok(yaml_serde::Value::Mapping(recipe)) = yaml_serde::from_str(text) else {
        return Vec::new();
    };
    let Some(yaml_serde::Value::Sequence(mounts)) = recipe.get("mounts") else {
        return Vec::new();
    };
    mounts
        .iter()
        .filter_map(|mount| {
            let yaml_serde::Value::Mapping(mount) = mount else {
                return None;
            };
            if mount
                .get("readonly")
                .and_then(yaml_serde::Value::as_bool)
                .unwrap_or(false)
            {
                return None;
            }
            yaml_serde::from_value::<PathBuf>(mount.get("host")?.clone()).ok()
        })
        .map(|host| {
            resolve_recipe_path(&host, project_dir).unwrap_or_else(|_| project_dir.join(host))
        })
        .collect()
}

/// Merge `env_file:` over `env:` - the file wins - warning on a name set in
/// both. Read without following symlinks (see [`crate::sys::open_no_symlinks`]).
pub(crate) fn merge_env_file(cfg: &mut Config) -> Result<()> {
    let Some(path) = cfg.env_file.as_ref() else {
        return Ok(());
    };
    let mut text = String::new();
    crate::sys::open_no_symlinks(path)
        .with_context(|| format!("opening env file {}", path.display()))?
        .take(MAX_ENV_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .with_context(|| format!("reading env file {}", path.display()))?;
    anyhow::ensure!(
        text.len() as u64 <= MAX_ENV_FILE_BYTES,
        "env file {} is larger than the {MAX_ENV_FILE_BYTES}-byte limit",
        path.display()
    );
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .with_context(|| format!("invalid env file line (want KEY=VAL): {line}"))?;
        // Only a value the merge actually changes is worth a word: the same
        // name set to the same thing in both is a recipe stating what the
        // dotenv already says, not an override anyone loses.
        if cfg.env.get(k).is_some_and(|from_recipe| from_recipe != v) {
            eprintln!(
                "terra: warning: env variable '{k}' is set in both env: and \
                 env_file: {} - the env_file wins",
                path.display()
            );
        }
        cfg.env.insert(k.to_string(), v.to_string());
    }
    validate_env(&cfg.env)
}

/// Where a path written in a recipe or a `terra.yaml` lands: `~` expanded, then
/// made absolute against `source_dir` - the directory that file belongs to,
/// never the shell's (see [`crate::resolve`]). The one spelling of the
/// rule, so a `mounts[].host`, an `env_file:` and a manifest reference cannot
/// resolve three different ways.
pub(crate) fn resolve_recipe_path(p: &Path, source_dir: &Path) -> Result<PathBuf> {
    crate::sys::resolve_absolute_path(&expand_tilde(p)?, source_dir)
}

pub(crate) fn expand_tilde(p: &Path) -> Result<PathBuf> {
    if let Ok(rest) = p.strip_prefix("~") {
        return Ok(crate::sys::resolve_home_dir()?.join(rest));
    }
    // `~alice/data` is the shell's expansion, not a path terra can resolve -
    // and it is not the current user's `~` either. Left alone it joins onto the
    // project directory and fails much later as a missing `./~alice/data`.
    if let Some(std::path::Component::Normal(first)) = p.components().next()
        && first.to_string_lossy().starts_with('~')
    {
        bail!(
            "path '{}' names another user's home with '~', which terra does not expand \
             - write the absolute path (only a leading '~/' is expanded)",
            p.display()
        );
    }
    Ok(p.to_path_buf())
}
