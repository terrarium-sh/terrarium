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
    pub components: Components,
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
pub struct Components {
    pub memory_mib: u32,
    pub total_memory_mib: u32,
}

impl Default for Components {
    fn default() -> Self {
        Self {
            memory_mib: terra_runtime::box_runtime::DEFAULT_COMPONENT_MEMORY_MIB,
            total_memory_mib: terra_runtime::box_runtime::DEFAULT_TOTAL_MEMORY_MIB,
        }
    }
}

impl Components {
    pub fn memory_limits(&self) -> Result<terra_runtime::box_runtime::ComponentMemoryLimits> {
        let component_bytes = usize::try_from(u64::from(self.memory_mib) << 20)
            .context("components.memory_mib is too large for this host")?;
        let total_bytes = usize::try_from(u64::from(self.total_memory_mib) << 20)
            .context("components.total_memory_mib is too large for this host")?;
        terra_runtime::box_runtime::ComponentMemoryLimits::new(component_bytes, total_bytes)
            .map_err(|error| anyhow::anyhow!("{error}"))
            .context("set components.memory_mib > 0 and components.total_memory_mib >= components.memory_mib")
    }
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
pub(crate) const MAX_RECIPE_BYTES: u64 = 8 << 20;

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
    /// Allows public destinations except addresses collected from host interfaces at VM startup.
    /// Explicit `allow` rules can grant access to those addresses and private ranges.
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
    /// `"8080"` means `8080:8080`. IPv4 is required; IPv6 loopback is best-effort.
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

pub(crate) fn read_recipe_text(path: &Path) -> std::io::Result<String> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    crate::sys::open_regular_file(path)
        .map(|file| file.take(MAX_RECIPE_BYTES + 1))?
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECIPE_BYTES {
        return Err(std::io::Error::other(format!(
            "recipe is larger than the {MAX_RECIPE_BYTES}-byte limit"
        )));
    }
    String::from_utf8(bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn open_regular_env_file(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, openat};
        use std::path::Component;

        if !path.is_absolute() {
            return Err(std::io::Error::other("env file is not an absolute path"));
        }
        let mut directory = std::fs::File::open("/")?;
        let mut components = path.components().peekable();
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                if component != Component::RootDir {
                    return Err(std::io::Error::other("env file is not an absolute path"));
                }
                continue;
            };
            let flags = if components.peek().is_some() {
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
            } else {
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC
            };
            let file =
                openat(&directory, name, flags, Mode::empty()).map_err(std::io::Error::from)?;
            if components.peek().is_some() {
                directory = file.into();
            } else {
                let file = std::fs::File::from(file);
                if !file.metadata()?.is_file() {
                    return Err(std::io::Error::other("expected a regular file"));
                }
                return Ok(file);
            }
        }
        Err(std::io::Error::other("expected a regular file"))
    }

    #[cfg(not(unix))]
    {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::other("expected a regular file"));
        }
        #[cfg(windows)]
        if read_final_path(&file)? != path {
            return Err(std::io::Error::other("env file changed while opening it"));
        }
        Ok(file)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn read_final_path(file: &std::fs::File) -> std::io::Result<PathBuf> {
    use std::os::{windows::ffi::OsStringExt as _, windows::io::AsRawHandle as _};
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;

    const PATH_CAPACITY: u32 = 32_768;
    let mut path = vec![0; PATH_CAPACITY as usize];
    // SAFETY: `path` is writable for its stated length and `file` stays open.
    let len = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle().cast(),
            path.as_mut_ptr(),
            PATH_CAPACITY,
            0,
        )
    };
    if len == 0 || len >= PATH_CAPACITY {
        return Err(std::io::Error::last_os_error());
    }
    Ok(std::ffi::OsString::from_wide(&path[..len as usize]).into())
}

fn escape_yaml_error(error: &yaml_serde::Error) -> anyhow::Error {
    anyhow::anyhow!(crate::render::escape_printable(&error.to_string()))
}

pub fn load_manifest(project_dir: &Path) -> Result<Option<Manifest>> {
    let path = project_dir.join(MANIFEST_FILE);
    let text = match read_recipe_text(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| {
                format!("reading {}", crate::render::escape_printable_path(&path))
            });
        }
    };
    let manifest: Manifest = yaml_serde::from_str(&text)
        .map_err(|error| escape_yaml_error(&error))
        .with_context(|| {
            format!(
                "failed to parse {}",
                crate::render::escape_printable_path(&path)
            )
        })?;
    for (name, reference) in &manifest.boxes {
        crate::name::validate_box_name(name)
            .with_context(|| format!("in {}", crate::render::escape_printable_path(&path)))?;
        if !crate::resolve::is_path(reference) {
            let reference = crate::render::escape_printable(reference);
            bail!(
                "box '{name}' in {} points at '{reference}', which is not a recipe path \
                 (a reference is a path, e.g. ./{reference}.yaml)",
                crate::render::escape_printable_path(&path)
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

pub fn load_path(path: &Path, project_dir: &Path) -> Result<Config> {
    let text = read_recipe_text(path)
        .with_context(|| format!("reading {}", crate::render::escape_printable_path(path)))?;
    parse_recipe(&text, project_dir, path)
}

pub fn parse_recipe(text: &str, project_dir: &Path, source: &Path) -> Result<Config> {
    let mut cfg: Config = yaml_serde::from_str(text)
        .map_err(|error| escape_yaml_error(&error))
        .with_context(|| {
            format!(
                "failed to parse YAML from {}",
                crate::render::escape_printable_path(source)
            )
        })?;
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
    let path = path.as_os_str().to_string_lossy();
    if !path.starts_with('/') {
        bail!(
            "guest path must be absolute: '{}'",
            crate::render::escape_printable(&path)
        );
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            name => {
                if name.contains('\\') {
                    bail!(
                        "guest path '{}' contains a backslash",
                        crate::render::escape_printable(&path)
                    );
                }
                components.push(name);
            }
        }
    }
    Ok(PathBuf::from(format!("/{}", components.join("/"))))
}
/// The writable shares a recipe declares, read leniently.
pub(crate) fn list_declared_writable_shares(
    text: &str,
    project_dir: &Path,
) -> Result<Vec<PathBuf>> {
    #[derive(Deserialize, Default)]
    struct RecipeMounts {
        #[serde(default)]
        mounts: Vec<yaml_serde::Value>,
    }

    let recipe: RecipeMounts = yaml_serde::from_str(text)?;
    anyhow::ensure!(
        !recipe
            .mounts
            .iter()
            .any(|mount| mount.as_mapping().is_some_and(|map| map.contains_key("<<"))),
        "cannot determine writable shares from YAML merge keys"
    );
    Ok(recipe
        .mounts
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
        .collect())
}

/// Merge `env_file:` over `env:` - the file wins - warning on a name set in
/// both.
pub(crate) fn merge_env_file(cfg: &mut Config) -> Result<()> {
    let Some(path) = cfg.env_file.as_ref() else {
        return Ok(());
    };
    let mut text = String::new();
    open_regular_env_file(path)
        .with_context(|| {
            format!(
                "opening env file {}",
                crate::render::escape_printable_path(path)
            )
        })?
        .take(MAX_ENV_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .with_context(|| {
            format!(
                "reading env file {}",
                crate::render::escape_printable_path(path)
            )
        })?;
    anyhow::ensure!(
        text.len() as u64 <= MAX_ENV_FILE_BYTES,
        "env file {} is larger than the {MAX_ENV_FILE_BYTES}-byte limit",
        crate::render::escape_printable_path(path)
    );
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .with_context(|| format!("invalid env file line {} (want KEY=VAL)", index + 1))?;
        // Only a value the merge actually changes is worth a word: the same
        // name set to the same thing in both is a recipe stating what the
        // dotenv already says, not an override anyone loses.
        if cfg.env.get(k).is_some_and(|from_recipe| from_recipe != v) {
            eprintln!(
                "terra: warning: env variable '{}' is set in both env: and \
                 env_file: {} - the env_file wins",
                crate::render::escape_printable(k),
                crate::render::escape_printable_path(path)
            );
        }
        cfg.env.insert(k.to_string(), v.to_string());
    }
    validate_env(&cfg.env)
}

pub(crate) fn resolve_env_file(cfg: &mut Config) -> Result<()> {
    let Some(path) = cfg.env_file.as_ref() else {
        return Ok(());
    };
    cfg.env_file = Some(std::fs::canonicalize(path).with_context(|| {
        format!(
            "resolving env file {}",
            crate::render::escape_printable_path(path)
        )
    })?);
    Ok(())
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
            crate::render::escape_printable_path(p)
        );
    }
    Ok(p.to_path_buf())
}
