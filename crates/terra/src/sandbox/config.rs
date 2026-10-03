use anyhow::{Context as _, Result, bail};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LauncherConfig {
    Direct,
    Custom(PathBuf),
    Sandboxed {
        policy: Option<PathBuf>,
        allow_fallback: bool,
    },
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct HostConfig {
    vm: Option<VmConfig>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct VmConfig {
    init: Option<yaml_serde::Value>,
    bwrap: Option<BwrapConfig>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct BwrapConfig {
    policy: Option<yaml_serde::Value>,
    allow_fallback: Option<bool>,
}

pub(crate) fn load() -> Result<LauncherConfig> {
    if let Some(path) = std::env::var_os("TERRA_SECCOMP_CONFIG") {
        return load_from(Path::new(&path));
    }
    let path = crate::state::get_terra_home_path()?.join("config.yaml");
    let launcher = load_from(&path)?;
    if let LauncherConfig::Sandboxed {
        policy: None,
        allow_fallback,
    } = launcher
    {
        return Ok(LauncherConfig::Sandboxed {
            policy: find_override_policy()?,
            allow_fallback,
        });
    }
    Ok(launcher)
}

fn find_override_policy() -> Result<Option<PathBuf>> {
    let path = crate::state::get_terra_home_path()?.join("config/seccomp.bpf");
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Ok(Some(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("checking seccomp policy {}", path.display()))
        }
    }
}

pub(crate) fn write_resolved(path: &Path) -> Result<()> {
    load()?.write_to(path)
}

pub(crate) fn write_policy_workload(path: &Path, policy: Option<&Path>) -> Result<()> {
    let launcher = match policy {
        Some(policy) => LauncherConfig::Sandboxed {
            policy: Some(policy.to_path_buf()),
            allow_fallback: false,
        },
        None => LauncherConfig::Direct,
    };
    launcher.write_to(path)
}

impl LauncherConfig {
    fn write_to(&self, path: &Path) -> Result<()> {
        let config = match self {
            Self::Direct => serde_json::json!({"vm": {"init": "direct"}}),
            Self::Custom(launcher) => serde_json::json!({"vm": {"init": launcher}}),
            Self::Sandboxed {
                policy,
                allow_fallback,
            } => serde_json::json!({
                "vm": {"init": "bwrap", "bwrap": {"policy": policy, "allow_fallback": allow_fallback}}
            }),
        };
        std::fs::write(path, serde_json::to_vec(&config)?).context("writing launcher configuration")
    }
}

fn default_launcher() -> LauncherConfig {
    if super::DEFAULT_LAUNCHER == "bwrap" {
        LauncherConfig::Sandboxed {
            policy: None,
            allow_fallback: true,
        }
    } else {
        LauncherConfig::Direct
    }
}

pub(crate) fn load_from(path: &Path) -> Result<LauncherConfig> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(default_launcher());
        }
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let config: HostConfig = yaml_serde::from_str(&text)
        .with_context(|| format!("invalid host configuration {}", path.display()))?;
    let vm = config.vm.unwrap_or_default();
    let init = match vm.init {
        Some(yaml_serde::Value::String(init)) => init,
        None => super::DEFAULT_LAUNCHER.to_owned(),
        Some(_) => bail!(
            "{}: vm.init must be direct, bwrap, or an executable path",
            path.display()
        ),
    };
    if init.trim().is_empty() {
        bail!("{}: vm.init must not be empty", path.display());
    }
    if init == "direct" {
        return Ok(LauncherConfig::Direct);
    }
    let directory = path
        .parent()
        .context("global config has no parent directory")?;
    if init == "bwrap" {
        super::require_sandbox_support()
            .with_context(|| format!("{}: vm.init: bwrap", path.display()))?;
        let bwrap = vm.bwrap.unwrap_or_default();
        let allow_fallback = bwrap.allow_fallback.unwrap_or(true);
        let policy = bwrap
            .policy
            .map(|policy| resolve_policy_path(policy, path, directory))
            .transpose()?;
        return Ok(LauncherConfig::Sandboxed {
            policy,
            allow_fallback,
        });
    }
    let launcher = Path::new(&init);
    let launcher = if launcher.is_absolute() {
        launcher.to_path_buf()
    } else {
        directory.join(launcher)
    };
    Ok(LauncherConfig::Custom(launcher))
}

fn resolve_policy_path(
    policy: yaml_serde::Value,
    config: &Path,
    directory: &Path,
) -> Result<PathBuf> {
    let yaml_serde::Value::String(policy) = policy else {
        bail!(
            "{}: vm.bwrap.policy must be a local file path",
            config.display()
        );
    };
    if policy.is_empty() {
        bail!("{}: vm.bwrap.policy must not be empty", config.display());
    }
    if policy.contains("://") {
        bail!(
            "{}: vm.bwrap.policy must name a local file",
            config.display()
        );
    }
    let policy = PathBuf::from(policy);
    Ok(if policy.is_absolute() {
        policy
    } else {
        directory.join(policy)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_native_launcher_names_the_config_and_returns_unsupported() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        std::fs::write(&path, "vm:\n  init: bwrap\n").unwrap();
        let error = load_from(&path).unwrap_err();
        assert!(error.to_string().contains("config.yaml"));
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn self_test_config_keeps_resolved_launcher_and_policy_paths() {
        let home = crate::sys::TestHome::new();
        let terra_home = home.get_path().join(".terra");
        std::fs::create_dir_all(&terra_home).unwrap();
        let bundle = tempfile::tempdir().unwrap();
        let exported = bundle.path().join("launcher.json");
        let mut configs = vec!["vm:\n  init: direct\n", "vm:\n  init: ./launcher\n"];
        if cfg!(target_os = "linux") {
            configs.extend([
                "vm:\n  init: bwrap\n",
                "vm:\n  bwrap:\n    policy: local.bpf\n    allow_fallback: false\n",
            ]);
        }
        for config in configs {
            std::fs::write(terra_home.join("config.yaml"), config).unwrap();
            let expected = load().unwrap();
            write_resolved(&exported).unwrap();
            assert_eq!(load_from(&exported).unwrap(), expected);
        }
    }

    #[test]
    fn host_config_selects_exact_launcher_and_resolves_paths() {
        let home = tempfile::tempdir().unwrap();
        let config = home.path().join("config.yaml");
        #[cfg(target_os = "linux")]
        let platform_default = LauncherConfig::Sandboxed {
            policy: None,
            allow_fallback: true,
        };
        #[cfg(not(target_os = "linux"))]
        let platform_default = LauncherConfig::Direct;
        assert_eq!(load_from(&config).unwrap(), platform_default);
        std::fs::write(&config, "vm: {}\n").unwrap();
        assert_eq!(load_from(&config).unwrap(), platform_default);
        std::fs::write(&config, "vm:\n  init: null\n").unwrap();
        assert_eq!(load_from(&config).unwrap(), platform_default);
        std::fs::write(&config, "vm:\n  init: direct\n").unwrap();
        assert_eq!(load_from(&config).unwrap(), LauncherConfig::Direct);
        std::fs::write(
            &config,
            "vm:\n  init: direct\n  bwrap:\n    policy: unused.yml\n",
        )
        .unwrap();
        assert_eq!(load_from(&config).unwrap(), LauncherConfig::Direct);
        std::fs::write(&config, "vm:\n  init: ./direct\n").unwrap();
        assert_eq!(
            load_from(&config).unwrap(),
            LauncherConfig::Custom(home.path().join("./direct"))
        );
        std::fs::write(
            &config,
            "vm:\n  init: ./launch vm\n  bwrap:\n    policy: unused.yml\n",
        )
        .unwrap();
        assert_eq!(
            load_from(&config).unwrap(),
            LauncherConfig::Custom(home.path().join("./launch vm"))
        );
        #[cfg(target_os = "linux")]
        {
            std::fs::write(&config, "vm:\n  bwrap:\n    policy: policy.yml\n").unwrap();
            assert_eq!(
                load_from(&config).unwrap(),
                LauncherConfig::Sandboxed {
                    policy: Some(home.path().join("policy.yml")),
                    allow_fallback: true
                }
            );
            std::fs::write(
                &config,
                "vm:\n  init: null\n  bwrap:\n    policy: policy.yml\n",
            )
            .unwrap();
            assert_eq!(
                load_from(&config).unwrap(),
                LauncherConfig::Sandboxed {
                    policy: Some(home.path().join("policy.yml")),
                    allow_fallback: true
                }
            );
            std::fs::write(
                &config,
                "vm:\n  init: bwrap\n  bwrap:\n    policy: policy.yml\n",
            )
            .unwrap();
            assert_eq!(
                load_from(&config).unwrap(),
                LauncherConfig::Sandboxed {
                    policy: Some(home.path().join("policy.yml")),
                    allow_fallback: true
                }
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fallback_is_optional_and_requires_a_boolean() {
        let home = tempfile::tempdir().unwrap();
        let config = home.path().join("config.yaml");
        for allow_fallback in [true, false] {
            std::fs::write(
                &config,
                format!("vm:\n  bwrap:\n    allow_fallback: {allow_fallback}\n"),
            )
            .unwrap();
            assert_eq!(
                load_from(&config).unwrap(),
                LauncherConfig::Sandboxed {
                    policy: None,
                    allow_fallback
                }
            );
        }
        std::fs::write(&config, "vm:\n  bwrap:\n    allow_fallback: sometimes\n").unwrap();
        assert!(load_from(&config).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn policy_precedence_is_explicit_then_home_override_then_builtin() {
        let home = crate::sys::TestHome::new();
        let terra_home = home.get_path().join(".terra");
        std::fs::create_dir_all(terra_home.join("config")).unwrap();
        assert_eq!(
            load().unwrap(),
            LauncherConfig::Sandboxed {
                policy: None,
                allow_fallback: true
            }
        );
        let override_path = terra_home.join("config/seccomp.bpf");
        std::fs::write(&override_path, b"invalid BPF").unwrap();
        let overridden = load().unwrap();
        assert_eq!(
            overridden,
            LauncherConfig::Sandboxed {
                policy: Some(override_path.clone()),
                allow_fallback: true
            }
        );
        assert!(crate::sandbox::resolve_policy(Some(&override_path), true).is_err());
        std::fs::write(
            terra_home.join("config.yaml"),
            "vm:\n  bwrap:\n    policy: explicit.bpf\n    allow_fallback: false\n",
        )
        .unwrap();
        assert_eq!(
            load().unwrap(),
            LauncherConfig::Sandboxed {
                policy: Some(terra_home.join("explicit.bpf")),
                allow_fallback: false
            }
        );
        std::fs::write(terra_home.join("config.yaml"), "vm:\n  init: direct\n").unwrap();
        assert_eq!(load().unwrap(), LauncherConfig::Direct);
    }

    #[test]
    fn invalid_launcher_settings_name_file() {
        let home = tempfile::tempdir().unwrap();
        let config = home.path().join("config.yaml");
        for text in [
            "vm:\n  init: ''\n",
            "vm:\n  init: ' '\n",
            "vm:\n  init: [bwrap]\n",
            "vm:\n  init: true\n",
            "vm:\n  init: 5\n",
            "vm:\n  int: bwrap\n",
            "vm:\n  bwrap:\n    polciy: x\n",
            "vm:\n  init: bwrap\n  bwrap:\n    policy: ''\n",
            "vm:\n  init: bwrap\n  bwrap:\n    policy: https://example.com/policy.yml\n",
        ] {
            std::fs::write(&config, text).unwrap();
            let error = load_from(&config).unwrap_err().to_string();
            assert!(error.contains("config.yaml"), "{error}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn default_bwrap_rejects_invalid_explicit_policy() {
        let home = tempfile::tempdir().unwrap();
        let config = home.path().join("config.yaml");
        for text in [
            "vm:\n  bwrap:\n    policy: ''\n",
            "vm:\n  bwrap:\n    policy: true\n",
            "vm:\n  bwrap:\n    policy: https://example.com/policy.yml\n",
        ] {
            std::fs::write(&config, text).unwrap();
            let error = load_from(&config).unwrap_err().to_string();
            assert!(error.contains("vm.bwrap.policy"), "{error}");
        }
    }
}
