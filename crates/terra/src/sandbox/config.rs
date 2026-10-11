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
    sandbox: Option<SandboxConfig>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SandboxConfig {
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
    let directory = crate::state::get_terra_home_path()?.join("config");
    let path = directory.join("seccomp");
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Ok(Some(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("checking seccomp bundle {}", path.display()))
        }
    }
}

pub(crate) fn write_resolved(path: &Path) -> Result<()> {
    load()?.write_to(path)
}

pub(crate) fn write_policy_workload(path: &Path, policy: Option<&Path>) -> Result<()> {
    LauncherConfig::Sandboxed {
        policy: policy.map(Path::to_path_buf),
        allow_fallback: policy.is_none(),
    }
    .write_to(path)
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
                "vm": {"init": "sandbox", "sandbox": {"policy": policy, "allow_fallback": allow_fallback}}
            }),
        };
        std::fs::write(path, serde_json::to_vec(&config)?).context("writing launcher configuration")
    }
}

const fn default_launcher() -> LauncherConfig {
    LauncherConfig::Sandboxed {
        policy: None,
        allow_fallback: true,
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
        None => "sandbox".to_owned(),
        Some(_) => bail!(
            "{}: vm.init must be direct, sandbox, or an executable path",
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
    if init == "sandbox" {
        let sandbox = vm.sandbox.unwrap_or_default();
        let allow_fallback = sandbox.allow_fallback.unwrap_or(true);
        let policy = sandbox
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
            "{}: vm.sandbox.policy must be a local bundle directory path",
            config.display()
        );
    };
    if policy.is_empty() {
        bail!("{}: vm.sandbox.policy must not be empty", config.display());
    }
    if policy.contains("://") {
        bail!(
            "{}: vm.sandbox.policy must name a local bundle directory",
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

    #[test]
    fn self_test_config_keeps_resolved_launcher_and_policy_paths() {
        let home = crate::sys::TestHome::new();
        let terra_home = home.get_path().join(".terra");
        std::fs::create_dir_all(&terra_home).unwrap();
        let bundle = tempfile::tempdir().unwrap();
        let exported = bundle.path().join("launcher.json");
        for config in [
            "vm:\n  init: direct\n",
            "vm:\n  init: ./launcher\n",
            "vm:\n  init: sandbox\n",
            "vm:\n  sandbox:\n    policy: local.bpf\n    allow_fallback: false\n",
        ] {
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
        let platform_default = default_launcher();
        assert_eq!(load_from(&config).unwrap(), platform_default);
        std::fs::write(&config, "vm: {}\n").unwrap();
        assert_eq!(load_from(&config).unwrap(), platform_default);
        std::fs::write(&config, "vm:\n  init: null\n").unwrap();
        assert_eq!(load_from(&config).unwrap(), platform_default);
        std::fs::write(&config, "vm:\n  init: direct\n").unwrap();
        assert_eq!(load_from(&config).unwrap(), LauncherConfig::Direct);
        std::fs::write(
            &config,
            "vm:\n  init: direct\n  sandbox:\n    policy: unused.yml\n",
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
            "vm:\n  init: ./launch vm\n  sandbox:\n    policy: unused.yml\n",
        )
        .unwrap();
        assert_eq!(
            load_from(&config).unwrap(),
            LauncherConfig::Custom(home.path().join("./launch vm"))
        );
        {
            std::fs::write(&config, "vm:\n  sandbox:\n    policy: policy.yml\n").unwrap();
            assert_eq!(
                load_from(&config).unwrap(),
                LauncherConfig::Sandboxed {
                    policy: Some(home.path().join("policy.yml")),
                    allow_fallback: true
                }
            );
            std::fs::write(
                &config,
                "vm:\n  init: null\n  sandbox:\n    policy: policy.yml\n",
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
                "vm:\n  init: sandbox\n  sandbox:\n    policy: policy.yml\n",
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

    #[test]
    fn fallback_is_optional_and_requires_a_boolean() {
        let home = tempfile::tempdir().unwrap();
        let config = home.path().join("config.yaml");
        for allow_fallback in [true, false] {
            std::fs::write(
                &config,
                format!("vm:\n  sandbox:\n    allow_fallback: {allow_fallback}\n"),
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
        std::fs::write(&config, "vm:\n  sandbox:\n    allow_fallback: sometimes\n").unwrap();
        assert!(load_from(&config).is_err());
    }

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
        let override_path = terra_home.join("config/seccomp");
        std::fs::write(&override_path, b"invalid BPF").unwrap();
        let overridden = load().unwrap();
        assert_eq!(
            overridden,
            LauncherConfig::Sandboxed {
                policy: Some(override_path.clone()),
                allow_fallback: true
            }
        );
        assert!(terra_sandbox::resolve_policy(Some(&override_path), true).is_err());
        std::fs::write(
            terra_home.join("config.yaml"),
            "vm:\n  sandbox:\n    policy: explicit.bpf\n    allow_fallback: false\n",
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
            "vm:\n  init: [sandbox]\n",
            "vm:\n  init: true\n",
            "vm:\n  init: 5\n",
            "vm:\n  int: sandbox\n",
            "vm:\n  sandbox:\n    polciy: x\n",
            "vm:\n  init: sandbox\n  sandbox:\n    policy: ''\n",
            "vm:\n  init: sandbox\n  sandbox:\n    policy: https://example.com/policy.yml\n",
        ] {
            std::fs::write(&config, text).unwrap();
            let error = load_from(&config).unwrap_err().to_string();
            assert!(error.contains("config.yaml"), "{error}");
        }
    }

    #[test]
    fn default_sandbox_rejects_invalid_explicit_policy() {
        let home = tempfile::tempdir().unwrap();
        let config = home.path().join("config.yaml");
        for text in [
            "vm:\n  sandbox:\n    policy: ''\n",
            "vm:\n  sandbox:\n    policy: true\n",
            "vm:\n  sandbox:\n    policy: https://example.com/policy.yml\n",
        ] {
            std::fs::write(&config, text).unwrap();
            let error = load_from(&config).unwrap_err().to_string();
            assert!(error.contains("vm.sandbox.policy"), "{error}");
        }
    }
}
