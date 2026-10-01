use anyhow::{Context as _, Result, bail};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LauncherConfig {
    Direct,
    Custom(PathBuf),
    Bwrap {
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
    let path = crate::state::get_terra_home_path()?.join("config.yaml");
    let launcher = load_from(&path)?;
    #[cfg(target_os = "linux")]
    if let LauncherConfig::Bwrap {
        policy: None,
        allow_fallback,
    } = launcher
    {
        return Ok(LauncherConfig::Bwrap {
            policy: super::launcher_policy::find_override_policy()?,
            allow_fallback,
        });
    }
    Ok(launcher)
}

fn default_launcher() -> LauncherConfig {
    if cfg!(target_os = "linux") {
        LauncherConfig::Bwrap {
            policy: None,
            allow_fallback: true,
        }
    } else {
        LauncherConfig::Direct
    }
}

fn load_from(path: &Path) -> Result<LauncherConfig> {
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
        None => {
            #[cfg(target_os = "linux")]
            {
                "bwrap".to_owned()
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Ok(LauncherConfig::Direct);
            }
        }
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
        #[cfg(not(target_os = "linux"))]
        bail!(
            "{}: vm.init: bwrap requires a Linux host; choose a custom launcher",
            path.display()
        );
        #[cfg(target_os = "linux")]
        {
            let bwrap = vm.bwrap.unwrap_or_default();
            let allow_fallback = bwrap.allow_fallback.unwrap_or(true);
            let policy = bwrap
                .policy
                .map(|policy| {
                    let yaml_serde::Value::String(policy) = policy else {
                        bail!(
                            "{}: vm.bwrap.policy must be a local file path",
                            path.display()
                        );
                    };
                    if policy.is_empty() {
                        bail!("{}: vm.bwrap.policy must not be empty", path.display());
                    }
                    if policy.contains("://") {
                        bail!("{}: vm.bwrap.policy must name a local file", path.display());
                    }
                    let policy = PathBuf::from(policy);
                    Ok(if policy.is_absolute() {
                        policy
                    } else {
                        directory.join(policy)
                    })
                })
                .transpose()?;
            return Ok(LauncherConfig::Bwrap {
                policy,
                allow_fallback,
            });
        }
    }
    let launcher = Path::new(&init);
    let launcher = if launcher.is_absolute() {
        launcher.to_path_buf()
    } else {
        directory.join(launcher)
    };
    Ok(LauncherConfig::Custom(launcher))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_config_selects_exact_launcher_and_resolves_paths() {
        let home = tempfile::tempdir().unwrap();
        let config = home.path().join("config.yaml");
        #[cfg(target_os = "linux")]
        let platform_default = LauncherConfig::Bwrap {
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
                LauncherConfig::Bwrap {
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
                LauncherConfig::Bwrap {
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
                LauncherConfig::Bwrap {
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
                LauncherConfig::Bwrap {
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
            LauncherConfig::Bwrap {
                policy: None,
                allow_fallback: true
            }
        );
        let override_path = terra_home.join("config/seccomp.bpf");
        std::fs::write(&override_path, b"invalid BPF").unwrap();
        let overridden = load().unwrap();
        assert_eq!(
            overridden,
            LauncherConfig::Bwrap {
                policy: Some(override_path.clone()),
                allow_fallback: true
            }
        );
        assert!(super::super::launcher_policy::resolve(Some(&override_path), true).is_err());
        std::fs::write(
            terra_home.join("config.yaml"),
            "vm:\n  bwrap:\n    policy: explicit.bpf\n    allow_fallback: false\n",
        )
        .unwrap();
        assert_eq!(
            load().unwrap(),
            LauncherConfig::Bwrap {
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
