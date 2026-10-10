//! Configuring the component VMM and the boot plan it sends to the guest.

pub mod boot;
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "macos", target_arch = "aarch64"),
    target_os = "windows"
))]
mod component;
mod launcher;
pub(crate) mod supervisor;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) use component::run_host_self_test_worker;
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "macos", target_arch = "aarch64"),
    target_os = "windows"
))]
pub use component::{run, run_host_self_test};
pub mod image;
mod resources;

use self::boot::BootSpec;
use crate::config;
use crate::policy::network;
use crate::render::{format_workload_line, redact_config_env, render_config_yaml};
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "macos", target_arch = "aarch64"),
    target_os = "windows"
)))]
use anyhow::bail;
use anyhow::{Context as _, Result};
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::Read as _;
use terra_protocol::{Disk, Net, Plan, PlanMode, Share, WORKLOAD_ID, WORKLOAD_USER_NAME};
use terra_runtime::component::network::HostServiceAddresses;

pub(crate) const HOST_SERVICE_ADDRESSES: HostServiceAddresses = HostServiceAddresses::default();
pub(crate) use terra_runtime::machine::MAX_GUEST_STORAGE_DEVICES;

fn read_host_timezone() -> Option<Vec<u8>> {
    #[cfg(unix)]
    {
        const MAX_TIMEZONE_BYTES: u64 = 1 << 20;

        let mut bytes = Vec::new();
        (File::open("/etc/localtime")
            .and_then(|file| file.take(MAX_TIMEZONE_BYTES + 1).read_to_end(&mut bytes))
            .is_ok()
            && bytes.len() as u64 <= MAX_TIMEZONE_BYTES
            && bytes.starts_with(b"TZif"))
        .then_some(bytes)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "macos", target_arch = "aarch64"),
    target_os = "windows"
)))]
#[allow(clippy::unused_async)]
pub async fn run(
    _spec: &BootSpec,
    _bx: &crate::state::BoxRef,
    _lock: Option<&File>,
    _on_ready: impl FnOnce() + Send,
) -> Result<std::process::ExitCode> {
    bail!(
        "VM execution requires Linux x86_64/aarch64, macOS Apple Silicon, or Windows x86_64/aarch64"
    )
}

#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "macos", target_arch = "aarch64"),
    target_os = "windows"
)))]
#[allow(clippy::unused_async)]
pub async fn run_host_self_test() -> Result<()> {
    bail!("host self-tests require a supported Terra platform")
}

pub(crate) fn encode_boot_plan(spec: &BootSpec) -> Result<Vec<u8>> {
    terra_protocol::encode_frame_with_limit(
        &terra_protocol::BootPlan::new(build_plan(spec)?),
        terra_protocol::MAX_PLAN_BYTES - terra_protocol::MAX_PLAN_HOST_STATE_BYTES,
    )
    .context("boot plan exceeds its encoded size limit; reduce the recipe or environment")
}

/// The resolved config the agent runs as PID 1.
fn build_plan(spec: &BootSpec) -> Result<Plan> {
    let cfg = &spec.cfg;
    let baking = spec.mode == PlanMode::Create;
    let shares = if baking {
        Vec::new()
    } else {
        cfg.mounts
            .iter()
            .enumerate()
            .map(|(index, mount)| Share {
                tag: terra_runtime::component::fs::share_tag(index),
                guest: mount.guest.to_string_lossy().into_owned(),
                readonly: mount.readonly,
            })
            .collect()
    };
    let volumes = cfg
        .volumes
        .iter()
        .enumerate()
        .map(|(index, volume)| {
            Ok(Disk {
                dev: terra_protocol::to_volume_device(index).with_context(|| {
                    format!("volume {index} is past the last guest block device")
                })?,
                guest: volume.guest.to_string_lossy().into_owned(),
            })
        })
        .collect::<Result<_>>()?;
    let published_mappings = if baking {
        Vec::new()
    } else {
        network::rules::parse_port_mappings(&cfg.network.ports)?
    };
    let (mut published_ports, mut published_udp_ports) = (Vec::new(), Vec::new());
    for mapping in published_mappings {
        match mapping.transport {
            terra_protocol::network::ResourceKind::Tcp => published_ports.push(mapping.guest),
            terra_protocol::network::ResourceKind::Udp => published_udp_ports.push(mapping.guest),
        }
    }
    published_ports.sort_unstable();
    published_ports.dedup();
    published_udp_ports.sort_unstable();
    published_udp_ports.dedup();
    let plan = Plan {
        mode: spec.mode,
        workdir: cfg
            .workload
            .workdir
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned()),
        shares,
        volumes,
        net: if cfg.network.enabled {
            Net::Tsi
        } else {
            Net::LocalOnly
        },
        published_ports,
        published_udp_ports,
        env: cfg.env.clone(),
        root: spec.root || baking,
        sudo: cfg.sudo.clone(),
        on_create: cfg.hooks.on_create.clone(),
        on_start: cfg.hooks.on_start.clone(),
        pre_stop: cfg.hooks.pre_stop.clone(),
        daemons: cfg.daemons.clone(),
        await_initial_session: spec.foreground || spec.mode == PlanMode::Create,
        workload: std::iter::once(cfg.workload.entrypoint.to_string_lossy().into_owned())
            .chain(cfg.workload.args.iter().cloned())
            .collect(),
        sandbox_info: generate_sandbox_info(cfg, spec.root),
        host_tz: read_host_timezone(),
        host_time: None,
        host_seed: None,
    };
    plan.validate_network()?;
    Ok(plan)
}

/// What the agent writes to `/terra/README.md`, so an AI agent looking
/// around the box finds an explanation instead of guessing.
#[must_use]
fn generate_sandbox_info(cfg: &config::Config, root: bool) -> String {
    let yaml = render_config_yaml(&redact_config_env(cfg)).unwrap_or_default();
    let who = if root {
        "`root`".to_string()
    } else {
        format!("`{WORKLOAD_USER_NAME}` (uid {WORKLOAD_ID}, non-root)")
    };
    format!(
        include_str!("sandbox_readme.md"),
        who = who,
        cmd = format_workload_line(cfg),
        yaml = yaml,
        egress = network::describe(&cfg.network),
        network_mode = if cfg.network.enabled {
            "External TCP and UDP use the filtered network vsock connection. DNS uses the guest resolver at `127.0.0.53`."
        } else {
            "Local-only networking: external connections and DNS resolution are disabled."
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn accepted_storage_count_fits_native_layout() {
        use terra_runtime::machine::build_machine_layout;

        for volumes in 0..=MAX_GUEST_STORAGE_DEVICES {
            let shares = MAX_GUEST_STORAGE_DEVICES - volumes;
            assert!(build_machine_layout(512 << 20, 2 + volumes, shares).is_ok());
        }
    }

    #[test]
    fn sandbox_info_carries_the_resolved_config_as_yaml() {
        let mut cfg: config::Config =
            yaml_serde::from_str("workload:\n  entrypoint: /bin/sh\n  args: [-c, make]\n").unwrap();
        cfg.mounts = vec![config::Mount {
            host: PathBuf::from("/srv/models"),
            guest: PathBuf::from("/models"),
            readonly: true,
        }];
        let info = generate_sandbox_info(&cfg, false);
        assert!(info.contains("# Terrarium sandbox"));
        assert!(info.contains("`/bin/sh -c make`"));
        assert!(info.contains("(uid 1000, non-root)"));
        assert!(info.contains("```yaml"), "{info}");
        assert!(info.contains("host: /srv/models"), "{info}");
        assert!(info.contains("readonly: true"), "{info}");
        assert!(
            info.contains("`mounts` - host directories shared"),
            "{info}"
        );
        assert!(info.contains("`sudo` - the commands"), "{info}");

        // --root: no privilege drop, and the doc says so.
        let root = generate_sandbox_info(&cfg, true);
        assert!(root.contains("You run as `root`"), "{root}");
    }

    /// The plan is the guest's whole contract: exec line in exec order, env in
    /// the plan and only there, devices and stop mode as configured.
    #[test]
    fn the_plan_carries_the_resolved_config() {
        let mut cfg: config::Config =
            yaml_serde::from_str("workload:\n  entrypoint: /bin/sh\n  args: [-c, make]\n").unwrap();
        cfg.env = BTreeMap::from([("API_KEY".to_string(), "sk-super-secret".to_string())]);
        cfg.daemons = vec!["ascend --serve".into()];
        let spec = BootSpec {
            cfg,
            project_dir: PathBuf::from("/proj"),
            root: false,
            mode: PlanMode::Run,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        };
        let mut spec = spec;
        spec.cfg.mounts = vec![config::Mount {
            host: "/host/work".into(),
            guest: "/work".into(),
            readonly: true,
        }];
        spec.cfg.volumes = vec![config::Volume {
            name: "data".into(),
            guest: "/data".into(),
            size_mib: 1,
        }];
        let plan = build_plan(&spec).unwrap();

        assert_eq!(plan.workload, ["/bin/sh", "-c", "make"]);
        assert_eq!(plan.daemons, ["ascend --serve"]);
        assert_eq!(plan.env["API_KEY"], "sk-super-secret");
        assert!(!plan.sandbox_info.contains("sk-super-secret"));
        assert_matches!(plan.mode, PlanMode::Run);
        assert_eq!(plan.shares[0].guest, "/work");
        assert!(plan.shares[0].readonly);
        assert_eq!(plan.volumes[0].dev, "/dev/vdc");
        assert_eq!(plan.volumes[0].guest, "/data");
        assert_eq!(plan.net, Net::Tsi);
        spec.cfg.network.enabled = false;
        assert_eq!(build_plan(&spec).unwrap().net, Net::LocalOnly);
        let foreground = BootSpec {
            foreground: true,
            ..spec
        };
        let foreground_plan = build_plan(&foreground).unwrap();
        assert!(foreground_plan.await_initial_session);
    }

    #[test]
    fn a_bake_waits_for_its_console_before_running_hooks() {
        let spec = BootSpec {
            cfg: yaml_serde::from_str("{}").unwrap(),
            project_dir: PathBuf::from("/proj"),
            root: false,
            mode: PlanMode::Create,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        };
        assert!(build_plan(&spec).unwrap().await_initial_session);
    }

    /// A bake installs software into the box's filesystem, so it runs as guest
    /// root however the boot was spelled - and a workload boot never inherits
    /// that. Read off the mode here rather than written onto the spec on the
    /// way in, which left two places deciding one thing.
    #[test]
    fn a_bake_is_guest_root_and_a_workload_boot_is_not() {
        let spec = |root, mode| BootSpec {
            cfg: yaml_serde::from_str("{}").unwrap(),
            project_dir: PathBuf::from("/proj"),
            root,
            mode,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        };
        let plan = |root, mode| build_plan(&spec(root, mode)).unwrap().root;

        assert!(plan(false, PlanMode::Create), "a bake is root");
        assert!(plan(true, PlanMode::Create));
        // …and it does not leak into the boot that follows it.
        assert!(!plan(false, PlanMode::Run), "a workload boot is not");
        assert!(plan(true, PlanMode::Run), "--root still reaches the plan");
    }

    /// `sandbox_info` lands in the guest's *persistent* filesystem: names are
    /// useful, values would outlive the boot that set them.
    #[test]
    fn sandbox_info_names_env_vars_without_their_values() {
        let cfg = config::Config {
            env: BTreeMap::from([("API_KEY".to_string(), "sk-super-secret".to_string())]),
            ..yaml_serde::from_str("{}").unwrap()
        };
        let info = generate_sandbox_info(&cfg, false);
        assert!(info.contains("API_KEY"), "the name should still be shown");
        assert!(!info.contains("sk-super-secret"), "{info}");
    }
}
