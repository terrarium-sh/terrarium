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
#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "macos", target_arch = "aarch64"),
    target_os = "windows"
))]
pub use component::run;
pub mod image;
mod resources;

use self::boot::BootSpec;
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

pub(crate) fn encode_boot_plan(spec: &BootSpec, box_name: &str) -> Result<Vec<u8>> {
    terra_protocol::encode_frame_with_limit(
        &terra_protocol::BootPlan::new(build_plan(spec, box_name)?),
        terra_protocol::MAX_PLAN_BYTES - terra_protocol::MAX_PLAN_HOST_STATE_BYTES,
    )
    .context("boot plan exceeds its encoded size limit; reduce the recipe or environment")
}

pub(crate) fn rootfs_access(spec: &BootSpec) -> terra_runtime::component::AccessMode {
    use terra_runtime::component::AccessMode;
    if spec.mode == PlanMode::Run && spec.cfg.hw.rootfs_readonly {
        AccessMode::ReadOnly
    } else {
        AccessMode::ReadWrite
    }
}

/// The resolved config the agent runs as PID 1.
fn build_plan(spec: &BootSpec, box_name: &str) -> Result<Plan> {
    let cfg = &spec.cfg;
    let is_setup_boot = spec.mode == PlanMode::Create;
    let is_root = spec.root || is_setup_boot;
    let shares = cfg
        .mounts
        .iter()
        .enumerate()
        .map(|(index, mount)| Share {
            tag: terra_runtime::component::fs::share_tag(index),
            guest: mount.guest.to_string_lossy().into_owned(),
            readonly: mount.readonly,
        })
        .collect();
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
    let published_mappings = if is_setup_boot {
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
        hostname: crate::name::box_hostname(box_name),
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
        root: is_root,
        rootfs_readonly: rootfs_access(spec) == terra_runtime::component::AccessMode::ReadOnly,
        sudo: cfg.sudo.clone(),
        on_create: cfg.hooks.on_create.clone(),
        on_start: cfg.hooks.on_start.clone(),
        pre_stop: cfg.hooks.pre_stop.clone(),
        daemons: cfg.daemons.clone(),
        await_initial_session: spec.foreground || spec.mode == PlanMode::Create,
        workload: std::iter::once(cfg.workload.entrypoint.to_string_lossy().into_owned())
            .chain(cfg.workload.args.iter().cloned())
            .collect(),
        sandbox_info: generate_sandbox_info(spec),
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
fn generate_sandbox_info(spec: &BootSpec) -> String {
    let cfg = &spec.cfg;
    let yaml = render_config_yaml(&redact_config_env(cfg)).unwrap_or_default();
    let who = if spec.root || spec.mode == PlanMode::Create {
        "`root`".to_string()
    } else {
        format!("`{WORKLOAD_USER_NAME}` (uid {WORKLOAD_ID}, non-root)")
    };
    format!(
        include_str!("sandbox_readme.md"),
        who = who,
        rootfs = if rootfs_access(spec) == terra_runtime::component::AccessMode::ReadOnly {
            "The root filesystem is READ-ONLY: every write to it fails with EROFS, as \
             root too. `/tmp`, `/var/tmp` and `/run` are in-memory and reset on every \
             boot; only the `mounts` and `lifetime: box` volumes below keep data."
        } else {
            "The root filesystem is a private disk image. It PERSISTS across restarts of \
             this sandbox; rebuilding or removing the box clears it. Its size is capped, \
             so it can fill up: writes past the cap fail with ENOSPC."
        },
        shares = match spec.mode {
            PlanMode::Create => {
                "This is setup's VM: the `mounts` below are not attached and the \
                 `volumes` are not mounted until the box starts, so writes to their \
                 guest paths land in the root filesystem."
            }
            PlanMode::Run => {
                "Only the `mounts` listed below are shared with the host. Everything \
                 else you write stays inside the sandbox."
            }
        },
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
    use crate::config;
    use std::assert_matches;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn build_run_spec(cfg: config::Config) -> BootSpec {
        BootSpec {
            cfg,
            project_dir: PathBuf::from("/project"),
            root: false,
            mode: PlanMode::Run,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        }
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn accepted_storage_count_fits_native_layout() {
        use terra_runtime::machine::build_machine_layout;

        for volumes in 0..=MAX_GUEST_STORAGE_DEVICES {
            let shares = MAX_GUEST_STORAGE_DEVICES - volumes;
            assert!(build_machine_layout(512 << 20, 2 + volumes, shares).is_ok());
        }
    }

    /// An agent reading the README acts on it, so it describes the boot it is
    /// in: setup's VM of a read-only box runs as root on a writable root with
    /// no mounts or volumes attached, and only the run boots after it are
    /// read-only, the workload user's, and shared with the host.
    #[test]
    fn sandbox_info_describes_the_boot_not_just_the_recipe() {
        let mut cfg: config::Config = yaml_serde::from_str("{}").unwrap();
        cfg.hw.rootfs_readonly = true;
        let info = |mode| {
            build_plan(
                &BootSpec {
                    cfg: cfg.clone(),
                    project_dir: PathBuf::from("/project"),
                    root: false,
                    mode,
                    foreground: false,
                    host_publishes_pid: false,
                    network_broker: None,
                },
                "dev",
            )
            .unwrap()
            .sandbox_info
        };
        let setup = info(PlanMode::Create);
        assert!(setup.contains("You run as `root`"), "{setup}");
        assert!(setup.contains("It PERSISTS"), "{setup}");
        assert!(
            setup.contains("not mounted until the box starts"),
            "{setup}"
        );
        assert!(!setup.contains("shared with the host"), "{setup}");
        let run = info(PlanMode::Run);
        assert!(run.contains("You run as `terri`"), "{run}");
        assert!(run.contains("READ-ONLY"), "{run}");
        assert!(run.contains("shared with the host"), "{run}");
    }

    /// An agent reading the README acts on it, so the root filesystem line must
    /// match the boot: writes to a read-only root fail, they do not persist.
    #[test]
    fn sandbox_info_says_whether_the_root_keeps_writes() {
        let mut spec = build_run_spec(config::Config::default());
        let writable = generate_sandbox_info(&spec);
        assert!(
            writable.contains("It PERSISTS across restarts"),
            "{writable}"
        );
        assert!(!writable.contains("READ-ONLY"), "{writable}");
        spec.cfg.hw.rootfs_readonly = true;
        let readonly = generate_sandbox_info(&spec);
        assert!(
            readonly.contains("READ-ONLY: every write to it fails with EROFS"),
            "{readonly}"
        );
        assert!(!readonly.contains("PERSISTS"), "{readonly}");
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
        let mut spec = build_run_spec(cfg);
        let info = generate_sandbox_info(&spec);
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
        spec.root = true;
        let root = generate_sandbox_info(&spec);
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
            lifetime: config::VolumeLifetime::Box,
        }];
        let plan = build_plan(&spec, "My_Box").unwrap();

        assert_eq!(plan.hostname, "my-box");
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
        assert_eq!(build_plan(&spec, "dev").unwrap().net, Net::LocalOnly);
        let foreground = BootSpec {
            foreground: true,
            ..spec
        };
        let foreground_plan = build_plan(&foreground, "dev").unwrap();
        assert!(foreground_plan.await_initial_session);
    }

    /// The setup boot attaches no filesystem device, but the agent creates the mount
    /// points in the base from the plan's share list.
    #[test]
    fn a_setup_plan_names_the_shares_and_publishes_no_ports() {
        let mut cfg: config::Config = yaml_serde::from_str("{}").unwrap();
        cfg.mounts = vec![config::Mount {
            host: "/host/work".into(),
            guest: "/work".into(),
            readonly: false,
        }];
        cfg.network.ports = vec!["8080:80".into()];
        let spec = BootSpec {
            cfg,
            project_dir: PathBuf::from("/proj"),
            root: false,
            mode: PlanMode::Create,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        };
        let plan = build_plan(&spec, "dev").unwrap();
        assert_eq!(plan.shares[0].guest, "/work");
        assert_eq!(plan.published_ports, [] as [u16; 0]);
    }

    /// The disk the host opens and the plan the agent reads come from one
    /// decision, so the agent never mounts a read-only device writable.
    #[test]
    fn only_a_run_boot_of_a_read_only_box_gets_a_read_only_root() {
        use terra_runtime::component::AccessMode;
        let spec = |mode, rootfs_readonly| {
            let mut cfg: config::Config = yaml_serde::from_str("{}").unwrap();
            cfg.hw.rootfs_readonly = rootfs_readonly;
            BootSpec {
                cfg,
                project_dir: PathBuf::from("/project"),
                root: false,
                mode,
                foreground: false,
                host_publishes_pid: false,
                network_broker: None,
            }
        };
        for (mode, rootfs_readonly, expected) in [
            (PlanMode::Run, true, AccessMode::ReadOnly),
            (PlanMode::Create, true, AccessMode::ReadWrite),
            (PlanMode::Run, false, AccessMode::ReadWrite),
        ] {
            let spec = spec(mode, rootfs_readonly);
            assert_eq!(
                rootfs_access(&spec),
                expected,
                "{mode:?}, {rootfs_readonly}"
            );
            assert_eq!(
                build_plan(&spec, "dev").unwrap().rootfs_readonly,
                expected == AccessMode::ReadOnly,
                "{mode:?}, {rootfs_readonly}"
            );
        }
    }

    #[test]
    fn a_setup_boot_waits_for_its_console_before_running_hooks() {
        let spec = BootSpec {
            cfg: yaml_serde::from_str("{}").unwrap(),
            project_dir: PathBuf::from("/proj"),
            root: false,
            mode: PlanMode::Create,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        };
        assert!(build_plan(&spec, "dev").unwrap().await_initial_session);
    }

    /// A setup boot installs software into the box's filesystem, so it runs as guest
    /// root however the boot was spelled - and a workload boot never inherits
    /// that. Read off the mode here rather than written onto the spec on the
    /// way in, which left two places deciding one thing.
    #[test]
    fn a_setup_boot_is_guest_root_and_a_workload_boot_is_not() {
        let spec = |root, mode| BootSpec {
            cfg: yaml_serde::from_str("{}").unwrap(),
            project_dir: PathBuf::from("/proj"),
            root,
            mode,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        };
        let plan = |root, mode| build_plan(&spec(root, mode), "dev").unwrap().root;

        assert!(plan(false, PlanMode::Create), "a setup boot is root");
        assert!(plan(true, PlanMode::Create));
        // …and it does not leak into the boot that follows it.
        assert!(!plan(false, PlanMode::Run), "a workload boot is not");
        assert!(plan(true, PlanMode::Run), "--root still reaches the plan");
    }

    /// `sandbox_info` is a file every guest process can read: names are
    /// useful, values would hand the recipe's secrets to all of them.
    #[test]
    fn sandbox_info_names_env_vars_without_their_values() {
        let cfg = config::Config {
            env: BTreeMap::from([("API_KEY".to_string(), "sk-super-secret".to_string())]),
            ..yaml_serde::from_str("{}").unwrap()
        };
        let info = generate_sandbox_info(&build_run_spec(cfg));
        assert!(info.contains("API_KEY"), "the name should still be shown");
        assert!(!info.contains("sk-super-secret"), "{info}");
    }
}
