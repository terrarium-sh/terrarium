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
use crate::render::{format_workload_line, redact_recipe_env, render_recipe_yaml};
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
use terra_protocol::{
    Disk, Net, Plan, PlanMode, RootfsMount, Share, WORKLOAD_ID, WORKLOAD_USER_NAME,
};
use terra_runtime::component::AccessMode;

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

pub(crate) fn rootfs_access(spec: &BootSpec) -> AccessMode {
    if spec.mode == PlanMode::Run && spec.recipe.hw.rootfs_readonly {
        AccessMode::ReadOnly
    } else {
        AccessMode::ReadWrite
    }
}

/// The plan the agent runs as PID 1, resolved from the recipe.
fn build_plan(spec: &BootSpec, box_name: &str) -> Result<Plan> {
    let recipe = &spec.recipe;
    let is_setup_boot = spec.mode == PlanMode::Create;
    let is_root = spec.root || is_setup_boot;
    let shares = recipe
        .mounts
        .iter()
        .enumerate()
        .map(|(index, mount)| Share {
            tag: terra_runtime::component::fs::share_tag(index),
            guest: mount.guest.to_string_lossy().into_owned(),
            readonly: mount.readonly,
        })
        .collect();
    let get_volume_device = |index| {
        terra_protocol::to_volume_device(index)
            .with_context(|| format!("volume {index} is past the last guest block device"))
    };
    let mut volumes = Vec::new();
    for (index, volume) in recipe.volumes.iter().enumerate() {
        if let Some(guest) = &volume.guest {
            volumes.push(Disk {
                dev: get_volume_device(index)?,
                guest: guest.to_string_lossy().into_owned(),
            });
        }
    }
    let rootfs = match rootfs_access(spec) {
        AccessMode::ReadWrite => RootfsMount::Writable,
        AccessMode::ReadOnly => match recipe
            .volumes
            .iter()
            .position(|volume| volume.rootfs_overlay)
        {
            Some(index) => RootfsMount::Overlay {
                upper_dev: get_volume_device(index)?,
            },
            None => RootfsMount::ReadOnly,
        },
    };
    let sandbox_info = generate_sandbox_info(spec, &rootfs);
    let published_mappings = if is_setup_boot {
        Vec::new()
    } else {
        network::rules::parse_port_mappings(&recipe.network.ports)?
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
        workdir: recipe
            .workload
            .workdir
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned()),
        shares,
        volumes,
        net: if recipe.network.enabled {
            Net::Tsi
        } else {
            Net::LocalOnly
        },
        published_ports,
        published_udp_ports,
        env: recipe.env.clone(),
        root: is_root,
        rootfs,
        sudo: recipe.sudo.clone(),
        on_create: recipe.hooks.on_create.clone(),
        on_start: recipe.hooks.on_start.clone(),
        pre_stop: recipe.hooks.pre_stop.clone(),
        daemons: recipe.daemons.clone(),
        await_initial_session: spec.foreground || spec.mode == PlanMode::Create,
        workload: std::iter::once(recipe.workload.entrypoint.to_string_lossy().into_owned())
            .chain(recipe.workload.args.iter().cloned())
            .collect(),
        sandbox_info,
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
fn generate_sandbox_info(spec: &BootSpec, rootfs: &RootfsMount) -> String {
    let recipe = &spec.recipe;
    let yaml = render_recipe_yaml(&redact_recipe_env(recipe)).unwrap_or_default();
    let who = if spec.root || spec.mode == PlanMode::Create {
        "`root`".to_string()
    } else {
        format!("`{WORKLOAD_USER_NAME}` (uid {WORKLOAD_ID}, non-root)")
    };
    format!(
        include_str!("sandbox_readme.md"),
        who = who,
        rootfs = match rootfs {
            RootfsMount::Writable => {
                "The root filesystem is a private disk image. It PERSISTS across restarts of \
                 this sandbox; rebuilding or removing the box clears it. Its size is capped, \
                 so it can fill up: writes past the cap fail with ENOSPC."
            }
            RootfsMount::ReadOnly => {
                "The root filesystem is READ-ONLY: every write to it fails with EROFS, as \
                 root too. `/tmp`, `/var/tmp` and `/run` are in-memory and reset on every \
                 boot; only the `mounts` and `lifetime: box` volumes below keep data."
            }
            RootfsMount::Overlay { .. } => {
                "The root filesystem is writable for this boot only: writes go to the \
                 `rootfs_overlay` volume and are gone after a restart; only the `mounts` and \
                 `lifetime: box` volumes below keep data."
            }
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
        cmd = format_workload_line(recipe),
        yaml = yaml,
        egress = network::describe(&recipe.network),
        network_mode = if recipe.network.enabled {
            "External TCP and UDP use the filtered network vsock connection. DNS uses the guest resolver at `127.0.0.53`."
        } else {
            "Local-only networking: external connections and DNS resolution are disabled."
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipe::{Mount, Recipe, Volume, VolumeLifetime};
    use std::assert_matches;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn build_run_spec(recipe: Recipe) -> BootSpec {
        BootSpec {
            recipe,
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
        let mut recipe: Recipe = yaml_serde::from_str("{}").unwrap();
        recipe.hw.rootfs_readonly = true;
        let info = |mode| {
            build_plan(
                &BootSpec {
                    recipe: recipe.clone(),
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
        let mut spec = build_run_spec(Recipe::default());
        let writable = build_plan(&spec, "dev").unwrap().sandbox_info;
        assert!(
            writable.contains("It PERSISTS across restarts"),
            "{writable}"
        );
        assert!(!writable.contains("READ-ONLY"), "{writable}");
        spec.recipe.hw.rootfs_readonly = true;
        let readonly = build_plan(&spec, "dev").unwrap().sandbox_info;
        assert!(
            readonly.contains("READ-ONLY: every write to it fails with EROFS"),
            "{readonly}"
        );
        assert!(!readonly.contains("PERSISTS"), "{readonly}");
    }

    #[test]
    fn sandbox_info_carries_the_resolved_recipe_as_yaml() {
        let mut recipe: Recipe =
            yaml_serde::from_str("workload:\n  entrypoint: /bin/sh\n  args: [-c, make]\n").unwrap();
        recipe.mounts = vec![Mount {
            host: PathBuf::from("/srv/models"),
            guest: PathBuf::from("/models"),
            readonly: true,
        }];
        let mut spec = build_run_spec(recipe);
        let info = build_plan(&spec, "dev").unwrap().sandbox_info;
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
        let root = build_plan(&spec, "dev").unwrap().sandbox_info;
        assert!(root.contains("You run as `root`"), "{root}");
    }

    /// The plan is the guest's whole contract: exec line in exec order, env in
    /// the plan and only there, devices and stop mode as the recipe sets them.
    #[test]
    fn the_plan_carries_the_resolved_recipe() {
        let mut recipe: Recipe =
            yaml_serde::from_str("workload:\n  entrypoint: /bin/sh\n  args: [-c, make]\n").unwrap();
        recipe.env = BTreeMap::from([("API_KEY".to_string(), "sk-super-secret".to_string())]);
        recipe.daemons = vec!["ascend --serve".into()];
        let spec = BootSpec {
            recipe,
            project_dir: PathBuf::from("/proj"),
            root: false,
            mode: PlanMode::Run,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        };
        let mut spec = spec;
        spec.recipe.mounts = vec![Mount {
            host: "/host/work".into(),
            guest: "/work".into(),
            readonly: true,
        }];
        spec.recipe.volumes = vec![Volume {
            name: "data".into(),
            guest: Some("/data".into()),
            rootfs_overlay: false,
            size_mib: 1,
            lifetime: VolumeLifetime::Box,
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
        spec.recipe.network.enabled = false;
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
        let mut recipe: Recipe = yaml_serde::from_str("{}").unwrap();
        recipe.mounts = vec![Mount {
            host: "/host/work".into(),
            guest: "/work".into(),
            readonly: false,
        }];
        recipe.network.ports = vec!["8080:80".into()];
        let spec = BootSpec {
            recipe,
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
        let spec = |mode, rootfs_readonly| {
            let mut recipe: Recipe = yaml_serde::from_str("{}").unwrap();
            recipe.hw.rootfs_readonly = rootfs_readonly;
            BootSpec {
                recipe,
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
                build_plan(&spec, "dev").unwrap().rootfs,
                match expected {
                    AccessMode::ReadOnly => RootfsMount::ReadOnly,
                    AccessMode::ReadWrite => RootfsMount::Writable,
                },
                "{mode:?}, {rootfs_readonly}"
            );
        }
    }

    #[test]
    fn a_setup_boot_waits_for_its_console_before_running_hooks() {
        let spec = BootSpec {
            recipe: yaml_serde::from_str("{}").unwrap(),
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
            recipe: yaml_serde::from_str("{}").unwrap(),
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
        let recipe = Recipe {
            env: BTreeMap::from([("API_KEY".to_string(), "sk-super-secret".to_string())]),
            ..yaml_serde::from_str("{}").unwrap()
        };
        let info = build_plan(&build_run_spec(recipe), "dev")
            .unwrap()
            .sandbox_info;
        assert!(info.contains("API_KEY"), "the name should still be shown");
        assert!(!info.contains("sk-super-secret"), "{info}");
    }

    fn overlay_spec(mode: PlanMode) -> BootSpec {
        let volume = |name: &str, guest: Option<&str>| Volume {
            name: name.into(),
            guest: guest.map(PathBuf::from),
            rootfs_overlay: guest.is_none(),
            size_mib: 64,
            lifetime: VolumeLifetime::Boot,
        };
        let mut recipe = Recipe::default();
        recipe.hw.rootfs_readonly = true;
        recipe.volumes = vec![
            volume("before", Some("/before")),
            volume("changes", None),
            volume("after", Some("/after")),
        ];
        BootSpec {
            recipe,
            project_dir: PathBuf::from("/project"),
            root: false,
            mode,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        }
    }

    /// The overlay keeps its slot among the attached disks, so the guest
    /// volumes around it keep theirs, and it is not also mounted at a path.
    #[test]
    fn a_run_plan_puts_the_overlay_device_in_rootfs_not_in_volumes() {
        let plan = build_plan(&overlay_spec(PlanMode::Run), "dev").unwrap();
        assert_eq!(
            plan.rootfs,
            RootfsMount::Overlay {
                upper_dev: terra_protocol::to_volume_device(1).unwrap()
            }
        );
        let devices: Vec<_> = plan.volumes.iter().map(|disk| disk.dev.clone()).collect();
        assert_eq!(
            devices,
            [
                terra_protocol::to_volume_device(0).unwrap(),
                terra_protocol::to_volume_device(2).unwrap()
            ]
        );
        assert_eq!(plan.volumes[0].guest, "/before");
        assert_eq!(plan.volumes[1].guest, "/after");
    }

    /// Setup writes the root itself; its plan keeps the guest volumes only for
    /// their mount points and carries no overlay.
    #[test]
    fn setups_plan_has_a_writable_root_and_no_overlay() {
        let plan = build_plan(&overlay_spec(PlanMode::Create), "dev").unwrap();
        assert_eq!(plan.rootfs, RootfsMount::Writable);
        assert_eq!(plan.volumes.len(), 2);
        let info = &plan.sandbox_info;
        assert!(!info.contains("writable for this boot only"), "{info}");
    }

    /// An agent reading the README must learn where its root writes go: the
    /// root line points at the volume the YAML below lists.
    #[test]
    fn sandbox_info_says_root_writes_go_to_the_overlay_volume() {
        let info = build_plan(&overlay_spec(PlanMode::Run), "dev")
            .unwrap()
            .sandbox_info;
        assert!(
            info.contains("writable for this boot only: writes go to the `rootfs_overlay` volume"),
            "{info}"
        );
        assert!(info.contains("rootfs_overlay: true"), "{info}");
        assert!(!info.contains("READ-ONLY"), "{info}");
    }
}
