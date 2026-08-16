//! Configuring and starting the libkrun VM, and serving the control channel
//! that carries the boot plan into the guest.

pub mod boot;
pub mod image;
mod libkrun_ext;

use self::boot::BootSpec;
use crate::policy::network;
use crate::render::{Options, config_yaml, mount_lines, workload_line};
use crate::state::BoxRef;
use crate::{config, logs, sys};
use anyhow::{Context, Result};
use smolvm_network::GuestNetworkConfig;
use std::fs::File;
use std::process::ExitCode;
use terra_agent::{Disk, Net, Plan, PlanMode, Share, WORKLOAD_UID};

// The two VMs one spec can ask for, told apart by `spec.mode`:
//   Create - a bare VM that bakes `on_create` and stops. No shares and no
//            agent ports, so nothing on the host is reachable from the guest.
//   Run    - the workload boot: shares mounted, agent ports served, runs
//            until stopped.

/// Attach the box's block devices. The kernel cmdline and the boot plan name
/// the devices this produces, so the add order *is* the contract:
///   /dev/vda  boot volume (agent + resize2fs, read-only, roots the kernel)
///   /dev/vdb  the box's persistent root filesystem
///   /dev/vdc… one per configured volume
fn attach_disks(krun: &libkrun_ext::Krun, cfg: &config::Config, bx: &BoxRef) -> Result<Vec<Disk>> {
    krun.add_disk("terra-boot", &image::ensure_boot_volume_on_disk()?, true)?;
    krun.add_disk("terra-root", &bx.rootfs_img(), false)?;
    let mut volumes = Vec::new();
    for (i, v) in cfg.volumes.iter().enumerate() {
        let img = bx.volume_img(&v.name);
        image::ensure_volume_image(&img, v.size_mib)
            .with_context(|| format!("preparing volume image {}", img.display()))?;
        krun.add_disk(&format!("vol{i}"), &img, false)?;
        volumes.push(Disk {
            // Recipe validation caps volumes at MAX_VOLUMES, so this is a bug
            // guard, not an input check.
            dev: terra_agent::volume_device(i)
                .with_context(|| format!("volume {i} is past the last guest block device"))?,
            guest: v.guest.to_string_lossy().into_owned(),
        });
    }
    Ok(volumes)
}

fn attach_shares(
    krun: &libkrun_ext::Krun,
    cfg: &config::Config,
    mode: PlanMode,
) -> Result<Vec<Share>> {
    let mut shares = Vec::new();
    if mode == PlanMode::Run {
        for (i, m) in cfg.mounts.iter().enumerate() {
            let tag = format!("sh{i}");
            krun.add_virtiofs(&tag, &m.host, m.readonly)?;
            shares.push(Share {
                tag,
                guest: m.guest.to_string_lossy().into_owned(),
                readonly: m.readonly,
            });
        }
    }
    Ok(shares)
}

/// libkrun binds under the process umask; the `0700` state directory is what
/// keeps another account off the root-capable exec service behind it.
fn attach_agent_port(krun: &libkrun_ext::Krun, bx: &BoxRef) -> Result<()> {
    let path = bx.agent_sock();
    // A crashed prior VM may have left a socket; libkrun binds EEXIST.
    let _ = std::fs::remove_file(&path);
    krun.add_vsock_port(terra_agent::AGENT_VSOCK_PORT, &path, true)
}

/// Run the box's VM until the workload ends.
pub fn run(spec: &BootSpec, bx: &BoxRef, _lock: File) -> Result<ExitCode> {
    // Before libkrun exists to log anything: its records reach the box's log
    // through the same subscriber as ours and the gateway's.
    logs::init();
    let cfg = &spec.cfg;
    let mode = spec.mode;
    if mode == PlanMode::Run {
        // Only a Run VM attaches shares (see the mode notes above), so only it
        // can hand a writable one to host root - checked here because this
        // process, not the spawning parent, is the one that attaches them.
        check_root_writable_shares(cfg)?;
        // Registered before the pid is published, so no SIGTERM can land where
        // it would kill the process outright, `pre_stop` and all.
        sys::install_stop_signal_handlers();
    }
    bx.publish_pid(std::process::id(), mode == PlanMode::Create);

    let krun = libkrun_ext::Krun::create()?;
    krun.set_vm_config(cfg.hw.cpus, cfg.hw.mem_mib)?;
    krun.set_kernel(
        &image::ensure_kernel_on_disk()?,
        &terra_agent::kernel_cmdline(),
    )?;

    let volumes = attach_disks(&krun, cfg, bx)?;
    let shares = attach_shares(&krun, cfg, mode)?;

    let null = sys::open_null().context("opening the null device for the guest console")?;
    let _console = krun.add_console(null, console_output(spec, bx)?)?;

    let guest_net = GuestNetworkConfig::default();
    let _net_rt = start_networking(&krun, &cfg.network, guest_net)?;

    // The vsock device carries every port added after it.
    krun.add_vsock()?;

    if mode == PlanMode::Run {
        attach_agent_port(&krun, bx)?;
    }

    let plan = build_plan(spec, shares, volumes, &guest_net);
    serve_control_sock(&krun, bx, &plan)?;

    let (vcpus, mem) = (cfg.hw.cpus, cfg.hw.mem_mib);
    match plan.mode {
        PlanMode::Create => println!("terra: baking on_create for {bx} ({vcpus} vCPU, {mem} MiB)"),
        PlanMode::Run => {
            println!("terra: starting {bx} ({vcpus} vCPU, {mem} MiB)");
            for line in mount_lines(cfg) {
                println!("{line}");
            }
        }
    }

    logs::roll_in_background(bx);

    // Foreground only: from here that stream is the guest's, and a host line
    // landing inside a guest escape sequence corrupts a live TUI - libkrun's
    // and the gateway's records arrive from background threads throughout.
    if spec.foreground {
        redirect_stdio_into_log(bx)?;
    }

    krun.start_enter()?;

    // Not reached in practice - a finished box has already left through
    // [`exit_as_the_guest_did`], a dead one through libkrun's own exit.
    Ok(ExitCode::SUCCESS)
}

/// The resolved config the agent runs as PID 1.
fn build_plan(
    spec: &BootSpec,
    shares: Vec<Share>,
    volumes: Vec<Disk>,
    guest_net: &GuestNetworkConfig,
) -> Plan {
    let cfg = &spec.cfg;
    let baking = spec.mode == PlanMode::Create;
    Plan {
        mode: spec.mode,
        workdir: cfg
            .workload
            .workdir
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned()),
        shares,
        volumes,
        share_owner: sys::share_owner(),
        net: Net {
            guest_ip: guest_net.guest_ip.to_string(),
            prefix: guest_net.prefix_len,
            gateway: guest_net.gateway_ip.to_string(),
            dns: guest_net.dns_server.to_string(),
        },
        env: cfg.env.clone(),
        root: spec.root || baking,
        sudo: cfg.sudo.clone(),
        on_create: cfg.hooks.on_create.clone(),
        on_start: cfg.hooks.on_start.clone(),
        pre_stop: cfg.hooks.pre_stop.clone(),
        workload_on_console: spec.foreground,
        workload: std::iter::once(cfg.workload.entrypoint.to_string_lossy().into_owned())
            .chain(cfg.workload.args.iter().cloned())
            .collect(),
        sandbox_info: generate_sandbox_info(cfg, guest_net, spec.root),
    }
}

/// Where the guest's console writes for this boot. A spawned VM writes it
/// into the box's log, so a refusal sits next to the request that earned it;
/// a `--foreground` VM keeps the streams the process was started with (see
/// [`Plan::workload_on_console`]).
fn console_output(spec: &BootSpec, bx: &BoxRef) -> Result<File> {
    if spec.foreground {
        use std::os::fd::AsFd;
        return std::io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .map(File::from)
            .context("duplicating stdout for the guest console");
    }
    sys::open_owner_only(&bx.log()).with_context(|| format!("opening log {}", bx.log().display()))
}

fn redirect_stdio_into_log(bx: &BoxRef) -> Result<()> {
    use std::io::Write;
    let path = bx.log();
    let log = logs::open_for_a_run(bx)?;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    sys::point_stdio_at(&log).with_context(|| format!("redirecting output to {}", path.display()))
}

/// What the agent writes to `/terra/README.md`, so an AI agent looking
/// around the box finds an explanation instead of guessing.
fn generate_sandbox_info(cfg: &config::Config, net: &GuestNetworkConfig, root: bool) -> String {
    let yaml = config_yaml(cfg, Options::REDACTED).unwrap_or_default();
    let who = if root {
        "`root`".to_string()
    } else {
        format!(
            "`{}` (uid {WORKLOAD_UID}, non-root)",
            terra_agent::WORKLOAD_USER_NAME
        )
    };
    format!(
        include_str!("sandbox_readme.md"),
        who = who,
        cmd = workload_line(cfg),
        yaml = yaml,
        egress = network::describe(&cfg.network),
        ip = net.guest_ip,
        prefix = net.prefix_len,
        gw = net.gateway_ip,
        dns = net.dns_server,
    )
}

/// The guest's traffic terminates in-process, under the egress policy. Keep
/// the returned runtime alive for the VM's life.
#[must_use = "the VM's networking dies with this runtime"]
fn start_networking(
    krun: &libkrun_ext::Krun,
    net: &config::Network,
    guest_net: GuestNetworkConfig,
) -> Result<smolvm_network::VirtioNetworkRuntime> {
    let (host_end, krun_end) =
        std::os::unix::net::UnixStream::pair().context("creating virtio-net socketpair")?;
    krun.add_net_unixstream(krun_end, &guest_net.guest_mac)?;
    let egress = network::BoxPolicy::new(net, &guest_net)?;
    println!(
        "terra: egress: {} - loopback/LAN/private/CGNAT floored unless a rule names them",
        network::describe(net)
    );
    let ports = network::parse_port_mappings(&net.ports)?;
    for p in &ports {
        println!(
            "terra: published: 127.0.0.1:{} -> guest:{}",
            p.host, p.guest
        );
    }
    smolvm_network::start_virtio_network(
        std::os::fd::OwnedFd::from(host_end).into(),
        guest_net,
        &ports,
        egress,
    )
    .context("starting host-side virtio-net runtime")
}

/// Opt-out for the host-root refusal below - an env var, not a flag, so it
/// cannot creep into an alias.
const ALLOW_ROOT_ENV: &str = "TERRA_ALLOW_ROOT";

fn check_root_writable_shares(cfg: &config::Config) -> Result<()> {
    if sys::is_host_root() && cfg.mounts.iter().any(|m| !m.readonly) {
        anyhow::ensure!(
            std::env::var_os(ALLOW_ROOT_ENV).is_some_and(|v| v == "1"),
            "running as host root, the guest writes read-write shares as real root - \
             a sandbox escape is a `chmod u+s` away.\n\
             Run terra as an unprivileged user in the `kvm` group (see \
             packaging/README.md), mark the mounts `readonly: true`, or set \
             {ALLOW_ROOT_ENV}=1 to proceed anyway"
        );
        eprintln!(
            "terra: warning: {ALLOW_ROOT_ENV}=1 - the guest writes read-write shares \
             as real root"
        );
    }
    Ok(())
}

/// The plan, secrets included, travels through host memory and never touches
/// a disk; the connection then stays open for the VM's life, carrying the
/// graceful-stop byte - which a bake does not get, since killing it outright
/// is what stopping one means.
fn serve_control_sock(krun: &libkrun_ext::Krun, bx: &BoxRef, plan: &Plan) -> Result<()> {
    let watch_stop = plan.mode == PlanMode::Run;
    let sock = bx.control_sock();
    let _ = std::fs::remove_file(&sock); // a crashed prior VM may have left one
    let listener = std::os::unix::net::UnixListener::bind(&sock)
        .with_context(|| format!("binding the control socket {}", sock.display()))?;
    // `bind` applies the process umask; the socket hands out secrets, so the
    // mode is stated here too, not left to the state dir alone.
    sys::owner_only(&sock, false).with_context(|| format!("securing {}", sock.display()))?;
    krun.add_vsock_port(terra_agent::CONTROL_VSOCK_PORT, &sock, false)?;

    let frame = terra_agent::frame(plan).context("serializing the boot plan")?;
    std::thread::spawn(move || {
        use std::io::Write;
        let accepted = listener.accept();
        // Stop listening the moment the agent has dialed: a later dial from
        // inside the guest gets a refused connection, not the plan.
        drop(listener);
        let mut conn = match accepted {
            Ok((conn, _)) => conn,
            Err(e) => {
                eprintln!("terra: warning: the guest never opened the control port: {e}");
                return;
            }
        };
        if let Err(e) = conn.write_all(&frame) {
            eprintln!("terra: warning: could not send the boot plan: {e}");
            return;
        }
        if watch_stop {
            match conn.try_clone() {
                Ok(stop_channel) => sys::register_stop_channel(stop_channel.into()),
                Err(e) => eprintln!(
                    "terra: warning: no stop channel for this box ({e}) - \
                     it can only be killed"
                ),
            }
        }
        // Park on the connection instead of closing it: closing while
        // `pre_stop` runs would cut the stop channel out from under the guest.
        // The guest's last act on it is its exit status; a read that ends
        // without one is the VM dying rather than finishing.
        if let Ok(code) = terra_agent::read_exit_status(&mut conn) {
            exit_as_the_guest_did(code);
        }
    });
    Ok(())
}

fn exit_as_the_guest_did(code: i32) -> ! {
    std::process::exit(i32::from(crate::exit_status_byte(code)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[test]
    fn sandbox_info_carries_the_resolved_config_as_yaml() {
        let mut cfg: config::Config =
            serde_yaml::from_str("workload:\n  entrypoint: /bin/sh\n  args: [-c, make]\n").unwrap();
        cfg.mounts = vec![config::Mount {
            host: PathBuf::from("/srv/models"),
            guest: PathBuf::from("/models"),
            readonly: true,
        }];
        let info = generate_sandbox_info(&cfg, &GuestNetworkConfig::default(), false);
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
        let root = generate_sandbox_info(&cfg, &GuestNetworkConfig::default(), true);
        assert!(root.contains("You run as `root`"), "{root}");
    }

    /// The plan is the guest's whole contract: exec line in exec order, env in
    /// the plan and only there, devices and stop mode as configured.
    #[test]
    fn the_plan_carries_the_resolved_config() {
        let mut cfg: config::Config =
            serde_yaml::from_str("workload:\n  entrypoint: /bin/sh\n  args: [-c, make]\n").unwrap();
        cfg.env = BTreeMap::from([("API_KEY".to_string(), "sk-super-secret".to_string())]);
        let spec = BootSpec {
            cfg,
            project_dir: PathBuf::from("/proj"),
            root: false,
            mode: PlanMode::Run,
            foreground: false,
        };
        let shares = vec![Share {
            tag: "sh0".into(),
            guest: "/work".into(),
            readonly: true,
        }];
        let volumes = vec![Disk {
            dev: "/dev/vdc".into(),
            guest: "/data".into(),
        }];
        let plan = build_plan(&spec, shares, volumes, &GuestNetworkConfig::default());

        assert_eq!(plan.workload, ["/bin/sh", "-c", "make"]);
        assert_eq!(plan.env["API_KEY"], "sk-super-secret");
        assert!(!plan.sandbox_info.contains("sk-super-secret"));
        assert!(matches!(plan.mode, PlanMode::Run));
        assert_eq!(plan.shares[0].guest, "/work");
        assert!(plan.shares[0].readonly);
        assert_eq!(plan.volumes[0].dev, "/dev/vdc");
        assert_eq!(plan.volumes[0].guest, "/data");
        // A spawned VM's console is the box's log, so the workload's terminal
        // stays off it - it would land in `terra logs` as a second stream
        // interleaved with the diagnostics the log is for.
        assert!(!plan.workload_on_console);
        let foreground = BootSpec {
            foreground: true,
            ..spec
        };
        assert!(
            build_plan(&foreground, vec![], vec![], &GuestNetworkConfig::default())
                .workload_on_console,
            "a --foreground VM has the console for its only reader"
        );
    }

    /// A bake installs software into the box's filesystem, so it runs as guest
    /// root however the boot was spelled - and a workload boot never inherits
    /// that. Read off the mode here rather than written onto the spec on the
    /// way in, which left two places deciding one thing.
    #[test]
    fn a_bake_is_guest_root_and_a_workload_boot_is_not() {
        let spec = |root, mode| BootSpec {
            cfg: serde_yaml::from_str("{}").unwrap(),
            project_dir: PathBuf::from("/proj"),
            root,
            mode,
            foreground: false,
        };
        let plan = |root, mode| {
            build_plan(
                &spec(root, mode),
                vec![],
                vec![],
                &GuestNetworkConfig::default(),
            )
            .root
        };

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
            ..serde_yaml::from_str("{}").unwrap()
        };
        let info = generate_sandbox_info(&cfg, &GuestNetworkConfig::default(), false);
        assert!(info.contains("API_KEY"), "the name should still be shown");
        assert!(!info.contains("sk-super-secret"), "{info}");
    }
}
